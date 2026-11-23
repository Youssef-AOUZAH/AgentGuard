"""Session state, owned and updated by the gate (seam S3 in `docs/interfaces.md`).

The gate is the only writer of `SessionState`. The resolver and the policy engine read it and
never change it; this module replaces it after each command, in the fixed order S3 sets out:
analyse against the current state, decide, run, and only then fold what happened into the state.

Takes in the outcome of one command: for an executed command, the parsed `Script`, the effects
the analyzer predicted, and the executor's `ExecResult`; for a refused one, the decision.

Three things change.

- **The working directory** becomes the one the shell reported when the command finished. That is
  ground truth rather than a prediction, so a `cd` the analysis misread still leaves the session
  where the shell really is. When the shell did not report (see `gate/executor.py`), the
  directory is left as it was.
- **Tracked variables** change in source order. A bare assignment (`A=1`, with no command word) in
  a statement that runs in the current shell sets its variable: to the value when the word is
  known, and to `Unknown` otherwise. It only counts if it certainly runs, so an assignment after
  `&&` or `||` makes the variable `Unknown`, and one in a pipeline of several commands, in a
  backgrounded statement or inside a subshell or substitution changes nothing, because bash runs
  those in a child process. An `ENV_MUTATE` effect from the analyzer makes the variable it names
  `Unknown`, and one whose variable could not be determined makes every tracked variable
  `Unknown`: this is how `read x`, `unset x` or `${x:=v}` stop the session trusting a stale value.
- **The denied history** gains an entry for every command that was not run.

Deliberately not handled: exported versus unexported variables (the executor passes every known
variable in the environment, and the distinction does not change what a later word expands to),
and arrays, which the grammar does not accept.
"""

from __future__ import annotations

from dataclasses import replace

from compiler.syntax import Script, SimpleCommand
from compiler.types import (
    Decision,
    DeniedEntry,
    Effect,
    EffectKind,
    SessionState,
    Unknown,
    Variable,
    Verdict,
)
from gate.types import ExecResult


class Session:
    """The current `SessionState` and the turn counter, with the two ways to advance them."""

    def __init__(self, state: SessionState) -> None:
        self.state = state
        self.turn = 0

    def record_refusal(self, command: str, decision: Decision) -> None:
        """Remember a command that was not run, so a later retry can be compared against it."""
        if decision.verdict is Verdict.ALLOW:
            raise ValueError("an allowed decision is not a refusal")
        entry = DeniedEntry(self.turn, command, decision)
        self.state = replace(self.state, denied=self.state.denied + (entry,))
        self.turn += 1

    def record_run(self, script: Script, effects: frozenset[Effect], result: ExecResult) -> None:
        """Fold an executed command into the state."""
        variables = dict(self.state.variables)
        for name, value in _variable_events(script, effects):
            if name is None:
                variables = {n: value for n in variables}
            else:
                variables[name] = value
        cwd = result.cwd if result.cwd is not None else self.state.cwd
        self.state = replace(self.state, cwd=cwd, variables=variables)
        self.turn += 1

    def record_failure(self) -> None:
        """A command the gate could not handle at all: it was not run and there is no decision to
        remember, so only the turn advances."""
        self.turn += 1


def _variable_events(script: Script, effects: frozenset[Effect]) -> list[tuple[str | None, str | Unknown]]:
    """Every change to a tracked variable this command makes, in source order. A name of None
    means "every variable"."""
    events: list[tuple[int, str | None, str | Unknown]] = []
    assignment_positions: set[int] = set()
    for statement in script.statements:
        if statement.background:
            continue
        for index, pipeline in enumerate(statement.and_or.pipelines):
            if len(pipeline.commands) != 1:
                continue
            command = pipeline.commands[0]
            if not isinstance(command, SimpleCommand) or command.words:
                continue
            for assignment in command.assignments:
                assignment_positions.add(assignment.pos)
                value = assignment.value.value
                if index > 0:
                    known: str | Unknown = Unknown("assigned after && or ||, so it may not have run")
                elif value is None:
                    reasons = "; ".join(assignment.value.unknown_reasons) or "its value is not known"
                    known = Unknown(f"assigned from a word we could not resolve: {reasons}")
                elif "\0" in value:
                    known = Unknown("its value contains a NUL byte, which bash cannot hold")
                else:
                    known = value
                events.append((assignment.pos, assignment.name, known))
    for effect in effects:
        if effect.kind is not EffectKind.ENV_MUTATE:
            continue
        pos = getattr(effect.origin, "pos", -1)
        if pos in assignment_positions:
            continue  # the assignment itself, already handled above
        if isinstance(effect.target, Variable):
            events.append((pos, effect.target.name, Unknown(f"changed by a command at offset {pos}")))
        else:
            events.append((pos, None, Unknown("changed by a command we could not follow")))
    events.sort(key=lambda event: event[0])
    return [(name, value) for _, name, value in events]
