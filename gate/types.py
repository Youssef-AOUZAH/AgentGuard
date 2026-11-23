"""Gate types: what the executor reports, what the gate returns, and the stages it plugs in.

`ExecResult` is seam S8 in `docs/interfaces.md`: the executor (3a) produces it and the bench
metrics (3b) consume it, comparing `observed` with the effects the compiler predicted. The
executor maps its filesystem observations into `Effect` records itself, so both ends of that
comparison are `Effect` sets; see the S8 entry in `docs/decisions.md`. Only the kinds in
`OBSERVABLE_KINDS` can ever appear in `observed`, and the metrics must restrict the predicted
set to the same kinds before comparing, or every `READ` counts as a miss.

`Analyzer` is how the middle end (resolver, effect analysis, policy; piece 1b) plugs into the
gate. The gate does not import `compiler/resolve.py`, `compiler/effects.py` or
`compiler/policy.py` directly, so it can be built and tested before they exist, and so the bench
can run the gate with a different middle end (a string denylist baseline is an `Analyzer` too).

Takes in: nothing. Declares types only. Does not decide anything.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Protocol

from compiler.syntax import Script
from compiler.types import Decision, Effect, EffectKind, SessionState, Verdict

# Effects a filesystem diff can show. Reads, execs, network traffic and signals leave no trace in
# a before-and-after snapshot, so they are never observed, and the paper must say the workaround
# metric is defined over this subset.
OBSERVABLE_KINDS: frozenset[EffectKind] = frozenset(
    {EffectKind.WRITE, EffectKind.APPEND, EffectKind.DELETE, EffectKind.PRIV_CHANGE}
)


@dataclass(frozen=True, slots=True)
class ExecResult:
    """What happened when the executor ran one emitted command (seam S8).

    `exit_code` is None when the command was killed for running past the timeout. `cwd` is the
    directory the shell was in when the command finished, reported by the shell itself, or None
    when the command left without reporting it (for example by resetting the exit trap); the
    session then falls back to the working directory it predicted. `stdout` and `stderr` are
    truncated to the executor's output limit, and `truncated` says whether that happened.
    """

    exit_code: int | None
    stdout: str
    stderr: str
    observed: frozenset[Effect]
    cwd: PurePosixPath | None
    duration: float
    timed_out: bool = False
    truncated: bool = False


class Executor(Protocol):
    """Runs an emitted command somewhere it cannot hurt anything that matters."""

    def run(self, emitted: str, state: SessionState, origin: Script) -> ExecResult: ...


class Analyzer(Protocol):
    """The middle end as the gate sees it: resolve, compute effects, decide.

    Must not mutate `state` (it cannot: `SessionState` is frozen) and must fail closed. An
    exception escaping `analyze` is caught by the gate and turned into a refusal, but an analyzer
    that returns `ALLOW` on input it did not understand is a bypass the gate cannot see.
    """

    def analyze(self, script: Script, state: SessionState) -> tuple[frozenset[Effect], Decision]: ...


class Approver(Protocol):
    """A human asked to approve an `ESCALATE`. Absent means nobody is watching, and an
    `ESCALATE` is then refused (`docs/policy-rules.md` §3)."""

    def approve(self, command: str, decision: Decision) -> bool: ...


class MessageLevel(StrEnum):
    """How much a refusal tells the agent. `GENERIC` is the decided default and the only level
    for real use (`docs/decisions.md`, "What does a rejection tell the agent?"); the other two
    exist only so gate hypothesis H1 can measure what a more informative message changes."""

    GENERIC = "generic"  # "Command refused based on user rules." and nothing else
    RULE = "rule"  # experiment only: the rule id and name, and the kind of effect
    DETAILED = "detailed"  # also the target and the part of the command responsible


@dataclass(frozen=True, slots=True)
class Outcome:
    """Everything the gate did with one command.

    `verdict` is final: after the classifier tightened it and after an `ESCALATE` was put to the
    approver, or refused for want of one. `decision` is what the analyzer and the classifier
    produced, before that last step, so the two can differ: an unapproved `ESCALATE` has a
    `decision` of `ESCALATE` and a `verdict` of `DENY`. `decision` is None only when the gate
    failed internally before any stage could decide, and `error` then says what went wrong.

    `emitted` is the command that was handed to the executor, when one was; it is our canonical
    re-serialisation, never the agent's text. `timings` holds seconds per stage.
    """

    turn: int
    command: str
    verdict: Verdict
    message: str
    decision: Decision | None = None
    effects: frozenset[Effect] = frozenset()
    emitted: str | None = None
    result: ExecResult | None = None
    classifier: Mapping[str, float] | None = None
    error: str | None = None
    timings: Mapping[str, float] = field(default_factory=dict)

    @property
    def executed(self) -> bool:
        return self.result is not None
