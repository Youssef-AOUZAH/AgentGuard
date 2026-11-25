"""The policy loader (piece 3a): turns a `.pol` file into a policy the gate may use, or refuses it.

Takes in a policy file's text and the session state the gate will start from. Returns the checked
`PolicyFile`, or raises `PolicyLoadError` with every reason it cannot be used. A policy is usable
only if it parses and checks cleanly (`compiler/policy_parser.py`) **and every one of its own
`expect` tests passes**. A policy that says "`rm -rf ~/*` is denied" and then allows it is worse
than no policy, because it would be trusted.

**How an `expect` test runs.** Each test starts from the given state with an empty history and is
played through a real `Gate`. That means the whole compiler (parse, resolve, effects, evaluate)
and the gate's own session updates (`gate/session.py`) run between commands, exactly as they
would for an agent. The commands in `after` go first, in order. A refused one is recorded in the
session's denied history (so R9 can see it) and leaves the working directory where it was; an
allowed one moves the session as it would have. Then the tested command is decided, and its
verdict, and the rule when the test names one, are compared with the expectation.

**Nothing is executed.** The gate is given `DryRunExecutor`, which runs no shell. In place of the
working directory a real shell would report, it predicts it with the resolver: the directory the
script would end in, when that is a single known path. A test whose `after` commands depend on
something only a shell could know is a bad test, and the prediction keeps the old directory.

`expect` compares the decision the policy reached (`Outcome.decision`), not the gate's final
verdict. So `expect escalate` means the policy escalated, even though, with nobody to approve it,
the gate would then refuse the command.

**The gate root.** `checkout_root` names the agentGuard checkout the way bash names it, which is
what `SessionState.gate_root` should be when the gate runs on a real machine: R8 then protects
the gate's code, policies and logs. The container sandbox uses its own `/sandbox/.gate`, since
the checkout is not inside the container.

Deliberately not handled: choosing which policy file to load, and watching it for changes.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath

from compiler.effects import effects_of
from compiler.parser import parse_source
from compiler.policy import evaluate
from compiler.policy_parser import parse_policy
from compiler.policy_syntax import Expect, PolicyError, PolicyFile
from compiler.resolve import resolve
from compiler.syntax import AndOr, AndOrOp, Pipeline, Script, Statement
from compiler.types import Decision, Effect, RuleId, SessionState, Verdict
from gate.gate import Gate
from gate.types import ExecResult

CHECKOUT = Path(__file__).resolve().parents[1]
_NOOP = parse_source(":").statements[0]


class CompilerAnalyzer:
    """The middle end behind the gate's `Analyzer` interface: resolve, compute effects, decide
    against `policy`. Exceptions are left to the gate, which turns them into refusals."""

    def __init__(self, policy: PolicyFile) -> None:
        self.policy = policy

    def analyze(self, script: Script, state: SessionState) -> tuple[frozenset[Effect], Decision]:
        effects = effects_of(resolve(script, state), state)
        return effects, evaluate(self.policy, script, effects, state)


class DryRunExecutor:
    """An executor that runs nothing. It reports success, no output and no observed effects, and
    predicts the working directory the script would end in, so the session moves as it would."""

    def run(self, emitted: str, state: SessionState, origin: Script) -> ExecResult:
        return ExecResult(
            exit_code=0,
            stdout="",
            stderr="",
            observed=frozenset(),
            cwd=predicted_cwd(origin, state),
            duration=0.0,
        )


def predicted_cwd(script: Script, state: SessionState) -> PurePosixPath | None:
    """Where `script` would leave the shell if every command in it succeeds, when the resolver
    can name one directory for that.

    A dry run assumes success, since nothing really runs. So the prediction joins the script's
    statements with `&&` and appends `:` (a command that does nothing): `:` then runs only on the
    path where everything succeeded, and the resolver says where that is, following every `cd`
    with its own rules. `&&` and `||` have equal precedence and group to the left, so `a || b; c`
    becomes `a || b && c && :`, which keeps each statement's meaning. None when a statement is
    backgrounded, or the place is unknown or one of several.
    """
    if not script.statements or any(s.background for s in script.statements):
        return None
    rest: list[tuple[AndOrOp, Pipeline]] = list(script.statements[0].and_or.rest)
    for statement in (*script.statements[1:], _NOOP):
        rest.append((AndOrOp.AND, statement.and_or.first))
        rest.extend(statement.and_or.rest)
    chained = AndOr(script.statements[0].and_or.first, 0, tuple(rest))
    commands = resolve(Script((Statement(chained, 0),), script.src), state).commands
    if not commands:
        return None
    cwd = commands[-1].cwd
    if isinstance(cwd, tuple) and len(cwd) == 1:
        return cwd[0]
    return None


@dataclass(frozen=True, slots=True)
class ExpectFailure:
    """One `expect` test that the policy did not meet."""

    expect: Expect
    verdict: Verdict | None  # what the policy decided; None if the gate failed before deciding
    rules: tuple[RuleId, ...]
    detail: str

    def __str__(self) -> str:
        wanted = f"{self.expect.verdict.name.lower()}" + (f" {self.expect.rule}" if self.expect.rule else "")
        after = f" after {', '.join(repr(a) for a in self.expect.after)}" if self.expect.after else ""
        return f"expect {wanted} {self.expect.command!r}{after}: {self.detail}"


class PolicyLoadError(Exception):
    """The policy cannot be used. `errors` are problems in the file itself; `failures` are its own
    tests that it does not pass. At least one of the two is non-empty."""

    def __init__(
        self, errors: tuple[PolicyError, ...] = (), failures: tuple[ExpectFailure, ...] = ()
    ) -> None:
        self.errors = errors
        self.failures = failures
        lines = [str(e) for e in errors] + [str(f) for f in failures]
        super().__init__("the policy cannot be loaded:\n" + "\n".join(f"  {line}" for line in lines))


def load_policy(src: str, state: SessionState) -> PolicyFile:
    """Parse, check and test a policy. Returns it only if all three succeed."""
    result = parse_policy(src)
    if result.policy is None:
        raise PolicyLoadError(errors=result.errors)
    failures = check_expects(result.policy, state)
    if failures:
        raise PolicyLoadError(failures=tuple(failures))
    return result.policy


def load_policy_file(path: Path, state: SessionState) -> PolicyFile:
    return load_policy(path.read_text(encoding="utf-8"), state)


def check_expects(policy: PolicyFile, state: SessionState) -> list[ExpectFailure]:
    """Every `expect` test in `policy` that fails, when run from `state`."""
    start = replace(state, denied=())
    return [failure for expect in policy.expects if (failure := _run(policy, expect, start)) is not None]


def _run(policy: PolicyFile, expect: Expect, state: SessionState) -> ExpectFailure | None:
    gate = Gate(DryRunExecutor(), state, analyzer=CompilerAnalyzer(policy))
    for command in expect.after:
        gate.submit(command)
    outcome = gate.submit(expect.command)
    if outcome.decision is None:
        return ExpectFailure(expect, None, (), f"the gate failed before deciding: {outcome.error}")
    decision = outcome.decision
    rules = tuple(dict.fromkeys(r.rule for r in decision.reasons))
    if decision.verdict is not expect.verdict:
        cited = ", ".join(map(str, rules)) or "no rule"
        return ExpectFailure(
            expect, decision.verdict, rules, f"got {decision.verdict.name.lower()} ({cited})"
        )
    if expect.rule is not None and expect.rule not in rules:
        cited = ", ".join(map(str, rules)) or "no rule"
        return ExpectFailure(
            expect, decision.verdict, rules, f"right verdict, but cited {cited}, not {expect.rule}"
        )
    return None


def checkout_root(bash: str | None = None) -> PurePosixPath:
    """The agentGuard checkout as bash names it: the gate root for runs on a real machine."""
    found = bash or shutil.which("bash")
    if found is None:
        raise RuntimeError("naming the checkout needs bash, and none was found on PATH")
    result = subprocess.run(
        [found, "--noprofile", "--norc", "-c", "builtin pwd -P"],
        cwd=CHECKOUT,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
    )
    return PurePosixPath(result.stdout.decode("utf-8").rstrip("\n"))
