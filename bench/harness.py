"""The bench harness: runs corpus entries through a gate in a sandbox and scores them.

Takes in corpus entries (`bench/corpus.py`), the middle end under test (any `Analyzer`: the
compiler, a baseline such as `bench/baselines.py`, or an ablation), and a way to make a fresh
sandbox for each entry. Gives back a `Report` with the two measures `bench/schema.md` defines:

- **decision match:** for each step, whether the analyzer's decision equals the entry's
  `expected` verdict and, when the entry names one, cites its rule. This is `Outcome.decision`,
  the verdict the analyzer reached, as in the policy loader. An unapproved `ESCALATE` is refused
  by the gate either way, but the entry says which of the two we meant.
- **workaround success:** for a bypass, whether any `goal` effect appears among the effects the
  sandbox observed while running the steps the gate let through. It is defined only over the
  kinds the sandbox can observe (`gate.types.OBSERVABLE_KINDS`), which is all a `goal` may name.

Plus the false-refusal rate on benign entries: the share with any step refused.

**Each entry runs in its own fresh sandbox**, seeded with the entry's `setup` files, so no entry
can affect another. The command-line entry point uses `ContainerExecutor` and nothing else unless
it is told otherwise, because a baseline will allow commands the policy would refuse, and
`AGENTS.md` permits destructive commands only in a disposable sandbox. The host `TempDirExecutor`
confines nothing on its own (its docstring says so), so it is opt-in and meant for corpora whose
commands stay inside `~` and the workspace.

Known gaps are scored like everything else and reported apart. An entry whose status is
`known-gap` but whose decisions now match is listed as fixed, so its status can be updated.

What this module deliberately does not handle: the classifier (pass a gate factory that adds
one), agent runs, and anything that reads its own results back into the corpus.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol

from bench.corpus import Entry, Kind, Status, load_corpus_dir
from compiler.types import Effect, RuleId, SessionState, Verdict
from gate.gate import Gate
from gate.types import Analyzer, ExecResult


class Sandbox(Protocol):
    """What the harness needs from an executor: both `ContainerExecutor` and `TempDirExecutor`
    provide it, through `seed` for the one difference between them."""

    workspace: PurePosixPath
    home: PurePosixPath

    def run(self, emitted: str, state: SessionState, origin) -> ExecResult: ...

    def initial_state(self) -> SessionState: ...

    def close(self) -> None: ...


# --------------------------------------------------------------------------- results


@dataclass(frozen=True, slots=True)
class StepResult:
    command: str
    expected: Verdict
    rule: RuleId | None
    decided: Verdict | None  # the analyzer's decision; None if the gate failed before deciding
    cited: tuple[RuleId, ...]
    ran: bool
    observed: frozenset[Effect]
    error: str | None = None

    @property
    def matches(self) -> bool:
        return self.decided is self.expected and (self.rule is None or self.rule in self.cited)

    @property
    def refused(self) -> bool:
        return not self.ran


@dataclass(frozen=True, slots=True)
class EntryResult:
    entry: Entry
    steps: tuple[StepResult, ...]
    goal_reached: bool | None  # None for a benign entry, which has no goal
    error: str | None = None  # the sandbox itself failed; the entry was not scored

    @property
    def matches(self) -> bool:
        return self.error is None and all(step.matches for step in self.steps)


@dataclass(frozen=True, slots=True)
class Report:
    results: tuple[EntryResult, ...]

    @property
    def _scored(self) -> list[EntryResult]:
        """Entries that ran without an internal failure. The failed ones are in `errors`."""
        return [r for r in self.results if r.error is None]

    def _of(self, kind: Kind) -> list[EntryResult]:
        return [r for r in self.results if r.entry.kind is kind and r.error is None]

    @property
    def regressions(self) -> list[EntryResult]:
        """Entries we expect to pass that do not: these fail a run."""
        return [r for r in self._scored if r.entry.status is Status.EXPECTED and not r.matches]

    @property
    def known_gaps(self) -> list[EntryResult]:
        return [r for r in self._scored if r.entry.status is Status.KNOWN_GAP and not r.matches]

    @property
    def fixed_gaps(self) -> list[EntryResult]:
        """Known gaps that now pass: update their status in the corpus."""
        return [r for r in self.results if r.entry.status is Status.KNOWN_GAP and r.matches]

    @property
    def errors(self) -> list[EntryResult]:
        return [r for r in self.results if r.error is not None]

    @property
    def workaround_success_rate(self) -> float | None:
        bypasses = self._of(Kind.BYPASS)
        return sum(bool(r.goal_reached) for r in bypasses) / len(bypasses) if bypasses else None

    @property
    def false_refusal_rate(self) -> float | None:
        benign = self._of(Kind.BENIGN)
        return sum(any(s.refused for s in r.steps) for r in benign) / len(benign) if benign else None

    @property
    def decision_match_rate(self) -> float | None:
        """Per step, as `bench/schema.md` defines it, so corpora with different numbers of steps
        per entry compare."""
        steps = [s for r in self.results if r.error is None for s in r.steps]
        return sum(s.matches for s in steps) / len(steps) if steps else None

    @property
    def entry_match_rate(self) -> float | None:
        """The share of entries whose every step matches."""
        scored = [r for r in self.results if r.error is None]
        return sum(r.matches for r in scored) / len(scored) if scored else None

    def summary(self) -> dict[str, object]:
        return {
            "entries": len(self.results),
            "decision_match_rate": self.decision_match_rate,
            "entry_match_rate": self.entry_match_rate,
            "workaround_success_rate": self.workaround_success_rate,
            "false_refusal_rate": self.false_refusal_rate,
            "regressions": [r.entry.id for r in self.regressions],
            "known_gaps": [r.entry.id for r in self.known_gaps],
            "fixed_gaps": [r.entry.id for r in self.fixed_gaps],
            "errors": {r.entry.id: r.error for r in self.errors},
        }


# --------------------------------------------------------------------------- running


GateFactory = Callable[[Sandbox, SessionState, Analyzer], Gate]


def default_gate(sandbox: Sandbox, state: SessionState, analyzer: Analyzer) -> Gate:
    """A gate with no classifier and no approver: an `ESCALATE` is refused, as when nobody is
    watching."""
    return Gate(sandbox, state, analyzer=analyzer)


def run_entry(
    entry: Entry,
    analyzer: Analyzer,
    sandbox: Sandbox,
    make_gate: GateFactory = default_gate,
    check_rules: bool = True,
) -> EntryResult:
    """Run one entry in `sandbox`, which must be fresh, and score it. With `check_rules` off, only
    verdicts are compared, which is how a baseline that cites none of our rules is scored."""
    try:
        for file in entry.setup:
            seed(sandbox, bind(file.path, sandbox), file.content.encode("utf-8"))
        gate = make_gate(sandbox, sandbox.initial_state(), analyzer)
    except Exception as exc:  # a sandbox that cannot be prepared is not a result about the gate
        return EntryResult(entry, (), None, error=f"{type(exc).__name__}: {exc}")
    steps = []
    for command, expected, rule in zip(entry.commands, entry.expected, entry.rules, strict=True):
        outcome = gate.submit(command)
        decision = outcome.decision
        steps.append(
            StepResult(
                command=command,
                expected=expected,
                rule=rule if check_rules else None,
                decided=decision.verdict if decision is not None else None,
                cited=tuple(dict.fromkeys(r.rule for r in decision.reasons)) if decision is not None else (),
                ran=outcome.executed,
                observed=outcome.result.observed if outcome.result is not None else frozenset(),
                error=outcome.error,
            )
        )
    goal_reached = None if entry.kind is Kind.BENIGN else _reached(entry, sandbox, steps)
    failed = [f"step {i + 1}: {s.error}" for i, s in enumerate(steps) if s.error is not None]
    # An internal failure is refused by the gate, but it is not a decision: scoring it would count
    # a broken sandbox or analyzer as a refusal. It is reported, and fails the run, instead.
    return EntryResult(entry, tuple(steps), goal_reached, error="; ".join(failed) or None)


def run_corpus(
    entries: Iterable[Entry],
    analyzer: Analyzer,
    new_sandbox: Callable[[], Sandbox],
    make_gate: GateFactory = default_gate,
    check_rules: bool = True,
) -> Report:
    """Run every entry in a sandbox of its own, closing each one afterwards."""
    results = []
    for entry in entries:
        try:
            sandbox = new_sandbox()
        except Exception as exc:
            results.append(EntryResult(entry, (), None, error=f"{type(exc).__name__}: {exc}"))
            continue
        try:
            results.append(run_entry(entry, analyzer, sandbox, make_gate, check_rules))
        finally:
            sandbox.close()
    return Report(tuple(results))


def bind(path: str, sandbox: Sandbox) -> PurePosixPath:
    """A corpus path with its anchor bound to the sandbox (`bench/schema.md`, "Paths")."""
    if path.startswith("~/"):
        return sandbox.home / path[2:]
    if path.startswith("{workspace}/"):
        return sandbox.workspace / path[len("{workspace}/") :]
    if path.startswith("/"):
        return PurePosixPath(path)
    raise ValueError(f"path {path!r} has no anchor; the corpus loader should have refused it")


def seed(sandbox: Sandbox, path: PurePosixPath, data: bytes) -> None:
    """Create a file in the sandbox before the first command."""
    put_file = getattr(sandbox, "put_file", None)
    if put_file is not None:
        put_file(path, data)
        return
    real_path = getattr(sandbox, "real_path", None)
    real = real_path(path) if real_path is not None else None
    if real is None:
        raise ValueError(f"cannot place {path} in this sandbox")
    real.parent.mkdir(parents=True, exist_ok=True)
    real.write_bytes(data)


def _reached(entry: Entry, sandbox: Sandbox, steps: list[StepResult]) -> bool:
    wanted = {(goal.kind, bind(goal.path, sandbox)) for goal in entry.goal}
    observed = {(e.kind, e.target) for step in steps for e in step.observed}
    return bool(wanted & observed)


# --------------------------------------------------------------------------- command line


def _analyzer(name: str) -> Analyzer:
    if name == "pending":
        from gate.gate import PendingMiddleEnd

        return PendingMiddleEnd()
    if name == "denylist":
        from bench.baselines import StringDenylist

        return StringDenylist()
    if name == "compiler":
        try:
            from gate.policy_loader import CompilerAnalyzer, load_policy_file
        except ImportError as exc:  # until the policy loader is merged
            raise SystemExit(f"the compiler analyzer is not available yet: {exc}") from exc
        from gate.container import ContainerExecutor

        # The policy's own tests run against the container's layout, where the corpus runs.
        state = SessionState(
            cwd=ContainerExecutor.workspace,
            home=ContainerExecutor.home,
            workspace=ContainerExecutor.workspace,
            gate_root=PurePosixPath("/sandbox/.gate"),
        )
        root = Path(__file__).resolve().parents[1]
        return CompilerAnalyzer(load_policy_file(root / "policies" / "default.pol", state))
    raise SystemExit(f"unknown analyzer {name!r}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score a corpus against a middle end, in a sandbox.")
    parser.add_argument("--analyzer", choices=["compiler", "denylist", "pending"], default="compiler")
    parser.add_argument("--corpus", type=Path, default=Path(__file__).resolve().parent / "corpus")
    parser.add_argument(
        "--host-tempdir",
        action="store_true",
        help="run in a host temporary directory instead of a container; it confines nothing, so use "
        "it only for corpora whose commands stay inside ~ and the workspace",
    )
    args = parser.parse_args(argv)
    entries = load_corpus_dir(args.corpus)
    if args.host_tempdir:
        from gate.executor import TempDirExecutor

        new_sandbox: Callable[[], Sandbox] = TempDirExecutor
    else:
        from gate.container import ContainerExecutor, docker_available

        if not docker_available():
            raise SystemExit("docker is not available; the corpus runs only in a container by default")
        new_sandbox = ContainerExecutor
    report = run_corpus(
        entries, _analyzer(args.analyzer), new_sandbox, check_rules=args.analyzer == "compiler"
    )
    json.dump(report.summary(), sys.stdout, indent=2)
    print()
    return 1 if report.regressions or report.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
