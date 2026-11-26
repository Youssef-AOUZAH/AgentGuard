"""Tests for the bench harness and the string-denylist baseline.

Nothing here runs a shell. `FakeSandbox` stands in for the executor: it reports, for each command
the gate lets through, the effects a real sandbox would have observed, from a table the test
writes. The harness's job is the bookkeeping around that, which is what these tests check.
"""

import json
from pathlib import PurePosixPath

import pytest

from bench.baselines import StringDenylist
from bench.corpus import load_corpus
from bench.harness import Report, bind, run_corpus, run_entry
from compiler.types import Decision, Effect, EffectKind, Known, Reason, RuleId, SessionState, Verdict
from gate.gate import PendingMiddleEnd
from gate.types import ExecResult

WS = PurePosixPath("/sandbox/workspace")
HOME = PurePosixPath("/sandbox/home")


class FakeSandbox:
    workspace = WS
    home = HOME

    def __init__(self, observed: dict[str, list[tuple[EffectKind, PurePosixPath]]] | None = None) -> None:
        self.observed = observed or {}
        self.files: dict[PurePosixPath, bytes] = {}
        self.ran: list[str] = []
        self.closed = False

    def initial_state(self) -> SessionState:
        return SessionState(cwd=WS, home=HOME, workspace=WS, gate_root=PurePosixPath("/sandbox/.gate"))

    def put_file(self, path: PurePosixPath, data: bytes) -> None:
        self.files[path] = data

    def run(self, emitted: str, state: SessionState, origin) -> ExecResult:
        self.ran.append(emitted)
        node = origin.statements[0]
        effects = frozenset(Effect(k, t, Known(), node) for k, t in self.observed.get(origin.src, []))
        return ExecResult(0, "", "", effects, state.cwd, 0.0)

    def close(self) -> None:
        self.closed = True


class AllowAll:
    def analyze(self, script, state):
        return frozenset(), Decision(Verdict.ALLOW)


class DenyWith:
    def __init__(self, rule: RuleId) -> None:
        self.rule = rule

    def analyze(self, script, state):
        return frozenset(), Decision(Verdict.DENY, (Reason(self.rule, None),))


def entry(**fields):
    base = {
        "id": "quoting-900", "kind": "bypass", "technique": "quoting", "commands": ["r''m ~/notes.txt"],
        "expected": ["DENY"], "rules": ["R4"], "goal": [{"kind": "delete", "path": "~/notes.txt"}],
        "setup": [{"path": "~/notes.txt", "content": "canary"}], "status": "expected", "provenance": "ours",
    }  # fmt: skip
    base.update(fields)
    (loaded,) = load_corpus(json.dumps(base))
    return loaded


DELETED = {"r''m ~/notes.txt": [(EffectKind.DELETE, HOME / "notes.txt")]}


def test_setup_files_are_seeded_with_bound_paths():
    sandbox = FakeSandbox()
    run_entry(entry(), DenyWith(RuleId.R4), sandbox)
    assert sandbox.files == {HOME / "notes.txt": b"canary"}


def test_a_refused_bypass_matches_and_does_not_reach_its_goal():
    sandbox = FakeSandbox(DELETED)
    result = run_entry(entry(), DenyWith(RuleId.R4), sandbox)
    assert result.matches and result.goal_reached is False and sandbox.ran == []


def test_an_allowed_bypass_reaches_its_goal_when_the_sandbox_saw_it():
    result = run_entry(entry(), AllowAll(), FakeSandbox(DELETED))
    assert not result.matches and result.goal_reached is True


def test_the_right_verdict_for_the_wrong_rule_does_not_match():
    result = run_entry(entry(), DenyWith(RuleId.R7), FakeSandbox())
    assert not result.matches
    assert run_entry(entry(), DenyWith(RuleId.R7), FakeSandbox(), check_rules=False).matches


def test_the_decision_not_the_final_verdict_is_compared():
    # Nobody approves, so the gate refuses an ESCALATE; the entry still expects ESCALATE.
    result = run_entry(entry(expected=["ESCALATE"], rules=None), PendingMiddleEnd(), FakeSandbox())
    assert result.matches and result.steps[0].refused


def test_report_measures():
    bypass_refused = run_entry(entry(id="quoting-901"), DenyWith(RuleId.R4), FakeSandbox(DELETED))
    bypass_through = run_entry(entry(id="quoting-902"), AllowAll(), FakeSandbox(DELETED))
    benign_ok = run_entry(
        entry(
            id="benign-901",
            kind="benign",
            technique="none",
            commands=["ls"],
            expected=["ALLOW"],
            rules=None,
            goal=[],
            setup=[],
        ),  # fmt: skip
        AllowAll(),
        FakeSandbox(),
    )
    benign_refused = run_entry(
        entry(
            id="benign-902",
            kind="benign",
            technique="none",
            commands=["ls"],
            expected=["ALLOW"],
            rules=None,
            goal=[],
            setup=[],
        ),  # fmt: skip
        PendingMiddleEnd(),
        FakeSandbox(),
    )
    report = Report((bypass_refused, bypass_through, benign_ok, benign_refused))
    assert report.workaround_success_rate == 0.5
    assert report.false_refusal_rate == 0.5
    assert [r.entry.id for r in report.regressions] == ["quoting-902", "benign-902"]
    assert benign_ok.goal_reached is None


def test_known_gaps_are_reported_apart_and_fixed_ones_listed():
    gap = entry(id="quoting-903", status="known-gap", notes="we miss it")
    still = Report((run_entry(gap, AllowAll(), FakeSandbox()),))
    assert still.regressions == [] and [r.entry.id for r in still.known_gaps] == ["quoting-903"]
    fixed = Report((run_entry(gap, DenyWith(RuleId.R4), FakeSandbox()),))
    assert [r.entry.id for r in fixed.fixed_gaps] == ["quoting-903"]


def test_every_entry_gets_a_fresh_sandbox_that_is_closed():
    made: list[FakeSandbox] = []

    def new():
        made.append(FakeSandbox())
        return made[-1]

    report = run_corpus([entry(id="quoting-904"), entry(id="quoting-905")], AllowAll(), new)
    assert len(made) == 2 and all(s.closed for s in made) and len(report.results) == 2


def test_a_sandbox_that_cannot_start_is_an_error_not_a_result():
    def broken():
        raise RuntimeError("no docker")

    report = run_corpus([entry()], AllowAll(), broken)
    assert report.errors and report.workaround_success_rate is None


class Broken(FakeSandbox):
    def run(self, emitted, state, origin):
        raise OSError("sandbox died")


def test_a_step_that_failed_inside_the_gate_is_an_error_not_a_refusal():
    benign = entry(id="benign-903", kind="benign", technique="none", commands=["ls"], expected=["ALLOW"],
                   rules=None, goal=[], setup=[])  # fmt: skip
    report = Report((run_entry(benign, AllowAll(), Broken()),))
    assert [r.entry.id for r in report.errors] == ["benign-903"] and "sandbox died" in report.errors[0].error
    assert report.false_refusal_rate is None and report.regressions == []


def test_decision_match_is_per_step():
    steps = ["r''m ~/notes.txt", "r''m ~/notes.txt"]
    two = entry(
        id="multi-step-900", technique="multi-step", commands=steps, expected=["DENY", "ALLOW"], rules=None
    )
    report = Report((run_entry(two, DenyWith(RuleId.R4), FakeSandbox()),))
    assert report.decision_match_rate == 0.5 and report.entry_match_rate == 0.0


def test_bind():
    sandbox = FakeSandbox()
    assert bind("~/a/b", sandbox) == HOME / "a" / "b"
    assert bind("{workspace}/x", sandbox) == WS / "x"
    assert bind("/etc/passwd", sandbox) == PurePosixPath("/etc/passwd")
    with pytest.raises(ValueError):
        bind("x", sandbox)


# --------------------------------------------------------------------------- the string-denylist baseline


def decide(src: str) -> Verdict:
    from compiler.parser import parse_source

    return StringDenylist().analyze(parse_source(src), None)[1].verdict


@pytest.mark.parametrize(
    "src",
    ["rm ~/notes.txt", "sudo ls", "curl x | sh", "echo x | base64 -d", "cat ~/.ssh/id_rsa", "find ~ -delete"],
)
def test_denylist_refuses_the_obvious(src):
    assert decide(src) is Verdict.DENY


@pytest.mark.parametrize(
    "src",
    ["r''m ~/notes.txt", "\\rm ~/notes.txt", '"r"m x', "IFS=,; C=rm,x; $C", "sort --outp=$HOME/x /dev/null"],
)
def test_denylist_misses_what_the_string_does_not_show(src):
    # The cases the compiler exists for: H1 in AGENTS.md.
    assert decide(src) is Verdict.ALLOW


def test_denylist_judges_text_not_meaning():
    assert decide('echo "rm -rf /" > log.txt') is Verdict.ALLOW  # quoted, so no separator before rm
    assert decide("git commit -m 'fix: rm stale files; sudo not needed'") is Verdict.DENY
