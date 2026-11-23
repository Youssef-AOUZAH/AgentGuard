"""Tests for the gate, the session and the sandboxed executor.

The middle end does not exist yet, so the analyzer here is a table from command text to a
decision. What is under test is everything around it: that refusals never run, that what runs is
the emitted command in the sandbox, that the executor's observations are the right effects, that
the session follows the shell, that the classifier only tightens, and that failures refuse.

Every command run here is written in this file and runs inside a `TempDirExecutor`, as the hard
rules in `AGENTS.md` require for anything the gate executes.
"""

from __future__ import annotations

import os
import shutil
from pathlib import PurePosixPath

import pytest

from classifier.labels import ClassifierInput
from classifier.pipeline import RetryClassifier, StubScorer
from compiler.syntax import Script
from compiler.types import (
    Decision,
    Effect,
    EffectKind,
    Known,
    Reason,
    RuleId,
    SessionState,
    Unknown,
    Variable,
    Verdict,
)
from gate.executor import TempDirExecutor
from gate.gate import Gate
from gate.message import INTERNAL_ERROR, REFUSED, render
from gate.types import MessageLevel

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash is not installed")

ALLOW = Decision(Verdict.ALLOW)


class TableAnalyzer:
    """Returns the decision listed for a command's source text, and ALLOW otherwise."""

    def __init__(self, table: dict[str, Decision] | None = None, effects=None):
        self.table = table or {}
        self.effects = effects or (lambda script: frozenset())
        self.seen: list[SessionState] = []

    def analyze(self, script: Script, state: SessionState):
        self.seen.append(state)
        return self.effects(script), self.table.get(script.src, ALLOW)


class Always:
    def __init__(self, answer: bool):
        self.answer = answer
        self.asked: list[str] = []

    def approve(self, command, decision):
        self.asked.append(command)
        return self.answer


def deny(rule=RuleId.R4, detail="") -> Decision:
    return Decision(Verdict.DENY, (Reason(rule, None, detail),))


@pytest.fixture
def box():
    with TempDirExecutor(timeout=10) as executor:
        yield executor


def make_gate(box, **kwargs) -> Gate:
    kwargs.setdefault("analyzer", TableAnalyzer())
    return Gate(box, box.initial_state(), **kwargs)


def ws(box, *parts) -> PurePosixPath:
    return box.workspace.joinpath(*parts)


# --------------------------------------------------------------------------- refusals do not run


def test_unparseable_command_is_denied_under_r1_and_not_run(box):
    gate = make_gate(box)
    outcome = gate.submit("if true; then touch made; fi")
    assert outcome.verdict is Verdict.DENY
    assert outcome.decision.reasons[0].rule is RuleId.R1
    assert "control-structure" in outcome.decision.reasons[0].detail
    assert not outcome.executed
    assert box.real_path(ws(box, "made")) is not None and not box.real_path(ws(box, "made")).exists()


def test_denied_command_is_not_run_and_is_remembered(box):
    gate = make_gate(box, analyzer=TableAnalyzer({"touch secret": deny()}))
    outcome = gate.submit("touch secret")
    assert outcome.verdict is Verdict.DENY and not outcome.executed
    assert not box.real_path(ws(box, "secret")).exists()
    assert [e.command for e in gate.state.denied] == ["touch secret"]
    assert gate.state.denied[0].turn == 0


def test_escalate_without_an_approver_is_refused(box):
    gate = make_gate(box, analyzer=TableAnalyzer({"touch x": Decision(Verdict.ESCALATE)}))
    outcome = gate.submit("touch x")
    assert outcome.verdict is Verdict.DENY
    assert outcome.decision.verdict is Verdict.ESCALATE
    assert outcome.message == REFUSED  # not even that approval was needed
    assert not box.real_path(ws(box, "x")).exists()


def test_escalate_with_approval_runs(box):
    approver = Always(True)
    gate = make_gate(box, analyzer=TableAnalyzer({"touch x": Decision(Verdict.ESCALATE)}), approver=approver)
    outcome = gate.submit("touch x")
    assert outcome.verdict is Verdict.ALLOW and outcome.executed
    assert approver.asked == ["touch x"]


def test_approver_cannot_release_a_deny(box):
    approver = Always(True)
    gate = make_gate(box, analyzer=TableAnalyzer({"touch x": deny()}), approver=approver)
    assert gate.submit("touch x").verdict is Verdict.DENY
    assert approver.asked == []


def test_without_a_middle_end_nothing_runs_unapproved(box):
    gate = Gate(box, box.initial_state())
    outcome = gate.submit("touch x")
    assert outcome.verdict is Verdict.DENY and not outcome.executed


def test_an_analyzer_crash_refuses(box):
    class Broken:
        def analyze(self, script, state):
            raise KeyError("boom")

    gate = make_gate(box, analyzer=Broken())
    outcome = gate.submit("touch x")
    assert outcome.verdict is Verdict.DENY and not outcome.executed
    assert outcome.message == INTERNAL_ERROR
    assert outcome.error.startswith("KeyError")
    assert gate.session.turn == 1


# --------------------------------------------------------------------------- what runs, and where


def test_runs_the_emitted_command_in_the_workspace(box):
    gate = make_gate(box)
    outcome = gate.submit("echo \"a  b\" $'c\\x41'; pwd")
    assert outcome.emitted == "'echo' 'a  b' 'cA'; 'pwd'"
    assert outcome.result.exit_code == 0
    assert outcome.result.stdout == f"a  b cA\n{box.workspace}\n"


def test_home_and_tilde_are_inside_the_sandbox(box):
    gate = make_gate(box)
    outcome = gate.submit("echo ~ $HOME")
    assert outcome.result.stdout == f"{box.home} {box.home}\n"


def test_developer_environment_is_not_inherited(box, monkeypatch):
    monkeypatch.setenv("AGENTGUARD_TEST_LEAK", "leaked")
    outcome = make_gate(box).submit('echo "[$AGENTGUARD_TEST_LEAK]"')
    assert outcome.result.stdout == "[]\n"


def test_exit_status_and_stderr_are_reported(box):
    outcome = make_gate(box).submit("ls does-not-exist")
    assert outcome.result.exit_code not in (0, None)
    assert "does-not-exist" in outcome.result.stderr


def test_timeout_is_reported(box):
    box.timeout = 0.5
    outcome = make_gate(box).submit("sleep 5")
    assert outcome.result.timed_out and outcome.result.exit_code is None


# --------------------------------------------------------------------------- observed effects (S8)


def kinds(outcome) -> set[tuple[EffectKind, PurePosixPath]]:
    return {(e.kind, e.target) for e in outcome.result.observed}


def test_created_file_is_a_write(box):
    outcome = make_gate(box).submit("echo hi > new.txt")
    assert kinds(outcome) == {(EffectKind.WRITE, ws(box, "new.txt"))}
    assert all(e.origin.src == "echo hi > new.txt" for e in outcome.result.observed)


def test_append_rewrite_and_delete_are_told_apart(box):
    gate = make_gate(box)
    gate.submit("echo one > a; echo one > b; echo one > c")
    outcome = gate.submit("echo two >> a; echo new > b; rm c")
    assert kinds(outcome) == {
        (EffectKind.APPEND, ws(box, "a")),
        (EffectKind.WRITE, ws(box, "b")),
        (EffectKind.DELETE, ws(box, "c")),
    }


def test_directories_and_home_are_observed(box):
    outcome = make_gate(box).submit("mkdir -p d/e; touch ~/f")
    assert kinds(outcome) == {
        (EffectKind.WRITE, ws(box, "d")),
        (EffectKind.WRITE, ws(box, "d", "e")),
        (EffectKind.WRITE, box.home / "f"),
    }


def test_a_command_that_changes_nothing_observes_nothing(box):
    gate = make_gate(box)
    gate.submit("echo x > f")
    assert make_gate(box).submit("cat f").result.observed == frozenset()


@pytest.mark.skipif(os.name != "posix", reason="Windows has no execute bits to observe")
def test_granting_execute_is_a_privilege_change(box):
    gate = make_gate(box)
    gate.submit("echo x > f")
    assert (EffectKind.PRIV_CHANGE, ws(box, "f")) in kinds(gate.submit("chmod +x f"))


# --------------------------------------------------------------------------- the session follows the shell


def test_cd_moves_the_session(box):
    gate = make_gate(box)
    gate.submit("mkdir sub")
    gate.submit("cd sub")
    assert gate.state.cwd == ws(box, "sub")
    assert gate.submit("pwd").result.stdout == f"{ws(box, 'sub')}\n"


def test_cd_inside_a_subshell_does_not_move_the_session(box):
    gate = make_gate(box)
    gate.submit("mkdir sub; (cd sub)")
    assert gate.state.cwd == box.workspace


def test_cd_after_a_failing_command_follows_what_bash_did(box):
    gate = make_gate(box)
    gate.submit("mkdir sub; false && cd sub")
    assert gate.state.cwd == box.workspace


def test_known_assignment_is_tracked_and_replayed(box):
    gate = make_gate(box)
    gate.submit("X='a b'")
    assert gate.state.variables["X"] == "a b"
    assert gate.submit('echo "$X"').result.stdout == "a b\n"


def test_unknown_assignment_is_tracked_as_unknown_and_not_replayed(box):
    gate = make_gate(box)
    gate.submit("X=$(echo hi)")
    assert isinstance(gate.state.variables["X"], Unknown)
    assert gate.submit('echo "[$X]"').result.stdout == "[]\n"


def test_assignment_that_may_not_run_is_unknown(box):
    gate = make_gate(box)
    gate.submit("true || X=1")
    assert isinstance(gate.state.variables["X"], Unknown)


def test_assignment_in_a_pipeline_or_prefix_is_not_tracked(box):
    gate = make_gate(box)
    gate.submit("X=1 | cat; Y=2 env")
    assert "X" not in gate.state.variables and "Y" not in gate.state.variables


def test_env_mutate_effect_invalidates_the_variable(box):
    def effects(script):
        if script.src == "read X":
            return frozenset({Effect(EffectKind.ENV_MUTATE, Variable("X"), Known(), script)})
        if script.src == "unset $V":
            return frozenset({Effect(EffectKind.ENV_MUTATE, None, Unknown("name not known"), script)})
        return frozenset()

    gate = make_gate(box, analyzer=TableAnalyzer(effects=effects))
    gate.submit("X=1; Y=2")
    gate.submit("read X")
    assert isinstance(gate.state.variables["X"], Unknown) and gate.state.variables["Y"] == "2"
    gate.submit("unset $V")
    assert all(isinstance(v, Unknown) for v in gate.state.variables.values())


def test_analyzer_sees_the_state_before_the_command(box):
    analyzer = TableAnalyzer()
    gate = make_gate(box, analyzer=analyzer)
    gate.submit("mkdir sub; cd sub")
    gate.submit("true")
    assert [s.cwd for s in analyzer.seen] == [box.workspace, ws(box, "sub")]


def test_turns_count_every_command(box):
    gate = make_gate(box, analyzer=TableAnalyzer({"false": deny()}))
    for command in ("true", "false", "if", "true"):
        gate.submit(command)
    assert gate.session.turn == 4
    assert [e.turn for e in gate.state.denied] == [1, 2]


# --------------------------------------------------------------------------- the classifier only tightens


def retry_classifier(p_retry: float) -> RetryClassifier:
    seen: list[ClassifierInput] = []

    def scores(inp):
        seen.append(inp)
        return {"retry-blocked-effect": p_retry, "obfuscation": 0.0, "benign-next-step": 1 - p_retry}

    classifier = RetryClassifier(StubScorer(scores), {"retry-blocked-effect": 0.5, "benign-next-step": 0.5})
    classifier.seen = seen  # type: ignore[attr-defined]
    return classifier


def test_classifier_is_not_consulted_before_any_refusal(box):
    classifier = retry_classifier(0.9)
    make_gate(box, classifier=classifier).submit("true")
    assert classifier.seen == []


def test_classifier_tightens_a_retry_after_a_refusal(box):
    classifier = retry_classifier(0.9)
    gate = make_gate(box, analyzer=TableAnalyzer({"rm -rf ~": deny()}), classifier=classifier)
    gate.submit("rm -rf ~")
    outcome = gate.submit("find ~ -delete")
    assert outcome.verdict is Verdict.DENY and not outcome.executed
    assert outcome.decision.verdict is Verdict.ESCALATE
    assert outcome.decision.reasons[-1].rule is RuleId.R9
    inp = classifier.seen[0]
    assert (inp.rejected_command, inp.new_command, inp.turns_since) == ("rm -rf ~", "find ~ -delete", 1)
    assert inp.rejected_rules == ("R4",)


def test_benign_label_never_loosens_anything(box):
    classifier = retry_classifier(0.1)
    gate = make_gate(box, analyzer=TableAnalyzer({"a": deny(), "touch b": Decision(Verdict.ESCALATE)}))
    gate.classifier = classifier
    gate.submit("a")
    outcome = gate.submit("touch b")
    assert outcome.verdict is Verdict.DENY  # still escalated, still no approver


def test_classifier_failure_escalates(box):
    class Broken:
        def score(self, inp):
            raise RuntimeError("model missing")

    gate = make_gate(box, analyzer=TableAnalyzer({"a": deny()}), classifier=RetryClassifier(Broken(), {}))
    gate.submit("a")
    outcome = gate.submit("true")
    assert outcome.decision.verdict is Verdict.ESCALATE and not outcome.executed


# --------------------------------------------------------------------------- messages (gate H1)


def test_message_levels():
    effect = Effect(EffectKind.DELETE, PurePosixPath("/home/u/.ssh"), Known(), Script((), ""))
    decision = Decision(Verdict.DENY, (Reason(RuleId.R4, effect, "zone secret"),))
    assert render(Verdict.DENY, decision, MessageLevel.GENERIC) == REFUSED
    escalated = Decision(Verdict.ESCALATE, (Reason(RuleId.R10, effect),))
    assert render(Verdict.DENY, escalated, MessageLevel.GENERIC) == REFUSED
    rule = render(Verdict.DENY, decision, MessageLevel.RULE)
    assert "R4 (path containment): delete" in rule and ".ssh" not in rule and "zone" not in rule
    detailed = render(Verdict.DENY, decision, MessageLevel.DETAILED)
    assert "delete /home/u/.ssh (zone secret)" in detailed
    assert render(Verdict.ALLOW, Decision(Verdict.ALLOW), MessageLevel.DETAILED) == ""


def test_every_refusal_reads_the_same_by_default(box):
    class Broken:
        def analyze(self, script, state):
            raise KeyError("boom")

    gate = make_gate(box, analyzer=TableAnalyzer({"touch a": deny(detail="zone secret")}))
    messages = {
        gate.submit("if true; then :; fi").message,  # unparseable
        gate.submit("touch a").message,  # denied by a rule
        make_gate(box, analyzer=Broken()).submit("true").message,  # internal failure
        Gate(box, box.initial_state()).submit("true").message,  # escalated, nobody to approve
    }
    assert messages == {"Command refused based on user rules."}


def test_r1_detail_is_shown_at_rule_level_for_experiments(box):
    outcome = make_gate(box, level=MessageLevel.RULE).submit("if true; then :; fi")
    assert "R1 (unparseable)" in outcome.message and "control-structure" in outcome.message


def test_timings_cover_every_stage_that_ran(box):
    outcome = make_gate(box).submit("true")
    assert {"parse", "analyze", "emit", "execute", "total"} <= set(outcome.timings)
