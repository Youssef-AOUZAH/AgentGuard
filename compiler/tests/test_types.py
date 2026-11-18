"""Tests for the middle-end types in `compiler/types.py`.

These check the invariants the types enforce at construction, because the rest of the middle end
relies on them instead of re-checking: absolute paths with no `..`, the three resolution values,
a DENY that always cites a rule, a verdict order that only tightens, and a session state that
cannot be changed after it is built.
"""

import dataclasses
from pathlib import PurePosixPath

import pytest

from compiler.parser import parse_source
from compiler.syntax import simple_commands
from compiler.types import (
    DESTRUCTIVE_KINDS,
    PATH_KINDS,
    Bounded,
    Decision,
    DeniedEntry,
    Effect,
    EffectKind,
    Host,
    Known,
    Port,
    Program,
    Reason,
    RuleId,
    SessionState,
    Unknown,
    Verdict,
)

WS = PurePosixPath("/work/project")
HOME = PurePosixPath("/home/dev")


@pytest.fixture
def origin():
    """A real AST node, so effects are built against what the parser actually produces."""
    return next(simple_commands(parse_source("rm -rf build")))


def deny(effect: Effect | None = None) -> Decision:
    return Decision(Verdict.DENY, (Reason(RuleId.R4, effect, "outside workspace"),))


# --- Effects and resolution -------------------------------------------------


def test_known_effect_on_absolute_path(origin):
    effect = Effect(EffectKind.DELETE, WS / "build" / "out.o", Known(), origin)
    assert effect.target == PurePosixPath("/work/project/build/out.o")


def test_bounded_effect_bounds_a_directory(origin):
    effect = Effect(EffectKind.DELETE, WS / "build", Bounded(), origin)
    assert isinstance(effect.resolution, Bounded)


def test_unknown_effect_has_no_target_and_a_reason(origin):
    effect = Effect(EffectKind.DELETE, None, Unknown("command substitution"), origin)
    assert effect.resolution.reason == "command substitution"


@pytest.mark.parametrize("path", ["build/out.o", "./x", "~/x"])
def test_relative_path_is_rejected(origin, path):
    # A relative path's zone would depend on whoever reads it (interfaces.md S4).
    with pytest.raises(ValueError, match="absolute"):
        Effect(EffectKind.WRITE, PurePosixPath(path), Known(), origin)


def test_dotdot_is_rejected_because_containment_is_textual(origin):
    sneaky = PurePosixPath("/work/project/../../etc/passwd")
    # The reason the check exists: pathlib says this path is inside the workspace.
    assert sneaky.is_relative_to(WS)
    with pytest.raises(ValueError, match=r"\.\."):
        Effect(EffectKind.READ, sneaky, Known(), origin)


def test_leading_double_slash_is_rejected(origin):
    with pytest.raises(ValueError, match="//"):
        Effect(EffectKind.READ, PurePosixPath("//etc/passwd"), Known(), origin)


def test_unknown_with_a_target_is_rejected(origin):
    with pytest.raises(ValueError, match="no target"):
        Effect(EffectKind.DELETE, WS, Unknown("glob"), origin)


def test_unknown_needs_a_reason():
    with pytest.raises(ValueError, match="reason"):
        Unknown("")


def test_bounded_needs_a_path_target(origin):
    with pytest.raises(ValueError, match="directory"):
        Effect(EffectKind.NET_OUT, Host("pypi.org"), Bounded(), origin)


def test_non_path_targets(origin):
    assert Effect(EffectKind.NET_OUT, Host("pypi.org"), Known(), origin).target == Host("pypi.org")
    assert Effect(EffectKind.EXEC, Program("ls"), Known(), origin).target == Program("ls")
    with pytest.raises(ValueError):
        Host("PyPI.org")
    with pytest.raises(ValueError):
        Port(70000)


def test_effects_are_hashable_and_origin_counts(origin):
    # Effects travel in a set (interfaces.md S4), so they must hash over real AST nodes.
    other = next(simple_commands(parse_source("ls; rm -rf build")))
    a = Effect(EffectKind.DELETE, WS / "build", Bounded(), origin)
    b = Effect(EffectKind.DELETE, WS / "build", Bounded(), origin)
    c = Effect(EffectKind.DELETE, WS / "build", Bounded(), other)
    assert len({a, b, c}) == 2


def test_effects_are_immutable(origin):
    effect = Effect(EffectKind.READ, WS / "a", Known(), origin)
    with pytest.raises(dataclasses.FrozenInstanceError):
        effect.kind = EffectKind.WRITE


def test_kind_groups_match_the_rules():
    assert DESTRUCTIVE_KINDS == {
        EffectKind.WRITE,
        EffectKind.APPEND,
        EffectKind.DELETE,
        EffectKind.MOVE,
        EffectKind.PRIV_CHANGE,
    }
    assert DESTRUCTIVE_KINDS <= PATH_KINDS
    assert len(EffectKind) == 14


# --- Verdicts and decisions -------------------------------------------------


def test_verdict_order():
    assert Verdict.ALLOW < Verdict.ESCALATE < Verdict.DENY


@pytest.mark.parametrize("a", list(Verdict))
@pytest.mark.parametrize("b", list(Verdict))
def test_join_never_lowers(a, b):
    joined = a.join(b)
    assert joined >= a and joined >= b
    assert joined in (a, b)


def test_deny_must_cite_a_rule():
    with pytest.raises(ValueError, match="cite"):
        Decision(Verdict.DENY)


def test_r1_reason_has_no_effect():
    decision = Decision(Verdict.DENY, (Reason(RuleId.R1, None, "brace-group"),))
    assert decision.reasons[0].effect is None


def test_tighten_cannot_lower_a_deny(origin):
    effect = Effect(EffectKind.DELETE, PurePosixPath("/"), Bounded(), origin)
    denied = deny(effect)
    combined = denied.tighten(Decision(Verdict.ALLOW))
    assert combined.verdict is Verdict.DENY
    assert combined.reasons == denied.reasons


def test_tighten_raises_and_keeps_both_reasons(origin):
    effect = Effect(EffectKind.EXEC, Program("python"), Known(), origin)
    allowed = Decision(Verdict.ALLOW)
    flagged = Decision(Verdict.ESCALATE, (Reason(RuleId.R9, effect, "retry"),))
    combined = allowed.tighten(flagged)
    assert combined.verdict is Verdict.ESCALATE
    assert [r.rule for r in combined.reasons] == [RuleId.R9]


# --- Session state ----------------------------------------------------------


def test_session_state_paths_must_be_absolute():
    with pytest.raises(ValueError, match="absolute"):
        SessionState(cwd=PurePosixPath("project"), home=HOME, workspace=WS)


def test_session_state_variables_are_read_only_and_copied():
    source = {"D": "/etc"}
    state = SessionState(cwd=WS, home=HOME, workspace=WS, variables=source)
    source["D"] = "/tmp"
    assert state.variables["D"] == "/etc"
    with pytest.raises(TypeError):
        state.variables["D"] = "/tmp"


def test_session_state_is_updated_by_replacement():
    state = SessionState(cwd=WS, home=HOME, workspace=WS)
    moved = dataclasses.replace(state, cwd=WS / "src")
    assert state.cwd == WS and moved.cwd == WS / "src"


def test_untracked_value_is_recorded_as_unknown():
    state = SessionState(cwd=WS, home=HOME, workspace=WS, variables={"X": Unknown("from $(...)")})
    assert isinstance(state.variables["X"], Unknown)


def test_denied_history_rejects_allowed_commands():
    with pytest.raises(ValueError, match="allowed"):
        DeniedEntry(turn=0, command="ls", decision=Decision(Verdict.ALLOW))


def test_denied_history_entry(origin):
    entry = DeniedEntry(turn=3, command="rm -rf build", decision=deny())
    state = SessionState(cwd=WS, home=HOME, workspace=WS, denied=(entry,))
    assert state.denied[0].turn == 3
