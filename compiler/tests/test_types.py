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
    FILE_KINDS,
    PATH_KINDS,
    Bounded,
    Decision,
    DeniedEntry,
    Effect,
    EffectKind,
    Fd,
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
GATE = PurePosixPath("/opt/agentguard")


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


@pytest.mark.parametrize("kind", sorted(FILE_KINDS))
@pytest.mark.parametrize("target", [None, Host("example.com"), Fd(3)])
def test_file_effect_needs_a_path(origin, kind, target):
    # Without a path R4 has nothing to zone, and the effect would slip past it.
    with pytest.raises(ValueError, match="path target"):
        Effect(kind, target, Known(), origin)


@pytest.mark.parametrize("kind", sorted(FILE_KINDS))
def test_file_effect_without_a_path_is_unknown(origin, kind):
    effect = Effect(kind, None, Unknown("command substitution"), origin)
    assert effect.target is None


def test_priv_change_may_have_no_path(origin):
    # `sudo` has no path, and R5 denies every PRIV_CHANGE regardless.
    assert Effect(EffectKind.PRIV_CHANGE, None, Known(), origin).target is None
    assert Effect(EffectKind.PRIV_CHANGE, WS / "run.sh", Known(), origin).target == WS / "run.sh"


@pytest.mark.parametrize("resolution", [Known(), Bounded(), Unknown("glob")])
def test_move_is_never_an_effect(origin, resolution):
    target = None if isinstance(resolution, Unknown) else WS / "x"
    with pytest.raises(ValueError, match="DELETE of the source plus WRITE"):
        Effect(EffectKind.MOVE, target, resolution, origin)


def test_move_as_delete_plus_write_keeps_the_secret_visible(origin):
    # `mv ~/.ssh/id_rsa ./x`: the source is what makes it dangerous, so it must be its own effect.
    effects = {
        Effect(EffectKind.DELETE, HOME / ".ssh" / "id_rsa", Known(), origin),
        Effect(EffectKind.WRITE, WS / "x", Known(), origin),
    }
    assert {e.target for e in effects} == {HOME / ".ssh" / "id_rsa", WS / "x"}


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
        EffectKind.PRIV_CHANGE,
    }
    assert DESTRUCTIVE_KINDS <= PATH_KINDS
    assert PATH_KINDS - FILE_KINDS == {EffectKind.PRIV_CHANGE}
    assert EffectKind.MOVE not in PATH_KINDS
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


def test_r11_reason_has_no_effect():
    # R11 fires on the `&` separator, not on anything the command does.
    decision = Decision(Verdict.DENY, (Reason(RuleId.R11, None, "background"),))
    assert decision.reasons[0].rule == "R11"
    assert len(RuleId) == 11


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


def test_gate_root_is_required():
    with pytest.raises(TypeError):
        SessionState(cwd=WS, home=HOME, workspace=WS)  # type: ignore[call-arg]


@pytest.mark.parametrize("gate", ["/work", "/work/project", "/"])
def test_gate_root_must_not_contain_the_workspace(gate):
    with pytest.raises(ValueError, match="gate root"):
        SessionState(cwd=WS, home=HOME, workspace=WS, gate_root=PurePosixPath(gate))


def test_gate_root_may_sit_inside_the_workspace():
    # Unusual but coherent: R8 then protects that one subtree.
    state = SessionState(cwd=WS, home=HOME, workspace=WS, gate_root=WS / ".agentguard")
    assert state.gate_root == WS / ".agentguard"


def test_session_state_paths_must_be_absolute():
    with pytest.raises(ValueError, match="absolute"):
        SessionState(cwd=PurePosixPath("project"), home=HOME, workspace=WS, gate_root=GATE)
    with pytest.raises(ValueError, match="absolute"):
        SessionState(cwd=WS, home=HOME, workspace=WS, gate_root=PurePosixPath("gate"))


def test_session_state_variables_are_read_only_and_copied():
    source = {"D": "/etc"}
    state = SessionState(cwd=WS, home=HOME, workspace=WS, gate_root=GATE, variables=source)
    source["D"] = "/tmp"
    assert state.variables["D"] == "/etc"
    with pytest.raises(TypeError):
        state.variables["D"] = "/tmp"


def test_session_state_is_updated_by_replacement():
    state = SessionState(cwd=WS, home=HOME, workspace=WS, gate_root=GATE)
    moved = dataclasses.replace(state, cwd=WS / "src")
    assert state.cwd == WS and moved.cwd == WS / "src"


def test_untracked_value_is_recorded_as_unknown():
    variables = {"X": Unknown("from $(...)")}
    state = SessionState(cwd=WS, home=HOME, workspace=WS, gate_root=GATE, variables=variables)
    assert isinstance(state.variables["X"], Unknown)


def test_denied_history_rejects_allowed_commands():
    with pytest.raises(ValueError, match="allowed"):
        DeniedEntry(turn=0, command="ls", decision=Decision(Verdict.ALLOW))


def test_denied_history_entry(origin):
    entry = DeniedEntry(turn=3, command="rm -rf build", decision=deny())
    state = SessionState(cwd=WS, home=HOME, workspace=WS, gate_root=GATE, denied=(entry,))
    assert state.denied[0].turn == 3
