"""Tests for the policy language front end: lexer, parser with recovery, and checker.

Three kinds of test. The repository's own policy and one example of every construct must parse to
the tree we expect. Every error code must be reported, at the right line and column. And the
front end must never raise and must report every independent mistake in one run, which is the
point of recovering rather than failing fast (`docs/decisions.md`).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from compiler.policy_lexer import PolicyTokenKind, tokenize_policy
from compiler.policy_parser import parse_policy
from compiler.policy_syntax import (
    Anchor,
    AnyEffect,
    Background,
    CommandSubject,
    Compare,
    EffectSubject,
    HostIn,
    InlineList,
    ListKind,
    ListRef,
    PolicyDiag,
    ProgramIn,
    RepeatBy,
    RepeatsDenied,
    StatementHas,
    SubstitutionDepth,
    TargetIn,
    TargetIs,
    TargetState,
    VariableIn,
    ZoneIs,
)
from compiler.types import EffectKind, RuleId, Verdict, Zone

DEFAULT_POLICY = Path(__file__).resolve().parents[2] / "policies" / "default.pol"


def policy(body: str):
    """Parse `body` wrapped in a policy block, and insist that it loads."""
    result = parse_policy('policy "t" {\n' + body + "\n}\n")
    assert result.ok, "\n".join(map(str, result.errors))
    return result.policy


def errors(body: str, *, wrap: bool = True):
    src = 'policy "t" {\n' + body + "\n}\n" if wrap else body
    result = parse_policy(src)
    assert not result.ok and result.policy is None
    return result.errors


def codes(body: str, **kw) -> list[PolicyDiag]:
    return [e.code for e in errors(body, **kw)]


def only_rule(body: str):
    (rule,) = policy(body).rules
    return rule


# --------------------------------------------------------------------------- the repository's policy


def test_default_policy_loads():
    result = parse_policy(DEFAULT_POLICY.read_text(encoding="utf-8"))
    assert result.ok, "\n".join(map(str, result.errors))
    assert result.policy.name == "workspace-confined"
    assert {z.zone for z in result.policy.zones} == {Zone.SECRET, Zone.SYSTEM, Zone.DEVICE, Zone.TEMP}
    assert len(result.policy.expects) >= 15
    cited = {r.rule for r in result.policy.rules}
    assert {RuleId.R2, RuleId.R3, RuleId.R4, RuleId.R5, RuleId.R6, RuleId.R7, RuleId.R8} <= cited


# --------------------------------------------------------------------------- every construct


def test_zones_lists_and_patterns():
    p = policy(
        """
        zone secret ["~/.ssh/**", "**/.env", "~"]
        hosts trusted ["pypi.org", "*.github.com"]
        paths guard ["{gate}/**", "{workspace}/.git/config", "/etc/passwd"]
        names loaders ["IFS", "PATH",]
        """
    )
    patterns = p.zones[0].patterns
    assert [(x.anchor, x.rest) for x in patterns] == [
        (Anchor.HOME, ".ssh/**"),
        (Anchor.ANYWHERE, ".env"),
        (Anchor.HOME, ""),
    ]
    kinds = {d.name: d.kind for d in p.lists}
    assert kinds == {"trusted": ListKind.HOSTS, "guard": ListKind.PATHS, "loaders": ListKind.NAMES}
    guard = p.lists[1].items
    assert [x.anchor for x in guard] == [Anchor.GATE, Anchor.WORKSPACE, Anchor.ROOT]
    assert p.lists[2].items == ("IFS", "PATH")


def test_rule_subjects():
    assert policy("").rules == ()
    rule = only_rule("R4 deny delete | write | append")
    assert rule.rule is RuleId.R4 and rule.verdict is Verdict.DENY and rule.conditions == ()
    assert isinstance(rule.subject, EffectSubject)
    assert rule.subject.kinds == {EffectKind.DELETE, EffectKind.WRITE, EffectKind.APPEND}
    assert isinstance(only_rule("R9 deny any").subject, AnyEffect)
    assert isinstance(only_rule("R7 escalate command where background").subject, CommandSubject)
    assert only_rule("R6 deny net_listen").subject.kinds == {EffectKind.NET_LISTEN}
    assert only_rule("R10 escalate unknown").subject.kinds == {EffectKind.UNKNOWN}


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("zone == secret", ZoneIs(frozenset({Zone.SECRET}), False, 0)),
        ("zone != workspace", ZoneIs(frozenset({Zone.WORKSPACE}), True, 0)),
        ("zone in [workspace, temp]", ZoneIs(frozenset({Zone.WORKSPACE, Zone.TEMP}), False, 0)),
        ("zone not in [system,]", ZoneIs(frozenset({Zone.SYSTEM}), True, 0)),
        ("target known", TargetIs(TargetState.KNOWN, False, 0)),
        ("target not bounded", TargetIs(TargetState.BOUNDED, True, 0)),
        ("target unknown", TargetIs(TargetState.UNKNOWN, False, 0)),
        ("not repeats denied zone", RepeatsDenied(RepeatBy.ZONE, True, 0)),
        ("repeats denied target", RepeatsDenied(RepeatBy.TARGET, False, 0)),
    ],
)
def test_simple_conditions(text, expected):
    (condition,) = only_rule(f"R4 deny read where {text}").conditions
    assert type(condition) is type(expected)
    for field in expected.__dataclass_fields__:
        if field != "pos":
            assert getattr(condition, field) == getattr(expected, field)


def test_list_conditions_by_name_and_inline():
    source = (
        'paths guard ["/g"]' + chr(10) + 'R4 deny write where target not in guard and target in ["/dev/null"]'
    )
    (rule,) = policy(source).rules
    first, second = rule.conditions
    assert isinstance(first, TargetIn) and first.negated and first.source.name == "guard"
    assert isinstance(second.source, InlineList)
    assert second.source.items[0].anchor is Anchor.ROOT
    # A named list may be defined after the rule that uses it: the file has no order.
    p = policy('R4 deny write where target in guard\npaths guard ["/x"]')
    assert isinstance(p.rules[0].conditions[0].source, ListRef)
    assert p.list_items(p.rules[0].conditions[0].source)[0].text == "/x"


def test_host_variable_program():
    assert isinstance(only_rule('R6 escalate net_out where host not in ["a.org"]').conditions[0], HostIn)
    assert isinstance(only_rule('R7 deny env_mutate where variable in ["IFS"]').conditions[0], VariableIn)
    assert isinstance(only_rule('R10 allow exec where program in ["ls"]').conditions[0], ProgramIn)


def test_statement_has():
    (cond,) = only_rule("R6 deny net_out where statement has read in zone secret").conditions
    assert cond == StatementHas(EffectKind.READ, frozenset({Zone.SECRET}), False, cond.pos)
    (cond,) = only_rule("R6 deny net_out where statement not has write").conditions
    assert cond.zones is None and cond.negated


def test_command_facts():
    rule = only_rule("R7 escalate command where substitution depth >= 2 and not background")
    depth, background = rule.conditions
    assert depth == SubstitutionDepth(Compare.GE, 2, False, depth.pos)
    assert background == Background(True, background.pos)


def test_conditions_join_with_and():
    rule = only_rule(
        'R4 deny write | append where zone != workspace and target known and target not in ["/x"]'
    )
    assert len(rule.conditions) == 3


def test_expect_lines():
    p = policy(
        'expect deny R4 "cd ~/Desktop"\n'
        'expect allow "cat notes.txt" after "cd ~/Desktop", "ls"\n'
        'expect escalate "a \\"quoted\\" \\\\ word"'
    )
    first, second, third = p.expects
    assert (first.verdict, first.rule, first.command, first.after) == (
        Verdict.DENY,
        RuleId.R4,
        "cd ~/Desktop",
        (),
    )
    assert second.rule is None and second.after == ("cd ~/Desktop", "ls")
    assert third.command == 'a "quoted" \\ word'


def test_comments_and_layout_are_free():
    p = parse_policy('# a comment\npolicy "t" { # here too\n R5 deny priv_change # and here\n}\n# end\n')
    assert p.ok and len(p.policy.rules) == 1


def test_r11_follows_the_rule_ids_compiler_types_declares():
    result = parse_policy('policy "t" {\n R11 deny command where background\n}')
    assert result.ok is hasattr(RuleId, "R11")


# --------------------------------------------------------------------------- every error, with its position


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ("R4 deny read where zone == secret $", PolicyDiag.UNEXPECTED_CHARACTER),
        ('expect deny "unclosed', PolicyDiag.UNTERMINATED_STRING),
        ('expect deny "bad \\q escape"', PolicyDiag.BAD_ESCAPE),
        ("R4 deny", PolicyDiag.UNEXPECTED_TOKEN),
        ("R99 deny read", PolicyDiag.UNKNOWN_RULE_ID),
        ("R4 deny remove", PolicyDiag.UNKNOWN_KIND),
        ("R4 deny read where zone == desktop", PolicyDiag.UNKNOWN_ZONE),
        ("R7 escalate command where substitution depth > 99999999", PolicyDiag.BAD_NUMBER),
        ('zone secret ["/a"]\nzone secret ["/b"]', PolicyDiag.DUPLICATE_ZONE),
        ('zone workspace ["/w"]', PolicyDiag.ZONE_NOT_DEFINABLE),
        ('hosts h ["a.org"]\nhosts h ["b.org"]', PolicyDiag.DUPLICATE_LIST),
        ("R4 deny write where target in nowhere", PolicyDiag.UNKNOWN_LIST),
        ('hosts h ["a.org"]\nR4 deny write where target in h', PolicyDiag.WRONG_LIST_KIND),
        ('zone secret ["relative/path"]', PolicyDiag.BAD_PATTERN),
        ('zone secret ["/a/../b"]', PolicyDiag.BAD_PATTERN),
        ('zone secret ["**/"]', PolicyDiag.BAD_PATTERN),
        ('hosts h ["Upper.Case"]', PolicyDiag.BAD_HOST),
        ('names n ["two words"]', PolicyDiag.BAD_NAME),
        ("R4 deny net_out where zone == secret", PolicyDiag.CONDITION_NOT_FOR_SUBJECT),
        ('R6 deny read where host in ["a.org"]', PolicyDiag.CONDITION_NOT_FOR_SUBJECT),
        ("R9 deny any where zone == secret", PolicyDiag.CONDITION_NOT_FOR_SUBJECT),
        ("R7 deny command where zone == secret", PolicyDiag.CONDITION_NOT_FOR_SUBJECT),
        ("R7 deny exec where background", PolicyDiag.CONDITION_NOT_FOR_SUBJECT),
        ("R4 deny move", PolicyDiag.MOVE_IS_NOT_AN_EFFECT),
        ("R3 allow interpret", PolicyDiag.ALLOW_INTERPRET),
        ("R3 allow any where target known", PolicyDiag.ALLOW_INTERPRET),
    ],
)
def test_each_error_code(body, code):
    assert code in codes(body)


def test_error_positions_are_line_and_column():
    (error,) = errors("R5 deny priv_change\n  R4 deny read where zone == desktop")
    assert error.code is PolicyDiag.UNKNOWN_ZONE
    assert (error.line, error.col) == (3, 30)  # line 1 is the `policy` line the helper adds
    assert str(error).startswith("line 3, column 30: unknown-zone:")


def test_checker_errors_point_at_the_list_reference():
    (error,) = errors("R4 deny write where target in nowhere")
    assert (error.line, error.col) == (2, 31)


def test_missing_policy_header_and_brace():
    assert codes("R5 deny priv_change", wrap=False) == [PolicyDiag.UNEXPECTED_TOKEN]
    assert codes('policy "t" {\n R5 deny priv_change\n', wrap=False) == [PolicyDiag.UNEXPECTED_TOKEN]
    assert codes('policy "t" { } extra', wrap=False) == [PolicyDiag.UNEXPECTED_TOKEN]


# --------------------------------------------------------------------------- recovery


def test_every_independent_mistake_is_reported_in_one_run():
    found = errors(
        "R4 deny read where zone == desktop\n"  # syntax: unknown zone
        "R5 deny priv_change\n"  # fine
        "R4 deny remove\n"  # syntax: unknown kind
        "R4 deny write where target in nowhere\n"  # checker: unknown list
        "R4 deny\n"  # syntax: missing subject, at the start of the next line
        "R3 allow interpret\n"  # checker: allows interpret
    )
    assert [e.code for e in found] == [
        PolicyDiag.UNKNOWN_ZONE,
        PolicyDiag.UNKNOWN_KIND,
        PolicyDiag.UNKNOWN_LIST,
        PolicyDiag.UNEXPECTED_TOKEN,
        PolicyDiag.ALLOW_INTERPRET,
    ]
    # The missing subject is reported where the parser found something else instead: line 7.
    assert [e.line for e in found] == [2, 4, 5, 7, 7]


def test_a_broken_line_does_not_swallow_the_next_rule():
    # `R4 deny` is cut short, and the next line's rule must still be read and checked.
    found = errors("R4 deny\nR3 allow interpret")
    assert [e.code for e in found] == [PolicyDiag.UNEXPECTED_TOKEN, PolicyDiag.ALLOW_INTERPRET]


def test_an_unclosed_string_costs_one_line():
    found = errors('expect deny "oops\nR3 allow interpret')
    assert [e.code for e in found] == [
        PolicyDiag.UNTERMINATED_STRING,
        PolicyDiag.UNEXPECTED_TOKEN,
        PolicyDiag.ALLOW_INTERPRET,
    ]


# --------------------------------------------------------------------------- never raises


WORDS = [
    "policy", "zone", "hosts", "paths", "names", "expect", "after", "R4", "R11", "R99",
    "allow", "deny", "escalate", "any", "command", "read", "write", "move", "interpret",
    "where", "and", "not", "in", "target", "known", "unknown", "host", "variable", "program",
    "statement", "has", "repeats", "denied", "background", "substitution", "depth",
    "secret", "workspace", "x", "{", "}", "[", "]", ",", "|", "==", "!=", ">", "3",
    '"/etc/**"', '"a.org"', '"~/x"', '"oops', "#c", "\n", "$",
]  # fmt: skip


@settings(max_examples=400, deadline=None)
@given(st.text(max_size=300))
def test_never_raises_on_any_text(src):
    result = parse_policy(src)
    assert result.ok == (not result.errors)


@settings(max_examples=600, deadline=None)
@given(st.lists(st.sampled_from(WORDS), max_size=60))
def test_never_raises_on_token_soup(words):
    result = parse_policy('policy "t" {\n' + " ".join(words) + "\n}")
    assert result.ok == (not result.errors)
    assert all(e.line >= 1 and e.col >= 1 for e in result.errors)


def test_lexer_marks_first_token_on_each_line():
    tokens, errs = tokenize_policy('a b\n  c "d"\n')
    assert errs == []
    assert [(t.kind, t.text, t.first_on_line) for t in tokens] == [
        (PolicyTokenKind.WORD, "a", True),
        (PolicyTokenKind.WORD, "b", False),
        (PolicyTokenKind.WORD, "c", True),
        (PolicyTokenKind.STRING, "d", False),
        (PolicyTokenKind.EOF, "", True),
    ]


def test_policy_result_holds_a_policy_or_errors_never_both():
    from compiler.policy_syntax import PolicyError, PolicyResult

    loaded = parse_policy('policy "t" { }').policy
    error = PolicyError(PolicyDiag.UNEXPECTED_TOKEN, "x", 0, 1, 1)
    with pytest.raises(ValueError):
        PolicyResult(loaded, (error,))
    with pytest.raises(ValueError):
        PolicyResult(None, ())
