"""The policy checker: what a policy file must satisfy beyond its grammar.

Takes in a parsed `PolicyFile`. Returns every error found, as `PolicyError`s, and never raises.
`compiler/policy_parser.py` runs it after parsing and loads the file only when neither found
anything, which is what lets the evaluator trust the guarantees listed in
`compiler/policy_syntax.py` instead of re-checking them.

The checks, each with its own `PolicyDiag` code:

- zones may be defined only for `secret`, `system`, `device` and `temp`, once each;
- list names are unique, and every list a rule names exists and has the kind the condition needs;
- path patterns are anchored and have no `..`; hosts are lower-case DNS names, optionally
  starting with `*.`; names are non-empty and contain no whitespace;
- each condition suits its rule's subject (see `_ALLOWED_KINDS`), and `command` rules use only
  `background` and `substitution depth`;
- no rule names `move`, which is never an effect (a move is a delete plus a write);
- no rule allows `interpret`, directly or through `any`: inline code in another language is
  exactly what we cannot analyse, so allowing it would allow anything.

It also provides `make_pattern`, which the parser uses to turn a pattern string into a
`PathPattern`; a pattern it cannot anchor gets `anchor=None` here and an error from `check`.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from compiler.policy_syntax import (
    Anchor,
    AnyEffect,
    Background,
    CommandSubject,
    EffectSubject,
    HostIn,
    InlineList,
    ListDef,
    ListKind,
    ListRef,
    ListSource,
    PathPattern,
    PolicyDiag,
    PolicyError,
    PolicyFile,
    ProgramIn,
    StatementHas,
    SubstitutionDepth,
    TargetIn,
    VariableIn,
    ZoneIs,
)
from compiler.types import PATH_KINDS, EffectKind, Verdict, Zone

DEFINABLE_ZONES = frozenset({Zone.SECRET, Zone.SYSTEM, Zone.DEVICE, Zone.TEMP})

# For each condition that only makes sense on some effects, the kinds it may be used with.
_ALLOWED_KINDS: dict[type, frozenset[EffectKind]] = {
    ZoneIs: PATH_KINDS,
    TargetIn: PATH_KINDS,
    HostIn: frozenset({EffectKind.NET_OUT}),
    VariableIn: frozenset({EffectKind.ENV_MUTATE}),
    ProgramIn: frozenset({EffectKind.EXEC, EffectKind.UNKNOWN}),
}
_CONDITION_WORDS: dict[type, str] = {
    ZoneIs: "zone",
    TargetIn: "target in",
    HostIn: "host",
    VariableIn: "variable",
    ProgramIn: "program",
    Background: "background",
    SubstitutionDepth: "substitution depth",
}
_LIST_FOR: dict[type, ListKind] = {
    TargetIn: ListKind.PATHS,
    HostIn: ListKind.HOSTS,
    VariableIn: ListKind.NAMES,
    ProgramIn: ListKind.NAMES,
}
_HOST = re.compile(r"(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*")
_ANCHORS = (("{workspace}", Anchor.WORKSPACE), ("{gate}", Anchor.GATE), ("~", Anchor.HOME))


def make_pattern(text: str, pos: int) -> PathPattern:
    """A `PathPattern` for `text`, with `anchor=None` when it has none of the allowed anchors."""
    if text.startswith("/"):
        return PathPattern(text, Anchor.ROOT, text[1:], pos)
    if text.startswith("**/"):
        return PathPattern(text, Anchor.ANYWHERE, text[3:], pos)
    for prefix, anchor in _ANCHORS:
        if text == prefix:
            return PathPattern(text, anchor, "", pos)
        if text.startswith(prefix + "/"):
            return PathPattern(text, anchor, text[len(prefix) + 1 :], pos)
    return PathPattern(text, None, text, pos)  # refused by check(), so never in a loaded policy


def check(policy: PolicyFile) -> list[PolicyError]:
    """Every error in a parsed policy. Empty means the file may be loaded."""
    return _Checker(policy).run()


class _Checker:
    def __init__(self, policy: PolicyFile) -> None:
        self.policy = policy
        self.errors: list[PolicyError] = []
        self.lists: dict[str, ListDef] = {}

    def error(self, code: PolicyDiag, message: str, pos: int) -> None:
        src = self.policy.src
        line = src.count("\n", 0, pos) + 1
        col = pos - (src.rfind("\n", 0, pos) + 1) + 1
        self.errors.append(PolicyError(code, message, pos, line, col))

    def run(self) -> list[PolicyError]:
        self.zones()
        self.list_defs()
        for rule in self.policy.rules:
            self.rule(rule)
        return self.errors

    def zones(self) -> None:
        seen: set[Zone] = set()
        for zone_def in self.policy.zones:
            if zone_def.zone not in DEFINABLE_ZONES:
                self.error(
                    PolicyDiag.ZONE_NOT_DEFINABLE,
                    f"zone {zone_def.zone} cannot be defined in a policy: workspace and home come from the "
                    "session, and outside is everything else",
                    zone_def.pos,
                )
            elif zone_def.zone in seen:
                self.error(PolicyDiag.DUPLICATE_ZONE, f"zone {zone_def.zone} is defined twice", zone_def.pos)
            seen.add(zone_def.zone)
            self.patterns(zone_def.patterns)

    def list_defs(self) -> None:
        for definition in self.policy.lists:
            if definition.name in self.lists:
                self.error(
                    PolicyDiag.DUPLICATE_LIST,
                    f"a list named {definition.name!r} already exists",
                    definition.pos,
                )
                continue
            self.lists[definition.name] = definition
            self.items(definition.kind, definition.items, definition.pos)

    def items(self, kind: ListKind, items: Iterable, pos: int) -> None:
        if kind is ListKind.PATHS:
            self.patterns(items)
        elif kind is ListKind.HOSTS:
            for host in items:
                if not _HOST.fullmatch(host):
                    self.error(PolicyDiag.BAD_HOST, f"{host!r} is not a lower-case host name", pos)
        else:
            for name in items:
                if not name or any(ch.isspace() for ch in name):
                    self.error(PolicyDiag.BAD_NAME, f"{name!r} is not a name", pos)

    def patterns(self, patterns: Iterable[PathPattern]) -> None:
        for pattern in patterns:
            if pattern.anchor is None:
                self.error(
                    PolicyDiag.BAD_PATTERN,
                    f"path pattern {pattern.text!r} must start with "
                    "'/', '~', '{workspace}', '{gate}' or '**/'",
                    pattern.pos,
                )
            elif ".." in pattern.rest.split("/"):
                self.error(
                    PolicyDiag.BAD_PATTERN,
                    f"path pattern {pattern.text!r} must not contain '..'",
                    pattern.pos,
                )
            elif pattern.anchor is Anchor.ANYWHERE and not pattern.rest:
                self.error(PolicyDiag.BAD_PATTERN, "'**/' must be followed by a name", pattern.pos)
            elif "\0" in pattern.text:
                self.error(PolicyDiag.BAD_PATTERN, "path patterns cannot contain NUL", pattern.pos)

    def rule(self, rule) -> None:
        subject = rule.subject
        if isinstance(subject, EffectSubject) and EffectKind.MOVE in subject.kinds:
            self.error(
                PolicyDiag.MOVE_IS_NOT_AN_EFFECT,
                "a move is reported as a delete of the source and a write of the destination; write those",
                subject.pos,
            )
        allows_interpret = isinstance(subject, AnyEffect) or (
            isinstance(subject, EffectSubject) and EffectKind.INTERPRET in subject.kinds
        )
        if rule.verdict is Verdict.ALLOW and allows_interpret:
            self.error(
                PolicyDiag.ALLOW_INTERPRET,
                "no rule may allow interpret: inline code in another language cannot be analysed",
                rule.pos,
            )
        for condition in rule.conditions:
            self.condition(condition, subject)

    def condition(self, condition, subject) -> None:
        kind_of = type(condition)
        word = _CONDITION_WORDS.get(kind_of)
        if isinstance(subject, CommandSubject):
            if kind_of not in (Background, SubstitutionDepth):
                self.error(
                    PolicyDiag.CONDITION_NOT_FOR_SUBJECT,
                    "a command rule can only test 'background' and 'substitution depth'",
                    condition.pos,
                )
            return
        if kind_of in (Background, SubstitutionDepth):
            self.error(
                PolicyDiag.CONDITION_NOT_FOR_SUBJECT,
                f"'{word}' is a fact about the whole command; use it in a 'command' rule",
                condition.pos,
            )
            return
        if isinstance(condition, StatementHas) and condition.kind is EffectKind.MOVE:
            self.error(PolicyDiag.MOVE_IS_NOT_AN_EFFECT, "no effect has kind move", condition.pos)
        allowed = _ALLOWED_KINDS.get(kind_of)
        if allowed is not None:
            if isinstance(subject, AnyEffect):
                self.error(
                    PolicyDiag.CONDITION_NOT_FOR_SUBJECT,
                    f"'{word}' does not apply to every effect; name the kinds instead of 'any'",
                    condition.pos,
                )
            elif not subject.kinds <= allowed:
                wrong = ", ".join(sorted(k.name.lower() for k in subject.kinds - allowed))
                self.error(
                    PolicyDiag.CONDITION_NOT_FOR_SUBJECT, f"'{word}' does not apply to {wrong}", condition.pos
                )
        if kind_of in _LIST_FOR:
            self.source(condition.source, _LIST_FOR[kind_of], word)

    def source(self, source: ListSource, needed: ListKind, word: str) -> None:
        if isinstance(source, InlineList):
            self.items(needed, source.items, source.pos)
            return
        if not isinstance(source, ListRef):
            return
        definition = self.lists.get(source.name)
        if definition is None:
            self.error(PolicyDiag.UNKNOWN_LIST, f"no list named {source.name!r} is defined", source.pos)
        elif definition.kind is not needed:
            self.error(
                PolicyDiag.WRONG_LIST_KIND,
                f"'{word} in' needs a {needed} list, and {source.name!r} is a {definition.kind} list",
                source.pos,
            )
