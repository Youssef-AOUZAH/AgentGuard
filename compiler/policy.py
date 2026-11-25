"""The policy evaluator: one command's effects, decided against a policy (`docs/interfaces.md` S5).

Takes in a checked `PolicyFile` (from `compiler/policy_parser.py`), the command's `Script`, its
effects from `compiler/effects.py`, and the `SessionState`. Gives back a `Decision`. It only
evaluates; running a policy's `expect` tests is the gate's job (`docs/decisions.md`, "Five
details of the policy language").

The meaning of the language is in `docs/policy-rules.md` §6. In short:

- **No rule order.** Every rule whose subject and conditions hold votes; the decision is the join
  of the votes, so a `deny` always wins and an `allow` only stops abstention.
- **Abstention is not permission.** An effect no rule votes on is `ESCALATE`, and so is a
  command with no effects at all. `ABSTAIN` never leaves this module.
- **Zones.** A path is in the first zone that matches it, in the order secret, device,
  workspace, temp, system, home, outside. A bounded target is decided once for each zone its
  subtree can touch (anywhere-patterns such as `**/.env` count only for a `read`). An unknown
  target touches every zone.

**Conditions have three values here**, which the language itself does not need to spell out:
yes, no, and maybe. A bounded target may or may not contain a path in a list, and an unknown path
may be anything. A `deny` or `escalate` rule fires when its conditions *may* hold; an `allow`
rule fires only when they *must*. That is the reading under which an unknown can never turn into
a permission. Hosts, variables and programs that are unknown are in no list, as decided: `host
in trusted` is no and `host not in trusted` yes.

**Retries (R9).** A refusal this evaluator makes records the zone it was about in each reason's
`detail` (`zone system`), and `repeats denied zone` matches the same kind in that same zone, not
in every zone the earlier target could have touched. Otherwise one refused `rm -rf /` would make
every later delete in the workspace a retry. For effects that are not on paths, a retry is the
same kind on the same target.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from enum import IntEnum
from fnmatch import fnmatchcase
from pathlib import PurePosixPath

from compiler.policy_syntax import (
    Anchor,
    AnyEffect,
    Background,
    CommandSubject,
    Compare,
    Condition,
    EffectSubject,
    HostIn,
    ListRef,
    PathPattern,
    PolicyFile,
    ProgramIn,
    RepeatBy,
    RepeatsDenied,
    Rule,
    StatementHas,
    SubstitutionDepth,
    TargetIn,
    TargetIs,
    TargetState,
    VariableIn,
    ZoneIs,
)
from compiler.syntax import Node, PartKind, Script, SimpleCommand, Statement, Subshell, Word, walk
from compiler.types import (
    PATH_KINDS,
    Bounded,
    Decision,
    Effect,
    EffectKind,
    Host,
    Known,
    Program,
    Reason,
    SessionState,
    Unknown,
    Variable,
    Verdict,
    Zone,
)

# The order in which zones claim a path (docs/decisions.md, "Five details").
ZONE_ORDER = (Zone.SECRET, Zone.DEVICE, Zone.WORKSPACE, Zone.TEMP, Zone.SYSTEM, Zone.HOME, Zone.OUTSIDE)
EVERY_ZONE = frozenset(ZONE_ORDER)

_ZONE_DETAIL = re.compile(r"zone ([a-z]+)")
_LIST_DETAIL = re.compile(r"list (\S+)")


class Tri(IntEnum):
    """A condition's value. `MAYBE` is for targets we can only bound, or not know at all."""

    NO = 0
    MAYBE = 1
    YES = 2

    def negate(self, negated: bool) -> Tri:
        return Tri(2 - self) if negated else self

    @classmethod
    def of(cls, value: bool) -> Tri:
        return cls.YES if value else cls.NO


# --------------------------------------------------------------------------- path patterns


@dataclass(frozen=True, slots=True)
class _Pattern:
    """A path pattern bound to this session: `base` is the anchor's directory, None for `**/`."""

    base: PurePosixPath | None
    parts: tuple[str, ...]

    def matches(self, path: PurePosixPath) -> bool:
        components = path.parts[1:]
        if self.base is None:
            return any(_match(self.parts, components[i:]) for i in range(len(components) + 1))
        if not path.is_relative_to(self.base):
            return False
        return _match(self.parts, path.relative_to(self.base).parts)

    def intersects(self, directory: PurePosixPath) -> bool:
        """Can this pattern match `directory` or anything under it?"""
        if self.base is None:
            return True
        if directory.is_relative_to(self.base):
            return _prefix(self.parts, directory.relative_to(self.base).parts)
        # The pattern is rooted below the directory; anything it matches is inside.
        return self.base.is_relative_to(directory)

    def covers(self, directory: PurePosixPath) -> bool:
        """Does this pattern match `directory` and everything under it?"""
        if self.base is None or not directory.is_relative_to(self.base):
            return False
        return _covers(self.parts, directory.relative_to(self.base).parts)


def _match(pattern: tuple[str, ...], path: tuple[str, ...]) -> bool:
    if not pattern:
        return not path
    if pattern[0] == "**":
        return any(_match(pattern[1:], path[i:]) for i in range(len(path) + 1))
    return bool(path) and fnmatchcase(path[0], pattern[0]) and _match(pattern[1:], path[1:])


def _prefix(pattern: tuple[str, ...], directory: tuple[str, ...]) -> bool:
    if not directory:
        return True  # the rest of the pattern can match the directory itself or below it
    if not pattern:
        return False  # the pattern names an ancestor of the directory, not what is under it
    if pattern[0] == "**":
        return True
    return fnmatchcase(directory[0], pattern[0]) and _prefix(pattern[1:], directory[1:])


def _covers(pattern: tuple[str, ...], directory: tuple[str, ...]) -> bool:
    if pattern == ("**",):
        return True
    if not pattern or not directory or pattern[0] == "**":
        return False
    return fnmatchcase(directory[0], pattern[0]) and _covers(pattern[1:], directory[1:])


def bind(pattern: PathPattern, state: SessionState) -> _Pattern:
    """A pattern as written, with its anchor bound to this session's directories."""
    bases = {
        Anchor.ROOT: PurePosixPath("/"),
        Anchor.HOME: state.home,
        Anchor.WORKSPACE: state.workspace,
        Anchor.GATE: state.gate_root,
        Anchor.ANYWHERE: None,
    }
    if pattern.anchor is None:
        raise ValueError(f"pattern {pattern.text!r} has no anchor; the checker should have refused it")
    parts = tuple(p for p in pattern.rest.split("/") if p not in ("", "."))
    return _Pattern(bases[pattern.anchor], parts)


# --------------------------------------------------------------------------- zones


class _Zones:
    def __init__(self, policy: PolicyFile, state: SessionState) -> None:
        defined = {d.zone: [bind(p, state) for p in d.patterns] for d in policy.zones}
        defined[Zone.WORKSPACE] = [_Pattern(state.workspace, ("**",))]
        defined[Zone.HOME] = [_Pattern(state.home, ("**",))]
        self.patterns = {
            zone: tuple(defined.get(zone, ())) for zone in ZONE_ORDER if zone is not Zone.OUTSIDE
        }

    def of(self, path: PurePosixPath) -> Zone:
        for zone, patterns in self.patterns.items():
            if any(p.matches(path) for p in patterns):
                return zone
        return Zone.OUTSIDE

    def touched(self, effect: Effect) -> frozenset[Zone] | None:
        """The zones an effect on a path can touch, or None when its target is not a path."""
        target = effect.target
        if isinstance(effect.resolution, Unknown):
            return EVERY_ZONE if effect.kind in PATH_KINDS else None
        if not isinstance(target, PurePosixPath):
            return None
        if isinstance(effect.resolution, Known):
            return frozenset({self.of(target)})
        anywhere = effect.kind is EffectKind.READ
        out: set[Zone] = set()
        for zone, patterns in self.patterns.items():
            usable = [p for p in patterns if p.base is not None or anywhere]
            if any(p.intersects(target) for p in usable):
                out.add(zone)
            if any(p.covers(target) for p in usable):
                return frozenset(out)  # every later zone is claimed first by this one
        out.add(Zone.OUTSIDE)
        return frozenset(out)


# --------------------------------------------------------------------------- the evaluator


def evaluate(policy: PolicyFile, script: Script, effects: Iterable[Effect], state: SessionState) -> Decision:
    """Decide one command. Never raises for a checked policy and effects built by `effects_of`."""
    return _Evaluator(policy, script, frozenset(effects), state).run()


class _Evaluator:
    def __init__(self, policy: PolicyFile, script: Script, effects: frozenset[Effect], state: SessionState):
        self.policy = policy
        self.script = script
        self.effects = sorted(effects, key=_effect_key)
        self.state = state
        self.zones = _Zones(policy, state)
        self.statement_of = _statements(script)
        self.denied = _denied(state)
        self.votes: list[tuple[Verdict, Reason | None]] = []

    def run(self) -> Decision:
        for effect in self.effects:
            touched = self.zones.touched(effect)
            for zone in sorted(touched) if touched is not None else [None]:
                self.decide(effect, zone)
        for rule in self.policy.rules:
            if isinstance(rule.subject, CommandSubject):
                self.vote(rule, None, None, self.command_conditions(rule))
        if not self.votes:
            return Decision(Verdict.ESCALATE)  # nothing to decide on is not permission
        verdict = max(v for v, _ in self.votes)
        reasons = tuple(dict.fromkeys(r for v, r in self.votes if v is verdict and r is not None))
        return Decision(verdict, reasons)

    def decide(self, effect: Effect, zone: Zone | None) -> None:
        voted = False
        for rule in self.policy.rules:
            if not _subject_matches(rule, effect):
                continue
            value = _all(self.condition(c, effect, zone) for c in rule.conditions)
            voted |= self.vote(rule, effect, zone, value)
        if not voted:
            self.votes.append((Verdict.ESCALATE, None))

    def vote(self, rule: Rule, effect: Effect | None, zone: Zone | None, value: Tri) -> bool:
        needed = Tri.YES if rule.verdict is Verdict.ALLOW else Tri.MAYBE
        if value < needed:
            return False
        self.votes.append((rule.verdict, Reason(rule.rule, effect, _about(rule, effect, zone, value))))
        return True

    # ---- conditions

    def condition(self, c: Condition, effect: Effect, zone: Zone | None) -> Tri:
        if isinstance(c, ZoneIs):
            return Tri.of(zone is not None and zone in c.zones).negate(c.negated)
        if isinstance(c, TargetIs):
            return Tri.of(_state_of(effect) is c.state).negate(c.negated)
        if isinstance(c, TargetIn):
            patterns = [bind(p, self.state) for p in self.policy.list_items(c.source)]  # type: ignore[arg-type]
            return _target_in(effect, patterns).negate(c.negated)
        if isinstance(c, HostIn):
            hosts = self.policy.list_items(c.source)
            inside = isinstance(effect.target, Host) and any(
                _host_matches(effect.target.name, h) for h in hosts
            )
            return Tri.of(inside).negate(c.negated)
        if isinstance(c, VariableIn):
            inside = isinstance(effect.target, Variable) and effect.target.name in self.policy.list_items(
                c.source
            )
            return Tri.of(inside).negate(c.negated)
        if isinstance(c, ProgramIn):
            inside = isinstance(effect.target, Program) and effect.target.name in self.policy.list_items(
                c.source
            )
            return Tri.of(inside).negate(c.negated)
        if isinstance(c, StatementHas):
            return self.statement_has(c, effect).negate(c.negated)
        if isinstance(c, RepeatsDenied):
            return self.repeats(c.by, effect, zone).negate(c.negated)
        if isinstance(c, (Background, SubstitutionDepth)):
            return self.command_condition(c)
        raise TypeError(f"not a condition: {c!r}")

    def command_conditions(self, rule: Rule) -> Tri:
        return _all(self.command_condition(c) for c in rule.conditions)

    def command_condition(self, c: Condition) -> Tri:
        if isinstance(c, Background):
            backgrounded = any(isinstance(n, Statement) and n.background for n in _nodes(self.script))
            return Tri.of(backgrounded).negate(c.negated)
        if isinstance(c, SubstitutionDepth):
            return Tri.of(_compare(c.op, _substitution_depth(self.script), c.value)).negate(c.negated)
        raise TypeError(f"{c!r} is not a condition on the command")

    def statement_has(self, c: StatementHas, effect: Effect) -> Tri:
        mine = self.statement_of.get(id(effect.origin))
        best = Tri.NO
        for other in self.effects:
            if other is effect or other.kind is not c.kind:
                continue
            if mine is None or self.statement_of.get(id(other.origin)) != mine:
                continue
            if c.zones is None:
                return Tri.YES
            touched = self.zones.touched(other) or frozenset()
            if touched & c.zones:
                best = max(best, Tri.YES if isinstance(other.resolution, Known) else Tri.MAYBE)
        return best

    def repeats(self, by: RepeatBy, effect: Effect, zone: Zone | None) -> Tri:
        best = Tri.NO
        for kind, target, denied_zone, denied_list in self.denied:
            if kind is not effect.kind:
                continue
            if by is RepeatBy.ZONE and denied_list is not None:
                patterns = [bind(p, self.state) for p in self.policy.list_items(ListRef(denied_list, 0))]
                best = max(best, _target_in(effect, patterns))  # type: ignore[arg-type]
                continue
            if by is RepeatBy.ZONE and zone is not None:
                if denied_zone == zone:
                    return Tri.YES
                continue
            if target is not None and target == effect.target:
                return Tri.YES
        return best


# --------------------------------------------------------------------------- helpers


def _subject_matches(rule: Rule, effect: Effect) -> bool:
    subject = rule.subject
    if isinstance(subject, AnyEffect):
        return True
    return isinstance(subject, EffectSubject) and effect.kind in subject.kinds


def _all(values: Iterable[Tri]) -> Tri:
    return min(values, default=Tri.YES)


def _state_of(effect: Effect) -> TargetState:
    if isinstance(effect.resolution, Unknown):
        return TargetState.UNKNOWN
    if isinstance(effect.resolution, Bounded):
        return TargetState.BOUNDED
    return TargetState.KNOWN


def _target_in(effect: Effect, patterns: list[_Pattern]) -> Tri:
    target = effect.target
    if isinstance(effect.resolution, Unknown):
        return Tri.MAYBE if effect.kind in PATH_KINDS else Tri.NO
    if not isinstance(target, PurePosixPath):
        return Tri.NO
    if isinstance(effect.resolution, Known):
        return Tri.of(any(p.matches(target) for p in patterns))
    if any(p.covers(target) for p in patterns):
        return Tri.YES
    return Tri.MAYBE if any(p.intersects(target) for p in patterns) else Tri.NO


def _host_matches(host: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        return host.endswith(pattern[1:])
    return host == pattern


def _compare(op: Compare, left: int, right: int) -> bool:
    return {
        Compare.GT: left > right,
        Compare.GE: left >= right,
        Compare.LT: left < right,
        Compare.LE: left <= right,
        Compare.EQ: left == right,
        Compare.NE: left != right,
    }[op]


def _effect_key(effect: Effect) -> tuple:
    return (
        effect.kind,
        str(effect.target),
        type(effect.resolution).__name__,
        getattr(effect.origin, "pos", 0),
    )


def _nodes(script: Script) -> Iterator[Node]:
    """Every node, including those inside command substitutions, which `walk` does not enter."""
    for node in walk(script):
        yield node
        for word in _words(node):
            for part in _parts(word.parts):
                if part.kind is PartKind.CMD_SUBST and part.script is not None:
                    yield from _nodes(part.script)


def _words(node: Node) -> Iterator[Word]:
    if isinstance(node, SimpleCommand):
        yield from node.words
        yield from (a.value for a in node.assignments)
        yield from (r.target for r in node.redirects if r.target is not None)
    elif isinstance(node, Subshell):
        yield from (r.target for r in node.redirects if r.target is not None)


def _parts(parts):
    for part in parts:
        yield part
        yield from _parts(part.parts)


def _statements(script: Script) -> dict[int, int]:
    """The top-level statement each node belongs to, by identity. A statement is one `and_or`
    list; taking the top-level one makes `statement has` see a little more, never less."""
    out: dict[int, int] = {}
    for index, statement in enumerate(script.statements):
        for node in _nodes(Script((statement,), script.src)):
            out[id(node)] = index
    return out


def _substitution_depth(script: Script) -> int:
    depth = 0
    for node in _nodes(script):
        for word in _words(node):
            for part in _parts(word.parts):
                if part.kind is PartKind.CMD_SUBST:
                    depth = max(depth, part.depth or 1)
    return depth


def _about(rule: Rule, effect: Effect | None, zone: Zone | None, value: Tri) -> str:
    """What a vote was about, written into the reason's `detail` for R9 to read back.

    Usually the zone. Two cases are narrower, because recording the zone would make far too much
    a retry afterwards. A target we know nothing about touches every zone, but the refusal was not
    about any of them, so `rm $(cat list)` records none. And a rule that fired only because a
    bounded target *may* reach a path in a list was about that list, not the whole zone: `rm -rf
    /` may reach `{gate}/**` from every zone, and recording `zone workspace` for that would make
    `rm notes.txt` a retry."""
    if effect is None or zone is None or isinstance(effect.resolution, Unknown):
        return ""
    if value is Tri.MAYBE:
        for c in rule.conditions:
            if isinstance(c, TargetIn) and not c.negated and isinstance(c.source, ListRef):
                return f"list {c.source.name}"
    return f"zone {zone}"


_Denied = tuple[EffectKind, object, Zone | None, str | None]


def _denied(state: SessionState) -> list[_Denied]:
    """What was refused earlier: kind, target, and the zone or the list the refusal was about if
    it said (see `_about`)."""
    out: list[_Denied] = []
    for entry in state.denied:
        for reason in entry.decision.reasons:
            if reason.effect is None:
                continue
            match = _ZONE_DETAIL.fullmatch(reason.detail)
            zone = Zone(match.group(1)) if match and match.group(1) in Zone._value2member_map_ else None
            listed = _LIST_DETAIL.fullmatch(reason.detail)
            out.append((reason.effect.kind, reason.effect.target, zone, listed.group(1) if listed else None))
    return out


__all__ = ["EVERY_ZONE", "ZONE_ORDER", "Tri", "bind", "evaluate"]
