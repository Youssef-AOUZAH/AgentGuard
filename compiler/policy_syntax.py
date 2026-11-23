"""Policy language types: the tree the policy front end produces and the policy evaluator reads.

This is the third shared file, after `compiler/syntax.py` and `compiler/types.py`, and it follows
the same rule: Youssef writes it, Younes reviews it, and a change updates every consumer in the
same pull request (`docs/decisions.md`, "The policy language's front end is Youssef's; its
evaluator is Younes's"). The language itself is described, with its grammar, in
`docs/policy-rules.md` §6.

Takes in: nothing. Declares types only, every one immutable.

What the front end guarantees about a `PolicyFile` it returns, so the evaluator need not check:

- every list a rule names exists and holds the right kind of item (paths for `target in`, hosts
  for `host in`, names for `variable in` and `program in`);
- every condition makes sense for the rule's subject: a zone test only on file effects, `host`
  only on `net_out`, `variable` only on `env_mutate`, `program` only on `exec` and `unknown`,
  `background` and `substitution depth` only on `command`;
- no rule allows `interpret`, directly or through `any`;
- zones are defined only for `secret`, `system`, `device` and `temp`, at most once each, since
  `workspace` and `home` are bound by the gate from `SessionState` and `outside` is the rest;
- every path pattern is anchored (see `Anchor`) and contains no `..`.

What it does not do: decide anything, match a path against a pattern, or run the `expect` tests,
which need the whole compiler and are run by the evaluator when it loads a policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from compiler.types import EffectKind, RuleId, Verdict, Zone

MAX_POLICY_LENGTH = 1024 * 1024


class PolicyDiag(StrEnum):
    """Why a policy file was refused. Each `PolicyError` carries one."""

    # lexical
    UNEXPECTED_CHARACTER = "unexpected-character"
    UNTERMINATED_STRING = "unterminated-string"
    BAD_ESCAPE = "bad-escape"
    TOO_LONG = "too-long"
    # syntactic
    UNEXPECTED_TOKEN = "unexpected-token"
    UNKNOWN_RULE_ID = "unknown-rule-id"
    UNKNOWN_KIND = "unknown-kind"
    UNKNOWN_ZONE = "unknown-zone"
    BAD_NUMBER = "bad-number"
    # semantic, found by the checker
    DUPLICATE_ZONE = "duplicate-zone"
    ZONE_NOT_DEFINABLE = "zone-not-definable"
    DUPLICATE_LIST = "duplicate-list"
    UNKNOWN_LIST = "unknown-list"
    WRONG_LIST_KIND = "wrong-list-kind"
    BAD_PATTERN = "bad-pattern"
    BAD_HOST = "bad-host"
    BAD_NAME = "bad-name"
    CONDITION_NOT_FOR_SUBJECT = "condition-not-for-subject"
    MOVE_IS_NOT_AN_EFFECT = "move-is-not-an-effect"
    ALLOW_INTERPRET = "allow-interpret"


@dataclass(frozen=True, slots=True)
class PolicyError:
    """One problem in a policy file, with where it is. The front end collects these rather than
    stopping at the first, so one run reports every mistake in the file."""

    code: PolicyDiag
    message: str
    pos: int
    line: int
    col: int

    def __str__(self) -> str:
        return f"line {self.line}, column {self.col}: {self.code}: {self.message}"


# --------------------------------------------------------------------------- patterns and lists


class Anchor(StrEnum):
    """What a path pattern is relative to. The evaluator binds each to a real directory."""

    ROOT = "root"  # /etc/**
    HOME = "home"  # ~/.ssh/**  (the session's home)
    WORKSPACE = "workspace"  # {workspace}/.git/config  (the session's workspace)
    GATE = "gate"  # {gate}/**  (where the gate's own code, policies and logs live)
    ANYWHERE = "anywhere"  # **/.env  (at any depth, under any directory)


@dataclass(frozen=True, slots=True)
class PathPattern:
    """A path pattern as written. `rest` is the part after the anchor, with no leading slash: for
    `~/.ssh/**` it is `.ssh/**`, for `**/.env` it is `.env`. `*` matches within one path
    component and `**` matches any number of components. `anchor` is None only for a pattern
    the checker refuses, so it is never None in a loaded policy."""

    text: str
    anchor: Anchor | None
    rest: str
    pos: int


class ListKind(StrEnum):
    HOSTS = "hosts"
    PATHS = "paths"
    NAMES = "names"


@dataclass(frozen=True, slots=True)
class ListDef:
    """A named list: `hosts trusted ["pypi.org"]`. `paths` lists hold `PathPattern`s; the others
    hold strings. A host may start with `*.` to match any subdomain."""

    kind: ListKind
    name: str
    items: tuple[str, ...] | tuple[PathPattern, ...]
    pos: int


@dataclass(frozen=True, slots=True)
class ListRef:
    """A rule naming a list defined elsewhere in the file. The checker guarantees it exists and
    has the right kind; `PolicyFile.list_items` looks it up."""

    name: str
    pos: int


@dataclass(frozen=True, slots=True)
class InlineList:
    """A list written in place: `target in ["/dev/null"]`. Paths become `PathPattern`s."""

    items: tuple[str, ...] | tuple[PathPattern, ...]
    pos: int


ListSource = ListRef | InlineList


@dataclass(frozen=True, slots=True)
class ZoneDef:
    """`zone secret ["~/.ssh/**", "**/.env"]`: the paths that fall in a zone."""

    zone: Zone
    patterns: tuple[PathPattern, ...]
    pos: int


# --------------------------------------------------------------------------- rules


@dataclass(frozen=True, slots=True)
class EffectSubject:
    """A rule about effects of these kinds: `delete | write`."""

    kinds: frozenset[EffectKind]
    pos: int


@dataclass(frozen=True, slots=True)
class AnyEffect:
    """A rule about every effect, whatever its kind: `any`."""

    pos: int


@dataclass(frozen=True, slots=True)
class CommandSubject:
    """A rule about the command line as a whole, not one of its effects: `command`. Fires once
    per command, for facts read from the syntax tree (backgrounding, substitution depth)."""

    pos: int


Subject = EffectSubject | AnyEffect | CommandSubject


class Resolution(StrEnum):
    """The three values of `compiler.types.Resolution`, as a rule names them."""

    KNOWN = "known"
    BOUNDED = "bounded"
    UNKNOWN = "unknown"


class RepeatBy(StrEnum):
    """What counts as repeating a refused effect (R9): the same kind on the same target, or the
    same kind in the same zone. Which one the default policy should use is a research question,
    so the language offers both."""

    TARGET = "target"
    ZONE = "zone"


class Compare(StrEnum):
    GT = ">"
    GE = ">="
    LT = "<"
    LE = "<="
    EQ = "=="
    NE = "!="


# Every condition has `negated`, which inverts its result, and `pos`.


@dataclass(frozen=True, slots=True)
class ZoneIs:
    """`zone == secret`, `zone != workspace`, `zone in [workspace, temp]`, `zone not in [...]`.
    True when the zone being decided is one of `zones`. For a bounded target the evaluator decides
    the effect once per zone its subtree touches, so this tests one zone at a time."""

    zones: frozenset[Zone]
    negated: bool
    pos: int


@dataclass(frozen=True, slots=True)
class TargetIs:
    """`target known`, `target bounded`, `target unknown`, or with `not`."""

    resolution: Resolution
    negated: bool
    pos: int


@dataclass(frozen=True, slots=True)
class TargetIn:
    """`target in protected`: the effect's path matches a pattern in a paths list."""

    source: ListSource
    negated: bool
    pos: int


@dataclass(frozen=True, slots=True)
class HostIn:
    """`host in trusted`, on `net_out`."""

    source: ListSource
    negated: bool
    pos: int


@dataclass(frozen=True, slots=True)
class VariableIn:
    """`variable in loaders`, on `env_mutate`."""

    source: ListSource
    negated: bool
    pos: int


@dataclass(frozen=True, slots=True)
class ProgramIn:
    """`program in [...]`, on `exec` and `unknown`."""

    source: ListSource
    negated: bool
    pos: int


@dataclass(frozen=True, slots=True)
class StatementHas:
    """`statement has read in zone secret`: another effect of `kind`, in one of `zones` when given,
    occurs in the same statement (one `and_or` list). The one construct for combinations; it is
    what the exfiltration rule needs."""

    kind: EffectKind
    zones: frozenset[Zone] | None
    negated: bool
    pos: int


@dataclass(frozen=True, slots=True)
class RepeatsDenied:
    """`repeats denied target` or `repeats denied zone`, against the session's refused effects."""

    by: RepeatBy
    negated: bool
    pos: int


@dataclass(frozen=True, slots=True)
class Background:
    """`background`, on `command`: some statement ends with `&`."""

    negated: bool
    pos: int


@dataclass(frozen=True, slots=True)
class SubstitutionDepth:
    """`substitution depth > 1`, on `command`: the deepest nesting of `$(...)` compared with
    `value`."""

    op: Compare
    value: int
    negated: bool
    pos: int


Condition = (
    ZoneIs
    | TargetIs
    | TargetIn
    | HostIn
    | VariableIn
    | ProgramIn
    | StatementHas
    | RepeatsDenied
    | Background
    | SubstitutionDepth
)


@dataclass(frozen=True, slots=True)
class Rule:
    """`R4 deny delete | write where zone not in [workspace, temp] and target not in benign`.

    Rules have no order. Every rule whose subject and conditions hold casts its verdict as a vote,
    the result is the join of the votes, and a subject no rule matches abstains (which the policy
    turns into `ESCALATE`). So an `allow` can stop abstention but can never cancel a `deny`.
    `conditions` are joined by `and`; an empty tuple means the rule always holds for its subject.
    """

    rule: RuleId
    verdict: Verdict
    subject: Subject
    conditions: tuple[Condition, ...]
    pos: int


@dataclass(frozen=True, slots=True)
class Expect:
    """`expect deny R4 "rm -rf ~/*" after "cd ~"`: a test the policy carries. The evaluator runs
    `after` in order, then `command`, and the policy refuses to load if the verdict, or the rule
    when one is named, differs."""

    verdict: Verdict
    rule: RuleId | None
    command: str
    after: tuple[str, ...]
    pos: int


@dataclass(frozen=True, slots=True)
class PolicyFile:
    """One parsed and checked policy file."""

    name: str
    zones: tuple[ZoneDef, ...]
    lists: tuple[ListDef, ...]
    rules: tuple[Rule, ...]
    expects: tuple[Expect, ...]
    src: str
    pos: int = 0

    def list_items(self, source: ListSource) -> tuple[str, ...] | tuple[PathPattern, ...]:
        """The items a condition's list stands for, whether named or written in place."""
        if isinstance(source, InlineList):
            return source.items
        for definition in self.lists:
            if definition.name == source.name:
                return definition.items
        raise KeyError(source.name)  # cannot happen for a checked file


@dataclass(frozen=True, slots=True)
class PolicyResult:
    """What the front end returns: a policy, or the reasons there is none. Never both: a file with
    any error is not loaded, so `policy` is None exactly when `errors` is non-empty."""

    policy: PolicyFile | None
    errors: tuple[PolicyError, ...]

    @property
    def ok(self) -> bool:
        return self.policy is not None
