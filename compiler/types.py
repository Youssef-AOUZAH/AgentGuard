"""Middle-end types: effects, resolution, zones, verdicts, decisions, and session state.

This is the contract between the middle end (resolver, effect analysis, policy engine; piece 1b)
and everything downstream of it: the gate, the classifier and the bench. It is the twin of
`compiler/syntax.py`, which holds what the front end produces. Seams S3, S4 and S5 in
`docs/interfaces.md` are declared here, and S6 and S7 depend on the names below.

Takes in: nothing. It only declares types, and every one of them is immutable. The resolver
annotates by building new values, and the gate updates session state by replacing it with
`dataclasses.replace`, never by mutating it.

The invariants that matter most are checked when a value is constructed, so that a bad value
cannot exist rather than relying on every consumer to check:

- A filesystem target is absolute and contains no `..`. A relative path would make its zone
  depend on whoever reads it, and `..` would defeat containment, because path containment in
  `pathlib` is textual: `PurePosixPath("/ws/../etc").is_relative_to("/ws")` is True.
- A `BOUNDED` resolution always bounds a directory, and an `UNKNOWN` one has no target and a
  stated reason.
- A file effect (read, write, append, delete, chdir) names a path unless it is `UNKNOWN`, so
  every one of them can be zoned. No effect is a `MOVE`: a move is a delete plus a write.
- A `DENY` decision always cites at least one rule.
- `ABSTAIN` does not exist at this seam. The policy engine may use it internally, but it turns
  total abstention into `ESCALATE` before returning (`docs/interfaces.md` S5).

What this module deliberately does not handle: computing zones, ordering zones by severity,
deciding anything, and converting `ESCALATE` to `DENY` when no human is present. Zones are
computed by the policy engine against the session's workspace and home; the conversion is the
gate's job, because the policy does not know whether anyone is watching.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from pathlib import PurePosixPath
from types import MappingProxyType

from compiler.syntax import Node, Word

# ---------------------------------------------------------------------------
# Effects (docs/policy-rules.md section 1)
# ---------------------------------------------------------------------------


class EffectKind(StrEnum):
    """One thing a command would do. A command usually has several effects.

    `MOVE` names what `mv` does, so the knowledge table can say it, but no `Effect` carries it:
    a move is always emitted as `DELETE(source)` plus `WRITE(destination)`. With a single target
    a move could only cite one of its two paths, and `mv ~/.ssh/id_rsa ./x` on its destination
    alone looks like a workspace write that hides the removal of a secret.

    `INTERPRET` is distinct from `EXEC` on purpose: `python file.py` runs a program by name,
    `python -c '...'` runs code we would have to parse in another language.
    """

    READ = "read"
    WRITE = "write"
    APPEND = "append"
    DELETE = "delete"
    MOVE = "move"
    CHDIR = "chdir"
    EXEC = "exec"
    INTERPRET = "interpret"
    NET_OUT = "net-out"
    NET_LISTEN = "net-listen"
    PRIV_CHANGE = "priv-change"
    ENV_MUTATE = "env-mutate"
    SIGNAL = "signal"
    UNKNOWN = "unknown"  # the command head is not in the knowledge table


# Kinds that act on a file, and so must name the path they act on unless it is Unknown.
FILE_KINDS: frozenset[EffectKind] = frozenset(
    {
        EffectKind.READ,
        EffectKind.WRITE,
        EffectKind.APPEND,
        EffectKind.DELETE,
        EffectKind.CHDIR,
    }
)

# Kinds whose target, when there is one, is a filesystem path. PRIV_CHANGE is here but not in
# FILE_KINDS: `chmod f` has a path, `sudo` has none, and R5 denies every PRIV_CHANGE either way.
PATH_KINDS: frozenset[EffectKind] = FILE_KINDS | {EffectKind.PRIV_CHANGE}

# Kinds that change or remove data, and so are denied by R2 when their target is UNKNOWN.
DESTRUCTIVE_KINDS: frozenset[EffectKind] = frozenset(
    {
        EffectKind.WRITE,
        EffectKind.APPEND,
        EffectKind.DELETE,
        EffectKind.PRIV_CHANGE,
    }
)


# Non-path targets. Each is a small named type rather than a bare string, so a host can never
# be mistaken for a path or a variable name for a program.


@dataclass(frozen=True, slots=True)
class Host:
    """A network host, as written after URL parsing. Lower-cased; no scheme, path or port."""

    name: str

    def __post_init__(self) -> None:
        if not self.name or self.name != self.name.lower():
            raise ValueError(f"host name must be non-empty and lower-case: {self.name!r}")


@dataclass(frozen=True, slots=True)
class Port:
    """A port a command would bind, for `NET_LISTEN`."""

    number: int

    def __post_init__(self) -> None:
        if not 0 <= self.number <= 65535:
            raise ValueError(f"port out of range: {self.number}")


@dataclass(frozen=True, slots=True)
class Program:
    """A program named as a command head, for `EXEC` and `UNKNOWN`. The name as resolved,
    for example `ls` or `/usr/bin/ls`; this is not a filesystem target and is never zoned."""

    name: str

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("program name must be non-empty")


@dataclass(frozen=True, slots=True)
class Process:
    """A process a signal is sent to, for `SIGNAL`. Negative ids are process groups, as with
    `kill`; `-1` means every process the user may signal."""

    pid: int


@dataclass(frozen=True, slots=True)
class Variable:
    """A shell variable a command changes, for `ENV_MUTATE`."""

    name: str

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("variable name must be non-empty")


@dataclass(frozen=True, slots=True)
class Fd:
    """A file descriptor, for effects on a descriptor rather than a named file."""

    number: int

    def __post_init__(self) -> None:
        if self.number < 0:
            raise ValueError(f"file descriptor must be non-negative: {self.number}")


Target = PurePosixPath | Host | Port | Program | Process | Variable | Fd


# ---------------------------------------------------------------------------
# Resolution (docs/decisions.md, "Resolution has three values, not two")
#
# Together with the target, the resolution says what an effect touches:
#   Known()          target is exactly the thing touched         rm build/out.o
#   Bounded()        target is a directory; everything touched   rm -rf build, rm *
#                    is at or under it
#   Unknown(reason)  no target: we cannot even bound it          rm $(cat list)
# The docs write these as KNOWN(path), BOUNDED(dir) and UNKNOWN(reason). The path or directory
# lives in `Effect.target` rather than inside the resolution, so it is stored exactly once.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Known:
    """The target names exactly what the effect touches."""


@dataclass(frozen=True, slots=True)
class Bounded:
    """The target is a directory, and every path the effect touches is at or under it.

    Containment is textual, not symlink-aware: a symlink under the directory can point
    anywhere. That is a named residual risk in `docs/threat-model.md`.
    """


@dataclass(frozen=True, slots=True)
class Unknown:
    """We cannot even bound what the effect touches. The reason is shown to the agent and
    cited in the decision, so it must say what we could not determine."""

    reason: str

    def __post_init__(self) -> None:
        if not self.reason:
            raise ValueError("an Unknown resolution must state its reason")


Resolution = Known | Bounded | Unknown


@dataclass(frozen=True, slots=True)
class Effect:
    """One effect of one command (`docs/interfaces.md` S4).

    `origin` is the AST node (or word) that caused the effect, so a verdict can point at the
    characters responsible. It takes part in equality on purpose: the same effect caused by two
    different parts of a command is two effects, and both must be citable.
    """

    kind: EffectKind
    target: Target | None
    resolution: Resolution
    origin: Node | Word

    def __post_init__(self) -> None:
        if self.kind is EffectKind.MOVE:
            raise ValueError("emit a move as DELETE of the source plus WRITE of the destination")
        if isinstance(self.resolution, Unknown):
            if self.target is not None:
                raise ValueError("an Unknown effect has no target; say why in the reason")
            return
        if isinstance(self.resolution, Bounded) and not isinstance(self.target, PurePosixPath):
            raise ValueError("a Bounded effect must bound a directory path")
        if self.kind in FILE_KINDS and not isinstance(self.target, PurePosixPath):
            # Without a path there is no zone, so R4 could not see the effect at all.
            raise ValueError(f"a {self.kind} effect needs a path target, or an Unknown resolution")
        if isinstance(self.target, PurePosixPath):
            _check_absolute_path(self.target)


def _check_absolute_path(path: PurePosixPath) -> None:
    if not path.is_absolute():
        raise ValueError(f"effect paths must be absolute, got {path}")
    if ".." in path.parts:
        raise ValueError(f"effect paths must not contain '..', got {path}")
    if str(path).startswith("//"):
        # POSIX leaves a leading '//' implementation-defined, and pathlib preserves it.
        raise ValueError(f"effect paths must not start with '//', got {path}")


# ---------------------------------------------------------------------------
# Zones (docs/policy-rules.md section 2)
# ---------------------------------------------------------------------------


class Zone(StrEnum):
    """The region a path falls in, computed by the policy engine against session state.

    No severity order is declared here: a `Bounded` target falls in every zone its subtree
    contains, and the policy decides each (kind, zone) pair and keeps the strictest verdict,
    which needs an order on verdicts, not on zones.
    """

    WORKSPACE = "workspace"
    HOME = "home"
    SECRET = "secret"
    SYSTEM = "system"
    DEVICE = "device"
    TEMP = "temp"
    OUTSIDE = "outside"


# ---------------------------------------------------------------------------
# Verdicts and decisions (docs/policy-rules.md section 3, docs/interfaces.md S5)
# ---------------------------------------------------------------------------


class Verdict(IntEnum):
    """`ALLOW < ESCALATE < DENY`. Any stage may raise a verdict; none may lower it.

    An `IntEnum` so the order is the integer order and `max` is the join.
    """

    ALLOW = 0
    ESCALATE = 1
    DENY = 2

    def join(self, other: Verdict) -> Verdict:
        """The stricter of the two. The only way verdicts should be combined."""
        return max(self, other)


class RuleId(StrEnum):
    """The rules of `docs/policy-rules.md` section 5. A decision cites these, so a regression
    test can assert which rule fired rather than only the verdict."""

    R1 = "R1"  # unparseable
    R2 = "R2"  # unbounded destructive target
    R3 = "R3"  # interpreter handoff
    R4 = "R4"  # path containment
    R5 = "R5"  # privilege
    R6 = "R6"  # network
    R7 = "R7"  # obfuscation
    R8 = "R8"  # self-protection
    R9 = "R9"  # retry of a denied effect
    R10 = "R10"  # unknown head
    R11 = "R11"  # backgrounded command


@dataclass(frozen=True, slots=True)
class Reason:
    """Why a verdict was reached: the rule that fired, the effect it fired on, and a short
    human-readable detail. `effect` is None when there is no single effect to cite: for R1, where
    the command never parsed and `detail` carries the diagnostic code; for R11, which fires on
    the `&` separator rather than on anything the command does; and for an R9 retry judged on
    the whole command."""

    rule: RuleId
    effect: Effect | None
    detail: str = ""


@dataclass(frozen=True, slots=True)
class Decision:
    """The policy engine's output (`docs/interfaces.md` S5)."""

    verdict: Verdict
    reasons: tuple[Reason, ...] = ()

    def __post_init__(self) -> None:
        if self.verdict is Verdict.DENY and not self.reasons:
            raise ValueError("a DENY must cite at least one rule")

    def tighten(self, other: Decision) -> Decision:
        """Combine with another decision without ever lowering the verdict.

        This is how the classifier, a stricter project config or the gate adds its opinion. The
        result's verdict is the join of both, and it keeps every reason from both sides.
        """
        return Decision(self.verdict.join(other.verdict), self.reasons + other.reasons)


# ---------------------------------------------------------------------------
# Session state (docs/policy-rules.md section 4, docs/interfaces.md S3)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DeniedEntry:
    """One refused command in the session's history: what the classifier compares a new
    command against (R9). `turn` is the index of the command in the session, so the gate can
    compute how many turns have passed since the refusal."""

    turn: int
    command: str
    decision: Decision

    def __post_init__(self) -> None:
        if self.turn < 0:
            raise ValueError(f"turn must be non-negative: {self.turn}")
        if self.decision.verdict is Verdict.ALLOW:
            raise ValueError("an allowed command does not belong in the denied history")


@dataclass(frozen=True, slots=True)
class SessionState:
    """What the gate remembers between commands. The gate is the only writer; the resolver and
    the policy engine get this read-only value and must not try to change it.

    `cwd`, `variables` and `denied` are the three fields of `docs/interfaces.md` S3. `home` and
    `workspace` are fixed for the session and bound when the gate starts: the resolver needs
    `home` to resolve `~`, and the policy needs both to compute zones. They live here because
    `resolve(script, state)` receives no other configuration.

    `variables` maps a name to its value when it was assigned from a statically known word, or
    to an `Unknown` once it has been assigned from anything else; a variable that is not present
    was never assigned in the session. Nothing is inherited from the real environment: seeding
    this from `os.environ` would make the analysis depend on the developer's machine.
    """

    cwd: PurePosixPath
    home: PurePosixPath
    workspace: PurePosixPath
    variables: Mapping[str, str | Unknown] = field(default_factory=dict)
    denied: tuple[DeniedEntry, ...] = ()

    def __post_init__(self) -> None:
        for path in (self.cwd, self.home, self.workspace):
            _check_absolute_path(path)
        # Copy into a read-only view, so the caller's dict cannot change this state afterwards.
        object.__setattr__(self, "variables", MappingProxyType(dict(self.variables)))
