"""What a knowledge table entry reports, the option parser, and the table itself. The entries
live in the sibling modules, which register themselves in `TABLE` when imported."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from compiler.resolve import Field, Unresolved
from compiler.types import EffectKind, Host, Process, Program, Variable

Arg = Field | Unresolved

READ, WRITE, APPEND, DELETE, CHDIR = (
    EffectKind.READ,
    EffectKind.WRITE,
    EffectKind.APPEND,
    EffectKind.DELETE,
    EffectKind.CHDIR,
)
EXEC, INTERPRET, NET_OUT = EffectKind.EXEC, EffectKind.INTERPRET, EffectKind.NET_OUT
PRIV, ENV, SIGNAL, UNKNOWN = (
    EffectKind.PRIV_CHANGE,
    EffectKind.ENV_MUTATE,
    EffectKind.SIGNAL,
    EffectKind.UNKNOWN,
)

HERE = Field(".")  # the working directory, as an operand


# --------------------------------------------------------------------------- what an entry reports


@dataclass(frozen=True, slots=True)
class OnPath:
    """An effect on a path operand. `recursive` means everything at or under it: `rm -r dir`."""

    kind: EffectKind
    arg: Arg
    recursive: bool = False


@dataclass(frozen=True, slots=True)
class OnTarget:
    """An effect on something that is not a path. `reason` set means the target is unknown."""

    kind: EffectKind
    target: Host | Program | Process | Variable | None = None
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class Run:
    """Another command this one runs with the same working directory: `sudo rm x` runs `rm x`."""

    argv: tuple[Arg, ...]


@dataclass(frozen=True, slots=True)
class AtHome:
    """An effect on a path under the session's home: `cd` with no operand, `git config --global`.
    Kept apart from `OnPath` so a quoted `'~'` operand is never mistaken for the home."""

    kind: EffectKind
    rest: str = ""


Want = OnPath | OnTarget | Run | AtHome


def unknown(head: str, reason: str) -> list[Want]:
    return [OnTarget(UNKNOWN, Program(head), reason)]


# --------------------------------------------------------------------------- option parsing


@dataclass(frozen=True, slots=True)
class Opts:
    """The options an entry understands.

    `flags` and `valued` are option keys: a single letter for a short option, or the long name
    for a long-only one. `long` maps each long name to its key. `dangerous` maps a key to the
    effect kind it adds, which is what an unseen argument might turn on. `numeric` accepts `-5`
    as `head -5` does. `posix` stops at the first operand, for commands whose operands are a
    command line of their own (`env`, `sudo`, `xargs`, `timeout`).
    """

    flags: str | frozenset[str] = ""
    valued: str | frozenset[str] = ""
    long: Mapping[str, str] = field(default_factory=dict)
    dangerous: Mapping[str, EffectKind] = field(default_factory=dict)
    numeric: bool = False
    posix: bool = False
    optional: frozenset[str] = frozenset()  # long flags that may take `=value`: --color=auto

    def is_flag(self, key: str) -> bool:
        return key in self.flags if isinstance(self.flags, frozenset) else len(key) == 1 and key in self.flags

    def is_valued(self, key: str) -> bool:
        return (
            key in self.valued if isinstance(self.valued, frozenset) else len(key) == 1 and key in self.valued
        )


@dataclass(slots=True)
class Parsed:
    options: list[tuple[str, Arg | None]] = field(default_factory=list)
    operands: list[Arg] = field(default_factory=list)
    unseen: list[Arg] = field(default_factory=list)  # args before `--` that may be options

    def has(self, *keys: str) -> bool:
        return any(k in keys for k, _ in self.options)

    def values(self, *keys: str) -> list[Arg]:
        return [v for k, v in self.options if k in keys and v is not None]


class OptionError(Exception):
    """An option the entry does not model. The message is the reason the command is UNKNOWN."""


def parse(args: tuple[Arg, ...], opts: Opts) -> Parsed:
    out = Parsed()
    i = 0
    ended = False
    while i < len(args):
        arg = args[i]
        i += 1
        if ended:
            out.operands.append(arg)
            continue
        if isinstance(arg, Unresolved) or (arg.is_pattern and arg.glob_at == 0):
            out.unseen.append(arg)
            out.operands.append(arg)
            if opts.posix:
                ended = True
            continue
        text = arg.text
        if text == "--":
            ended = True
            continue
        if not text.startswith("-") or text == "-":
            out.operands.append(arg)
            if opts.posix:
                ended = True
            continue
        if text.startswith("--"):
            name, eq, value = text[2:].partition("=")
            key = _long_key(name, opts)
            if opts.is_valued(key):
                if eq:
                    out.options.append((key, Field(value)))
                elif i < len(args):
                    out.options.append((key, args[i]))
                    i += 1
                else:
                    raise OptionError(f"--{name} needs a value")
            elif eq and key not in opts.optional:
                raise OptionError(f"--{name} does not take a value")
            else:
                out.options.append((key, None))
            continue
        if opts.numeric and text[1:].isdigit():
            out.options.append(("#", Field(text[1:])))
            continue
        j = 1
        while j < len(text):
            letter = text[j]
            j += 1
            if opts.is_valued(letter):
                if j < len(text):
                    out.options.append((letter, Field(text[j:])))
                elif i < len(args):
                    out.options.append((letter, args[i]))
                    i += 1
                else:
                    raise OptionError(f"-{letter} needs a value")
                break
            if not opts.is_flag(letter):
                raise OptionError(f"option -{letter} is not modelled")
            out.options.append((letter, None))
    return out


def _long_key(name: str, opts: Opts) -> str:
    """The key for a long option, matching unambiguous prefixes as GNU getopt does."""
    if name in opts.long:
        return opts.long[name]
    matches = {key for long, key in opts.long.items() if long.startswith(name)} if name else set()
    if len(matches) == 1:
        return matches.pop()
    if matches:
        raise OptionError(f"--{name} is ambiguous")
    raise OptionError(f"option --{name} is not modelled")


def _guarded(
    head: str, opts: Opts, handler: Callable[[str, Parsed], list[Want]]
) -> Callable[[str, tuple], list]:
    """Parse, run the handler, and add what an unseen argument might switch on."""

    def run(name: str, args: tuple[Arg, ...]) -> list[Want]:
        try:
            parsed = parse(args, opts)
        except OptionError as exc:
            return unknown(name, str(exc))
        wants = handler(name, parsed)
        if parsed.unseen and opts.dangerous:
            why = f"an argument we cannot see may be an option of {name}"
            for kind in sorted(set(opts.dangerous.values())):
                wants.append(OnPath(kind, Unresolved(why)) if kind in _PATHY else OnTarget(kind, None, why))
        return wants

    return run


_PATHY = frozenset({READ, WRITE, APPEND, DELETE, CHDIR, PRIV})


def _o(flags: str = "", valued: str = "", **kw) -> Opts:
    return Opts(flags=flags, valued=valued, **kw)


# --------------------------------------------------------------------------- entries

TABLE: dict[str, Callable[[str, tuple[Arg, ...]], list[Want]]] = {}


def entry(*names: str, opts: Opts | None = None):
    def register(handler: Callable[[str, Parsed], list[Want]]):
        for name in names:
            TABLE[name] = _guarded(name, opts or Opts(), handler) if opts is not None else handler
        return handler

    return register


def _reads(parsed: Parsed, recursive: bool = False, default: Arg | None = None) -> list[Want]:
    operands = parsed.operands or ([default] if default is not None else [])
    return [OnPath(READ, a, recursive) for a in operands]


# No effects beyond running the program. Arguments are data, not paths.
for _name in (
    "echo",
    "true",
    "false",
    ":",
    "test",
    "[",
    "sleep",
    "whoami",
    "id",
    "uname",
    "pwd",
    "seq",
    "yes",
    "basename",
    "dirname",
    "expr",
    "which",
    "type",
    "ps",
    "tr",
    "printenv",
):
    TABLE[_name] = lambda name, args: []


@entry(
    "date",
    opts=Opts(
        "uRI",
        "drs",
        {"utc": "u", "date": "d", "reference": "r", "iso-8601": "I", "rfc-email": "R", "set": "s"},
        optional=frozenset("I"),
    ),
)
def _date(name: str, p: Parsed) -> list[Want]:
    wants: list[Want] = [OnPath(READ, v) for v in p.values("r")]
    if p.has("s"):
        wants.append(OnTarget(PRIV, None))
    return wants
