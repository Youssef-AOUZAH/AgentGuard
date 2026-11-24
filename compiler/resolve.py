"""The resolver: what each word of a command expands to, and where each command runs.

Takes in a parsed `Script` and the session's `SessionState`. Gives back a `ResolvedScript`: for
every simple command, in the order bash would run it, the directories it may run in and the
fields each of its words expands to, or why that cannot be known. `compiler/effects.py` reads
this to build `Effect`s; nothing else does, so these types live here, not in `types.py`.

The resolver never touches the filesystem, never reads `os.environ`, and never runs anything.
Everything it knows comes from the source text and the session state.

What it does, in bash's order (bash manual, "Shell Expansions"):

- **Brace expansion** of plain `{a,b}` and `{1..3}` forms. Anything fancier is unresolved.
- **Tilde expansion** of `~` against a tracked `HOME` if the session has one, else `state.home`
  (`docs/interfaces.md` S3). `~user`, `~+` and `~-` are unresolved.
- **Parameter expansion** of `$name` and `${name}` from tracked variables. Operator forms, special
  parameters and untracked names are unresolved: a value is never guessed, and nothing is read from
  the real environment.
- **Field splitting** of unquoted expansion results on `IFS`, with POSIX's whitespace rules.
- **Pathname expansion** is not performed. A field with an active glob character records where
  the pattern starts, and `effects.py` bounds it to the directory before that point.

Command substitution and arithmetic are always unresolved. A command substitution's own commands
are still resolved, against a copy of the state, because they run and have effects of their own.

**Session changes within one script.** `cd build && rm *` runs `rm` in `build`, so the resolver
follows the working directory and variables through the script. Because a command can fail,
it tracks the state on success and on failure separately through `&&`, `||` and `!`. After a
statement, the two are joined, and the working directory becomes the set of places it may be:
`cd build; rm *` may run `rm` in either directory if the `cd` fails. A variable whose value
differs between the two becomes `Unknown`. Subshells, pipelines of several commands, backgrounded
statements and command substitutions run in a child shell, so their changes are discarded.

Anything that can change the state in a way we do not follow makes the affected state unknown,
rather than leaving it stale (`docs/decisions.md`, "Variables change in more ways than assignment
words"):

- `unset`, `read`, `export`, `declare`, `mapfile` and the like make the variables they name
  `Unknown`, or every variable when the names cannot be read;
- `${x:=v}` and `${x=v}` make `x` `Unknown`;
- `eval`, `source`, `.`, `enable`, an unresolved command name, and `command` or `builtin` in
  front of a state-changing builtin make the working directory and every variable unknown;
- `shopt` and `set` can change how globs match (`shopt -u globskipdots` lets `.*` match `..`),
  so every glob after them is unresolved.

What this module deliberately does not handle: deciding anything, and knowing what a program
does with its arguments. Both belong to `effects.py` and `policy.py`.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from pathlib import PurePosixPath
from types import MappingProxyType

from compiler.syntax import (
    AndOr,
    AndOrOp,
    PartKind,
    Pipeline,
    Redirect,
    RedirectOp,
    Script,
    SimpleCommand,
    Statement,
    Subshell,
    Word,
    WordPart,
)
from compiler.types import SessionState, Unknown

# Above these sizes, a value is reported as unresolved rather than enumerated.
MAX_FIELDS = 256  # fields from one word, after brace expansion and splitting
MAX_CWDS = 8  # possible working directories at one command

DEFAULT_IFS = " \t\n"
GLOB_CHARS = frozenset("*?[")
_IFS_WHITESPACE = frozenset(" \t\n")

_SIMPLE_PARAM = re.compile(r"\$(?:([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)\})")
_ASSIGNING_PARAM = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*):?=")
_NAME_ARG = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)(?:\[[^\]]*\])?(?:\+?=.*)?", re.S)
_BRACE_PLAIN = re.compile(r"\{[^{}$`'\"\\~*?\[\]]*\}")
_BRACE_SEQ = re.compile(r"\{(-?\d+|[A-Za-z])\.\.(-?\d+|[A-Za-z])(?:\.\.(-?\d+))?\}")

# Builtins that change variables as commands. Each name-like argument is invalidated; that
# over-approximates (`read -p prompt x` also invalidates `prompt`), which is the safe direction.
VARIABLE_BUILTINS = frozenset(
    {
        "unset", "read", "export", "declare", "typeset", "local", "readonly", "mapfile", "readarray",
        "getopts", "printf",
    }
)  # fmt: skip
# The variable a builtin writes when given no name.
_DEFAULT_TARGET = {"read": "REPLY", "mapfile": "MAPFILE", "readarray": "MAPFILE"}
# Builtins whose effect on the session we do not follow at all.
OPAQUE_BUILTINS = frozenset({"eval", "source", ".", "enable", "alias", "unalias", "trap"})
# Builtins that change how later words expand.
OPTION_BUILTINS = frozenset({"shopt", "set"})
DIRECTORY_BUILTINS = frozenset({"cd", "pushd", "popd"})
WRAPPERS = frozenset({"command", "builtin"})
# POSIX special builtins: a prefix assignment in front of one may persist in the shell.
SPECIAL_BUILTINS = frozenset(
    {
        ":", ".", "break", "continue", "eval", "exec", "exit", "export", "readonly", "return", "set", "shift",
        "times", "trap", "unset", "source",
    }
)  # fmt: skip


# --------------------------------------------------------------------------- results


@dataclass(frozen=True, slots=True)
class Field:
    """One argument bash would pass. `glob_at` is the index in `text` of the first character that
    would start pathname expansion, or None when the field is passed as written. A pattern that
    matches nothing is passed literally, so `text` is also what bash passes in that case."""

    text: str
    glob_at: int | None = None

    @property
    def is_pattern(self) -> bool:
        return self.glob_at is not None


@dataclass(frozen=True, slots=True)
class Fields:
    """A word whose expansion is known: zero or more fields. Zero is real: an unquoted empty
    expansion passes no argument at all."""

    fields: tuple[Field, ...]


@dataclass(frozen=True, slots=True)
class Unresolved:
    """A word we cannot expand. Neither its value nor its number of fields is known."""

    reason: str


WordValue = Fields | Unresolved


@dataclass(frozen=True, slots=True)
class ResolvedRedirect:
    """A redirection and its target. `target` is None for a here-document, whose body is literal
    because the grammar accepts only quoted delimiters. For a file redirection it holds exactly
    one field or is unresolved: bash refuses an expansion to zero or several words."""

    redirect: Redirect
    target: Field | Unresolved | None


@dataclass(frozen=True, slots=True)
class ResolvedCommand:
    """One simple command with everything the effect analysis needs about its context.

    `cwd` is every directory the command may run in, or `Unknown`. `words` lines up with
    `node.words`. `env` holds the command's own prefix assignments (`A=1 cmd`), which reach the
    program's environment but not the session. `depth` counts the command substitutions this
    command is nested in, 0 for a top-level command. `background` is True when its statement
    ends with `&`.
    """

    node: SimpleCommand
    cwd: tuple[PurePosixPath, ...] | Unknown
    words: tuple[WordValue, ...]
    env: tuple[tuple[str, str | Unknown], ...]
    redirects: tuple[ResolvedRedirect, ...]
    depth: int = 0
    background: bool = False

    @property
    def argv(self) -> tuple[Field, ...] | Unresolved:
        """All the fields in order, or the first reason one word could not be expanded."""
        out: list[Field] = []
        for value in self.words:
            if isinstance(value, Unresolved):
                return value
            out.extend(value.fields)
        return tuple(out)

    @property
    def head(self) -> str | Unresolved | None:
        """The program name bash would look up: the first field of the first word that has one.
        None when there is no command word, as in a bare assignment or `$EMPTY` alone."""
        for value in self.words:
            if isinstance(value, Unresolved):
                return value
            if value.fields:
                first = value.fields[0]
                if first.is_pattern:
                    return Unresolved("the command name is a glob pattern")
                return first.text
        return None


@dataclass(frozen=True, slots=True)
class ResolvedScript:
    """Every simple command in `script`, in the order it would run. A command substitution's
    commands come before the command whose words contain it, because they run first."""

    script: Script
    commands: tuple[ResolvedCommand, ...]


# --------------------------------------------------------------------------- the state as it evolves


@dataclass(frozen=True, slots=True)
class _Env:
    cwds: frozenset[PurePosixPath] | Unknown
    variables: Mapping[str, str | Unknown]
    home: PurePosixPath
    globs_ok: bool = True

    def with_variables(self, updates: Mapping[str, str | Unknown]) -> _Env:
        if not updates:
            return self
        return replace(self, variables=MappingProxyType({**self.variables, **updates}))

    def forget_all(self, reason: str) -> _Env:
        unknown = Unknown(reason)
        return replace(self, cwds=unknown, variables=_AllUnknown(self.variables, unknown))


class _AllUnknown(Mapping[str, str | Unknown]):
    """Every variable, tracked or not, is unknown. Needed because after `eval` even a variable the
    session never tracked may have been set, and an untracked variable is otherwise unresolved by
    name rather than by this reason."""

    def __init__(self, base: Mapping[str, str | Unknown], unknown: Unknown) -> None:
        self._keys = tuple(base)
        self._unknown = unknown

    def __getitem__(self, key: str) -> str | Unknown:
        return self._unknown

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str)

    def __iter__(self):
        return iter(self._keys)

    def __len__(self) -> int:
        return len(self._keys)


def _join(a: _Env, b: _Env) -> _Env:
    """The state when either `a` or `b` may hold."""
    if a is b:
        return a
    if isinstance(a.cwds, Unknown):
        cwds: frozenset[PurePosixPath] | Unknown = a.cwds
    elif isinstance(b.cwds, Unknown):
        cwds = b.cwds
    else:
        cwds = a.cwds | b.cwds
        if len(cwds) > MAX_CWDS:
            cwds = Unknown(f"more than {MAX_CWDS} possible working directories")
    if isinstance(a.variables, _AllUnknown):
        variables: Mapping[str, str | Unknown] = a.variables
    elif isinstance(b.variables, _AllUnknown):
        variables = b.variables
    else:
        merged: dict[str, str | Unknown] = {}
        for name in a.variables.keys() | b.variables.keys():
            left, right = a.variables.get(name), b.variables.get(name)
            if left == right and left is not None:
                merged[name] = left
            else:
                merged[name] = Unknown(f"${name} differs depending on which commands ran")
        variables = MappingProxyType(merged)
    return _Env(cwds, variables, a.home, a.globs_ok and b.globs_ok)


@dataclass(slots=True)
class _Outcome:
    ok: _Env
    fail: _Env

    @classmethod
    def same(cls, env: _Env) -> _Outcome:
        return cls(env, env)

    def joined(self) -> _Env:
        return _join(self.ok, self.fail)


# --------------------------------------------------------------------------- entry point


def resolve(script: Script, state: SessionState) -> ResolvedScript:
    """Resolve every word in `script` against `state`. Never mutates `state` and never raises
    for a parsed script: what cannot be resolved is reported as `Unresolved` or `Unknown`."""
    env = _Env(frozenset({state.cwd}), MappingProxyType(dict(state.variables)), state.home)
    resolver = _Resolver()
    resolver.statements(script.statements, env, depth=0)
    return ResolvedScript(script, tuple(resolver.out))


@dataclass(slots=True)
class _Resolver:
    out: list[ResolvedCommand] = field(default_factory=list)

    # ---- structure

    def statements(self, statements: Iterable[Statement], env: _Env, depth: int) -> _Env:
        for statement in statements:
            if statement.background:
                # Runs asynchronously in a child shell: nothing it does reaches the next statement.
                self.and_or(statement.and_or, env, depth, background=True)
            else:
                env = self.and_or(statement.and_or, env, depth).joined()
        return env

    def and_or(self, node: AndOr, env: _Env, depth: int, background: bool = False) -> _Outcome:
        outcome = self.pipeline(node.first, env, depth, background)
        for op, pipeline in node.rest:
            if op is AndOrOp.AND:
                after = self.pipeline(pipeline, outcome.ok, depth, background)
                outcome = _Outcome(after.ok, _join(outcome.fail, after.fail))
            else:
                after = self.pipeline(pipeline, outcome.fail, depth, background)
                outcome = _Outcome(_join(outcome.ok, after.ok), after.fail)
        return outcome

    def pipeline(self, node: Pipeline, env: _Env, depth: int, background: bool) -> _Outcome:
        if len(node.commands) == 1:
            outcome = self.command(node.commands[0], env, depth, background)
        else:
            # Every command of a multi-command pipeline runs in its own child shell.
            for command in node.commands:
                self.command(command, env, depth, background)
            outcome = _Outcome.same(env)
        return _Outcome(outcome.fail, outcome.ok) if node.negated else outcome

    def command(self, node: SimpleCommand | Subshell, env: _Env, depth: int, background: bool) -> _Outcome:
        if isinstance(node, Subshell):
            self.statements(node.body, env, depth)
            for redirect in node.redirects:
                self.substitutions_in(redirect.target, env, depth)
            return _Outcome.same(env)
        return self.simple(node, env, depth, background)

    # ---- one simple command

    def simple(self, node: SimpleCommand, env: _Env, depth: int, background: bool) -> _Outcome:
        for word in (*(a.value for a in node.assignments), *node.words, *(r.target for r in node.redirects)):
            self.substitutions_in(word, env, depth)

        words = tuple(expand(word, env) for word in node.words)
        prefix = tuple((a.name, assigned_value(a.value, env)) for a in node.assignments)
        redirects = tuple(_redirect(r, env) for r in node.redirects)
        cwd = env.cwds if isinstance(env.cwds, Unknown) else tuple(sorted(env.cwds))
        resolved = ResolvedCommand(node, cwd, words, prefix, redirects, depth, background)
        self.out.append(resolved)
        return _after(resolved, env)

    def substitutions_in(self, word: Word | None, env: _Env, depth: int) -> None:
        """Resolve the commands inside each `$(...)` of `word`, in a child shell."""
        if word is None:
            return
        for part in _walk_parts(word.parts):
            if part.kind is PartKind.CMD_SUBST and part.script is not None:
                self.statements(part.script.statements, env, depth + 1)


def _walk_parts(parts: Iterable[WordPart]):
    for part in parts:
        yield part
        yield from _walk_parts(part.parts)


# --------------------------------------------------------------------------- how a command changes the state


def _after(command: ResolvedCommand, env: _Env) -> _Outcome:
    """The state after `command` succeeds and after it fails."""
    env = env.with_variables(_assigned_by_expansion(command.node, env))
    head = command.head
    if command.node.name is None:
        # A bare assignment persists; it cannot fail in a way that undoes it.
        return _Outcome.same(env.with_variables(dict(command.env)))
    if isinstance(head, Unresolved):
        return _Outcome.same(env.forget_all(f"a command we could not name ran: {head.reason}"))
    if head is None:
        return _Outcome.same(env)
    argv = command.argv
    if isinstance(argv, Unresolved):
        # The name is known but an argument is not: a state-changing builtin may change anything.
        if head in _STATEFUL or head in WRAPPERS:
            return _Outcome.same(env.forget_all(f"{head} was given an argument we could not resolve"))
        return _Outcome.same(env)
    args = argv[1:]

    if head in SPECIAL_BUILTINS and command.env:
        env = env.with_variables({name: Unknown(f"assigned in front of {head}") for name, _ in command.env})
    if head in WRAPPERS:
        if any(f.text in _STATEFUL for f in args):
            return _Outcome.same(env.forget_all(f"{head} ran a builtin that changes the shell"))
        return _Outcome.same(env)
    if head in OPAQUE_BUILTINS:
        return _Outcome.same(env.forget_all(f"{head} can change anything in the shell"))
    if head in OPTION_BUILTINS:
        return _Outcome.same(replace(env, globs_ok=False))
    if head in VARIABLE_BUILTINS:
        return _Outcome.same(_invalidate(head, args, env))
    if head in DIRECTORY_BUILTINS:
        # bash sets PWD and OLDPWD on every directory change; we do not predict their text.
        moved = _change_directory(head, args, command, env)
        moved = moved.with_variables({name: Unknown(f"set by {head}") for name in ("PWD", "OLDPWD")})
        return _Outcome(moved, env)
    return _Outcome.same(env)


_STATEFUL = VARIABLE_BUILTINS | OPAQUE_BUILTINS | OPTION_BUILTINS | DIRECTORY_BUILTINS


def _assigned_by_expansion(node: SimpleCommand, env: _Env) -> dict[str, Unknown]:
    """`${x:=v}` and `${x=v}` assign `x` while expanding."""
    names: dict[str, Unknown] = {}
    targets = (r.target for r in node.redirects if r.target is not None)
    for word in (*(a.value for a in node.assignments), *node.words, *targets):
        for part in _walk_parts(word.parts):
            if part.kind is PartKind.PARAM_EXP and (match := _ASSIGNING_PARAM.match(part.raw)):
                names[match.group(1)] = Unknown(f"assigned while expanding {part.raw}")
    return names


def _invalidate(head: str, args: tuple[Field, ...], env: _Env) -> _Env:
    if head == "printf" and not any(f.text.startswith("-v") for f in args):
        return env  # printf without -v writes no variable
    if any(f.is_pattern for f in args):
        return env.forget_all(f"{head} was given a glob, so the names it changes are unknown")
    names = [m.group(1) for f in args if not f.text.startswith("-") and (m := _NAME_ARG.fullmatch(f.text))]
    # An option's value may be glued to it (`printf -vx`, `read -ax`); take that as a name too.
    names += [m.group(1) for f in args if f.text.startswith("-") and (m := _NAME_ARG.fullmatch(f.text[2:]))]
    if head in _DEFAULT_TARGET:
        names.append(_DEFAULT_TARGET[head])
    return env.with_variables({name: Unknown(f"changed by {head}") for name in names})


def _change_directory(head: str, args: tuple[Field, ...], command: ResolvedCommand, env: _Env) -> _Env:
    """The state after a successful `cd`, `pushd` or `popd`."""

    def unknown(reason: str) -> _Env:
        return replace(env, cwds=Unknown(reason))

    if head == "popd" or command.env:
        return unknown(f"{head} with a directory stack or prefix assignments is not followed")
    operands = list(args)
    while operands and operands[0].text.startswith("-") and operands[0].text != "-":
        if operands[0].text == "--":
            operands.pop(0)
            break
        if operands[0].text == "-P":
            return unknown(f"{head} -P resolves symlinks on the filesystem, which we do not read")
        if operands[0].text not in ("-L", "-e"):
            return unknown(f"{head} option {operands[0].text} is not followed")
        operands.pop(0)
    if len(operands) > 1:
        return unknown(f"{head} was given more than one directory")
    if not operands:
        if head == "pushd":
            return unknown("pushd with no directory swaps the stack")
        target = _home(env)
        if isinstance(target, Unknown):
            return unknown(target.reason)
        operand = str(target)
    else:
        if operands[0].is_pattern:
            return unknown(f"{head} to a glob pattern")
        operand = operands[0].text
    if operand == "-":
        return unknown(f"{head} - goes to $OLDPWD, which is not tracked")
    if operand == "" or operand.startswith("//"):
        return unknown(f"{head} to {operand!r} is not followed")
    if not operand.startswith("/"):
        cdpath = env.variables.get("CDPATH")
        if cdpath is not None and cdpath != "":
            return unknown("$CDPATH is set, so a relative cd may go elsewhere")
        if isinstance(env.cwds, Unknown):
            return env
    bases = [PurePosixPath("/")] if operand.startswith("/") else sorted(env.cwds)  # type: ignore[arg-type]
    return replace(env, cwds=frozenset(logical_join(base, operand) for base in bases))


def logical_join(base: PurePosixPath, path: str) -> PurePosixPath:
    """`cd`'s default (`-L`) meaning of `path` from `base`: `.` dropped and `..` removing the
    component before it, textually, as bash does before it looks at the filesystem."""
    parts = [] if path.startswith("/") else list(base.parts[1:])
    for component in path.split("/"):
        if component in ("", "."):
            continue
        if component == "..":
            if parts:
                parts.pop()
        else:
            parts.append(component)
    return PurePosixPath("/", *parts)


def _home(env: _Env) -> PurePosixPath | Unknown:
    """What `~` and a bare `cd` mean: a tracked `HOME` wins over the session's home."""
    tracked = env.variables.get("HOME")
    if tracked is None:
        return env.home
    if isinstance(tracked, Unknown):
        return Unknown(f"$HOME is unknown: {tracked.reason}")
    if not tracked.startswith("/"):
        return Unknown(f"$HOME is not absolute: {tracked!r}")
    return PurePosixPath(tracked)


# --------------------------------------------------------------------------- expanding one word

# A word on its way through expansion is a list of characters, each with two flags: whether it
# came from an unquoted expansion (so field splitting applies to it) and whether it is an active
# glob character. An empty string marks a quoted empty part, which keeps a field alive.
_Char = tuple[str, bool, bool]


def expand(word: Word, env: _Env) -> WordValue:
    """The fields `word` expands to, as an argument of a simple command."""
    variants = _brace_variants(word.parts)
    if isinstance(variants, Unresolved):
        return variants
    ifs = env.variables.get("IFS", DEFAULT_IFS)
    fields: list[Field] = []
    for parts in variants:
        chars = _chars(parts, env, quoted=False)
        if isinstance(chars, Unresolved):
            return chars
        if isinstance(ifs, Unknown):
            if any(splittable for _, splittable, _ in chars):
                return Unresolved(f"$IFS is unknown, so the fields cannot be split: {ifs.reason}")
            split = _split(chars, "")
        else:
            split = _split(chars, ifs)
        if not env.globs_ok and any(f.is_pattern for f in split):
            return Unresolved("glob options were changed earlier in the command")
        fields.extend(split)
        if len(fields) > MAX_FIELDS:
            return Unresolved(f"expands to more than {MAX_FIELDS} fields")
    return Fields(tuple(fields))


def assigned_value(word: Word, env: _Env) -> str | Unknown:
    """The value an assignment stores: no splitting, no globbing, no brace expansion."""
    chars = _chars(word.parts, env, quoted=True)
    if isinstance(chars, Unresolved):
        return Unknown(chars.reason)
    return "".join(c[0] for c in chars)


def _redirect(redirect: Redirect, env: _Env) -> ResolvedRedirect:
    if redirect.target is None or redirect.op in (RedirectOp.HEREDOC, RedirectOp.HEREDOC_DASH):
        return ResolvedRedirect(redirect, None)
    value = expand(redirect.target, env)
    if isinstance(value, Unresolved):
        return ResolvedRedirect(redirect, value)
    if len(value.fields) != 1:
        return ResolvedRedirect(redirect, Unresolved("ambiguous redirect: not exactly one word"))
    return ResolvedRedirect(redirect, value.fields[0])


def _chars(parts: Iterable[WordPart], env: _Env, quoted: bool) -> list[_Char] | Unresolved:
    out: list[_Char] = []
    for part in parts:
        kind = part.kind
        if kind is PartKind.DQUOTED:
            inner = _chars(part.parts, env, quoted=True)
            if isinstance(inner, Unresolved):
                return inner
            out.append(("", False, False))
            out.extend(inner)
        elif kind is PartKind.GLOB:
            if quoted:
                out.extend((c, False, False) for c in part.raw)
            else:
                out.extend((c, False, True) for c in part.raw)
        elif kind is PartKind.TILDE:
            home = _home(env) if part.raw == "~" else Unknown(part.reason or f"{part.raw} is not followed")
            if isinstance(home, Unknown):
                return Unresolved(home.reason)
            out.extend((c, False, False) for c in str(home))
        elif kind is PartKind.PARAM_EXP:
            value = _parameter(part, env)
            if isinstance(value, Unresolved):
                return value
            if quoted:
                out.append(("", False, False))
                out.extend((c, False, False) for c in value)
            else:
                out.extend((c, True, c in GLOB_CHARS) for c in value)
        elif kind in (PartKind.SQUOTED, PartKind.ANSI_C_QUOTED):
            if part.value is None:
                return Unresolved(part.reason or f"{part.raw} has no known value")
            out.append(("", False, False))
            out.extend((c, False, False) for c in part.value)
        elif part.value is not None:
            out.extend((c, False, False) for c in part.value)
        else:
            return Unresolved(part.reason or f"{part.raw} has no known value")
    return out


def _parameter(part: WordPart, env: _Env) -> str | Unresolved:
    match = _SIMPLE_PARAM.fullmatch(part.raw)
    if match is None:
        return Unresolved(part.reason or f"{part.raw} is not interpreted")
    name = match.group(1) or match.group(2)
    value = env.variables.get(name)
    if value is None:
        return Unresolved(f"${name} is not tracked")
    if isinstance(value, Unknown):
        return Unresolved(f"${name} is unknown: {value.reason}")
    return value


def _split(chars: list[_Char], ifs: str) -> list[Field]:
    """POSIX field splitting. Only characters from unquoted expansions delimit. A run of IFS
    whitespace is one delimiter and is dropped at either end; each other IFS character delimits
    on its own, together with the whitespace around it."""

    def is_ws(i: int) -> bool:
        c, splittable, _ = chars[i]
        return splittable and c in ifs and c in _IFS_WHITESPACE

    def is_hard(i: int) -> bool:
        c, splittable, _ = chars[i]
        return splittable and c != "" and c in ifs and c not in _IFS_WHITESPACE

    fields: list[Field] = []
    current: list[_Char] = []
    started = False
    n = len(chars)
    i = 0
    while i < n and is_ws(i):
        i += 1
    while i < n:
        if is_ws(i) or is_hard(i):
            j = i
            while j < n and is_ws(j):
                j += 1
            if j < n and is_hard(j):
                j += 1
                while j < n and is_ws(j):
                    j += 1
            fields.append(_field(current))
            current, started = [], False
            i = j
            continue
        current.append(chars[i])
        started = True
        i += 1
    if started:
        fields.append(_field(current))
    return fields


def _field(chars: list[_Char]) -> Field:
    text = ""
    glob_at = None
    for c, _, is_glob in chars:
        if is_glob and glob_at is None:
            glob_at = len(text)
        text += c
    return Field(text, glob_at)


# --------------------------------------------------------------------------- brace expansion


def _brace_variants(parts: tuple[WordPart, ...]) -> list[tuple[WordPart, ...]] | Unresolved:
    """The words a word becomes under brace expansion, each still a sequence of parts."""
    variants: list[list[WordPart]] = [[]]
    for part in parts:
        if part.kind is not PartKind.BRACE_EXP:
            for v in variants:
                v.append(part)
            continue
        items = _brace_items(part.raw)
        if isinstance(items, Unresolved):
            return items
        if len(variants) * len(items) > MAX_FIELDS:
            return Unresolved(f"brace expansion produces more than {MAX_FIELDS} words")
        literal = [WordPart(PartKind.LITERAL, item, value=item) for item in items]
        variants = [[*v, item] for v in variants for item in literal]
    return [tuple(v) for v in variants]


def _brace_items(raw: str) -> list[str] | Unresolved:
    seq = _BRACE_SEQ.fullmatch(raw)
    if seq is not None:
        return _sequence(*seq.groups())
    if _BRACE_PLAIN.fullmatch(raw) is None or "," not in raw:
        return Unresolved(f"brace expansion {raw} is not interpreted")
    return raw[1:-1].split(",")


def _sequence(start: str, end: str, step_text: str | None) -> list[str] | Unresolved:
    step = abs(int(step_text)) if step_text else 1
    step = step or 1
    numeric = start.lstrip("-").isdigit()
    if numeric != end.lstrip("-").isdigit():
        return Unresolved(f"brace sequence {{{start}..{end}}} mixes letters and numbers")
    a, b = (int(start), int(end)) if numeric else (ord(start), ord(end))
    if abs(b - a) // step + 1 > MAX_FIELDS:
        return Unresolved(f"brace sequence produces more than {MAX_FIELDS} words")
    values = range(a, b + 1, step) if b >= a else range(a, b - 1, -step)
    if not numeric:
        letters = [chr(v) for v in values]
        if not all(c.isalpha() for c in letters):
            # {Z..a} passes through [ \ ] ^ _ `, which would need quoting rules of their own.
            return Unresolved(f"brace sequence {{{start}..{end}}} crosses non-letters")
        return letters
    if _padded(start) or _padded(end):
        if a < 0 or b < 0:
            return Unresolved(f"zero-padded negative brace sequence {{{start}..{end}}} is not interpreted")
        width = max(len(start), len(end))
        return [str(v).zfill(width) for v in values]
    return [str(v) for v in values]


def _padded(number: str) -> bool:
    digits = number.lstrip("-")
    return len(digits) > 1 and digits.startswith("0")


__all__ = [
    "Field",
    "Fields",
    "ResolvedCommand",
    "ResolvedRedirect",
    "ResolvedScript",
    "Unresolved",
    "WordValue",
    "assigned_value",
    "expand",
    "logical_join",
    "resolve",
]
