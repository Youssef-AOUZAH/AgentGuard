"""The effect analysis: what a resolved command would do, as `Effect`s (`docs/interfaces.md` S4).

Takes in the resolver's `ResolvedScript` and the `SessionState`. Gives back a frozenset of
`Effect`s for the whole script, for the policy engine to decide on.

Effects come from three places, in order of reliability (`docs/policy-rules.md` §1):

- **Redirections**, which need no knowledge table: `> f` writes `f`, `>> f` appends, `< f` reads,
  `<> f` reads and writes. Descriptor duplication (`2>&1`, `>&3`) has no effect of its own: the
  descriptor it copies was opened by an earlier redirection, whose effect is already counted.
- **The command head**, through `compiler/knowledge/`. A known head is an `EXEC` of that
  program plus what its entry reports; an unknown head is one `UNKNOWN` effect, never nothing.
- **Structure**: every assignment, bare or prefix, is an `ENV_MUTATE` of its variable, so
  `IFS=,` and `LD_PRELOAD=x cmd` reach R7. A command name that cannot be resolved, such as
  `$(echo rm)`, is an `EXEC` of an unknown target.

Paths are made absolute against every directory the command may run in, so `cd build; rm x`
yields a delete of both `ws/x` and `ws/build/x`. They are normalised textually: `..` removes
the component before it. This is the same claim about names the threat model states for bounded
sets ("Bounded path sets are bounded textually, not by inode"); a symlink can make it wrong.

A glob bounds its field to the directory before the pattern starts: `build/*.o` is
`BOUNDED(ws/build)`. A `..` after the pattern starts can climb back out, so the bound moves up
by the furthest the rest of the path reaches above that directory, counting each glob or literal
component as one level down (a glob component matches exactly one name, and never `..`). A path
that must be relative but has no known working directory is `Unknown`.

What this module deliberately does not handle: deciding anything, and the zone of a path. Both
belong to the policy engine.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import PurePosixPath

from compiler.knowledge import TABLE, AtHome, InRepo, OnPath, OnTarget, Run, Want, unknown
from compiler.resolve import Field, ResolvedCommand, ResolvedScript, Unresolved
from compiler.syntax import Node, PartKind, RedirectOp
from compiler.types import Bounded, Effect, EffectKind, Known, Program, SessionState, Unknown, Variable

# How deep wrappers may nest (`sudo env timeout 5 nice rm x`) before the rest is unknown.
MAX_WRAPPER_DEPTH = 8

_PATH_KINDS_OF_REDIRECT = {
    RedirectOp.READ: (EffectKind.READ,),
    RedirectOp.WRITE: (EffectKind.WRITE,),
    RedirectOp.CLOBBER: (EffectKind.WRITE,),
    RedirectOp.APPEND: (EffectKind.APPEND,),
    RedirectOp.READ_WRITE: (EffectKind.READ, EffectKind.WRITE),
}

Cwds = tuple[PurePosixPath, ...] | Unknown


def effects_of(resolved: ResolvedScript, state: SessionState) -> frozenset[Effect]:
    """Every effect of every command in `resolved`. Never raises for a resolved script."""
    out: set[Effect] = set()
    for command in resolved.commands:
        out.update(_command(command, state))
    return frozenset(out)


def _command(command: ResolvedCommand, state: SessionState) -> list[Effect]:
    node = command.node
    out: list[Effect] = []
    for assignment in node.assignments:
        out.append(Effect(EffectKind.ENV_MUTATE, Variable(assignment.name), Known(), assignment))
    out += _assigned_while_expanding(command)
    for resolved in command.redirects:
        kinds = _PATH_KINDS_OF_REDIRECT.get(resolved.redirect.op, ())
        if resolved.target is None:
            continue
        for kind in kinds:
            out += path_effects(kind, resolved.target, False, command.cwd, resolved.redirect)
    head = command.head
    if head is None:
        return out
    if isinstance(head, Unresolved):
        why = Unknown(f"the command name is unknown: {head.reason}")
        return [*out, Effect(EffectKind.EXEC, None, why, node)]
    args = _args_after_head(command)
    return out + _run(head, args, command.cwd, state, node, depth=0)


def _args_after_head(command: ResolvedCommand) -> tuple[Field | Unresolved, ...]:
    """The arguments after the command name. An unresolved word stands for any number of them."""
    args: list[Field | Unresolved] = []
    seen_head = False
    for value in command.words:
        if isinstance(value, Unresolved):
            args.append(value)
            continue
        for field in value.fields:
            if not seen_head:
                seen_head = True
                continue
            args.append(field)
    return tuple(args)


def _assigned_while_expanding(command: ResolvedCommand) -> list[Effect]:
    """`${x:=v}` and `${x=v}` assign `x` while the word expands, which R7 must see."""
    out: list[Effect] = []
    for word in command.node.words:
        for part in _walk(word.parts):
            if part.kind is PartKind.PARAM_EXP and (match := _ASSIGNING_PARAM.match(part.raw)):
                out.append(Effect(EffectKind.ENV_MUTATE, Variable(match.group(1)), Known(), command.node))
    return out


_ASSIGNING_PARAM = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*):?=")


def _walk(parts):
    for part in parts:
        yield part
        yield from _walk(part.parts)


# --------------------------------------------------------------------------- the knowledge table


def _run(head: str, args, cwds: Cwds, state: SessionState, origin: Node, depth: int) -> list[Effect]:
    if head == "":
        return []  # bash: command not found, nothing runs
    handler = TABLE.get(head) if "/" not in head else None
    if handler is None:
        wants: list = unknown(head, f"{head} is not in the knowledge table")
    else:
        wants = [OnTarget(EffectKind.EXEC, Program(head)), *handler(head, args)]
    out: list[Effect] = []
    for want in wants:
        out += _want(want, cwds, state, origin, depth)
    return out


def _want(want: Want | InRepo, cwds: Cwds, state: SessionState, origin: Node, depth: int) -> list[Effect]:
    if isinstance(want, OnPath):
        return path_effects(want.kind, want.arg, want.recursive, cwds, origin)
    if isinstance(want, OnTarget):
        if want.kind is EffectKind.UNKNOWN and want.target is not None:
            # The kind already says we do not know what it does; keep the program, which
            # `program in [...]` rules match on.
            return [Effect(want.kind, want.target, Known(), origin)]
        if want.reason is not None:
            return [Effect(want.kind, None, Unknown(want.reason), origin)]
        return [Effect(want.kind, want.target, Known(), origin)]
    if isinstance(want, AtHome):
        path = state.home / want.rest if want.rest else state.home
        return path_effects(want.kind, Field(str(path)), False, cwds, origin)
    if isinstance(want, InRepo):
        return _in_repo(want, cwds, state, origin)
    if isinstance(want, Run):
        if depth >= MAX_WRAPPER_DEPTH:
            return [Effect(EffectKind.EXEC, None, Unknown("wrappers nest too deeply"), origin)]
        if not want.argv:
            return []
        head, *rest = want.argv
        if isinstance(head, Unresolved) or head.is_pattern:
            reason = head.reason if isinstance(head, Unresolved) else "the command name is a glob pattern"
            return [Effect(EffectKind.EXEC, None, Unknown(reason), origin)]
        return _run(head.text, tuple(rest), cwds, state, origin, depth + 1)
    raise TypeError(f"not a want: {want!r}")


def _in_repo(want: InRepo, cwds: Cwds, state: SessionState, origin: Node) -> list[Effect]:
    """git looks upwards for `.git`, so the repository root is known only when every working
    directory is inside the workspace, which we take to be the repository. That is a knowledge
    table assumption, stated here so the bench can test it."""
    inside = not isinstance(cwds, Unknown) and all(c.is_relative_to(state.workspace) for c in cwds)
    if not inside:
        why = Unknown("the repository root is not known outside the workspace")
        return [Effect(want.kind, None, why, origin)]
    target = state.workspace if want.path == "." else state.workspace / want.path
    resolution = Bounded() if want.recursive else Known()
    return [Effect(want.kind, target, resolution, origin)]


# --------------------------------------------------------------------------- paths


def path_effects(
    kind: EffectKind, arg: Field | Unresolved, recursive: bool, cwds: Cwds, origin: Node
) -> list[Effect]:
    """The effects of `kind` on the path `arg`, once per working directory it may be relative to."""
    if isinstance(arg, Unresolved):
        return [Effect(kind, None, Unknown(arg.reason), origin)]
    text = arg.text
    if text == "":
        return []  # an empty file name fails before anything is touched
    if arg.is_pattern:
        prefix = text[: arg.glob_at]
        directory = prefix[: prefix.rfind("/") + 1]
        ups = _levels_above(text[len(directory) :])
        bases = _absolute(directory or ".", cwds)
        if isinstance(bases, Unknown):
            return [Effect(kind, None, bases, origin)]
        return [Effect(kind, _up(b, ups), Bounded(), origin) for b in _unique(bases)]
    bases = _absolute(text, cwds)
    if isinstance(bases, Unknown):
        return [Effect(kind, None, bases, origin)]
    resolution = Bounded() if recursive else Known()
    return [Effect(kind, b, resolution, origin) for b in _unique(bases)]


def _absolute(text: str, cwds: Cwds) -> list[PurePosixPath] | Unknown:
    if text.startswith("/"):
        return [normalise(PurePosixPath("/"), text)]
    if isinstance(cwds, Unknown):
        return Unknown(f"a relative path with an unknown working directory: {cwds.reason}")
    return [normalise(cwd, text) for cwd in cwds]


def normalise(base: PurePosixPath, text: str) -> PurePosixPath:
    """`text` from `base`, with `.` dropped, `..` removing the component before it, and repeated
    slashes collapsed. Textual, like the rest of the analysis."""
    parts = [] if text.startswith("/") else list(base.parts[1:])
    for component in text.split("/"):
        if component in ("", "."):
            continue
        if component == "..":
            if parts:
                parts.pop()
        else:
            parts.append(component)
    return PurePosixPath("/", *parts)


def _levels_above(rest: str) -> int:
    """How far above its starting directory `rest` can reach. Every component that is not `.` or
    `..`, glob or literal, is exactly one name deeper, and each `..` one shallower, so
    `*/../../x` reaches one level up and `*/..` none."""
    depth = lowest = 0
    for component in rest.split("/"):
        if component in ("", "."):
            continue
        depth += -1 if component == ".." else 1
        lowest = min(lowest, depth)
    return -lowest


def _up(path: PurePosixPath, levels: int) -> PurePosixPath:
    for _ in range(levels):
        path = path.parent
    return path


def _unique(paths: Iterable[PurePosixPath]) -> list[PurePosixPath]:
    return list(dict.fromkeys(paths))


__all__ = ["effects_of", "normalise", "path_effects"]
