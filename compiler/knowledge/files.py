"""Entries for programs that read and change files."""

from __future__ import annotations

import re
from collections.abc import Callable

from compiler.knowledge.base import (
    APPEND,
    DELETE,
    EXEC,
    HERE,
    PRIV,
    READ,
    TABLE,
    WRITE,
    Arg,
    Field,
    OnPath,
    Opts,
    Parsed,
    Unresolved,
    Want,
    _guarded,
    _o,
    _reads,
    entry,
    unknown,
)

# ---- reading files

_CAT = _o("AbeEnstTuv", long={"number": "n", "show-all": "A", "squeeze-blank": "s", "number-nonblank": "b"})
entry("cat", opts=_CAT)(lambda name, p: _reads(p))

_HEAD = _o(
    "qvz",
    "nc",
    numeric=True,
    long={"lines": "n", "bytes": "c", "quiet": "q", "silent": "q", "verbose": "v", "zero-terminated": "z"},
)
entry("head", opts=_HEAD)(lambda name, p: _reads(p))
_TAIL = _o(
    "qvzfF",
    "ncs",
    numeric=True,
    long={"lines": "n", "bytes": "c", "quiet": "q", "follow": "f", "verbose": "v", "zero-terminated": "z"},
)
entry("tail", opts=_TAIL)(lambda name, p: _reads(p))
entry("wc", opts=_o("clmwL", long={"lines": "l", "words": "w", "bytes": "c", "chars": "m"}))(
    lambda n, p: _reads(p)
)
entry("cut", opts=_o("sz", "bcdf", long={"fields": "f", "delimiter": "d", "characters": "c", "bytes": "b"}))(
    lambda name, p: _reads(p)
)
entry("diff", opts=_o("uqrNawiBbEty", "U", long={"unified": "U", "brief": "q", "recursive": "r"}))(
    lambda name, p: _reads(p, recursive=p.has("r"))
)
entry("stat", "file", "md5sum", "sha1sum", "sha256sum", "cmp", "comm", opts=_o("Lb", "c"))(
    lambda n, p: _reads(p)
)
entry("du", opts=_o("ahcsxLk", "d", long={"max-depth": "d", "summarize": "s", "human-readable": "h"}))(
    lambda name, p: _reads(p, recursive=True, default=HERE)
)


@entry(
    "ls",
    opts=_o(
        "1aAlhrtSRdFGinsuc",
        "I",
        long={
            "all": "a",
            "almost-all": "A",
            "human-readable": "h",
            "recursive": "R",
            "directory": "d",
            "color": "C",
            "classify": "F",
            "reverse": "r",
            "ignore": "I",
        },
        optional=frozenset("C"),
    ),
)
def _ls(name: str, p: Parsed) -> list[Want]:
    # A listing reads names, not contents, so it is a known read of the directory itself.
    return _reads(p, default=HERE)


_GREP = _o(
    "EFGPiwxcvlLnhHoqsrRIazy",
    "efmABCD",
    long={
        "extended-regexp": "E",
        "fixed-strings": "F",
        "ignore-case": "i",
        "word-regexp": "w",
        "line-regexp": "x",
        "count": "c",
        "invert-match": "v",
        "files-with-matches": "l",
        "files-without-match": "L",
        "line-number": "n",
        "no-filename": "h",
        "with-filename": "H",
        "only-matching": "o",
        "quiet": "q",
        "silent": "q",
        "no-messages": "s",
        "recursive": "r",
        "dereference-recursive": "R",
        "regexp": "e",
        "file": "f",
        "max-count": "m",
        "after-context": "A",
        "before-context": "B",
        "context": "C",
        "include": "include",
        "exclude": "exclude",
        "color": "color",
        "colour": "color",
    },
)
_GREP = Opts(
    frozenset(_GREP.flags) | {"color"},
    frozenset(_GREP.valued) | {"include", "exclude"},
    _GREP.long,
    optional=frozenset({"color"}),
)


@entry("grep", "egrep", "fgrep", opts=_GREP)
def _grep(name: str, p: Parsed) -> list[Want]:
    files = p.operands if (p.has("e", "f")) else p.operands[1:]
    recursive = p.has("r", "R")
    wants = [OnPath(READ, f) for f in p.values("f")]
    if not files and recursive:
        files = [HERE]
    return wants + [OnPath(READ, f, recursive) for f in files]


def _sort(name: str, p: Parsed) -> list[Want]:
    if p.has("!", "@", "T"):
        return unknown(name, "sort with a compress program, a file list or a temp directory is not modelled")
    return _reads(p) + [OnPath(WRITE, v) for v in p.values("o")]


_SORT_VALUED = frozenset("ktSo") | {"!", "@", "T"}
TABLE["sort"] = _guarded(
    "sort",
    Opts(
        "bdfgiMhnRrsuVcCmz",
        _SORT_VALUED,
        {
            "output": "o",
            "key": "k",
            "field-separator": "t",
            "reverse": "r",
            "unique": "u",
            "numeric-sort": "n",
            "human-numeric-sort": "h",
            "buffer-size": "S",
            "compress-program": "!",
            "files0-from": "@",
            "temporary-directory": "T",
        },
        dangerous={"o": WRITE, "!": EXEC},
    ),
    _sort,
)


@entry("uniq", opts=_o("cdiuz", "fsw", long={"count": "c", "repeated": "d", "unique": "u"}))
def _uniq(name: str, p: Parsed) -> list[Want]:
    wants: list[Want] = [OnPath(READ, a) for a in p.operands[:1]]
    return wants + [OnPath(WRITE, a) for a in p.operands[1:2]]


# ---- changing files

_RM = Opts(
    frozenset("rRfivdIx!p"),
    "",
    {
        "recursive": "r",
        "force": "f",
        "interactive": "i",
        "verbose": "v",
        "dir": "d",
        "one-file-system": "x",
        "no-preserve-root": "!",
        "preserve-root": "p",
    },
)
entry("rm", opts=_RM)(lambda name, p: [OnPath(DELETE, a, p.has("r", "R")) for a in p.operands])
entry("rmdir", opts=_o("pv", long={"parents": "p", "verbose": "v"}))(
    lambda name, p: [OnPath(DELETE, a) for a in p.operands]
)
entry("mkdir", opts=_o("pv", "m", long={"parents": "p", "verbose": "v", "mode": "m"}))(
    lambda name, p: [OnPath(WRITE, a) for a in p.operands]
)


@entry("touch", opts=_o("acmh", "dtr", long={"no-create": "c", "date": "d", "reference": "r"}))
def _touch(name: str, p: Parsed) -> list[Want]:
    return [OnPath(READ, v) for v in p.values("r")] + [OnPath(WRITE, a) for a in p.operands]


_COPY_LONG = {
    "recursive": "r",
    "force": "f",
    "interactive": "i",
    "no-clobber": "n",
    "verbose": "v",
    "archive": "a",
    "target-directory": "t",
    "no-target-directory": "T",
    "parents": "P",
    "update": "u",
    "preserve": "p",
    "symbolic-link": "s",
    "link": "l",
    "dereference": "L",
}


def _copy(remove_sources: bool) -> Callable[[str, Parsed], list[Want]]:
    def handler(name: str, p: Parsed) -> list[Want]:
        targets = p.values("t")
        sources = p.operands if targets else p.operands[:-1]
        dest = targets[0] if targets else (p.operands[-1] if p.operands else None)
        if dest is None or (not sources and not targets):
            return []  # usage error, nothing runs
        recursive = remove_sources or p.has("r", "R", "a")
        wants: list[Want] = [OnPath(READ, s, recursive) for s in sources]
        if not remove_sources and p.has("s", "l"):
            # `cp -s` and `cp -l` make links, not copies: a later write to the copy writes the
            # source (see `_ln`). cp accepts only absolute sources for a symbolic link outside
            # the working directory, so the sources are already paths from here.
            wants += [OnPath(WRITE, s, True) for s in sources]
        if remove_sources:
            wants += [OnPath(DELETE, s, True) for s in sources]
        return wants + [OnPath(WRITE, dest, True)]

    return handler


_CP = Opts("rRfinvaTPuplsLdHx", "t", _COPY_LONG, dangerous={"t": WRITE})
entry("cp", opts=_CP)(_copy(remove_sources=False))
entry("mv", opts=Opts("finvTu", "t", _COPY_LONG, dangerous={"t": WRITE}))(_copy(remove_sources=True))


@entry(
    "ln",
    opts=Opts(
        "sfnvTr",
        "t",
        {
            "symbolic": "s",
            "force": "f",
            "no-dereference": "n",
            "verbose": "v",
            "no-target-directory": "T",
            "relative": "r",
            "target-directory": "t",
        },
        dangerous={"t": WRITE},
    ),
)
def _ln(name: str, p: Parsed) -> list[Want]:
    # A link is a second name for its target: whatever later reads or writes the link reads or
    # writes the target, and the policy will only ever see the link's name. So the target counts
    # as read and written here, when the link is made: `ln -s ~/.ssh/id_rsa k && cat k` is a read
    # of the key, and `ln ~/.ssh/id_rsa k` (a hard link) the same.
    targets = p.values("t")
    if targets:
        dest, sources, inside = targets[0], p.operands, True
    elif len(p.operands) > 1:
        dest, sources, inside = p.operands[-1], p.operands[:-1], len(p.operands) > 2
    else:
        dest, sources, inside = HERE, p.operands, True
    wants: list[Want] = [OnPath(WRITE, dest, True)]
    symbolic = p.has("s") and not p.has("r")
    for source in sources:
        for target in _link_targets(source, dest, symbolic, inside, p.has("T")):
            wants += [OnPath(READ, target, True), OnPath(WRITE, target, True)]
    return wants


def _link_targets(source: Arg, dest: Arg, symbolic: bool, inside: bool, not_dir: bool) -> list[Arg]:
    """Where a link made from `source` points, as paths from the working directory.

    A hard link, and a symbolic link made with `-r`, take `source` from the working directory. A
    symbolic link stores `source` as written, and a relative one is read from the directory the
    link sits in. That is `dest` itself when the link goes inside it (`-t`, several sources, or
    `dest` an existing directory, which we cannot see, so both are kept unless `-T` rules it out),
    and otherwise the directory part of `dest`."""
    if not symbolic or isinstance(source, Unresolved) or source.text.startswith("/"):
        return [source]
    if isinstance(dest, Unresolved):
        return [Unresolved("a relative symbolic link placed in a directory we cannot see")]
    if inside:
        bases = [dest]
    elif not_dir:
        bases = [_dirname(dest)]
    else:
        bases = [_dirname(dest), dest]
    return [_join(base, source) for base in dict.fromkeys(bases)]


def _dirname(path: Field) -> Field:
    head = path.text.rstrip("/").rpartition("/")[0] if "/" in path.text.rstrip("/") else "."
    head = head or "/"
    glob = path.glob_at if path.glob_at is not None and path.glob_at < len(head) else None
    return Field(head, glob)


def _join(base: Field, rel: Field) -> Field:
    prefix = base.text.rstrip("/") + "/"
    if base.glob_at is not None and base.glob_at < len(base.text):
        glob: int | None = base.glob_at
    elif rel.glob_at is not None:
        glob = len(prefix) + rel.glob_at
    else:
        glob = None
    return Field(prefix + rel.text, glob)


@entry("tee", opts=_o("aip", long={"append": "a", "ignore-interrupts": "i"}))
def _tee(name: str, p: Parsed) -> list[Want]:
    kind = APPEND if p.has("a") else WRITE
    return [OnPath(kind, a) for a in p.operands]


_PRIV_MODE = re.compile(
    r"[xstX]|^[0-7]*[1357][0-7]{2}$|^[0-7]*[0-7][1357][0-7]$|^[0-7]*[0-7]{2}[1357]$|^[1-7][0-7]{3}$"
)


@entry(
    "chmod",
    opts=_o("Rcfv", long={"recursive": "R", "reference": "@", "verbose": "v"}, valued=frozenset({"@"})),
)
def _chmod(name: str, p: Parsed) -> list[Want]:
    if p.has("@") or not p.operands:
        return unknown(name, "chmod --reference copies a mode we cannot see")
    mode, files = p.operands[0], p.operands[1:]
    recursive = p.has("R")
    if isinstance(mode, Unresolved) or mode.is_pattern or _PRIV_MODE.search(mode.text):
        # Granting execute or setuid is a privilege change (R5); an unseen mode may grant it.
        return [OnPath(PRIV, f, recursive) for f in files]
    return [OnPath(WRITE, f, recursive) for f in files]


@entry(
    "chown",
    "chgrp",
    opts=_o("Rcfvh", long={"recursive": "R", "verbose": "v", "reference": "@"}, valued=frozenset({"@"})),
)
def _chown(name: str, p: Parsed) -> list[Want]:
    files = p.operands if p.has("@") else p.operands[1:]
    return [OnPath(PRIV, f, p.has("R")) for f in files]


def _dd(name: str, args: tuple[Arg, ...]) -> list[Want]:
    wants: list[Want] = []
    for arg in args:
        if isinstance(arg, Unresolved):
            return [OnPath(READ, arg), OnPath(WRITE, arg)]
        key, eq, value = arg.text.partition("=")
        if not eq:
            return unknown(name, f"dd operand {arg.text!r} is not modelled")
        if key == "if":
            wants.append(OnPath(READ, Field(value)))
        elif key == "of":
            wants.append(OnPath(WRITE, Field(value)))
        elif key not in ("bs", "count", "skip", "seek", "ibs", "obs", "status", "conv", "iflag", "oflag"):
            return unknown(name, f"dd operand {key}= is not modelled")
    return wants


TABLE["dd"] = _dd


@entry(
    "mktemp",
    opts=Opts(
        "dqut", "p", {"directory": "d", "tmpdir": "p", "quiet": "q", "dry-run": "u"}, optional=frozenset("p")
    ),
)
def _mktemp(name: str, p: Parsed) -> list[Want]:
    # $TMPDIR may move the default; the gate passes only tracked variables, so it is /tmp unless
    # tracked, which effects.py does not see. Escalate rather than guess when a directory is given.
    if p.values("p") or p.has("p", "t"):
        return unknown(name, "mktemp with a directory option is not modelled")
    if not p.operands:
        return [OnPath(WRITE, Field("/tmp"), True)]
    template = p.operands[0]
    if isinstance(template, Unresolved):
        return [OnPath(WRITE, template)]
    directory = template.text.rsplit("/", 1)[0] or "/" if "/" in template.text else "."
    return [OnPath(WRITE, Field(directory), True)]
