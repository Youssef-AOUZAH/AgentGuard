"""Entries for programs that talk to the network: curl, wget and git."""

from __future__ import annotations

import re
from dataclasses import dataclass

from compiler.knowledge.base import (
    HERE,
    NET_OUT,
    READ,
    TABLE,
    WRITE,
    Arg,
    AtHome,
    EffectKind,
    Field,
    Host,
    OnPath,
    OnTarget,
    Opts,
    Parsed,
    Unresolved,
    Want,
    entry,
    unknown,
)

# ---- the network

_URL = re.compile(r"^(?:[A-Za-z][A-Za-z0-9+.-]*://)?(?:[^@/?#]*@)?(\[[^\]]*\]|[^:/?#]*)")


def host_of(arg: Arg) -> Want:
    if isinstance(arg, Unresolved) or arg.is_pattern:
        return OnTarget(NET_OUT, None, getattr(arg, "reason", "the URL is a pattern"))
    match = _URL.match(arg.text)
    host = match.group(1).lower() if match else ""
    if not host:
        return OnTarget(NET_OUT, None, f"no host in {arg.text!r}")
    return OnTarget(NET_OUT, Host(host))


_CURL = Opts(
    frozenset("sSLfIikvGO#")
    | {
        "compressed",
        "fail-with-body",
        "http1.1",
        "http2",
        "no-progress-meter",
        "remote-name",
        "location",
        "silent",
        "show-error",
        "fail",
        "head",
        "include",
        "insecure",
        "verbose",
        "get",
    },
    frozenset("oHXAudFTwmbecxK")
    | {
        "retry",
        "connect-timeout",
        "data-binary",
        "data-raw",
        "data-urlencode",
        "output",
        "header",
        "request",
        "user-agent",
        "user",
        "data",
        "form",
        "upload-file",
        "write-out",
        "max-time",
        "cookie",
        "cookie-jar",
        "referer",
        "proxy",
        "config",
    },
    {
        "output": "o",
        "remote-name": "O",
        "header": "H",
        "request": "X",
        "user-agent": "A",
        "user": "u",
        "data": "d",
        "data-binary": "data-binary",
        "data-raw": "data-raw",
        "data-urlencode": "data-urlencode",
        "form": "F",
        "upload-file": "T",
        "write-out": "w",
        "max-time": "m",
        "cookie": "b",
        "cookie-jar": "c",
        "referer": "e",
        "proxy": "x",
        "config": "K",
        "silent": "s",
        "show-error": "S",
        "location": "L",
        "fail": "f",
        "head": "I",
        "include": "i",
        "insecure": "k",
        "verbose": "v",
        "get": "G",
        "retry": "retry",
        "connect-timeout": "connect-timeout",
        "compressed": "compressed",
        "fail-with-body": "fail-with-body",
        "no-progress-meter": "no-progress-meter",
        "http1.1": "http1.1",
        "http2": "http2",
    },
    dangerous={"o": WRITE, "T": READ, "c": WRITE},
)


@entry("curl", opts=_CURL)
def _curl(name: str, p: Parsed) -> list[Want]:
    if p.values("K"):
        return unknown(name, "curl --config reads options from a file")
    wants: list[Want] = [host_of(u) for u in p.operands] + [host_of(x) for x in p.values("x")]
    wants += [OnPath(WRITE, v) for v in p.values("o", "c")]
    wants += [OnPath(READ, v) for v in p.values("T")]
    if p.has("O"):
        wants.append(OnPath(WRITE, HERE, True))
    for value in p.values("d", "data-binary", "data-urlencode", "F"):
        if isinstance(value, Unresolved) or "@" in value.text or value.text.startswith("<"):
            file = value if isinstance(value, Unresolved) else Field(value.text.split("@", 1)[-1].lstrip("<"))
            wants.append(OnPath(READ, file))
    return wants


_WGET = Opts(
    frozenset("qcNrnvk") | {"no-check-certificate", "quiet", "continue", "recursive", "no-verbose"},
    frozenset("OPiTt")
    | {"output-document", "directory-prefix", "input-file", "timeout", "tries", "user-agent", "header"},
    {
        "output-document": "O",
        "directory-prefix": "P",
        "input-file": "i",
        "timeout": "T",
        "tries": "t",
        "quiet": "q",
        "continue": "c",
        "recursive": "r",
        "no-verbose": "nv",
        "user-agent": "user-agent",
        "header": "header",
        "no-check-certificate": "no-check-certificate",
    },
    dangerous={"O": WRITE, "P": WRITE, "i": READ},
)


@entry("wget", opts=_WGET)
def _wget(name: str, p: Parsed) -> list[Want]:
    wants: list[Want] = [host_of(u) for u in p.operands]
    if p.values("i"):
        wants += [OnPath(READ, v) for v in p.values("i")] + [OnTarget(NET_OUT, None, "URLs come from a file")]
    if p.values("O"):
        return wants + [OnPath(WRITE, v) for v in p.values("O")]
    return wants + [OnPath(WRITE, d, True) for d in (p.values("P") or [HERE])]


# ---- git

_GIT_READ = frozenset(
    {"status", "log", "diff", "show", "rev-parse", "ls-files", "blame", "describe", "shortlog", "grep"}
)
_GIT_WRITE = frozenset(
    {
        "add",
        "commit",
        "checkout",
        "switch",
        "restore",
        "reset",
        "stash",
        "merge",
        "rebase",
        "mv",
        "rm",
        "init",
        "tag",
        "cherry-pick",
        "revert",
        "apply",
        "branch",
        "clean",
    }
)
_GIT_NET = frozenset({"push", "pull", "fetch", "ls-remote", "submodule"})
_GIT_SAFE_OPTION = re.compile(
    r"-[A-Za-z0-9]$|--$|--(oneline|stat|short|porcelain|cached|staged|name-only|name-status|graph|all|decorate|"
    r"no-pager|no-color|color|patch|quiet|verbose|force|hard|soft|mixed|amend|no-edit|no-verify|ff-only|"
    r"rebase|abbrev-commit|pretty=[a-z]+|format=[^ ]*|max-count=\d+|since=.*|until=.*|author=.*|depth=\d+|"
    r"show-toplevel|abbrev-ref|set-upstream|tags|prune|continue|abort|recursive|init|update|list|global)$"
)


@dataclass(frozen=True, slots=True)
class InRepo:
    """An effect on the repository: `effects.py` binds it to the workspace when every working
    directory is inside it, since the repository root is otherwise unknown (`git` looks upwards
    for `.git`). `path` is relative to that root; `.` for the whole tree."""

    kind: EffectKind
    path: str = "."
    recursive: bool = True


def _git(name: str, args: tuple[Arg, ...]) -> list[Want | InRepo]:
    rest = list(args)
    while rest and isinstance(rest[0], Field) and rest[0].text.startswith("-"):
        option = rest.pop(0).text
        if option in ("--no-pager", "-P"):
            continue
        # -C moves git elsewhere and -c can set core.sshCommand or an alias that runs anything.
        return unknown(name, f"git option {option} is not modelled")
    if not rest:
        return []
    sub = rest.pop(0)
    if isinstance(sub, Unresolved):
        return unknown(name, sub.reason)
    for arg in rest:
        if isinstance(arg, Unresolved):
            return unknown(name, f"git {sub.text} was given an argument we cannot see")
        if arg.text.startswith("-") and not _GIT_SAFE_OPTION.match(arg.text):
            return unknown(name, f"git {sub.text} option {arg.text} is not modelled")
    if sub.text in _GIT_READ:
        return [InRepo(READ, ".", recursive=False)]
    if sub.text in _GIT_WRITE:
        return [InRepo(READ, ".", recursive=False), InRepo(WRITE)]
    if sub.text in _GIT_NET:
        out: list[Want | InRepo] = [OnTarget(NET_OUT, None, "the remote comes from .git/config")]
        if sub.text in ("pull", "submodule"):
            out.append(InRepo(WRITE))
        return out
    if sub.text == "clone":
        operands = [a for a in rest if not a.text.startswith("-")]
        if not operands:
            return []
        dest = operands[1] if len(operands) > 1 else HERE
        return [host_of(operands[0]), OnPath(WRITE, dest, True)]
    if sub.text in ("config", "remote"):
        if any(a.text == "--global" for a in rest):
            return [AtHome(WRITE, ".gitconfig")]
        if sub.text == "remote" and all(a.text in ("-v", "--verbose") for a in rest):
            return [InRepo(READ, ".git/config", recursive=False)]
        return [InRepo(WRITE, ".git/config", recursive=False)]
    return unknown(name, f"git {sub.text} is not modelled")


TABLE["git"] = _git  # type: ignore[assignment]
