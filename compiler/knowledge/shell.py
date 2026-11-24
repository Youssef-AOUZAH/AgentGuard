"""Entries for the shell's own builtins, interpreters, wrappers that run another command, and find."""

from __future__ import annotations

import re
from collections.abc import Callable

from compiler.knowledge.base import (
    CHDIR,
    DELETE,
    ENV,
    EXEC,
    HERE,
    INTERPRET,
    PRIV,
    READ,
    SIGNAL,
    TABLE,
    WRITE,
    Arg,
    AtHome,
    Field,
    OnPath,
    OnTarget,
    OptionError,
    Opts,
    Parsed,
    Process,
    Run,
    Unresolved,
    Variable,
    Want,
    _o,
    entry,
    parse,
    unknown,
)

# ---- the session

for _name in ("cd", "pushd"):
    TABLE[_name] = lambda name, args: _cd(name, args)
TABLE["popd"] = lambda name, args: [OnPath(CHDIR, Unresolved("popd returns to a directory on the stack"))]


def _cd(name: str, args: tuple[Arg, ...]) -> list[Want]:
    operands = [a for a in args if not (isinstance(a, Field) and a.text in ("-L", "-e", "--"))]
    if any(isinstance(a, Field) and a.text == "-P" for a in operands):
        return [OnPath(CHDIR, Unresolved(f"{name} -P resolves symlinks"))]
    if not operands:
        return [AtHome(CHDIR)]
    if len(operands) > 1:
        return []  # bash refuses: too many arguments
    target = operands[0]
    if isinstance(target, Field) and target.text == "-":
        return [OnPath(CHDIR, Unresolved(f"{name} - goes to $OLDPWD, which is not tracked"))]
    return [OnPath(CHDIR, target)]


def _variable(arg: Arg) -> Want:
    if isinstance(arg, Unresolved):
        return OnTarget(ENV, None, arg.reason)
    match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", arg.text)
    if match is None:
        return OnTarget(ENV, None, f"cannot read a variable name from {arg.text!r}")
    return OnTarget(ENV, Variable(match.group(1)))


def _variables(name: str, args: tuple[Arg, ...]) -> list[Want]:
    names = [a for a in args if isinstance(a, Unresolved) or not a.text.startswith("-")]
    if name == "read" and not names:
        return [OnTarget(ENV, Variable("REPLY"))]
    if name in ("mapfile", "readarray") and not names:
        return [OnTarget(ENV, Variable("MAPFILE"))]
    if name == "getopts":
        names = names[1:2]
    return [_variable(a) for a in names]


for _name in (
    "export",
    "unset",
    "declare",
    "typeset",
    "local",
    "readonly",
    "read",
    "mapfile",
    "readarray",
    "getopts",
):
    TABLE[_name] = _variables


@entry("kill", opts=_o("l", "sn", numeric=True, long={"signal": "s"}))
def _kill(name: str, p: Parsed) -> list[Want]:
    out: list[Want] = []
    for a in p.operands:
        if isinstance(a, Field) and a.text.isdigit():
            out.append(OnTarget(SIGNAL, Process(int(a.text))))
        else:
            out.append(OnTarget(SIGNAL, None, "the kill target is not a single known process"))
    return out


# ---- code in another language (R3)


def _interpret(why: str) -> list[Want]:
    return [OnTarget(INTERPRET, None, why)]


_SHELLS = ("sh", "bash", "dash", "zsh", "ksh")


def _shell(name: str, args: tuple[Arg, ...]) -> list[Want]:
    for arg in args:
        if isinstance(arg, Unresolved):
            return _interpret(f"{name} was given an argument we cannot see")
        if arg.text == "-c" or (
            arg.text.startswith("-") and "c" in arg.text[1:] and not arg.text.startswith("--")
        ):
            return _interpret(f"{name} -c runs inline code")
        if arg.text in ("-s", "-i", "-"):
            return _interpret(f"{name} {arg.text} reads code from its input")
        if arg.text.startswith("--"):
            return unknown(name, f"{name} option {arg.text} is not modelled")
        if arg.text.startswith("-") or arg.text.startswith("+"):
            if set(arg.text[1:]) <= set("euxvfnC") and arg.text[0] in "-+":
                continue
            return unknown(name, f"{name} option {arg.text} is not modelled")
        return [OnPath(READ, arg)]  # a script file, run as a program
    return _interpret(f"{name} with no script reads code from its input")


for _name in _SHELLS:
    TABLE[_name] = _shell


def _scripting(inline: str, module: str | None = None) -> Callable[[str, tuple[Arg, ...]], list[Want]]:
    def handler(name: str, args: tuple[Arg, ...]) -> list[Want]:
        for arg in args:
            if isinstance(arg, Unresolved):
                return _interpret(f"{name} was given an argument we cannot see")
            text = arg.text
            if text in inline.split() or any(text.startswith(f) and len(f) == 2 for f in inline.split()):
                return _interpret(f"{name} {text} runs inline code")
            if module and text.startswith(module):
                return unknown(name, f"{name} {module} runs a module we do not model")
            if text == "-":
                return _interpret(f"{name} - reads code from its input")
            if text.startswith("-"):
                if text in ("-u", "-B", "-O", "-OO", "-q", "-E", "-s", "-I", "--version", "-V"):
                    continue
                return unknown(name, f"{name} option {text} is not modelled")
            return [OnPath(READ, arg)]
        return _interpret(f"{name} with no script reads code from its input")

    return handler


for _name in ("python", "python3"):
    TABLE[_name] = _scripting("-c", module="-m")
TABLE["node"] = _scripting("-e -p --eval --print")
TABLE["perl"] = _scripting("-e -E")
TABLE["ruby"] = _scripting("-e")
for _name in ("awk", "gawk", "mawk", "eval", "source", "."):
    TABLE[_name] = lambda name, args: _interpret(f"{name} runs code we do not parse")


_SED_SAFE = re.compile(
    r"(?:(?:\d+|\$)(?:,(?:\d+|\$))?)?(?:[dp]|s([/|#:,])(?:\\.|(?!\1).)*\1(?:\\.|(?!\1).)*\1[gIip0-9]*)"
)


@entry(
    "sed",
    opts=_o(
        "nrEsuz",
        "ef",
        long={
            "quiet": "n",
            "silent": "n",
            "regexp-extended": "E",
            "expression": "e",
            "file": "f",
            "in-place": "i",
        },
    ),
)
def _sed(name: str, p: Parsed) -> list[Want]:
    scripts = p.values("e")
    files = p.operands if scripts else p.operands[1:]
    if not scripts:
        scripts = p.operands[:1]
    if p.values("f") or p.has("i"):
        return unknown(name, "sed with a script file or in-place editing is not modelled")
    for script in scripts:
        if isinstance(script, Unresolved) or not all(
            _SED_SAFE.fullmatch(s.strip()) for s in script.text.split(";")
        ):
            # `1e cmd` runs a command and `w f` writes a file: anything but plain s///, d and p.
            return _interpret("sed program uses commands beyond s, d and p")
    return [OnPath(READ, f) for f in files]


# ---- programs that run another command


def _rest(args: tuple[Arg, ...], opts: Opts, name: str) -> tuple[Parsed, list[Want]] | list[Want]:
    try:
        return parse(args, Opts(opts.flags, opts.valued, opts.long, posix=True)), []
    except OptionError as exc:
        return unknown(name, str(exc))


def _wrapper(opts: Opts, skip: int = 0, extra: Callable[[Parsed], list[Want]] | None = None):
    def handler(name: str, args: tuple[Arg, ...]) -> list[Want]:
        parsed = _rest(args, opts, name)
        if isinstance(parsed, list):
            return parsed
        p, wants = parsed
        if extra is not None:
            wants += extra(p)
        command = p.operands[skip:]
        if command:
            wants.append(Run(tuple(command)))
        return wants

    return handler


def _sudo_shell(p: Parsed) -> list[Want]:
    # `sudo -s`, `sudo -i` and a bare `sudo` start a shell that reads code from its input.
    wants: list[Want] = [OnTarget(PRIV, None)]
    if p.has("s", "i") or not p.operands:
        wants += _interpret("sudo starts a shell")
    return wants


TABLE["sudo"] = _wrapper(Opts("nEHkSbiAs", "ugCDph"), extra=_sudo_shell)
TABLE["doas"] = _wrapper(Opts("ns", "uC"), extra=_sudo_shell)
TABLE["su"] = lambda name, args: [OnTarget(PRIV, None)] + _interpret("su runs a shell")
TABLE["nice"] = _wrapper(Opts("", "n", {"adjustment": "n"}))
TABLE["nohup"] = _wrapper(Opts())
TABLE["time"] = _wrapper(Opts("p"))
TABLE["exec"] = _wrapper(Opts("cl", "a"))
TABLE["timeout"] = _wrapper(
    Opts("vf", "sk", {"signal": "s", "kill-after": "k", "foreground": "f", "preserve-status": "p"}), skip=1
)
TABLE["builtin"] = _wrapper(Opts())


def _command_builtin(name: str, args: tuple[Arg, ...]) -> list[Want]:
    if any(isinstance(a, Field) and a.text in ("-v", "-V") for a in args):
        return []
    return _wrapper(Opts("p"))(name, args)


TABLE["command"] = _command_builtin


def _env(name: str, args: tuple[Arg, ...]) -> list[Want]:
    try:
        p = parse(args, Opts("i0", "uC", {"ignore-environment": "i", "unset": "u", "chdir": "C"}, posix=True))
    except OptionError as exc:
        return unknown(name, str(exc))
    if p.values("C"):
        return unknown(name, "env --chdir runs the command elsewhere")
    wants: list[Want] = [_variable(v) for v in p.values("u")]
    operands = list(p.operands)
    while (
        operands and isinstance(operands[0], Field) and re.match(r"[A-Za-z_][A-Za-z0-9_]*=", operands[0].text)
    ):
        wants.append(_variable(operands.pop(0)))
    if operands and isinstance(operands[0], Unresolved):
        wants.append(OnTarget(ENV, None, operands[0].reason))
    if operands:
        wants.append(Run(tuple(operands)))
    return wants


TABLE["env"] = _env


def _xargs(name: str, args: tuple[Arg, ...]) -> list[Want]:
    try:
        p = parse(
            args,
            Opts(
                "0rtpx",
                "IndLPsEa",
                {
                    "null": "0",
                    "no-run-if-empty": "r",
                    "max-args": "n",
                    "delimiter": "d",
                    "max-procs": "P",
                    "arg-file": "a",
                    "replace": "I",
                    "verbose": "t",
                },
                posix=True,
            ),
        )
    except OptionError as exc:
        return unknown(name, str(exc))
    wants: list[Want] = [OnPath(READ, v) for v in p.values("a")]
    command = p.operands or [Field("echo")]
    # The arguments come from the input, so they are unseen: one unresolved word stands for them.
    return [*wants, Run((*command, Unresolved(f"{name} reads its arguments from its input")))]


TABLE["xargs"] = _xargs


def _find(name: str, args: tuple[Arg, ...]) -> list[Want]:
    rest = list(args)
    while rest and isinstance(rest[0], Field) and rest[0].text in ("-H", "-L", "-P"):
        rest.pop(0)
    starts: list[Arg] = []
    while rest:
        first = rest[0]
        if isinstance(first, Unresolved) or (first.is_pattern and first.glob_at == 0):
            break  # may be a start point or an action such as -delete: the expression loop decides
        if first.text[:1] in ("-", "(", "!") or first.text == ",":
            break
        starts.append(rest.pop(0))
    starts = starts or [HERE]
    wants: list[Want] = [OnPath(READ, s) for s in starts]  # names, like ls
    i = 0
    while i < len(rest):
        arg = rest[i]
        i += 1
        if isinstance(arg, Unresolved) or (arg.is_pattern and arg.glob_at == 0):
            # It could be -delete or -exec: an unquoted `-name *.py` can match a file named -delete.
            why = (
                arg.reason
                if isinstance(arg, Unresolved)
                else f"the unquoted pattern {arg.text} may match an action"
            )
            return wants + [OnPath(DELETE, Unresolved(why)), OnTarget(EXEC, None, why)]
        text = arg.text
        if text == "-delete":
            wants += [OnPath(DELETE, s, True) for s in starts]
        elif text in ("-exec", "-ok"):
            end = next(
                (j for j in range(i, len(rest)) if isinstance(rest[j], Field) and rest[j].text in (";", "+")),
                None,
            )
            if end is None:
                return unknown(name, f"{text} without a terminator")
            command = rest[i:end]
            i = end + 1
            for start in starts:
                wants.append(Run(tuple(_substitute(a, start) for a in command)))
        elif text in ("-execdir", "-okdir"):
            return wants + [OnTarget(EXEC, None, f"find {text} runs a command in each found directory")]
        elif text in ("-fprint", "-fprint0", "-fprintf", "-fls"):
            if i < len(rest):
                wants.append(OnPath(WRITE, rest[i]))
            i += 2 if text == "-fprintf" else 1
        elif text == "-files0-from":
            return unknown(name, "find -files0-from takes start points from a file")
    return wants


def _substitute(arg: Arg, start: Arg) -> Arg:
    """`{}` stands for each found path: everything at or under the start point."""
    if isinstance(arg, Unresolved) or "{}" not in arg.text:
        return arg
    if isinstance(start, Unresolved):
        return start
    base = start.text.rstrip("/") or "/"
    prefix = base if base == "/" else base + "/"
    replaced = arg.text.replace("{}", prefix + "*", 1)
    return Field(replaced, glob_at=arg.text.index("{}") + len(prefix))


TABLE["find"] = _find


@entry("printf", opts=_o(valued="v", posix=True))
def _printf(name: str, p: Parsed) -> list[Want]:
    return [_variable(v) for v in p.values("v")]
