"""Tests for the canonical emitter.

Four properties, each catching a different failure:

1. Round trip: parsing the emitted command gives the same meaning as parsing the original.
   "Meaning" is compared through `shape`, which ignores spelling and positions but keeps every
   value, every expansion, and whether each expansion is quoted.
2. Fixed point: emitting, parsing and emitting again gives the identical string. Canonical means
   one output per meaning.
3. The argv oracle: bash passes the same arguments for the emitted word as for the original, and
   for a known word those arguments equal our value. This is the narrow exception in AGENTS.md:
   generated words only, `printf` only, in a temporary directory, in a test module.
4. `bash -n` accepts every emitted command.
"""

import shutil
import subprocess

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from compiler.emit import EmitError, emit, emit_word
from compiler.lexer import is_name
from compiler.parser import parse_source
from compiler.syntax import (
    AndOr,
    LexError,
    ParseError,
    PartKind,
    Pipeline,
    RedirectOp,
    Script,
    SimpleCommand,
    Statement,
    Subshell,
    simple_commands,
)

needs_bash = pytest.mark.skipif(shutil.which("bash") is None, reason="bash is not installed")


def canonical(src: str) -> str:
    return emit(parse_source(src))


def the_word(src: str):
    """The single argument word of `printf <src>`."""
    return list(simple_commands(parse_source("printf " + src)))[0].words[1]


# --------------------------------------------------------------------------- meaning, for comparison


def shape(node):
    """What a node means, with its spelling and positions thrown away."""
    if isinstance(node, Script):
        return ("script", tuple(shape(s) for s in node.statements))
    if isinstance(node, Statement):
        return ("statement", shape(node.and_or), node.background)
    if isinstance(node, AndOr):
        return ("and_or", shape(node.first), tuple((op, shape(p)) for op, p in node.rest))
    if isinstance(node, Pipeline):
        return ("pipeline", node.negated, tuple(shape(c) for c in node.commands))
    if isinstance(node, SimpleCommand):
        return (
            "command",
            tuple((a.name, word_shape(a.value.parts)) for a in node.assignments),
            tuple(word_shape(w.parts) for w in node.words),
            tuple(redirect_shape(r) for r in node.redirects),
        )
    if isinstance(node, Subshell):
        return (
            "subshell",
            tuple(shape(s) for s in node.body),
            tuple(redirect_shape(r) for r in node.redirects),
        )
    raise TypeError(node)


def redirect_shape(redirect):
    op = RedirectOp.HEREDOC if redirect.op is RedirectOp.HEREDOC_DASH else redirect.op
    target = word_shape(redirect.target.parts) if redirect.target is not None else None
    body = redirect.body.value if redirect.body is not None else None
    return (op, redirect.fd, target, body)


def word_shape(parts):
    """Known text merged into runs; each expansion with whether it sits inside double quotes; and
    whether the word may vanish, which happens only when nothing in it is known or quoted."""
    items: list = []

    def add(part, quoted):
        if part.is_known:
            if part.value:
                if items and isinstance(items[-1], str):
                    items[-1] += part.value
                else:
                    items.append(part.value)
            return
        if part.kind is PartKind.DQUOTED:
            for child in part.parts:
                add(child, True)
            return
        if part.kind is PartKind.CMD_SUBST:
            items.append(("subst", shape(part.script), quoted))
        elif part.kind is PartKind.PARAM_EXP:
            name = part.raw[2:-1] if part.raw.startswith("${") else part.raw[1:]
            items.append(("param", name if is_name(name) else part.raw, quoted))
        else:
            items.append((part.kind, part.raw, quoted))

    for part in parts:
        add(part, False)
    may_vanish = not any(p.is_known or p.kind is PartKind.DQUOTED for p in parts)
    return (tuple(items), may_vanish)


# --------------------------------------------------------------------------- the form of the output


@pytest.mark.parametrize(
    ("src", "expected"),
    [
        ("ls -la /tmp", "'ls' '-la' '/tmp'"),
        ("a\\ b \"a b\" $'a\\x20b'", "'a b' 'a b' 'a b'"),
        ("echo it\\'s", "'echo' 'it'\\''s'"),
        ("A=1 B=two cmd", "A='1' B='two' 'cmd'"),
        ("x=", "x=''"),
        (">out.txt", ">'out.txt'"),
        ("cmd 2>err 2>&1 2>&- <in >>log >|f <>rw", "'cmd' 2>'err' 2>&1 2>&- <'in' >>'log' >|'f' <>'rw'"),
        ("a; b & c", "'a'; 'b' & 'c'"),
        ("! a | b && c || d", "! 'a' | 'b' && 'c' || 'd'"),
        ("echo $x ${y}", "'echo' ${x} ${y}"),
        ('echo "a $x b"', "'echo' 'a '\"${x}\"' b'"),
        ('echo "$@"', "'echo' \"$@\""),
        ("echo *.txt {a,b}c", "'echo' *'.txt' {a,b}'c'"),
        ("echo $(echo $(whoami))", "'echo' $('echo' $('whoami'))"),
    ],
)
def test_canonical_form(src, expected):
    assert canonical(src) == expected


def test_control_characters_use_fixed_width_escapes():
    # Raw control characters would not lex again, so they come back as $'...'.
    assert canonical("echo $'\\x01\\tz'") == "'echo' $'\\x01\\x09z'"


def test_nested_subshells_never_produce_double_parentheses():
    # `((` is bash's arithmetic command, which runs code stored in variables.
    assert canonical("( (ls) )") == "( ( 'ls' ) )"
    assert "((" not in canonical("( ( (ls) ) )")


def test_subshell_inside_substitution_is_not_arithmetic_expansion():
    assert canonical("echo $( (ls) )") == "'echo' $( ( 'ls' ))"


def test_quoted_empty_text_keeps_a_word_alive():
    # `''$e` with e empty is one empty argument; `$e` alone is none.
    assert canonical("echo ''$e") == "'echo' ${e}''"
    assert canonical("echo $e") == "'echo' ${e}"


@pytest.mark.parametrize(
    ("src", "expected"),
    [
        ("~/x", "~/'x'"),
        ("~", "~"),
        ("~+", "~+"),
        ("of=~/x", "of=~/'x'"),
        ("a=x:~/b", "a='x':~/'b'"),
    ],
)
def test_tilde_keeps_the_characters_around_it_bare(src, expected):
    assert emit_word(the_word(src)) == expected


def test_tilde_in_an_assignment():
    assert canonical("P=~/a:~/b cmd") == "P=~/'a':~/'b' 'cmd'"


def test_heredoc_body_follows_its_line():
    assert canonical("cat <<'X'\nhello\nX\n") == "'cat' <<'EOF'\nhello\nEOF\n"


def test_heredoc_delimiter_avoids_the_body():
    assert canonical("cat <<'X'\nEOF\nX\n") == "'cat' <<'EOF1'\nEOF\nEOF1\n"


def test_heredoc_dash_becomes_plain_heredoc():
    # The parser has already stripped the tabs, so the body no longer needs <<-.
    assert canonical("cat <<-'X'\n\thi\n\tX\n") == "'cat' <<'EOF'\nhi\nEOF\n"


def test_heredoc_body_is_written_at_the_next_newline_even_inside_a_subshell():
    # Bash reads pending bodies at the next newline token, wherever it is.
    out = canonical("cat <<'A' | ( b; c )\nbody\nA\n")
    assert out == "'cat' <<'EOF' | ( 'b'\nbody\nEOF\n'c' )"


def test_heredoc_inside_a_substitution():
    assert canonical("echo $(cat <<'B'\nin\nB\n)") == "'echo' $('cat' <<'EOF'\nin\nEOF\n)"


def test_ambiguous_heredoc_across_a_substitution_is_refused():
    with pytest.raises(EmitError):
        canonical("cat <<'A' | echo $(cat <<'B'\nx\nB\n)\ny\nA\n")


def test_within_one_command_the_substitution_is_written_first():
    # Redirections go after the arguments, so the inner body comes before the outer one is opened.
    out = canonical("cat <<'A' $(cat <<'B'\nx\nB\n)\ny\nA\n")
    assert out == "'cat' $('cat' <<'EOF'\nx\nEOF\n) <<'EOF'\ny\nEOF\n"


# --------------------------------------------------------------------------- round trip and fixed point

_FRAGMENTS = [
    "ls",
    "-la",
    "a=1",
    "x=$(y)",
    "P=~/a:~/b",
    "|",
    "&&",
    "||",
    ";",
    "&",
    "\n",
    "(",
    ")",
    ">",
    ">>",
    "2>",
    "2>&1",
    "<",
    "<<'E'\nbody\nE\n",
    "<<-'E'\n\tx\n\tE\n",
    "$(ls)",
    "$(a; b)",
    '"$(a)"',
    '"a $x b"',
    "'q'",
    "'it'\\''s'",
    "a\\ b",
    "$'\\x01'",
    "$'\\t'",
    "~",
    "~/x",
    "of=~/y",
    "a=x:~/b",
    "~'/x'",
    "*.txt",
    "{a,b}",
    "$x",
    "${y}",
    "$@",
    '"$@"',
    "''$e",
    "!",
    "$((1+2))",
    "#c",
    "é",
    "( a )",
]
_shell_shaped = st.lists(st.sampled_from(_FRAGMENTS), max_size=12).map(" ".join)


def _parsed(src):
    try:
        return parse_source(src)
    except (LexError, ParseError):
        return None


@settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
@given(_shell_shaped)
def test_round_trip_preserves_meaning(src):
    script = _parsed(src)
    if script is None:
        return
    try:
        out = emit(script)
    except EmitError:
        return
    again = parse_source(out)  # must not raise: the emitter only produces what we accept
    assert shape(again) == shape(script)


@settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
@given(_shell_shaped)
def test_emission_is_a_fixed_point(src):
    script = _parsed(src)
    if script is None:
        return
    try:
        out = emit(script)
    except EmitError:
        return
    assert emit(parse_source(out)) == out


@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
@given(_shell_shaped)
def test_only_emit_error_escapes(src):
    script = _parsed(src)
    if script is None:
        return
    try:
        emit(script)
    except EmitError:
        pass


# --------------------------------------------------------------------------- the argv oracle

_ORACLE_WORDS = [
    "plain",
    "a\\ b",
    '"a b"',
    "'it'\\''s'",
    "$'a\\x20b'",
    "$'\\x01x'",
    "$'\\8'",
    '"\\$x"',
    "a#b",
    "é",
    "'a'b'c'",
    '"a"\\ "b"',
    "~",
    "~/x",
    "~'/x'",
    "~\\a",
    "~-",
    "of=~/x",
    "--opt=~/x",
    "a=x:~/b",
    "a=b=~/x",
    "$x",
    '"$x"',
    '"a $x b"',
    "''$e",
    "$e",
    '"$@"',
    "*.txt",
    "'*'.txt",
    "{a,b}c",
    "$(printf hi)",
    "\"$(printf 'a  b')\"",
    "$((2+3))",
]


def _bash_argv(word: str, cwd) -> list[bytes]:
    """What bash passes for `word`, with fixed variables. Over stdin, because on Windows
    `subprocess` rewrites backslashes in arguments under the MS C runtime rules."""
    script = "HOME=/h; OLDPWD=/old; x='a  b'; e=; set -- p 'q r'; printf '%s\\0' " + word
    out = subprocess.run(
        ["bash", "--noprofile", "--norc", "-s"],
        input=script.encode(),
        capture_output=True,
        check=True,
        cwd=cwd,
    ).stdout
    return out.split(b"\0")[:-1]


@needs_bash
@pytest.mark.parametrize("word", _ORACLE_WORDS)
def test_bash_passes_the_same_arguments_for_the_emitted_word(word, tmp_path):
    (tmp_path / "a.txt").write_text("")
    (tmp_path / "b.txt").write_text("")
    parsed = the_word(word)
    emitted = emit_word(parsed)
    original = _bash_argv(word, tmp_path)
    assert _bash_argv(emitted, tmp_path) == original, f"{word!r} emitted as {emitted!r}"
    if parsed.is_known:
        assert original == [parsed.value.encode()], f"bash disagrees with our value for {word!r}"


# --------------------------------------------------------------------------- bash -n accepts every output

_COMMANDS = [
    "ls -la",
    "A=1 B=$(pwd) env",
    "cat f | grep x | wc -l",
    "a && b || c; d &",
    "(cd /tmp; ls) > out 2>&1",
    "( (ls) )",
    "echo $( (ls) )",
    "! true",
    "echo $(echo $(whoami))",
    "cat <<'EOF'\nbody\nEOF\n",
    "cat <<'A' | ( b; c )\nbody\nA\n",
    "echo $(cat <<'B'\nin\nB\n)",
    "echo 'a b' \"c $x d\" e\\ f $'\\x01'",
    "P=~/a:~/b cmd ~/x of=~/y",
    ">out.txt",
    "x=",
]


def _bash_parses(src: str) -> bool:
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-n"],
        input=src.encode(),
        capture_output=True,
        check=False,
    )
    return result.returncode == 0


@needs_bash
@pytest.mark.parametrize("src", _COMMANDS)
def test_bash_accepts_every_emitted_command(src):
    out = canonical(src)
    assert _bash_parses(out), f"bash -n rejects {out!r}"
