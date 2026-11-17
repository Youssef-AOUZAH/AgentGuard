"""Tests for the parser, organised by the obligations in `compiler/grammar.md` section 5.

Every refusal is asserted by its diagnostic code, not just by the fact that it was refused: a test
that only checks "this was denied" will one day pass for the wrong reason.
"""

import shutil
import subprocess

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from compiler.lexer import tokenize
from compiler.parser import parse, parse_source
from compiler.syntax import (
    MAX_NESTING_DEPTH,
    AndOrOp,
    Diag,
    LexError,
    ParseError,
    PartKind,
    RedirectOp,
    SimpleCommand,
    Subshell,
    simple_commands,
    walk,
)


def refused(src: str) -> Diag:
    with pytest.raises(ParseError) as excinfo:
        parse_source(src)
    return excinfo.value.code


def only_command(src: str) -> SimpleCommand:
    commands = list(simple_commands(parse_source(src)))
    assert len(commands) == 1
    return commands[0]


def values(command: SimpleCommand) -> list[str | None]:
    return [w.value for w in command.words]


# --------------------------------------------------------------------------- structure


def test_empty_input_is_an_empty_script():
    assert parse_source("").statements == ()
    assert parse_source("\n\n").statements == ()


def test_simple_command_name_and_arguments():
    cmd = only_command("ls -la /tmp")
    assert cmd.name is not None and cmd.name.value == "ls"
    assert [w.value for w in cmd.args] == ["-la", "/tmp"]


def test_pipeline_and_negation():
    pipeline = parse_source("! cat f | grep x | wc -l").statements[0].and_or.first
    assert pipeline.negated
    assert len(pipeline.commands) == 3


def test_and_or_is_flat_and_in_execution_order():
    and_or = parse_source("a && b || c").statements[0].and_or
    assert [op for op, _ in and_or.rest] == [AndOrOp.AND, AndOrOp.OR]
    assert len(and_or.pipelines) == 3


def test_separators_and_background():
    statements = parse_source("a; b & c").statements
    assert [s.background for s in statements] == [False, True, False]


def test_newline_allowed_after_pipe_and_and_if():
    assert len(list(simple_commands(parse_source("a |\n b &&\n\n c")))) == 3


def test_newlines_separate_statements():
    assert len(parse_source("a\nb\n\nc\n").statements) == 3


# --------------------------------------------------------------------------- commands with no head


def test_redirection_alone_is_a_command_with_no_name():
    cmd = only_command(">out.txt")
    assert cmd.name is None and cmd.words == ()
    assert cmd.redirects[0].op is RedirectOp.WRITE


def test_assignment_alone_is_a_command_with_no_name():
    cmd = only_command("A=1")
    assert cmd.name is None
    assert cmd.assignments[0].name == "A" and cmd.assignments[0].value.value == "1"


# --------------------------------------------------------------------------- rule 7: assignments


def test_assignments_in_prefix():
    cmd = only_command("A=1 B=two cmd x")
    assert [(a.name, a.value.value) for a in cmd.assignments] == [("A", "1"), ("B", "two")]
    assert values(cmd) == ["cmd", "x"]


def test_empty_assignment_value_is_known_and_empty():
    assert only_command("x=").assignments[0].value.value == ""


def test_assignment_value_keeps_its_substitution():
    value = only_command("D=$(pwd)").assignments[0].value
    assert value.value is None
    assert value.parts[0].kind is PartKind.CMD_SUBST
    assert value.parts[0].script is not None


def test_assignment_after_command_name_is_an_argument():
    cmd = only_command("echo a=b")
    assert cmd.assignments == () and values(cmd) == ["echo", "a=b"]


def test_leading_equals_is_an_ordinary_word():
    assert values(only_command("=1 cmd")) == ["=1", "cmd"]


def test_non_name_before_equals_in_prefix_is_refused():
    assert refused("a-b=c cmd") is Diag.MALFORMED_ASSIGNMENT


def test_non_name_before_equals_as_argument_is_fine():
    assert values(only_command("echo a-b=c")) == ["echo", "a-b=c"]


# --------------------------------------------------------------------------- rule 1: reserved words


@pytest.mark.parametrize("word", ["if", "while", "until", "for", "case", "select"])
def test_control_structures_are_refused_by_name(word):
    assert refused(f"{word} x") is Diag.CONTROL_STRUCTURE


@pytest.mark.parametrize(
    ("src", "code"),
    [
        ("{ ls; }", Diag.BRACE_GROUP),
        ("function f", Diag.FUNCTION_DEFINITION),
        ("f() { ls; }", Diag.FUNCTION_DEFINITION),
        ("[[ -f x ]]", Diag.BASH_CONDITIONAL),
        ("time ls", Diag.UNSUPPORTED_CONSTRUCT),
        ("coproc ls", Diag.UNSUPPORTED_CONSTRUCT),
        ("fi", Diag.UNEXPECTED_TOKEN),
        ("then ls", Diag.UNEXPECTED_TOKEN),
    ],
)
def test_other_reserved_words_are_refused_by_name(src, code):
    assert refused(src) is code


def test_quoting_defeats_a_reserved_word():
    assert values(only_command('"if" x')) == ["if", "x"]


def test_reserved_word_as_an_argument_is_ordinary():
    assert values(only_command("echo if then fi }")) == ["echo", "if", "then", "fi", "}"]


def test_reserved_word_after_an_assignment_is_still_refused():
    # POSIX rule 7b would make this a command named `if`; we refuse it as stricter.
    assert refused("A=1 if x") is Diag.CONTROL_STRUCTURE


def test_bang_only_at_the_start_of_a_pipeline():
    assert refused("! ! true") is Diag.UNSUPPORTED_CONSTRUCT
    assert refused("ls | ! grep x") is Diag.UNSUPPORTED_CONSTRUCT


# --------------------------------------------------------------------------- redirections


def test_io_number_versus_word():
    redirected = only_command("cmd 2>file")
    assert values(redirected) == ["cmd"]
    assert redirected.redirects[0].fd == 2

    argument = only_command("echo 2 > file")
    assert values(argument) == ["echo", "2"]
    assert argument.redirects[0].fd is None
    assert argument.redirects[0].effective_fd == 1


def test_unicode_digits_are_not_a_file_descriptor():
    # `"²".isdigit()` is True in Python, but bash treats `²` as an ordinary word.
    cmd = only_command("echo ²>f")
    assert values(cmd) == ["echo", "²"]
    assert cmd.redirects[0].fd is None


@pytest.mark.parametrize(
    ("src", "op", "writes"),
    [
        ("cmd <in", RedirectOp.READ, False),
        ("cmd >out", RedirectOp.WRITE, True),
        ("cmd >>log", RedirectOp.APPEND, True),
        ("cmd >|out", RedirectOp.CLOBBER, True),
        ("cmd <>f", RedirectOp.READ_WRITE, True),
    ],
)
def test_file_redirections(src, op, writes):
    redirect = only_command(src).redirects[0]
    assert redirect.op is op and redirect.writes is writes


def test_descriptor_duplication():
    redirect = only_command("cmd 2>&1").redirects[0]
    assert redirect.op is RedirectOp.DUP_OUT and redirect.fd == 2
    assert redirect.target is not None and redirect.target.value == "1"
    assert only_command("cmd 2>&-").redirects[0].target.value == "-"


@pytest.mark.parametrize("src", ["ls >& file", "ls >&$FD", "ls >&٣", "ls <&file"])
def test_duplication_to_a_file_name_is_refused(src):
    # In bash `>&file` writes both streams to `file`, a write that DUP_OUT would hide.
    assert refused(src) is Diag.BASH_ONLY_OPERATOR


def test_redirection_without_a_target_is_refused():
    assert refused("cmd >") is Diag.UNEXPECTED_TOKEN
    assert refused("cmd > | x") is Diag.UNEXPECTED_TOKEN


def test_redirections_in_prefix_and_suffix_keep_their_order():
    cmd = only_command("<in cmd >out 2>err")
    assert [r.op for r in cmd.redirects] == [RedirectOp.READ, RedirectOp.WRITE, RedirectOp.WRITE]
    assert values(cmd) == ["cmd"]


# --------------------------------------------------------------------------- here-documents


def test_quoted_heredoc_body_is_attached():
    redirect = only_command("cat <<'EOF'\nhello\nworld\nEOF\n").redirects[0]
    assert redirect.op is RedirectOp.HEREDOC
    assert redirect.body is not None and redirect.body.value == "hello\nworld\n"
    assert redirect.target is None


def test_heredoc_dash_strips_tabs():
    redirect = only_command("cat <<-'EOF'\n\thello\n\tEOF\n").redirects[0]
    assert redirect.op is RedirectOp.HEREDOC_DASH
    assert redirect.body.value == "hello\n"


def test_heredoc_with_no_body_is_refused_by_the_lexer():
    with pytest.raises(LexError) as excinfo:
        tokenize("cat <<'EOF'")
    assert excinfo.value.code is Diag.UNTERMINATED_HEREDOC


# --------------------------------------------------------------------------- subshells


def test_subshell_with_redirection():
    command = parse_source("(cd /etc; ls) > out").statements[0].and_or.first.commands[0]
    assert isinstance(command, Subshell)
    assert len(command.body) == 2
    assert command.redirects[0].op is RedirectOp.WRITE


def test_walk_reaches_commands_inside_subshells():
    names = [c.name.value for c in simple_commands(parse_source("(a; (b | c)) && d"))]
    assert names == ["a", "b", "c", "d"]


def test_nested_subshells_with_a_space():
    assert [c.name.value for c in simple_commands(parse_source("( (ls) )"))] == ["ls"]


def test_double_paren_is_an_arithmetic_command():
    # `((ls))` evaluates the variable `ls` as arithmetic, which runs any `$(...)` stored in it.
    assert refused("((ls))") is Diag.ARITHMETIC_COMMAND
    assert refused("echo x; ((y = 1))") is Diag.ARITHMETIC_COMMAND


@pytest.mark.parametrize("src", ["()", "(ls", "ls )", "(ls) foo"])
def test_malformed_subshells_are_refused(src):
    assert refused(src) is Diag.UNEXPECTED_TOKEN


def test_subshell_nesting_is_bounded():
    deep = "( " * (MAX_NESTING_DEPTH + 1) + "ls" + " )" * (MAX_NESTING_DEPTH + 1)
    assert refused(deep) is Diag.NESTING_TOO_DEEP


# --------------------------------------------------------------------------- command substitution


def test_substitution_is_parsed_recursively():
    part = only_command("echo $(whoami)").words[1].parts[0]
    assert part.kind is PartKind.CMD_SUBST
    assert [c.name.value for c in simple_commands(part.script)] == ["whoami"]


def test_substitution_inside_double_quotes_is_parsed():
    quoted = only_command('echo "x$(date)y"').words[1].parts[0]
    inner = [p for p in quoted.parts if p.kind is PartKind.CMD_SUBST][0]
    assert [c.name.value for c in simple_commands(inner.script)] == ["date"]


def test_nested_substitution_positions_are_absolute():
    src = "echo $(echo $(whoami))"
    outer = only_command(src).words[1].parts[0]
    middle = list(simple_commands(outer.script))[0]
    inner = middle.words[1].parts[0]
    whoami = list(simple_commands(inner.script))[0]
    assert src[whoami.pos : whoami.pos + len("whoami")] == "whoami"


def test_substitution_whose_inside_does_not_parse_denies_the_command():
    assert refused("echo $(if true; then ls; fi)") is Diag.CONTROL_STRUCTURE


def test_substitution_whose_inside_does_not_lex_is_a_parse_error():
    # The outer lexer only scans for the closing `)`; the inside fails when lexed for real.
    assert refused("echo $(cat <(ls))") is Diag.PROCESS_SUBSTITUTION


@pytest.mark.parametrize("src", ["echo ${x:-$(id)}", "echo ${x:=$(id)}", "echo $((1 + $(id)))"])
def test_substitution_hidden_in_an_expansion_is_refused(src):
    # These parts are opaque to the lexer, so the substitution would run unseen.
    assert refused(src) is Diag.SUBSTITUTION_IN_EXPANSION


def test_empty_substitution_is_accepted():
    assert only_command("echo $()").words[1].parts[0].script.statements == ()


# --------------------------------------------------------------------------- bash-only and stray tokens


@pytest.mark.parametrize("src", ["ls &>f", "ls &>>f", "ls |& cat", "cat <<<x", "ls ;;& ls"])
def test_bash_only_operators_are_refused_by_name(src):
    assert refused(src) is Diag.BASH_ONLY_OPERATOR


@pytest.mark.parametrize("src", ["ls |", "| ls", "; ls", "ls && && ls", "ls ;; ls", "ls &&"])
def test_stray_operators_are_refused(src):
    assert refused(src) is Diag.UNEXPECTED_TOKEN


def test_error_position_points_at_the_offending_token():
    with pytest.raises(ParseError) as excinfo:
        parse_source("ls; echo ok && while x")
    assert excinfo.value.pos == len("ls; echo ok && ")


# --------------------------------------------------------------------------- fail-closed properties

_FRAGMENTS = [
    "ls",
    "a=1",
    "a-b=c",
    "|",
    "&&",
    "||",
    ";",
    "&",
    "(",
    ")",
    "((",
    "\n",
    ">",
    "2>",
    ">&",
    "1",
    "-",
    "<<'E'\nx\nE\n",
    "$(ls)",
    '"$(a)"',
    "$(",
    "!",
    "if",
    "{",
    "}",
    "fi",
    "f()",
    "${x:-$(a)}",
    "$((1))",
    "&>",
    "|&",
    "<<<",
    ";;",
    "'q'",
    '"',
    "x=$(y)",
    "²",
    "#c",
]


def _parse_must_not_raise_anything_else(src: str) -> None:
    try:
        tokens = tokenize(src)
    except LexError:
        return
    try:
        parse(tokens, src)
    except ParseError:
        pass


@settings(max_examples=400, suppress_health_check=[HealthCheck.too_slow])
@given(st.text(max_size=80))
def test_only_parse_error_escapes_for_arbitrary_text(src):
    """For any input the lexer accepts, the parser returns a Script or raises ParseError."""
    _parse_must_not_raise_anything_else(src)


@settings(max_examples=600, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(st.sampled_from(_FRAGMENTS), max_size=14).map(" ".join))
def test_only_parse_error_escapes_for_shell_shaped_input(src):
    """Random text rarely gets past the lexer; shell-shaped fragments reach the parser's states."""
    _parse_must_not_raise_anything_else(src)


@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(st.sampled_from(_FRAGMENTS), max_size=14).map(" ".join))
def test_every_node_has_a_position_inside_the_source(src):
    """A denial points at characters through `pos`, so no node may point outside the command."""
    try:
        script = parse_source(src)
    except (LexError, ParseError):
        return
    for node in walk(script):
        assert 0 <= node.pos <= len(src)


# --------------------------------------------------------------- differential test against bash -n

_DIFFERENTIAL_CORPUS = [
    "ls -la",
    "A=1 B=2 env",
    "cat f | grep x | wc -l",
    "a && b || c; d &",
    "(cd /tmp; ls) > out 2>&1",
    "! true",
    "echo $(echo $(whoami))",
    "cat <<'EOF'\nbody\nEOF\n",
    "echo 'a b' \"c d\" e\\ f",
    "echo if then fi",
    ">out.txt",
    "x=",
    "( (ls) )",
    "if true; then ls; fi",
    "while x; do y; done",
    "for i in a b; do echo $i; done",
    "case x in a) ls;; esac",
    "{ ls; }",
    "f() { ls; }",
    "[[ -f x ]]",
    "((x = 1))",
    "ls &>f",
    "ls |& cat",
    "cat <<<x",
    "ls >& file",
    "a-b=c cmd",
    "echo ${x:-$(id)}",
    "! ! true",
    "ls |",
    "| ls",
    "ls ;; ls",
    "()",
    "(ls",
    "ls )",
    "ls && && ls",
    "fi",
]

# Codes that name a construct we refuse on purpose. When bash accepts a command and we refuse it,
# the refusal must carry one of these; a bare UNEXPECTED_TOKEN there would mean we failed to
# parse something the grammar meant to accept.
_DELIBERATE_REFUSALS = {
    Diag.CONTROL_STRUCTURE,
    Diag.BRACE_GROUP,
    Diag.FUNCTION_DEFINITION,
    Diag.BASH_CONDITIONAL,
    Diag.ARITHMETIC_COMMAND,
    Diag.BASH_ONLY_OPERATOR,
    Diag.SUBSTITUTION_IN_EXPANSION,
    Diag.MALFORMED_ASSIGNMENT,
    Diag.UNSUPPORTED_CONSTRUCT,
    Diag.PROCESS_SUBSTITUTION,
    Diag.BACKQUOTE_SUBSTITUTION,
    Diag.HEREDOC_UNQUOTED_DELIMITER,
    Diag.UNTERMINATED_HEREDOC,
    Diag.NESTING_TOO_DEEP,
}


def _bash_accepts(src: str) -> bool:
    """`bash -n` reads and parses without running anything, so it needs no sandbox.

    The script goes in over stdin: on Windows, passing it as an argument lets `subprocess` rewrite
    backslashes under the MS C runtime quoting rules, which corrupts exactly the inputs under test.
    """
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-n"],
        input=src.encode(),
        capture_output=True,
        check=False,
    )
    return result.returncode == 0


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash is not installed")
@pytest.mark.parametrize("src", _DIFFERENTIAL_CORPUS)
def test_agrees_with_bash_n(src):
    """If bash rejects and we accept, that is a bug. If bash accepts and we reject, the
    refusal must be a deliberate one that names its construct."""
    bash_ok = _bash_accepts(src)
    try:
        parse_source(src)
        ours_ok, code = True, None
    except (LexError, ParseError) as exc:
        ours_ok, code = False, exc.code

    if ours_ok:
        assert bash_ok, f"we accept {src!r} but bash -n rejects it"
    elif bash_ok:
        assert code in _DELIBERATE_REFUSALS, f"bash accepts {src!r} but we refuse it with {code}"
