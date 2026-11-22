"""Parser: from the lexer's tokens to the AST, for the language in `compiler/grammar.md`.

Takes the token list `tokenize` returns and produces a `Script` (see `compiler/syntax.py`).
Raises `ParseError`, and nothing else, on the first construct outside the grammar.

It is recursive descent with one method per production, each named after its production and
laid out in the same order as the EBNF in grammar section 3.1, so the parser and the grammar
can be checked against each other line by line. That correspondence is the argument that our
accepted language is specified rather than emergent.

Three things happen here rather than in the lexer, because they need to know where in the
grammar a token sits:

- POSIX rule 1. A word in command position that is exactly a reserved word is that reserved
  word. We accept `!` at the start of a pipeline and refuse every other one by name.
- POSIX rule 7. A word in a command prefix with an unquoted `=` after a valid name is an
  assignment. Where POSIX leaves the case implementation-defined, as in `a-b=c`, we refuse.
- The inside of every `$(...)` is parsed by calling this parser on it, as POSIX requires the
  tokenizing rules to be reapplied recursively. The result lands in the part's `script` field.

What it deliberately does not do: expand, resolve or evaluate anything. Every word is passed on
with its parts exactly as the lexer recorded them; turning words into values is the resolver's
job. Nor does it recover after an error. See `docs/decisions.md` for why the command parser
fails fast while the policy language's parser should not.
"""

from __future__ import annotations

import dataclasses
import re

from compiler.lexer import tokenize
from compiler.syntax import (
    BASH_ONLY_OPERATORS,
    MAX_NESTING_DEPTH,
    AndOr,
    AndOrOp,
    Assignment,
    Command,
    Diag,
    LexError,
    ParseError,
    PartKind,
    Pipeline,
    Redirect,
    RedirectOp,
    Script,
    SimpleCommand,
    Statement,
    Subshell,
    Token,
    TokenKind,
    Word,
    WordPart,
)

# The redirection operators we accept, mapped to the node's operator.
_FILE_REDIRECTS: dict[TokenKind, RedirectOp] = {
    TokenKind.LT: RedirectOp.READ,
    TokenKind.GT: RedirectOp.WRITE,
    TokenKind.DGREAT: RedirectOp.APPEND,
    TokenKind.CLOBBER: RedirectOp.CLOBBER,
    TokenKind.LESSGREAT: RedirectOp.READ_WRITE,
    TokenKind.LESSAND: RedirectOp.DUP_IN,
    TokenKind.GREATAND: RedirectOp.DUP_OUT,
}
_HEREDOC_REDIRECTS: dict[TokenKind, RedirectOp] = {
    TokenKind.DLESS: RedirectOp.HEREDOC,
    TokenKind.DLESSDASH: RedirectOp.HEREDOC_DASH,
}
_REDIRECT_TOKENS = frozenset(_FILE_REDIRECTS) | frozenset(_HEREDOC_REDIRECTS)

# A command substitution inside an opaque expansion: `$(` not followed by a second `(`, which would
# be nested arithmetic, or a backquote. Matched against the inside of the expansion only, since
# `$((` at the start of an arithmetic expansion is its own opening, not a substitution.
_HIDDEN_SUBSTITUTION = re.compile(r"\$\((?!\()|`")

# What each bash-only operator would have meant, for the message the agent sees.
_BASH_ONLY_MEANING: dict[TokenKind, str] = {
    TokenKind.AND_GREAT: "`&>` sends both output streams to a file",
    TokenKind.AND_DGREAT: "`&>>` appends both output streams to a file",
    TokenKind.PIPE_AND: "`|&` pipes the error stream as well as the output",
    TokenKind.TRIPLE_LESS: "`<<<` is a here-string",
    TokenKind.DSEMI_AND: "`;;&` is a case-statement terminator",
}

# Reserved words in command position, and why each is refused. `!` is absent because it is
# accepted at the start of a pipeline; anywhere else it falls through to the generic refusal.
_RESERVED_REFUSALS: dict[str, tuple[Diag, str]] = {
    **{
        word: (
            Diag.CONTROL_STRUCTURE,
            f"`{word}` begins a control structure; loops and branches are not analysed, "
            "because their effects are not a fixed set we can check before running",
        )
        for word in ("if", "while", "until", "for", "case", "select")
    },
    "{": (
        Diag.BRACE_GROUP,
        "`{ ...; }` brace groups are not supported; a subshell `( ... )` is",
    ),
    "function": (
        Diag.FUNCTION_DEFINITION,
        "function definitions are not analysed, because they change what a name means for "
        "every later command",
    ),
    "[[": (
        Diag.BASH_CONDITIONAL,
        "`[[ ... ]]` is not supported; `test` or `[ ... ]` is",
    ),
    "time": (Diag.UNSUPPORTED_CONSTRUCT, "the `time` keyword is not supported"),
    "coproc": (Diag.UNSUPPORTED_CONSTRUCT, "coprocesses are not supported"),
}


def parse(tokens: list[Token], src: str = "") -> Script:
    """Parse a token list from `tokenize`. Raises `ParseError`, and nothing else, on refusal."""
    return _Parser(tokens, src, base=0, depth=0).program()


def parse_source(src: str) -> Script:
    """Tokenize and parse in one step. Raises `LexError` or `ParseError`, and nothing else."""
    return parse(tokenize(src), src)


class _Parser:
    def __init__(self, tokens: list[Token], src: str, *, base: int, depth: int) -> None:
        if not tokens or tokens[-1].kind is not TokenKind.EOF:
            raise ParseError(Diag.UNEXPECTED_TOKEN, "token list does not end with EOF")
        self.tokens = tokens
        self.src = src
        # `base` is where this text starts in the original command, so that positions inside a
        # command substitution are offsets into the whole command and a denial can point at the
        # right characters. `depth` is how many substitutions deep we are.
        self.base = base
        self.depth = depth
        self.subshells = 0
        self.i = 0

    # ------------------------------------------------------------------ token helpers

    def _peek(self, ahead: int = 0) -> Token:
        return self.tokens[min(self.i + ahead, len(self.tokens) - 1)]

    def _advance(self) -> Token:
        tok = self.tokens[self.i]
        if tok.kind is not TokenKind.EOF:
            self.i += 1
        return tok

    def _pos(self, tok: Token) -> int:
        return tok.pos + self.base

    def _fail(self, code: Diag, message: str, tok: Token) -> ParseError:
        return ParseError(code, message, self._pos(tok))

    # ------------------------------------------------------------------ productions

    def program(self) -> Script:
        """program : linebreak complete_commands linebreak | linebreak"""
        statements = self._statements(closing=TokenKind.EOF)
        return Script(statements=statements, src=self.src, pos=self.base)

    def _statements(self, closing: TokenKind) -> tuple[Statement, ...]:
        """complete_commands at the top level, compound_list inside a subshell.

        The two productions differ only in what ends them, end of input or `)`, so one loop
        serves both. Each `and_or` is closed by `&`, `;`, a newline or the closing token.
        """
        out: list[Statement] = []
        while True:
            self._linebreak()
            tok = self._peek()
            if tok.kind is closing:
                return tuple(out)
            if tok.kind is TokenKind.EOF:
                raise self._fail(Diag.UNEXPECTED_TOKEN, "a subshell `(` is never closed by `)`", tok)

            and_or = self.and_or()
            tok = self._peek()
            background = False
            if tok.kind is TokenKind.AMP:
                background = True
                self._advance()
            elif tok.kind is TokenKind.SEMI:
                self._advance()
            elif tok.kind not in (TokenKind.NEWLINE, closing):
                raise self._refuse_stray(tok)
            out.append(Statement(and_or=and_or, pos=and_or.pos, background=background))

    def and_or(self) -> AndOr:
        """and_or : pipeline | and_or AND_IF linebreak pipeline | and_or OR_IF linebreak pipeline"""
        first = self.pipeline()
        rest: list[tuple[AndOrOp, Pipeline]] = []
        while self._peek().kind in (TokenKind.AND_IF, TokenKind.OR_IF):
            op = AndOrOp(self._advance().raw)
            self._linebreak()
            rest.append((op, self.pipeline()))
        return AndOr(first=first, pos=first.pos, rest=tuple(rest))

    def pipeline(self) -> Pipeline:
        """pipeline : pipe_sequence | Bang pipe_sequence
        pipe_sequence : command | pipe_sequence PIPE linebreak command"""
        start = self._peek()
        negated = False
        if self._is_reserved(start, "!"):
            self._advance()
            negated = True
        commands: list[Command] = [self.command()]
        while self._peek().kind is TokenKind.PIPE:
            self._advance()
            self._linebreak()
            commands.append(self.command())
        return Pipeline(commands=tuple(commands), pos=self._pos(start), negated=negated)

    def command(self) -> Command:
        """command : simple_command | subshell | subshell redirect_list"""
        tok = self._peek()
        if tok.kind is TokenKind.LPAREN:
            # `((` at the start of a command is not two subshells: bash reads it as an arithmetic
            # command, and arithmetic evaluates the contents of the variables it names as code.
            # So `((ls))` looks like running `ls` and instead runs whatever was stored in the
            # variable `ls`. POSIX leaves `((` at command start unspecified for exactly this
            # reason. `( (ls) )`, with a space, is genuinely nested subshells and is accepted.
            nxt = self._peek(1)
            if nxt.kind is TokenKind.LPAREN and nxt.pos == tok.pos + 1:
                raise self._fail(
                    Diag.ARITHMETIC_COMMAND,
                    "`((` begins an arithmetic command, which evaluates variable contents as "
                    "code; write `( (` with a space if nested subshells are meant",
                    tok,
                )
            return self.subshell()
        if tok.kind is TokenKind.WORD and tok.could_be_reserved:
            raise self._refuse_reserved(tok)
        if tok.kind in (TokenKind.WORD, TokenKind.IO_NUMBER) or tok.kind in _REDIRECT_TOKENS:
            return self.simple_command()
        raise self._refuse_stray(tok)

    def subshell(self) -> Subshell:
        """subshell : LPAREN compound_list RPAREN, followed by an optional redirect_list"""
        open_tok = self._advance()
        if self.depth + self.subshells >= MAX_NESTING_DEPTH:
            raise self._fail(Diag.NESTING_TOO_DEEP, "subshells are nested too deeply", open_tok)
        self.subshells += 1
        body = self._statements(closing=TokenKind.RPAREN)
        self.subshells -= 1
        close_tok = self._advance()  # _statements only returns when it sees the closing `)`
        if not body:
            raise self._fail(Diag.UNEXPECTED_TOKEN, "a subshell `( )` cannot be empty", close_tok)
        redirects: list[Redirect] = []
        while self._starts_redirect(self._peek()):
            redirects.append(self.io_redirect())
        return Subshell(body=body, pos=self._pos(open_tok), redirects=tuple(redirects))

    def simple_command(self) -> SimpleCommand:
        """simple_command : cmd_prefix cmd_word cmd_suffix | cmd_prefix cmd_word | cmd_prefix
        | cmd_name cmd_suffix | cmd_name"""
        start = self._peek()
        assignments: list[Assignment] = []
        words: list[Word] = []
        redirects: list[Redirect] = []

        # cmd_prefix: redirections and assignments, in any order, before the command word.
        while True:
            tok = self._peek()
            if self._starts_redirect(tok):
                redirects.append(self.io_redirect())
            elif tok.kind is TokenKind.WORD and tok.metadata.get("bad_assignment"):
                # Rule 7's implementation-defined case. `a-b=c` in prefix position is more likely
                # obfuscation than intent, and a shell may read it either way.
                raise self._fail(
                    Diag.MALFORMED_ASSIGNMENT,
                    f"`{tok.raw}` looks like an assignment but the part before `=` is not a "
                    "valid name, and shells disagree on what that means",
                    tok,
                )
            elif tok.kind is TokenKind.WORD and tok.assignment_name is not None:
                assignments.append(self._assignment(self._advance()))
            else:
                break

        # cmd_word or cmd_name. POSIX applies rule 7b here, under which a reserved word after
        # an assignment is an ordinary word, so `A=1 if` names a command called `if`. We refuse
        # it anyway: no real command is called `if`, and bash itself then fails on the `then`.
        tok = self._peek()
        if tok.kind is TokenKind.WORD:
            if tok.could_be_reserved:
                raise self._refuse_reserved(tok)
            words.append(self._word(self._advance()))
            if self._peek().kind is TokenKind.LPAREN:
                raise self._fail(
                    Diag.FUNCTION_DEFINITION,
                    f"`{tok.raw}()` defines a function; function definitions are not analysed, "
                    "because they change what a name means for every later command",
                    tok,
                )
            # cmd_suffix: arguments and redirections. Rules 1 and 7 do not apply here, so
            # `echo if` and `echo a=b` are ordinary arguments.
            while True:
                tok = self._peek()
                if tok.kind is TokenKind.WORD:
                    words.append(self._word(self._advance()))
                elif self._starts_redirect(tok):
                    redirects.append(self.io_redirect())
                else:
                    break

        if not (assignments or words or redirects):
            raise self._refuse_stray(self._peek())
        return SimpleCommand(
            pos=self._pos(start),
            assignments=tuple(assignments),
            words=tuple(words),
            redirects=tuple(redirects),
        )

    def io_redirect(self) -> Redirect:
        """io_redirect : io_file | IO_NUMBER io_file | io_here | IO_NUMBER io_here"""
        start = self._peek()
        fd: int | None = None
        if start.kind is TokenKind.IO_NUMBER:
            fd = int(self._advance().raw)
        tok = self._peek()

        if tok.kind in _HEREDOC_REDIRECTS:
            # io_here : DLESS here_end. The lexer has already consumed the delimiter word, checked
            # that it is quoted, and attached the body to the operator token.
            self._advance()
            if tok.heredoc is None:
                raise self._fail(Diag.UNTERMINATED_HEREDOC, "here-document has no body", tok)
            body = dataclasses.replace(tok.heredoc, pos=tok.heredoc.pos + self.base)
            return Redirect(op=_HEREDOC_REDIRECTS[tok.kind], pos=self._pos(start), fd=fd, body=body)

        if tok.kind in _FILE_REDIRECTS:
            op = _FILE_REDIRECTS[self._advance().kind]
            target_tok = self._peek()
            if target_tok.kind is not TokenKind.WORD:
                raise self._fail(
                    Diag.UNEXPECTED_TOKEN,
                    f"redirection `{tok.raw}` is not followed by a file name",
                    target_tok,
                )
            target = self._word(self._advance())
            if op in (RedirectOp.DUP_IN, RedirectOp.DUP_OUT):
                self._check_dup_target(tok, target_tok, target)
            return Redirect(op=op, pos=self._pos(start), fd=fd, target=target)

        raise self._refuse_stray(tok)

    def _check_dup_target(self, op_tok: Token, target_tok: Token, target: Word) -> None:
        """`>&` and `<&` must name a descriptor: a known run of digits, or `-` to close it.

        In bash `>&file` is not a duplication at all but the redirect-both-streams form, a write
        to `file` that `DUP_OUT` would hide from the effect analysis. An unresolvable target like
        `>&$FD` could expand to either, so it is refused for the same reason.
        """
        value = target.value
        # ASCII only: `"٣".isdigit()` is True, but to bash `>&٣` names a file, not descriptor 3.
        if value is not None and (value == "-" or (value.isascii() and value.isdigit())):
            return
        raise self._fail(
            Diag.BASH_ONLY_OPERATOR,
            f"`{op_tok.raw}` must be followed by a file descriptor number or `-`; with a file "
            "name, bash sends both output streams to that file",
            target_tok,
        )

    def _linebreak(self) -> None:
        """linebreak : newline_list | empty"""
        while self._peek().kind is TokenKind.NEWLINE:
            self._advance()

    # ------------------------------------------------------------------ words

    def _word(self, tok: Token) -> Word:
        """The token's word, positioned in the whole command, with its substitutions parsed."""
        if tok.word is None:  # the lexer attaches a word to every WORD token; fail closed if not
            raise self._fail(Diag.UNEXPECTED_TOKEN, f"`{tok.raw}` has no word attached", tok)
        pos = self._pos(tok)
        parts = self._parse_substitutions(tok.word.parts, tok.word.raw, pos)
        return Word(parts=parts, raw=tok.word.raw, pos=pos)

    def _assignment(self, tok: Token) -> Assignment:
        """Split `NAME=value` at the first `=`. The value keeps its parts and quoting.

        The lexer's rule 7 hint guarantees the name is made of literal parts only, so the `=`
        is the first one in the raw text and lies in a literal part.
        """
        name = tok.assignment_name
        if tok.word is None or name is None or "=" not in tok.word.raw:
            raise self._fail(Diag.MALFORMED_ASSIGNMENT, f"`{tok.raw}` is not an assignment", tok)
        eq = tok.word.raw.index("=")
        value_parts: list[WordPart] = []
        consumed = 0
        split = False
        for part in tok.word.parts:
            if split:
                value_parts.append(part)
                continue
            if consumed + len(part.raw) <= eq:
                consumed += len(part.raw)
                continue
            # This literal part contains the `=`: keep what follows it as the value's first part.
            rest = part.raw[eq - consumed + 1 :]
            if rest:
                value_parts.append(WordPart(PartKind.LITERAL, rest, value=rest))
            split = True
        value_raw = tok.word.raw[eq + 1 :]
        value_pos = self._pos(tok) + eq + 1
        parts = self._parse_substitutions(tuple(value_parts), value_raw, value_pos)
        value = Word(parts=parts, raw=value_raw, pos=value_pos)
        return Assignment(name=name, value=value, pos=self._pos(tok))

    def _parse_substitutions(self, parts: tuple[WordPart, ...], raw: str, pos: int) -> tuple[WordPart, ...]:
        """Fill in the `script` of every command substitution, including ones inside double quotes.

        `raw` is the text the parts were cut from and `pos` where it starts in the command, so
        each nested script can be parsed with absolute positions.
        """
        out: list[WordPart] = []
        cursor = 0
        for part in parts:
            found = raw.find(part.raw, cursor)
            offset = found if found >= 0 else cursor
            cursor = offset + len(part.raw)
            part_pos = pos + offset

            if part.kind is PartKind.CMD_SUBST:
                inner = part.raw[2:-1]
                part = dataclasses.replace(part, script=self._parse_nested(inner, part_pos + 2))
            elif part.kind is PartKind.DQUOTED and part.parts:
                part = dataclasses.replace(
                    part, parts=self._parse_substitutions(part.parts, part.raw, part_pos)
                )
            elif part.kind in (PartKind.PARAM_EXP, PartKind.ARITH_EXP) and _HIDDEN_SUBSTITUTION.search(
                part.raw[3:-2] if part.kind is PartKind.ARITH_EXP else part.raw[1:]
            ):
                # The lexer keeps `${x:-...}` operator forms and `$((...))` as opaque parts, so a
                # substitution inside one would run without ever appearing in the AST. Refuse,
                # rather than let it be invisible.
                raise ParseError(
                    Diag.SUBSTITUTION_IN_EXPANSION,
                    f"`{part.raw}` contains a command substitution inside a parameter or "
                    "arithmetic expansion, which is not analysed",
                    part_pos,
                )
            out.append(part)
        return tuple(out)

    def _parse_nested(self, inner: str, pos: int) -> Script:
        """Parse the text inside `$(...)` with this same parser, one level deeper.

        A failure inside is a failure of the whole command. A lexical failure inside is
        converted to a `ParseError` carrying the same code, which keeps `ParseError` the only
        exception `parse` can raise: the outer lexer only scanned far enough to find the closing
        parenthesis, so the inside can fail to lex even though the outside did not.
        """
        depth = self.depth + self.subshells + 1
        if depth > MAX_NESTING_DEPTH:
            raise ParseError(Diag.NESTING_TOO_DEEP, "command substitutions are nested too deeply", pos)
        try:
            tokens = tokenize(inner)
        except LexError as exc:
            where = pos + exc.pos if exc.pos >= 0 else pos
            raise ParseError(exc.code, f"inside a command substitution: {exc.message}", where) from None
        return _Parser(tokens, inner, base=pos, depth=depth).program()

    # ------------------------------------------------------------------ refusals

    def _starts_redirect(self, tok: Token) -> bool:
        return tok.kind is TokenKind.IO_NUMBER or tok.kind in _REDIRECT_TOKENS

    @staticmethod
    def _is_reserved(tok: Token, word: str) -> bool:
        return (
            tok.kind is TokenKind.WORD
            and tok.could_be_reserved
            and tok.word is not None
            and tok.word.value == word
        )

    def _refuse_reserved(self, tok: Token) -> ParseError:
        """Rule 1: a reserved word in command position. Name the construct it would begin."""
        word = tok.word.value if tok.word is not None else tok.raw
        if word in _RESERVED_REFUSALS:
            code, message = _RESERVED_REFUSALS[word]
            return self._fail(code, message, tok)
        if word == "!":
            return self._fail(
                Diag.UNSUPPORTED_CONSTRUCT,
                "`!` is accepted only once, at the start of a pipeline",
                tok,
            )
        return self._fail(
            Diag.UNEXPECTED_TOKEN,
            f"`{word}` is a reserved word and cannot begin a command",
            tok,
        )

    def _refuse_stray(self, tok: Token) -> ParseError:
        """A token where a command or a separator was expected."""
        if tok.kind in BASH_ONLY_OPERATORS:
            return self._fail(
                Diag.BASH_ONLY_OPERATOR,
                f"{_BASH_ONLY_MEANING[tok.kind]}, which is bash-only and not supported",
                tok,
            )
        if tok.kind in (TokenKind.DSEMI, TokenKind.SEMI_AND):
            return self._fail(
                Diag.UNEXPECTED_TOKEN,
                f"`{tok.raw}` is a case-statement terminator outside a case statement",
                tok,
            )
        if tok.kind in (TokenKind.EOF, TokenKind.NEWLINE):
            return self._fail(
                Diag.UNEXPECTED_TOKEN, "the command ends where another command was expected", tok
            )
        return self._fail(Diag.UNEXPECTED_TOKEN, f"unexpected `{tok.raw}`", tok)
