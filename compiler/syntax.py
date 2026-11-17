"""Front-end types: tokens, word parts, and the AST node kinds the parser produces.

This is the contract between the lexer (`compiler/lexer.py`) and the parser. It deliberately
does NOT define `Effect` or `Verdict`; those belong to the middle end and live in
`compiler/types.py`, which is owned by the other half of the team (see TEAM.md).

The one idea that matters here is that a word is not a string. It is an ordered list of
`WordPart`s, each of which remembers how it was written in the source. That is what lets the
policy layer refuse to decide about `rm$IFS-rf$IFS/` instead of reading it as harmless text.
See `compiler/grammar.md` section 2.3 and `docs/related-work.md` on the GuardFall bypasses.

What this module deliberately does not handle: word splitting, glob expansion, and variable
lookup. A word may become zero, one or many arguments at execution time, and deciding that is
the resolver's job, not the lexer's.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

# Target shell. The accepted language is a subset of THIS shell, not of POSIX: a grammar
# written against POSIX and executed by bash is a bypass, because the two disagree (for
# example `&>f`, which POSIX reads as "background, then truncate f" and bash reads as "send
# both streams to f"). See docs/threat-model.md.
TARGET_SHELL = "bash"
TARGET_SHELL_MIN_VERSION = "5.2"
TARGET_SHELL_INVOCATION = ("bash", "--noprofile", "--norc", "-c")

# Resource limits. Hitting either is a named denial, never a Python exception escaping from
# somewhere unexpected.
MAX_INPUT_LENGTH = 65536
MAX_NESTING_DEPTH = 16


class Diag(StrEnum):
    """Diagnostic codes. Every refusal names one, so a verdict can cite it and a regression
    test can assert it. Codes are stable identifiers: rename them and you break both."""

    # Input hygiene
    INPUT_TOO_LONG = "input-too-long"
    ILLEGAL_CONTROL_BYTE = "illegal-control-byte"
    NESTING_TOO_DEEP = "nesting-too-deep"

    # Unterminated constructs
    UNTERMINATED_SQUOTE = "unterminated-single-quote"
    UNTERMINATED_DQUOTE = "unterminated-double-quote"
    UNTERMINATED_ANSI_C_QUOTE = "unterminated-ansi-c-quote"
    UNTERMINATED_EXPANSION = "unterminated-expansion"
    UNTERMINATED_BACKQUOTE = "unterminated-backquote"
    UNTERMINATED_HEREDOC = "unterminated-heredoc"
    TRAILING_BACKSLASH = "trailing-backslash"

    # Constructs we reject by name (see grammar.md section 3.2)
    PROCESS_SUBSTITUTION = "process-substitution"
    BACKQUOTE_SUBSTITUTION = "backquote-substitution"
    HEREDOC_UNQUOTED_DELIMITER = "heredoc-unquoted-delimiter"
    DECODED_NUL = "decoded-nul-byte"
    IO_LOCATION_REDIRECT = "io-location-redirect"

    # Reserved for the parser
    UNSUPPORTED_CONSTRUCT = "unsupported-construct"
    UNEXPECTED_TOKEN = "unexpected-token"
    MALFORMED_ASSIGNMENT = "malformed-assignment"


class LexError(Exception):
    """The only exception `tokenize` is allowed to raise.

    The gate turns this into a DENY. The fail-closed property test asserts that no other
    exception type ever escapes the lexer, for any input whatsoever.
    """

    def __init__(self, code: Diag, message: str, pos: int = -1) -> None:
        super().__init__(f"{code}: {message}" + (f" (at offset {pos})" if pos >= 0 else ""))
        self.code = code
        self.message = message
        self.pos = pos


class PartKind(StrEnum):
    """How one piece of a word was written. The security-relevant distinction is whether a
    kind carries a statically known value or not; see `WordPart.value`."""

    LITERAL = "literal"  # bare text
    ESCAPED = "escaped"  # \c
    SQUOTED = "squoted"  # '...'
    DQUOTED = "dquoted"  # "..." - holds nested parts
    ANSI_C_QUOTED = "ansi_c_quoted"  # $'...'
    PARAM_EXP = "param_exp"  # $name, ${name}
    CMD_SUBST = "cmd_subst"  # $(...)
    ARITH_EXP = "arith_exp"  # $((...))
    TILDE = "tilde"  # ~, ~user
    GLOB = "glob"  # unquoted *, ?, [...]
    BRACE_EXP = "brace_exp"  # {a,b}, {1..3}
    HEREDOC_BODY = "heredoc_body"  # the text of a here-document


@dataclass(frozen=True, slots=True)
class WordPart:
    """One piece of a word.

    `value` is the text this part contributes to the argument, when that is determined by the
    source alone. It is `None` when it is not: a command substitution has to run, a glob is
    matched against the filesystem, a parameter expansion needs the environment. `None` is not
    a failure, it is the honest answer, and the policy layer is built to act on it.

    `reason` explains a `None` value, so a denial can say why rather than just that.
    """

    kind: PartKind
    raw: str
    value: str | None = None
    reason: str | None = None
    parts: tuple[WordPart, ...] = ()
    depth: int = 0

    @property
    def is_known(self) -> bool:
        return self.value is not None


@dataclass(frozen=True, slots=True)
class Word:
    """A sequence of parts, exactly as written, with the quoting preserved."""

    parts: tuple[WordPart, ...]
    raw: str
    pos: int = -1

    @property
    def is_known(self) -> bool:
        """True when every part's value comes from the source.

        A known word still may not be a single argument: `"$E"` is known-empty and yields one
        field, while an unquoted empty expansion yields none. That is the resolver's problem.
        """
        return all(p.is_known for p in self.parts)

    @property
    def value(self) -> str | None:
        """The concatenated literal value, or None if any part is unknown."""
        if not self.is_known:
            return None
        return "".join(p.value or "" for p in self.parts)

    @property
    def unknown_reasons(self) -> tuple[str, ...]:
        return tuple(p.reason for p in self.parts if p.reason is not None)

    def has_kind(self, kind: PartKind) -> bool:
        return any(p.kind is kind for p in self.parts)


class TokenKind(StrEnum):
    """POSIX token names (Issue 8, section 2.10), plus the bash-only operators.

    The bash-only operators are tokenized even though the parser rejects every one of them.
    Recognising `&>` and reporting "redirect-both-streams is not supported" is correct; silently
    reading it as `&` followed by `>` is a bypass, and that is precisely the difference we
    verified on bash 5.3.15.
    """

    # Word-level
    WORD = "WORD"
    IO_NUMBER = "IO_NUMBER"
    NEWLINE = "NEWLINE"
    EOF = "EOF"

    # POSIX multi-character operators
    AND_IF = "AND_IF"  # &&
    OR_IF = "OR_IF"  # ||
    DSEMI = "DSEMI"  # ;;
    SEMI_AND = "SEMI_AND"  # ;&
    DLESS = "DLESS"  # <<
    DGREAT = "DGREAT"  # >>
    LESSAND = "LESSAND"  # <&
    GREATAND = "GREATAND"  # >&
    LESSGREAT = "LESSGREAT"  # <>
    DLESSDASH = "DLESSDASH"  # <<-
    CLOBBER = "CLOBBER"  # >|

    # POSIX single-character operators
    PIPE = "PIPE"  # |
    AMP = "AMP"  # &
    SEMI = "SEMI"  # ;
    LPAREN = "LPAREN"  # (
    RPAREN = "RPAREN"  # )
    LT = "LT"  # <
    GT = "GT"  # >

    # bash-only: tokenized, then rejected by the parser
    AND_GREAT = "AND_GREAT"  # &>   both streams to a file
    AND_DGREAT = "AND_DGREAT"  # &>>  both streams, appending
    PIPE_AND = "PIPE_AND"  # |&   pipe both streams
    TRIPLE_LESS = "TRIPLE_LESS"  # <<<  here-string
    DSEMI_AND = "DSEMI_AND"  # ;;&  case fallthrough


# Operators longest-first, so that `<<-` wins over `<<` and `&>>` over `&>`.
OPERATORS: tuple[tuple[str, TokenKind], ...] = (
    (";;&", TokenKind.DSEMI_AND),
    ("<<<", TokenKind.TRIPLE_LESS),
    ("<<-", TokenKind.DLESSDASH),
    ("&>>", TokenKind.AND_DGREAT),
    ("&&", TokenKind.AND_IF),
    ("||", TokenKind.OR_IF),
    (";;", TokenKind.DSEMI),
    (";&", TokenKind.SEMI_AND),
    ("<<", TokenKind.DLESS),
    (">>", TokenKind.DGREAT),
    ("<&", TokenKind.LESSAND),
    (">&", TokenKind.GREATAND),
    ("<>", TokenKind.LESSGREAT),
    (">|", TokenKind.CLOBBER),
    ("&>", TokenKind.AND_GREAT),
    ("|&", TokenKind.PIPE_AND),
    ("|", TokenKind.PIPE),
    ("&", TokenKind.AMP),
    (";", TokenKind.SEMI),
    ("(", TokenKind.LPAREN),
    (")", TokenKind.RPAREN),
    ("<", TokenKind.LT),
    (">", TokenKind.GT),
)

BASH_ONLY_OPERATORS = frozenset(
    {
        TokenKind.AND_GREAT,
        TokenKind.AND_DGREAT,
        TokenKind.PIPE_AND,
        TokenKind.TRIPLE_LESS,
        TokenKind.DSEMI_AND,
    }
)

# The operator characters, used by token-recognition rule 6.
OPERATOR_START_CHARS = frozenset("|&;()<>")

# POSIX reserved words (section 2.4). We accept only `!`; the parser rejects the rest with a
# named diagnostic. A word is only a candidate if no character of it was quoted, which is why
# `Token.could_be_reserved` is computed from the parts rather than from the text.
RESERVED_WORDS = frozenset(
    {
        "!",
        "{",
        "}",
        "case",
        "do",
        "done",
        "elif",
        "else",
        "esac",
        "fi",
        "for",
        "if",
        "in",
        "then",
        "until",
        "while",
    }
)

# Words bash reserves that POSIX leaves optional. Recognised only so that they are rejected
# explicitly instead of being treated as a command name.
BASH_RESERVED_WORDS = frozenset({"[[", "]]", "function", "select", "time", "coproc"})


@dataclass(frozen=True, slots=True)
class Token:
    """One token, with the source text it came from and its offset.

    `word` is present for WORD and IO_NUMBER tokens. The two context-dependent classifications
    POSIX describes are precomputed as hints rather than decided here, because deciding them
    needs the parser's position: `assignment_name` supports rule 7 and `could_be_reserved`
    supports rule 1. The lexer offers, the parser chooses.
    """

    kind: TokenKind
    raw: str
    pos: int
    word: Word | None = None
    assignment_name: str | None = None
    could_be_reserved: bool = False
    heredoc: Word | None = None
    metadata: dict[str, str] = field(default_factory=dict, compare=False)

    def __str__(self) -> str:
        return f"{self.kind}({self.raw!r})"
