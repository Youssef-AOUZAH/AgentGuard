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

    `script` is the parsed contents of a CMD_SUBST part. The lexer leaves it None, because it
    only scans far enough to find the matching `)`; the parser fills it in by calling itself on
    the captured text, as POSIX requires the tokenizing rules to be reapplied recursively. A
    substitution's value stays None either way — we know what command it would run, not what it
    would print — but rules R3 and R7 need the structure. See `compiler/grammar.md` section 3.1.
    """

    kind: PartKind
    raw: str
    value: str | None = None
    reason: str | None = None
    parts: tuple[WordPart, ...] = ()
    depth: int = 0
    script: Script | None = None

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


# ---------------------------------------------------------------------------
# The AST
#
# One node per production in `compiler/grammar.md` section 3.1, with the POSIX names kept so
# that a reader can check the parser against the grammar and the grammar against the standard.
# Nodes are frozen: the resolver annotates by building new ones, never by mutating the tree
# the parser handed it, so a verdict can always be traced back to what was actually parsed.
#
# Every node carries `pos`, the offset of the token it began at. This is not decoration. An
# `Effect` points at the node that caused it, and the gate turns that into the character range
# it shows the agent; a node with no position makes a denial unexplainable.
# ---------------------------------------------------------------------------


class RedirectOp(StrEnum):
    """The redirection operators we accept, spelled as they are written.

    Each one also fixes the default file descriptor it applies to and whether it reads or
    writes, which is what makes redirections the one effect source that needs no knowledge
    table: `> f` is a WRITE to `f` whatever the command happens to be.
    """

    READ = "<"  # LT, default fd 0
    WRITE = ">"  # GT, default fd 1
    APPEND = ">>"  # DGREAT, default fd 1
    CLOBBER = ">|"  # overrides noclobber; still a WRITE
    READ_WRITE = "<>"  # LESSGREAT, default fd 0
    DUP_IN = "<&"  # LESSAND, duplicates a descriptor
    DUP_OUT = ">&"  # GREATAND, duplicates a descriptor
    HEREDOC = "<<"  # DLESS, quoted delimiter only
    HEREDOC_DASH = "<<-"  # DLESSDASH, leading tabs stripped


# Which descriptor an operator touches when no IO_NUMBER precedes it, and whether that
# descriptor is read or written. The resolver needs both to turn a Redirect into an Effect, and
# keeping them here means that knowledge lives in one place.
REDIRECT_DEFAULT_FD: dict[RedirectOp, int] = {
    RedirectOp.READ: 0,
    RedirectOp.WRITE: 1,
    RedirectOp.APPEND: 1,
    RedirectOp.CLOBBER: 1,
    RedirectOp.READ_WRITE: 0,
    RedirectOp.DUP_IN: 0,
    RedirectOp.DUP_OUT: 1,
    RedirectOp.HEREDOC: 0,
    RedirectOp.HEREDOC_DASH: 0,
}

REDIRECT_WRITES: frozenset[RedirectOp] = frozenset(
    {RedirectOp.WRITE, RedirectOp.APPEND, RedirectOp.CLOBBER, RedirectOp.READ_WRITE}
)


@dataclass(frozen=True, slots=True)
class Redirect:
    """One `io_redirect`.

    `fd` is the explicit IO_NUMBER when the source had one, otherwise None, meaning the
    operator's default: `2>f` has fd 2, while `>f` has fd None and defaults to 1. Keeping None
    rather than substituting the default preserves what was written, which is what the
    canonical emitter re-serialises.

    `target` is the filename word for a file redirection and None for a here-document, where
    `body` carries the text instead. For `<&` and `>&` the target is the descriptor word, so
    `2>&1` has target `1` -- a word and not an int, because `>&$FD` is legal and unresolvable.
    """

    op: RedirectOp
    pos: int
    fd: int | None = None
    target: Word | None = None
    body: Word | None = None

    @property
    def effective_fd(self) -> int:
        return self.fd if self.fd is not None else REDIRECT_DEFAULT_FD[self.op]

    @property
    def writes(self) -> bool:
        return self.op in REDIRECT_WRITES


@dataclass(frozen=True, slots=True)
class Assignment:
    """An ASSIGNMENT_WORD in a command prefix: `NAME=word`.

    `name` is a plain string because POSIX rule 7 recognises an assignment only when the text
    before the `=` is a valid unquoted name. `value` is a Word because the right-hand side is
    arbitrary, so `D=$(pwd)` has an unknown value and is recorded as unknown rather than
    guessed at.

    An assignment with no command word after it persists for the rest of the session, which is
    why the session's tracked variables are updated from these and only these.
    """

    name: str
    value: Word
    pos: int


@dataclass(frozen=True, slots=True)
class SimpleCommand:
    """`cmd_prefix cmd_word cmd_suffix` and its shorter forms.

    `words` holds the command name and its arguments in source order, so `words[0]` is the name
    when there is one. There may be none: `>out.txt` alone is a legal simple command that
    creates a file and runs nothing, and `A=1` alone is an assignment that runs nothing. Both
    have real effects and neither has a head, so code that assumes `words[0]` exists is wrong.
    """

    pos: int
    assignments: tuple[Assignment, ...] = ()
    words: tuple[Word, ...] = ()
    redirects: tuple[Redirect, ...] = ()

    @property
    def name(self) -> Word | None:
        """The command name, or None when this command only assigns or redirects."""
        return self.words[0] if self.words else None

    @property
    def args(self) -> tuple[Word, ...]:
        return self.words[1:]


@dataclass(frozen=True, slots=True)
class Subshell:
    """`( compound_list )`, optionally with redirections applied to the whole group.

    A subshell is its own environment: a `cd` or an assignment inside it does not outlive it.
    The resolver must therefore evaluate `body` against a copy of the session state and discard
    the copy, or `(cd /etc)` would silently move the session.
    """

    body: tuple[Statement, ...]
    pos: int
    redirects: tuple[Redirect, ...] = ()


Command = SimpleCommand | Subshell


@dataclass(frozen=True, slots=True)
class Pipeline:
    """`pipe_sequence`, optionally negated by `!`.

    Several commands sharing a data path, which is why the exfiltration rule has to look at a
    pipeline as a unit rather than at each command separately: reading a secret is one effect,
    sending it is another, and only their co-occurrence in one pipeline is what we refuse.
    """

    commands: tuple[Command, ...]
    pos: int
    negated: bool = False


class AndOrOp(StrEnum):
    AND = "&&"
    OR = "||"


@dataclass(frozen=True, slots=True)
class AndOr:
    """`and_or`: pipelines joined by `&&` and `||`, kept flat and left-associative.

    Stored as a first pipeline plus a list of (operator, pipeline) pairs rather than as a binary
    tree, because that is the order they execute in and nothing downstream needs the tree shape.

    Note for the resolver: whether a later pipeline runs at all depends on the exit status of an
    earlier one, which we cannot know. So the effects of an `and_or` are the union over every
    pipeline in it, a conservative over-approximation and the safe direction to err in.
    """

    first: Pipeline
    pos: int
    rest: tuple[tuple[AndOrOp, Pipeline], ...] = ()

    @property
    def pipelines(self) -> tuple[Pipeline, ...]:
        return (self.first,) + tuple(p for _, p in self.rest)


@dataclass(frozen=True, slots=True)
class Statement:
    """One `and_or` with the separator that terminated it.

    `background` is True when the separator was `&`. The parser accepts the form and records it;
    refusing it is a policy decision with a rule id, not a syntax error, because `&` is ordinary
    POSIX and a denial that cites a rule explains itself better than one that cites a parse
    failure. See the time-of-check note in `docs/threat-model.md`: a backgrounded command's
    effects land at an unknown time relative to the commands after it, which is why the policy
    treats it as unresolvable in time rather than as unparseable.
    """

    and_or: AndOr
    pos: int
    background: bool = False


@dataclass(frozen=True, slots=True)
class Script:
    """A whole command line: the root the parser returns.

    `src` is the original text, kept so a diagnostic can quote it and so the canonical emitter's
    round-trip test has something to compare against. Statements are in source order, which is
    also execution order, and the session state is threaded through them in that order.
    """

    statements: tuple[Statement, ...]
    src: str
    pos: int = 0


Node = Script | Statement | AndOr | Pipeline | SimpleCommand | Subshell | Redirect | Assignment


def walk(node: Node):
    """Yield `node` and every node beneath it, parents before children.

    The effect analysis and the canonical emitter both need a full traversal, and writing it
    once here stops them disagreeing about what "every command" means. In particular commands
    inside a subshell are included, which is easy to miss and is exactly where `(rm -rf /)`
    would hide.
    """
    yield node
    if isinstance(node, Script):
        for statement in node.statements:
            yield from walk(statement)
    elif isinstance(node, Statement):
        yield from walk(node.and_or)
    elif isinstance(node, AndOr):
        for pipeline in node.pipelines:
            yield from walk(pipeline)
    elif isinstance(node, Pipeline):
        for command in node.commands:
            yield from walk(command)
    elif isinstance(node, SimpleCommand):
        yield from node.assignments
        yield from node.redirects
    elif isinstance(node, Subshell):
        for statement in node.body:
            yield from walk(statement)
        yield from node.redirects


def simple_commands(root: Node):
    """Every `SimpleCommand` in the tree, subshells included. The common case of `walk`."""
    return (n for n in walk(root) if isinstance(n, SimpleCommand))


class ParseError(Exception):
    """The only exception `parse` is allowed to raise, mirroring `LexError`.

    The parser refuses on the first construct outside the grammar and does not recover. Error
    recovery exists to report many errors in a long source file; our input is one command line,
    there is nothing to synchronise to, and recovery would mean analysing a reconstruction of a
    command nobody wrote. `docs/decisions.md` records the reasoning, including why the policy
    DSL's own parser does the opposite.
    """

    def __init__(self, code: Diag, message: str, pos: int = -1) -> None:
        super().__init__(f"{code}: {message}" + (f" (at offset {pos})" if pos >= 0 else ""))
        self.code = code
        self.message = message
        self.pos = pos
