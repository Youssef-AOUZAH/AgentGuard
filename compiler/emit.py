"""Canonical emitter: from the AST back to a command string, which is what the gate executes.

Takes a `Script` from the parser and returns one string. The gate runs that string, never the
command the agent sent. If our reading of the agent's text and the shell's reading ever differ,
executing our own re-serialisation means the thing that runs is the thing that was checked.
`docs/related-work.md` section 3 explains why none of the existing guards does this.

The rule that makes it work: every part of a word whose value we know is written out afresh from
that value, in single quotes, and the agent's spelling of it is thrown away. `a\\ b`, `"a b"` and
`$'a\\x20b'` all become `'a b'`. Inside single quotes nothing is special except the closing quote,
so what has to be right shrinks from our whole lexer to one quoting rule. A value containing a
control character uses `$'...'` with fixed-width escapes instead, because our own lexer refuses
raw control characters and the output must parse again.

Parts whose value we do not know keep a fixed form that preserves what bash will do with them:
`$x` becomes `${x}`, `$(...)` is re-emitted from its parsed contents, and globs, brace expansions
and tildes stay unquoted, because quoting them would switch the expansion off. An expansion that
was inside double quotes stays inside double quotes, since quoting decides whether its result is
split into several arguments.

Several spellings would change meaning if written the obvious way, and each is handled where it
arises: the name of an assignment stays bare, the character after a tilde stays bare, a subshell
directly inside a subshell or a `$(` gets a space so that `((` never appears, and here-document
bodies follow the newline that ends their line.

What this module deliberately does not do: execute anything, resolve variables, or preserve the
agent's formatting. Comments and line continuations are gone by the time the AST exists, `<<-`
becomes `<<` because the parser has already stripped the tabs, and statements are separated by
`; ` except where a here-document needs a newline.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from compiler.lexer import is_name
from compiler.syntax import (
    AndOr,
    Assignment,
    Command,
    PartKind,
    Pipeline,
    Redirect,
    RedirectOp,
    Script,
    SimpleCommand,
    Statement,
    Subshell,
    Word,
    WordPart,
)


class EmitError(Exception):
    """Raised when a parsed command has no canonical form. The gate treats it as a DENY.

    It is raised for one construct: a here-document inside a command substitution, while an
    earlier command on the same line already has a here-document waiting for its body, as in
    `cat <<'A' | echo $(cat <<'B' ...)`. Which body bash would read at the newline inside the
    substitution is exactly the kind of question we refuse to guess at. Within a single command
    the question never arises, because redirections are written after the arguments.
    """


def emit(script: Script) -> str:
    """The canonical command for `script`. Raises `EmitError`, and nothing else, on refusal."""
    writer = _Writer()
    writer.statements(script.statements)
    writer.flush_heredocs()
    return "".join(writer.out)


def emit_word(word: Word) -> str:
    """One word in canonical form, as it would appear as a command argument."""
    return _emit_word(word.parts, _Writer())


# --------------------------------------------------------------------------- statements


@dataclass
class _Writer:
    """Accumulates output, and the here-documents whose bodies wait for the next newline.

    Bash reads the bodies of all pending here-documents, in order, at the next newline token,
    which may come in the middle of a subshell. So pending bodies belong to the writer rather than
    to the statement that opened them. A command substitution gets a writer of its own, with a
    link to the writer it is nested in so it can tell whether a body is already waiting outside.
    """

    out: list[str] = field(default_factory=list)
    pending: list[tuple[str, str]] = field(default_factory=list)
    outer: _Writer | None = None

    def write(self, text: str) -> None:
        self.out.append(text)

    def statements(self, statements: tuple[Statement, ...]) -> None:
        for index, statement in enumerate(statements):
            if index:
                if self.pending:
                    self.newline()
                elif not statements[index - 1].background:
                    self.write("; ")
                else:
                    self.write(" ")  # `&` already separates: `a & b`
            self.write(_and_or(statement.and_or, self))
            if statement.background:
                self.write(" &")

    def newline(self) -> None:
        self._check_newline_is_safe()
        self.write("\n")
        self._write_bodies()

    def flush_heredocs(self) -> None:
        """Write any pending bodies, after the newline they need."""
        if self.pending:
            self.newline()

    def _write_bodies(self) -> None:
        for delimiter, body in self.pending:
            self.write(body)
            self.write(delimiter + "\n")
        self.pending.clear()

    def _check_newline_is_safe(self) -> None:
        # A newline inside a command substitution, while a body is waiting on the line outside
        # it: bash might read the outer body here. We refuse rather than guess.
        if self.outer_has_pending():
            raise EmitError(
                "a here-document inside a command substitution, on a line where another "
                "here-document is already waiting for its body"
            )

    def outer_has_pending(self) -> bool:
        writer = self.outer
        while writer is not None:
            if writer.pending:
                return True
            writer = writer.outer
        return False


def _and_or(and_or: AndOr, writer: _Writer) -> str:
    text = _pipeline(and_or.first, writer)
    for op, pipeline in and_or.rest:
        text += f" {op.value} " + _pipeline(pipeline, writer)
    return text


def _pipeline(pipeline: Pipeline, writer: _Writer) -> str:
    text = " | ".join(_command(command, writer) for command in pipeline.commands)
    return "! " + text if pipeline.negated else text


def _command(command: Command, writer: _Writer) -> str:
    if isinstance(command, Subshell):
        return _subshell(command, writer)
    return _simple_command(command, writer)


def _subshell(subshell: Subshell, writer: _Writer) -> str:
    # The body is written straight into the writer, because a newline inside it is where bash
    # reads any pending here-document bodies. The spaces inside the parentheses are not style:
    # without them `( (ls) )` would come out as `((ls))`, which bash runs as arithmetic.
    inner = _Writer(pending=writer.pending, outer=writer.outer)
    inner.statements(subshell.body)
    text = "( " + "".join(inner.out) + " )"
    for redirect in subshell.redirects:
        text += " " + _redirect(redirect, writer)
    return text


def _simple_command(command: SimpleCommand, writer: _Writer) -> str:
    # Assignments must come first. Redirections may move: their position relative to the
    # arguments does not matter to bash, while their order relative to each other does, and is
    # kept, since `>f 2>&1` and `2>&1 >f` do different things.
    pieces = [_assignment(a, writer) for a in command.assignments]
    pieces += [_emit_word(w.parts, writer) for w in command.words]
    pieces += [_redirect(r, writer) for r in command.redirects]
    return " ".join(pieces)


def _assignment(assignment: Assignment, writer: _Writer) -> str:
    # The name stays bare: quoted, `A=1` would be a command called `A=1`. The value is written in
    # assignment context, where a tilde may follow the `=` or a `:`.
    return assignment.name + "=" + _emit_word(assignment.value.parts, writer, assignment_value=True)


def _redirect(redirect: Redirect, writer: _Writer) -> str:
    fd = "" if redirect.fd is None else str(redirect.fd)
    if redirect.op in (RedirectOp.HEREDOC, RedirectOp.HEREDOC_DASH):
        body = redirect.body.value if redirect.body is not None else None
        if body is None:
            raise EmitError("a here-document has no literal body")
        delimiter = _heredoc_delimiter(body)
        writer.pending.append((delimiter, body))
        # `<<-` becomes `<<`: the parser has already stripped the leading tabs from the body.
        return f"{fd}<<'{delimiter}'"
    if redirect.target is None:
        raise EmitError(f"redirection {redirect.op.value} has no target")
    if redirect.op in (RedirectOp.DUP_IN, RedirectOp.DUP_OUT):
        # The parser guarantees a duplication target is a known run of ASCII digits or `-`. It is
        # written bare, as written, because a quoted target is not the same construct to bash.
        target = redirect.target.value
        if target is None or not (target == "-" or (target.isascii() and target.isdigit())):
            raise EmitError(f"{redirect.op.value} must be followed by a descriptor number or -")
        return f"{fd}{redirect.op.value}{target}"
    return f"{fd}{redirect.op.value}" + _emit_word(redirect.target.parts, writer)


def _heredoc_delimiter(body: str) -> str:
    """`EOF`, or `EOF1`, `EOF2`... if the body contains a line equal to it. Deterministic, so the
    same body always gets the same delimiter and emission stays a fixed point."""
    lines = set(body.split("\n"))
    candidate, n = "EOF", 0
    while candidate in lines:
        n += 1
        candidate = f"EOF{n}"
    return candidate


# --------------------------------------------------------------------------- words


def _emit_word(parts: tuple[WordPart, ...], writer: _Writer, *, assignment_value: bool = False) -> str:
    """Re-serialise one word from its parts.

    Known text is collected and written out quoted. Unknown parts are written in their fixed
    form. Two rules about tildes, both verified against bash 5.3.15: the character right after a
    tilde (`/`, or `:` in an assignment) must stay unquoted, because a quoted character in the
    tilde-prefix switches expansion off, and in an argument shaped like an assignment the
    `NAME=` before a tilde must stay unquoted too, since that shape is what lets bash expand it.
    """
    out: list[str] = []
    pending_text: list[str] = []
    after_tilde = False
    quoted_known = False

    def flush() -> None:
        nonlocal after_tilde
        text = "".join(pending_text)
        pending_text.clear()
        if after_tilde and text[:1] in ("/", ":"):
            out.append(text[0])
            text = text[1:]
        after_tilde = False
        if text:
            out.append(_quote(text))

    # In an argument such as `of=~/x` the lexer only marks the tilde when the word is shaped like
    # an assignment, so its first part is a literal starting with `NAME=`. Keep that bare.
    if not assignment_value and any(p.kind is PartKind.TILDE for p in parts[1:]):
        head = parts[0]
        if head.kind is not PartKind.LITERAL or head.value is None or "=" not in head.value:
            raise EmitError("a tilde after `=` in a word that is not shaped like an assignment")
        name, _, rest = head.value.partition("=")
        if not is_name(name):
            raise EmitError(f"`{name}=` before a tilde is not a valid name")
        out.append(name + "=")
        parts = ((WordPart(PartKind.LITERAL, rest, value=rest),) if rest else ()) + parts[1:]
        assignment_value = True

    for part in parts:
        if part.kind is PartKind.TILDE:
            # A tilde after a `:` in an assignment needs that `:` unquoted as well.
            if assignment_value and pending_text and pending_text[-1].endswith(":"):
                pending_text[-1] = pending_text[-1][:-1]
                flush()
                out.append(":")
            else:
                flush()
            out.append(part.raw)
            after_tilde = True
            continue
        if part.is_known:
            if part.kind is not PartKind.LITERAL:
                quoted_known = True
            pending_text.append(part.value or "")
            continue
        flush()
        if part.kind is PartKind.DQUOTED:
            out.append(_double_quoted(part, writer))
        else:
            out.append(_unknown_part(part, writer))

    flush()
    text = "".join(out)
    # A quoted empty string keeps a word alive even when the rest of it expands to nothing:
    # `''$e` with `e` empty is one empty argument, `$e` alone is none. Keep that.
    if (quoted_known or not text) and "'" not in text and '"' not in text:
        text += "''"
    return text


def _double_quoted(part: WordPart, writer: _Writer) -> str:
    """A double-quoted part with at least one unknown expansion inside it.

    Known text inside is written single-quoted, and each expansion is wrapped in its own double
    quotes: `"a$x b"` becomes `'a'"${x}"' b'`. Adjacent quoted pieces concatenate into one word,
    and each expansion stays quoted, so it is still not split into several arguments.
    """
    pieces: list[str] = []
    text: list[str] = []
    for child in part.parts:
        if child.is_known:
            text.append(child.value or "")
            continue
        if text:
            pieces.append(_quote("".join(text)))
            text.clear()
        pieces.append('"' + _unknown_part(child, writer) + '"')
    if text:
        pieces.append(_quote("".join(text)))
    return "".join(pieces)


def _unknown_part(part: WordPart, writer: _Writer) -> str:
    if part.kind is PartKind.CMD_SUBST:
        if part.script is None:
            raise EmitError("a command substitution was never parsed")
        return _substitution(part.script, writer)
    if part.kind is PartKind.PARAM_EXP and part.raw.startswith("$") and is_name(part.raw[1:]):
        return "${" + part.raw[1:] + "}"  # the braced form cannot run into the next character
    if part.kind in (
        PartKind.PARAM_EXP,
        PartKind.ARITH_EXP,
        PartKind.GLOB,
        PartKind.BRACE_EXP,
        PartKind.TILDE,
    ):
        # Written as the agent wrote it: these are expansions we did not interpret, so the only
        # faithful form is the original one, unquoted, exactly where it was.
        return part.raw
    raise EmitError(f"no canonical form for a {part.kind.value} part")


def _substitution(script: Script, writer: _Writer) -> str:
    # The substitution's own here-documents are written inside it, before the `)`. Every newline
    # that needs goes through `newline`, which refuses if a body is waiting outside.
    inner = _Writer(outer=writer)
    inner.statements(script.statements)
    inner.flush_heredocs()
    body = "".join(inner.out)
    # `$( (ls) )`, not `$((ls))`, which is arithmetic expansion.
    if body.startswith("("):
        body = " " + body
    return "$(" + body + ")"


def _quote(text: str) -> str:
    """Known text, quoted so that bash reads exactly this value back."""
    if all(ch.isprintable() or ch in "\t\n" for ch in text):
        return "'" + text.replace("'", "'\\''") + "'"
    return "$'" + "".join(_ansi_c_escape(ch) for ch in text) + "'"


def _ansi_c_escape(ch: str) -> str:
    # Fixed width, so a following hex digit can never be read as part of the escape.
    if ch == "\\":
        return "\\\\"
    if ch == "'":
        return "\\'"
    if ch.isprintable():
        return ch
    code = ord(ch)
    if code < 0x80:
        return f"\\x{code:02x}"
    if code <= 0xFFFF:
        return f"\\u{code:04x}"
    return f"\\U{code:08x}"
