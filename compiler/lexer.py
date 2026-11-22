"""The lexer: a command string in, a list of `Token` out.

It implements the ten token-recognition rules of POSIX Issue 8 section 2.3, in order, against
the bash dialect named in `compiler/syntax.py`. `compiler/grammar.md` is the specification;
this file is the implementation, and where they disagree the document wins and this is a bug.

Two things it does and the borrowed parsers do not. It keeps, for every piece of every word,
how that piece was written, so that a word whose value is not determined by its source is
visibly unknown rather than quietly misread. And it tokenizes constructs it will not accept,
so that a refusal can name the construct instead of mis-tokenizing it: `&>f` becomes one
AND_GREAT token to be rejected, never AMP followed by GT, which is how a POSIX-only lexer
reads it and how a filter gets bypassed.

What it does NOT do, on purpose:
  - no expansion of anything: we never run a command substitution, glob the filesystem, or
    look up a variable. See docs/threat-model.md.
  - no word splitting. A word may become zero, one or many arguments; that is the resolver's
    job, and the distinction is where option injection lives.
  - no decision about whether a word is a reserved word or an assignment. Both are
    context-dependent in POSIX (rules 1 and 7), so the lexer computes hints and the parser
    decides from its position.

The only exception that may escape `tokenize` is `LexError`. A property test asserts that for
arbitrary input, which is what makes the gate able to fail closed.
"""

from __future__ import annotations

import dataclasses
import re

from compiler.syntax import (
    BASH_RESERVED_WORDS,
    MAX_INPUT_LENGTH,
    MAX_NESTING_DEPTH,
    OPERATOR_START_CHARS,
    OPERATORS,
    RESERVED_WORDS,
    Diag,
    LexError,
    PartKind,
    Token,
    TokenKind,
    Word,
    WordPart,
)

_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Characters that end a word (token-recognition rules 6 and 7).
_WORD_DELIMITERS = frozenset(" \t\n") | OPERATOR_START_CHARS

# What may follow `~` for bash to expand it: nothing, a login name, or a directory stack
# reference (`~+`, `~-`, `~2`, `~+1`). Anything else makes `~` an ordinary character.
_TILDE_PREFIX_RE = re.compile(r"|[+-]|[+-]?[0-9]+|[A-Za-z0-9._][A-Za-z0-9._-]*")

# Allowed control characters. Everything else in the C0 range, and DEL, is refused: a stray
# carriage return changes how a command tokenizes, and NUL truncates words in bash.
_ALLOWED_CONTROL = frozenset("\t\n")

# Inside double quotes, backslash escapes only these. `"\a"` stays two characters - verified
# on bash 5.3.15, and the most common hand-written lexer bug.
_DQUOTE_ESCAPABLE = frozenset('$`"\\\n')

# Escapes understood inside $'...'.
_ANSI_C_SIMPLE = {
    "a": "\a",
    "b": "\b",
    "e": "\x1b",
    "E": "\x1b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "v": "\v",
    "\\": "\\",
    "'": "'",
    '"': '"',
    "?": "?",
}

# Parameter expansions whose value we never claim to know. Every operator form
# (${x:=v}, ${x@P}, ${!x}, ${#x}, ${x//a/b}) and every special parameter lands here.
_SPECIAL_PARAM_CHARS = frozenset("?$!*@#-0123456789")


def is_name(text: str) -> bool:
    """True when `text` is a valid shell name, per POSIX (XBD 3.216)."""
    return bool(_NAME_RE.match(text))


def tokenize(src: str) -> list[Token]:
    """Tokenize `src`. Raises `LexError`, and nothing else, on refusal."""
    return _Lexer(src).run()


class _Lexer:
    def __init__(self, src: str) -> None:
        self._validate(src)
        self.src = src
        self.n = len(src)
        self.i = 0
        self.tokens: list[Token] = []
        # Here-documents whose bodies start after the next newline: (token index, strip tabs,
        # delimiter word). A command may queue several, and they are read in order.
        self.pending: list[tuple[int, bool, Word]] = []

    # ------------------------------------------------------------------ input hygiene

    @staticmethod
    def _validate(src: str) -> None:
        if len(src) > MAX_INPUT_LENGTH:
            raise LexError(
                Diag.INPUT_TOO_LONG,
                f"command is {len(src)} characters, limit is {MAX_INPUT_LENGTH}",
            )
        for pos, ch in enumerate(src):
            if not ch.isprintable() and ch not in _ALLOWED_CONTROL:
                raise LexError(
                    Diag.ILLEGAL_CONTROL_BYTE,
                    f"control character U+{ord(ch):04X} is not allowed in a command",
                    pos,
                )

    # ------------------------------------------------------------------ main loop

    def run(self) -> list[Token]:
        while True:
            self._skip_blanks()
            if self.i >= self.n:
                break
            ch = self.src[self.i]

            if ch == "\n":
                start = self.i
                self.i += 1
                self.tokens.append(Token(TokenKind.NEWLINE, "\n", start))
                self._read_pending_heredocs()
                continue

            # Rule 9: a comment runs to, but does not include, the newline. We only get here
            # at the start of a token, so `a#b` is handled inside _read_word (rule 8 first).
            if ch == "#":
                while self.i < self.n and self.src[self.i] != "\n":
                    self.i += 1
                continue

            if ch in OPERATOR_START_CHARS:
                self._read_operator()
                continue

            self._read_word_token()

        # A here-document whose body never started: `cat <<'EOF'` with no newline after it.
        # Bash warns and runs with an empty body; we refuse, since the command as written is
        # incomplete and the token would otherwise reach the parser with no body attached.
        if self.pending:
            _, _, delimiter = self.pending[0]
            raise LexError(
                Diag.UNTERMINATED_HEREDOC,
                f"here-document has no body; it must be closed by a line containing {delimiter.value!r}",
                self.i,
            )

        self.tokens.append(Token(TokenKind.EOF, "", self.i))
        return self.tokens

    def _skip_blanks(self) -> None:
        while self.i < self.n and self.src[self.i] in " \t":
            self.i += 1

    # ------------------------------------------------------------------ operators

    def _read_operator(self) -> None:
        start = self.i

        # Process substitution looks like an operator but is a word construct. Reject by name.
        if self.src.startswith(("<(", ">("), self.i):
            raise LexError(
                Diag.PROCESS_SUBSTITUTION,
                f"process substitution {self.src[self.i : self.i + 2]}...) is not supported",
                start,
            )

        for text, kind in OPERATORS:
            if self.src.startswith(text, self.i):
                self.i += len(text)
                self.tokens.append(Token(kind, text, start))
                if kind in (TokenKind.DLESS, TokenKind.DLESSDASH):
                    self._queue_heredoc(strip_tabs=kind is TokenKind.DLESSDASH)
                return

        # Unreachable while OPERATORS covers OPERATOR_START_CHARS, but fail closed anyway.
        raise LexError(Diag.UNEXPECTED_TOKEN, f"unrecognised operator {self.src[start]!r}", start)

    # ------------------------------------------------------------------ here-documents

    def _queue_heredoc(self, *, strip_tabs: bool) -> None:
        """The word after << or <<- is the delimiter. Register it; the body comes later."""
        token_index = len(self.tokens) - 1
        self._skip_blanks()
        if self.i >= self.n or self.src[self.i] in "\n":
            raise LexError(Diag.UNTERMINATED_HEREDOC, "here-document has no delimiter word", self.i)
        delimiter = self._read_word()

        # A quoted delimiter means the body is literal text, which is the only form we accept.
        # With an unquoted delimiter the body undergoes expansion, so its content would not be
        # statically known; that is a named refusal rather than a silent guess.
        quoted = any(
            p.kind in (PartKind.SQUOTED, PartKind.DQUOTED, PartKind.ESCAPED, PartKind.ANSI_C_QUOTED)
            for p in delimiter.parts
        )
        if not quoted:
            raise LexError(
                Diag.HEREDOC_UNQUOTED_DELIMITER,
                "here-document delimiter must be quoted, as in <<'EOF', so the body is literal",
                delimiter.pos,
            )
        if delimiter.value is None:
            raise LexError(
                Diag.UNTERMINATED_HEREDOC,
                "here-document delimiter is not statically known",
                delimiter.pos,
            )
        self.pending.append((token_index, strip_tabs, delimiter))

    def _read_pending_heredocs(self) -> None:
        """Consume the bodies that follow the newline we just emitted."""
        while self.pending:
            token_index, strip_tabs, delimiter = self.pending.pop(0)
            terminator = delimiter.value or ""
            body_lines: list[str] = []
            closed = False
            while self.i < self.n:
                end = self.src.find("\n", self.i)
                if end == -1:
                    line, next_i = self.src[self.i :], self.n
                else:
                    line, next_i = self.src[self.i : end], end + 1
                candidate = line.lstrip("\t") if strip_tabs else line
                self.i = next_i
                if candidate == terminator:
                    closed = True
                    break
                body_lines.append(candidate)
            if not closed:
                raise LexError(
                    Diag.UNTERMINATED_HEREDOC,
                    f"here-document is not closed by a line containing {terminator!r}",
                    self.i,
                )
            body = "".join(line + "\n" for line in body_lines)
            part = WordPart(PartKind.HEREDOC_BODY, body, value=body)
            word = Word((part,), body, self.i)
            self.tokens[token_index] = dataclasses.replace(self.tokens[token_index], heredoc=word)

    # ------------------------------------------------------------------ words

    def _read_word_token(self) -> None:
        start = self.i
        word = self._read_word()
        raw = self.src[start : self.i]

        # Lexical classification, POSIX 2.10.1 rule 2: digits delimited by < or > are a file
        # descriptor number, so `2>f` redirects fd 2 while `echo 2 > f` passes the word `2`.
        nxt = self.src[self.i] if self.i < self.n else ""
        # `nxt in "<>"` would be True at end of input, since "" is a substring of everything.
        # `isdigit` alone is not enough: it is True for `²` and `٣`, which bash treats as an
        # ordinary word, and `int("²")` raises. POSIX means the ASCII digits.
        if nxt in ("<", ">") and raw.isascii() and raw.isdigit():
            self.tokens.append(Token(TokenKind.IO_NUMBER, raw, start, word=word))
            return

        # POSIX 2.10.1 rule 3: {name}< is an optional, implementation-defined redirection form.
        if nxt in ("<", ">") and len(raw) >= 3 and raw.startswith("{") and raw.endswith("}"):
            raise LexError(
                Diag.IO_LOCATION_REDIRECT,
                f"the {raw}< redirection form is implementation-defined and not supported",
                start,
            )

        assignment_name, bad_assignment = self._assignment_hint(word)
        could_be_reserved = (
            all(p.kind is PartKind.LITERAL for p in word.parts)
            and word.value is not None
            and (word.value in RESERVED_WORDS or word.value in BASH_RESERVED_WORDS)
        )
        metadata = {"bad_assignment": "1"} if bad_assignment else {}
        self.tokens.append(
            Token(
                TokenKind.WORD,
                raw,
                start,
                word=word,
                assignment_name=assignment_name,
                could_be_reserved=could_be_reserved,
                metadata=metadata,
            )
        )

    def _assignment_hint(self, word: Word) -> tuple[str | None, bool]:
        """Rule 7, as a hint. Returns (name, malformed).

        Only an unquoted `=` in a LITERAL part counts, and only the first one. A leading `=`
        makes the token an ordinary word. A non-name prefix is the case POSIX leaves
        implementation-defined, which grammar.md resolves as a rejection, so we flag it and
        let the parser refuse if the token sits in a command prefix.
        """
        prefix: list[str] = []
        seen_non_literal = False
        for part in word.parts:
            if part.kind is not PartKind.LITERAL:
                seen_non_literal = True
                continue
            if "=" not in part.raw:
                prefix.append(part.raw)
                continue
            if seen_non_literal:
                # The name would depend on an expansion, as in `${x}a=1`, or be quoted, as in
                # `"A"=1` which bash treats as a command word. We will not guess; flag it so
                # the parser can refuse should it appear in a command prefix.
                return None, True
            head, _, _ = part.raw.partition("=")
            prefix.append(head)
            candidate = "".join(prefix)
            if candidate == "":
                return None, False  # a leading `=` makes this an ordinary word
            if is_name(candidate):
                return candidate, False
            return None, True  # POSIX leaves this unspecified; grammar.md rejects it
        return None, False

    def _read_word(self, depth: int = 0) -> Word:
        """Assemble one word from its parts, stopping at an unquoted delimiter."""
        if depth > MAX_NESTING_DEPTH:
            raise LexError(Diag.NESTING_TOO_DEEP, "word nesting is too deep", self.i)

        start = self.i
        parts: list[WordPart] = []
        literal: list[str] = []
        # Where bash expands a tilde, verified on 5.3.15 with printf: at the start of a word;
        # and, in a word shaped like an assignment (a valid unquoted name, then the first `=`),
        # right after that `=` and after each unquoted `:` that follows. Bash does this even for
        # an ordinary argument, so `dd of=~/x` writes under the home directory. It does not
        # happen after a second `=` (`a=b=~/x` is literal) or in a word whose part before `=` is
        # not a name (`--opt=~/x`, `a-b=~/x` and `=~/x` are all literal).
        tilde_ok = True
        seen_eq = False
        assignment_shaped = False

        def flush() -> None:
            if literal:
                text = "".join(literal)
                parts.append(WordPart(PartKind.LITERAL, text, value=text))
                literal.clear()

        while self.i < self.n:
            ch = self.src[self.i]

            if ch in _WORD_DELIMITERS:
                break

            if ch == "\\":
                # Line continuation is removed before tokenization (POSIX 2.2.1), so a
                # backslash-newline neither separates tokens nor contributes a character.
                if self.i + 1 >= self.n:
                    raise LexError(Diag.TRAILING_BACKSLASH, "command ends in a backslash", self.i)
                nxt = self.src[self.i + 1]
                self.i += 2
                if nxt == "\n":
                    continue
                flush()
                parts.append(WordPart(PartKind.ESCAPED, "\\" + nxt, value=nxt))
                tilde_ok = False
                continue

            if ch == "'":
                flush()
                parts.append(self._read_single_quoted())
                tilde_ok = False
                continue

            if ch == '"':
                flush()
                parts.append(self._read_double_quoted(depth))
                tilde_ok = False
                continue

            if ch == "`":
                raise LexError(
                    Diag.BACKQUOTE_SUBSTITUTION,
                    "backquote substitution is not supported; its escaping rules differ from $()",
                    self.i,
                )

            if ch == "$":
                part = self._read_dollar(depth)
                if part is None:  # a lone `$`, which is an ordinary character
                    literal.append("$")
                    self.i += 1
                else:
                    flush()
                    parts.append(part)
                tilde_ok = False
                continue

            if ch == "~" and tilde_ok:
                tilde = self._read_tilde(in_assignment=assignment_shaped)
                if tilde is not None:
                    flush()
                    parts.append(tilde)
                    tilde_ok = False
                    continue
                # Not a tilde expansion after all: `~` is an ordinary character, and what
                # follows it is read normally, quotes and expansions included.

            if ch in "*?":
                flush()
                self.i += 1
                parts.append(
                    WordPart(PartKind.GLOB, ch, reason=f"glob {ch!r} is matched against the filesystem")
                )
                tilde_ok = False
                continue

            if ch == "[" and self._bracket_closes():
                flush()
                parts.append(self._read_bracket())
                tilde_ok = False
                continue

            if ch == "{":
                brace = self._try_read_brace_expansion()
                if brace is not None:
                    flush()
                    parts.append(brace)
                    tilde_ok = False
                    continue

            if ch == "=" and not seen_eq:
                seen_eq = True
                assignment_shaped = not parts and is_name("".join(literal))
                tilde_ok = assignment_shaped
            else:
                tilde_ok = ch == ":" and assignment_shaped
            literal.append(ch)
            self.i += 1

        flush()
        return Word(tuple(parts), self.src[start : self.i], start)

    # ------------------------------------------------------------------ tilde

    def _read_tilde(self, *, in_assignment: bool) -> WordPart | None:
        """`~`, `~user`, `~+`, `~-`, `~N`. Never resolved here. Returns None if it is not one.

        The tilde-prefix runs to the first `/`, or also the first `:` inside an assignment-shaped
        word, and bash expands it only when that prefix is empty, a login name, or a directory
        stack reference. Anything else switches expansion off and leaves `~` as an ordinary
        character: a quoted character (`~'/x'` and `~""` are literal) or an expansion (`~$x` is
        `~` followed by the value of x). This matters for more than precision: reading the whole
        prefix as a user name used to swallow `"$` in `~"$(id)"`, hiding the start of a command
        substitution inside a tilde.

        A bare `~` becomes the session's home directory, but the lexer does not know it: HOME is
        session state, and `~user` needs a passwd lookup. The resolver fills this in from the
        fixed environment the executor owns, which is also why assignments to HOME are denied -
        otherwise the meaning of `~` would be agent-controlled.
        """
        start = self.i
        stops = "/:" if in_assignment else "/"
        j = start + 1
        while j < self.n and self.src[j] not in _WORD_DELIMITERS and self.src[j] not in stops:
            j += 1
        user = self.src[start + 1 : j]
        if not _TILDE_PREFIX_RE.fullmatch(user):
            return None
        self.i = j
        raw = self.src[start:j]
        if user == "":
            reason = "~ expands to the session's home directory"
        elif user[0] in "+-0123456789":
            reason = f"{raw} expands from the directory stack or the previous directory"
        else:
            reason = f"~{user} needs a passwd lookup"
        return WordPart(PartKind.TILDE, raw, reason=reason)

    # ------------------------------------------------------------------ quoting

    def _read_single_quoted(self) -> WordPart:
        start = self.i
        end = self.src.find("'", self.i + 1)
        if end == -1:
            raise LexError(Diag.UNTERMINATED_SQUOTE, "single quote is never closed", start)
        self.i = end + 1
        body = self.src[start + 1 : end]
        return WordPart(PartKind.SQUOTED, self.src[start : self.i], value=body)

    def _read_double_quoted(self, depth: int) -> WordPart:
        start = self.i
        self.i += 1  # opening quote
        parts: list[WordPart] = []
        literal: list[str] = []

        def flush() -> None:
            if literal:
                text = "".join(literal)
                parts.append(WordPart(PartKind.LITERAL, text, value=text))
                literal.clear()

        while True:
            if self.i >= self.n:
                raise LexError(Diag.UNTERMINATED_DQUOTE, "double quote is never closed", start)
            ch = self.src[self.i]

            if ch == '"':
                self.i += 1
                break

            if ch == "\\":
                if self.i + 1 >= self.n:
                    raise LexError(Diag.UNTERMINATED_DQUOTE, "double quote is never closed", start)
                nxt = self.src[self.i + 1]
                if nxt in _DQUOTE_ESCAPABLE:
                    self.i += 2
                    if nxt != "\n":  # escaped newline disappears
                        flush()
                        parts.append(WordPart(PartKind.ESCAPED, "\\" + nxt, value=nxt))
                    continue
                # Not escapable here, so the backslash is an ordinary character.
                literal.append("\\")
                self.i += 1
                continue

            if ch == "`":
                raise LexError(
                    Diag.BACKQUOTE_SUBSTITUTION,
                    "backquote substitution is not supported",
                    self.i,
                )

            if ch == "$":
                part = self._read_dollar(depth + 1)
                if part is None:
                    literal.append("$")
                    self.i += 1
                else:
                    flush()
                    parts.append(part)
                continue

            literal.append(ch)
            self.i += 1

        flush()
        inner = tuple(parts)
        known = all(p.is_known for p in inner)
        return WordPart(
            PartKind.DQUOTED,
            self.src[start : self.i],
            value="".join(p.value or "" for p in inner) if known else None,
            reason=None if known else "double-quoted text contains an expansion",
            parts=inner,
            depth=depth,
        )

    # ------------------------------------------------------------------ $ constructs

    def _read_dollar(self, depth: int) -> WordPart | None:
        """Handle everything that starts with `$`. Returns None for a bare `$`."""
        if depth > MAX_NESTING_DEPTH:
            raise LexError(Diag.NESTING_TOO_DEEP, "expansion nesting is too deep", self.i)

        start = self.i
        nxt = self.src[start + 1] if start + 1 < self.n else ""

        if nxt == "'":
            self.i += 1
            return self._read_ansi_c_quoted(start)

        if nxt == "(" and self.src.startswith("$((", start):
            end = self._scan_arithmetic(start + 3)
            raw = self.src[start:end]
            self.i = end
            # Arithmetic evaluates variable contents recursively, so `x='a[$(cmd)]'` with
            # `$((x))` runs cmd. We never claim to know the value.
            return WordPart(
                PartKind.ARITH_EXP,
                raw,
                reason="arithmetic expansion can evaluate variable contents recursively",
                depth=depth,
            )

        if nxt == "(":
            end, nesting = self._scan_cmd_subst(start + 2)
            raw = self.src[start:end]
            self.i = end
            return WordPart(
                PartKind.CMD_SUBST,
                raw,
                reason="command substitution must run to produce a value",
                depth=nesting,
            )

        if nxt == "{":
            end = self._scan_braced_param(start + 2)
            raw = self.src[start:end]
            self.i = end
            inner = raw[2:-1]
            if is_name(inner):
                return WordPart(
                    PartKind.PARAM_EXP,
                    raw,
                    reason=f"value of ${{{inner}}} is not tracked",
                    depth=depth,
                )
            return WordPart(
                PartKind.PARAM_EXP,
                raw,
                reason="parameter expansion operator forms are not interpreted",
                depth=depth,
            )

        if nxt and (nxt.isalpha() or nxt == "_"):
            j = start + 1
            while j < self.n and (self.src[j].isalnum() or self.src[j] == "_"):
                j += 1
            raw = self.src[start:j]
            self.i = j
            return WordPart(PartKind.PARAM_EXP, raw, reason=f"value of {raw} is not tracked", depth=depth)

        if nxt and nxt in _SPECIAL_PARAM_CHARS:
            raw = self.src[start : start + 2]
            self.i = start + 2
            return WordPart(
                PartKind.PARAM_EXP,
                raw,
                reason=f"special parameter {raw} is not interpreted",
                depth=depth,
            )

        return None

    def _read_ansi_c_quoted(self, start: int) -> WordPart:
        """`$'...'`, with the escape set bash implements. A decoded NUL is refused."""
        self.i += 1  # the opening quote
        out: list[str] = []
        while True:
            if self.i >= self.n:
                raise LexError(Diag.UNTERMINATED_ANSI_C_QUOTE, "$'...' is never closed", start)
            ch = self.src[self.i]
            if ch == "'":
                self.i += 1
                break
            if ch != "\\":
                out.append(ch)
                self.i += 1
                continue

            if self.i + 1 >= self.n:
                raise LexError(Diag.UNTERMINATED_ANSI_C_QUOTE, "$'...' is never closed", start)
            esc = self.src[self.i + 1]
            self.i += 2
            if esc in _ANSI_C_SIMPLE:
                out.append(_ANSI_C_SIMPLE[esc])
            elif esc == "x":
                out.append(self._read_radix_escape(16, 2, start))
            elif esc == "u":
                out.append(self._read_radix_escape(16, 4, start))
            elif esc == "U":
                out.append(self._read_radix_escape(16, 8, start))
            elif esc in "01234567":
                # Octal: back up so the first digit is read too. Guarding on the octal digits
                # rather than on isdigit() matters, because `\8` has no digits to consume and
                # would otherwise leave the cursor where it was.
                self.i -= 1
                out.append(self._read_radix_escape(8, 3, start))
            elif esc == "c":
                if self.i >= self.n:
                    raise LexError(Diag.UNTERMINATED_ANSI_C_QUOTE, "$'...' ends inside \\c", start)
                ctrl = self.src[self.i]
                self.i += 1
                out.append(chr(ord(ctrl.upper()) ^ 0x40))
            else:
                # An escape bash does not recognise keeps its backslash: `$'\8'` is the two
                # characters \8, not 8. Verified against bash 5.3.15 with printf.
                out.append("\\" + esc)

        value = "".join(out)
        if "\x00" in value:
            # bash silently drops the rest of the word at a NUL. Silence is not an option for
            # a security tool, so this is a named refusal.
            raise LexError(Diag.DECODED_NUL, "$'...' decodes to a NUL byte, which bash would truncate", start)
        return WordPart(PartKind.ANSI_C_QUOTED, self.src[start : self.i], value=value)

    def _read_radix_escape(self, base: int, max_digits: int, start: int) -> str:
        digits = "0123456789abcdef"[:base]
        j = self.i
        while j < self.n and j - self.i < max_digits and self.src[j].lower() in digits:
            j += 1
        if j == self.i:
            return ""
        try:
            code = int(self.src[self.i : j], base)
            out = chr(code)
        except (ValueError, OverflowError) as exc:
            raise LexError(Diag.UNTERMINATED_ANSI_C_QUOTE, f"invalid escape in $'...': {exc}", start) from exc
        self.i = j
        return out

    # ------------------------------------------------------------------ scanners

    def _scan_cmd_subst(self, i: int) -> tuple[int, int]:
        """Find the `)` closing a `$(`. Returns (index after it, maximum nesting depth).

        Parentheses cannot simply be counted: `$(echo ")")` has a `)` inside a quoted string,
        and a `#` beginning a word starts a comment. Quoted sections and nested substitutions
        are therefore skipped recursively.
        """
        depth = 1
        max_depth = 1
        prev_significant = ""
        while i < self.n:
            ch = self.src[i]
            if ch == "\\":
                i += 2
                prev_significant = "\\"
                continue
            if ch == "'":
                end = self.src.find("'", i + 1)
                if end == -1:
                    raise LexError(Diag.UNTERMINATED_SQUOTE, "single quote in $() is never closed", i)
                i = end + 1
                prev_significant = "'"
                continue
            if ch == '"':
                i = self._skip_double_quoted(i)
                prev_significant = '"'
                continue
            if ch == "#" and prev_significant in ("", " ", "\t", "\n", ";", "|", "&", "("):
                end = self.src.find("\n", i)
                i = self.n if end == -1 else end
                continue
            if ch == "(":
                depth += 1
                max_depth = max(max_depth, depth)
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    if max_depth > MAX_NESTING_DEPTH:
                        raise LexError(Diag.NESTING_TOO_DEEP, "command substitution nesting is too deep", i)
                    return i + 1, max_depth
            prev_significant = ch
            i += 1
        raise LexError(Diag.UNTERMINATED_EXPANSION, "$( is never closed", i)

    def _scan_arithmetic(self, i: int) -> int:
        depth = 2  # we are past `$((`
        while i < self.n:
            ch = self.src[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
        raise LexError(Diag.UNTERMINATED_EXPANSION, "$(( is never closed", i)

    def _scan_braced_param(self, i: int) -> int:
        depth = 1
        while i < self.n:
            ch = self.src[i]
            if ch == "\\":
                i += 2
                continue
            if ch == "'":
                end = self.src.find("'", i + 1)
                i = self.n if end == -1 else end + 1
                continue
            if ch == '"':
                i = self._skip_double_quoted(i)
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
        raise LexError(Diag.UNTERMINATED_EXPANSION, "${ is never closed", i)

    def _skip_double_quoted(self, i: int) -> int:
        """Skip a double-quoted run starting at `i`, returning the index after it."""
        i += 1
        while i < self.n:
            ch = self.src[i]
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                return i + 1
            i += 1
        raise LexError(Diag.UNTERMINATED_DQUOTE, "double quote is never closed", i)

    # ------------------------------------------------------------------ globs and braces

    def _bracket_closes(self) -> bool:
        """True when an unquoted `]` follows within this word, making `[` a bracket expression.

        Without this check the `[` of `[ -f x ]`, which is the `test` builtin, would be read as
        a glob and the word would become unresolvable for no reason.
        """
        j = self.i + 1
        if j < self.n and self.src[j] in "!^":
            j += 1
        if j < self.n and self.src[j] == "]":  # a literal ] as the first member
            j += 1
        while j < self.n and self.src[j] not in _WORD_DELIMITERS:
            if self.src[j] == "]":
                return True
            j += 1
        return False

    def _read_bracket(self) -> WordPart:
        start = self.i
        j = self.i + 1
        if j < self.n and self.src[j] in "!^":
            j += 1
        if j < self.n and self.src[j] == "]":
            j += 1
        while j < self.n and self.src[j] != "]":
            j += 1
        self.i = min(j + 1, self.n)
        return WordPart(
            PartKind.GLOB,
            self.src[start : self.i],
            reason="bracket expression is matched against the filesystem",
        )

    def _try_read_brace_expansion(self) -> WordPart | None:
        """Detect `{a,b}` and `{1..3}`, which bash expands into several words.

        Brace expansion runs before every other expansion and its rules are intricate, so v1
        recognises it and calls it unknown rather than enumerating it. grammar.md records this
        as deliberate, to be revisited with a differential test.
        """
        depth = 0
        j = self.i
        while j < self.n and self.src[j] not in _WORD_DELIMITERS:
            ch = self.src[j]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    inner = self.src[self.i + 1 : j]
                    if "," in inner or ".." in inner:
                        start = self.i
                        self.i = j + 1
                        return WordPart(
                            PartKind.BRACE_EXP,
                            self.src[start : self.i],
                            reason="brace expansion produces several words",
                        )
                    return None
            j += 1
        return None
