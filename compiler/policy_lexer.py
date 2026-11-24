"""Lexer for the policy language (`policies/*.pol`).

Takes in the text of a policy file. Returns the tokens and the lexical errors found, never
raising: an unexpected character or an unterminated string is recorded, skipped, and lexing goes
on, so the parser can report every mistake in one run (`docs/decisions.md`, "The command parser
fails fast; the policy DSL recovers").

Tokens:

- `WORD`: a bare word, `[A-Za-z_][A-Za-z0-9_]*`. Keywords, rule ids (`R4`), effect kinds
  (`net_out`), zones and list names are all words; the parser tells them apart by position, which
  keeps the keyword list in one place and lets a list be called `trusted` without escaping.
- `STRING`: `"..."`, with `\\"`, `\\\\`, `\\n` and `\\t` as the only escapes. Paths, hosts,
  names and the commands in `expect` lines are strings.
- `NUMBER`: ASCII digits.
- punctuation: `{ } [ ] , |` and the comparisons `== != > >= < <=`.
- `EOF`, always last.

`#` starts a comment that runs to the end of the line. Newlines separate nothing in the grammar,
but each token records whether it is the first on its line, which is where the parser
resynchronises after an error.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from compiler.policy_syntax import MAX_POLICY_LENGTH, PolicyDiag, PolicyError


class PolicyTokenKind(StrEnum):
    WORD = "word"
    STRING = "string"
    NUMBER = "number"
    LBRACE = "{"
    RBRACE = "}"
    LBRACKET = "["
    RBRACKET = "]"
    COMMA = ","
    PIPE = "|"
    COMPARE = "compare"
    EOF = "end of file"


@dataclass(frozen=True, slots=True)
class PolicyToken:
    kind: PolicyTokenKind
    text: str  # the word, the string's value (escapes resolved), the digits, or the punctuation
    pos: int
    line: int
    col: int
    first_on_line: bool


_PUNCTUATION = {
    "{": PolicyTokenKind.LBRACE,
    "}": PolicyTokenKind.RBRACE,
    "[": PolicyTokenKind.LBRACKET,
    "]": PolicyTokenKind.RBRACKET,
    ",": PolicyTokenKind.COMMA,
    "|": PolicyTokenKind.PIPE,
}
_ESCAPES = {'"': '"', "\\": "\\", "n": "\n", "t": "\t"}


def _is_word_start(ch: str) -> bool:
    return ch == "_" or ("a" <= ch <= "z") or ("A" <= ch <= "Z")


def _is_word_char(ch: str) -> bool:
    return _is_word_start(ch) or ("0" <= ch <= "9")


def tokenize_policy(src: str) -> tuple[list[PolicyToken], list[PolicyError]]:
    """The tokens of `src`, ending with `EOF`, and every lexical error. Never raises."""
    return _Lexer(src).run()


class _Lexer:
    def __init__(self, src: str) -> None:
        self.src = src
        self.i = 0
        self.line = 1
        self.line_start = 0
        self.line_has_token = False
        self.tokens: list[PolicyToken] = []
        self.errors: list[PolicyError] = []

    def run(self) -> tuple[list[PolicyToken], list[PolicyError]]:
        if len(self.src) > MAX_POLICY_LENGTH:
            self._error(
                PolicyDiag.TOO_LONG, f"a policy file may be at most {MAX_POLICY_LENGTH} characters", 0
            )
            self.tokens.append(PolicyToken(PolicyTokenKind.EOF, "", 0, 1, 1, True))
            return self.tokens, self.errors
        src = self.src
        while self.i < len(src):
            ch = src[self.i]
            if ch == "\n":
                self.i += 1
                self.line += 1
                self.line_start = self.i
                self.line_has_token = False
            elif ch in " \t\r":
                self.i += 1
            elif ch == "#":
                while self.i < len(src) and src[self.i] != "\n":
                    self.i += 1
            elif _is_word_start(ch):
                start = self.i
                while self.i < len(src) and _is_word_char(src[self.i]):
                    self.i += 1
                self._token(PolicyTokenKind.WORD, src[start : self.i], start)
            elif "0" <= ch <= "9":
                start = self.i
                while self.i < len(src) and "0" <= src[self.i] <= "9":
                    self.i += 1
                self._token(PolicyTokenKind.NUMBER, src[start : self.i], start)
            elif ch == '"':
                self._string()
            elif ch in _PUNCTUATION:
                self._token(_PUNCTUATION[ch], ch, self.i)
                self.i += 1
            elif ch in "=!<>":
                self._compare()
            else:
                self._error(PolicyDiag.UNEXPECTED_CHARACTER, f"unexpected character {ch!r}", self.i)
                self.i += 1
        self._token(PolicyTokenKind.EOF, "", len(src))
        return self.tokens, self.errors

    def _compare(self) -> None:
        start = self.i
        two = self.src[start : start + 2]
        if two in ("==", "!=", ">=", "<="):
            self.i += 2
            self._token(PolicyTokenKind.COMPARE, two, start)
        elif self.src[start] in "<>":
            self.i += 1
            self._token(PolicyTokenKind.COMPARE, self.src[start], start)
        else:
            self._error(PolicyDiag.UNEXPECTED_CHARACTER, f"unexpected character {self.src[start]!r}", start)
            self.i += 1

    def _string(self) -> None:
        start = self.i
        self.i += 1
        out: list[str] = []
        src = self.src
        while self.i < len(src):
            ch = src[self.i]
            if ch == '"':
                self.i += 1
                self._token(PolicyTokenKind.STRING, "".join(out), start)
                return
            if ch == "\n":
                break
            if ch == "\\":
                nxt = src[self.i + 1] if self.i + 1 < len(src) else ""
                if nxt in _ESCAPES and nxt:
                    out.append(_ESCAPES[nxt])
                    self.i += 2
                    continue
                self._error(PolicyDiag.BAD_ESCAPE, f"unknown escape {('\\' + nxt)!r} in a string", self.i)
                self.i += 2 if nxt and nxt != "\n" else 1
                continue
            out.append(ch)
            self.i += 1
        # Ran into a newline or the end of the file. The string is dropped, and lexing resumes on
        # the next line, so one missing quote costs one error rather than the rest of the file.
        self._error(PolicyDiag.UNTERMINATED_STRING, "string is not closed on the line it starts", start)

    def _token(self, kind: PolicyTokenKind, text: str, start: int) -> None:
        line, col = self._where(start)
        self.tokens.append(PolicyToken(kind, text, start, line, col, not self.line_has_token))
        self.line_has_token = True

    def _error(self, code: PolicyDiag, message: str, pos: int) -> None:
        line, col = self._where(pos)
        self.errors.append(PolicyError(code, message, pos, line, col))

    def _where(self, pos: int) -> tuple[int, int]:
        # Tokens and errors are always on the current line, except the EOF token after a newline.
        return self.line, pos - self.line_start + 1
