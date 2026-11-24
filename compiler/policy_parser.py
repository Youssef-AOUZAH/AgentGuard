"""Parser for the policy language, with error recovery, and the front end's entry point.

Takes in the text of a policy file. `parse_policy` returns a `PolicyResult`: a checked
`PolicyFile`, or every error found and no file. It never raises.

The grammar, also in `docs/policy-rules.md` §6:

    file       = "policy" STRING "{" { item } "}" EOF
    item       = zone_def | list_def | rule | expect
    zone_def   = "zone" ZONE string_list
    list_def   = ("hosts" | "paths" | "names") WORD string_list
    rule       = RULE_ID verdict subject [ "where" condition { "and" condition } ]
    verdict    = "allow" | "escalate" | "deny"
    subject    = "any" | "command" | KIND { "|" KIND }
    condition  = "zone" ("==" | "!=") ZONE
               | "zone" [ "not" ] "in" "[" ZONE { "," ZONE } "]"
               | "target" [ "not" ] ( "known" | "bounded" | "unknown" )
               | ( "target" | "host" | "variable" | "program" ) [ "not" ] "in" source
               | "statement" [ "not" ] "has" KIND [ "in" "zone" ZONE ]
               | [ "not" ] "repeats" "denied" ( "target" | "zone" )
               | [ "not" ] "background"
               | "substitution" "depth" COMPARE NUMBER
    source     = WORD | string_list
    string_list= "[" [ STRING { "," STRING } [ "," ] ] "]"
    expect     = "expect" verdict [ RULE_ID ] STRING [ "after" STRING { "," STRING } ]

A recursive-descent parser, one method per production, like the command parser. Unlike the
command parser it recovers: an error inside an item is recorded, and the parser skips to the next
token that starts an item at the beginning of a line (or to the closing brace), and goes on. This
is panic-mode recovery synchronising on items, decided in `docs/decisions.md` because a policy is
a file of many independent rules that a person edits, where reporting every mistake at once is
what the author needs, and nothing unsafe follows because a file with any error is not loaded.

After parsing, `compiler/policy_check.py` checks what the grammar cannot express (list names
exist, conditions suit their subject, and so on). Its errors are added to the parser's; the file
is returned only when there are none.
"""

from __future__ import annotations

from compiler.policy_check import check, make_pattern
from compiler.policy_lexer import PolicyToken, PolicyTokenKind, tokenize_policy
from compiler.policy_syntax import (
    AnyEffect,
    Background,
    CommandSubject,
    Compare,
    Condition,
    EffectSubject,
    Expect,
    HostIn,
    InlineList,
    ListDef,
    ListKind,
    ListRef,
    ListSource,
    PolicyDiag,
    PolicyError,
    PolicyFile,
    PolicyResult,
    ProgramIn,
    RepeatBy,
    RepeatsDenied,
    Rule,
    StatementHas,
    Subject,
    SubstitutionDepth,
    TargetIn,
    TargetIs,
    TargetState,
    VariableIn,
    ZoneDef,
    ZoneIs,
)
from compiler.types import EffectKind, RuleId, Verdict, Zone

T = PolicyTokenKind

# Effect kinds as the language spells them: the enum member name in lower case (`net_out`).
KINDS: dict[str, EffectKind] = {kind.name.lower(): kind for kind in EffectKind}
ZONES: dict[str, Zone] = {zone.value: zone for zone in Zone}
VERDICTS = {"allow": Verdict.ALLOW, "escalate": Verdict.ESCALATE, "deny": Verdict.DENY}
LIST_KINDS = {kind.value: kind for kind in ListKind}
ITEM_STARTERS = frozenset({"zone", "hosts", "paths", "names", "expect"})


def parse_policy(src: str) -> PolicyResult:
    """Lex, parse and check a policy file. Never raises; see `PolicyResult`."""
    tokens, errors = tokenize_policy(src)
    parser = _Parser(tokens, src)
    policy = parser.file()
    errors += parser.errors
    if policy is not None:
        errors += check(policy)
    errors.sort(key=lambda e: e.pos)
    if errors:
        return PolicyResult(None, tuple(errors))
    return PolicyResult(policy, ())


class _Recover(Exception):
    """Raised inside an item when it cannot be parsed; caught at item level."""


class _Parser:
    def __init__(self, tokens: list[PolicyToken], src: str) -> None:
        self.tokens = tokens
        self.src = src
        self.i = 0
        self.errors: list[PolicyError] = []

    # ------------------------------------------------------------------ token helpers

    @property
    def tok(self) -> PolicyToken:
        return self.tokens[self.i]

    def advance(self) -> PolicyToken:
        tok = self.tokens[self.i]
        if tok.kind is not T.EOF:
            self.i += 1
        return tok

    def is_word(self, *words: str) -> bool:
        return self.tok.kind is T.WORD and self.tok.text in words

    def error(self, code: PolicyDiag, message: str, tok: PolicyToken | None = None) -> _Recover:
        tok = tok or self.tok
        self.errors.append(PolicyError(code, message, tok.pos, tok.line, tok.col))
        return _Recover()

    def unexpected(self, wanted: str) -> _Recover:
        found = "the end of the file" if self.tok.kind is T.EOF else repr(self.tok.text)
        return self.error(PolicyDiag.UNEXPECTED_TOKEN, f"expected {wanted}, found {found}")

    def expect(self, kind: PolicyTokenKind, wanted: str) -> PolicyToken:
        if self.tok.kind is not kind:
            raise self.unexpected(wanted)
        return self.advance()

    def expect_word(self, word: str) -> PolicyToken:
        if not self.is_word(word):
            raise self.unexpected(f"'{word}'")
        return self.advance()

    def synchronise(self, item_start: int) -> None:
        """Skip to the next token that can start an item: a keyword or rule id first on its line,
        or the closing brace, or the end. Never stops on the token the failed item began at, so
        the loop always makes progress."""
        while self.tok.kind is not T.EOF:
            if self.i > item_start and self.tok.kind is T.RBRACE:
                return
            if self.i > item_start and self.tok.first_on_line and self._starts_item():
                return
            self.advance()

    def _starts_item(self) -> bool:
        return self.tok.kind is T.WORD and (
            self.tok.text in ITEM_STARTERS or _looks_like_rule_id(self.tok.text)
        )

    # ------------------------------------------------------------------ productions

    def file(self) -> PolicyFile | None:
        try:
            first = self.expect_word("policy")
            name = self.expect(T.STRING, "the policy's name in quotes").text
            self.expect(T.LBRACE, "'{'")
        except _Recover:
            return None
        zones: list[ZoneDef] = []
        lists: list[ListDef] = []
        rules: list[Rule] = []
        expects: list[Expect] = []
        while self.tok.kind not in (T.RBRACE, T.EOF):
            item_start = self.i
            try:
                if self.is_word("zone"):
                    zones.append(self.zone_def())
                elif self.is_word("hosts", "paths", "names"):
                    lists.append(self.list_def())
                elif self.is_word("expect"):
                    expects.append(self.expect_line())
                elif self.tok.kind is T.WORD and _looks_like_rule_id(self.tok.text):
                    rules.append(self.rule())
                else:
                    raise self.unexpected(
                        "a rule id such as R4, or 'zone', 'hosts', 'paths', 'names' or 'expect'"
                    )
            except _Recover:
                self.synchronise(item_start)
        if self.tok.kind is T.EOF:
            self.unexpected("'}' to close the policy")
            return None
        self.advance()
        if self.tok.kind is not T.EOF:
            self.unexpected("the end of the file after the policy's closing '}'")
        return PolicyFile(name, tuple(zones), tuple(lists), tuple(rules), tuple(expects), self.src, first.pos)

    def zone_def(self) -> ZoneDef:
        start = self.expect_word("zone")
        zone = self.zone_name()
        items = self.string_list()
        return ZoneDef(zone, tuple(make_pattern(text, pos) for text, pos in items), start.pos)

    def list_def(self) -> ListDef:
        start = self.advance()
        kind = LIST_KINDS[start.text]
        name = self.expect(T.WORD, "a name for the list").text
        items = self.string_list()
        if kind is ListKind.PATHS:
            return ListDef(kind, name, tuple(make_pattern(t, p) for t, p in items), start.pos)
        return ListDef(kind, name, tuple(t for t, _ in items), start.pos)

    def rule(self) -> Rule:
        start = self.advance()
        try:
            rule_id = RuleId(start.text)
        except ValueError:
            known = ", ".join(r.value for r in RuleId)
            raise self.error(
                PolicyDiag.UNKNOWN_RULE_ID, f"{start.text} is not a rule id; known: {known}", start
            ) from None
        verdict = self.verdict()
        subject = self.subject()
        conditions: list[Condition] = []
        if self.is_word("where"):
            self.advance()
            conditions.append(self.condition())
            while self.is_word("and"):
                self.advance()
                conditions.append(self.condition())
        return Rule(rule_id, verdict, subject, tuple(conditions), start.pos)

    def verdict(self) -> Verdict:
        if self.tok.kind is T.WORD and self.tok.text in VERDICTS:
            return VERDICTS[self.advance().text]
        raise self.unexpected("'allow', 'escalate' or 'deny'")

    def subject(self) -> Subject:
        if self.is_word("any"):
            return AnyEffect(self.advance().pos)
        if self.is_word("command"):
            return CommandSubject(self.advance().pos)
        start = self.tok
        kinds = {self.kind()}
        while self.tok.kind is T.PIPE:
            self.advance()
            kinds.add(self.kind())
        return EffectSubject(frozenset(kinds), start.pos)

    def kind(self) -> EffectKind:
        tok = self.tok
        if tok.kind is T.WORD and tok.text in KINDS:
            self.advance()
            return KINDS[tok.text]
        if tok.kind is T.WORD and not (tok.first_on_line and self._starts_item()):
            known = ", ".join(KINDS)
            raise self.error(PolicyDiag.UNKNOWN_KIND, f"{tok.text!r} is not an effect kind; known: {known}")
        raise self.unexpected("an effect kind, 'any' or 'command'")

    def zone_name(self) -> Zone:
        tok = self.tok
        if tok.kind is T.WORD and tok.text in ZONES:
            self.advance()
            return ZONES[tok.text]
        if tok.kind is T.WORD and not (tok.first_on_line and self._starts_item()):
            known = ", ".join(ZONES)
            raise self.error(PolicyDiag.UNKNOWN_ZONE, f"{tok.text!r} is not a zone; known: {known}")
        raise self.unexpected("a zone name")

    def negation(self) -> bool:
        if self.is_word("not"):
            self.advance()
            return True
        return False

    def condition(self) -> Condition:
        start = self.tok
        if self.is_word("zone"):
            return self.zone_condition()
        if self.is_word("target"):
            self.advance()
            negated = self.negation()
            if self.tok.kind is T.WORD and self.tok.text in ("known", "bounded", "unknown"):
                return TargetIs(TargetState(self.advance().text), negated, start.pos)
            self.expect_word("in")
            return TargetIn(self.source(paths=True), negated, start.pos)
        if self.is_word("host", "variable", "program"):
            word = self.advance().text
            negated = self.negation()
            self.expect_word("in")
            source = self.source(paths=False)
            cls = {"host": HostIn, "variable": VariableIn, "program": ProgramIn}[word]
            return cls(source, negated, start.pos)
        if self.is_word("statement"):
            self.advance()
            negated = self.negation()
            self.expect_word("has")
            kind = self.kind()
            zones = None
            if self.is_word("in"):
                self.advance()
                self.expect_word("zone")
                zones = frozenset({self.zone_name()})
            return StatementHas(kind, zones, negated, start.pos)
        if self.is_word("substitution"):
            self.advance()
            self.expect_word("depth")
            op = Compare(self.expect(T.COMPARE, "a comparison such as '>'").text)
            number = self.expect(T.NUMBER, "a number")
            if len(number.text) > 6:
                raise self.error(PolicyDiag.BAD_NUMBER, "substitution depth must be a small number", number)
            return SubstitutionDepth(op, int(number.text), False, start.pos)
        negated = self.negation()
        if self.is_word("repeats"):
            self.advance()
            self.expect_word("denied")
            if self.tok.kind is T.WORD and self.tok.text in ("target", "zone"):
                return RepeatsDenied(RepeatBy(self.advance().text), negated, start.pos)
            raise self.unexpected("'target' or 'zone'")
        if self.is_word("background"):
            self.advance()
            return Background(negated, start.pos)
        raise self.unexpected("a condition")

    def zone_condition(self) -> ZoneIs:
        start = self.advance()
        if self.tok.kind is T.COMPARE and self.tok.text in ("==", "!="):
            negated = self.advance().text == "!="
            return ZoneIs(frozenset({self.zone_name()}), negated, start.pos)
        negated = self.negation()
        self.expect_word("in")
        self.expect(T.LBRACKET, "'['")
        zones = {self.zone_name()}
        while self.tok.kind is T.COMMA:
            self.advance()
            if self.tok.kind is T.RBRACKET:
                break
            zones.add(self.zone_name())
        self.expect(T.RBRACKET, "']'")
        return ZoneIs(frozenset(zones), negated, start.pos)

    def source(self, *, paths: bool) -> ListSource:
        if self.tok.kind is T.WORD:
            tok = self.advance()
            return ListRef(tok.text, tok.pos)
        start = self.tok
        items = self.string_list()
        if paths:
            return InlineList(tuple(make_pattern(t, p) for t, p in items), start.pos)
        return InlineList(tuple(t for t, _ in items), start.pos)

    def string_list(self) -> list[tuple[str, int]]:
        self.expect(T.LBRACKET, "'['")
        items: list[tuple[str, int]] = []
        while self.tok.kind is not T.RBRACKET:
            tok = self.expect(T.STRING, "a string in quotes, or ']'")
            items.append((tok.text, tok.pos))
            if self.tok.kind is T.COMMA:
                self.advance()
            elif self.tok.kind is not T.RBRACKET:
                raise self.unexpected("',' or ']'")
        self.advance()
        return items

    def expect_line(self) -> Expect:
        start = self.expect_word("expect")
        verdict = self.verdict()
        rule = None
        if self.tok.kind is T.WORD and _looks_like_rule_id(self.tok.text) and not self.tok.first_on_line:
            tok = self.advance()
            try:
                rule = RuleId(tok.text)
            except ValueError:
                raise self.error(PolicyDiag.UNKNOWN_RULE_ID, f"{tok.text} is not a rule id", tok) from None
        command = self.expect(T.STRING, "the command to test, in quotes").text
        after: list[str] = []
        if self.is_word("after"):
            self.advance()
            after.append(self.expect(T.STRING, "a command in quotes").text)
            while self.tok.kind is T.COMMA:
                self.advance()
                after.append(self.expect(T.STRING, "a command in quotes").text)
        return Expect(verdict, rule, command, tuple(after), start.pos)


def _looks_like_rule_id(text: str) -> bool:
    return len(text) >= 2 and text[0] == "R" and text[1:].isascii() and text[1:].isdigit()
