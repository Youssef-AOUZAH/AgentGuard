# Where our pieces meet

`TEAM.md` says who owns what. This file says how the owned pieces connect: for every point where one member's code hands something to the other member's code, what the thing is, which file declares it, who may change that declaration, and what goes wrong if we get it wrong.

The purpose is that neither of us has to read the other's implementation to use it. If you find yourself opening the other person's module to work out what it returns, that is a bug in this document, and fixing this document is the right response.

Two conventions throughout.

**A seam is a type, not a function.** Each handoff below is named by the data structure that crosses it. Functions can be renamed and rewritten freely; the data structure is the promise. Changing a seam type means a pull request that updates the type and every consumer together, reviewed by the other member, as `AGENTS.md` already requires.

**Nothing crosses a seam unless it is declared in a shared file.** `compiler/syntax.py` and `compiler/types.py` are the two shared files. If a piece needs to pass something that is not declared in one of them, that is the signal to stop and agree the type first, not to pass a dict.

## 0. Summary

| # | What crosses | From | To | Declared in |
|---|---|---|---|---|
| S1 | `list[Token]` | lexer (Y-sef, 1a) | parser (Y-sef, 1a) | `compiler/syntax.py` |
| S2 | AST (`Command`, `Pipeline`, `AndOr`, `Redirect`, …) | parser (Y-sef, 1a) | resolver (Y-nes, 1b) | `compiler/syntax.py` |
| S3 | `SessionState` | gate (Y-sef, 3a) | resolver + policy (Y-nes, 1b) | `compiler/types.py` |
| S4 | `set[Effect]` | effects (Y-nes, 1b) | policy (Y-nes, 1b), gate, bench | `compiler/types.py` |
| S5 | `Decision` (verdict + cited reasons) | policy (Y-nes, 1b) | gate (Y-sef, 3a) | `compiler/types.py` |
| S6 | `ClassifierInput` / `LabelScores` | gate (Y-sef, 3a) ↔ NLI (Y-sef, 2a) | labels by Y-nes (2b) | `classifier/labels.py` |
| S7 | corpus record (JSONL) | corpus (Y-nes, 3b) | compiler tests (Y-sef), bench harness | `bench/schema.md` |
| S8 | `ExecResult` with observed effects | executor (Y-sef, 3a) | metrics (Y-nes, 3b) | `gate/types.py` |
| S9 | policy file text | us both, on paper | policy parser (open: see S9) | `policies/*.pol` |
| S10 | `run_id` and recorded numbers | whoever ran it | the paper | each area's `hypotheses.md` |

Read your own row and the two rows either side of it. Nobody needs all ten in their head at once.

## S1. Tokens — lexer to parser

Both halves are Youssef's, so this is not a cross-member seam, but it is the one seam that already exists in code and it sets the pattern for the rest.

- **Produced by** `tokenize(src: str) -> list[Token]` in `compiler/lexer.py`.
- **Declared in** `compiler/syntax.py`: `Token`, `TokenKind`, `Word`, `WordPart`, `PartKind`, `Diag`, `LexError`.
- **Shape.** A `Token` carries its `kind`, its `raw` text, its `pos` in the input, and, for a word token, a `Word`. A `Word` is a tuple of `WordPart`s, each tagged with how it was written — literal, single-quoted, `$'…'`, parameter expansion, command substitution, glob, and so on. `Word.value` is the resolved string **or `None`**, and `Word.is_known` says which. `Token.assignment_name` is a hint, not a conclusion: the parser decides whether a word in that position really is an assignment.
- **Errors.** `tokenize` raises `LexError` and nothing else. That is enforced by a Hypothesis property test, and the gate's fail-closed behaviour depends on it: one `LexError` means `DENY` with a diagnostic code, whereas an unexpected `TypeError` escaping would mean an exception path nobody wrote a verdict for.
- **Pitfall.** Do not read `Word.value` without checking `is_known`. `None` means we could not determine the value, and treating `None` as an empty string is exactly the bypass this design exists to prevent.

## S2. The AST — parser to resolver

This is the first real cross-member seam, and the most important one, because it is where Youssef's half of the compiler ends and Younes's begins.

- **Produced by** `parse(tokens: list[Token], src: str) -> Script` in `compiler/parser.py` (Youssef), or `parse_source(src)` for both steps at once.
- **Consumed by** `resolve(script, state)` in `compiler/resolve.py` (Younes, not yet written).
- **Declared in** `compiler/syntax.py`, alongside the token types.
- **Shape.** The node set follows the POSIX productions in `compiler/grammar.md` §4 rather than being invented: `Script`, `AndOr` (a list of `Pipeline`s joined by `&&`/`||`), `Pipeline` (a list of `Command`s), `SimpleCommand` (assignments, words, redirections), `Subshell`, `BraceGroup`, `Redirect`, and the compound forms the grammar accepts. Every node keeps the `pos` of the token it started at, so a verdict can point at the characters that caused it.
- **Who may change it.** Youssef writes it, because it is the output of his parser, but Younes must approve any change, because he is the only consumer. In practice the reviewer of that PR is the person the change inconveniences, which is the right incentive.
- **Pitfall, and the thing to settle first.** The AST contains `Word`s with unknown parts. The resolver's job is to turn those into values where it can and to mark them unresolved where it cannot — it is **not** the parser's job to refuse an unknown word. The parser refuses what the grammar does not derive; the resolver refuses what it cannot determine. If those two responsibilities blur, we will end up with two places that deny things and no way to say which rule fired.

### A correction to the layout AGENTS.md documents

`AGENTS.md` says the shared types including AST nodes live in `compiler/types.py`. That is no longer what we want, and the split that has emerged in the code is better:

- **`compiler/syntax.py`** holds everything the front end *produces*: tokens, words, word parts, AST nodes, diagnostics. Youssef writes it; Younes reviews changes.
- **`compiler/types.py`** holds everything the middle end produces and the gate consumes: `Effect`, `EffectKind`, `Resolution`, `Zone`, `Verdict`, `Decision`, `SessionState`. Younes writes it; Youssef reviews changes.

The reason is practical: a single shared file makes every change to either half a change to the other half's file, so both of us would be editing it constantly and the "reviewed by the other member" rule would become noise. Two files, each with one author and one reviewer, keeps the rule meaningful. `compiler/types.py` does not exist yet; the sections below specify exactly what belongs in it.

## S3. Session state — gate to resolver

The seam that makes us different from the stateless prior work, and the only one where data flows backwards from a later phase to an earlier one.

- **Owned and mutated by** the gate (`gate/session.py`, Youssef).
- **Read by** the resolver and the policy engine (Younes).
- **Declared in** `compiler/types.py`.
- **Shape.** Three fields, all described in `docs/policy-rules.md` §4: `cwd` (a `Path`, used to resolve every relative path), `variables` (a mapping from name to a resolved value, where a variable assigned from anything unresolved is recorded as permanently unresolved and never guessed), and `denied` (the history of refused effects, which is what the classifier compares against). Alongside them, three roots fixed for the session: `home`, `workspace`, and `gate_root`, the directory holding the gate's own code, policies and logs. The policy binds a file's `~`, `{workspace}` and `{gate}` anchors to these. `gate_root` is required, because without it R8's `{gate}` patterns would match nothing and self-protection would switch off silently.
- **The mutation rule, which matters more than the shape.** The gate is the only writer. The resolver receives a read-only view and must not mutate it, because a resolver that updates `cwd` would apply a `cd` the policy is about to deny. Order is fixed: resolve against the current state, compute effects, decide, and only then, if the verdict is `ALLOW` and the command actually ran, does the gate fold the new effects into the state.
- **How the gate does it.** `gate/session.py`. The working directory after a command is the one the shell itself reported, not a prediction. Variables change only from bare assignments that certainly ran in the current shell, and any `ENV_MUTATE` effect makes the variable it names `Unknown` — so `read`, `unset` and `${x:=v}` need only be reported as `ENV_MUTATE` by the effect analysis. The executor passes exactly the known variables to the next command's environment, so the state is what bash really sees, not a guess about a long-lived shell. One consequence for the resolver: if the session tracks `HOME`, bash's tilde follows that value, not `state.home`.
- **Pitfall.** `variables` holds only values assigned from statically known words. There is no inheritance from the real environment: if we seeded it from `os.environ` the compiler's analysis would depend on the developer's machine, and a test that passes for Youssef would fail for Younes.

## S4. Effects — the middle end's output

- **Produced by** `effects_of(resolved_script, state) -> set[Effect]` in `compiler/effects.py` (Younes).
- **Consumed by** the policy engine (Younes), the gate's message to the agent (Youssef), and the bench metrics (Younes).
- **Declared in** `compiler/types.py`.
- **Shape.** `Effect(kind, target, resolution, origin)`, with the fourteen kinds, the target types and the resolution values all listed in `docs/policy-rules.md` §1. `origin` is the AST node, which is how a verdict points at a character range — so an `Effect` is only as useful as the `pos` fields the parser filled in, which is a dependency of S2 on this seam that is easy to forget.
- **Pitfall.** Zones are computed against session state, not against the raw text, so an `Effect`'s target is an absolute path, an absolute directory bounding a set of them, or `UNKNOWN` with a reason. A relative path must never survive into an `Effect`: if the resolver cannot make it absolute it is `UNKNOWN`, and a bounded target's `dir` is absolute too. The zone of a `BOUNDED` target is the join over its whole subtree, which is the one place this seam is easy to implement wrongly and safely-looking — see `docs/policy-rules.md` §2.

## S5. The decision — policy to gate

- **Produced by** `evaluate(policy, script, effects, state) -> Decision` in `compiler/policy.py` (Younes). It takes the `Script` as well as the effects, because `statement has` must know which statement each effect came from, and `Effect.origin` is a node inside the script. It only evaluates: running a policy's `expect` tests is the gate's job (Youssef), since it needs the gate's session updates between commands.
- **Consumed by** the gate (Youssef), which turns it into a message for the agent and an execution or a refusal.
- **Declared in** `compiler/types.py`.
- **Shape.** `Decision(verdict, reasons)` where `verdict` is one of `ALLOW`, `ESCALATE`, `DENY` and `reasons` is a tuple of `(rule_id, effect)` pairs — the rule ids being the `R1`–`R11` of `docs/policy-rules.md` §5, so that a verdict cites a documented rule and a regression test can assert the rule id rather than just the verdict. A test that only checks `DENY` will pass for the wrong reason sooner or later.
- **The lattice is the contract.** `ALLOW < ESCALATE < DENY`, and no stage may lower a verdict. The gate may raise what the policy returned; it may never soften it. `ABSTAIN`, if the policy engine uses it internally, must not cross this seam: the policy converts total abstention to `ESCALATE` before returning, so the gate never has to know what abstention means.
- **Pitfall.** `ESCALATE` with no human available is `DENY`, and that conversion belongs to the gate, not the policy. The policy does not know whether anyone is watching.

## S6. Classifier — labels, input records, scores

Three pieces by two people, which makes this the seam most likely to go wrong quietly.

- **The label set** is Younes's (2b) and is the actual contract. It lives in `classifier/labels.py` as the `LABELS` tuple of `LabelSpec`s, with, for each label, the natural-language hypothesis template the NLI model is given. Everything else keys off it. **Set (28 November 2026):** five labels, each describing what an agent does after a refusal: `retry-blocked-effect`, `obfuscation`, `indirect-execution` (experimental, outside the classifier's one claim) and `boundary-probe` raise to `ESCALATE` (never `DENY`, since a zero-shot model has no adversarial robustness), and `benign-next-step` raises nothing. They are independent (`EXCLUSIVE = False`); a dataset line carries the one *primary* label, and each label is evaluated one-versus-rest. The reasoning is in the `classifier/labels.py` docstring.
- **The pipeline** is Youssef's (2a): `score(input: ClassifierInput) -> LabelScores`, returning a probability per label, with a stub implementation that returns fixed scores for tests. CI never downloads a model.
- **The dataset** is Younes's (2b) and must serialize *exactly* `ClassifierInput`, one JSON object per line, plus a `label` field drawn from the same enum. One shape, two uses: live input and training record. If the dataset invents its own field names, every experiment needs a conversion script and the conversion script becomes the bug.
- **Shape of `ClassifierInput`.** The rejected command, the rule ids and effects that rejected it, the new command, and the elapsed turns between them. Note what this means: the classifier sees the *compiler's output*, not just two strings, which is hypothesis classifier-H2. So S6 depends on S5, and the dataset cannot be built until `Decision` exists — which is a scheduling fact worth knowing now rather than in week ten.
- **As built.** `ClassifierInput` holds text only — `rejected_command`, `rejected_rules`, `rejected_effects` (each effect described by `describe_effect`), `new_command`, `turns_since` — with `to_json` and `from_json`, so a dataset line is `to_json()` plus a `label` field. `input_for(denied_entry, new_command, turn)` builds one from the session history. `LabelScores` maps label names to probabilities. Each `LabelSpec` names the verdict the gate raises a command to when that label fires, and the gate cites R9 for it.
- **Pitfall.** Whether the labels are mutually exclusive (softmax) or independent (per-label sigmoid) changes what a probability means and therefore how thresholds are chosen. It is a property of the label set, so it is Younes's call, and it must be written in `classifier/labels.py` as a comment, not assumed by the pipeline.

## S7. Corpus records — corpus to everyone's tests

- **Produced by** Younes (3b) as JSONL under `bench/corpus/`.
- **Consumed by** the bench harness (Younes), and by Youssef's regression tests when a bypass needs a test in `compiler/tests/`.
- **Declared in** `bench/schema.md`, with the field list and one worked example.
- **Shape.** Per entry: `id`, `command`, `technique` (quoting, encoding, alternative tool, multi-step), `expected_verdict` using the `Verdict` names from `compiler/types.py`, `provenance` (MITRE technique id, GTFOBins page, RedCode entry, or "ours"), and `notes`. Multi-step entries carry a list of commands rather than one, because a workaround across a rejection is the case we actually care about.
- **Rules that are already in `AGENTS.md`** and bear repeating here: corpus entries are declarative data, never runnable scripts, and they are generic shell technique rather than a working attack on a named product.
- **Pitfall.** `expected_verdict` is our *intent*, not our current behaviour. An entry whose expected verdict we do not yet achieve is a valuable record, not a broken test — so the harness must distinguish "expected to pass" from "known gap", or we will be tempted to weaken the expectation to make the suite green, which `AGENTS.md` forbids.

## S8. Execution results — executor to metrics

The seam nobody thinks about until the metric cannot be computed.

- **Produced by** the sandboxed executor (`gate/executor.py`, Youssef): `ExecResult(exit_code, stdout, stderr, observed)`.
- **Consumed by** the bench metrics (Younes), to compute the headline number — workaround success rate, meaning a forbidden effect happened anyway.
- **Declared in** `gate/types.py`.
- **The hard part.** That metric compares what the compiler *predicted* with what the sandbox *observed*, so `observed` must be comparable to `set[Effect]`. Filesystem observation yields paths that were created, written or removed; it does not yield our effect kinds. Either the executor maps its observations into `Effect` records, or the metrics code does, and we must decide which, because if both assume the other did it the number is uncomputable. **Proposal: the executor maps.** It is the only piece that knows how the sandbox reports changes, and the metrics code should work on `Effect` sets at both ends so the comparison is one line. Decided, and built this way in `gate/executor.py` (`docs/decisions.md`): `ExecResult(exit_code, stdout, stderr, observed, cwd, duration, timed_out, truncated)`, with the kinds it can observe in `gate.types.OBSERVABLE_KINDS`. Two backends produce it the same way: `TempDirExecutor` on the host and `ContainerExecutor` (`gate/container.py`) in Docker; the bench should use the container, where execute bits, and so `PRIV_CHANGE`, are observable even from a Windows host.
- **Pitfall.** Not every forbidden effect is observable from the filesystem. A `NET_OUT` needs the sandbox's network log; a `READ` leaves no trace at all. So the metric is defined over the observable subset, and the paper has to say so rather than implying full coverage.

## S9. The policy language

`docs/policy-rules.md` §6 sketches a small DSL, and `docs/decisions.md` records that we prefer writing our own over reading YAML because it is a second small compiler and good coursework.

**Decided (23 November 2026):** Youssef writes its lexer and parser, producing a policy AST declared in `compiler/policy_syntax.py`; Younes writes the evaluator in `compiler/policy.py` against that AST. The language's shape — no rule order, rule ids on every line, one construct for combinations within a statement, no machine-specific paths, tests inside the file — is recorded in `docs/decisions.md`. The file extension and location are `policies/*.pol`. Built: `parse_policy(src) -> PolicyResult` in `compiler/policy_parser.py` returns a checked `PolicyFile` (declared in `compiler/policy_syntax.py`) or every error with its line and column; the language and its grammar are in `docs/policy-rules.md` §6.

## S10. Results to the paper

- **Produced by** whoever ran the experiment, as an entry in that area's `hypotheses.md` using the template at the bottom of `AGENTS.md`, with a `run_id`.
- **Consumed by** the paper, where the rule from `AGENTS.md` applies without exception: no number appears in the paper that does not carry a `run_id` from a recorded run. If you did not run it, the paper says so.
- **Pitfall.** The person who drafts a section is not always the person who ran the experiment it reports, which is the normal way a wrong number gets into a paper. The cross-review rule covers it: the reviewer of a paper section checks each number against its `hypotheses.md` entry.

## What to do with this

Three things are specified here that do not exist yet, and they are the critical path:

1. **`compiler/types.py`** — `Effect`, `EffectKind`, `Resolution`, `Zone`, `Verdict`, `Decision`, `SessionState`. Younes's, and it blocks S3, S4, S5, S6 and S7. It is an afternoon's work from `docs/policy-rules.md` plus this file, and almost everything else waits on it.
2. **The AST node set in `compiler/syntax.py`** — Youssef's, blocks S2, and the parser cannot start without it.
3. **`bench/schema.md`** — Younes's, blocks S7, and the corpus should start early because everything is evaluated on it.

The two layout changes this file proposes — the `syntax.py`/`types.py` split in S2, and the executor mapping observations to effects in S8 — are proposals, not decisions. Both need Younes's agreement and an entry in `docs/decisions.md` before anyone writes code against them.
