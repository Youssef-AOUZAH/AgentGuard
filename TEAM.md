# Division of work

Two members: **Youssef Aouzah** and **Younes Menfalouti**. The project has three areas: the compiler, the classifier, and the gate with evaluation. Each area is split into two pieces, and each member owns exactly one piece per area, so both of us touch every part of the system and neither is stuck with only one kind of work.

| Area | Youssef owns | Younes owns |
|---|---|---|
| Compiler (`compiler/`) | 1a. Front end: lexer, parser, grammar | 1b. Middle end: resolver, effect analysis, policy engine |
| Classifier (`classifier/`) | 2a. NLI pipeline, thresholds, calibration | 2b. Label taxonomy and the (rejected, next command) dataset |
| Gate and evaluation (`gate/`, `bench/`) | 3a. Gate and sandboxed executor | 3b. Bypass corpus, baselines, agent experiments, metrics |

Owning a piece means you write its code, its tests and its entries in the area's `hypotheses.md`, and you draft its methods and results in the paper.

## How we both stay on top of everything

- **Cross review.** Every pull request is reviewed by the other member. The reviewer must be able to explain the change; if they cannot, the code needs a clearer docstring or a simpler design.
- **Swap and explain.** At the end of each phase, each member walks the other through their piece (parser, effect analysis, classifier, gate). The listener writes down anything unclear in `docs/`.
- **Shared contract.** [`docs/interfaces.md`](docs/interfaces.md) specifies all ten points where our pieces meet: what crosses each one, which file declares it, who may change it, and where to find it. `compiler/syntax.py` (front-end types) and `compiler/types.py` (effects, verdicts, session state) are the two files those contracts live in. We decide changes to either together and update all consumers in the same PR.
- **Pairing on the hard parts.** Resolver edge cases, the policy language and the experiment design are done together, not alone.

## Area 1: Compiler

- **1a. Front end (Youssef).** Four deliverables. (i) The **lexer** for the bash subset in `compiler/grammar.md`: quoting and escapes, token recognition, here-documents, the bash-only operators. *Done.* (ii) The **AST node set** in `compiler/syntax.py`, which is the seam the resolver consumes, so it is agreed with Younes before the parser is written. (iii) The **parser**: simple commands, pipelines, lists (`&&`, `||`, `;`), redirections, subshells, assignments, the POSIX parser-lexer interaction rules, and a named diagnostic for every construct the grammar rejects. (iv) The **canonical emitter** in `compiler/emit.py`, which re-serialises the AST into the command the gate actually executes. Compare against `bash -n` and the argv oracle in tests.
Also Youssef's, decided 23 November 2026: the **policy language's lexer and parser**, producing the policy AST in `compiler/policy_syntax.py`. Younes writes the evaluator (`compiler/policy.py`) against it, and the language is designed together. See `docs/decisions.md`.

- **1b. Middle end (Younes).** Resolve words the way bash would (quote removal, escapes, known variables, `$'...'`, brace expansion where static), mark dynamic parts UNRESOLVED, then compute effects per command with a knowledge table of common tools, and evaluate the declarative policy in `policies/`.

## Area 2: Classifier

- **2a. NLI pipeline (Youssef).** Wrap an open-source zero-shot NLI model behind a small interface that returns a probability per label, with a stub implementation for tests. Choose thresholds on a development split only; report calibration.
- **2b. Taxonomy and dataset (Younes).** Define the labels ("retries a blocked effect", "benign next step", "obfuscation", and so on) and build the dataset of rejected command followed by the agent's next command, from corpus data and recorded agent runs. Keep a held-out test split that nobody tunes on.

## Area 3: Gate and evaluation

- **3a. Gate and executor (Youssef).** Pipeline runner, session history, the message returned to the agent, and a sandboxed executor (disposable container or temporary directory). Measures latency.
- **3b. Corpus, baselines, experiments (Younes).** Bypass corpus (quoting tricks, encoding, alternative tools, multi-step workarounds), benign developer task corpus, string denylist baselines, and the agent experiments that measure workaround success and false rejections.

## Shared work

| Piece | Owner |
|---|---|
| Repo template and CI | Youssef |
| `compiler/types.py`, `compiler/grammar.md` and `docs/` decision notes | Younes |
| Paper: introduction, related work | Youssef |
| Paper: design, evaluation, discussion | Younes |
| Presentation | Both, one area section each, then swap |

## Where we are, and what to pick up next

Read this before starting work, human or agent. It is the one place that says what is built and what is blocked, and it is kept current.

**Built:** the lexer (`compiler/lexer.py`), the parser (`compiler/parser.py`) and the canonical emitter (`compiler/emit.py`), with a differential test against `bash -n` and an argv oracle comparing emitted words with what bash really passes; the token types and the AST node set (`compiler/syntax.py`); the accepted language (`compiler/grammar.md`); and the design documents in `docs/`.

Also built, by Youssef:

- **The gate (3a)** in `gate/`: `gate.py` runs the stages in order and refuses on any failure; `executor.py` runs the emitted command in a throwaway directory and maps what changed into `Effect` records (S8), and `container.py` does the same inside a Docker container with no network, as an unprivileged user, killing anything left running after each command — **use the container for the bypass corpus and agent experiments**, and `put_file` to seed canaries; `session.py` updates `SessionState` from what really happened; `message.py` writes the refusal at one of three levels for gate H1. The middle end plugs in through the `Analyzer` interface in `gate/types.py`. Until `resolve.py`, `effects.py` and `policy.py` exist, the gate uses `PendingMiddleEnd`, which escalates everything, so nothing runs unapproved.
- **The NLI pipeline (2a)** in `classifier/`: `pipeline.py` (a stub scorer for tests, the zero-shot NLI scorer, thresholds per label) and `calibrate.py` (threshold choice on the development split, ECE, Brier score, reliability bins). `classifier/labels.py` declares the S6 records; its label set is Younes's: five labels describing what an agent does after a refusal, explained in its docstring.
- **The policy language front end (1a)**: `compiler/policy_lexer.py`, `compiler/policy_parser.py` (with error recovery: every mistake in one run) and `compiler/policy_check.py`, producing the tree declared in `compiler/policy_syntax.py`; the language is described in `docs/policy-rules.md` §6, and `policies/default.pol` is the shipped policy with its own `expect` tests.
- **The paper's introduction and related work** in `paper/` (`latexmk -pdf main.tex`). Every claim taken from a paper not yet read in the original carries a red `\checkcite` marker.

**Start now, nothing blocks these:**

| Piece | Owner | Comes from |
|---|---|---|
| Address the three follow-ups from the review of `compiler/types.py` (PR #3, now merged) | Younes | the review comments on PR #3 |
| `bench/schema.md` — the fields of one corpus entry | Younes | `docs/interfaces.md` §S7 |
| The knowledge table — the forty command heads | Younes | `docs/policy-rules.md` §2 |
| `compiler/resolve.py` and `compiler/effects.py` — the parser hands over a `Script`; read the docstrings in `compiler/syntax.py` first | Younes | `docs/interfaces.md` §S2–S4, `docs/policy-rules.md` §1–§2, and the two parser findings at the top of "Open" in `docs/decisions.md`, which this code must handle |
| `compiler/policy.py` — the evaluator, `evaluate(policy, script, effects, state) -> Decision`, against the tree `parse_policy` returns; also add a gate root to `SessionState` for `{gate}` | Younes | `compiler/policy_syntax.py` (what the front end guarantees is in its docstring), `docs/policy-rules.md` §5–§7, and "Five details of the policy language" in `docs/decisions.md` (zone order, bounded targets, unknown targets, R9, who runs the tests) |
| The policy loader on the gate's side: parse a `.pol` file and run its `expect` tests through the pipeline and the session updates, refusing a policy that fails one | Youssef, once `policy.py` exists | `docs/decisions.md`, "Five details of the policy language" |
| Wire the middle end into the gate — an `Analyzer` (`gate/types.py`) that calls `resolve`, `effects_of` and `decide` | Younes, once those exist | `gate/gate.py` docstring; `PendingMiddleEnd` is what it replaces |

`compiler/types.py` is in: five of the ten seams in `docs/interfaces.md` are declared in it, and the gate and the classifier already build on it.

**Blocked, do not start yet:**

- The classifier dataset (`classifier/`, piece 2b) can now be serialised, since `Decision` and `ClassifierInput` exist, but its *contents* need real refusals: the rule ids and effects in each record come from the policy engine, so the dataset waits for `compiler/policy.py`. See `docs/interfaces.md` §S6.

**Decided on 23 November 2026, by Youssef.** The four questions that were open are now under "Decided" in `docs/decisions.md`: a refused command tells the agent only "Command refused based on user rules.", with no rule, effect or reason; the executor (Youssef) turns sandbox observations into effects; Youssef writes the policy language's lexer and parser and Younes its evaluator; and the policy language is our own order-free DSL whose rules cite rule ids and carry their own tests. Younes: if you disagree with any of them, raise it in an issue rather than coding around it.

**Open questions that an agent must not answer on its own** are the entries still under "Open" in `docs/decisions.md`. If a task runs into one, stop and leave it to the humans rather than choosing and proceeding.

One smaller item is owed to Younes's code by the gate: `RULE_NAMES` in `gate/message.py` needs R11 once PR #4 is merged. The zone in `Reason` (issue #5) is no longer needed for messages, since refusals no longer name anything.

## Order of work

1. **Together first:** agree the supported subset, `compiler/types.py` and the policy language on paper before writing code.
2. **Build:** 1a and 1b in parallel against the agreed types; 2a and 3a can start against stubs; 3b starts the corpus early because everything is evaluated on it.
3. **Integrate:** gate wires the phases; run baselines and the full stack on the corpora.
4. **Evaluate and write:** record every result in `hypotheses.md` first, then draft the paper.

## Branches and merging

See [`CONTRIBUTING.md`](CONTRIBUTING.md).
