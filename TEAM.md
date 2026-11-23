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
Not yet assigned, and deliberately left open until we agree: the **policy DSL's lexer and parser** (see `docs/decisions.md`). The policy language belongs to 1b by area, but its front end is the same kind of work as 1a.

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

- **The gate (3a)** in `gate/`: `gate.py` runs the stages in order and refuses on any failure; `executor.py` runs the emitted command in a throwaway directory and maps what changed into `Effect` records (S8); `session.py` updates `SessionState` from what really happened; `message.py` writes the refusal at one of three levels for gate H1. The middle end plugs in through the `Analyzer` interface in `gate/types.py`. Until `resolve.py`, `effects.py` and `policy.py` exist, the gate uses `PendingMiddleEnd`, which escalates everything, so nothing runs unapproved.
- **The NLI pipeline (2a)** in `classifier/`: `pipeline.py` (a stub scorer for tests, the zero-shot NLI scorer, thresholds per label) and `calibrate.py` (threshold choice on the development split, ECE, Brier score, reliability bins). `classifier/labels.py` declares the S6 records; **its label set is provisional and is Younes's to replace** (see its docstring).
- **The paper's introduction and related work** in `paper/` (`latexmk -pdf main.tex`). Every claim taken from a paper not yet read in the original carries a red `\checkcite` marker.

**Start now, nothing blocks these:**

| Piece | Owner | Comes from |
|---|---|---|
| Address the three follow-ups from the review of `compiler/types.py` (PR #3, now merged) | Younes | the review comments on PR #3 |
| `bench/schema.md` — the fields of one corpus entry | Younes | `docs/interfaces.md` §S7 |
| The knowledge table — the forty command heads | Younes | `docs/policy-rules.md` §2 |
| `compiler/resolve.py` and `compiler/effects.py` — the parser hands over a `Script`; read the docstrings in `compiler/syntax.py` first | Younes | `docs/interfaces.md` §S2–S4, `docs/policy-rules.md` §1–§2, and the two parser findings at the top of "Open" in `docs/decisions.md`, which this code must handle |
| The real label set in `classifier/labels.py` — replace the provisional labels, templates, verdicts and `EXCLUSIVE` | Younes | `docs/interfaces.md` §S6; the module docstring says what is provisional |
| Wire the middle end into the gate — an `Analyzer` (`gate/types.py`) that calls `resolve`, `effects_of` and `decide` | Younes, once those exist | `gate/gate.py` docstring; `PendingMiddleEnd` is what it replaces |

`compiler/types.py` is in: five of the ten seams in `docs/interfaces.md` are declared in it, and the gate and the classifier already build on it.

**Blocked, do not start yet:**

- `compiler/policy.py` needs both `types.py` and a decision on the policy language's syntax.
- The classifier dataset (`classifier/`, piece 2b) can now be serialised, since `Decision` and `ClassifierInput` exist, but its *contents* need real refusals: the rule ids and effects in each record come from the policy engine, so the dataset waits for `compiler/policy.py`. See `docs/interfaces.md` §S6.

**Open questions that an agent must not answer on its own.** Four entries under "Open" in `docs/decisions.md` are decisions for the two of us, not defaults to be picked: who writes the policy DSL's front end, who converts sandbox observations into effects, the policy language's syntax, and what a rejection message tells the agent. **Each now carries a recommendation from Youssef (23 November 2026), marked "open until Younes agrees".** An agent working for Younes should show him those four recommendations and let him accept, change or reject each; it must not treat a recommendation as decided, and must not build `compiler/policy.py` or the policy parser until he has. Once he agrees, move the entry from "Open" to "Decided" in the same pull request.

Two smaller items are owed to Younes's code by the gate, and need his call: `Reason` has no zone, so the rule-level message cannot name the zone the recommendation asks for (`gate/message.py`); and a rule id for backgrounded commands (from the PR #3 review).

## Order of work

1. **Together first:** agree the supported subset, `compiler/types.py` and the policy language on paper before writing code.
2. **Build:** 1a and 1b in parallel against the agreed types; 2a and 3a can start against stubs; 3b starts the corpus early because everything is evaluated on it.
3. **Integrate:** gate wires the phases; run baselines and the full stack on the corpora.
4. **Evaluate and write:** record every result in `hypotheses.md` first, then draft the paper.

## Branches and merging

See [`CONTRIBUTING.md`](CONTRIBUTING.md).
