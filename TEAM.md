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

**Built:** the lexer (`compiler/lexer.py`, 50 tests), the token and word types (`compiler/syntax.py`), the accepted language (`compiler/grammar.md`), and the design documents in `docs/`.

**Start now, nothing blocks these:**

| Piece | Owner | Comes from |
|---|---|---|
| `compiler/types.py` — `Effect`, `EffectKind`, `Resolution`, `Zone`, `Verdict`, `Decision`, `SessionState` | Younes | `docs/policy-rules.md` §1–§4 and `docs/interfaces.md` §S3–S5 |
| `bench/schema.md` — the fields of one corpus entry | Younes | `docs/interfaces.md` §S7 |
| The knowledge table — the forty command heads | Younes | `docs/policy-rules.md` §2 |
| The AST node set, added to `compiler/syntax.py` | Youssef | `compiler/grammar.md` §3.1 |

`compiler/types.py` unblocks the most work of anything in the repo: five of the ten seams in `docs/interfaces.md` are declared in it.

**Blocked, do not start yet:**

- `compiler/resolve.py` and `compiler/effects.py` consume the AST, and the AST node set does not exist yet. Starting the resolver now means inventing node shapes that the parser will then contradict, and one of us throwing the work away. Wait for the node set to land in `compiler/syntax.py`.
- `compiler/policy.py` needs both `types.py` and a decision on the policy language's syntax.
- The classifier dataset (`classifier/`, piece 2b) needs `Decision` to exist, because the record it serialises carries the rule ids and effects that caused the rejection — see `docs/interfaces.md` §S6. This is later than the order of work below implies.

**Open questions that an agent must not answer on its own.** Four entries under "Open" in `docs/decisions.md` are decisions for the two of us, not defaults to be picked: who writes the policy DSL's front end, who converts sandbox observations into effects, the policy language's syntax, and what a rejection message tells the agent. If a task runs into one of these, stop and leave it to the humans rather than choosing and proceeding.

## Order of work

1. **Together first:** agree the supported subset, `compiler/types.py` and the policy language on paper before writing code.
2. **Build:** 1a and 1b in parallel against the agreed types; 2a and 3a can start against stubs; 3b starts the corpus early because everything is evaluated on it.
3. **Integrate:** gate wires the phases; run baselines and the full stack on the corpora.
4. **Evaluate and write:** record every result in `hypotheses.md` first, then draft the paper.

## Branches and merging

See [`CONTRIBUTING.md`](CONTRIBUTING.md).
