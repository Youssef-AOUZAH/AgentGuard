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
- **Shared contract.** `compiler/types.py` (tokens, AST nodes, `Effect`, `Verdict`) is the interface between our pieces. We decide changes together and update all consumers in the same PR.
- **Pairing on the hard parts.** Resolver edge cases, the policy language and the experiment design are done together, not alone.

## Area 1: Compiler

- **1a. Front end (Youssef).** Write the lexer and parser for the bash subset in `compiler/grammar.md`: quoting and escapes, simple commands, pipelines, lists (`&&`, `||`, `;`), redirections, subshells, command substitution, assignments. Reject anything outside the subset. Compare against `bash -n` or another parser in tests as an oracle.
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

## Order of work

1. **Together first:** agree the supported subset, `compiler/types.py` and the policy language on paper before writing code.
2. **Build:** 1a and 1b in parallel against the agreed types; 2a and 3a can start against stubs; 3b starts the corpus early because everything is evaluated on it.
3. **Integrate:** gate wires the phases; run baselines and the full stack on the corpora.
4. **Evaluate and write:** record every result in `hypotheses.md` first, then draft the paper.

## Branches and merging

See [`CONTRIBUTING.md`](CONTRIBUTING.md).
