# Decisions and open questions

A short record of choices we made and why, so neither of us has to reconstruct the reasoning later, and so a coding agent reading the repo does not undo a decision on purpose. Add an entry when you decide something that is not obvious from the code.

## Decided

**Name: agentGuard.** Note for later: `bashguard` and `sh-guard` are existing open-source tools in the same space, and `ShellSieve` is one of the papers we cite, so when we write the paper we should say plainly how we differ from them. Renaming the GitHub repo later is cheap (GitHub redirects the old URL), but both of us would have to update our git remotes.

**Classifier: zero-shot NLI, not Jev.** Jev (TypeSafe AI) is a hosted classifier and needs an API key, which makes the project non-reproducible for anyone without an account. An open-source NLI model runs locally. Do not reintroduce an API-key dependency.

**The repo is public.** See the publication rules in `README.md` and `AGENTS.md`. The practical consequence is that the bypass corpus is generic shell technique, never a working attack on a named product.

**No parser generators in the core.** The lexer and parser are written by hand, because this is a compilers course project and that is the part being assessed. Tree-sitter or `bash -n` may be used in tests as an independent oracle to compare our parse against.

**The grammar is a documented subset of POSIX Issue 8, section 2.** We use the standard's own token names and productions rather than inventing our own, so our accepted language is checkable against a specification. Every existing tool in this space borrows a parser instead (CARE uses `bashlex`, bashguard uses `tree-sitter-bash`, others use regex), and none states what language it accepts; see `docs/related-work.md`. The accepted subset and the explicit rejected-construct list are in `compiler/grammar.md`.

**Anything outside the grammar is a denial, not a parse failure.** This is what makes the from-scratch grammar a security property rather than a limitation, and it is why unspecified POSIX behaviour is also rejected: a divergence between our reading and the real shell's is exactly a bypass.

**Words carry quoting provenance; we never expand.** A word is a list of parts, each tagged with how it was written (literal, single-quoted, `$'...'`, parameter expansion, command substitution, glob, and so on), and a word is resolved only when every part is statically known. The prior tools normalize and decode to produce a string to match; normalization is lossy, and refusing to decide is not. This is the direct response to the GuardFall quoting bypasses.

**The gate is session-aware.** We track the working directory, resolved variable assignments, and the history of denied effects. CARE states that its mediation is stateless and per-command, which is why a sequence like `cd ~/Desktop` followed by `cat notes.txt` is invisible to it. Session state is also what makes retry detection possible, which is the survey's RG3 "verifier tax" and the gap we are aiming at.

**Verdicts form a lattice and only ever tighten.** `ALLOW < ESCALATE < DENY`; every stage may raise a verdict and none may lower it. CARE reports that its LLM judge made realised harm *worse* than its static profile by flipping warn cases to allow, which is the empirical argument for the rule already in `AGENTS.md` that the classifier may only tighten.

## Deferred

**CI guard script.** The hard rules in `AGENTS.md` (the compiler never executes what it analyzes, no committed secrets or data, corpus entries are data not scripts) are prose only; nothing enforces them. The plan is a Python script in `.github/scripts/` run as a CI step, using the `ast` module to reject `eval`, `exec`, `subprocess` and friends in `compiler/` and `classifier/` while exempting `gate/`, whose sandboxed executor legitimately needs them. Deferred until there is code for it to check.

## Open

**What does a rejection tell the agent?** A detailed reason ("this would delete files outside the workspace") helps a legitimate retry but teaches the agent where the boundary is, so it can probe around it. A generic refusal does the opposite. This is gate H1 in `gate/hypotheses.md`, to be answered with a measurement rather than a guess.

**Which NLI model.** Piece 2a. Needs to be open-weight, small enough to run on a laptop in the command path, and good enough on the (rejected, next command) task. Record the choice and the latency here once measured.

**Policy language shape.** What a rule over effects actually looks like, and whether it is YAML or a small DSL we parse ourselves. To be agreed together before `compiler/policy.py` is written.
