# Decisions and open questions

A short record of choices we made and why, so neither of us has to reconstruct the reasoning later, and so a coding agent reading the repo does not undo a decision on purpose. Add an entry when you decide something that is not obvious from the code.

## Decided

**Name: agentGuard.** Note for later: `bashguard` and `sh-guard` are existing open-source tools in the same space, and `ShellSieve` is one of the papers we cite, so when we write the paper we should say plainly how we differ from them. Renaming the GitHub repo later is cheap (GitHub redirects the old URL), but both of us would have to update our git remotes.

**Classifier: zero-shot NLI, not Jev.** Jev (TypeSafe AI) is a hosted classifier and needs an API key, which makes the project non-reproducible for anyone without an account. An open-source NLI model runs locally. Do not reintroduce an API-key dependency.

**The repo is public.** See the publication rules in `README.md` and `AGENTS.md`. The practical consequence is that the bypass corpus is generic shell technique, never a working attack on a named product.

**No parser generators in the core.** The lexer and parser are written by hand, because this is a compilers course project and that is the part being assessed. Tree-sitter or `bash -n` may be used in tests as an independent oracle to compare our parse against.

## Deferred

**CI guard script.** The hard rules in `AGENTS.md` (the compiler never executes what it analyzes, no committed secrets or data, corpus entries are data not scripts) are prose only; nothing enforces them. The plan is a Python script in `.github/scripts/` run as a CI step, using the `ast` module to reject `eval`, `exec`, `subprocess` and friends in `compiler/` and `classifier/` while exempting `gate/`, whose sandboxed executor legitimately needs them. Deferred until there is code for it to check.

## Open

**What does a rejection tell the agent?** A detailed reason ("this would delete files outside the workspace") helps a legitimate retry but teaches the agent where the boundary is, so it can probe around it. A generic refusal does the opposite. This is gate H1 in `gate/hypotheses.md`, to be answered with a measurement rather than a guess.

**Which NLI model.** Piece 2a. Needs to be open-weight, small enough to run on a laptop in the command path, and good enough on the (rejected, next command) task. Record the choice and the latency here once measured.

**Policy language shape.** What a rule over effects actually looks like, and whether it is YAML or a small DSL we parse ourselves. To be agreed together before `compiler/policy.py` is written.
