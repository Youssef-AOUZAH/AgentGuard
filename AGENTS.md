# AGENTS.md

Context for coding agents (and humans) working in this repository. Read this fully before making changes.

## Project in one sentence

agentGuard is a compiler that sits between an AI coding agent and the command line: it parses each shell command the agent wants to run, works out what the command would actually do, and only lets it through if a policy allows it. A zero-shot NLI classifier watches for agents that try to get around a rejection.

This is the Compilers course team project (UM6P College of Computing) by Youssef Aouzah and Younes Menfalouti. It is research flavoured: the deliverables are a working prototype, an evaluation, and a short paper plus presentation.

**This repository is public and we intend to publish the work as a paper.** Everything committed here is read by outsiders, so write for them: every module says what it does, every number in a `hypotheses.md` is traceable to a recorded run, and nothing goes in that we would not want attached to our names. Two consequences for the corpus: bypasses are described as generic shell technique rather than as working attacks on a named product, and anything specific to a particular agent or tool goes to that vendor first and into the repo only once it is fixed or disclosed. Corpus entries are declarative data files, never runnable exploit scripts.

## The problem

Coding agents such as Claude Code and Codex can run shell commands directly when they have broad permissions. Existing guards are mostly denylists that match the raw command string (for example "block `rm -rf`"). These are fragile: the same effect can be written many ways (`find -delete`, `python -c "shutil.rmtree(...)"`, a base64 encoded payload piped to `sh`, quoting tricks that the shell expands but the filter never sees). Worse, when a command is rejected, agents often keep going and look for another way to reach the same goal. A rejection is therefore not the end of the interaction, it is the start of a search by the agent for a command the filter misses.

## The idea

Three layers, each covering a weakness of the one before.

1. **Compiler (static analysis).** Treat the command as a program in a language (a subset of bash) and compile it in the usual phases: lexer, parser, resolver (expand quoting, escapes, variables and substitutions as the real shell would), effect analysis (what files, network hosts and processes the command would touch), and a policy check on those effects. The policy talks about effects, not strings. Anything the compiler cannot resolve statically (`eval`, unknown `$(...)`, decoded payloads piped to a shell) is escalated, never silently allowed.
2. **Classifier (zero-shot NLI).** Natural language inference is a task where a model decides whether a premise entails a hypothesis. Zero-shot classification uses it to label text with categories the model was never trained on: each candidate label is turned into a hypothesis ("this command tries to achieve the same effect as a command that was just blocked") and the model returns a probability per label. We use an open-source NLI model, not a hosted API, so everyone can run it. The classifier looks at escalated commands and at the agent's retry behaviour after a rejection, using the session history, not one command in isolation.
3. **Gate (integration).** Receives the agent's command, runs the compiler and classifier, returns a verdict and a message to the agent, and only executes approved commands, inside a sandbox.

Why not Jev (TypeSafe AI's classifier)? It needs a hosted API. NLI zero-shot is open source and reproducible. Do not add API-key dependencies.

Research question: can an effect-based compiler with a zero-shot intent classifier stop agent workarounds better than a string denylist, at an acceptable false-rejection rate on benign tasks?

## Hard rules on safety

These are the equivalent of ethics rules in this project. Do not bend them.

- **The compiler never executes what it analyzes.** No `eval`, `exec`, `subprocess`, `os.system` or shell invocation on agent-supplied or corpus commands inside `compiler/` or `classifier/`. Analysis is parsing and data flow only.
- **Fail closed.** A parse error, an unknown construct, or an internal exception in the compiler is a DENY (or ESCALATE), never ALLOW.
- **The classifier can only tighten.** It may turn an ALLOW into ESCALATE or DENY. It must never turn a compiler DENY into ALLOW. Do not "fix" a false rejection by letting the classifier override the compiler.
- **Dangerous commands run only in a sandbox.** The bypass corpus and agent experiments contain destructive commands. They may execute only in a disposable container or temporary directory created for that run, never on a developer's real files, home directory or credentials. Tests that check effects use a temp directory.
- **No secrets.** Never commit API keys, tokens, real credentials or real personal data. Experiments use throwaway repositories and fake files.
- **No third parties.** Do not point agents, the corpus or any scanner at systems we do not own.
- **Do not weaken the compiler to make a test pass.** If a bypass gets through, the fix is a better analysis or policy and a new regression test, not an allowlist entry for that exact string.

## Scope

In scope: bash-like commands issued by local coding agents; a policy language over effects; the NLI intent classifier; an evaluation against string denylist baselines.

Out of scope: a full POSIX shell implementation (we support a documented subset in `compiler/grammar.md` and reject the rest), Windows cmd and PowerShell (possible future work), kernel level enforcement (we assume an OS sandbox exists underneath and measure how much the compiler adds on top).

## Key literature

Read these before designing the matching part. All are 2026 and not all are peer reviewed; verify numbers against the papers before citing.

- **CARE: Pre-Execution Command Verification for Shell-Executing LLM Agents** (arXiv:2607.21642). Closest work: canonicalize a command, score it statically, escalate only ambiguous commands to an LLM judge. Our structure is similar; our differences are the effect-based policy over a real parser and the retry-aware classifier.
- **CmdNeedle / ShellSieve** (arXiv:2606.15549). Shows command denylists are fragile; an LLM proposes bypass commands and each is validated by its side effects in a sandbox. Method to reuse for generating our bypass corpus.
- **Don't Let AI Agents YOLO Your Files** (arXiv:2604.13536). The "shell loophole": shell commands run outside the harness, so policies on built-in tools do not apply. Argues for filtering on filesystem effects, not strings.
- **Red-Teaming the Agentic Red-Team** (arXiv:2606.24496). Policy control must be non-bypassable by the agent.
- **GuardFall** (Cloud Security Alliance research note, July 2026, industry disclosure not peer review). Shell quoting and expansion bypasses beat the string filters of 10 of 11 open-source agents; the agent that held tokenizes like bash does.
- **Agents routing around blocks**: blog level evidence only, for example "Door's Locked, Try the Window" (LessWrong) and reports on Cursor and Claude Code denylist bypasses. Use as motivation, not as results.
- Open-source baselines: bashguard (tree-sitter rules, verdicts ALLOW/BLOCK/CONFIRM/REDIRECT) and the Bionic shell safety write-up (mvdan/sh parser).

Gap we aim at: no paper models the agent's behaviour after a rejection, and none gives a formal grammar plus an effect-based policy over a hand-built parser.

## Pipeline and interfaces

```
command string
  -> lexer      compiler/lexer.py      tokens (words with quoting info, operators)
  -> parser     compiler/parser.py     AST (simple commands, pipelines, lists, redirections, subshells, substitutions)
  -> resolver   compiler/resolve.py    AST with statically known words expanded; dynamic parts marked UNRESOLVED
  -> effects    compiler/effects.py    set of Effect records (read, write, delete, exec, network, privilege)
  -> policy     compiler/policy.py     Verdict: ALLOW | DENY | ESCALATE, with reasons
  -> classifier classifier/            probabilities per label; may tighten the verdict
  -> gate       gate/                  message back to the agent; sandboxed execution if allowed
```

The shared types (`Token`, AST nodes, `Effect`, `Verdict`) live in `compiler/types.py`. This file is the contract between the two team members' pieces, like a schema: change it only through a pull request reviewed by the other member, and update every consumer in the same PR.

## Repository layout

```
compiler/     lexer, parser, resolver, effect analysis, policy engine
  types.py    shared types; changes only by reviewed pull request
  grammar.md  the supported bash subset (EBNF); keep it in sync with the parser
classifier/   zero-shot NLI intent classifier and its label definitions
gate/         integration: pipeline runner, sandboxed executor, message to the agent
bench/        bypass corpus, benign task corpus, baselines, agent experiments, metrics
policies/     policy files (declarative rules over effects)
docs/         design notes and decisions
data/         gitignored; model caches, raw agent transcripts, generated datasets
paper/        LaTeX for the final report
```

Each of `compiler/`, `classifier/`, `gate/`, `bench/` contains its code, a `tests/` folder and a `hypotheses.md` where finished experiments are recorded.

## Rules for coding agents in this repo

- Both members work on all aspects; ownership is per piece, not per area (see `TEAM.md`). Only edit files belonging to the piece you were assigned, plus its tests. Do not touch the other person's piece without being asked. If you need a change there, say so and let the human open the request.
- Never change `compiler/types.py` or `compiler/grammar.md` without being explicitly told to.
- Never push to `main`. Work on the member's own branch and open a pull request; it merges only after CI passes and the other member approves (see `CONTRIBUTING.md`). Run the CI checks locally before pushing.
- Write a test with every change. For the compiler, add a regression test for every bypass you fix: the failing command string, and the expected verdict.
- Tests must be deterministic and offline. CI never downloads a model: tests for `classifier/` use a stub model with fixed scores; the real model runs only in `bench/` experiments, locally.
- Explain what you built. The other member must be able to review and modify any piece, so leave a short docstring at the top of each module saying what the phase takes in, what it returns, and what it deliberately does not handle. Prefer small readable code to cleverness, and standard library for the compiler (no parser generators or tree-sitter in the core; they may be used in tests as an independent oracle to compare against).
- Python 3.12. Format and lint with ruff. Verdicts and classifier outputs carry reasons and probabilities, not bare labels.
- Do not invent results. Numbers in `hypotheses.md` and the paper come from a recorded run with its `run_id`; if you did not run it, say so.
- When an experiment finishes, record it in the folder's `hypotheses.md` (template below) before starting the next one.

## Evaluation plan (sketch, refine as we go)

Four setups, compared on the same corpora: (1) string denylist baseline, (2) compiler alone, (3) compiler plus NLI classifier, (4) the full stack with an OS sandbox underneath.

Metrics: workaround success rate (an effect the policy forbids still happens, measured in the sandbox), false-rejection rate on benign developer tasks, classifier probability calibration, and latency per command. The bypass corpus covers quoting and expansion tricks, encoded payloads, alternative tools with the same effect, and multi-step workarounds across rejections.

Open design question to settle early and record in `docs/`: what does the rejection message tell the agent? A detailed reason helps legitimate retries but teaches the agent how to probe; a generic message does the opposite. This is one of our hypotheses (gate H1).

## Starting hypotheses

Compiler:
- H1: effect-based rules block more bypasses in the corpus than a string denylist, at equal false-rejection rate.
- H2: constructs the compiler cannot resolve (`eval`, decoded payloads, unknown substitutions) are rare in benign tasks, so escalating them costs little.

Classifier:
- H1: zero-shot NLI separates "retry of a blocked effect" from "benign next step" with useful accuracy on (rejected command, next command) pairs.
- H2: giving the classifier the rejected command as context beats classifying the new command alone.

Gate and agents:
- H1: detailed rejection messages lead to more workaround attempts than generic ones.
- H2: the full stack lowers workaround success against real agents compared with a denylist.

## hypotheses.md template

```
## H<n>: <one sentence hypothesis>
Date:
Run ids:
Setup: <agents, models, corpora, policy version, number of runs>
Result: <numbers>
Conclusion: supported / rejected / inconclusive
Next: <what this changes, and for which piece>
```
