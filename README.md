# agentGuard: a compiler between AI agents and the shell

AI coding agents can run shell commands directly when they have broad permissions, and string based denylists are easy to get around. agentGuard treats each command as a program: it parses it, works out what it would do to files, the network and processes, and checks those effects against a policy before anything runs. When an agent is rejected and tries another route to the same goal, a zero-shot NLI classifier (natural language inference, open source, no API key) flags the retry.

Compilers course team project by **Youssef Aouzah** and **Younes Menfalouti**, UM6P College of Computing. Deliverables: a working prototype, an evaluation against string denylist baselines, a short paper and a presentation.

## Publication

This repository is public on purpose. We intend to publish the work as a paper, and this repo is the artifact that goes with it: the compiler, the policies, the corpora and the recorded experiments should let a reader reproduce every number we report. Treat `hypotheses.md`, the policy files and the corpus as part of the publication, written for an outside reader, not as private scratch space.

Because it is public, the bypass corpus is written as **generic shell technique, never as a working attack on a named product**. If we find a bypass specific to a particular agent or tool, it goes to that vendor first and into the repo only once it is fixed or disclosed. Corpus entries stay declarative data files, not runnable exploit scripts.

## Research question

Can an effect-based compiler plus a zero-shot intent classifier stop agent workarounds better than a string denylist, at an acceptable false-rejection rate on benign developer tasks?

## How it works

```
command -> lexer -> parser -> resolver -> effect analysis -> policy -> classifier -> gate
                                                  verdict: ALLOW | DENY | ESCALATE
```

Anything the compiler cannot resolve statically is escalated, never silently allowed. The classifier can only make a verdict stricter. Approved commands run in a sandbox. Full design, safety rules and literature are in [`AGENTS.md`](AGENTS.md).

## Repository layout

```
compiler/     lexer, parser, resolver, effect analysis, policy engine (grammar in compiler/grammar.md)
classifier/   zero-shot NLI intent classifier
gate/         pipeline runner, sandboxed executor, messages back to the agent
bench/        bypass corpus, benign corpus, baselines, agent experiments, metrics
policies/     declarative policy files
docs/         design notes and decisions
data/         gitignored; model caches, transcripts, generated datasets
paper/        LaTeX report
```

Each of `compiler/`, `classifier/`, `gate/` and `bench/` has its own tests and a `hypotheses.md` where every finished experiment is recorded.

## Safety

The compiler never executes the commands it analyzes. It fails closed: errors mean DENY or ESCALATE. Destructive test commands run only in disposable sandboxes, never on real files. No secrets or real personal data are committed. See the hard rules in `AGENTS.md`.

## Getting started

1. Read [`AGENTS.md`](AGENTS.md) in full. It holds the project context, literature, safety rules, interfaces and working rules for humans and coding agents.
2. Check [`TEAM.md`](TEAM.md) for the division of work. Both members own pieces in every area, and review each other's work.
3. Install and check:

```
pip install -r requirements-dev.txt
ruff check . && ruff format --check .
pytest
```

The classifier needs extra packages (`pip install -r requirements.txt`) and downloads an open NLI model on first use; the tests never do.

4. Work on your own branch and open a pull request into `main`; see [`CONTRIBUTING.md`](CONTRIBUTING.md).
