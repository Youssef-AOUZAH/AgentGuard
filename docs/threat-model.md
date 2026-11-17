# Threat model

Who we defend against, what we claim, and what we do not. Written before `compiler/types.py` on purpose: every design choice below this point depends on these answers, and without them there is no way to argue that any particular layer is worth building.

This is not the policy. The policy, in `docs/policy-rules.md`, says what is forbidden. This document says who might attempt it, by what means, and which of our layers can actually hold.

## The adversaries

Three are possible. We pick one as primary and are explicit about the other two.

| Adversary | Behaviour | Which layers can hold |
|---|---|---|
| **Over-eager agent** (primary) | Pursues the task past a denial. Does not conceal what it is doing | Compiler, session state, classifier |
| **Prompt-injected agent** (secondary) | Follows hostile text from a repository, a web page or a tool result. Will obfuscate deliberately | Compiler only |
| **Hostile operator** (out of scope) | Controls the agent's configuration, its tools, and the host the gate runs on | None |

**The over-eager agent is our primary adversary.** It is the one the literature actually documents: the survey's "verifier tax", where blocking 94% of unsafe actions still left under 5% of tasks completed safely and correctly because agents found other routes, and Permission Denied's finding that harnesses which retry aggressively burn tokens on denied actions while those that change strategy keep their success rate. The behaviour is not malice. The agent has a task, the obvious command was refused, and it reaches for the next way to finish the job. `rm` is denied, so it tries `find -delete`; `sudo` is denied, so it patches a cached `.pyc` instead.

This choice is what makes the classifier defensible. We are not claiming it defeats an attacker. We are claiming it notices an agent that has stopped respecting a boundary it was just told about, which is a much weaker and much more checkable claim.

**The prompt-injected agent is secondary, and only the compiler defends against it.** The injection has already happened by the time a command reaches us; we bound its blast radius rather than detect it. The compiler holds here because its analysis is structural: an effect either falls inside the policy or it does not, and no wording of the command changes that.

The classifier does **not** hold here, and the paper must say so. Two reasons, and the second is the one people miss. An injection author who knows the classifier is there can word a command to slip past it, and a zero-shot NLI model has no adversarial robustness whatsoever. More fundamentally, the classifier's strongest signal is "this command follows a denial and pursues the same effect" — so a command that is harmful on its first attempt, with no prior denial, gives the retry hypothesis nothing to work with. Only the obfuscation and exfiltration hypotheses could fire, and both are far weaker.

We still run the classifier under injection, because it costs nothing and crude injections are not obfuscated. Whatever it catches gets reported as an observed result, never as a guarantee.

**The hostile operator is out of scope.** Someone who controls the host can edit the policy, disable the gate, or replace the shell. No pre-execution check survives that, and R8's self-protection rules raise the cost without changing the conclusion.

## The one claim

> For every command the gate allows, the direct effects of the pinned shell evaluating that command line are within policy — provided the knowledge table entries used are correct, and the filesystem does not change between the check and the execution.

The sentence is written to name its own dependencies, and all three are real.

**The pinned shell.** The claim holds for one shell, one version, one invocation. This is not pedantry: we verified on bash 5.3.15 that `ls /nonexistent &>cap.txt` sends stderr into the file, where a POSIX reading of `&>` would background the command and truncate the file. A grammar written against POSIX and executed by bash is a bypass, so `compiler/grammar.md` has to name the exact shell and the executor has to use it.

**The knowledge table.** This is the largest and least verifiable assumption in the system, and the paper should say so plainly rather than bury it. A single unmodelled flag turns a read-only tool into one that writes or executes: we verified that `sort --outp=sorted.txt` creates a file, because GNU tools accept any unambiguous long-option prefix. The mitigation is to measure the table's soundness rather than assert it — run each entry in a container, observe what it actually touches, and assert that the observed effects are a subset of the predicted ones.

**No change between check and execution.** A time-of-check-to-time-of-use gap: we decide using the filesystem as it is now, and the shell runs a moment later. A background process started earlier could replace a directory with a symlink in between. Denying backgrounded commands narrows the window; only the sandbox closes it. This is a residual risk we name rather than fix.

## The non-claims

What follows is permitted by our own rules. Listing it is not an admission of failure — it is the first thing a security reviewer looks for, and a paper that knows its limits is the only kind worth submitting.

**Indirect effects of an allowed program.** `echo 'import os; os.remove("x")' > t.py` is an ordinary workspace write, and `python t.py` is an ordinary execution. Neither is forbidden; together they do whatever the agent wrote. The same holds for `make`, `npm install`, `pip install` and `pytest`, all of which run arbitrary code from files the agent can edit. Decision: leave this to the sandbox and say so. Measure the alternative — tainting files written this session and escalating when an interpreter runs them — as an ablation, because its utility cost is itself a result.

**Other agent tools.** The gate covers the shell. An agent's own file-writing or editing tool reaches the filesystem without passing through us, including the policy file. Either every tool is hooked, or the scope is stated as the shell tool only. We state the latter.

**Destruction inside the workspace.** R4 permits writes and deletes inside the workspace, so `rm -rf .`, `git reset --hard`, `git clean -fdx` and `git push --force` all pass. Partial mitigation: a protected sub-zone for `.git`, CI configuration and agent instruction files, and treating uncommitted work as unrecoverable.

**Exfiltration through an allowed host.** An allowed host is not an allowed destination. `git push` to an attacker's repository on github.com satisfies the allowlist, and so does `curl -T file` to any permitted host. Mitigation: split outbound network effects into fetch and send, and escalate sends.

**A secret read now and sent later.** `cat .env > /tmp/x` followed two commands later by `curl -T /tmp/x` defeats R6, which only inspects a single pipeline. Mitigation: mark the session tainted after any read from a secret zone and escalate every later send.

**Resource abuse.** `yes > f`, `dd if=/dev/zero of=big`, `sleep 99999`, `kill -9 -1`. No effect kind covers these. They belong to the executor: a wall-clock timeout, a disk quota and a process limit.

## What the compiler adds over a sandbox

We assume an operating-system sandbox underneath. That creates a measurement problem which has to be handled before the corpus is built: with a blocking sandbox in place, forbidden effects fail in every configuration, so "workaround success" cannot distinguish the compiler from the sandbox.

The fix is to make the container **observe rather than block**, so it is the instrument and not the defence. Effects are then measured by hashing the filesystem before and after, tracing file and network calls, and planting canary files with unique contents in the fake home and secret zones so that reads — which leave no trace in a diff — become visible.

What the compiler gives that a sandbox cannot:

- **A reason the agent can act on.** A sandbox returns `EACCES`. We can say which effect was refused and why, which is the whole basis of the denial-message experiment.
- **Denial before any side effect occurs.** A sandbox stops the write after the process has started and the earlier commands in the list have already run.
- **Rules over combinations, and inside the workspace.** Secret-read-then-send, and protecting `.git` from the agent, are not expressible as filesystem permissions.
- **Retry detection.** Nothing about a sandbox notices that this command pursues the effect refused two commands ago.

## Residual risks, stated plainly

The time-of-check gap above. The knowledge table being incomplete in a way we have not measured. The classifier being evadable by anyone who knows it exists. Any divergence between our lexer and the pinned shell, which canonical emission is intended to close by construction. And the fact that filename-based secret detection is a heuristic: a credential pasted into an ordinary source file is invisible to it.
