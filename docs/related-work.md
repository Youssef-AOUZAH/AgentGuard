# Related work: compilers and parsers between agents and the shell

State of the field as of November 2026, gathered to decide our own grammar and rules. Every claim here is marked with how well we verified it, because several of the strongest-sounding numbers come from secondary write-ups or from model-extracted summaries of papers rather than from the papers' own text. Before any of this goes into our paper, the cited source has to be read directly.

## 1. The research papers

**CARE: Pre-Execution Command Verification for Shell-Executing LLM Agents** (arXiv:2607.21642, Liu et al., accepted at ISSRE 2026). This is the closest published work to what we are building, and the one we must position against. It checks each shell command before the host shell runs it, using a four-layer static pipeline with an LLM judge only for uncertain cases.

Its architecture, which is worth understanding in detail because ours will resemble it:

- **Canonicalization (L0).** A single-pass, idempotent, deterministic rewrite: it unwraps wrapper shells (`sh -c`, `zsh -c`, `dash -c`, `busybox sh -c`), normalizes quoting and escapes, does bounded decoding, and applies light deobfuscation. It explicitly aims at "bounded normalization, not full semantic recovery", keeps the original tokens beside the normalized form, and runs no subprocess.
- **Structure (L1).** Binary structural indicators, scored by severity: piping into an interpreter scores 1.00, `eval` or substitution-as-source 0.90, nested command substitution at depth two or more 0.60, plain command substitution 0.30, a plain pipe 0.05. (Scores from a summary, not verified in the paper body.)
- **Semantics (L2).** Each command head maps to a risk class with a base score. From the published code: `READ_ONLY` 0.00, `WRITE_LOCAL` 0.15, `NETWORK_FETCH` 0.40, `EXECUTION_CHAIN` 0.60, `WRITE_SENSITIVE` 0.70, `PRIVILEGE_OR_PERMISSION` 0.75, `PERSISTENCE` 0.80, `RESOURCE_ABUSE` 0.85, `DESTRUCTIVE` 1.00, `UNKNOWN` 0.35. Roughly 250 heads are classified, with sub-classifiers for dual-use tools (`chmod`, `dd`, `docker`, `find`, `sed -i`, `tar`, `awk`/`perl`/`ruby`).
- **Paths (L3).** Path operands are taken from AST tokens and redirection targets, normalized, then scored by sensitivity tier and by whether the access is a read or a write. The asymmetry matters and we should copy it: reading `/etc/os-release` is fine, appending to `/etc/profile` is not.
- **Patterns (L4).** A catalog of 139 regex rules, each weighted by provenance: 92 from MITRE ATT&CK at weight 1.00, 31 from GTFOBins at 0.85, 16 hand-written at 0.60.

The layers combine as `0.3*semantic + 0.3*path + 0.3*pattern + 0.1*structure`, and the score falls into three bands: allow below 0.15, warn from 0.15 to 0.35, deny above. Only warn commands can reach the LLM judge, and even then "skip predicates" deny outright when a high-confidence rule fires, a high-risk semantic class is hit, or a protected path is written. Reported results are 85.64% F1 with a 0.91% false-positive rate at 2.32 ms mean latency, and a static-only profile keeping 84.99% F1 at 0.34 ms.

Two findings in it should shape our own evaluation. First, on the RedCode-gen attack set, the *static* profile reduced realised harm to 37.33% while the *full* system with the LLM judge only reached 52.50%, worse than static alone, because the judge appears to flip genuinely dangerous warn cases to allow. If that holds up, it is an argument for our NLI classifier being allowed only to tighten a verdict, never to loosen one, which is already a hard rule in `AGENTS.md`. Second, and most important for us: the paper states that each decision is "made over a single command in isolation" and that mediation is "stateless". It is explicitly not a trajectory-level defence, and it names trajectory-level reasoning as future work.

**CmdNeedle / ShellSieve** (arXiv:2606.15549). Demonstrates that command denylists are fragile by having an LLM propose bypasses and validating each one by its actual side effects in a sandbox. This is both our motivation and the method we should reuse to generate the bypass corpus: validate by effect, not by whether a string matched.

**Don't Let AI Agents YOLO Your Files** (arXiv:2604.13536). Names the "shell loophole": shell commands execute outside the agent harness, so the policies that govern the harness's own built-in tools simply do not apply. Argues for filtering on filesystem effects rather than command strings, which is the premise of our design.

**Red-Teaming the Agentic Red-Team** (arXiv:2606.24496). Argues that policy enforcement must be non-bypassable by the agent and the worker it controls.

**Toward Safe LLM Agents: A Survey of Specification, Verification, and Enforcement** (arXiv:2608.14590, Dantas, Cordeiro, Nowroozi, Tihanyi). The broad survey to cite for framing. Its taxonomy has three stages, specification (how a safety property is acquired and represented), verification (whether a plan satisfies it), and enforcement (what happens when it does not), and it distinguishes verification, which observes and reports, from runtime enforcement, which observes and intervenes. Properties are expressed in temporal logics (LTL, LTLf, CTL, STL, PCTL).

Its single most useful result for us is in the abstract: in one study, blocking 94% of unsafe actions still left under 5% of tasks completed both safely and correctly, "because agents found other unsafe routes". The survey calls this the **verifier tax** and lists it as research gap RG3, one of its three priority gaps, stating that no existing system resolves it. It also notes that agents respond to blocked authentication by hallucinating credentials, and offers an untested hypothesis that repeated hard blocks push agents into out-of-distribution behaviour. This is exactly the phenomenon our retry-aware classifier targets, and it means our framing is a recognised open problem rather than something we invented.

Two caveats on this survey. It never discusses shell commands, bash, or command-string analysis anywhere our search could read, so it positions our work rather than competing with it. And it rates its own evidence quality as Very Low for seven of nine claims, with the 94%/5% figures described as too narrow to generalize, so quote them as illustrative, not as established fact.

**GuardFall** (Cloud Security Alliance research note, July 2026). An industry disclosure, not peer-reviewed. Reports that shell quoting and expansion tricks defeat the pattern-based command filters of ten of eleven popular open-source coding agents, and that the single agent which held up was the one that tokenizes commands the way bash itself does. This is the strongest available argument for writing a real lexer rather than matching strings, and the reason our `Token` must record how each piece of a word was quoted.

**ClawGuard** (arXiv:2604.11790). A runtime security framework for tool-augmented agents against indirect prompt injection. Adjacent rather than central; worth a citation in related work.

Blog-level evidence that agents route around blocks, such as "Door's Locked, Try the Window" on LessWrong and the reported Cursor and Claude Code denylist bypasses, is useful as motivation but must not be cited as a result.

## 2. The existing projects, and which grammar each uses

This is the part that matters for our choice. Not one of these writes its own shell grammar; every one of them either borrows a parser or falls back on regular expressions.

| Project | Parser / grammar | Policy form | Notes |
|---|---|---|---|
| **CARE** (`prisma-research/CARE`) | `bashlex`, a Python bash parser | 139 JSON regex rules plus scored layers, thresholds in code | A summary of its appendix reports an 11% parse-error rate on the bash dialect of a multi-shell set; unverified. Fails closed when a parse failure co-occurs with high-risk tokens |
| **bashguard** (`sunir/bashguard`) | `tree-sitter-bash` | Python rule classes, `.bashguard.yaml` for severity mapping and host allowlist | Rules grouped as `destructive.irreversible`, `credentials.privileged_path`, `network.unknown_host`, `git.destructive`, `paths.protected_write`, `content.secret_in_args`, `content.exfiltration_pattern`, and 13 `evasion.*` rules |
| **cc-bash-guard** (`tasuku43/cc-bash-guard`) | unnamed "parser-backed" pipeline, coverage explicitly finite | declarative YAML, tests required per rule | The most developed policy language of the group; see below |
| **agent-command-guard** (`tomatoaiu/agent-command-guard`) | Go, AST plus regex command rules | regex rules checked before a built-in shell policy | Path-aware |
| **policy-command-guard** | AST decomposition, quote-context normalization | compiled declarative policy | Also uses negative-lookahead regex and path containment |
| **agentkit shellguard** (Go) | none; deterministic denylist | denylist then optional LLM | Two-step gate |
| **Claude Code's own deny list** | reportedly inspects only the first token | settings permissions | Reported bypassable by chaining; blog-level evidence |
| **Continue** | tokenizes as bash does | not documented | Per GuardFall, the only agent of eleven that withstood quoting bypasses |

Three designs in this table are worth stealing from deliberately.

**bashguard separates evidence from decision.** A rule emits a `Finding` carrying a rule id, a severity and an `ActionType`, and policy then turns findings into a verdict, so the same finding can produce different verdicts in different contexts. Its `ActionType` enum is effectively a first attempt at an effect taxonomy: `FILESYSTEM_READ`, `FILESYSTEM_WRITE`, `FILESYSTEM_DELETE`, `FILESYSTEM_MOVE`, `NETWORK_OUTBOUND`, `GIT_SAFE`, `GIT_DESTRUCTIVE`, `PACKAGE_INSTALL`, `LANG_EXEC`, `PROCESS_SIGNAL`, `ENV_MUTATION`, `OBFUSCATED`, `CREDENTIAL_ACCESS`, `SYSTEM_CONFIG`, `UNKNOWN`. It is a classification of what a command does rather than a model of what it would touch, and there is no sign of state tracked across commands. Its verdicts are `ALLOW` (run inside a kernel sandbox), `BLOCK`, `CONFIRM` (ask the user) and `REDIRECT` (reroute to a structured tool). It ratchets: `ALLOW < CONFIRM < BLOCK`, a project config may tighten but never relax, and the optional LLM second opinion is consulted only on `CONFIRM`, never on `BLOCK`. Its stated principle is one we should adopt verbatim in spirit: if intent cannot be read from the AST, block, because structural ambiguity is itself the signal.

**cc-bash-guard shows what a good declarative policy looks like.** Top-level keys are `include`, `permission` (holding `deny`, `ask`, `allow` buckets) and `test`. A rule matches on `command.name`, `command.name_in`, per-command `semantic` fields such as `verb`, `verb_in` and `force`, environment variables via `env.requires` and `env.missing`, parser-derived `shape_flags_any`/`_all`/`_none` (`redirect_file_write`, `redirect_append_file`, `redirect_stdin_from_file`, `redirect_heredoc`, `redirect_to_devnull`, `redirect_stream_merge`), and raw `patterns` regexes as an explicit escape hatch. Precedence is `deny > ask > allow > abstain`, where **abstain** means no rule had an opinion, and the fallback when everything abstains is `ask`. Every permission rule is *required* to carry a `test` block listing commands that must come out allow, ask, deny or abstain, and a `verify` command runs those tests and refuses to build the artifact if a rule is too broad: it rejects, for example, an allow rule on bare `git` with no semantic fields, or any allow rule for `bash`, `sh`, `python3`, `node`, `make`, `npm`, `npx`, `xargs` or `ssh`. Quoting is handled in the parser, so `grep '2>&1' file` is correctly seen as a literal argument rather than a redirect. Its honest non-goals are also instructive: it states it is a permission policy layer and not an OS, filesystem or network sandbox, does not interpret scripts, and has finite parser coverage.

**CARE keeps rules as data and weights as configuration.** Rules live in `care/rules/rule_provenance.json` with fields `rule_id`, `layer`, `description`, `failure_family`, `mitre_techniques`, `shellcheck_ids`, `owasp_category`, `gtfobins_related`, `cve_examples`, `confidence`, `provenance_tier` and `pattern_regex`. Provenance weight is held per tier rather than per rule, which makes tuning cheap. Path tiers mix literal prefixes with compiled regexes (`CRITICAL_PATH_PATTERNS`, `SECRET_READ_PATHS`, `SENSITIVE_WRITE_PATHS`, `SYSTEM_ROOT_TARGETS`, `BENIGN_DEVICE_PATHS`) and its operating modes are nothing more than threshold presets (balanced 0.15/0.35, strict 0.10/0.20, auto 0.20/0.50), so one scoring implementation serves all modes.

## 3. Where that leaves us

Four gaps are real, and together they are our contribution.

**Nobody writes the grammar.** Every project borrows `bashlex`, `tree-sitter-bash`, or regex. That is sensible engineering and a poor fit for a compilers course, and it also means nobody states what their accepted language actually is: CARE's parser reportedly fails on around 11% of one bash set, and cc-bash-guard admits only that coverage is "finite". A written grammar with an explicit rejected-construct list, where everything outside the grammar is a denial by construction, is both the coursework and a genuine methodological improvement.

**Quoting provenance is normalized away rather than carried.** GuardFall's bypasses exist precisely because filters inspect a string before the shell expands it, and the tools respond by *normalizing*: CARE's bounded decoding, policy-command-guard's quote-context normalization. Normalization is lossy and CARE's own paper says so. Carrying, for every piece of every word, how it was quoted or where it came from, and refusing to decide when a piece is unresolvable, is stricter and easier to argue.

**Enforcement is stateless.** CARE says so explicitly. bashguard tracks no state across commands. This is why `cd ~/Desktop` is hard for all of them: whether a later relative path escapes the workspace depends on the current directory, which is session state. Tracking the working directory, and the set of effects already denied, is necessary for correctness, not a nice extra.

**The verifier tax is named but unaddressed.** The survey makes it a priority gap and says no system resolves it; CARE defers it as future work. A gate that detects when a new command pursues an effect that was just denied is the direct attack on that gap, and it is what our NLI classifier is for.

So our claim is: a from-scratch, specified grammar that preserves quoting provenance, feeding an effect model and a session-aware policy, with a retry-detecting classifier on top. Each of the four parts answers something the literature says is missing.
