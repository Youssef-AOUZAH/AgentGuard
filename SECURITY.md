# Security policy

## What this project is, and is not

agentGuard is a **research prototype built for a university course**. It is not
a security product, it has not been audited, and it must not be relied on as a
security boundary. Do not put it in front of an agent that has access to
anything you care about. Everything it does is a best-effort static analysis of
a shell command, and the design documents in `docs/` list, deliberately and at
length, the cases it cannot decide.

If you want an actual boundary, use an operating-system sandbox. We assume one
underneath us, and our own documentation treats the compiler as a layer that
gives better *reasons* than a sandbox can, not better *guarantees*.

## Reporting a bypass in agentGuard

A bypass is a command, or a sequence of commands, that our gate allows and whose
real effects a policy forbids. We want to hear about those — they are the whole
point of the project, and a reported bypass is more useful to us than a star.

Use GitHub's private vulnerability reporting on this repository (the Security
tab, then "Report a vulnerability"). That keeps the report out of public view
until we have looked at it. For anything that is not sensitive — a false
rejection, a parser disagreement, a wrong effect in the knowledge table — a
normal public issue is better, because those are ordinary bugs and the
discussion is useful to read.

In a report, the two things that help most are the exact command string, byte
for byte including its quoting, and the effect you observed rather than the one
you expected. If you have a container recipe that demonstrates it, include that.

We will acknowledge a report, and if it is a real bypass we will add it to the
regression corpus with attribution unless you ask us not to. We cannot offer a
bounty, and we cannot promise a fix timeline: this is coursework, and after the
course ends the repository may be archived.

## Bypasses we find in other people's tools

Our evaluation runs other guards as baselines — CARE, bashguard, and string
denylists taken from real projects. If we find a bypass in one of those, we tell
its maintainers first and give them time to respond before the finding appears
in this repository or in our paper. The corpus may describe the generic
technique; it will not ship a working attack against a named product that has
not been fixed or disclosed.

The same rule holds for coding agents themselves. If an experiment reveals a way
past a shipped agent's own command filter, that goes to the vendor before it goes
anywhere else.

## Scope

In scope: the compiler, the policy engine, the classifier, the gate, and the
corpora in this repository.

Out of scope: vulnerabilities in our dependencies, which belong upstream;
anything requiring control of the machine the gate runs on, which our threat
model excludes; and the absence of features the documentation already says are
absent, such as the rejected shell constructs listed in `compiler/grammar.md`.
