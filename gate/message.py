"""The message a refused command returns to the agent.

Takes in the final verdict, the decision behind it and a `MessageLevel`, and returns one fixed
piece of text.

**Decided (`docs/decisions.md`, "What does a rejection tell the agent?"): the agent is told that
the command was refused under the user's rules, and nothing else.** Every refusal, whatever caused
it (a denying rule, an escalation nobody approved, a command we could not parse, an internal
failure), gets the same sentence, `REFUSED`. Any difference between refusals would tell the agent
something about where the boundary is or why it was hit, and the point is to tell it nothing it can
probe with. `GENERIC` is the default and the only level for real use.

`RULE` and `DETAILED` remain for one purpose: gate hypothesis H1 measures how much a more
informative message changes what an agent does next, and that needs the informative messages to
exist. They are experiment settings, never a deployment option.

- `RULE`: for each cited rule, its id and name and the kind of effect it fired on. For R1 the
  detail is the diagnostic, which describes the construct, not the policy.
- `DETAILED`: also the target of each effect and the policy's own detail text.
"""

from __future__ import annotations

from compiler.types import Decision, Reason, RuleId, Verdict
from gate.types import MessageLevel

REFUSED = "Command refused based on user rules."

RULE_NAMES: dict[RuleId, str] = {
    RuleId.R1: "unparseable",
    RuleId.R2: "unbounded destructive target",
    RuleId.R3: "interpreter handoff",
    RuleId.R4: "path containment",
    RuleId.R5: "privilege",
    RuleId.R6: "network",
    RuleId.R7: "obfuscation",
    RuleId.R8: "self-protection",
    RuleId.R9: "retry of a denied effect",
    RuleId.R10: "unknown command",
}

MAX_REASONS = 5

# Kept as its own name so callers can say what they mean; the text is the same on purpose.
INTERNAL_ERROR = REFUSED


def render(verdict: Verdict, decision: Decision, level: MessageLevel) -> str:
    """The text for a command with this final verdict. Empty for a command that was allowed."""
    if verdict is Verdict.ALLOW:
        return ""
    if level is MessageLevel.GENERIC or not decision.reasons:
        return REFUSED
    lines = list(dict.fromkeys(_line(reason, level) for reason in decision.reasons))
    shown = lines[:MAX_REASONS]
    if len(lines) > MAX_REASONS:
        shown.append(f"and {len(lines) - MAX_REASONS} more")
    return REFUSED + "\n" + "\n".join(f"- {line}" for line in shown)


def _line(reason: Reason, level: MessageLevel) -> str:
    text = f"{reason.rule} ({RULE_NAMES.get(reason.rule, 'unnamed rule')})"
    if reason.effect is not None:
        text += f": {reason.effect.kind}"
        if level is MessageLevel.DETAILED and reason.effect.target is not None:
            text += f" {reason.effect.target}"
    if reason.detail and (reason.rule is RuleId.R1 or level is MessageLevel.DETAILED):
        text += f" ({reason.detail})"
    return text
