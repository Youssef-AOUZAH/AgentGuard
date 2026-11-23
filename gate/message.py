"""The message a refused command returns to the agent.

Takes in the final verdict, the decision behind it and a `MessageLevel`, and returns one fixed
piece of text. What the message should say is gate hypothesis H1, so the three levels exist to be
compared, and the wording at each level is fixed rather than varied, so that the classifier's
dataset is not confounded by message wording (`docs/decisions.md`, "What does a rejection tell
the agent?").

- `GENERIC`: that the command was refused, and whether a human could have approved it.
- `RULE`: also, for each cited rule, its id and name and the kind of effect it fired on. For R1
  the detail is the diagnostic, which describes the construct, not the policy.
- `DETAILED`: also the target of each effect and the policy's own detail text.

No level ever states the policy itself or what would have been allowed instead.

Deliberately not handled: the zone at the `RULE` level, which the recommendation in
`docs/decisions.md` wants but which `Reason` does not yet carry (zones are computed by the policy
engine, and adding a field to `compiler/types.py` is Younes's call).
"""

from __future__ import annotations

from compiler.types import Decision, Reason, RuleId, Verdict
from gate.types import MessageLevel

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

INTERNAL_ERROR = "agentGuard refused this command: it could not be analysed."


def render(verdict: Verdict, decision: Decision, level: MessageLevel) -> str:
    """The text for a command with this final verdict. Empty for a command that was allowed."""
    if verdict is Verdict.ALLOW:
        return ""
    if decision.verdict is Verdict.ESCALATE:
        head = "agentGuard refused this command: it needs a human's approval, and none was given"
    else:
        head = "agentGuard refused this command"
    if level is MessageLevel.GENERIC or not decision.reasons:
        return head + "."
    lines = list(dict.fromkeys(_line(reason, level) for reason in decision.reasons))
    shown = lines[:MAX_REASONS]
    if len(lines) > MAX_REASONS:
        shown.append(f"and {len(lines) - MAX_REASONS} more")
    return head + ":\n" + "\n".join(f"- {line}" for line in shown)


def _line(reason: Reason, level: MessageLevel) -> str:
    text = f"{reason.rule} ({RULE_NAMES.get(reason.rule, 'unnamed rule')})"
    if reason.effect is not None:
        text += f": {reason.effect.kind}"
        if level is MessageLevel.DETAILED and reason.effect.target is not None:
            text += f" {reason.effect.target}"
    if reason.detail and (reason.rule is RuleId.R1 or level is MessageLevel.DETAILED):
        text += f" ({reason.detail})"
    return text
