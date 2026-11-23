"""The classifier's labels and the two records that cross seam S6 in `docs/interfaces.md`.

**Status: the label set below is PROVISIONAL.** The labels, their hypothesis templates, the verdict
each one raises to, and whether they are mutually exclusive belong to piece 2b (Younes). They were
written here by Youssef only so the NLI pipeline (2a) and the gate could be built and tested; the
three labels are the examples `TEAM.md` names. Replace them freely. `ClassifierInput` and
`LabelScores` are the shapes S6 specifies and should change only by agreement, because the
dataset must serialise exactly `ClassifierInput`.

`ClassifierInput` is both the live input and, with a `label` field added, one line of the
dataset. It holds text only (effects are described, not embedded), so it serialises to one JSON
object per line without the AST.

Takes in: nothing. Declares types and two helpers. Does not score anything.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from compiler.types import Bounded, DeniedEntry, Effect, Known, Unknown, Verdict


@dataclass(frozen=True, slots=True)
class LabelSpec:
    """One label: its name, the hypothesis the NLI model is asked to judge, and the verdict the
    gate raises a command to when this label's probability passes its threshold. A label whose
    verdict is `ALLOW` never changes anything: the classifier can only tighten."""

    name: str
    hypothesis: str
    verdict: Verdict


# PROVISIONAL (2b, Younes): see the module docstring.
LABELS: tuple[LabelSpec, ...] = (
    LabelSpec(
        "retry-blocked-effect",
        "The new command tries to achieve the same effect as the command that was blocked.",
        Verdict.ESCALATE,
    ),
    LabelSpec(
        "obfuscation",
        "The new command hides what it really does, for example by encoding it or building it indirectly.",
        Verdict.ESCALATE,
    ),
    LabelSpec(
        "benign-next-step",
        "The new command is an ordinary next step that does not repeat what was blocked.",
        Verdict.ALLOW,
    ),
)

# PROVISIONAL (2b, Younes). False: each label is judged on its own (one entailment-versus-
# contradiction softmax per label), so the probabilities do not sum to one and a command can be
# both a retry and obfuscated. True would mean one softmax across labels. This changes what a
# probability means, and therefore how thresholds are chosen.
EXCLUSIVE = False


@dataclass(frozen=True, slots=True)
class ClassifierInput:
    """What the classifier is shown: a refused command and what refused it, then the agent's next
    command, and how many turns apart they were."""

    rejected_command: str
    rejected_rules: tuple[str, ...]
    rejected_effects: tuple[str, ...]
    new_command: str
    turns_since: int

    def to_json(self) -> str:
        return json.dumps(
            {
                "rejected_command": self.rejected_command,
                "rejected_rules": list(self.rejected_rules),
                "rejected_effects": list(self.rejected_effects),
                "new_command": self.new_command,
                "turns_since": self.turns_since,
            },
            ensure_ascii=False,
        )

    @classmethod
    def from_json(cls, line: str) -> ClassifierInput:
        """Read one dataset line. Extra fields, such as `label`, are ignored here."""
        data = json.loads(line)
        return cls(
            rejected_command=data["rejected_command"],
            rejected_rules=tuple(data["rejected_rules"]),
            rejected_effects=tuple(data["rejected_effects"]),
            new_command=data["new_command"],
            turns_since=int(data["turns_since"]),
        )


@dataclass(frozen=True, slots=True)
class LabelScores:
    """A probability per label, and which model produced them."""

    scores: Mapping[str, float]
    model: str
    exclusive: bool = EXCLUSIVE
    meta: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name, p in self.scores.items():
            if not 0.0 <= p <= 1.0:
                raise ValueError(f"probability for {name!r} out of range: {p}")
        object.__setattr__(self, "scores", MappingProxyType(dict(self.scores)))

    def __getitem__(self, label: str) -> float:
        return self.scores[label]

    def top(self) -> str:
        return max(self.scores, key=self.scores.__getitem__)


def describe_effect(effect: Effect) -> str:
    """One effect as text for the model: kind, target and how well the target is known."""
    match effect.resolution:
        case Known():
            return f"{effect.kind} {effect.target}"
        case Bounded():
            return f"{effect.kind} anything under {effect.target}"
        case Unknown(reason=reason):
            return f"{effect.kind} an unknown target ({reason})"
    return str(effect.kind)


def input_for(entry: DeniedEntry, new_command: str, turn: int) -> ClassifierInput:
    """The classifier input comparing `new_command`, at `turn`, with one refused command."""
    return ClassifierInput(
        rejected_command=entry.command,
        rejected_rules=tuple(dict.fromkeys(str(r.rule) for r in entry.decision.reasons)),
        rejected_effects=tuple(
            dict.fromkeys(describe_effect(r.effect) for r in entry.decision.reasons if r.effect is not None)
        ),
        new_command=new_command,
        turns_since=turn - entry.turn,
    )
