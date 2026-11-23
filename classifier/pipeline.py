"""The zero-shot NLI pipeline (piece 2a): a probability per label for one `ClassifierInput`.

Natural language inference asks whether a premise entails a hypothesis. Zero-shot classification
uses that to label text with categories the model was never trained on: the input becomes the
premise, each label's sentence in `classifier/labels.py` becomes a hypothesis, and the model's
entailment probability is the label's score. No training data is needed, which is the point: the
dataset (2b) is for choosing thresholds and measuring, not for fitting.

Three pieces:

- `Scorer` is the interface: `score(ClassifierInput) -> LabelScores`. `StubScorer` returns fixed
  scores, for tests and for running the gate without a model; CI only ever uses it.
- `NLIScorer` runs an open-weight NLI model through the `transformers` zero-shot pipeline, loaded
  on first use. `transformers` and `torch` are in `requirements.txt` but not in
  `requirements-dev.txt`, so nothing here imports them until a real score is asked for. Which
  model is still an open question in `docs/decisions.md`; the default is a candidate, not a
  choice, and the choice gets recorded there with its measured latency.
- `RetryClassifier` applies a threshold per label and says which labels fired. Thresholds come
  from `classifier/calibrate.py`, run on the development split only.

`with_context` is classifier hypothesis H2: with it, the premise describes the refused command
and why it was refused before the new command; without it, the premise is the new command alone.

What it deliberately does not do: decide anything. Turning fired labels into a tighter verdict is
the gate's job, and the gate may only tighten (`AGENTS.md`).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from classifier.labels import EXCLUSIVE, LABELS, ClassifierInput, LabelScores, LabelSpec

# A candidate, not a decision: see "Which NLI model" under Open in docs/decisions.md.
DEFAULT_MODEL = "MoritzLaurer/deberta-v3-base-zeroshot-v2.0"


class Scorer(Protocol):
    def score(self, inp: ClassifierInput) -> LabelScores: ...


class StubScorer:
    """Fixed scores, or scores computed by a plain function of the input. No model involved."""

    def __init__(self, scores: Mapping[str, float] | Callable[[ClassifierInput], Mapping[str, float]]):
        self._scores = scores

    def score(self, inp: ClassifierInput) -> LabelScores:
        scores = self._scores(inp) if callable(self._scores) else self._scores
        return LabelScores(scores, model="stub")


def premise(inp: ClassifierInput, *, with_context: bool = True) -> str:
    """The text the model reads. Kept in one place, because changing it changes every number."""
    new = f"The agent then ran this command: {inp.new_command}"
    if not with_context:
        return f"An agent ran this command: {inp.new_command}"
    rules = ", ".join(inp.rejected_rules) or "no rule"
    effects = "; ".join(inp.rejected_effects) or "effects we could not determine"
    turns = "immediately after" if inp.turns_since <= 1 else f"{inp.turns_since} commands later"
    return (
        f"An agent's command was blocked: {inp.rejected_command}\n"
        f"It was blocked under {rules} because it would {effects}.\n"
        f"{new} ({turns})."
    )


class NLIScorer:
    """Zero-shot scores from an NLI model.

    `pipeline` may be passed in, for tests: any callable with the `transformers` zero-shot
    signature, `pipeline(text, candidate_labels=[...], hypothesis_template=..., multi_label=...)`
    returning `{"labels": [...], "scores": [...]}`.
    """

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        labels: Sequence[LabelSpec] = LABELS,
        *,
        exclusive: bool = EXCLUSIVE,
        with_context: bool = True,
        device: int = -1,
        pipeline: Callable[..., Any] | None = None,
    ) -> None:
        self.model = model
        self.labels = tuple(labels)
        self.exclusive = exclusive
        self.with_context = with_context
        self.device = device
        self._pipeline = pipeline

    def _load(self) -> Callable[..., Any]:
        if self._pipeline is None:
            from transformers import pipeline  # heavy and optional: imported on first use only

            self._pipeline = pipeline("zero-shot-classification", model=self.model, device=self.device)
        return self._pipeline

    def score(self, inp: ClassifierInput) -> LabelScores:
        by_hypothesis = {spec.hypothesis: spec.name for spec in self.labels}
        result = self._load()(
            premise(inp, with_context=self.with_context),
            candidate_labels=list(by_hypothesis),
            hypothesis_template="{}",  # each hypothesis is already a full sentence
            multi_label=not self.exclusive,
        )
        scores = {
            by_hypothesis[h]: min(1.0, max(0.0, float(s)))
            for h, s in zip(result["labels"], result["scores"], strict=True)
        }
        context = "with-context" if self.with_context else "new-command-only"
        return LabelScores(scores, model=self.model, exclusive=self.exclusive, meta={"premise": context})


@dataclass(frozen=True, slots=True)
class Judgement:
    """The scores, and the labels whose score reached their threshold."""

    scores: LabelScores
    fired: tuple[LabelSpec, ...]


class RetryClassifier:
    """A scorer plus a threshold per label. A label with no threshold never fires."""

    def __init__(
        self,
        scorer: Scorer,
        thresholds: Mapping[str, float],
        labels: Sequence[LabelSpec] = LABELS,
    ) -> None:
        known = {spec.name for spec in labels}
        unknown = set(thresholds) - known
        if unknown:
            raise ValueError(f"thresholds for labels that do not exist: {sorted(unknown)}")
        self.scorer = scorer
        self.thresholds = dict(thresholds)
        self.labels = tuple(labels)

    def judge(self, inp: ClassifierInput) -> Judgement:
        scores = self.scorer.score(inp)
        fired = tuple(
            spec
            for spec in self.labels
            if spec.name in self.thresholds
            and scores.scores.get(spec.name, 0.0) >= self.thresholds[spec.name]
        )
        return Judgement(scores, fired)
