"""Thresholds and calibration for one label (piece 2a).

Takes in, for one label, the model's probabilities on a set of examples and whether each example
really has that label. Returns a threshold, or a measure of how far the probabilities can be
trusted as probabilities.

The rule that matters more than any function here: **thresholds are chosen on the development
split only**, and the test split is scored once, with the thresholds fixed, for the number that
goes in `classifier/hypotheses.md`. Choosing a threshold on the test split and reporting the test
score is fitting to the test set, however indirect it looks.

- `choose_threshold` picks the threshold with the best F1, or the lowest threshold whose precision
  reaches a floor. The floor is the useful mode for us: a false positive refuses a benign command,
  which is the failure the field is judged on, so "the most recall we can get at 95% precision"
  is the question to ask.
- `expected_calibration_error`, `brier_score` and `reliability` say whether 0.8 means "right four
  times in five". Zero-shot NLI scores usually are not calibrated, which is worth reporting
  whatever threshold is chosen.

Pure Python, no model and no numpy, so CI can test it.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Counts:
    tp: int
    fp: int
    fn: int
    tn: int

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0


def _check(probs: Sequence[float], truth: Sequence[bool]) -> None:
    if len(probs) != len(truth):
        raise ValueError(f"{len(probs)} probabilities but {len(truth)} labels")
    if not probs:
        raise ValueError("no examples")
    if any(not 0.0 <= p <= 1.0 for p in probs):
        raise ValueError("probabilities must be in [0, 1]")


def counts_at(threshold: float, probs: Sequence[float], truth: Sequence[bool]) -> Counts:
    """The confusion counts when a label fires at `p >= threshold`."""
    _check(probs, truth)
    tp = sum(1 for p, t in zip(probs, truth, strict=True) if p >= threshold and t)
    fp = sum(1 for p, t in zip(probs, truth, strict=True) if p >= threshold and not t)
    fn = sum(1 for p, t in zip(probs, truth, strict=True) if p < threshold and t)
    return Counts(tp, fp, fn, len(probs) - tp - fp - fn)


def choose_threshold(
    probs: Sequence[float], truth: Sequence[bool], *, min_precision: float | None = None
) -> float:
    """The threshold to use for one label, from development data.

    Candidates are the observed probabilities. Without `min_precision`, the one with the best F1,
    preferring the higher threshold on a tie (fewer refusals for the same F1). With it, the lowest
    threshold whose precision reaches the floor, which maximises recall under the constraint; if
    none does, 1.0 plus a hair is returned, so the label never fires rather than firing badly.
    """
    _check(probs, truth)
    candidates = sorted(set(probs))
    if min_precision is not None:
        for threshold in candidates:
            if counts_at(threshold, probs, truth).precision >= min_precision:
                return threshold
        return float.fromhex("0x1.0000000000001p+0")  # just above 1.0
    best = max(candidates, key=lambda t: (counts_at(t, probs, truth).f1, t))
    return best


def brier_score(probs: Sequence[float], truth: Sequence[bool]) -> float:
    """Mean squared distance between probability and outcome. 0 is perfect; always saying 0.5
    scores 0.25."""
    _check(probs, truth)
    return sum((p - float(t)) ** 2 for p, t in zip(probs, truth, strict=True)) / len(probs)


@dataclass(frozen=True, slots=True)
class Bin:
    low: float
    high: float
    count: int
    mean_probability: float
    frequency: float  # how often the label was really present among these examples


def reliability(probs: Sequence[float], truth: Sequence[bool], bins: int = 10) -> list[Bin]:
    """Equal-width bins over [0, 1]; empty bins are left out. Plot `frequency` against
    `mean_probability`: a calibrated model lies on the diagonal."""
    _check(probs, truth)
    if bins < 1:
        raise ValueError("need at least one bin")
    grouped: list[list[tuple[float, bool]]] = [[] for _ in range(bins)]
    for p, t in zip(probs, truth, strict=True):
        grouped[min(int(p * bins), bins - 1)].append((p, t))
    result = []
    for index, members in enumerate(grouped):
        if members:
            result.append(
                Bin(
                    low=index / bins,
                    high=(index + 1) / bins,
                    count=len(members),
                    mean_probability=sum(p for p, _ in members) / len(members),
                    frequency=sum(1 for _, t in members if t) / len(members),
                )
            )
    return result


def expected_calibration_error(probs: Sequence[float], truth: Sequence[bool], bins: int = 10) -> float:
    """The gap between confidence and frequency, averaged over bins weighted by their size."""
    total = len(probs)
    return sum(
        b.count / total * abs(b.mean_probability - b.frequency) for b in reliability(probs, truth, bins)
    )
