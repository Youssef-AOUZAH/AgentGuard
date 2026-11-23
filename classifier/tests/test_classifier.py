"""Tests for the classifier: the S6 records, the NLI pipeline with a fake model, and calibration.

No model is downloaded: `NLIScorer` is given a fake pipeline that records what it was asked, so
these tests check what we send to the model and how we read its answer, which is the part that is
ours. Whether the real model is any good is classifier H1, measured in `bench/`, not here.
"""

from __future__ import annotations

from pathlib import PurePosixPath

import pytest
from hypothesis import given
from hypothesis import strategies as st

from classifier.calibrate import (
    brier_score,
    choose_threshold,
    counts_at,
    expected_calibration_error,
    reliability,
)
from classifier.labels import (
    LABELS,
    ClassifierInput,
    LabelScores,
    describe_effect,
    input_for,
)
from classifier.pipeline import NLIScorer, RetryClassifier, StubScorer, premise
from compiler.syntax import Script
from compiler.types import (
    Bounded,
    Decision,
    DeniedEntry,
    Effect,
    EffectKind,
    Known,
    Reason,
    RuleId,
    Unknown,
    Verdict,
)

ORIGIN = Script((), "")
SAMPLE = ClassifierInput(
    rejected_command="rm -rf ~/.ssh",
    rejected_rules=("R4",),
    rejected_effects=("delete anything under /home/u/.ssh",),
    new_command="find ~/.ssh -delete",
    turns_since=1,
)


# --------------------------------------------------------------------------- records (S6)


def test_input_round_trips_through_json():
    line = SAMPLE.to_json()
    assert ClassifierInput.from_json(line) == SAMPLE
    assert "\n" not in line


def test_dataset_line_with_a_label_still_reads():
    line = SAMPLE.to_json()[:-1] + ', "label": "retry-blocked-effect"}'
    assert ClassifierInput.from_json(line) == SAMPLE


@given(st.text(), st.text(), st.integers(min_value=0, max_value=1000))
def test_json_round_trip_for_any_text(rejected, new, turns):
    inp = ClassifierInput(rejected, ("R1",), (), new, turns)
    assert ClassifierInput.from_json(inp.to_json()) == inp


def test_effects_are_described_as_text():
    path = PurePosixPath("/w/build")
    assert describe_effect(Effect(EffectKind.DELETE, path, Known(), ORIGIN)) == "delete /w/build"
    assert (
        describe_effect(Effect(EffectKind.DELETE, path, Bounded(), ORIGIN))
        == "delete anything under /w/build"
    )
    unknown = Effect(EffectKind.WRITE, None, Unknown("target is a substitution"), ORIGIN)
    assert describe_effect(unknown) == "write an unknown target (target is a substitution)"


def test_input_for_a_denied_entry():
    effect = Effect(EffectKind.DELETE, PurePosixPath("/h/.ssh"), Bounded(), ORIGIN)
    decision = Decision(
        Verdict.DENY, (Reason(RuleId.R4, effect), Reason(RuleId.R4, effect), Reason(RuleId.R2, None))
    )
    inp = input_for(DeniedEntry(3, "rm -rf ~/.ssh", decision), "find ~/.ssh -delete", 5)
    assert inp.rejected_rules == ("R4", "R2")
    assert inp.rejected_effects == ("delete anything under /h/.ssh",)
    assert inp.turns_since == 2


def test_scores_are_probabilities():
    with pytest.raises(ValueError):
        LabelScores({"x": 1.5}, model="m")
    scores = LabelScores({"a": 0.2, "b": 0.7}, model="m")
    assert scores.top() == "b" and scores["a"] == 0.2


def test_provisional_labels_have_unique_names_and_hypotheses():
    assert len({s.name for s in LABELS}) == len(LABELS)
    assert len({s.hypothesis for s in LABELS}) == len(LABELS)
    assert all("{" not in s.hypothesis for s in LABELS)  # the pipeline formats with "{}"


# --------------------------------------------------------------------------- the NLI pipeline


class FakePipeline:
    """Answers like the transformers zero-shot pipeline, in a shuffled order, and records calls."""

    def __init__(self, by_hypothesis):
        self.by_hypothesis = by_hypothesis
        self.calls = []

    def __call__(self, text, *, candidate_labels, hypothesis_template, multi_label):
        self.calls.append((text, list(candidate_labels), hypothesis_template, multi_label))
        ordered = sorted(candidate_labels, key=lambda h: -self.by_hypothesis[h])
        return {"sequence": text, "labels": ordered, "scores": [self.by_hypothesis[h] for h in ordered]}


def fake_for(values):
    return FakePipeline({spec.hypothesis: values[spec.name] for spec in LABELS})


def test_nli_scores_map_back_to_label_names():
    values = {"retry-blocked-effect": 0.91, "obfuscation": 0.12, "benign-next-step": 0.05}
    pipe = fake_for(values)
    scores = NLIScorer(pipeline=pipe).score(SAMPLE)
    assert dict(scores.scores) == values
    text, candidates, template, multi = pipe.calls[0]
    assert template == "{}"
    assert candidates == [spec.hypothesis for spec in LABELS]
    assert multi is True  # labels are independent unless EXCLUSIVE says otherwise
    assert scores.meta["premise"] == "with-context"


def test_exclusive_labels_use_one_softmax():
    pipe = fake_for({"retry-blocked-effect": 0.6, "obfuscation": 0.3, "benign-next-step": 0.1})
    NLIScorer(pipeline=pipe, exclusive=True).score(SAMPLE)
    assert pipe.calls[0][3] is False


def test_premise_with_and_without_context():
    full = premise(SAMPLE)
    assert "rm -rf ~/.ssh" in full and "R4" in full and "find ~/.ssh -delete" in full
    bare = premise(SAMPLE, with_context=False)
    assert "rm -rf" not in bare and "R4" not in bare and "find ~/.ssh -delete" in bare
    pipe = fake_for({s.name: 0.5 for s in LABELS})
    NLIScorer(pipeline=pipe, with_context=False).score(SAMPLE)
    assert pipe.calls[0][0] == bare


def test_premise_counts_turns():
    later = ClassifierInput("a", (), (), "b", 4)
    assert "4 commands later" in premise(later)
    assert "effects we could not determine" in premise(later)


def test_retry_classifier_fires_at_threshold():
    stub = StubScorer({"retry-blocked-effect": 0.5, "obfuscation": 0.49, "benign-next-step": 0.9})
    judgement = RetryClassifier(stub, {"retry-blocked-effect": 0.5, "obfuscation": 0.5}).judge(SAMPLE)
    assert [s.name for s in judgement.fired] == ["retry-blocked-effect"]  # no threshold, never fires


def test_retry_classifier_rejects_unknown_labels():
    with pytest.raises(ValueError):
        RetryClassifier(StubScorer({}), {"no-such-label": 0.5})


# --------------------------------------------------------------------------- calibration


PROBS = [0.1, 0.2, 0.35, 0.4, 0.6, 0.7, 0.8, 0.9]
TRUTH = [False, False, True, False, True, False, True, True]


def test_counts():
    c = counts_at(0.6, PROBS, TRUTH)
    assert (c.tp, c.fp, c.fn, c.tn) == (3, 1, 1, 3)
    assert c.precision == 0.75 and c.recall == 0.75


def test_threshold_by_f1():
    best = choose_threshold(PROBS, TRUTH)
    f1 = counts_at(best, PROBS, TRUTH).f1
    assert all(counts_at(t, PROBS, TRUTH).f1 <= f1 for t in PROBS)


def test_threshold_by_precision_floor_is_the_lowest_that_reaches_it():
    t = choose_threshold(PROBS, TRUTH, min_precision=1.0)
    assert t == 0.8
    assert counts_at(t, PROBS, TRUTH).precision == 1.0


def test_unreachable_precision_never_fires():
    t = choose_threshold([0.9], [False], min_precision=0.5)
    assert t > 1.0 and counts_at(t, [0.9, 1.0], [True, True]).tp == 0


def test_calibration_measures():
    assert brier_score([1.0, 0.0], [True, False]) == 0.0
    assert brier_score([0.5, 0.5], [True, False]) == 0.25
    assert expected_calibration_error([0.95, 0.95, 0.05, 0.05], [True, True, False, False]) == pytest.approx(
        0.05
    )
    bins = reliability([0.05, 0.95, 1.0], [False, True, True], bins=10)
    assert [(b.count, b.frequency) for b in bins] == [(1, 0.0), (2, 1.0)]


def test_bad_inputs_are_refused():
    with pytest.raises(ValueError):
        brier_score([0.5], [True, False])
    with pytest.raises(ValueError):
        choose_threshold([], [])
    with pytest.raises(ValueError):
        reliability([1.2], [True])
