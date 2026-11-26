"""Tests for the corpus format and its loader (`bench/schema.md`, `bench/corpus.py`)."""

import json
import re
from pathlib import Path

import pytest

from bench.corpus import GOAL_KINDS, CorpusError, Kind, Status, load_corpus, load_corpus_dir
from compiler.types import RuleId, Verdict
from gate.types import OBSERVABLE_KINDS

CORPUS = Path(__file__).resolve().parents[1] / "corpus"
SCHEMA = Path(__file__).resolve().parents[1] / "schema.md"

GOOD = {
    "id": "quoting-999", "kind": "bypass", "technique": "quoting", "commands": ["r''m ~/x"],
    "expected": ["DENY"], "goal": [{"kind": "delete", "path": "~/x"}], "status": "expected",
    "provenance": "ours",
}  # fmt: skip


def line(**changes) -> str:
    entry = {**GOOD, **changes}
    return json.dumps({k: v for k, v in entry.items() if v is not None})


def problems(text: str) -> list[str]:
    with pytest.raises(CorpusError) as exc:
        load_corpus(text)
    return exc.value.problems


def test_the_committed_corpus_loads():
    entries = load_corpus_dir(CORPUS)
    assert len({e.id for e in entries}) == len(entries)
    assert {e.kind for e in entries} == {Kind.BYPASS, Kind.BENIGN}


def test_goal_kinds_are_what_the_sandbox_can_observe():
    assert GOAL_KINDS == OBSERVABLE_KINDS


def test_the_worked_example_in_the_schema_loads():
    block = re.search(r"```json\n(.*?)```", SCHEMA.read_text(encoding="utf-8"), re.S).group(1)
    (entry,) = load_corpus(" ".join(block.split("\n")))
    assert entry.commands == ("rm ~/notes.txt", "find ~ -name notes.txt -delete")
    assert entry.expected == (Verdict.DENY, Verdict.DENY) and entry.rules == (RuleId.R4, RuleId.R4)


def test_a_good_line_and_its_defaults():
    (entry,) = load_corpus(line())
    assert (
        entry.rules == (None,) and entry.setup == () and entry.notes == "" and entry.status is Status.EXPECTED
    )
    assert entry.line == 1


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"id": "Quoting_1"}, "lower-case"),
        ({"kind": "attack"}, "kind"),
        ({"technique": "magic"}, "technique"),
        ({"technique": "none"}, "names its technique"),
        ({"commands": []}, "non-empty list"),
        ({"expected": ["DENY", "DENY"]}, "2 verdicts for 1 commands"),
        ({"expected": ["BLOCK"]}, "ALLOW, ESCALATE or DENY"),
        ({"rules": ["R99"]}, "not one of R1"),
        ({"rules": ["R4", "R4"]}, "one per command"),
        ({"goal": []}, "names the effect"),
        ({"goal": [{"kind": "read", "path": "~/x"}]}, "not observable"),
        ({"goal": [{"kind": "delete", "path": "notes.txt"}]}, "must start with"),
        ({"goal": [{"kind": "delete", "path": "~/../etc/x"}]}, "'..'"),
        ({"setup": [{"path": "/etc/x", "content": "c"}]}, "~/ or {workspace}/"),
        ({"status": "flaky"}, "status"),
        ({"provenance": "the internet"}, "provenance"),
        ({"surprise": 1}, "unknown field"),
        ({"provenance": None}, "missing field 'provenance'"),
        ({"technique": "multi-step"}, "at least two commands"),
        ({"status": "known-gap"}, "why we miss it"),
        ({"commands": ["echo 'unterminated"]}, "does not parse"),
    ],
)
def test_bad_entries_are_refused(changes, message):
    found = problems(line(**changes))
    assert any(message in p for p in found), found


@pytest.mark.parametrize(
    "changes",
    [
        {"kind": ["bypass"]},
        {"expected": [["DENY"]]},
        {"rules": [{"r": 1}]},
        {"goal": [{"kind": ["delete"], "path": "~/x"}]},
        {"goal": [{"kind": "delete", "path": 7}]},
        {"setup": [{"path": "~/x", "content": 7}]},
        {"commands": "rm x"},
        {"notes": 3},
        {"goal": "x"},
    ],
)
def test_wrong_json_types_are_reported_not_raised(changes):
    assert problems(line(**changes))


def test_benign_entries_have_no_technique_or_goal():
    found = problems(line(kind="benign", expected=["ALLOW"]))
    assert any("technique 'none'" in p for p in found) and any("no goal" in p for p in found)
    assert load_corpus(line(kind="benign", technique="none", expected=["ALLOW"], goal=[]))


def test_an_unparseable_command_must_expect_r1():
    assert load_corpus(line(commands=["echo 'unterminated"], expected=["DENY"], rules=["R1"]))


def test_every_problem_is_reported_with_its_line():
    text = "\n".join([line(), "not json", line(id="quoting-998", kind="attack"), line()])
    found = problems(text)
    assert any(p.startswith("line 2: not valid JSON") for p in found)
    assert any(p.startswith("line 3: kind") for p in found)
    assert any(p.startswith("line 4: id 'quoting-999' is used twice") for p in found)


def test_ids_are_unique_across_files(tmp_path):
    (tmp_path / "a.jsonl").write_text(line() + "\n", encoding="utf-8")
    (tmp_path / "b.jsonl").write_text(line() + "\n", encoding="utf-8")
    with pytest.raises(CorpusError) as exc:
        load_corpus_dir(tmp_path)
    assert exc.value.problems == ["b.jsonl: line 1: id 'quoting-999' is used twice"]


def test_blank_lines_are_ignored():
    assert len(load_corpus("\n" + line() + "\n\n")) == 1
