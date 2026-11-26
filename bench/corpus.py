"""Loading and validating corpus files (`bench/schema.md`, `docs/interfaces.md` S7).

Takes in the text of a `bench/corpus/*.jsonl` file. Gives back a tuple of `Entry`, or raises
`CorpusError` listing every problem with its line number, so one run shows every mistake in a
file. The harness and any regression test read the corpus through `load_corpus`, never by hand.

Nothing here runs a command. The one check that looks inside a command uses
`compiler.parser.parse_source`, which only parses: a command that does not parse must expect
`DENY` by R1.

What this module deliberately does not handle: running entries, binding `~` and `{workspace}` to
a sandbox's directories, and scoring. Those belong to the harness.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from compiler.parser import parse_source
from compiler.syntax import LexError, ParseError
from compiler.types import EffectKind, RuleId, Verdict

_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_PROVENANCE = re.compile(
    r"ours|mitre:T\d{4}(?:\.\d{3})?|gtfobins:[a-z0-9._+-]+|redcode:[A-Za-z0-9._-]+|arxiv:\d{4}\.\d{4,5}"
)
# The kinds the sandbox can observe (`gate.types.OBSERVABLE_KINDS`). Repeated rather than
# imported, so the bench's data format does not depend on the gate's code; a test keeps them equal.
GOAL_KINDS = frozenset({EffectKind.WRITE, EffectKind.APPEND, EffectKind.DELETE, EffectKind.PRIV_CHANGE})
MAX_CONTENT = 4096

_FIELDS = {
    "id", "kind", "technique", "commands", "expected", "rules", "goal", "setup", "status", "provenance",
    "notes",
}  # fmt: skip
_REQUIRED = {"id", "kind", "technique", "commands", "expected", "status", "provenance"}


class Kind(StrEnum):
    BYPASS = "bypass"
    BENIGN = "benign"


class Technique(StrEnum):
    QUOTING = "quoting"
    EXPANSION = "expansion"
    ENCODING = "encoding"
    ALTERNATIVE_TOOL = "alternative-tool"
    INDIRECTION = "indirection"
    MULTI_STEP = "multi-step"
    NONE = "none"


class Status(StrEnum):
    EXPECTED = "expected"
    KNOWN_GAP = "known-gap"


@dataclass(frozen=True, slots=True)
class Goal:
    """An effect a bypass tries to cause, on an anchored path (`~/`, `{workspace}/` or `/`)."""

    kind: EffectKind
    path: str


@dataclass(frozen=True, slots=True)
class SetupFile:
    path: str
    content: str


@dataclass(frozen=True, slots=True)
class Entry:
    id: str
    kind: Kind
    technique: Technique
    commands: tuple[str, ...]
    expected: tuple[Verdict, ...]
    rules: tuple[RuleId | None, ...]
    goal: tuple[Goal, ...]
    setup: tuple[SetupFile, ...]
    status: Status
    provenance: str
    notes: str
    line: int


class CorpusError(Exception):
    """A corpus file that cannot be used. `problems` holds one message per problem, each naming
    its line."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        super().__init__("the corpus cannot be loaded:\n" + "\n".join(f"  {p}" for p in problems))


def load_corpus(text: str, seen_ids: set[str] | None = None) -> tuple[Entry, ...]:
    """Every entry in `text`, or `CorpusError`. `seen_ids` carries ids across several files, so
    an id is unique in the whole corpus; it is updated with this file's ids."""
    seen = seen_ids if seen_ids is not None else set()
    entries: list[Entry] = []
    problems: list[str] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip():
            continue
        found: list[str] = []
        entry = _entry(raw, number, found)
        if entry is not None and entry.id in seen:
            found.append(f"id {entry.id!r} is used twice")
        problems += [f"line {number}: {p}" for p in found]
        if entry is not None and not found:
            seen.add(entry.id)
            entries.append(entry)
    if problems:
        raise CorpusError(problems)
    return tuple(entries)


def load_corpus_dir(directory: Path) -> tuple[Entry, ...]:
    """Every entry in every `*.jsonl` file under `directory`, with ids unique across them."""
    seen: set[str] = set()
    entries: list[Entry] = []
    problems: list[str] = []
    for path in sorted(directory.glob("*.jsonl")):
        try:
            entries += load_corpus(path.read_text(encoding="utf-8"), seen)
        except CorpusError as exc:
            problems += [f"{path.name}: {p}" for p in exc.problems]
    if problems:
        raise CorpusError(problems)
    return tuple(entries)


# --------------------------------------------------------------------------- one entry


def _entry(raw: str, line: int, problems: list[str]) -> Entry | None:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        problems.append(f"not valid JSON: {exc.msg}")
        return None
    if not isinstance(data, dict):
        problems.append("an entry must be a JSON object")
        return None
    for name in sorted(_REQUIRED - data.keys()):
        problems.append(f"missing field {name!r}")
    for name in sorted(data.keys() - _FIELDS):
        problems.append(f"unknown field {name!r}")
    if problems:
        return None

    entry_id = _string(data, "id", problems)
    if entry_id is not None and not _ID.fullmatch(entry_id):
        problems.append(f"id {entry_id!r} must be lower-case words and digits joined by '-'")
    kind = _enum(Kind, data, "kind", problems)
    technique = _enum(Technique, data, "technique", problems)
    status = _enum(Status, data, "status", problems)
    provenance = _string(data, "provenance", problems)
    if provenance is not None and not _PROVENANCE.fullmatch(provenance):
        problems.append(f"provenance {provenance!r} is not one of the forms in bench/schema.md")
    notes = data.get("notes", "")
    if not isinstance(notes, str):
        problems.append("notes must be a string")

    commands = _strings(data, "commands", problems)
    expected = tuple(_verdicts(data.get("expected"), problems))
    rules = tuple(_rules(data.get("rules"), len(commands), problems))
    if commands and len(expected) != len(commands):
        problems.append(f"expected has {len(expected)} verdicts for {len(commands)} commands")
    goal = tuple(_goals(data.get("goal", []), problems))
    setup = tuple(_setup(data.get("setup", []), problems))

    if status is Status.KNOWN_GAP and not (isinstance(notes, str) and notes.strip()):
        problems.append("a known gap says in notes why we miss it")
    if kind is Kind.BENIGN:
        if technique is not None and technique is not Technique.NONE:
            problems.append("a benign entry has technique 'none'")
        if goal:
            problems.append("a benign entry has no goal")
    if kind is Kind.BYPASS:
        if technique is Technique.NONE:
            problems.append("a bypass names its technique")
        if not goal:
            problems.append("a bypass names the effect it is trying to cause in 'goal'")
        if technique is Technique.MULTI_STEP and len(commands) < 2:
            problems.append("a multi-step entry has at least two commands")
    for index, command in enumerate(commands):
        _check_parses(command, expected, rules, index, problems)
    if problems:
        return None
    return Entry(entry_id, kind, technique, commands, expected, rules or (None,) * len(commands), goal, setup,
                 status, provenance, notes, line)  # type: ignore[arg-type]  # fmt: skip


def _check_parses(command: str, expected, rules, index: int, problems: list[str]) -> None:
    try:
        parse_source(command)
    except (LexError, ParseError) as exc:
        step_expected = expected[index] if index < len(expected) else None
        step_rule = rules[index] if index < len(rules) else None
        if step_expected is not Verdict.DENY or step_rule is not RuleId.R1:
            problems.append(
                f"command {index + 1} does not parse ({exc}); expect DENY with rule R1, or fix it"
            )


def _string(data: dict, name: str, problems: list[str]) -> str | None:
    value = data.get(name)
    if not isinstance(value, str) or not value:
        problems.append(f"{name} must be a non-empty string")
        return None
    return value


def _enum(enum, data: dict, name: str, problems: list[str]):
    value = data.get(name)
    try:
        return enum(value)
    except (ValueError, TypeError):
        choices = ", ".join(repr(m.value) for m in enum)
        problems.append(f"{name} {value!r} is not one of {choices}")
        return None


def _strings(data: dict, name: str, problems: list[str]) -> tuple[str, ...]:
    value = data.get(name)
    if not isinstance(value, list) or not value or not all(isinstance(v, str) and v for v in value):
        problems.append(f"{name} must be a non-empty list of non-empty strings")
        return ()
    return tuple(value)


def _verdicts(value, problems: list[str]) -> Iterable[Verdict]:
    if not isinstance(value, list):
        problems.append("expected must be a list of verdicts")
        return
    for item in value:
        if not isinstance(item, str) or item not in Verdict.__members__:
            problems.append(f"verdict {item!r} is not ALLOW, ESCALATE or DENY")
            continue
        yield Verdict[item]


def _rules(value, count: int, problems: list[str]) -> Iterable[RuleId | None]:
    if value is None:
        return
    if not isinstance(value, list) or len(value) != count:
        problems.append(f"rules must be a list of {count} rule ids or nulls, one per command")
        return
    for item in value:
        if item is None:
            yield None
        elif isinstance(item, str) and item in RuleId._value2member_map_:
            yield RuleId(item)
        else:
            problems.append(f"rule {item!r} is not one of R1 to R{len(RuleId)}")


def _goals(value, problems: list[str]) -> Iterable[Goal]:
    if not isinstance(value, list):
        problems.append("goal must be a list")
        return
    for item in value:
        if not isinstance(item, dict) or set(item) != {"kind", "path"}:
            problems.append("each goal is {'kind': ..., 'path': ...}")
            continue
        kind = EffectKind._value2member_map_.get(item["kind"]) if isinstance(item["kind"], str) else None
        if kind not in GOAL_KINDS:
            names = ", ".join(sorted(k.value for k in GOAL_KINDS))
            problems.append(
                f"goal kind {item['kind']!r} is not observable in the sandbox; use one of {names}"
            )
            continue
        if _path_problem(item["path"], problems, allow_absolute=True):
            yield Goal(kind, item["path"])  # type: ignore[arg-type]


def _setup(value, problems: list[str]) -> Iterable[SetupFile]:
    if not isinstance(value, list):
        problems.append("setup must be a list")
        return
    for item in value:
        if not isinstance(item, dict) or set(item) != {"path", "content"}:
            problems.append("each setup file is {'path': ..., 'content': ...}")
            continue
        content = item["content"]
        if not isinstance(content, str) or len(content) > MAX_CONTENT:
            problems.append(f"setup content must be a string of at most {MAX_CONTENT} characters")
            continue
        if _path_problem(item["path"], problems, allow_absolute=False):
            yield SetupFile(item["path"], content)


def _path_problem(path, problems: list[str], allow_absolute: bool) -> bool:
    """True when `path` is usable; otherwise records why not."""
    anchors = ("~/", "{workspace}/") + (("/",) if allow_absolute else ())
    if not isinstance(path, str) or not path.startswith(anchors):
        where = "~/, {workspace}/ or /" if allow_absolute else "~/ or {workspace}/"
        problems.append(f"path {path!r} must start with {where}")
        return False
    if ".." in path.split("/"):
        problems.append(f"path {path!r} must not contain '..'")
        return False
    return True


__all__ = ["CorpusError", "Entry", "GOAL_KINDS", "Goal", "Kind", "SetupFile", "Status", "Technique",
           "load_corpus", "load_corpus_dir"]  # fmt: skip
