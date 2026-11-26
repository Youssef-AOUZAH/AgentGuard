"""Baselines the compiler is measured against (`AGENTS.md`, H1).

Each is an `Analyzer`, so the harness runs it through the same gate and sandbox as the compiler,
and the only thing that differs between two runs is the middle end.

`StringDenylist` is the baseline the project is defined against: a list of patterns over the
command text, the way agent harnesses commonly configure command blocking. It refuses a command
whose text matches a pattern and allows everything else. It reports no effects, because it has
none to report: it never looks past the string.

Its refusals cite `R1`, because `Decision` requires a rule id and a baseline has none of ours;
the detail names the pattern instead. Run baselines with `check_rules=False` in the harness, so
the score compares verdicts only.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from compiler.syntax import Script
from compiler.types import Decision, Effect, Reason, RuleId, SessionState, Verdict

# Generic patterns in the style of a hand-written denylist: dangerous programs at the start of a
# command or after a separator, privilege, piping into a shell, decoding, and well-known secret
# paths. Deliberately reasonable rather than a straw man; the point of the comparison is what a
# careful string list still misses.
DEFAULT_PATTERNS = (
    r"(?:^|[;&|]\s*)(?:sudo|su|doas)\b",
    r"(?:^|[;&|]\s*)rm\s",
    r"(?:^|[;&|]\s*)(?:chmod|chown|chgrp)\s",
    r"(?:^|[;&|]\s*)(?:dd|mkfs\S*|shred)\s",
    r"\|\s*(?:sh|bash|zsh|dash)\b",
    r"\b(?:base64|xxd)\s+(?:-d|--decode|-r)\b",
    r"(?:^|[;&|]\s*)(?:eval|source)\s",
    r"~/\.(?:ssh|aws|gnupg|kube)\b|\.env\b|/etc/(?:passwd|shadow)\b",
    r"(?:^|[;&|]\s*)(?:curl|wget)\s.*(?:-T|--upload-file|-d\s*@)",
    r"-delete\b",
)


class StringDenylist:
    """Refuse a command whose text matches any pattern; allow everything else."""

    def __init__(self, patterns: Iterable[str] = DEFAULT_PATTERNS) -> None:
        self.patterns = tuple((p, re.compile(p)) for p in patterns)

    def analyze(self, script: Script, state: SessionState) -> tuple[frozenset[Effect], Decision]:
        text = script.src
        for source, pattern in self.patterns:
            if pattern.search(text):
                return frozenset(), Decision(Verdict.DENY, (Reason(RuleId.R1, None, f"denylist: {source}"),))
        return frozenset(), Decision(Verdict.ALLOW)


__all__ = ["DEFAULT_PATTERNS", "StringDenylist"]
