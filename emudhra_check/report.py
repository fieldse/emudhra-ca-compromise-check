"""report.py: findings, output lines and the run summary.

Defines the levels, the Subject and Finding values every detection yields, the sanitising that
keeps each output field on one line, the stderr note format, and the SUMMARY line with its exit code.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from emudhra_check.limits import MAX_FIELD_CHARS


class Level(Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    INFO = "info"
    SKIP = "skip"
    ERROR = "error"


ALWAYS_SHOWN = frozenset({Level.FAIL, Level.WARN, Level.ERROR})


def sanitise(text: str, limit: int = MAX_FIELD_CHARS) -> str:
    """Replace control, format, surrogate and separator characters with ? and cut to limit."""
    out = []
    for char in text[: limit + 1]:
        category = unicodedata.category(char)
        if category[0] == "C" or (category[0] == "Z" and char != " "):
            out.append("?")
        else:
            out.append(char)
    clean = "".join(out)
    if len(clean) > limit:
        return clean[:limit] + "..."
    return clean


def note(prog: str, text: str) -> str:
    """Format one stderr note."""
    return f"{sanitise(prog)}: note: {sanitise(text)}"


@dataclass(frozen=True)
class Subject:
    name: str
    where: str


@dataclass(frozen=True)
class Finding:
    level: Level
    subject: Optional[Subject]
    detail: str

    def line(self) -> str:
        """Return the output line, every field sanitised."""
        level = f"{self.level.name:<4}"
        if self.subject is None:
            return f"{level}  {sanitise(self.detail)}"
        name = sanitise(self.subject.name)
        where = sanitise(self.subject.where)
        return f"{level}  {name} [{where}] {sanitise(self.detail)}"


def is_shown(level: Level, quiet: bool) -> bool:
    """Return whether a finding is printed: FAIL, WARN and ERROR always, the rest without -q."""
    return level in ALWAYS_SHOWN or not quiet


@dataclass
class Summary:
    counts: dict[Level, int] = field(
        default_factory=lambda: {level: 0 for level in Level}
    )

    def add(self, level: Level) -> None:
        """Count one finding."""
        self.counts[level] += 1

    def line(self) -> str:
        """Return the SUMMARY line."""
        fields = " ".join(f"{level.value}={self.counts[level]}" for level in Level)
        return f"SUMMARY {fields}"

    def exit_code(self, strict: bool) -> int:
        """Return 1 on FAIL, or on WARN or ERROR when strict, else 0."""
        if self.counts[Level.FAIL]:
            return 1
        if strict and (self.counts[Level.WARN] or self.counts[Level.ERROR]):
            return 1
        return 0
