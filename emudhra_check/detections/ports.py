"""ports.py: what the detections need from the outside world, and the values that cross that boundary.

Defines the values the adapters return to the detections: Located, CommandResult, Skipped, ProbeStatus
and ProbeRun. The adapters import these from here, so data crossing the boundary belongs to the inner side.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

from emudhra_check.scope import FileId


@dataclass(frozen=True)
class Located:
    """A tool found on PATH or at a fixed path."""

    path: Path
    real: Path
    permitted: bool
    file_id: Optional[FileId]


@dataclass(frozen=True)
class CommandResult:
    returncode: Optional[int]
    stdout: str
    stderr: str
    timed_out: bool
    overran: bool


@dataclass(frozen=True)
class Skipped:
    """A read that returned no bytes, and why."""

    reason: str


MISSING = "missing"
UNREADABLE = "unreadable"
EXCLUDED = "inside an excluded directory"
CHANGED = "changed since indexed"
TOO_LARGE = "too large"


class ProbeStatus(Enum):
    OK = "ok"
    NO_SHELL = "no shell"
    FAILED = "failed"
    TIMEOUT = "timeout"
    OVERRUN = "overrun"


@dataclass(frozen=True)
class ProbeRun:
    status: ProbeStatus
    output: bytes
