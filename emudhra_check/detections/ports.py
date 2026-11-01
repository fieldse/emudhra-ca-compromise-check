"""ports.py: what the detections need from the outside world, and the values that cross that boundary.

Defines the Detection interface, the Context every detection reads, the Ledger of claimed files, the
Files, Commands, Host and Images protocols with only the methods detections call, and the values the
adapters return: Located, CommandResult, Skipped, ProbeStatus and ProbeRun. The adapters import these
from here, so data crossing the boundary belongs to the inner side.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import ClassVar, Iterator, Optional, Protocol, Sequence, Union

from emudhra_check.certificates import Buffer
from emudhra_check.hostenv import HostEnvironment
from emudhra_check.report import Finding
from emudhra_check.scope import FileId, FileInterests, Index, ScanScope


@dataclass(frozen=True)
class Located:
    """A tool found on PATH or at a fixed path. writable is true when the check runs as root and a
    non-root user could change the tool's file or a directory above it."""

    path: Path
    real: Path
    permitted: bool
    file_id: Optional[FileId]
    writable: bool = False


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


class Ledger:
    """Claimed file ids. A claim only suppresses a second report of the same file.
    No verdict, level or detail depends on which detection claimed first.
    An id with ino 0 (a file system without stable inode numbers) is never recorded."""

    def __init__(self) -> None:
        self.claimed: set[FileId] = set()

    def claim(self, file_id: FileId) -> bool:
        """Record file_id and return True, or return False when it was already claimed."""
        if file_id.ino == 0:
            return True
        if file_id in self.claimed:
            return False
        self.claimed.add(file_id)
        return True


class Files(Protocol):
    def read_bytes(
        self, path: Path, cap: int, expect: Optional[FileId] = None
    ) -> Union[Buffer, Skipped]: ...

    def file_id(self, path: Path) -> Optional[FileId]: ...

    def list_dir(self, path: Path) -> tuple[str, ...]: ...

    def is_dir(self, path: Path) -> bool: ...

    def refused_reads(self) -> int: ...


class Commands(Protocol):
    def which(self, name: str) -> Optional[Located]: ...

    def locate(self, path: Path) -> Optional[Located]: ...

    def run(
        self, tool: Located, args: Sequence[str], timeout: int = ..., limit: int = ...
    ) -> CommandResult: ...


class Host(Protocol):
    def developer_tools_installed(self) -> bool: ...

    def keychain_has(self, label: str) -> bool: ...

    def java_homes(self) -> tuple[Path, ...]: ...


class Images(Protocol):
    names: tuple[str, ...]

    def probe(self, name: str) -> ProbeRun: ...


@dataclass(frozen=True)
class Context:
    """Everything a detection may read, built once by cli.build_context."""

    scope: ScanScope
    hostenv: HostEnvironment
    index: Index
    files: Files
    commands: Commands
    host: Host
    images: Optional[Images]
    ledger: Ledger
    notes: tuple[str, ...] = ()
    scope_findings: tuple[Finding, ...] = ()
    quiet: bool = False
    strict: bool = False
    containers: bool = False


class Detection(Protocol):
    name: ClassVar[str]
    interests: ClassVar[FileInterests]

    def run(self, ctx: Context) -> Iterator[Finding]: ...
