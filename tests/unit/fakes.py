"""fakes.py: in-memory fakes of the detection ports, shared by the detection unit tests.

FakeFiles serves file bytes and ids from a dictionary, FakeCommands finds tools and replays recorded
output, FakeHost answers the platform questions, and make_context builds a Context from them.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Optional, Sequence, Union

from emudhra_check.detections.ports import (
    CHANGED,
    EXCLUDED,
    MISSING,
    TOO_LARGE,
    CommandResult,
    Context,
    Detection,
    Ledger,
    Located,
    Skipped,
)
from emudhra_check.hostenv import HostEnvironment
from emudhra_check.report import Finding
from emudhra_check.scope import FileId, Index, IndexedDir, IndexedFile, ScanScope
from emudhra_check.versions import Version

Content = Union[bytes, Skipped]


class FakeFiles:
    """Files by path: bytes or a Skipped, each with a file id, plus directories and excluded paths."""

    def __init__(
        self,
        files: Optional[dict[str, Content]] = None,
        dirs: Iterable[str] = (),
        excluded: Iterable[str] = (),
        ids: Optional[dict[str, FileId]] = None,
    ) -> None:
        self.files = {Path(p): v for p, v in (files or {}).items()}
        self.dirs = {Path(d) for d in dirs}
        for path in self.files:
            self.dirs.update(path.parents)
        self.excluded = [Path(e) for e in excluded]
        self.ids = {Path(p): i for p, i in (ids or {}).items()}
        self.refused = 0
        self.reads: list[Path] = []

    def id_of(self, path: Path) -> FileId:
        if path in self.ids:
            return self.ids[path]
        return FileId(1, 1000 + sorted(map(str, self.files)).index(str(path)))

    def is_excluded(self, path: Path) -> bool:
        return any(path == e or e in path.parents for e in self.excluded)

    def read_bytes(
        self, path: Path, cap: int, expect: Optional[FileId] = None
    ) -> Union[bytes, Skipped]:
        if self.is_excluded(path):
            self.refused += 1
            return Skipped(EXCLUDED)
        if path not in self.files:
            return Skipped(MISSING)
        value = self.files[path]
        if isinstance(value, Skipped):
            return value
        if expect is not None and expect != self.id_of(path):
            return Skipped(CHANGED)
        if len(value) > cap:
            return Skipped(TOO_LARGE)
        self.reads.append(path)
        return value

    def file_id(self, path: Path) -> Optional[FileId]:
        if self.is_excluded(path):
            self.refused += 1
            return None
        return self.id_of(path) if path in self.files else None

    def list_dir(self, path: Path) -> tuple[str, ...]:
        if self.is_excluded(path):
            return ()
        names = {p.relative_to(path).parts[0] for p in self.files if path in p.parents}
        names |= {d.name for d in self.dirs if d.parent == path and d != path}
        return tuple(sorted(names))

    def is_dir(self, path: Path) -> bool:
        return not self.is_excluded(path) and path in self.dirs

    def refused_reads(self) -> int:
        return self.refused

    def indexed(self, *paths: str) -> tuple[IndexedFile, ...]:
        """Return index entries for some of the files, as the walk would record them."""
        out = []
        for text in paths:
            path = Path(text)
            value = self.files[path]
            size = len(value) if isinstance(value, bytes) else 0
            out.append(IndexedFile(path, path, self.id_of(path), size))
        return tuple(out)


def located(
    path: str,
    permitted: bool = True,
    real: str = "",
    ino: int = 0,
    writable: bool = False,
) -> Located:
    """Return a Located tool at path, resolving to real when given."""
    return Located(
        Path(path),
        Path(real or path),
        permitted,
        FileId(2, ino or hash(path) % 100000),
        writable,
    )


def result(
    stdout: str = "", returncode: int = 0, stderr: str = "", timed_out: bool = False
) -> CommandResult:
    return CommandResult(returncode, stdout, stderr, timed_out, False)


class FakeCommands:
    """Tools by name and recorded output by (tool path, args), with every call kept."""

    def __init__(
        self,
        tools: Optional[dict[str, Located]] = None,
        outputs: Optional[dict[tuple[str, ...], CommandResult]] = None,
    ) -> None:
        self.tools = tools or {}
        self.outputs = outputs or {}
        self.calls: list[tuple[str, ...]] = []

    def which(self, name: str) -> Optional[Located]:
        return self.tools.get(name)

    def locate(self, path: Path) -> Optional[Located]:
        return self.tools.get(str(path))

    def run(
        self, tool: Located, args: Sequence[str], timeout: int = 60, limit: int = 0
    ) -> CommandResult:
        if not tool.permitted or tool.writable:
            raise ValueError("refusing to run an unpermitted tool")
        key = (str(tool.path), *args)
        self.calls.append(key)
        for recorded, value in self.outputs.items():
            if key[: len(recorded)] == recorded:
                return value
        return result(returncode=127, stderr="not recorded")


class FakeHost:
    def __init__(
        self,
        tools: bool = True,
        keychain: Iterable[str] = (),
        java_homes: Iterable[str] = (),
    ) -> None:
        self.tools = tools
        self.keychain = set(keychain)
        self.homes = tuple(Path(h) for h in java_homes)

    def developer_tools_installed(self) -> bool:
        return self.tools

    def keychain_has(self, label: str) -> bool:
        return label in self.keychain

    def java_homes(self) -> tuple[Path, ...]:
        return self.homes


def hostenv(
    system: str = "Linux",
    home: str = "/home/u",
    path_dirs: Sequence[str] = ("/usr/bin",),
    running: str = "3.13.5",
    brew_prefix: Optional[str] = None,
) -> HostEnvironment:
    numbers = tuple(int(n) for n in running.split("."))
    return HostEnvironment(
        system,
        Path(home),
        tuple(Path(p) for p in path_dirs),
        Path(brew_prefix) if brew_prefix else None,
        None,
        None,
        None,
        Version(running, numbers),
    )


def make_context(
    files: Optional[FakeFiles] = None,
    commands: Optional[FakeCommands] = None,
    host: Optional[FakeHost] = None,
    indexed: Iterable[IndexedFile] = (),
    dirs: Iterable[IndexedDir] = (),
    env: Optional[HostEnvironment] = None,
    ledger: Optional[Ledger] = None,
) -> Context:
    return Context(
        ScanScope((), frozenset()),
        env or hostenv(),
        Index(tuple(indexed), tuple(dirs)),
        files or FakeFiles(),
        commands or FakeCommands(),
        host or FakeHost(),
        None,
        ledger or Ledger(),
    )


def lines(detection: Detection, ctx: Context) -> list[str]:
    """Run one detection and return its output lines."""
    return [finding.line() for finding in detection.run(ctx)]


def run_all(detections: Sequence[Detection], ctx: Context) -> list[Finding]:
    found: list[Finding] = []
    for detection in detections:
        found.extend(detection.run(ctx))
    return found
