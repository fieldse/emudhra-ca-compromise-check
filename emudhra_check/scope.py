"""scope.py: which paths the scan may touch, and what the walk records about them.

Resolves the -x excludes and the scan roots to file ids through a PathOracle, so an excluded
directory is matched by its identity on disk and never by the spelling of its name. Also holds the
interests a detection declares, the program-path rule and the Index the walk fills.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Optional, Protocol

from emudhra_check.buildinfo import BinaryKind
from emudhra_check.errors import CheckError
from emudhra_check.report import Finding, Level, Subject

PRUNE_SUFFIXES: tuple[tuple[str, ...], ...] = tuple(
    tuple(PurePosixPath(p).parts)
    for p in (
        ".git",
        ".Trash",
        "Library/Containers",
        "Library/Group Containers",
        "Library/Mail",
        "Library/Messages",
        "Library/Safari",
        "Library/CloudStorage",
        "Library/Mobile Documents",
        ".local/share/containers",
    )
)
APP_EXECUTABLE_GLOB = "*/*.app/Contents/MacOS/*"
PROGRAM_DIR_NAMES = frozenset({"bin", "sbin"})


@dataclass(frozen=True)
class FileId:
    dev: int
    ino: int


@dataclass(frozen=True)
class PathFacts:
    file_id: FileId
    is_dir: bool
    stable: bool


class PathOracle(Protocol):
    def real_path(self, path: Path) -> Path: ...

    def facts(self, path: Path) -> Optional[PathFacts]: ...


@dataclass(frozen=True)
class ExcludeSet:
    ids: frozenset[FileId]
    paths: tuple[Path, ...]
    notes: tuple[str, ...]


@dataclass(frozen=True)
class Root:
    path: Path
    file_id: FileId
    dev: int


def top_down(path: Path) -> list[Path]:
    """Return path's ancestors from / down to path itself."""
    return list(reversed(path.parents)) + [path]


@dataclass(frozen=True)
class ScanScope:
    roots: tuple[Root, ...]
    excluded: frozenset[FileId]

    def permits(self, file_id: FileId) -> bool:
        """Return whether a file id is outside every excluded directory's own id."""
        return file_id not in self.excluded

    def permits_path(self, real: Path, oracle: PathOracle) -> bool:
        """Return whether no ancestor of a resolved path, nor the path, is excluded."""
        return first_excluded(real, self.excluded, oracle) is None


def first_excluded(
    real: Path, excluded: frozenset[FileId], oracle: PathOracle
) -> Optional[Path]:
    """Return the highest excluded directory on a resolved path, stopping there, or None."""
    if not excluded:
        return None
    for ancestor in top_down(real):
        facts = oracle.facts(ancestor)
        if facts is None:
            return None
        if facts.file_id in excluded:
            return ancestor
    return None


@dataclass(frozen=True)
class ScopeResult:
    scope: ScanScope
    notes: tuple[str, ...]
    findings: tuple[Finding, ...]


def expand(text: str, cwd: Path, home: Path) -> Path:
    """Expand a leading ~ to home and join a relative text to cwd, without normalising."""
    if text == "~":
        return home
    if text.startswith("~/"):
        return Path(str(home) + text[1:])
    if text.startswith("/"):
        return Path(text)
    return Path(str(cwd) + "/" + text)


def resolve_excludes(
    texts: tuple[str, ...], cwd: Path, home: Path, oracle: PathOracle
) -> ExcludeSet:
    """Resolve each -x text to a directory's file id."""
    ids: list[FileId] = []
    paths: list[Path] = []
    notes: list[str] = []
    for text in texts:
        real = oracle.real_path(expand(text, cwd, home))
        facts = oracle.facts(real)
        if facts is None:
            notes.append(f"exclude {text} not found, nothing to skip")
            continue
        if not facts.is_dir:
            raise CheckError(f"exclude is not a directory: {text}")
        if not facts.stable:
            raise CheckError(
                f"exclude is on a file system without stable inode numbers, unsupported: {text}"
            )
        if facts.file_id not in ids:
            ids.append(facts.file_id)
            paths.append(real)
        notes.append(f"excluding {real} (given as {text})")
    return ExcludeSet(frozenset(ids), tuple(paths), tuple(notes))


def default_roots(
    system: str, home: Path, brew_prefix: Optional[Path]
) -> tuple[Path, ...]:
    """Return the roots every run on this system adds: app folders and the Homebrew prefix on macOS."""
    if system != "Darwin":
        return ()
    roots = [Path("/Applications"), home / "Applications"]
    if brew_prefix is not None:
        roots += [brew_prefix / "etc", brew_prefix / "Caskroom"]
    return tuple(roots)


@dataclass(frozen=True)
class Candidate:
    real: Path
    facts: PathFacts


def resolve_roots(
    texts: tuple[str, ...],
    defaults: tuple[Path, ...],
    excludes: ExcludeSet,
    cwd: Path,
    home: Path,
    oracle: PathOracle,
) -> ScopeResult:
    """Resolve the scan roots, drop duplicates, roots inside excludes and roots inside other roots."""
    notes: list[str] = []
    findings: list[Finding] = []
    candidates: list[Candidate] = []
    for text in texts or ("~",):
        real = oracle.real_path(expand(text, cwd, home))
        facts = oracle.facts(real)
        if facts is None or not facts.is_dir:
            raise CheckError(f"scan root is not a directory: {text}")
        candidates.append(Candidate(real, facts))
    for path in defaults:
        real = oracle.real_path(path)
        facts = oracle.facts(real)
        if facts is not None and facts.is_dir:
            candidates.append(Candidate(real, facts))
    unique: list[Candidate] = []
    for candidate in candidates:
        if all(identity(candidate) != identity(kept) for kept in unique):
            unique.append(candidate)
    allowed = []
    for candidate in unique:
        if first_excluded(candidate.real, excludes.ids, oracle) is not None:
            notes.append(
                f"scan root {candidate.real} lies inside an excluded directory, skipped"
            )
        else:
            allowed.append(candidate)
    ids = {c.facts.file_id: c for c in allowed if c.facts.stable}
    kept: list[Candidate] = []
    for candidate in allowed:
        outer = enclosing_root(candidate, ids, oracle)
        if outer is not None:
            detail = f"lies inside scan root [{outer.real}], skipped"
            findings.append(
                Finding(Level.INFO, Subject("scan", str(candidate.real)), detail)
            )
        else:
            kept.append(candidate)
    for candidate in kept:
        if not candidate.facts.stable:
            notes.append(
                f"scan root {candidate.real} is on a file system without stable inode numbers,"
                " files may be reported more than once"
            )
    roots = tuple(Root(c.real, c.facts.file_id, c.facts.file_id.dev) for c in kept)
    return ScopeResult(ScanScope(roots, excludes.ids), tuple(notes), tuple(findings))


def identity(candidate: Candidate) -> object:
    """Return what makes two roots the same: the file id, or the real path where ids are not stable."""
    return candidate.facts.file_id if candidate.facts.stable else candidate.real


def enclosing_root(
    candidate: Candidate, roots: dict[FileId, Candidate], oracle: PathOracle
) -> Optional[Candidate]:
    """Return the nearest other root that is a proper ancestor of candidate."""
    for ancestor in reversed(candidate.real.parents):
        facts = oracle.facts(ancestor)
        if facts is not None and facts.stable and facts.file_id in roots:
            return roots[facts.file_id]
    return None


def is_program_path(
    path: Path, fixed_dirs: frozenset[Path], executable_globs: frozenset[str]
) -> bool:
    """Return whether an executable file at path is a program candidate for the binary detections."""
    if path.parent in fixed_dirs:
        return True
    text = str(path)
    if path.parent.name in PROGRAM_DIR_NAMES and "node_modules" not in path.parts:
        return True
    if fnmatch.fnmatchcase(text, APP_EXECUTABLE_GLOB):
        return True
    return any(fnmatch.fnmatchcase(text, "*/" + glob) for glob in executable_globs)


def is_pruned(path: Path) -> bool:
    """Return whether a directory ends with one of the pruned path suffixes, compared by component."""
    parts = path.parts
    return any(
        parts[-len(suffix) :] == suffix
        for suffix in PRUNE_SUFFIXES
        if len(parts) >= len(suffix)
    )


@dataclass(frozen=True)
class FileInterests:
    """The files and directories one detection wants the walk to index."""

    name_globs: frozenset[str] = frozenset()
    suffixes: frozenset[str] = frozenset()
    dir_globs: frozenset[str] = frozenset()
    executables: bool = False

    def matches(self, path: Path) -> bool:
        """Return whether path is one this detection wants."""
        name = path.name
        if any(fnmatch.fnmatchcase(name, glob) for glob in self.name_globs):
            return True
        if any(name.endswith(suffix) for suffix in self.suffixes):
            return True
        text = str(path)
        return any(fnmatch.fnmatchcase(text, "*/" + glob) for glob in self.dir_globs)

    def union(self, other: FileInterests) -> FileInterests:
        """Return interests that match whatever either one matches."""
        return FileInterests(
            self.name_globs | other.name_globs,
            self.suffixes | other.suffixes,
            self.dir_globs | other.dir_globs,
            self.executables or other.executables,
        )


@dataclass(frozen=True)
class IndexedFile:
    path: Path
    real: Path
    file_id: FileId
    size: int


@dataclass(frozen=True)
class IndexedDir:
    path: Path
    file_id: FileId


@dataclass(frozen=True)
class Executable:
    path: Path
    file_id: FileId
    kind: BinaryKind


@dataclass(frozen=True)
class Index:
    """The one walk's result: matched files and directories, classified programs and walk notices."""

    files: tuple[IndexedFile, ...] = ()
    dirs: tuple[IndexedDir, ...] = ()
    executables: tuple[Executable, ...] = ()
    notices: tuple[Finding, ...] = ()

    def files_for(self, interests: FileInterests) -> tuple[IndexedFile, ...]:
        return tuple(f for f in self.files if interests.matches(f.path))

    def dirs_for(self, interests: FileInterests) -> tuple[IndexedDir, ...]:
        return tuple(d for d in self.dirs if interests.matches(d.path))
