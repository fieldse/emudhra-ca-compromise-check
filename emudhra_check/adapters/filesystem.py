"""filesystem.py: the file-system adapter, the only module that walks, stats and reads scanned files.

LocalPathOracle resolves paths and reports file ids. LocalFiles walks the scan roots once with
os.fwalk, never following directory symlinks, never crossing a device and never entering an
excluded directory, and reads files with O_NOFOLLOW, S_ISREG and a size cap. Files above
MAX_TEXT_BYTES are mapped with mmap. A mapped file truncated by another process raises SIGBUS,
which Python cannot catch.
"""

from __future__ import annotations

import mmap
import os
import stat
from pathlib import Path
from typing import Callable, Optional, Union

from emudhra_check.buildinfo import BinaryKind
from emudhra_check.certificates import Buffer
from emudhra_check.detections.ports import (
    CHANGED,
    EXCLUDED,
    MISSING,
    TOO_LARGE,
    UNREADABLE,
    Skipped,
)
from emudhra_check.limits import (
    MAX_BINARY_BYTES,
    MAX_BINARY_TOTAL_BYTES,
    MAX_ERROR_CHARS,
    MAX_TEXT_BYTES,
    MAX_WALK_DEPTH,
)
from emudhra_check.report import Finding, Level, Subject
from emudhra_check.scope import (
    Executable,
    FileId,
    FileInterests,
    Index,
    IndexedDir,
    IndexedFile,
    PathFacts,
    Root,
    ScanScope,
    is_program_path,
    is_pruned,
)

READ_CHUNK = 1024 * 1024
Classifier = Callable[[Buffer], BinaryKind]


def file_id_of(st: os.stat_result) -> FileId:
    return FileId(st.st_dev, st.st_ino)


class LocalPathOracle:
    """Resolves paths with os.path.realpath and reports their file ids with os.stat."""

    def real_path(self, path: Path) -> Path:
        return Path(os.path.realpath(path))

    def facts(self, path: Path) -> Optional[PathFacts]:
        try:
            st = os.stat(path)
        except (OSError, ValueError):
            return None
        return PathFacts(file_id_of(st), stat.S_ISDIR(st.st_mode), st.st_ino != 0)


def notice(
    name: str, path: Union[Path, str], detail: str, level: Level = Level.INFO
) -> Finding:
    return Finding(level, Subject(name, str(path)), detail)


class Walk:
    """The state of one LocalFiles.walk call."""

    def __init__(
        self,
        files: LocalFiles,
        interests: FileInterests,
        fixed_dirs: tuple[Path, ...],
        classify: Classifier,
        executable_globs: frozenset[str],
    ) -> None:
        self.owner = files
        self.interests = interests
        self.fixed_dirs = frozenset(fixed_dirs)
        self.classify = classify
        self.globs = executable_globs
        self.files: list[IndexedFile] = []
        self.dirs: list[IndexedDir] = []
        self.executables: list[Executable] = []
        self.seen_programs: set[FileId] = set()
        self.notices: list[Finding] = []
        self.spent = 0

    def index(self) -> Index:
        return Index(
            tuple(self.files),
            tuple(self.dirs),
            tuple(self.executables),
            tuple(self.notices),
        )

    def run(self) -> Index:
        if self.interests.executables:
            for directory in sorted(self.fixed_dirs):
                self.list_fixed_dir(directory)
        for root in self.owner.scope.roots:
            try:
                self.walk_root(root)
            except Exception as error:
                message = f"{type(error).__name__}: {error}"[:MAX_ERROR_CHARS]
                self.notices.append(
                    notice("scan", root.path, f"walk failed: {message}", Level.ERROR)
                )
        return self.index()

    def list_fixed_dir(self, directory: Path) -> None:
        """Record the program candidates directly inside one fixed binary directory."""
        real = Path(os.path.realpath(directory))
        if not self.owner.scope.permits_path(real, self.owner.oracle):
            return
        try:
            names = sorted(os.listdir(real))
        except (OSError, ValueError):
            return
        for name in names:
            path = directory / name
            try:
                st = os.stat(real / name, follow_symlinks=False)
            except (OSError, ValueError):
                self.notices.append(notice("scan", path, "not readable, skipped"))
                continue
            self.consider_program(path, real / name, st)

    def walk_root(self, root: Root) -> None:
        try:
            os.close(os.open(root.path, os.O_RDONLY | os.O_DIRECTORY))
        except OSError:
            self.notices.append(notice("scan", root.path, "not readable, skipped"))
            return
        base_depth = len(root.path.parts)
        expected = {str(root.path)}
        opened: set[str] = set()
        for dirpath, dirnames, filenames, dirfd in os.fwalk(
            str(root.path), topdown=True, follow_symlinks=False
        ):
            opened.add(dirpath)
            here = Path(dirpath)
            at_limit = len(here.parts) - base_depth >= MAX_WALK_DEPTH
            kept = []
            for name in sorted(dirnames):
                path = here / name
                try:
                    st = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
                except (OSError, ValueError):
                    self.notices.append(notice("scan", path, "not readable, skipped"))
                    continue
                if (
                    not stat.S_ISDIR(st.st_mode)
                    or st.st_dev != root.dev
                    or is_pruned(path)
                ):
                    continue
                file_id = file_id_of(st)
                if not self.owner.scope.permits(file_id):
                    continue
                if not at_limit and self.interests.matches(path):
                    self.dirs.append(IndexedDir(path, file_id))
                kept.append(name)
            if kept and at_limit:
                self.notices.append(
                    notice(
                        "scan",
                        here,
                        f"deeper than {MAX_WALK_DEPTH} levels, not entered",
                    )
                )
                kept = []
            dirnames[:] = kept
            expected.update(
                dirpath + "/" + name if dirpath != "/" else "/" + name for name in kept
            )
            for name in sorted(filenames):
                self.consider_file(root, here / name, name, dirfd)
        for missed in sorted(expected - opened):
            self.notices.append(notice("scan", missed, "not readable, skipped"))

    def consider_file(self, root: Root, path: Path, name: str, dirfd: int) -> None:
        """Index one directory entry that is not a directory, when an interest or the program rule wants it."""
        wanted = self.interests.matches(path)
        program = self.interests.executables and is_program_path(
            path, self.fixed_dirs, self.globs
        )
        if not (wanted or program):
            return
        try:
            st = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
        except (OSError, ValueError):
            self.notices.append(notice("scan", path, "not readable, skipped"))
            return
        if stat.S_ISREG(st.st_mode):
            if wanted:
                self.files.append(IndexedFile(path, path, file_id_of(st), st.st_size))
            if program:
                self.consider_program(path, path, st)
        elif stat.S_ISLNK(st.st_mode):
            if wanted:
                self.consider_symlink(root, path)
        elif wanted:
            self.notices.append(notice("scan", path, "is not a regular file, skipped"))

    def consider_symlink(self, root: Root, path: Path) -> None:
        """Index a symlinked file by its target when the target is a regular file on the root's device in scope."""
        real = Path(os.path.realpath(path))
        if not self.owner.scope.permits_path(real, self.owner.oracle):
            self.notices.append(
                notice("symlink", path, "points into an excluded directory, skipped")
            )
            return
        try:
            st = os.stat(real)
        except (OSError, ValueError):
            self.notices.append(notice("scan", path, "not readable, skipped"))
            return
        if not stat.S_ISREG(st.st_mode):
            self.notices.append(notice("scan", path, "is not a regular file, skipped"))
        elif st.st_dev != root.dev:
            self.notices.append(
                notice("symlink", path, "leaves the scan device, skipped")
            )
        else:
            self.files.append(IndexedFile(path, real, file_id_of(st), st.st_size))

    def consider_program(self, path: Path, real: Path, st: os.stat_result) -> None:
        """Classify one executable regular file, once, within the size cap and the walk's byte budget."""
        if not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111:
            return
        file_id = file_id_of(st)
        if file_id in self.seen_programs:
            return
        self.seen_programs.add(file_id)
        if st.st_size > MAX_BINARY_BYTES:
            self.notices.append(notice("scan", path, "too large to scan, skipped"))
            return
        if self.spent >= self.owner.binary_budget:
            self.notices.append(
                notice("scan", path, "binary budget exhausted, skipped")
            )
            return
        self.spent += st.st_size
        data = self.owner.read_bytes(real, MAX_BINARY_BYTES, file_id)
        if isinstance(data, Skipped):
            self.notices.append(notice("scan", path, "not readable, skipped"))
            return
        try:
            kind = self.classify(data)
        except (OSError, ValueError):
            self.notices.append(notice("scan", path, "not readable, skipped"))
            return
        finally:
            if isinstance(data, mmap.mmap):
                data.close()
        if kind is not BinaryKind.OTHER:
            self.executables.append(Executable(path, file_id, kind))


class LocalFiles:
    """Walks the scan roots and reads files inside the scan scope."""

    def __init__(
        self,
        scope: ScanScope,
        oracle: LocalPathOracle,
        binary_budget: int = MAX_BINARY_TOTAL_BYTES,
    ) -> None:
        self.scope = scope
        self.oracle = oracle
        self.binary_budget = binary_budget
        self.refused = 0

    def walk(
        self,
        interests: FileInterests,
        fixed_dirs: tuple[Path, ...],
        classify: Classifier,
        executable_globs: frozenset[str] = frozenset(),
    ) -> Index:
        """Walk every root once and return what the interests asked for.

        executable_globs are the dir_globs of the detections that want executables, whose matching
        files become program candidates beside those of the bin and app rules.
        """
        return Walk(self, interests, fixed_dirs, classify, executable_globs).run()

    def resolve(self, path: Path) -> Optional[Path]:
        """Return the real path when the scope permits it, else count the refusal and return None."""
        real = Path(os.path.realpath(path))
        if self.scope.permits_path(real, self.oracle):
            return real
        self.refused += 1
        return None

    def read_bytes(
        self, path: Path, cap: int, expect: Optional[FileId] = None
    ) -> Union[Buffer, Skipped]:
        """Read a regular file of at most cap bytes, refusing excluded paths and files changed since indexed."""
        real = self.resolve(path)
        if real is None:
            return Skipped(EXCLUDED)
        try:
            fd = os.open(
                real, os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY | os.O_NOFOLLOW
            )
        except (FileNotFoundError, NotADirectoryError):
            return Skipped(MISSING)
        except (OSError, ValueError):
            return Skipped(UNREADABLE)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                return Skipped(UNREADABLE)
            if expect is not None and file_id_of(st) != expect:
                return Skipped(CHANGED)
            if st.st_size > cap:
                return Skipped(TOO_LARGE)
            if st.st_size == 0:
                return b""
            if st.st_size <= MAX_TEXT_BYTES:
                return read_capped(fd, cap)
            return mmap.mmap(fd, min(cap, st.st_size), access=mmap.ACCESS_READ)
        except OSError:
            return Skipped(UNREADABLE)
        finally:
            os.close(fd)

    def file_id(self, path: Path) -> Optional[FileId]:
        """Return the file id of a fixed path inside the scope, or None when it is missing or refused."""
        real = self.resolve(path)
        if real is None:
            return None
        try:
            return file_id_of(os.stat(real))
        except (OSError, ValueError):
            return None

    def list_dir(self, path: Path) -> tuple[str, ...]:
        """Return the sorted names in a directory inside the scope."""
        real = self.resolve(path)
        if real is None:
            return ()
        try:
            return tuple(sorted(os.listdir(real)))
        except (OSError, ValueError):
            return ()

    def is_dir(self, path: Path) -> bool:
        """Return whether a path inside the scope is a directory."""
        real = self.resolve(path)
        if real is None:
            return False
        try:
            return stat.S_ISDIR(os.stat(real).st_mode)
        except (OSError, ValueError):
            return False

    def refused_reads(self) -> int:
        """Return how many host paths were refused as inside an excluded directory."""
        return self.refused


def read_capped(fd: int, cap: int) -> bytes:
    """Read from fd until end of file or cap bytes, whichever comes first."""
    chunks = []
    total = 0
    while total < cap:
        chunk = os.read(fd, min(READ_CHUNK, cap - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)
