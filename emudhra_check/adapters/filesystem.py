"""filesystem.py: the file-system adapter, the only module that walks, stats and reads scanned files.

LocalPathOracle resolves paths and reports file ids. LocalFiles walks the scan roots once, opening
each directory relative to its parent's descriptor without following a symlink or blocking and
checking it is the directory listed, never crossing a device and never entering an excluded
directory. A directory that cannot be opened or listed is skipped with a notice. Files are read with
O_NOFOLLOW, S_ISREG and a size cap. Files above MAX_TEXT_BYTES are mapped with mmap. A mapped file
truncated by another process raises SIGBUS, which Python cannot catch.
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
    FoundFile,
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
# O_DIRECTORY and O_NONBLOCK each keep a FIFO swapped in for a directory from blocking the open.
DIR_FLAGS = os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
Classifier = Callable[[Buffer], BinaryKind]


def file_id_of(st: os.stat_result) -> FileId:
    return FileId(st.st_dev, st.st_ino)


def open_directory(
    name: Union[str, Path], expected: FileId, dir_fd: Optional[int] = None
) -> Optional[int]:
    """Open a directory relative to dir_fd, or None when what opened is not the directory listed.

    Raises OSError when the open fails.
    """
    fd = os.open(name, os.O_RDONLY | DIR_FLAGS, dir_fd=dir_fd)
    try:
        st = os.fstat(fd)
    except OSError:
        os.close(fd)
        raise
    if stat.S_ISDIR(st.st_mode) and file_id_of(st) == expected:
        return fd
    os.close(fd)
    return None


def list_entries(fd: int) -> tuple[list[str], list[str]]:
    """Return the names in an open directory as directories and the rest, a symlink by its target."""
    dirs: list[str] = []
    others: list[str] = []
    with os.scandir(fd) as entries:
        for entry in entries:
            try:
                is_dir = entry.is_dir()
            except OSError:
                try:
                    if entry.is_symlink():
                        others.append(entry.name)
                except OSError:
                    pass
                continue
            (dirs if is_dir else others).append(entry.name)
    return dirs, others


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

    def owner_and_mode(self, path: Path) -> Optional[tuple[int, int]]:
        try:
            st = os.stat(path, follow_symlinks=False)
        except (OSError, ValueError):
            return None
        return st.st_uid, st.st_mode


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
        """Record the program candidates directly inside one fixed binary directory, following file symlinks."""
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
            if stat.S_ISLNK(st.st_mode):
                target = self.follow_link(path, None, quiet=True)
                if target is not None:
                    self.consider_program(path, *target)
            else:
                self.consider_program(path, real / name, st)

    def walk_root(self, root: Root) -> None:
        """Walk one root top down. Directories that could not be opened or listed are noted last, sorted."""
        missed: list[Path] = []
        try:
            fd = open_directory(root.path, root.file_id)
        except (OSError, ValueError):
            fd = None
        if fd is None:
            self.notices.append(notice("scan", root.path, "not readable, skipped"))
            return
        try:
            self.walk_directory(root, root.path, fd, 0, missed)
        finally:
            os.close(fd)
        for path in sorted(missed, key=str):
            self.notices.append(notice("scan", path, "not readable, skipped"))

    def walk_directory(
        self, root: Root, here: Path, fd: int, depth: int, missed: list[Path]
    ) -> None:
        """Index one open directory's entries, then open and walk each kept subdirectory relative to fd."""
        try:
            dirnames, filenames = list_entries(fd)
        except OSError:
            missed.append(here)
            return
        at_limit = depth >= MAX_WALK_DEPTH
        kept: list[tuple[str, FileId]] = []
        for name in sorted(dirnames):
            path = here / name
            try:
                st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except (OSError, ValueError):
                self.notices.append(notice("scan", path, "not readable, skipped"))
                continue
            if not stat.S_ISDIR(st.st_mode) or st.st_dev != root.dev or is_pruned(path):
                continue
            file_id = file_id_of(st)
            if not self.owner.scope.permits(file_id):
                continue
            if not at_limit and self.interests.matches(path):
                self.dirs.append(IndexedDir(path, file_id))
            kept.append((name, file_id))
        if kept and at_limit:
            self.notices.append(
                notice(
                    "scan", here, f"deeper than {MAX_WALK_DEPTH} levels, not entered"
                )
            )
            kept = []
        for name in sorted(filenames):
            self.consider_file(root, here / name, name, fd)
        for name, file_id in kept:
            try:
                child = open_directory(name, file_id, fd)
            except (OSError, ValueError):
                child = None
            if child is None:
                missed.append(here / name)
                continue
            try:
                self.walk_directory(root, here / name, child, depth + 1, missed)
            finally:
                os.close(child)

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
            target = self.follow_link(path, root.dev, quiet=not wanted)
            if target is None:
                return
            real, target_st = target
            if wanted:
                self.files.append(
                    IndexedFile(path, real, file_id_of(target_st), target_st.st_size)
                )
            if program:
                self.consider_program(path, real, target_st)
        elif wanted:
            self.notices.append(notice("scan", path, "is not a regular file, skipped"))

    def follow_link(
        self, path: Path, dev: Optional[int], quiet: bool
    ) -> Optional[tuple[Path, os.stat_result]]:
        """Return a symlink's real path and stat when the target is a regular file in scope, on dev when given.

        A link into an excluded directory always gives its notice. quiet drops the others.
        """
        real = Path(os.path.realpath(path))
        if not self.owner.scope.permits_path(real, self.owner.oracle):
            self.notices.append(
                notice("symlink", path, "points into an excluded directory, skipped")
            )
            return None
        problem = None
        try:
            st = os.stat(real)
        except (OSError, ValueError):
            problem = notice("scan", path, "not readable, skipped")
        else:
            if not stat.S_ISREG(st.st_mode):
                problem = notice("scan", path, "is not a regular file, skipped")
            elif dev is not None and st.st_dev != dev:
                problem = notice("symlink", path, "leaves the scan device, skipped")
        if problem is None:
            return real, st
        if not quiet:
            self.notices.append(problem)
        return None

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
            self.executables.append(Executable(path, real, file_id, kind))


class LocalFiles:
    """Walks the scan roots and reads files inside the scan scope."""

    def __init__(
        self,
        scope: ScanScope,
        oracle: LocalPathOracle,
        binary_budget: int = MAX_BINARY_TOTAL_BYTES,
        read_budget: int = MAX_BINARY_TOTAL_BYTES,
    ) -> None:
        self.scope = scope
        self.oracle = oracle
        self.binary_budget = binary_budget
        self.read_budget = read_budget
        self.read_spent = 0
        self.refused = 0

    def charge_binary_read(self, path: Path) -> bool:
        """Spend a file's size from the detections' binary read budget before it is read.

        Returns False when the budget is already spent. The walk keeps a budget of its own.
        """
        if self.read_spent >= self.read_budget:
            return False
        real = Path(os.path.realpath(path))
        if self.scope.permits_path(real, self.oracle):
            try:
                self.read_spent += os.stat(real).st_size
            except (OSError, ValueError):
                pass
        return True

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
        """Read a regular file of at most cap bytes, refusing excluded paths and files changed since indexed.

        A path that is not a regular file is never opened, so no FIFO or device sees an open.
        """
        real = self.resolve(path)
        if real is None:
            return Skipped(EXCLUDED)
        try:
            if not stat.S_ISREG(os.stat(real, follow_symlinks=False).st_mode):
                return Skipped(UNREADABLE)
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
        except ValueError:
            # mmap raises ValueError when the file shrank after fstat.
            return Skipped(CHANGED)
        finally:
            os.close(fd)

    def lookup(self, path: Path) -> Union[FoundFile, Skipped]:
        """Return a fixed path's real path and file id, or why not: refused, missing or unreadable.

        A refused path is never stat'ed.
        """
        real = self.resolve(path)
        if real is None:
            return Skipped(EXCLUDED)
        try:
            st = os.stat(real)
        except (FileNotFoundError, NotADirectoryError):
            return Skipped(MISSING)
        except (OSError, ValueError):
            return Skipped(UNREADABLE)
        return FoundFile(real, file_id_of(st))

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
