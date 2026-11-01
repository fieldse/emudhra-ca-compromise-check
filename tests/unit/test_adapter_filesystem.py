"""test_adapter_filesystem.py: tests of emudhra_check/adapters/filesystem.py against the real file system.

Builds real trees under /tmp inside the test container and walks and reads them with LocalFiles.
AsNobodyTest needs mode bits to apply, so tests/run-tests.sh runs it as user 65534 with no
capabilities, and it skips when run as root.
"""

from __future__ import annotations

import os
import signal
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable, Iterable, Optional
from unittest import mock

from emudhra_check.adapters import filesystem
from emudhra_check.adapters.filesystem import LocalFiles, LocalPathOracle
from emudhra_check.buildinfo import BinaryKind
from emudhra_check.detections.ports import (
    CHANGED,
    EXCLUDED,
    MISSING,
    TOO_LARGE,
    UNREADABLE,
    Skipped,
)
from emudhra_check.limits import MAX_BUNDLE_BYTES, MAX_WALK_DEPTH
from emudhra_check.scope import FileId, FileInterests, Root, ScanScope

BUNDLE = FileInterests(
    name_globs=frozenset({"cacert*", "cacerts"}),
    suffixes=frozenset({".pem", ".crt", ".cer"}),
)
PROGRAMS = BUNDLE.union(FileInterests(executables=True))
ORACLE = LocalPathOracle()
WATCHDOG = 10


class Hung(Exception):
    """Raised by the watchdog when a walk blocks."""


def raise_hung(signum: int, frame: Any) -> None:
    raise Hung()


def other(data: Any) -> BinaryKind:
    return BinaryKind.OTHER


def file_id(path: Path) -> FileId:
    st = os.stat(path)
    return FileId(st.st_dev, st.st_ino)


def file_id_of_fd(fd: int) -> FileId:
    st = os.fstat(fd)
    return FileId(st.st_dev, st.st_ino)


def root_of(path: Path) -> Root:
    st = os.stat(path)
    return Root(path, FileId(st.st_dev, st.st_ino), st.st_dev)


def scope(roots: Iterable[Path], excluded: Iterable[Path] = ()) -> ScanScope:
    return ScanScope(
        tuple(root_of(r) for r in roots), frozenset(file_id(e) for e in excluded)
    )


def write(path: Path, data: bytes = b"x", mode: Optional[int] = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if mode is not None:
        path.chmod(mode)
    return path


def lines(index: Any) -> list[str]:
    return [n.line() for n in index.notices]


class TreeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(dir="/tmp")))
        self.root = self.tmp / "r"
        self.root.mkdir()

    def tearDown(self) -> None:
        signal.alarm(0)
        subprocess.run(
            ["chmod", "-R", "u+rwx", str(self.tmp)],
            check=False,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(["rm", "-rf", str(self.tmp)], check=False)

    def walk(
        self,
        interests: FileInterests = BUNDLE,
        classify: Any = other,
        roots: Optional[list[Path]] = None,
        **kw: Any,
    ) -> Any:
        excluded = kw.pop("excluded", ())
        files = LocalFiles(scope(roots or [self.root], excluded), ORACLE, **kw)
        return files.walk(interests, (), classify)

    def indexed(self, index: Any) -> list[str]:
        return sorted(str(f.path) for f in index.files)


class WalkTest(TreeTest):
    def test_bundles_are_indexed(self) -> None:
        write(self.root / "a" / "cacert.pem")
        write(self.root / "b" / "ca-bundle.cer")
        write(self.root / "b" / "readme.txt")
        index = self.walk()
        self.assertEqual(
            self.indexed(index),
            [f"{self.root}/a/cacert.pem", f"{self.root}/b/ca-bundle.cer"],
        )
        self.assertEqual(index.notices, ())

    def test_symlinked_directory_is_not_entered(self) -> None:
        write(self.tmp / "outside" / "cacert.pem")
        write(self.root / "inner" / "x.pem")
        (self.root / "link-out").symlink_to(self.tmp / "outside")
        (self.root / "link-in").symlink_to(self.root / "inner")
        index = self.walk()
        self.assertEqual(self.indexed(index), [f"{self.root}/inner/x.pem"])
        self.assertEqual(index.notices, ())

    def test_symlinked_file_is_indexed_with_its_target_id(self) -> None:
        target = write(self.tmp / "outside" / "real.pem")
        (self.root / "link.pem").symlink_to(target)
        (entry,) = self.walk().files
        self.assertEqual(
            (entry.path, entry.real, entry.file_id),
            (self.root / "link.pem", target, file_id(target)),
        )

    def test_symlinked_file_into_an_excluded_directory(self) -> None:
        target = write(self.tmp / "secret" / "cacert.pem")
        (self.root / "link.pem").symlink_to(target)
        with mock.patch.object(
            LocalFiles, "read_bytes", side_effect=AssertionError("read")
        ):
            index = self.walk(excluded=[self.tmp / "secret"])
        self.assertEqual(index.files, ())
        self.assertEqual(
            lines(index),
            [
                f"INFO  symlink [{self.root}/link.pem] points into an excluded directory, skipped"
            ],
        )

    def test_excluded_directory_is_pruned(self) -> None:
        write(self.root / "secret" / "cacert.pem")
        write(self.root / "open" / "cacert.pem")
        index = self.walk(excluded=[self.root / "secret"])
        self.assertEqual(self.indexed(index), [f"{self.root}/open/cacert.pem"])

    def test_fifo_and_a_link_to_it(self) -> None:
        os.mkfifo(self.root / "cacert.pem")
        (self.root / "link.crt").symlink_to(self.root / "cacert.pem")
        signal.alarm(WATCHDOG)
        index = self.walk()
        files = LocalFiles(scope([self.root]), ORACLE)
        self.assertEqual(
            files.read_bytes(self.root / "cacert.pem", 10), Skipped(UNREADABLE)
        )
        signal.alarm(0)
        self.assertEqual(index.files, ())
        self.assertEqual(
            lines(index),
            [
                f"INFO  scan [{self.root}/cacert.pem] is not a regular file, skipped",
                f"INFO  scan [{self.root}/link.crt] is not a regular file, skipped",
            ],
        )

    def test_empty_pem(self) -> None:
        path = write(self.root / "empty.pem", b"")
        files = LocalFiles(scope([self.root]), ORACLE)
        with mock.patch.object(
            filesystem.mmap, "mmap", side_effect=AssertionError("mapped")
        ):
            self.assertEqual(files.read_bytes(path, 10), b"")

    def test_symlink_loop_entry_and_root(self) -> None:
        (self.root / "loop.pem").symlink_to(self.root / "loop.pem")
        index = self.walk()
        self.assertEqual(
            lines(index), [f"INFO  scan [{self.root}/loop.pem] not readable, skipped"]
        )
        loop = self.tmp / "looproot"
        loop.symlink_to(loop)
        files = LocalFiles(
            ScanScope((Root(loop, FileId(1, 1), 1),), frozenset()), ORACLE
        )
        index = files.walk(BUNDLE, (), other)
        self.assertEqual(lines(index), [f"INFO  scan [{loop}] not readable, skipped"])

    def test_sparse_file_too_large_to_read(self) -> None:
        path = self.root / "big.crt"
        with open(path, "wb") as handle:
            handle.truncate(100 * 1024 * 1024)
        files = LocalFiles(scope([self.root]), ORACLE)
        (entry,) = files.walk(BUNDLE, (), other).files
        self.assertEqual(entry.size, 100 * 1024 * 1024)
        self.assertEqual(
            files.read_bytes(path, MAX_BUNDLE_BYTES, entry.file_id), Skipped(TOO_LARGE)
        )

    def test_large_file_is_mapped(self) -> None:
        path = self.root / "large.crt"
        with open(path, "wb") as handle:
            handle.seek(40 * 1024 * 1024)
            handle.write(b"tail")
        data = LocalFiles(scope([self.root]), ORACLE).read_bytes(path, MAX_BUNDLE_BYTES)
        assert not isinstance(data, Skipped)
        self.assertEqual(data.find(b"tail"), 40 * 1024 * 1024)

    def test_non_regular_file_is_never_opened(self) -> None:
        os.mkfifo(self.root / "cacert.pem")
        (self.root / "link.pem").symlink_to(self.root / "cacert.pem")
        files = LocalFiles(scope([self.root]), ORACLE)
        with mock.patch.object(
            filesystem.os, "open", side_effect=AssertionError("opened")
        ):
            for name in ("cacert.pem", "link.pem"):
                self.assertEqual(
                    files.read_bytes(self.root / name, 10), Skipped(UNREADABLE)
                )

    def test_file_shrunk_before_it_is_mapped(self) -> None:
        path = self.root / "large.crt"
        with open(path, "wb") as handle:
            handle.truncate(40 * 1024 * 1024)
        files = LocalFiles(scope([self.root]), ORACLE)
        with mock.patch.object(
            filesystem.mmap,
            "mmap",
            side_effect=ValueError("mmap length is greater than file size"),
        ):
            self.assertEqual(files.read_bytes(path, MAX_BUNDLE_BYTES), Skipped(CHANGED))

    def test_invalid_utf8_name(self) -> None:
        name = b"cacert-\xff.pem"
        with open(os.path.join(os.fsencode(self.root), name), "wb") as handle:
            handle.write(b"x")
        (entry,) = self.walk().files
        self.assertEqual(entry.path.name, os.fsdecode(name))

    def test_prune_paths(self) -> None:
        for prune in (
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
        ):
            write(self.root / prune / "cacert.pem")
        write(self.root / "Library" / "Other" / "cacert.pem")
        write(self.root / ".github" / "cacert.pem")
        self.assertEqual(
            self.indexed(self.walk()),
            [
                f"{self.root}/.github/cacert.pem",
                f"{self.root}/Library/Other/cacert.pem",
            ],
        )

    def test_program_candidates(self) -> None:
        write(self.root / "node_modules" / "x" / "bin" / "cli", b"\x7fELF", 0o755)
        write(self.root / "tools" / "bin" / "tool", b"\x7fELF", 0o755)
        write(self.root / "tools" / "bin" / "notes", b"text", 0o644)
        write(self.root / "tools" / "lib" / "tool", b"\x7fELF", 0o755)
        seen: list[bytes] = []

        def classify(data: Any) -> BinaryKind:
            seen.append(bytes(data))
            return BinaryKind.GO

        index = self.walk(PROGRAMS, classify)
        self.assertEqual(
            [(str(e.path), e.kind) for e in index.executables],
            [(f"{self.root}/tools/bin/tool", BinaryKind.GO)],
        )
        self.assertEqual(seen, [b"\x7fELF"])

    def test_symlinked_programs(self) -> None:
        fixed = self.tmp / "fixedbin"
        fixed.mkdir()
        secret = write(self.tmp / "secret" / "evil", b"\x7fELF secret", 0o755)
        (fixed / "gh").symlink_to(
            write(self.tmp / "Cellar" / "gh", b"\x7fELF gh", 0o755)
        )
        (fixed / "evil").symlink_to(secret)
        (fixed / "dangling").symlink_to(self.tmp / "nowhere")
        (self.root / "bin").mkdir()
        (self.root / "bin" / "tool").symlink_to(
            write(self.root / "opt" / "tool", b"\x7fELF tool", 0o755)
        )
        (self.root / "bin" / "evil").symlink_to(secret)
        write(self.root / "bin" / "real", b"\x7fELF real", 0o755)
        (self.root / "bin" / "twin").symlink_to(self.root / "bin" / "real")
        seen: list[bytes] = []

        def classify(data: Any) -> BinaryKind:
            seen.append(bytes(data))
            return BinaryKind.GO

        files = LocalFiles(scope([self.root], [self.tmp / "secret"]), ORACLE)
        index = files.walk(PROGRAMS, (fixed,), classify)
        self.assertEqual(
            [str(e.path) for e in index.executables],
            [f"{fixed}/gh", f"{self.root}/bin/real", f"{self.root}/bin/tool"],
        )
        self.assertEqual(seen, [b"\x7fELF gh", b"\x7fELF real", b"\x7fELF tool"])
        self.assertEqual(
            lines(index),
            [
                f"INFO  symlink [{fixed}/evil] points into an excluded directory, skipped",
                f"INFO  symlink [{self.root}/bin/evil] points into an excluded directory, skipped",
            ],
        )

    def test_no_executable_interest_never_classifies(self) -> None:
        write(self.root / "bin" / "tool", b"\x7fELF", 0o755)
        index = self.walk(BUNDLE, mock.Mock(side_effect=AssertionError("classified")))
        self.assertEqual(index.executables, ())

    def test_binary_budget(self) -> None:
        for name in ("a", "b", "c"):
            write(self.root / "bin" / name, b"\x7fELF" + b"\0" * 96, 0o755)
        counted: list[int] = []

        def classify(data: Any) -> BinaryKind:
            counted.append(len(data))
            return BinaryKind.OTHER

        index = self.walk(PROGRAMS, classify, binary_budget=150)
        self.assertEqual(counted, [100, 100])
        self.assertEqual(
            lines(index),
            [f"INFO  scan [{self.root}/bin/c] binary budget exhausted, skipped"],
        )

    def test_detection_reads_have_their_own_budget(self) -> None:
        for name in ("a", "b"):
            write(self.root / "bin" / name, b"\x7fELF" + b"\0" * 96, 0o755)
        app = write(self.root / "app" / "app", b"\x7fELF" + b"\0" * 96, 0o755)
        files = LocalFiles(
            scope([self.root]), ORACLE, binary_budget=50, read_budget=150
        )
        index = files.walk(PROGRAMS, (), other)
        self.assertEqual(
            lines(index),
            [f"INFO  scan [{self.root}/bin/b] binary budget exhausted, skipped"],
        )
        self.assertEqual(
            [files.charge_binary_read(app) for _ in range(3)], [True, True, False]
        )
        self.assertEqual(files.read_spent, 200)

    def test_walk_of_filesystem_root_stays_on_its_device(self) -> None:
        index = self.walk(roots=[Path("/")])
        for entry in list(index.files) + list(index.dirs):
            with self.subTest(path=str(entry.path)):
                for mount in ("/proc/", "/sys/", "/out/", "/repo/", "/dev/"):
                    self.assertFalse(str(entry.path).startswith(mount))
        self.assertTrue(any(str(f.path).startswith("/etc/ssl/") for f in index.files))

    def test_deep_chain(self) -> None:
        write(self.root / "cacert.pem")
        fd = os.open(self.root, os.O_RDONLY)
        try:
            for _ in range(2000):
                os.mkdir("d", dir_fd=fd)
                child = os.open("d", os.O_RDONLY, dir_fd=fd)
                os.close(fd)
                fd = child
            bottom = os.open("cacert.pem", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=fd)
            os.write(bottom, b"x")
            os.close(bottom)
        finally:
            os.close(fd)
        index = self.walk()
        self.assertEqual(self.indexed(index), [f"{self.root}/cacert.pem"])
        deep = "/".join(["d"] * MAX_WALK_DEPTH)
        self.assertEqual(
            lines(index),
            [f"INFO  scan [{self.root}/{deep}] deeper than 128 levels, not entered"],
        )

    def walk_with_swap(self, swap: Callable[[Path], None], flags: int) -> Any:
        """Walk a root whose directory d is replaced by swap after the root is listed and before d is opened."""
        write(self.root / "a.pem")
        write(self.root / "d" / "cacert.pem")
        write(self.root / "e" / "cacert.pem")
        consider_file = filesystem.Walk.consider_file

        def consider(walk: Any, root: Root, path: Path, name: str, fd: int) -> None:
            if path == self.root / "a.pem":
                (self.root / "d").rename(self.tmp / "moved")
                swap(self.root / "d")
            consider_file(walk, root, path, name, fd)

        previous = signal.signal(signal.SIGALRM, raise_hung)
        signal.alarm(WATCHDOG)
        try:
            with mock.patch.object(
                filesystem.Walk, "consider_file", consider
            ), mock.patch.object(filesystem, "DIR_FLAGS", flags):
                return self.walk()
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)

    def assert_swap_skipped(self, index: Any) -> None:
        self.assertEqual(
            self.indexed(index), [f"{self.root}/a.pem", f"{self.root}/e/cacert.pem"]
        )
        self.assertEqual(
            lines(index), [f"INFO  scan [{self.root}/d] not readable, skipped"]
        )

    def test_directory_swapped_for_a_fifo(self) -> None:
        self.assert_swap_skipped(self.walk_with_swap(os.mkfifo, filesystem.DIR_FLAGS))

    def test_directory_swapped_for_a_file(self) -> None:
        self.assert_swap_skipped(self.walk_with_swap(write, filesystem.DIR_FLAGS))

    def test_directory_swapped_for_a_symlink(self) -> None:
        def link(path: Path) -> None:
            path.symlink_to(self.tmp / "moved")

        self.assert_swap_skipped(self.walk_with_swap(link, filesystem.DIR_FLAGS))

    def test_o_nonblock_alone_keeps_a_fifo_from_blocking(self) -> None:
        flags = filesystem.DIR_FLAGS & ~os.O_DIRECTORY
        self.assert_swap_skipped(self.walk_with_swap(os.mkfifo, flags))

    def test_o_directory_alone_keeps_a_fifo_from_blocking(self) -> None:
        flags = filesystem.DIR_FLAGS & ~os.O_NONBLOCK
        self.assert_swap_skipped(self.walk_with_swap(os.mkfifo, flags))

    def test_listing_error_skips_one_directory(self) -> None:
        write(self.root / "d" / "cacert.pem")
        write(self.root / "e" / "cacert.pem")
        list_entries = filesystem.list_entries
        d_id = file_id(self.root / "d")

        def failing(fd: int) -> Any:
            if file_id_of_fd(fd) == d_id:
                raise OSError("listing failed")
            return list_entries(fd)

        with mock.patch.object(filesystem, "list_entries", failing):
            index = self.walk()
        self.assertEqual(self.indexed(index), [f"{self.root}/e/cacert.pem"])
        self.assertEqual(
            lines(index), [f"INFO  scan [{self.root}/d] not readable, skipped"]
        )

    def test_directory_swapped_for_a_symlink_into_an_exclude(self) -> None:
        write(self.root / "d" / "cacert.pem", b"indexed")
        write(self.tmp / "secret" / "cacert.pem", b"secret bytes")
        files = LocalFiles(scope([self.root], [self.tmp / "secret"]), ORACLE)
        (entry,) = files.walk(BUNDLE, (), other).files
        (self.root / "d").rename(self.tmp / "moved")
        (self.root / "d").symlink_to(self.tmp / "secret")
        self.assertEqual(
            files.read_bytes(entry.real, 100, entry.file_id), Skipped(EXCLUDED)
        )

    def test_directory_swapped_for_a_symlink_elsewhere(self) -> None:
        write(self.root / "d" / "cacert.pem", b"indexed")
        write(self.root / "other" / "cacert.pem", b"other bytes")
        files = LocalFiles(scope([self.root]), ORACLE)
        entry = next(
            f for f in files.walk(BUNDLE, (), other).files if f.path.parent.name == "d"
        )
        (self.root / "d").rename(self.tmp / "moved")
        (self.root / "d").symlink_to(self.root / "other")
        self.assertEqual(
            files.read_bytes(entry.real, 100, entry.file_id), Skipped(CHANGED)
        )

    def test_read_stops_at_cap_when_the_file_grew(self) -> None:
        path = write(self.root / "grow.pem", b"y" * 100)
        real_fstat = os.fstat

        def small_fstat(fd: int) -> os.stat_result:
            st = real_fstat(fd)
            return os.stat_result(
                (
                    st.st_mode,
                    st.st_ino,
                    st.st_dev,
                    st.st_nlink,
                    st.st_uid,
                    st.st_gid,
                    10,
                    0,
                    0,
                    0,
                )
            )

        files = LocalFiles(scope([self.root]), ORACLE)
        with mock.patch.object(filesystem.os, "fstat", small_fstat):
            self.assertEqual(files.read_bytes(path, 50), b"y" * 50)

    def test_missing_path(self) -> None:
        files = LocalFiles(scope([self.root]), ORACLE)
        self.assertEqual(files.read_bytes(self.root / "nope.pem", 10), Skipped(MISSING))
        self.assertEqual(
            files.read_bytes(self.root / "nope" / "x.pem", 10), Skipped(MISSING)
        )
        self.assertIsNone(files.file_id(self.root / "nope.pem"))
        self.assertEqual(files.refused_reads(), 0)

    def test_refused_paths_are_counted(self) -> None:
        write(self.root / "secret" / "cacert.pem")
        files = LocalFiles(scope([self.root], [self.root / "secret"]), ORACLE)
        self.assertEqual(
            files.read_bytes(self.root / "secret" / "cacert.pem", 10), Skipped(EXCLUDED)
        )
        self.assertIsNone(files.file_id(self.root / "secret" / "cacert.pem"))
        self.assertEqual(files.list_dir(self.root / "secret"), ())
        self.assertFalse(files.is_dir(self.root / "secret"))
        self.assertEqual(files.refused_reads(), 4)

    def test_fixed_path_helpers(self) -> None:
        path = write(self.root / "a" / "cacert.pem")
        files = LocalFiles(scope([self.root]), ORACLE)
        self.assertEqual(files.file_id(path), file_id(path))
        self.assertEqual(files.list_dir(self.root / "a"), ("cacert.pem",))
        self.assertTrue(files.is_dir(self.root / "a"))
        self.assertFalse(files.is_dir(path))

    def test_failing_root_does_not_stop_the_next(self) -> None:
        second = self.tmp / "second"
        write(second / "cacert.pem")
        write(self.root / "bin" / "boom", b"\x7fELF", 0o755)

        def classify(data: Any) -> BinaryKind:
            raise RuntimeError("boom")

        index = self.walk(PROGRAMS, classify, roots=[self.root, second])
        self.assertEqual(
            lines(index), [f"ERROR  scan [{self.root}] walk failed: RuntimeError: boom"]
        )
        self.assertEqual(self.indexed(index), [f"{second}/cacert.pem"])


class OracleTest(TreeTest):
    def test_facts(self) -> None:
        path = write(self.root / "f")
        facts = ORACLE.facts(path)
        assert facts is not None
        self.assertEqual(
            (facts.file_id, facts.is_dir, facts.stable), (file_id(path), False, True)
        )
        self.assertIsNone(ORACLE.facts(self.root / "missing"))
        (self.root / "l").symlink_to(self.root)
        self.assertEqual(ORACLE.real_path(self.root / "l" / "f"), path)


@unittest.skipIf(
    os.geteuid() == 0,
    "mode bits need an unprivileged user, run-tests.sh runs these as 65534",
)
class AsNobodyTest(TreeTest):
    def test_unreadable_entries_sort_before_a_bundle(self) -> None:
        write(self.root / "a-dir" / "cacert.pem")
        (self.root / "a-dir").chmod(0o444)
        write(self.root / "bin" / "a-tool", b"\x7fELF", 0o111)
        write(self.root / "bin" / "z-cacert.pem", b"bundle")
        write(self.root / "z" / "cacert.pem", b"bundle")
        index = self.walk(PROGRAMS, lambda data: BinaryKind.OTHER)
        self.assertEqual(
            self.indexed(index),
            [f"{self.root}/bin/z-cacert.pem", f"{self.root}/z/cacert.pem"],
        )
        self.assertEqual(
            sorted(lines(index)),
            [
                f"INFO  scan [{self.root}/a-dir/cacert.pem] not readable, skipped",
                f"INFO  scan [{self.root}/bin/a-tool] not readable, skipped",
            ],
        )

    def test_mode_000_file_and_directory(self) -> None:
        path = write(self.root / "locked.pem", b"x", 0o000)
        write(self.root / "closed" / "cacert.pem")
        (self.root / "closed").chmod(0o000)
        files = LocalFiles(scope([self.root]), ORACLE)
        index = files.walk(BUNDLE, (), other)
        self.assertEqual(
            lines(index), [f"INFO  scan [{self.root}/closed] not readable, skipped"]
        )
        (entry,) = index.files
        self.assertEqual(files.read_bytes(path, 10, entry.file_id), Skipped(UNREADABLE))
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0)


if __name__ == "__main__":
    unittest.main()
