"""test_scope.py: unit tests of emudhra_check/scope.py.

Resolves excludes and roots against a dictionary-backed PathOracle, one row per exclude bypass and
per root rule, and checks the program-path rule and FileInterests matching with plain values.
"""

from __future__ import annotations

import unittest
from pathlib import Path, PurePosixPath
from typing import Iterable, Optional

from emudhra_check.errors import CheckError
from emudhra_check.report import Finding, Level, Subject
from emudhra_check.scope import (
    PRUNE_SUFFIXES,
    ExcludeSet,
    FileId,
    FileInterests,
    PathFacts,
    default_roots,
    is_program_path,
    is_pruned,
    resolve_excludes,
    resolve_roots,
)

CWD = Path("/t")
HOME = Path("/home/u")


class FakeOracle:
    """Paths as a dictionary: each entry has an inode number and a type, symlinks resolve by table."""

    def __init__(
        self,
        dirs: Iterable[str] = (),
        files: Iterable[str] = (),
        links: Optional[dict[str, str]] = None,
        same: Optional[dict[str, str]] = None,
        unstable: Iterable[str] = (),
        forbid_below: Optional[str] = None,
    ) -> None:
        self.entries: dict[str, tuple[int, bool]] = {"/": (1, True)}
        for path in dirs:
            self.add(path, True)
        for path in files:
            self.add(path, False)
        for alias, canonical in (same or {}).items():
            self.entries[alias] = self.entries[canonical]
        self.links = links or {}
        self.unstable = set(unstable)
        self.forbid_below = forbid_below
        self.asked: list[str] = []

    def add(self, path: str, is_dir: bool) -> None:
        parts = PurePosixPath(path).parts
        for depth in range(2, len(parts)):
            parent = str(PurePosixPath(*parts[:depth]))
            self.entries.setdefault(parent, (len(self.entries) + 1, True))
        self.entries[path] = (len(self.entries) + 1, is_dir)

    def id_of(self, path: str) -> FileId:
        return FileId(1, self.entries[path][0])

    def real_path(self, path: Path) -> Path:
        pending = list(path.parts[1:])
        resolved = PurePosixPath("/")
        hops = 0
        while pending:
            name = pending.pop(0)
            if name == ".":
                continue
            if name == "..":
                resolved = resolved.parent
                continue
            candidate = str(resolved / name)
            if candidate in self.links:
                hops += 1
                if hops > 40:
                    return path
                pending = list(PurePosixPath(self.links[candidate]).parts[1:]) + pending
                resolved = PurePosixPath("/")
            else:
                resolved = resolved / name
        return Path(str(resolved))

    def facts(self, path: Path) -> Optional[PathFacts]:
        text = str(path)
        self.asked.append(text)
        if self.forbid_below is not None and text.startswith(self.forbid_below + "/"):
            raise AssertionError(f"asked about {text} below an excluded directory")
        if text not in self.entries:
            return None
        ino, is_dir = self.entries[text]
        stable = text not in self.unstable
        return PathFacts(FileId(1, ino if stable else 0), is_dir, stable)


def excludes(oracle: FakeOracle, *texts: str) -> ExcludeSet:
    return resolve_excludes(texts, CWD, HOME, oracle)


class ExcludeTest(unittest.TestCase):
    def test_prune_by_id_not_by_string(self) -> None:
        oracle = FakeOracle(
            dirs=["/h/Secret"],
            files=["/h/Secret/cacert.pem"],
            same={"/h/secret": "/h/Secret"},
        )
        result = excludes(oracle, "/h/secret")
        self.assertEqual(result.ids, frozenset({oracle.id_of("/h/Secret")}))
        scope = resolve_roots(("/h",), (), result, CWD, HOME, oracle).scope
        self.assertFalse(scope.permits(oracle.id_of("/h/Secret")))
        self.assertFalse(scope.permits_path(Path("/h/Secret/cacert.pem"), oracle))

    def test_wrong_case_missing(self) -> None:
        oracle = FakeOracle(dirs=["/t/Secret"])
        result = excludes(oracle, "/t/secret")
        self.assertEqual(result.ids, frozenset())
        self.assertEqual(
            result.notes, ("exclude /t/secret not found, nothing to skip",)
        )

    def test_glob_characters(self) -> None:
        oracle = FakeOracle(dirs=["/t/glob[x]*?", "/t/globx", "/t/globxyz"])
        result = excludes(oracle, "/t/glob[x]*?")
        self.assertEqual(result.ids, frozenset({oracle.id_of("/t/glob[x]*?")}))
        scope = resolve_roots(("/t",), (), result, CWD, HOME, oracle).scope
        self.assertTrue(scope.permits_path(Path("/t/globx"), oracle))
        self.assertTrue(scope.permits_path(Path("/t/globxyz"), oracle))
        self.assertFalse(scope.permits_path(Path("/t/glob[x]*?"), oracle))

    def test_symlinked_exclude(self) -> None:
        oracle = FakeOracle(
            dirs=["/t/secret"], links={"/t/link-to-secret": "/t/secret"}
        )
        result = excludes(oracle, "/t/link-to-secret")
        self.assertEqual(result.ids, frozenset({oracle.id_of("/t/secret")}))
        self.assertEqual(
            result.notes, ("excluding /t/secret (given as /t/link-to-secret)",)
        )

    def test_trailing_dot(self) -> None:
        oracle = FakeOracle(dirs=["/t/secret"])
        self.assertEqual(
            excludes(oracle, "/t/secret/.").ids, frozenset({oracle.id_of("/t/secret")})
        )

    def test_trailing_dotdot(self) -> None:
        oracle = FakeOracle(dirs=["/t/secret/sub"])
        self.assertEqual(
            excludes(oracle, "/t/secret/sub/..").ids,
            frozenset({oracle.id_of("/t/secret")}),
        )

    def test_dotdot_through_a_symlink_is_physical(self) -> None:
        oracle = FakeOracle(
            dirs=["/t/secret", "/elsewhere/deep"], links={"/t/hop": "/elsewhere/deep"}
        )
        self.assertEqual(
            excludes(oracle, "/t/hop/..").ids, frozenset({oracle.id_of("/elsewhere")})
        )

    def test_relative_and_home(self) -> None:
        oracle = FakeOracle(dirs=["/t/secret", "/home/u/secret"])
        self.assertEqual(
            excludes(oracle, "./secret").ids, frozenset({oracle.id_of("/t/secret")})
        )
        self.assertEqual(
            excludes(oracle, "secret").ids, frozenset({oracle.id_of("/t/secret")})
        )
        self.assertEqual(
            excludes(oracle, "~/secret").ids,
            frozenset({oracle.id_of("/home/u/secret")}),
        )
        self.assertEqual(
            excludes(oracle, "~").ids, frozenset({oracle.id_of("/home/u")})
        )

    def test_exclude_that_is_a_file(self) -> None:
        oracle = FakeOracle(files=["/t/file"])
        with self.assertRaisesRegex(
            CheckError, "^exclude is not a directory: /t/file$"
        ):
            excludes(oracle, "/t/file")

    def test_exclude_without_stable_inode(self) -> None:
        oracle = FakeOracle(dirs=["/net/share"], unstable=["/net/share"])
        with self.assertRaisesRegex(
            CheckError, "without stable inode numbers, unsupported: /net/share$"
        ):
            excludes(oracle, "/net/share")

    def test_symlink_loop_exclude(self) -> None:
        oracle = FakeOracle(links={"/t/loop": "/t/loop2", "/t/loop2": "/t/loop"})
        self.assertEqual(
            excludes(oracle, "/t/loop").notes,
            ("exclude /t/loop not found, nothing to skip",),
        )

    def test_notes_name_paths_bare(self) -> None:
        oracle = FakeOracle(dirs=["/t/secret", "/t/a"])
        notes = excludes(oracle, "/t/secret", "/t/missing").notes
        notes += resolve_roots(
            ("/t/secret/..", "/t/secret"),
            (),
            excludes(oracle, "/t/secret"),
            CWD,
            HOME,
            oracle,
        ).notes
        self.assertEqual(len(notes), 3)
        for note in notes:
            self.assertNotIn("[", note)


class RootTest(unittest.TestCase):
    def roots(
        self,
        oracle: FakeOracle,
        texts: tuple[str, ...],
        *excluded: str,
        defaults: tuple[Path, ...] = (),
    ):
        return resolve_roots(
            texts, defaults, excludes(oracle, *excluded), CWD, HOME, oracle
        )

    def test_parent_is_filesystem_root(self) -> None:
        oracle = FakeOracle(dirs=["/exclroot", "/openroot"])
        result = self.roots(oracle, ("/",), "/exclroot")
        self.assertEqual([r.path for r in result.scope.roots], [Path("/")])
        self.assertFalse(
            result.scope.permits_path(Path("/exclroot/cacert.pem"), oracle)
        )
        self.assertTrue(result.scope.permits_path(Path("/openroot/cacert.pem"), oracle))

    def test_exclude_resolves_to_root(self) -> None:
        oracle = FakeOracle(dirs=["/scan"])
        result = self.roots(oracle, ("/scan",), "/..")
        self.assertEqual(result.scope.roots, ())
        self.assertEqual(
            result.notes,
            ("scan root /scan lies inside an excluded directory, skipped",),
        )
        self.assertFalse(result.scope.permits_path(Path("/etc/ssl/cert.pem"), oracle))

    def test_nested_root_excluded(self) -> None:
        oracle = FakeOracle(dirs=["/t/a/b"])
        result = self.roots(oracle, ("/t/a", "/t/a/b"), "/t/a/b")
        self.assertEqual([r.path for r in result.scope.roots], [Path("/t/a")])
        self.assertEqual(
            result.notes,
            ("scan root /t/a/b lies inside an excluded directory, skipped",),
        )
        result = self.roots(oracle, ("/t/a/b",), "/t/a")
        self.assertEqual(result.scope.roots, ())

    def test_nested_root_inside_root_both_orders(self) -> None:
        oracle = FakeOracle(dirs=["/t/a/b"])
        want = (
            Finding(
                Level.INFO,
                Subject("scan", "/t/a/b"),
                "lies inside scan root [/t/a], skipped",
            ),
        )
        for texts in (("/t/a", "/t/a/b"), ("/t/a/b", "/t/a")):
            with self.subTest(texts=texts):
                result = self.roots(oracle, texts)
                self.assertEqual([r.path for r in result.scope.roots], [Path("/t/a")])
                self.assertEqual(result.findings, want)
        self.assertEqual(
            want[0].line(), "INFO  scan [/t/a/b] lies inside scan root [/t/a], skipped"
        )

    def test_root_through_symlinked_parent_into_exclude(self) -> None:
        oracle = FakeOracle(dirs=["/t/secret/b"], links={"/t/via": "/t/secret"})
        result = self.roots(oracle, ("/t/via/b",), "/t/secret")
        self.assertEqual(result.scope.roots, ())
        self.assertEqual(
            result.notes,
            ("scan root /t/secret/b lies inside an excluded directory, skipped",),
        )

    def test_root_inside_exclude_stops_at_the_excluded_id(self) -> None:
        oracle = FakeOracle(dirs=["/t/secret/deep/er"], forbid_below="/t/secret")
        result = self.roots(oracle, ("/t",), "/t/secret")
        self.assertFalse(
            result.scope.permits_path(Path("/t/secret/deep/er/x.pem"), oracle)
        )

    def test_fixed_bin_dir_inside_exclude(self) -> None:
        oracle = FakeOracle(dirs=["/home/u/.cargo/bin"])
        scope = self.roots(oracle, ("/home/u",), "/home/u/.cargo").scope
        self.assertFalse(scope.permits_path(Path("/home/u/.cargo/bin"), oracle))
        self.assertTrue(scope.permits_path(Path("/home/u/go/bin"), oracle))

    def test_duplicates_keep_the_first(self) -> None:
        oracle = FakeOracle(dirs=["/t/a"], links={"/t/l": "/t/a"})
        result = self.roots(oracle, ("/t/l", "/t/a", "/t/a/."))
        self.assertEqual([r.path for r in result.scope.roots], [Path("/t/a")])
        self.assertEqual(result.findings, ())

    def test_missing_root(self) -> None:
        oracle = FakeOracle(dirs=["/t"])
        with self.assertRaisesRegex(
            CheckError, "^scan root is not a directory: /nope$"
        ):
            self.roots(oracle, ("/nope",))

    def test_root_that_is_a_file(self) -> None:
        oracle = FakeOracle(files=["/t/f"])
        with self.assertRaisesRegex(CheckError, "^scan root is not a directory: /t/f$"):
            self.roots(oracle, ("/t/f",))

    def test_home_is_the_default_root(self) -> None:
        oracle = FakeOracle(dirs=["/home/u"])
        self.assertEqual(
            [r.path for r in self.roots(oracle, ()).scope.roots], [Path("/home/u")]
        )

    def test_missing_default_root_is_dropped(self) -> None:
        oracle = FakeOracle(dirs=["/home/u", "/Applications"])
        defaults = default_roots("Darwin", HOME, Path("/opt/homebrew"))
        result = self.roots(oracle, (), defaults=defaults)
        self.assertEqual(
            [r.path for r in result.scope.roots],
            [Path("/home/u"), Path("/Applications")],
        )
        self.assertEqual(result.notes, ())

    def test_default_root_inside_an_exclude(self) -> None:
        oracle = FakeOracle(dirs=["/home/u", "/opt/homebrew/etc"])
        result = self.roots(
            oracle, (), "/opt/homebrew", defaults=(Path("/opt/homebrew/etc"),)
        )
        self.assertEqual([r.path for r in result.scope.roots], [Path("/home/u")])

    def test_root_without_stable_inodes(self) -> None:
        oracle = FakeOracle(dirs=["/net/a", "/net/b"], unstable=["/net/a", "/net/b"])
        result = self.roots(oracle, ("/net/a", "/net/b"))
        self.assertEqual(
            [r.path for r in result.scope.roots], [Path("/net/a"), Path("/net/b")]
        )
        self.assertEqual(
            result.notes[0],
            "scan root /net/a is on a file system without stable inode numbers, files may be reported more than once",
        )

    def test_root_records_its_device(self) -> None:
        oracle = FakeOracle(dirs=["/t/a"])
        root = self.roots(oracle, ("/t/a",)).scope.roots[0]
        self.assertEqual((root.file_id, root.dev), (oracle.id_of("/t/a"), 1))


class DefaultRootsTest(unittest.TestCase):
    def test_per_system(self) -> None:
        self.assertEqual(
            default_roots("Linux", HOME, Path("/home/linuxbrew/.linuxbrew")), ()
        )
        self.assertEqual(
            default_roots("Darwin", HOME, None),
            (Path("/Applications"), HOME / "Applications"),
        )
        self.assertEqual(
            default_roots("Darwin", HOME, Path("/opt/homebrew")),
            (
                Path("/Applications"),
                HOME / "Applications",
                Path("/opt/homebrew/etc"),
                Path("/opt/homebrew/Caskroom"),
            ),
        )


class ProgramPathTest(unittest.TestCase):
    def test_rows(self) -> None:
        fixed = frozenset({Path("/home/u/go/bin")})
        globs = frozenset({".cache/codex-runtimes/*/payload"})
        rows = [
            ("/home/u/go/bin/hello", True),
            ("/home/u/go/bin/sub/hello", False),
            ("/opt/tool/bin/tool", True),
            ("/opt/tool/sbin/tool", True),
            ("/p/node_modules/x/bin/cli", False),
            ("/Applications/Foo.app/Contents/MacOS/Foo", True),
            ("/home/u/.cache/codex-runtimes/1.2/payload", True),
            ("/home/u/src/tool", False),
            ("/home/u/bin.d/tool", False),
            ("/home/u/src/go-bin/tool", False),
        ]
        for path, want in rows:
            with self.subTest(path=path):
                self.assertIs(is_program_path(Path(path), fixed, globs), want)


class InterestsTest(unittest.TestCase):
    interests = FileInterests(
        name_globs=frozenset({"cacerts", "cacert*", "requirements*.txt"}),
        suffixes=frozenset({".pem", ".cer"}),
        dir_globs=frozenset({"*.dist-info", ".nvm/versions/node/v*"}),
    )

    def test_rows(self) -> None:
        rows = [
            ("/x/cacerts", True),
            ("/x/my-cacerts", False),
            ("/x/cacert-x.pem", True),
            ("/x/cacert", True),
            ("/x/requirements-dev.txt", True),
            ("/x/requirements.txt.orig", False),
            ("/x/ca-bundle.cer", True),
            ("/x/pem", False),
            ("/x/site-packages/certifi-2026.7.22.dist-info", True),
            ("/home/u/.nvm/versions/node/v24.22.0", True),
            ("/home/u/nvm/versions/node/v24.22.0", False),
            ("/x/CACERTS", False),
        ]
        for path, want in rows:
            with self.subTest(path=path):
                self.assertIs(self.interests.matches(Path(path)), want)

    def test_union(self) -> None:
        union = FileInterests(name_globs=frozenset({"go.mod"})).union(
            FileInterests(executables=True)
        )
        self.assertTrue(union.matches(Path("/x/go.mod")))
        self.assertTrue(union.executables)


class PruneTest(unittest.TestCase):
    def test_ten_suffixes(self) -> None:
        self.assertEqual(len(PRUNE_SUFFIXES), 10)

    def test_rows(self) -> None:
        rows = [
            ("/r/.git", True),
            ("/r/x/.Trash", True),
            ("/home/u/Library/Containers", True),
            ("/home/u/Library/Group Containers", True),
            ("/home/u/Library/Mobile Documents", True),
            ("/home/u/.local/share/containers", True),
            ("/home/u/Library", False),
            ("/home/u/MyLibrary/Containers", False),
            ("/r/.github", False),
            ("/home/u/share/containers", False),
        ]
        for path, want in rows:
            with self.subTest(path=path):
                self.assertIs(is_pruned(Path(path)), want)


if __name__ == "__main__":
    unittest.main()
