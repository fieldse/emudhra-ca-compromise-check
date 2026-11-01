"""test_hostenv.py: unit tests of emudhra_check/hostenv.py.

Filters PATH, finds the Homebrew prefix, lists the fixed binary directories and decides macOS stubs
against a dictionary-backed oracle.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from typing import Optional

from emudhra_check.hostenv import (
    HostEnvironment,
    child_environment,
    filter_path,
    find_brew_prefix,
    fixed_binary_dirs,
    is_macos_stub,
)
from emudhra_check.scope import ExcludeSet, PathFacts, resolve_excludes
from emudhra_check.versions import Version
from tests.unit.test_scope import FakeOracle

CWD = Path("/t")
HOME = Path("/home/u")


class LinkOracle(FakeOracle):
    """FakeOracle whose facts follow symlinks, as os.stat does."""

    def facts(self, path: Path) -> Optional[PathFacts]:
        return super().facts(self.real_path(path))


def none_excluded() -> ExcludeSet:
    return ExcludeSet(frozenset(), (), ())


class FilterPathTest(unittest.TestCase):
    def test_table(self) -> None:
        oracle = LinkOracle(
            dirs=["/usr/bin", "/t/excl/tools/bin", "/opt/bin"],
            links={"/t/usrbin": "/usr/bin"},
        )
        excludes = resolve_excludes(("/t/excl",), CWD, HOME, oracle)
        text = ":.:relative/bin:/missing:/t/excl/tools/bin:/usr/bin:/t/usrbin:/opt/bin:/usr/bin:"
        dirs, notes = filter_path(text, excludes, oracle)
        self.assertEqual(dirs, (Path("/usr/bin"), Path("/opt/bin")))
        self.assertEqual(
            notes,
            (
                "PATH entry /t/excl/tools/bin lies inside an excluded directory, not searched",
            ),
        )
        for note in notes:
            self.assertNotIn("[", note)

    def test_link_into_an_exclude(self) -> None:
        oracle = LinkOracle(dirs=["/t/excl/bin"], links={"/t/links": "/t/excl/bin"})
        excludes = resolve_excludes(("/t/excl",), CWD, HOME, oracle)
        self.assertEqual(filter_path("/t/links", excludes, oracle)[0], ())

    def test_empty(self) -> None:
        self.assertEqual(filter_path("", none_excluded(), LinkOracle()), ((), ()))


class BrewPrefixTest(unittest.TestCase):
    def test_apple_silicon(self) -> None:
        oracle = LinkOracle(
            dirs=["/opt/homebrew/bin", "/opt/homebrew/Cellar", "/usr/bin"],
            files=["/opt/homebrew/bin/brew"],
        )
        self.assertEqual(
            find_brew_prefix((Path("/usr/bin"), Path("/opt/homebrew/bin")), oracle),
            Path("/opt/homebrew"),
        )

    def test_intel_link_into_homebrew_repository(self) -> None:
        oracle = LinkOracle(
            dirs=["/usr/local/bin", "/usr/local/Cellar", "/usr/local/Homebrew/bin"],
            files=["/usr/local/Homebrew/bin/brew"],
            links={"/usr/local/bin/brew": "/usr/local/Homebrew/bin/brew"},
        )
        self.assertEqual(
            find_brew_prefix((Path("/usr/local/bin"),), oracle), Path("/usr/local")
        )

    def test_no_cellar(self) -> None:
        oracle = LinkOracle(dirs=["/opt/tools/bin"], files=["/opt/tools/bin/brew"])
        self.assertIsNone(find_brew_prefix((Path("/opt/tools/bin"),), oracle))

    def test_no_brew(self) -> None:
        oracle = LinkOracle(dirs=["/opt/homebrew/bin", "/opt/homebrew/Cellar"])
        self.assertIsNone(find_brew_prefix((Path("/opt/homebrew/bin"),), oracle))


class StubTest(unittest.TestCase):
    def test_per_system(self) -> None:
        python = Path("/usr/bin/python3")
        self.assertTrue(is_macos_stub(python, "Darwin", False))
        self.assertFalse(is_macos_stub(python, "Darwin", True))
        self.assertFalse(is_macos_stub(python, "Linux", False))
        self.assertFalse(
            is_macos_stub(Path("/opt/homebrew/bin/python3"), "Darwin", False)
        )


class ChildEnvironmentTest(unittest.TestCase):
    def test_allowlist(self) -> None:
        hostenv = HostEnvironment(
            "Linux",
            HOME,
            (Path("/usr/bin"), Path("/bin")),
            None,
            None,
            None,
            None,
            Version("3.13.5", (3, 13, 5)),
        )
        environ = {
            "TMPDIR": "/var/tmp",
            "PYTHONPATH": "/evil",
            "LD_PRELOAD": "x.so",
            "NODE_OPTIONS": "-r x",
            "PATH": ".:/x",
        }
        self.assertEqual(
            child_environment(hostenv, environ),
            {
                "PATH": "/usr/bin:/bin",
                "HOME": "/home/u",
                "TMPDIR": "/var/tmp",
                "LANG": "C",
                "LC_ALL": "C",
                "GOTOOLCHAIN": "local",
                "PIP_DISABLE_PIP_VERSION_CHECK": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
        self.assertNotIn("TMPDIR", child_environment(hostenv, {}))


def env_with(
    gobin: Optional[str] = None,
    gopath: Optional[str] = None,
    brew: Optional[str] = None,
) -> HostEnvironment:
    return HostEnvironment(
        "Darwin",
        HOME,
        (),
        Path(brew) if brew else None,
        gobin,
        gopath,
        None,
        Version("3.9.6", (3, 9, 6)),
    )


class FixedBinaryDirsTest(unittest.TestCase):
    def test_defaults(self) -> None:
        self.assertEqual(
            fixed_binary_dirs(env_with()),
            tuple(
                Path(p)
                for p in (
                    "/home/u/go/bin",
                    "/home/u/.cargo/bin",
                    "/home/u/.local/bin",
                    "/usr/local/bin",
                )
            ),
        )

    def test_gobin_gopath_entries_and_homebrew(self) -> None:
        got = fixed_binary_dirs(
            env_with("/g/bin", "/p1:relative::/p2", "/opt/homebrew")
        )
        self.assertEqual(got[:3], (Path("/g/bin"), Path("/p1/bin"), Path("/p2/bin")))
        self.assertEqual(got[-1], Path("/opt/homebrew/bin"))
        self.assertNotIn(Path("/home/u/go/bin"), got)

    def test_relative_gobin_is_ignored(self) -> None:
        self.assertEqual(fixed_binary_dirs(env_with("bin"))[0], Path("/home/u/go/bin"))


if __name__ == "__main__":
    unittest.main()
