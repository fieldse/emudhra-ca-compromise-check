"""test_adapter_platform.py: unit tests of emudhra_check/adapters/platform.py.

Replays macOS tool output through a Commands fake. security-*.txt and xcode-select-p.txt were
recorded on a Mac. java_home-V-none.txt was recorded on a Mac with no JDK, and
java_home-V-example.txt is written in the format java_home -V prints to stderr.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from typing import Optional, Sequence

from emudhra_check.adapters.platform import LocalHost, java_home_paths
from emudhra_check.detections.ports import CommandResult, Located

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "macos"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def located(path: str, permitted: bool = True) -> Located:
    return Located(Path(path), Path(path), permitted, None)


class FakeCommands:
    """Answers which, locate, locate_dir and run from tables."""

    def __init__(
        self,
        tools: dict[str, Located],
        results: dict[str, CommandResult],
        dirs: Sequence[str] = (),
    ) -> None:
        self.tools = tools
        self.results = results
        self.dirs = set(dirs)
        self.ran: list[tuple[str, tuple[str, ...]]] = []

    def which(self, name: str) -> Optional[Located]:
        return self.tools.get(name)

    def locate(self, path: Path) -> Optional[Located]:
        return self.tools.get(str(path))

    def locate_dir(self, path: Path) -> Optional[Path]:
        return path if str(path) in self.dirs else None

    def run(self, tool: Located, args: Sequence[str]) -> CommandResult:
        if not tool.permitted:
            raise ValueError("not permitted")
        self.ran.append((str(tool.path), tuple(args)))
        return self.results[tool.path.name]


def result(code: int, stdout: str = "", stderr: str = "") -> CommandResult:
    return CommandResult(code, stdout, stderr, False, False)


def host(
    commands: FakeCommands, system: str = "Darwin", java_home: Optional[str] = None
) -> LocalHost:
    return LocalHost(commands, system, java_home)


class KeychainTest(unittest.TestCase):
    def test_found(self) -> None:
        commands = FakeCommands(
            {"/usr/bin/security": located("/usr/bin/security")},
            {"security": result(0, fixture("security-found.txt"))},
        )
        self.assertTrue(host(commands).keychain_has("emSign ECC Root CA - G3"))
        self.assertEqual(
            commands.ran,
            [
                (
                    "/usr/bin/security",
                    (
                        "find-certificate",
                        "-c",
                        "emSign ECC Root CA - G3",
                        "/System/Library/Keychains/SystemRootCertificates.keychain",
                    ),
                )
            ],
        )

    def test_not_found(self) -> None:
        commands = FakeCommands(
            {"/usr/bin/security": located("/usr/bin/security")},
            {"security": result(44, "", fixture("security-notfound.txt"))},
        )
        self.assertFalse(host(commands).keychain_has("AAA Certificate Services"))

    def test_not_on_linux(self) -> None:
        commands = FakeCommands({"/usr/bin/security": located("/usr/bin/security")}, {})
        self.assertFalse(host(commands, "Linux").keychain_has("x"))
        self.assertEqual(commands.ran, [])

    def test_security_inside_an_exclude(self) -> None:
        commands = FakeCommands(
            {"/usr/bin/security": located("/usr/bin/security", False)}, {}
        )
        self.assertFalse(host(commands).keychain_has("x"))

    def test_path_lookups_are_never_used(self) -> None:
        commands = FakeCommands(
            {
                "security": located("/tmp/bin/security"),
                "xcode-select": located("/tmp/bin/xcode-select"),
            },
            {"security": result(0), "xcode-select": result(0, "/x")},
        )
        local = host(commands)
        self.assertFalse(local.keychain_has("x"))
        self.assertFalse(local.developer_tools_installed())
        self.assertEqual(commands.ran, [])

    def test_tools_a_non_root_user_can_change_are_not_run(self) -> None:
        writable = {
            path: Located(Path(path), Path(path), True, None, True)
            for path in ("/usr/bin/security", "/usr/bin/xcode-select")
        }
        commands = FakeCommands(
            writable, {"security": result(0), "xcode-select": result(0, "/x")}
        )
        local = host(commands)
        self.assertFalse(local.keychain_has("x"))
        self.assertFalse(local.developer_tools_installed())
        self.assertEqual(commands.ran, [])


class DeveloperToolsTest(unittest.TestCase):
    def test_installed_and_asked_once(self) -> None:
        commands = FakeCommands(
            {"/usr/bin/xcode-select": located("/usr/bin/xcode-select")},
            {"xcode-select": result(0, fixture("xcode-select-p.txt"))},
        )
        local = host(commands)
        self.assertTrue(local.developer_tools_installed())
        self.assertTrue(local.developer_tools_installed())
        self.assertEqual(len(commands.ran), 1)

    def test_not_installed(self) -> None:
        commands = FakeCommands(
            {"/usr/bin/xcode-select": located("/usr/bin/xcode-select")},
            {"xcode-select": result(2, "", "error")},
        )
        self.assertFalse(host(commands).developer_tools_installed())


class JavaHomesTest(unittest.TestCase):
    homes = [
        "/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home",
        "/Library/Java/JavaVirtualMachines/jdk-17.jdk/Contents/Home",
    ]

    def test_listing_parser(self) -> None:
        self.assertEqual(
            java_home_paths(fixture("java_home-V-example.txt")), self.homes
        )
        self.assertEqual(java_home_paths(fixture("java_home-V-none.txt")), [])

    def test_three_sources_on_macos(self) -> None:
        commands = FakeCommands(
            {
                "java": Located(
                    Path("/usr/bin/java"), Path("/opt/jdk/bin/java"), True, None
                ),
                "/usr/libexec/java_home": located("/usr/libexec/java_home"),
            },
            {"java_home": result(0, "", fixture("java_home-V-example.txt"))},
            dirs=["/env/jdk", *self.homes],
        )
        self.assertEqual(
            host(commands, java_home="/env/jdk").java_homes(),
            (Path("/env/jdk"), Path("/opt/jdk"), *(Path(h) for h in self.homes)),
        )

    def test_java_inside_an_exclude(self) -> None:
        commands = FakeCommands(
            {
                "java": Located(
                    Path("/usr/bin/java"), Path("/secret/jdk/bin/java"), False, None
                )
            },
            {},
        )
        self.assertEqual(host(commands, "Linux").java_homes(), ())

    def test_java_home_env_outside_the_scope(self) -> None:
        self.assertEqual(
            host(FakeCommands({}, {}), "Linux", "/secret/jdk").java_homes(), ()
        )

    def test_linux_never_runs_java_home(self) -> None:
        commands = FakeCommands(
            {"/usr/libexec/java_home": located("/usr/libexec/java_home")}, {}
        )
        self.assertEqual(host(commands, "Linux").java_homes(), ())
        self.assertEqual(commands.ran, [])

    def test_mac_with_no_jdk(self) -> None:
        commands = FakeCommands(
            {"/usr/libexec/java_home": located("/usr/libexec/java_home")},
            {"java_home": result(1, "", fixture("java_home-V-none.txt"))},
        )
        self.assertEqual(host(commands).java_homes(), ())


if __name__ == "__main__":
    unittest.main()
