"""test_adapter_process.py: tests of emudhra_check/adapters/process.py with real child processes.

Runs small shell scripts in the test container to check tool lookup, the scope check, the working
directory, the environment allowlist, the timeout, the output limit and decoding.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Iterable, Optional

from emudhra_check.adapters.filesystem import LocalPathOracle
from emudhra_check.adapters.process import LocalCommands
from emudhra_check.hostenv import HostEnvironment, child_environment, filter_path
from emudhra_check.limits import MAX_COMMAND_OUTPUT
from emudhra_check.scope import FileId, ScanScope, resolve_excludes
from emudhra_check.versions import Version

ORACLE = LocalPathOracle()
ALLOWED = {
    "PATH",
    "HOME",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "GOTOOLCHAIN",
    "PIP_DISABLE_PIP_VERSION_CHECK",
}
ALLOWED |= {"PYTHONDONTWRITEBYTECODE"}
SHELL_SET = {"PWD", "SHLVL", "_", "OLDPWD"}


def file_id(path: Path) -> FileId:
    st = os.stat(path)
    return FileId(st.st_dev, st.st_ino)


def script(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n" + body + "\n")
    path.chmod(0o755)
    return path


class Owners(LocalPathOracle):
    """The real oracle with owner and mode from a table, root and 0755 for any path not listed."""

    def __init__(self, table: dict[Path, tuple[int, int]]) -> None:
        self.table = table

    def owner_and_mode(self, path: Path) -> Optional[tuple[int, int]]:
        return self.table.get(path, (0, 0o40755))


class CommandsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(dir="/tmp")))

    def tearDown(self) -> None:
        subprocess.run(["rm", "-rf", str(self.tmp)], check=False)

    def commands(
        self,
        path_text: str = "/usr/bin:/bin",
        excluded: Iterable[Path] = (),
        oracle: LocalPathOracle = ORACLE,
        euid: int = 1000,
    ) -> LocalCommands:
        excludes = resolve_excludes(
            tuple(str(p) for p in excluded), Path("/"), self.tmp, ORACLE
        )
        dirs, _ = filter_path(path_text, excludes, ORACLE)
        hostenv = HostEnvironment(
            "Linux", self.tmp, dirs, None, None, None, None, Version("3", (3,))
        )
        environ = {"TMPDIR": "/tmp", "PYTHONPATH": "/evil", "SECRET": "x"}
        return LocalCommands(
            hostenv,
            ScanScope((), excludes.ids),
            child_environment(hostenv, environ),
            oracle,
            euid,
        )

    def test_root_run_refuses_a_tool_a_user_can_change(self) -> None:
        marker = self.tmp / "EXECUTED-tool"
        tool = script(self.tmp / "bin" / "tool", f": >{marker}")
        (self.tmp / "links").mkdir()
        (self.tmp / "links" / "sh").symlink_to("/bin/sh")
        rows: list[tuple[str, dict[Path, tuple[int, int]], int, bool]] = [
            ("all root", {}, 0, False),
            ("file owned by a user", {tool: (1000, 0o100755)}, 0, True),
            ("directory group-writable", {tool.parent: (0, 0o40775)}, 0, True),
            ("ancestor world-writable", {self.tmp.parent: (0, 0o40777)}, 0, True),
            ("not root", {tool: (1000, 0o100755)}, 1000, False),
        ]
        for name, owners, euid, writable in rows:
            with self.subTest(name):
                commands = self.commands(
                    f"{self.tmp}/bin", oracle=Owners(owners), euid=euid
                )
                found = commands.which("tool")
                assert found is not None
                self.assertIs(found.writable, writable)
                if writable:
                    with self.assertRaises(ValueError):
                        commands.run(found, [])
                else:
                    self.assertEqual(commands.run(found, []).returncode, 0)
                    marker.unlink()
        self.assertFalse(marker.exists())
        owners = {self.tmp / "links": (1000, 0o40777)}
        commands = self.commands(f"{self.tmp}/links", oracle=Owners(owners), euid=0)
        linked = commands.which("sh")
        assert linked is not None
        self.assertFalse(linked.writable)

    def test_true_and_exit_code(self) -> None:
        commands = self.commands()
        true = commands.locate(Path("/bin/true"))
        assert true is not None
        self.assertTrue(true.permitted)
        self.assertEqual(true.file_id, file_id(true.real))
        self.assertEqual(commands.run(true, []).returncode, 0)
        sh = commands.which("sh")
        assert sh is not None
        self.assertEqual(sh.file_id, file_id(sh.real))
        result = commands.run(sh, ["-c", "exit 3"])
        self.assertEqual(
            (
                result.returncode,
                result.stdout,
                result.stderr,
                result.timed_out,
                result.overran,
            ),
            (3, "", "", False, False),
        )

    def test_locate_inside_an_exclude(self) -> None:
        tool = script(self.tmp / "secret" / "tool", "echo ran")
        commands = self.commands(excluded=[self.tmp / "secret"])
        found = commands.locate(tool)
        assert found is not None
        self.assertFalse(found.permitted)
        with self.assertRaises(ValueError):
            commands.run(found, [])

    def test_link_from_a_searched_directory_into_an_exclude(self) -> None:
        marker = self.tmp / "EXECUTED-tool"
        script(self.tmp / "secret" / "tool", f"touch {marker}")
        (self.tmp / "bin").mkdir()
        (self.tmp / "bin" / "tool").symlink_to(self.tmp / "secret" / "tool")
        commands = self.commands(
            f"{self.tmp}/bin:/usr/bin", excluded=[self.tmp / "secret"]
        )
        found = commands.which("tool")
        assert found is not None
        self.assertEqual(
            (found.path, found.permitted), (self.tmp / "bin" / "tool", False)
        )
        with self.assertRaises(ValueError):
            commands.run(found, [])
        self.assertFalse(marker.exists())

    def test_timeout_kills_the_process_group(self) -> None:
        pid_file = self.tmp / "pid"
        tool = script(self.tmp / "slow", f"sleep 5 & echo $! > {pid_file}; wait")
        commands = self.commands()
        located = commands.locate(tool)
        assert located is not None
        result = commands.run(located, [], timeout=1)
        self.assertTrue(result.timed_out)
        child = pid_file.read_text().strip()
        status = Path(f"/proc/{child}/status")
        self.assertTrue(not status.exists() or "\nState:\tZ" in status.read_text())

    def test_invalid_utf8_and_empty_output(self) -> None:
        commands = self.commands()
        sh = commands.which("sh")
        assert sh is not None
        self.assertEqual(commands.run(sh, ["-c", "printf 'a\\377b'"]).stdout, "a�b")
        self.assertEqual(commands.run(sh, ["-c", ":"]).stdout, "")

    def test_output_limit(self) -> None:
        commands = self.commands()
        sh = commands.which("sh")
        assert sh is not None
        result = commands.run(sh, ["-c", "head -c 10485760 /dev/zero"])
        self.assertTrue(result.overran)
        self.assertLessEqual(len(result.stdout), MAX_COMMAND_OUTPUT)

    def test_relative_path_entry_is_never_searched(self) -> None:
        marker = Path("/tmp/EXECUTED-node")
        script(self.tmp / "node", f"touch {marker}")
        cwd = os.getcwd()
        os.chdir(self.tmp)
        try:
            commands = self.commands(".:/usr/bin")
            self.assertEqual(commands.hostenv.path_dirs, (Path("/usr/bin"),))
            found = commands.which("node")
            if found is not None:
                commands.run(found, ["--version"])
        finally:
            os.chdir(cwd)
        self.assertFalse(marker.exists())

    def test_working_directory_environment_and_argv0(self) -> None:
        (self.tmp / "bin").mkdir()
        (self.tmp / "bin" / "show").symlink_to("/bin/sh")
        commands = self.commands(f"{self.tmp}/bin")
        found = commands.which("show")
        assert found is not None
        self.assertEqual(found.real, Path(os.path.realpath("/bin/sh")))
        lines = commands.run(found, ["-c", 'pwd; echo "$0"; env']).stdout.splitlines()
        self.assertEqual(lines[:2], ["/", str(self.tmp / "bin" / "show")])
        names = {line.split("=", 1)[0] for line in lines[2:]}
        self.assertLessEqual(names - SHELL_SET, ALLOWED)
        self.assertNotIn("PYTHONPATH", names)
        self.assertNotIn("SECRET", names)

    def test_locate_dir(self) -> None:
        (self.tmp / "jdk" / "bin").mkdir(parents=True)
        (self.tmp / "secret").mkdir()
        commands = self.commands(excluded=[self.tmp / "secret"])
        self.assertEqual(commands.locate_dir(self.tmp / "jdk"), self.tmp / "jdk")
        self.assertIsNone(commands.locate_dir(self.tmp / "secret"))
        self.assertIsNone(commands.locate_dir(self.tmp / "missing"))

    def test_relative_locate_is_refused(self) -> None:
        self.assertIsNone(self.commands().locate(Path("bin/true")))


if __name__ == "__main__":
    unittest.main()
