"""test_adapter_podman.py: tests of emudhra_check/adapters/podman.py against tests/fixtures/fake-podman.

Runs LocalPodman with the fake podman first on PATH: the hardened run flags with -- before the image,
image names that look like options or hold shell characters, stdin closed, the image list, the
preflight errors, and the timeout, overrun and no-shell statuses with the container removed by name.
Also runs the CLI with -i against the fake to check a missing image ends the run before the header.
"""

from __future__ import annotations

import contextlib
import io
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from emudhra_check import cli
from emudhra_check.adapters.filesystem import LocalPathOracle
from emudhra_check.adapters.podman import LocalPodman, probe_script
from emudhra_check.adapters.process import LocalCommands
from emudhra_check.detections.ports import ProbeStatus
from emudhra_check.errors import CheckError
from emudhra_check.hostenv import HostEnvironment, child_environment, filter_path
from emudhra_check.scope import ScanScope, resolve_excludes
from emudhra_check.versions import Version

FAKE = Path(__file__).resolve().parents[1] / "fixtures" / "fake-podman"
ORACLE = LocalPathOracle()
RUN_FLAGS = [
    "--network=none",
    "--pull=never",
    "--cap-drop=all",
    "--security-opt=no-new-privileges",
    "--read-only",
    "--pids-limit=256",
    "--memory=512m",
]


class PodmanTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(dir="/tmp")))
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        shutil.copy(FAKE, self.bin / "podman")
        (self.bin / "podman").chmod(0o755)

    def tearDown(self) -> None:
        subprocess.run(["rm", "-rf", str(self.tmp)], check=False)

    def mode(self, mode: str) -> None:
        (self.bin / "mode").write_text(mode)

    def podman(self, timeout: int = 60, grace: int = 30) -> LocalPodman:
        excludes = resolve_excludes((), Path("/"), self.tmp, ORACLE)
        path_dirs, _ = filter_path(f"{self.bin}:/usr/bin:/bin", excludes, ORACLE)
        hostenv = HostEnvironment(
            "Linux",
            self.tmp,
            path_dirs,
            None,
            None,
            None,
            None,
            Version("3.13.5", (3, 13, 5)),
        )
        commands = LocalCommands(
            hostenv, ScanScope((), frozenset()), child_environment(hostenv, {})
        )
        tool = commands.which("podman")
        assert tool is not None
        return LocalPodman(
            commands,
            tool,
            probe_timeout=timeout,
            grace=grace,
            extra_env={"XDG_RUNTIME_DIR": "/run/u"},
        )

    def calls(self) -> list[list[str]]:
        count = int((self.bin / "count").read_text())
        return [
            (self.bin / "calls" / str(n)).read_bytes().decode().split("\0")[:-1]
            for n in range(1, count + 1)
        ]

    def test_run_flags_and_image_as_one_argument(self) -> None:
        self.mode("ok")
        podman = self.podman()
        for image in ("--privileged", "a;b c"):
            self.assertIs(podman.probe(image).status, ProbeStatus.OK)
        for call, image in zip(self.calls(), ("--privileged", "a;b c")):
            self.assertEqual(call[:2], ["run", "--rm"])
            for flag in RUN_FLAGS + ["--timeout=60"]:
                self.assertIn(flag, call)
            dash = call.index("--")
            self.assertEqual(call[dash - 2 : dash], ["--entrypoint", "sh"])
            self.assertEqual(call[dash + 1 : dash + 3], [image, "-c"])
            self.assertEqual(call[dash + 3], probe_script())
            self.assertEqual(len(call), dash + 4)
        self.assertEqual((self.bin / "stdin" / "1").read_text().strip(), "/dev/null")

    def test_image_list_drops_untagged_and_duplicates(self) -> None:
        self.mode("ok")
        podman = self.podman()
        podman.preflight(())
        self.assertEqual(podman.names, ("a:1", "b:2"))

    def test_preflight_errors(self) -> None:
        self.mode("missing")
        with self.assertRaisesRegex(CheckError, "image not found locally .*: x:1$"):
            self.podman().preflight(("x:1",))
        self.mode("imagesfail")
        with self.assertRaisesRegex(
            CheckError, "^podman images failed: Error: cannot connect to Podman$"
        ):
            self.podman().preflight(())

    def test_flood_is_an_overrun_and_the_container_is_removed(self) -> None:
        self.mode("flood")
        self.assertIs(self.podman().probe("img").status, ProbeStatus.OVERRUN)
        run, remove = self.calls()
        self.assertEqual(remove, ["rm", "-f", "--", run[run.index("--name") + 1]])

    def test_timeout_and_the_container_is_removed(self) -> None:
        self.mode("sleep")
        self.assertIs(
            self.podman(timeout=1, grace=1).probe("img").status, ProbeStatus.TIMEOUT
        )
        run, remove = self.calls()
        self.assertIn("--timeout=1", run)
        self.assertEqual(remove[:3], ["rm", "-f", "--"])

    def test_exit_codes(self) -> None:
        for mode, status in (
            ("noshell", ProbeStatus.NO_SHELL),
            ("fail", ProbeStatus.FAILED),
        ):
            with self.subTest(mode=mode):
                self.mode(mode)
                self.assertIs(self.podman().probe("img").status, status)

    def test_missing_image_ends_the_run_before_the_header(self) -> None:
        self.mode("missing")
        out, err = io.StringIO(), io.StringIO()
        env = {"PATH": f"{self.bin}:/usr/bin:/bin", "HOME": str(self.tmp)}
        with mock.patch.dict(os.environ, env, clear=True), contextlib.redirect_stdout(
            out
        ):
            with contextlib.redirect_stderr(err):
                code = cli.main(["-r", str(self.tmp), "-i", "absent:none"])
        self.assertEqual(code, 2)
        self.assertEqual(out.getvalue(), "")
        self.assertIn(
            "image not found locally (or podman is not running): absent:none",
            err.getvalue(),
        )

    def test_podman_inside_an_exclude_is_refused(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        env = {"PATH": f"{self.bin}:/usr/bin:/bin", "HOME": str(self.tmp)}
        with mock.patch.dict(os.environ, env, clear=True), contextlib.redirect_stdout(
            out
        ):
            with contextlib.redirect_stderr(err):
                code = cli.main(["-r", str(self.tmp), "-x", str(self.bin), "-c"])
        self.assertEqual(code, 2)
        self.assertIn("-c needs podman, which was not found", err.getvalue())
        self.assertFalse((self.bin / "count").exists())


if __name__ == "__main__":
    unittest.main()
