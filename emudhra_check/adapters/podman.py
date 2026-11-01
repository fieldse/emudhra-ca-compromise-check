"""podman.py: the Podman adapter, which lists local images and runs the probe inside each one.

LocalPodman checks before the run that the images exist, then runs the rendered probe in each image
with no network, no pull, no capabilities, no new privileges, a read-only root, a process and memory
limit and a Podman timeout, through LocalCommands. When the host deadline passes or the output
outgrows its cap, the client is killed and the container removed by name.
"""

from __future__ import annotations

import os
from importlib import resources
from typing import Mapping, Optional

from emudhra_check.adapters.process import LocalCommands
from emudhra_check.detections.ports import Located, ProbeRun, ProbeStatus
from emudhra_check.errors import CheckError
from emudhra_check.limits import (
    COMMAND_TIMEOUT,
    MAX_PROBE_OUTPUT,
    PROBE_GRACE,
    PROBE_TIMEOUT,
)
from emudhra_check.probe import render

NO_SHELL_CODES = (126, 127)


def probe_script() -> str:
    """Return the probe template from the package data, rendered."""
    return render(resources.files("emudhra_check").joinpath("probe.sh").read_text())


def first_line(text: str) -> str:
    lines = text.strip().splitlines()
    return lines[0] if lines else "no message"


class LocalPodman:
    """The local images the check probes, and how it probes one."""

    def __init__(
        self,
        commands: LocalCommands,
        podman: Located,
        probe_timeout: int = PROBE_TIMEOUT,
        grace: int = PROBE_GRACE,
        extra_env: Optional[Mapping[str, str]] = None,
    ) -> None:
        self.commands = commands
        self.podman = podman
        self.probe_timeout = probe_timeout
        self.grace = grace
        self.extra_env = dict(extra_env or {})
        self.names: tuple[str, ...] = ()
        self.count = 0
        self.script: Optional[str] = None

    def podman_run(self, args: list[str], timeout: int = COMMAND_TIMEOUT) -> str:
        """Run one short podman command and return its stdout, or raise CheckError when it fails."""
        result = self.commands.run(
            self.podman, args, timeout=timeout, extra_env=self.extra_env
        )
        if result.returncode != 0 or result.timed_out:
            raise CheckError(first_line(result.stderr))
        return result.stdout

    def preflight(self, images: tuple[str, ...]) -> None:
        """Check each -i image exists, or list the local images, before the run starts."""
        if images:
            for image in images:
                try:
                    self.podman_run(["image", "exists", "--", image])
                except CheckError:
                    raise CheckError(
                        f"image not found locally (or podman is not running): {image}"
                    ) from None
            self.names = tuple(dict.fromkeys(images))
            return
        try:
            out = self.podman_run(["images", "--format", "{{.Repository}}:{{.Tag}}"])
        except CheckError as error:
            raise CheckError(f"podman images failed: {error}") from None
        names = [n.strip() for n in out.splitlines()]
        self.names = tuple(dict.fromkeys(n for n in names if n and "<none>" not in n))

    def probe(self, name: str) -> ProbeRun:
        """Run the probe in one image and return its status and output."""
        if self.script is None:
            self.script = probe_script()
        self.count += 1
        container = f"emudhra-probe-{os.getpid()}-{self.count}"
        args = [
            "run",
            "--rm",
            "--name",
            container,
            "--network=none",
            "--pull=never",
            "--cap-drop=all",
            "--security-opt=no-new-privileges",
            "--read-only",
            "--pids-limit=256",
            "--memory=512m",
            f"--timeout={self.probe_timeout}",
            "--entrypoint",
            "sh",
            "--",
            name,
            "-c",
            self.script,
        ]
        result = self.commands.run(
            self.podman,
            args,
            timeout=self.probe_timeout + self.grace,
            limit=MAX_PROBE_OUTPUT,
            extra_env=self.extra_env,
        )
        output = result.stdout.encode("utf-8", errors="replace")
        if result.timed_out or result.overran:
            self.commands.run(
                self.podman,
                ["rm", "-f", "--", container],
                timeout=PROBE_GRACE,
                extra_env=self.extra_env,
            )
            status = ProbeStatus.TIMEOUT if result.timed_out else ProbeStatus.OVERRUN
            return ProbeRun(status, output)
        if result.returncode == 0:
            return ProbeRun(ProbeStatus.OK, output)
        if result.returncode in NO_SHELL_CODES:
            return ProbeRun(ProbeStatus.NO_SHELL, output)
        return ProbeRun(ProbeStatus.FAILED, output)
