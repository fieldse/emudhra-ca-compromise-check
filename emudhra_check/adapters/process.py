"""process.py: the process adapter, the only module that starts child processes.

LocalCommands finds tools on the filtered PATH or at a fixed path and runs them with cwd "/", the
allowlisted environment, stdin closed, the resolved file as the executable, a timeout and an output
limit. On either limit the child's whole process group is killed. Output is decoded with
errors="replace".
"""

from __future__ import annotations

import os
import selectors
import signal
import stat
import subprocess
import time
from pathlib import Path
from typing import Mapping, Optional, Sequence

from emudhra_check.adapters.filesystem import LocalPathOracle
from emudhra_check.detections.ports import CommandResult, Located
from emudhra_check.hostenv import HostEnvironment
from emudhra_check.limits import COMMAND_TIMEOUT, MAX_COMMAND_OUTPUT
from emudhra_check.scope import FileId, ScanScope

READ_SIZE = 64 * 1024
REAP_SECONDS = 5


def read_bounded(
    proc: subprocess.Popen[bytes], timeout: float, limit: int
) -> tuple[bytes, bytes, bool, bool]:
    """Read a child's stdout and stderr until both close, the deadline passes or limit bytes arrive."""
    deadline = time.monotonic() + timeout
    assert proc.stdout is not None and proc.stderr is not None
    out_fd, err_fd = proc.stdout.fileno(), proc.stderr.fileno()
    out: dict[int, list[bytes]] = {out_fd: [], err_fd: []}
    selector = selectors.DefaultSelector()
    for fd in out:
        selector.register(fd, selectors.EVENT_READ)
    total = 0
    timed_out = overran = False
    try:
        while selector.get_map() and not overran:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            for key, _ in selector.select(remaining):
                chunk = os.read(key.fd, READ_SIZE)
                if not chunk:
                    selector.unregister(key.fd)
                    continue
                keep = chunk[: max(0, limit - total)]
                total += len(chunk)
                out[key.fd].append(keep)
                if total > limit:
                    overran = True
                    break
        if not (timed_out or overran):
            try:
                proc.wait(max(0.0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                timed_out = True
    finally:
        selector.close()
    if timed_out or overran:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass
    try:
        proc.wait(REAP_SECONDS)
    except subprocess.TimeoutExpired:
        pass
    proc.stdout.close()
    proc.stderr.close()
    return b"".join(out[out_fd]), b"".join(out[err_fd]), timed_out, overran


class LocalCommands:
    """Finds and runs host tools inside the scan scope."""

    def __init__(
        self,
        hostenv: HostEnvironment,
        scope: ScanScope,
        env: Mapping[str, str],
        oracle: Optional[LocalPathOracle] = None,
    ) -> None:
        self.hostenv = hostenv
        self.scope = scope
        self.env = dict(env)
        self.oracle = oracle or LocalPathOracle()

    def located(self, path: Path) -> Optional[Located]:
        """Return a Located for an executable regular file at path, or None."""
        try:
            st = os.stat(path)
        except (OSError, ValueError):
            return None
        if not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111:
            return None
        real = Path(os.path.realpath(path))
        permitted = self.scope.permits_path(real, self.oracle)
        return Located(path, real, permitted, FileId(st.st_dev, st.st_ino))

    def which(self, name: str) -> Optional[Located]:
        """Return the first executable named name in the filtered PATH directories."""
        for directory in self.hostenv.path_dirs:
            found = self.located(directory / name)
            if found is not None:
                return found
        return None

    def locate(self, path: Path) -> Optional[Located]:
        """Return a Located for one fixed absolute path that is not on PATH."""
        return self.located(path) if path.is_absolute() else None

    def locate_dir(self, path: Path) -> Optional[Path]:
        """Return the real path of a directory inside the scope, or None."""
        real = Path(os.path.realpath(path))
        try:
            if not stat.S_ISDIR(os.stat(real).st_mode):
                return None
        except (OSError, ValueError):
            return None
        return real if self.scope.permits_path(real, self.oracle) else None

    def run(
        self,
        tool: Located,
        args: Sequence[str],
        timeout: int = COMMAND_TIMEOUT,
        limit: int = MAX_COMMAND_OUTPUT,
        extra_env: Optional[Mapping[str, str]] = None,
    ) -> CommandResult:
        """Run a permitted tool and return its bounded, decoded output.

        extra_env adds variables to the allowlisted environment for this one child.
        """
        if not tool.permitted:
            raise ValueError(
                f"refusing to run {tool.path}, it lies inside an excluded directory"
            )
        proc = subprocess.Popen(
            [str(tool.path), *args],
            executable=str(tool.real),
            cwd="/",
            env={**self.env, **(extra_env or {})},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        stdout, stderr, timed_out, overran = read_bounded(proc, timeout, limit)
        return CommandResult(
            proc.returncode,
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
            timed_out,
            overran,
        )
