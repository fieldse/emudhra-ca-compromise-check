"""platform.py: the platform adapter, the host facts that come from macOS tools and Java homes.

LocalHost answers whether the macOS developer tools are installed (/usr/bin/xcode-select -p),
whether the macOS system roots keychain lists a certificate (/usr/bin/security find-certificate),
and which Java homes exist (JAVA_HOME, the java on PATH, and /usr/libexec/java_home -V on macOS).
The three macOS tools are called by absolute path. Every tool runs through LocalCommands and is
skipped inside an excluded directory or, in a root run, when a non-root user can change it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from emudhra_check.adapters.process import LocalCommands
from emudhra_check.detections.ports import Located

SYSTEM_ROOTS_KEYCHAIN = "/System/Library/Keychains/SystemRootCertificates.keychain"
JAVA_HOME_TOOL = Path("/usr/libexec/java_home")
XCODE_SELECT_TOOL = Path("/usr/bin/xcode-select")
SECURITY_TOOL = Path("/usr/bin/security")


def runnable(tool: Optional[Located]) -> Optional[Located]:
    """Return the tool when it may run: outside every exclude and, in a root run, root's alone."""
    if tool is None or not tool.permitted or tool.writable:
        return None
    return tool


def java_home_paths(listing: str) -> list[str]:
    """Return the home paths in java_home -V output, one per JVM line."""
    paths = []
    for line in listing.splitlines():
        _, quote, path = line.rpartition('" ')
        if quote and path.startswith("/"):
            paths.append(path.strip())
    return paths


class LocalHost:
    """Host facts read through LocalCommands."""

    def __init__(
        self, commands: LocalCommands, system: str, java_home_env: Optional[str]
    ) -> None:
        self.commands = commands
        self.system = system
        self.java_home_env = java_home_env
        self.developer_tools: Optional[bool] = None

    def developer_tools_installed(self) -> bool:
        """Return whether xcode-select -p names a developer directory, on macOS only, asked once."""
        if self.developer_tools is None:
            self.developer_tools = False
            tool = (
                runnable(self.commands.locate(XCODE_SELECT_TOOL))
                if self.system == "Darwin"
                else None
            )
            if tool is not None:
                result = self.commands.run(tool, ["-p"])
                self.developer_tools = result.returncode == 0 and bool(
                    result.stdout.strip()
                )
        return self.developer_tools

    def keychain_has(self, label: str) -> bool:
        """Return whether the macOS system roots keychain lists a certificate with this label."""
        if self.system != "Darwin":
            return False
        tool = runnable(self.commands.locate(SECURITY_TOOL))
        if tool is None:
            return False
        result = self.commands.run(
            tool, ["find-certificate", "-c", label, SYSTEM_ROOTS_KEYCHAIN]
        )
        return result.returncode == 0 and not result.timed_out

    def java_homes(self) -> tuple[Path, ...]:
        """Return the Java homes from JAVA_HOME, the java on PATH and java_home -V, each inside the scope."""
        homes: list[Path] = []
        if self.java_home_env and self.java_home_env.startswith("/"):
            real = self.commands.locate_dir(Path(self.java_home_env))
            if real is not None:
                homes.append(real)
        java = self.commands.which("java")
        if java is not None and java.permitted:
            homes.append(java.real.parent.parent)
        if self.system == "Darwin":
            tool = runnable(self.commands.locate(JAVA_HOME_TOOL))
            if tool is not None:
                for text in java_home_paths(self.commands.run(tool, ["-V"]).stderr):
                    real = self.commands.locate_dir(Path(text))
                    if real is not None:
                        homes.append(real)
        return tuple(dict.fromkeys(homes))
