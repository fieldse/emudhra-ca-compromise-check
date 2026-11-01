"""hostenv.py: what the host's environment and PATH say, read once and checked against the scope.

Filters PATH to absolute directories outside every excluded directory, finds the Homebrew prefix
from the PATH directory holding brew without running it, builds the child processes' allowlisted
environment, lists the fixed binary directories, decides whether a macOS /usr/bin tool is a stub,
and decides whether a non-root user could change a tool a root run would execute. Pure over the
PathOracle and the OwnerOracle.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional, Protocol

from emudhra_check.scope import ExcludeSet, PathOracle, first_excluded
from emudhra_check.versions import Version

MACOS_STUBS = frozenset({Path("/usr/bin/python3")})
STICKY = 0o1000
CHILD_FIXED_ENV = {
    "LANG": "C",
    "LC_ALL": "C",
    "GOTOOLCHAIN": "local",
    "PIP_DISABLE_PIP_VERSION_CHECK": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
}


@dataclass(frozen=True)
class HostEnvironment:
    system: str
    home: Path
    path_dirs: tuple[Path, ...]
    brew_prefix: Optional[Path]
    gobin: Optional[str]
    gopath: Optional[str]
    java_home_env: Optional[str]
    running_python: Version


def filter_path(
    path_text: str, excludes: ExcludeSet, oracle: PathOracle
) -> tuple[tuple[Path, ...], tuple[str, ...]]:
    """Return PATH's absolute, existing, distinct directories outside every exclude, and the notes."""
    kept: list[Path] = []
    seen: set[object] = set()
    notes: list[str] = []
    for entry in path_text.split(":"):
        if not entry.startswith("/"):
            continue
        real = oracle.real_path(Path(entry))
        facts = oracle.facts(real)
        if facts is None or not facts.is_dir:
            continue
        if first_excluded(real, excludes.ids, oracle) is not None:
            notes.append(
                f"PATH entry {entry} lies inside an excluded directory, not searched"
            )
            continue
        identity = facts.file_id if facts.stable else real
        if identity in seen:
            continue
        seen.add(identity)
        kept.append(Path(entry))
    return tuple(kept), tuple(notes)


class OwnerOracle(Protocol):
    def owner_and_mode(self, path: Path) -> Optional[tuple[int, int]]:
        """Return the owner's uid and the mode of path without following a final symlink, or None."""
        ...


def writable_by_non_root(real: Path, oracle: OwnerOracle) -> bool:
    """Return whether a non-root user could change real: it or a directory above it is not owned by root
    or is group- or world-writable. A sticky directory counts as safe, since every entry below it on the
    path is root-owned and only root can rename or remove those. A path that cannot be stat'ed counts
    as writable. ACLs are not read."""
    for path in (real, *real.parents):
        facts = oracle.owner_and_mode(path)
        if facts is None:
            return True
        uid, mode = facts
        if uid != 0:
            return True
        if mode & 0o022 and not (path != real and mode & STICKY):
            return True
    return False


def find_brew_prefix(path_dirs: tuple[Path, ...], oracle: PathOracle) -> Optional[Path]:
    """Return the parent of the first PATH directory that holds brew, when it has a Cellar directory."""
    for directory in path_dirs:
        brew = oracle.facts(directory / "brew")
        if brew is None or brew.is_dir:
            continue
        cellar = oracle.facts(directory.parent / "Cellar")
        if cellar is not None and cellar.is_dir:
            return directory.parent
    return None


def child_environment(
    hostenv: HostEnvironment, environ: Mapping[str, str]
) -> dict[str, str]:
    """Return the allowlisted environment every child process gets."""
    env = {
        "PATH": ":".join(str(d) for d in hostenv.path_dirs),
        "HOME": str(hostenv.home),
    }
    if environ.get("TMPDIR"):
        env["TMPDIR"] = environ["TMPDIR"]
    env.update(CHILD_FIXED_ENV)
    return env


def is_macos_stub(path: Path, system: str, developer_tools_installed: bool) -> bool:
    """Return whether path is a macOS /usr/bin stub that prompts to install the developer tools."""
    return system == "Darwin" and path in MACOS_STUBS and not developer_tools_installed


def fixed_binary_dirs(hostenv: HostEnvironment) -> tuple[Path, ...]:
    """Return the directories whose programs the binary detections list: GOBIN, each GOPATH bin and the usual bins."""
    dirs: list[Path] = []
    if hostenv.gobin and hostenv.gobin.startswith("/"):
        dirs.append(Path(hostenv.gobin))
    gopaths = [p for p in (hostenv.gopath or "").split(":") if p.startswith("/")]
    for entry in gopaths or [str(hostenv.home / "go")]:
        dirs.append(Path(entry) / "bin")
    dirs += [hostenv.home / ".cargo" / "bin", hostenv.home / ".local" / "bin"]
    dirs.append(Path("/usr/local/bin"))
    if hostenv.brew_prefix is not None:
        dirs.append(hostenv.brew_prefix / "bin")
    return tuple(dict.fromkeys(dirs))


PODMAN_ENV_KEYS = ("XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS")


def podman_environment(environ: Mapping[str, str]) -> dict[str, str]:
    """Return the caller's variables rootless Podman needs to apply its resource limits."""
    return {key: environ[key] for key in PODMAN_ENV_KEYS if environ.get(key)}
