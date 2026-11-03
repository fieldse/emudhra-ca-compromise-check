"""cli.py: command-line entry and composition root of the eMudhra CA compromise check.

Parses the arguments, builds the scan context from the environment, the excludes, PATH and the
roots in a fixed order, runs every registered detection inside its own exception boundary, prints
each finding as it arrives and the SUMMARY line, and returns the exit code. It is the only module
that imports both the detections and the adapters.
"""

from __future__ import annotations

import io
import os
import platform
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Optional, Sequence

from emudhra_check import buildinfo
from emudhra_check.adapters.filesystem import LocalFiles, LocalPathOracle
from emudhra_check.adapters.platform import LocalHost
from emudhra_check.adapters.podman import LocalPodman
from emudhra_check.adapters.process import LocalCommands
from emudhra_check.detections import REGISTRY
from emudhra_check.detections.ports import Context, Detection, Ledger
from emudhra_check.errors import CheckError
from emudhra_check.hostenv import (
    HostEnvironment,
    child_environment,
    filter_path,
    find_brew_prefix,
    fixed_binary_dirs,
    podman_environment,
)
from emudhra_check.limits import MAX_ERROR_CHARS
from emudhra_check.report import (
    Finding,
    Level,
    Subject,
    Summary,
    is_shown,
    note,
    sanitise,
)
from emudhra_check.scope import (
    FileInterests,
    default_roots,
    resolve_excludes,
    resolve_roots,
)
from emudhra_check.versions import running_cpython

Writer = Callable[[str], None]

USAGE = """\
Usage: {prog} [-r|--root ROOT]... [-x|--exclude DIR]... [-c|--containers] [-i|--image IMAGE]... \
[-q|--quiet] [-s|--strict] [-h|--help]

Read-only check for the eMudhra intermediate CA key compromise (October 2026).

Options:
  -r, --root ROOT   Directory to scan for CA bundles, keystores, binaries and package files
                    (repeatable, default $HOME). Also accepts --root=ROOT. On macOS, /Applications,
                    ~/Applications and the Homebrew etc and Caskroom directories are always added
  -x, --exclude DIR Never enter this directory (repeatable). Also accepts --exclude=DIR
  -c, --containers  Also probe local Podman images (runs a probe with --network=none)
  -i, --image IMAGE Probe only this local image (repeatable, implies -c)
  -q, --quiet       Print only FAIL, WARN and ERROR lines plus the summary
  -s, --strict      Exit 1 on WARN and ERROR as well as FAIL
  -h, --help        Show this help

A FAIL on a bundle, keystore or binary means it still contains one of the three emSign G3 roots
or a compromised intermediate, so software using it trusts certificates anyone can now issue.
Version FAILs mean a release older than the fix. AAA Certificate Services is reported as WARN.
Exit codes: 0 no FAIL, 1 any FAIL, 2 usage or environment error. A WARN or ERROR alone exits 0
unless --strict is given, which makes it exit 1.

Examples:
  python3 -I -S {prog} -r ~ -q
  python3 -I -S {prog} --root=/opt --containers
  python3 -I -S {prog} -r ~ -x ~/scratch -q
"""


class UsageError(Exception):
    """A command-line argument the check does not accept."""


@dataclass(frozen=True)
class Options:
    roots: tuple[str, ...] = ()
    excludes: tuple[str, ...] = ()
    images: tuple[str, ...] = ()
    containers: bool = False
    quiet: bool = False
    strict: bool = False
    help: bool = False


def parse_args(argv: Sequence[str]) -> Options:
    """Parse the command line as the Bash check did, with -x and --exclude added."""
    roots: list[str] = []
    excludes: list[str] = []
    images: list[str] = []
    flags = {"containers": False, "quiet": False, "strict": False, "help": False}
    lists = {
        "-r": roots,
        "--root": roots,
        "-x": excludes,
        "--exclude": excludes,
        "-i": images,
        "--image": images,
    }
    switches = {
        "-c": "containers",
        "--containers": "containers",
        "-q": "quiet",
        "--quiet": "quiet",
    }
    switches.update(
        {"-s": "strict", "--strict": "strict", "-h": "help", "--help": "help"}
    )
    args = list(argv)
    while args:
        arg = args.pop(0)
        name, equals, value = arg.partition("=")
        if arg in lists:
            if not args or not args[0]:
                raise UsageError(f"Option {arg} needs an argument")
            lists[arg].append(args.pop(0))
            if arg in ("-i", "--image"):
                flags["containers"] = True
        elif equals and name in ("--root", "--exclude"):
            if not value:
                raise UsageError(f"Option {name} needs an argument")
            lists[name].append(value)
        elif arg in switches:
            flags[switches[arg]] = True
            if arg in ("-h", "--help"):
                break
        else:
            raise UsageError(f"Unknown option: {arg} (try --help)")
    return Options(tuple(roots), tuple(excludes), tuple(images), **flags)


def all_interests(registry: Sequence[Detection]) -> FileInterests:
    """Return the union of every registered detection's interests."""
    union = FileInterests()
    for detection in registry:
        union = union.union(detection.interests)
    return union


def executable_globs(registry: Sequence[Detection]) -> frozenset[str]:
    """Return the dir_globs of the detections that want program candidates."""
    globs: frozenset[str] = frozenset()
    for detection in registry:
        if detection.interests.executables:
            globs = globs | detection.interests.dir_globs
    return globs


def podman_images(
    commands: LocalCommands, images: tuple[str, ...], env: Mapping[str, str]
) -> LocalPodman:
    """Find podman on the filtered PATH and run the preflight, or raise CheckError."""
    podman = commands.which("podman")
    if podman is None:
        raise CheckError("-c needs podman, which was not found")
    if not podman.permitted:
        raise CheckError("-c needs podman, found only inside an excluded directory")
    if podman.writable:
        raise CheckError(
            "-c needs podman, and a non-root user can change the one on PATH, not run as root"
        )
    local = LocalPodman(commands, podman, extra_env=env)
    local.preflight(images)
    return local


def build_context(
    options: Options,
    environ: Mapping[str, str],
    system: str,
    home: Path,
    cwd: Path,
    registry: Sequence[Detection] = REGISTRY,
) -> Context:
    """Build the scan context, each step taking the previous step's output."""
    oracle = LocalPathOracle()
    excludes = resolve_excludes(options.excludes, cwd, home, oracle)
    path_dirs, path_notes = filter_path(environ.get("PATH", ""), excludes, oracle)
    brew_prefix = find_brew_prefix(path_dirs, oracle)
    running = running_cpython(*sys.version_info[:5])
    hostenv = HostEnvironment(
        system,
        home,
        path_dirs,
        brew_prefix,
        environ.get("GOBIN"),
        environ.get("GOPATH"),
        environ.get("JAVA_HOME"),
        running,
    )
    result = resolve_roots(
        options.roots,
        default_roots(system, home, brew_prefix),
        excludes,
        cwd,
        home,
        oracle,
    )
    files = LocalFiles(result.scope, oracle)
    commands = LocalCommands(
        hostenv, result.scope, child_environment(hostenv, environ), oracle
    )
    host = LocalHost(commands, system, hostenv.java_home_env)
    images = (
        podman_images(commands, options.images, podman_environment(environ))
        if options.containers
        else None
    )
    index = files.walk(
        all_interests(registry),
        fixed_binary_dirs(hostenv),
        buildinfo.classify,
        executable_globs(registry),
    )
    return Context(
        result.scope,
        hostenv,
        index,
        files,
        commands,
        host,
        images,
        Ledger(),
        excludes.notes + path_notes + result.notes,
        result.findings,
        options.quiet,
        options.strict,
        options.containers,
    )


def header(context: Context) -> Finding:
    """Return the run's first line, which names the scan roots."""
    roots = "".join(f"{root.path} " for root in context.scope.roots)
    detail = f"eMudhra CA compromise check; scan roots: {roots}containers={int(context.containers)}"
    return Finding(Level.INFO, None, detail)


def failure(detection: Detection, error: Exception) -> Finding:
    message = f"{type(error).__name__}: {error}"[:MAX_ERROR_CHARS]
    return Finding(
        Level.ERROR, Subject("detection", detection.name), f"failed: {message}"
    )


def run(
    context: Context,
    registry: Sequence[Detection],
    prog: str,
    write: Writer,
    write_err: Writer,
) -> int:
    """Print the notes, the header, every finding and the summary, and return the exit code."""
    summary = Summary()

    def emit(finding: Finding) -> None:
        summary.add(finding.level)
        if is_shown(finding.level, context.quiet):
            write(finding.line())

    for text in context.notes:
        write_err(note(prog, text))
    emit(header(context))
    for finding in context.scope_findings + context.index.notices:
        emit(finding)
    for detection in registry:
        try:
            for finding in detection.run(context):
                emit(finding)
        except Exception as error:
            emit(failure(detection, error))
    refused = context.files.refused_reads()
    if refused:
        write_err(
            note(
                prog, f"{refused} host paths inside excluded directories were not read"
            )
        )
    write(summary.line())
    return summary.exit_code(context.strict)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the check with the process's arguments and environment and return the exit code."""
    prog = (
        os.path.basename(sys.argv[0]) if sys.argv and sys.argv[0] else "emudhra_check"
    )
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(errors="replace")

    def write(line: str) -> None:
        sys.stdout.write(line + "\n")

    def write_err(line: str) -> None:
        sys.stderr.write(line + "\n")

    try:
        options = parse_args(sys.argv[1:] if argv is None else argv)
    except UsageError as error:
        write_err(sanitise(str(error)))
        sys.stderr.write(USAGE.format(prog=prog))
        return 2
    if options.help:
        sys.stdout.write(USAGE.format(prog=prog))
        return 0
    try:
        context = build_context(
            options, os.environ, platform.system(), Path.home(), Path.cwd()
        )
        return run(context, REGISTRY, prog, write, write_err)
    except CheckError as error:
        write_err(f"{sanitise(prog)}: {sanitise(str(error))}")
        return 2
    except Exception as error:
        write_err(
            f"{sanitise(prog)}: internal error: {sanitise(type(error).__name__ + ': ' + str(error))}"
        )
        return 2
