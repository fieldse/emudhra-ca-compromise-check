"""runtimes.py: detections of the runtimes on PATH and in Node version managers.

BunHost, NodeHost, DenoHost, GoToolchain and CPythonHost ask each runtime on the filtered PATH for its
version and judge it against its fixed release, and the three that bundle a root store also have
their binary scanned. NodeVersionDirs judges Node installs from nvm, volta, asdf, fnm and mise by
directory name and binary content. Each binary is claimed in the ledger before it is read or run, so
a node that links to bun is reported once, as bun.
"""

from __future__ import annotations

import dataclasses
from enum import Enum
from pathlib import Path
from typing import Callable, ClassVar, Iterator, Optional, Sequence

from emudhra_check.buildinfo import node_release_version
from emudhra_check.certificates import (
    G3_ECC_ROOT,
    ISRG_ROOT_X1_LINE,
    CertificateMatch,
    MatchKind,
    match_finding,
)
from emudhra_check.detections.ports import Context, Located
from emudhra_check.detections.shared import (
    MATCHER,
    content_findings,
    find_tool,
    not_run_finding,
    read_or_skip,
    release,
    run_tool,
)
from emudhra_check.fixes import (
    BUN_FIXED,
    CPYTHON_BUNDLED_PIP,
    CPYTHON_FIXED,
    DENO_FIXED,
    GO_FIXED,
    NODE_FIXED,
)
from emudhra_check.hostenv import is_macos_stub
from emudhra_check.limits import MAX_BINARY_BYTES, MAX_FIELD_CHARS, MAX_TEXT_BYTES
from emudhra_check.report import Finding, Level, Subject
from emudhra_check.scope import FileId, FileInterests
from emudhra_check.versions import (
    judge,
    judge_branched,
    parse_cpython_version,
    parse_version,
)

__all__ = [
    "BunHost",
    "CPythonHost",
    "DenoHost",
    "GoToolchain",
    "NodeHost",
    "NodeVersionDirs",
    "StoreKind",
    "bun_version",
    "deno_version",
    "go_version",
    "node_store_findings",
    "node_version",
    "python_version",
]

GO_TOOLCHAIN_MINIMUM = dataclasses.replace(
    GO_FIXED,
    below=Level.INFO,
    no_fix=Level.INFO,
    note="a minimum, not a pin; the installed go and the built binaries decide",
)
CPYTHON_OLDEST_FIXED_BRANCH = (3, 11)
# Each manager's install directories, including nvm's layout for Node below 0.12.0, fnm's ~/.fnm and mise --system.
VERSION_MANAGERS = (
    ((".nvm", "versions", "node"), "v"),
    ((".nvm",), "v"),
    ((".volta", "tools", "image", "node"), ""),
    ((".asdf", "installs", "nodejs"), ""),
    (("fnm", "node-versions"), "v"),
    ((".fnm", "node-versions"), "v"),
    ((".local", "share", "mise", "installs", "node"), ""),
    (("local", "share", "mise", "installs", "node"), ""),
)
NODE_BINARIES = ("bin/node", "installation/bin/node")


class StoreKind(Enum):
    """Whether a Node binary holds its own root list. Upstream Node always compiles one in."""

    BUNDLED = "bundled"
    OS = "os"


def token(text: str) -> Optional[str]:
    """Return text when it is a plausible version field, else None."""
    return text if 0 < len(text) <= MAX_FIELD_CHARS else None


def first_line_words(output: str) -> list[str]:
    lines = output.strip().splitlines()
    return lines[0].split() if lines else []


def node_version(output: str) -> Optional[str]:
    """Return the version in node --version output such as v24.22.0."""
    words = first_line_words(output)
    return token(words[0][1:]) if words and words[0].startswith("v") else None


def bun_version(output: str) -> Optional[str]:
    """Return the version in bun --version output such as 1.4.4."""
    words = first_line_words(output)
    return token(words[0]) if words else None


def deno_version(output: str) -> Optional[str]:
    """Return the version in the first line of deno --version, such as deno 2.9.8 (stable, ...)."""
    words = first_line_words(output)
    return token(words[1]) if len(words) >= 2 and words[0] == "deno" else None


def go_version(output: str) -> Optional[str]:
    """Return the version in go version output such as go version go1.27.2 linux/amd64."""
    words = first_line_words(output)
    if len(words) < 3 or words[:2] != ["go", "version"]:
        return None
    field = words[3] if words[2] == "devel" and len(words) >= 4 else words[2]
    return token(field[2:]) if field.startswith("go") else None


def python_version(output: str) -> Optional[str]:
    """Return the version in python3 --version output such as Python 3.13.5."""
    words = first_line_words(output)
    return token(words[1]) if len(words) >= 2 and words[0] == "Python" else None


def node_store_findings(
    subject: Subject,
    version: str,
    matches: Sequence[CertificateMatch],
    store: StoreKind,
    binary: Optional[str] = None,
) -> list[Finding]:
    """Judge a Node binary by its version, then note the bundled G3 root or a missing bundled root list."""
    verdict = judge_branched(subject, version, NODE_FIXED)
    findings = [verdict]
    where = Subject(subject.name, binary or subject.where)
    g3 = any(m.label == G3_ECC_ROOT.label and m.kind is MatchKind.FULL for m in matches)
    if store is StoreKind.OS:
        detail = "binary bundles no Node.js root list (a patched build), judged by its version"
        findings.append(Finding(Level.INFO, where, detail))
    elif g3 and verdict.level is not Level.FAIL:
        detail = f"binary still bundles {G3_ECC_ROOT.label}"
        findings.append(Finding(Level.FAIL, where, detail))
    elif g3:
        detail = f"binary bundles {G3_ECC_ROOT.label} (confirms the version FAIL)"
        findings.append(Finding(Level.INFO, where, detail))
    elif verdict.level is Level.FAIL and binary is not None:
        detail = (
            f"binary does not bundle {G3_ECC_ROOT.label} (custom build or system CA store);"
            " upgrade anyway"
        )
        findings.append(Finding(Level.INFO, where, detail))
    for match in matches:
        if not (match.label == G3_ECC_ROOT.label and match.kind is MatchKind.FULL):
            findings.append(match_finding(where, match))
    return findings


def scan_node_binary(
    ctx: Context,
    subject: Subject,
    version: Optional[str],
    path: Path,
    file_id: Optional[FileId],
) -> list[Finding]:
    """Read a Node binary and judge it, or judge the version alone when it cannot be read.

    A version of None is read from the release URL the binary names.
    """
    data = read_or_skip(
        ctx, Subject(subject.name, str(path)), path, MAX_BINARY_BYTES, file_id
    )
    if isinstance(data, list):
        if version is None:
            return data
        return data + node_store_findings(subject, version, (), StoreKind.BUNDLED)
    try:
        version = version or node_release_version(data) or "unknown"
        matches = MATCHER.scan(data)
        has_store = data.find(ISRG_ROOT_X1_LINE) >= 0
    finally:
        release(data)
    g3 = any(m.label == G3_ECC_ROOT.label for m in matches)
    store = StoreKind.BUNDLED if has_store or g3 else StoreKind.OS
    return node_store_findings(subject, version, matches, store, str(path))


def claimed(ctx: Context, tool: Located) -> bool:
    """Claim a tool's binary, returning False when another detection already reported it."""
    return tool.file_id is None or ctx.ledger.claim(tool.file_id)


def version_of(
    ctx: Context,
    tool: Located,
    name: str,
    args: list[str],
    parse: Callable[[str], Optional[str]],
) -> tuple[list[Finding], Optional[str]]:
    """Run a tool's version command and parse it with parse, or return the timeout or unreadable line."""
    result = run_tool(ctx, tool, name, args)
    if isinstance(result, list):
        return result, None
    version = parse(result.stdout or result.stderr)
    if version is None:
        return [Finding(Level.WARN, Subject(name, "host"), "version unreadable")], None
    return [], version


class BunHost:
    """The bun on PATH: its version, and the roots its binary holds."""

    name: ClassVar[str] = "bun-host"
    interests: ClassVar[FileInterests] = FileInterests()

    def run(self, ctx: Context) -> Iterator[Finding]:
        tool = find_tool(ctx, "bun")
        if isinstance(tool, list):
            yield from tool
            return
        if not claimed(ctx, tool):
            return
        lines, version = version_of(ctx, tool, "bun", ["--version"], bun_version)
        yield from lines
        if version is not None:
            yield judge(Subject("bun", "host"), version, BUN_FIXED)
        yield from content_findings(
            ctx,
            Subject("bun", str(tool.real)),
            tool.real,
            tool.file_id,
            MAX_BINARY_BYTES,
        )


class NodeHost:
    """The node on PATH, judged by version and by the binary process.execPath names."""

    name: ClassVar[str] = "node-host"
    interests: ClassVar[FileInterests] = FileInterests()

    def run(self, ctx: Context) -> Iterator[Finding]:
        tool = find_tool(ctx, "node")
        if isinstance(tool, list):
            yield from tool or [
                Finding(Level.INFO, Subject("node", "host"), "not installed")
            ]
            return
        if not claimed(ctx, tool):
            return
        if tool.writable:
            yield not_run_finding("node")
            yield from scan_node_binary(
                ctx, Subject("node", "host"), None, tool.real, tool.file_id
            )
            return
        lines, version = version_of(ctx, tool, "node", ["--version"], node_version)
        yield from lines
        if version is None:
            return
        binary, file_id = tool.real, tool.file_id
        result = run_tool(ctx, tool, "node", ["-p", "process.execPath"])
        if not isinstance(result, list) and result.returncode == 0:
            words = result.stdout.strip().splitlines()
            exec_path = Path(words[0]) if words and words[0].startswith("/") else None
            exec_id = ctx.files.file_id(exec_path) if exec_path is not None else None
            if exec_path is not None and exec_id is not None and exec_id != file_id:
                if not ctx.ledger.claim(exec_id):
                    yield judge_branched(Subject("node", "host"), version, NODE_FIXED)
                    return
                binary, file_id = exec_path, exec_id
        yield from scan_node_binary(
            ctx, Subject("node", "host"), version, binary, file_id
        )


class DenoHost:
    """The deno on PATH: its version, and the roots and blocked keys its binary holds."""

    name: ClassVar[str] = "deno-host"
    interests: ClassVar[FileInterests] = FileInterests()

    def run(self, ctx: Context) -> Iterator[Finding]:
        tool = find_tool(ctx, "deno")
        if isinstance(tool, list):
            yield from tool
            return
        if not claimed(ctx, tool):
            return
        lines, version = version_of(ctx, tool, "deno", ["--version"], deno_version)
        yield from lines
        if version is not None:
            yield judge(Subject("deno", "host"), version, DENO_FIXED)
        yield from content_findings(
            ctx,
            Subject("deno", str(tool.real)),
            tool.real,
            tool.file_id,
            MAX_BINARY_BYTES,
        )


def toolchain_line(text: str) -> Optional[str]:
    """Return the version of the first toolchain line in a go.mod, such as toolchain go1.27.2."""
    for line in text.splitlines():
        words = line.split("//", 1)[0].split()
        if len(words) == 2 and words[0] == "toolchain" and words[1].startswith("go"):
            return token(words[1][2:])
    return None


class GoToolchain:
    """The go on PATH, and the toolchain minimums go.mod files declare."""

    name: ClassVar[str] = "go-toolchain"
    interests: ClassVar[FileInterests] = FileInterests(name_globs=frozenset({"go.mod"}))

    def run(self, ctx: Context) -> Iterator[Finding]:
        tool = find_tool(ctx, "go")
        if isinstance(tool, list):
            yield from tool
        elif claimed(ctx, tool):
            lines, version = version_of(ctx, tool, "go", ["version"], go_version)
            yield from lines
            if version is not None:
                yield judge_branched(Subject("go", "host"), version, GO_FIXED)
        for indexed in ctx.index.files_for(self.interests):
            where = f"{indexed.path} toolchain minimum"
            data = read_or_skip(
                ctx, Subject("go", where), indexed.real, MAX_TEXT_BYTES, indexed.file_id
            )
            if isinstance(data, list):
                yield from data
                continue
            try:
                version = toolchain_line(
                    data[0 : len(data)].decode("utf-8", errors="replace")
                )
            finally:
                release(data)
            if version is not None:
                yield judge_branched(
                    Subject("go", where), version, GO_TOOLCHAIN_MINIMUM
                )


def cpython_findings(subject: Subject, version: str) -> list[Finding]:
    """Judge a CPython version: end-of-life branches have no fix, the rest by their branch's ssl fix, with a
    note on branches whose fixed release still bundles an affected pip."""
    parsed = parse_cpython_version(version)
    if parsed is None:
        return [judge_branched(subject, version, CPYTHON_FIXED, parse_cpython_version)]
    if parsed.release[:2] < CPYTHON_OLDEST_FIXED_BRANCH:
        return [Finding(Level.WARN, subject, f"found {version}, end-of-life, no fix")]
    findings = [judge_branched(subject, version, CPYTHON_FIXED, parse_cpython_version)]
    branch = ".".join(str(n) for n in parsed.release[:2])
    pip = dict(CPYTHON_BUNDLED_PIP).get(branch)
    fixed = dict(CPYTHON_FIXED.fixes).get(branch)
    if pip is not None and fixed is not None:
        detail = (
            f"{fixed} blocks the compromised keys in ssl but bundles pip {pip},"
            " whose certifi is affected, the pip and certifi checks decide"
        )
        findings.append(Finding(Level.INFO, subject, detail))
    return findings


class CPythonHost:
    """The python3 on PATH, and the interpreter running the check when it differs."""

    name: ClassVar[str] = "cpython-host"
    interests: ClassVar[FileInterests] = FileInterests()

    def run(self, ctx: Context) -> Iterator[Finding]:
        running = ctx.hostenv.running_python.text
        found = None
        tool = find_tool(ctx, "python3")
        if isinstance(tool, list):
            yield from tool
        elif not (
            ctx.hostenv.system == "Darwin"
            and is_macos_stub(
                tool.path, ctx.hostenv.system, ctx.host.developer_tools_installed()
            )
        ):
            lines, found = version_of(
                ctx, tool, "python3", ["--version"], python_version
            )
            yield from lines
            if found is not None:
                yield from cpython_findings(Subject("python3", "host"), found)
        if found != running:
            yield from cpython_findings(Subject("python3", "running"), running)


def manager_version(path: Path) -> Optional[str]:
    """Return the Node version a version-manager directory names, or None for any other directory."""
    for parent, prefix in VERSION_MANAGERS:
        if path.parent.parts[-len(parent) :] != parent:
            continue
        name = path.name
        if prefix and not name.startswith(prefix):
            return None
        version = name[len(prefix) :]
        return version if parse_version(version) is not None else None
    return None


class NodeVersionDirs:
    """Node installs from nvm, volta, asdf, fnm and mise under the scan roots."""

    name: ClassVar[str] = "node-version-dirs"
    interests: ClassVar[FileInterests] = FileInterests(
        dir_globs=frozenset(
            {
                ".nvm/versions/node/v*",
                ".nvm/v*",
                ".volta/tools/image/node/*",
                ".asdf/installs/nodejs/*",
                "fnm/node-versions/v*",
                ".fnm/node-versions/v*",
                ".local/share/mise/installs/node/*",
                "local/share/mise/installs/node/*",
            }
        )
    )

    def run(self, ctx: Context) -> Iterator[Finding]:
        found = 0
        for indexed in ctx.index.dirs_for(self.interests):
            version = manager_version(indexed.path)
            if version is None:
                continue
            found += 1
            subject = Subject("node", str(indexed.path))
            binary = None
            for relative in NODE_BINARIES:
                file_id = ctx.files.file_id(indexed.path / relative)
                if file_id is not None:
                    binary = (indexed.path / relative, file_id)
                    break
            if binary is None:
                yield from node_store_findings(subject, version, (), StoreKind.BUNDLED)
            elif ctx.ledger.claim(binary[1]):
                yield from scan_node_binary(ctx, subject, version, *binary)
        if found == 0:
            detail = "no nvm, volta, asdf, fnm or mise installs under scan roots"
            yield Finding(Level.INFO, Subject("node", "version managers"), detail)
