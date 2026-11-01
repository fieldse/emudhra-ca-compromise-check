"""language_packages.py: detections of language packages that vendor a CA bundle.

PythonDistInfo judges certifi, pip and uv from installed dist-info directories, PythonPins the certifi
pins in requirements files and locks, HostPythonPackages the certifi and pip the host python3 sees
(read from metadata in a child python3 -I -S that imports no package), and UvHost the uv on PATH by
version and by the roots its binary holds. A package installed by a distribution is judged by the
bundle it resolves to.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar, Iterator, Optional, Union

from emudhra_check.detections.ports import Context, Located
from emudhra_check.detections.shared import (
    content_findings,
    find_tool,
    read_or_skip,
    release,
    run_tool,
)
from emudhra_check.fixes import CERTIFI_FIXED, CERTIFI_RECOMMENDED, PIP_FIXED, UV_FIXED
from emudhra_check.hostenv import is_macos_stub
from emudhra_check.limits import MAX_BINARY_BYTES, MAX_FIELD_CHARS, MAX_TEXT_BYTES
from emudhra_check.lockfiles import (
    normalise,
    package_count,
    pipfile_versions,
    requirement_pins,
    toml_package_versions,
)
from emudhra_check.report import Finding, Level, Subject
from emudhra_check.scope import FileId, FileInterests
from emudhra_check.versions import judge

__all__ = [
    "HostPythonPackages",
    "PythonDistInfo",
    "PythonPins",
    "UvHost",
    "python_package_finding",
]

RULES = {"certifi": CERTIFI_FIXED, "pip": PIP_FIXED, "uv": UV_FIXED}
BUNDLES = {"certifi": "certifi/cacert.pem", "pip": "pip/_vendor/certifi/cacert.pem"}
DISTRO_INSTALLERS = frozenset({"dpkg", "rpm", "apk", "brew"})
TOML_LOCKS = frozenset({"poetry.lock", "uv.lock"})
NO_BUNDLE = "no bundled cacert.pem, patched to use the system store"
CHILD_SCRIPT = """\
import sys
if sys.version_info < (3, 8):
    sys.stdout.write("NOPY %d.%d.%d\\n" % sys.version_info[:3])
    sys.exit(0)
import os
import site
import importlib.metadata as metadata


def venv(path):
    here = os.path.dirname(path)
    for candidate in (here, os.path.dirname(here)):
        if os.path.isfile(os.path.join(candidate, "pyvenv.cfg")):
            return candidate
    return None


home = venv(sys.argv[1]) or venv(sys.executable)
if home:
    lib = "python%d.%d" % sys.version_info[:2]
    paths = [os.path.join(home, "lib", lib, "site-packages")]
else:
    paths = list(site.getsitepackages())
paths.append(site.getusersitepackages())
for dist in metadata.distributions(path=paths):
    name = (dist.metadata["Name"] or "").lower()
    if name in ("certifi", "pip"):
        installer = (dist.read_text("INSTALLER") or "").strip().splitlines()
        location = str(dist.locate_file(""))
        fields = (name, dist.version, installer[0] if installer else "unknown", location)
        sys.stdout.write("\\t".join(fields) + "\\n")
"""


def python_package_finding(
    subject: Subject, version: str, *, installer: str
) -> list[Finding]:
    """Judge certifi, pip or uv: by version when it vendors its bundle, else defer to the bundle it resolves to."""
    if installer in DISTRO_INSTALLERS:
        detail = f"found {version}, installed by {installer}, judged by the bundle it resolves to"
        return [Finding(Level.INFO, subject, detail)]
    findings = [judge(subject, version, RULES[subject.name])]
    if subject.name == "certifi" and version == CERTIFI_FIXED.fixed:
        detail = f"{CERTIFI_RECOMMENDED} or later restores unaffected emSign roots"
        findings.append(Finding(Level.INFO, subject, detail))
    return findings


def text_of(
    ctx: Context, subject: Subject, path: Path, expect: Optional[FileId] = None
) -> Union[str, list[Finding]]:
    """Read a small text file, or return the lines that explain why it was not read."""
    data = read_or_skip(ctx, subject, path, MAX_TEXT_BYTES, expect)
    if isinstance(data, list):
        return data
    try:
        return data[0 : len(data)].decode("utf-8", errors="replace")
    finally:
        release(data)


def bundle_findings_once(
    ctx: Context, name: str, bundle: Path, *, distro: bool
) -> list[Finding]:
    """Return the content verdict of a package's own bundle, once per file, and the line for a missing one."""
    subject = Subject(f"{name} bundle", str(bundle))
    file_id = ctx.files.file_id(bundle)
    if file_id is None:
        return [Finding(Level.INFO, subject, NO_BUNDLE)] if distro else []
    if not ctx.ledger.claim(file_id):
        return []
    return content_findings(ctx, subject, bundle, file_id)


class PythonDistInfo:
    """certifi, pip and uv dist-info directories under the scan roots."""

    name: ClassVar[str] = "python-dist-info"
    interests: ClassVar[FileInterests] = FileInterests(
        dir_globs=frozenset({"*.dist-info"})
    )

    def run(self, ctx: Context) -> Iterator[Finding]:
        for indexed in ctx.index.dirs_for(self.interests):
            stem = indexed.path.name[: -len(".dist-info")]
            package, dash, version = stem.partition("-")
            name = normalise(package)
            if not dash or name not in RULES:
                continue
            subject = Subject(name, str(indexed.path))
            text = text_of(ctx, subject, indexed.path / "INSTALLER")
            lines = text.strip().splitlines() if isinstance(text, str) else []
            installer = lines[0].strip()[:MAX_FIELD_CHARS] if lines else "unknown"
            yield from python_package_finding(subject, version, installer=installer)
            if installer in DISTRO_INSTALLERS and name in BUNDLES:
                bundle = indexed.path.parent / BUNDLES[name]
                yield from bundle_findings_once(ctx, name, bundle, distro=True)


class PythonPins:
    """certifi pins in requirements files, poetry.lock, uv.lock and Pipfile.lock."""

    name: ClassVar[str] = "python-pins"
    interests: ClassVar[FileInterests] = FileInterests(
        name_globs=frozenset(
            {"requirements*.txt", "poetry.lock", "uv.lock", "Pipfile.lock"}
        )
    )

    def run(self, ctx: Context) -> Iterator[Finding]:
        for indexed in ctx.index.files_for(self.interests):
            lock = indexed.path.name
            subject = Subject("certifi", str(indexed.path))
            lock_subject = Subject(lock, str(indexed.path))
            text = text_of(ctx, lock_subject, indexed.real, indexed.file_id)
            if isinstance(text, list):
                yield from text
                continue
            if lock in TOML_LOCKS:
                packages, complete = toml_package_versions(text, "certifi")
                versions = [p.version for p in packages]
                if not complete:
                    detail = f"partly unreadable, {package_count(text)} packages read"
                    yield Finding(Level.INFO, lock_subject, detail)
            elif lock == "Pipfile.lock":
                pinned = pipfile_versions(text, "certifi")
                if pinned is None:
                    yield Finding(Level.INFO, lock_subject, "unreadable, skipped")
                    continue
                versions = pinned
            else:
                versions = requirement_pins(text, "certifi")
            for version in versions:
                yield from python_package_finding(subject, version, installer="")


class HostPythonPackages:
    """certifi and pip as the python3 on PATH sees them, read from package metadata only."""

    name: ClassVar[str] = "host-python-packages"
    interests: ClassVar[FileInterests] = FileInterests()

    def run(self, ctx: Context) -> Iterator[Finding]:
        tool = find_tool(ctx, "python3")
        if isinstance(tool, list):
            yield from tool
            return
        system = ctx.hostenv.system
        if system == "Darwin" and is_macos_stub(
            tool.path, system, ctx.host.developer_tools_installed()
        ):
            return
        result = run_tool(
            ctx, tool, "python3", ["-I", "-S", "-c", CHILD_SCRIPT, str(tool.path)]
        )
        if isinstance(result, list):
            yield from result
            return
        records = []
        for line in result.stdout.splitlines():
            if line.startswith("NOPY "):
                yield self.not_inspected(line[len("NOPY ") :].strip())
                return
            fields = line.split("\t")
            if len(fields) == 4 and fields[0] in BUNDLES:
                records.append(fields)
        if result.returncode != 0 and not records:
            yield self.not_inspected(self.version(ctx, tool))
            return
        for name, version, installer, location in records:
            subject = Subject(name, "host python")
            yield from python_package_finding(subject, version, installer=installer)
            bundle = Path(location) / BUNDLES[name]
            distro = installer in DISTRO_INSTALLERS
            yield from bundle_findings_once(ctx, name, bundle, distro=distro)

    @staticmethod
    def not_inspected(version: str) -> Finding:
        detail = f"{version} predates importlib.metadata, certifi and pip not inspected"
        return Finding(Level.WARN, Subject("python3", "host"), detail)

    @staticmethod
    def version(ctx: Context, tool: Located) -> str:
        result = run_tool(ctx, tool, "python3", ["--version"])
        if isinstance(result, list):
            return "unknown"
        words = (result.stdout or result.stderr).split()
        return words[1] if len(words) >= 2 else "unknown"


def uv_version(output: str) -> Optional[str]:
    """Return the version in uv --version output such as "uv 0.13.4 (abc 2026-10-20)"."""
    words = output.split()
    if len(words) >= 2 and words[0] == "uv":
        return words[1]
    return None


class UvHost:
    """The uv on PATH: its version, and the roots its binary holds."""

    name: ClassVar[str] = "uv-host"
    interests: ClassVar[FileInterests] = FileInterests()

    def run(self, ctx: Context) -> Iterator[Finding]:
        tool = find_tool(ctx, "uv")
        if isinstance(tool, list):
            yield from tool
            return
        if tool.file_id is not None and not ctx.ledger.claim(tool.file_id):
            return
        result = run_tool(ctx, tool, "uv", ["--version"])
        if isinstance(result, list):
            yield from result
        else:
            version = uv_version(result.stdout)
            if version is not None:
                yield from python_package_finding(
                    Subject("uv", "host uv"), version, installer=""
                )
        yield from content_findings(
            ctx,
            Subject("uv", str(tool.real)),
            tool.real,
            tool.file_id,
            MAX_BINARY_BYTES,
        )
