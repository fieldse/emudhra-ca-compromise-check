"""language_packages.py: detections of language packages that vendor a CA bundle or a root list.

PythonDistInfo judges certifi, pip and uv from installed dist-info directories, PythonPins the certifi
pins in requirements files and locks, HostPythonPackages the certifi and pip the host python3 sees
(read from metadata in a child python3 -I -S that imports no package), and UvHost the uv on PATH by
version and by the roots its binary holds. A package installed by a distribution is judged by the
bundle it resolves to. ElectronPackages judges installed and declared Electron versions, and
CargoLocks, ComposerLocks, GemfileLocks and MixLocks the Rust, PHP, Ruby and Elixir packages that
carry their own roots.
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
from emudhra_check.fixes import (
    CASTORE_FIXED,
    CERTIFI_FIXED,
    CERTIFI_RECOMMENDED,
    COMPOSER_CA_BUNDLE_FIXED,
    ELECTRON_FIXED,
    EXCON_FIXED,
    HEX_CERTIFI_FIXED,
    PIP_FIXED,
    RUSTLS_WEBPKI_FIXED,
    UV_FIXED,
    WEBPKI_ROOTS_FIXED,
    WEBPKI_WRAPPER,
)
from emudhra_check.hostenv import is_macos_stub
from emudhra_check.limits import MAX_BINARY_BYTES, MAX_FIELD_CHARS, MAX_TEXT_BYTES
from emudhra_check.lockfiles import (
    LockPackage,
    bounded_json,
    composer_versions,
    gem_versions,
    mix_versions,
    normalise,
    npm_exact_version,
    npm_range_lower_bound,
    package_count,
    pipfile_versions,
    requirement_pins,
    toml_package_versions,
)
from emudhra_check.report import Finding, Level, Subject
from emudhra_check.scope import FileId, FileInterests, IndexedFile
from emudhra_check.versions import judge, judge_branched, parse_version

__all__ = [
    "CargoLocks",
    "ComposerLocks",
    "ElectronPackages",
    "GemfileLocks",
    "HostPythonPackages",
    "MixLocks",
    "PythonDistInfo",
    "PythonPins",
    "UvHost",
    "electron_range_finding",
    "python_package_finding",
    "rustls_webpki_finding",
    "webpki_findings",
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


def electron_range_finding(subject: Subject, spec: str) -> Optional[Finding]:
    """Judge a declared Electron spec: an exact version as installed, a range by its lowest version.

    None for a spec that names no release.
    """
    bound = npm_range_lower_bound(spec)
    if bound is None:
        return None
    lower, bounded_major = bound
    exact = npm_exact_version(spec)
    if exact is not None and parse_version(exact) is None:
        exact = None
    if exact is not None:
        lower, bounded_major = exact, True
    found = lower or spec
    if not bounded_major or parse_version(lower) is None:
        return Finding(
            Level.WARN,
            subject,
            f"found {found}, unbounded range, check the installed version",
        )
    verdict = judge_branched(subject, lower, ELECTRON_FIXED)
    if verdict.level is Level.PASS:
        return verdict
    fixed = dict(ELECTRON_FIXED.fixes).get(lower.split(".")[0])
    if fixed is None:
        what = (
            "this version is affected"
            if exact is not None
            else "this range can only install affected versions"
        )
        return Finding(
            Level.FAIL, subject, f"found {lower}, {what} (no fix on its branch)"
        )
    if exact is not None:
        return Finding(
            Level.FAIL,
            subject,
            f"found {lower}, fixed {fixed}: this version is affected",
        )
    detail = f"found {lower}, fixed {fixed}: a range may resolve higher, check the installed version"
    return Finding(Level.WARN, subject, detail)


def json_object(
    ctx: Context, subject: Subject, indexed: IndexedFile
) -> Union[dict[str, object], list[Finding]]:
    """Read a JSON object file, or return the lines for one that could not be read or is not an object."""
    text = text_of(ctx, subject, indexed.real, indexed.file_id)
    if isinstance(text, list):
        return text
    data = bounded_json(text)
    if not isinstance(data, dict):
        return [
            Finding(Level.INFO, subject, f"{indexed.path.name} unreadable, skipped")
        ]
    return data


class ElectronPackages:
    """Electron installed in node_modules, and the Electron ranges package.json files declare."""

    name: ClassVar[str] = "electron-packages"
    interests: ClassVar[FileInterests] = FileInterests(
        name_globs=frozenset({"package.json"})
    )

    def run(self, ctx: Context) -> Iterator[Finding]:
        for indexed in ctx.index.files_for(self.interests):
            parts = indexed.path.parts
            installed = parts[-3:] == ("node_modules", "electron", "package.json")
            if "node_modules" in parts and not installed:
                continue
            subject = Subject("electron", str(indexed.path))
            data = json_object(ctx, subject, indexed)
            if isinstance(data, list):
                yield from data
                continue
            if installed:
                version = data.get("version")
                if isinstance(version, str):
                    yield judge_branched(subject, version, ELECTRON_FIXED)
                continue
            declared = Subject("electron", f"{indexed.path} declared range starts at")
            for section in ("dependencies", "devDependencies", "optionalDependencies"):
                entries = data.get(section)
                spec = entries.get("electron") if isinstance(entries, dict) else None
                if isinstance(spec, str):
                    finding = electron_range_finding(declared, spec)
                    if finding is not None:
                        yield finding


def wrapped_version(
    package: LockPackage, crate: str, packages: list[LockPackage]
) -> Optional[str]:
    """Return the 1.x version a 0.26 wrapper depends on, from its dependency entry or the lock's only 1.x."""
    for entry in package.dependencies:
        words = entry.split()
        if words and words[0] == crate:
            if len(words) >= 2:
                return words[1]
            majors = [p.version for p in packages if not p.version.startswith("0.")]
            return majors[0] if len(majors) == 1 else None
    return None


def webpki_findings(subject: Subject, packages: list[LockPackage]) -> list[Finding]:
    """Judge each webpki-roots or webpki-root-certs entry, resolving a 0.26.11 wrapper through its dependency."""
    findings = []
    first_wrapper = parse_version(WEBPKI_WRAPPER)
    for package in packages:
        version = parse_version(package.version)
        found = package.version
        if version is None or first_wrapper is None:
            findings.append(judge(subject, found, WEBPKI_ROOTS_FIXED))
        elif version.release[:2] < (0, 26):
            findings.append(
                Finding(
                    Level.FAIL,
                    subject,
                    f"found {found}, no fix, move to 1.0.10 or later",
                )
            )
        elif version.release[:2] == (0, 26) and version < first_wrapper:
            findings.append(
                Finding(
                    Level.FAIL,
                    subject,
                    f"found {found}, carries its own list with the G3 root",
                )
            )
        elif version.release[:2] == (0, 26):
            wrapped = wrapped_version(package, subject.name, packages)
            if wrapped is None:
                detail = f"found {found}, 0.26.11 wraps 1.x, fixed only if that dependency is 1.0.10 or later"
                findings.append(Finding(Level.WARN, subject, detail))
            else:
                verdict = judge(subject, wrapped, WEBPKI_ROOTS_FIXED)
                detail = f"found {found}, wraps {verdict.detail[len('found '):]}"
                findings.append(Finding(verdict.level, subject, detail))
        else:
            findings.append(judge(subject, found, WEBPKI_ROOTS_FIXED))
    return findings


def rustls_webpki_finding(subject: Subject, version: str) -> Finding:
    parsed = parse_version(version)
    if parsed is not None and parsed.release[:2] < (0, 103):
        return Finding(
            Level.FAIL, subject, f"found {version}, 0.102 and older lines have no fix"
        )
    return judge_branched(subject, version, RUSTLS_WEBPKI_FIXED)


class LockDetection:
    """A detection that reads each indexed lock file of one name as text."""

    def texts(
        self, ctx: Context, interests: FileInterests
    ) -> Iterator[Union[Finding, tuple[IndexedFile, str]]]:
        for indexed in ctx.index.files_for(interests):
            text = text_of(
                ctx,
                Subject(indexed.path.name, str(indexed.path)),
                indexed.real,
                indexed.file_id,
            )
            if isinstance(text, list):
                yield from text
            else:
                yield indexed, text


class CargoLocks(LockDetection):
    """webpki-roots, webpki-root-certs and rustls-webpki in Cargo.lock files."""

    name: ClassVar[str] = "cargo-locks"
    interests: ClassVar[FileInterests] = FileInterests(
        name_globs=frozenset({"Cargo.lock"})
    )

    def run(self, ctx: Context) -> Iterator[Finding]:
        for item in self.texts(ctx, self.interests):
            if isinstance(item, Finding):
                yield item
                continue
            indexed, text = item
            where = str(indexed.path)
            complete = True
            for crate in ("webpki-roots", "webpki-root-certs"):
                packages, complete = toml_package_versions(text, crate)
                yield from webpki_findings(Subject(crate, where), packages)
            for package in toml_package_versions(text, "rustls-webpki")[0]:
                yield rustls_webpki_finding(
                    Subject("rustls-webpki", where), package.version
                )
            if not complete:
                detail = f"partly unreadable, {package_count(text)} packages read"
                yield Finding(Level.INFO, Subject("Cargo.lock", where), detail)


class ComposerLocks(LockDetection):
    """composer/ca-bundle in composer.lock files."""

    name: ClassVar[str] = "composer-locks"
    interests: ClassVar[FileInterests] = FileInterests(
        name_globs=frozenset({"composer.lock"})
    )

    def run(self, ctx: Context) -> Iterator[Finding]:
        for item in self.texts(ctx, self.interests):
            if isinstance(item, Finding):
                yield item
                continue
            indexed, text = item
            versions = composer_versions(text, "composer/ca-bundle")
            if versions is None:
                yield Finding(
                    Level.INFO,
                    Subject("composer.lock", str(indexed.path)),
                    "unreadable, skipped",
                )
                continue
            for version in versions:
                subject = Subject("composer/ca-bundle", str(indexed.path))
                yield judge_branched(subject, version, COMPOSER_CA_BUNDLE_FIXED)


class GemfileLocks(LockDetection):
    """excon in Gemfile.lock files."""

    name: ClassVar[str] = "gemfile-locks"
    interests: ClassVar[FileInterests] = FileInterests(
        name_globs=frozenset({"Gemfile.lock"})
    )

    def run(self, ctx: Context) -> Iterator[Finding]:
        for item in self.texts(ctx, self.interests):
            if isinstance(item, Finding):
                yield item
                continue
            indexed, text = item
            for version in gem_versions(text, "excon"):
                yield judge(Subject("excon", str(indexed.path)), version, EXCON_FIXED)


class MixLocks(LockDetection):
    """castore and Hex certifi in mix.lock files."""

    name: ClassVar[str] = "mix-locks"
    interests: ClassVar[FileInterests] = FileInterests(
        name_globs=frozenset({"mix.lock"})
    )

    def run(self, ctx: Context) -> Iterator[Finding]:
        rules = {
            "castore": ("castore", CASTORE_FIXED),
            "certifi": ("hex certifi", HEX_CERTIFI_FIXED),
        }
        for item in self.texts(ctx, self.interests):
            if isinstance(item, Finding):
                yield item
                continue
            indexed, text = item
            for package, version in mix_versions(text):
                label, rule = rules[package]
                yield judge(Subject(label, str(indexed.path)), version, rule)
