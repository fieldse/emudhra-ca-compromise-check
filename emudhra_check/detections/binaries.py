"""binaries.py: detections of native programs judged by their bytes, never run.

GoBinaries reads the build information of every Go program the walk classified, judges its
toolchain and the x509roots fallback module it embeds, and scans it for the compromised roots. A
toolchain FAIL is WARN when the program does not hold crypto/x509's Verify. RustBinaries judges the
webpki crates whose source paths a Rust program carries and scans it the same way. An old
rustls-webpki crate is FAIL only when the same program holds an affected root.
BundledNodeBinaries judges the Node binaries apps ship by the release they name.
ElectronApps judges macOS and Linux Electron apps by version, with what the framework binary holds
as notes, and UpdaterCaches the apps left in ShipIt update caches. Each claims its binaries in the
ledger, so a binary a runtime check already reported is not reported again.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import ClassVar, Iterator, Optional

from emudhra_check.buildinfo import (
    BinaryKind,
    GoBuildInfo,
    classify,
    electron_app_version,
    electron_version_string,
    go_build_info,
    node_release_version,
    rust_crate_versions,
)
from emudhra_check.certificates import (
    G3_ECC_ROOT,
    ISRG_ROOT_X1_LINE,
    CertificateMatch,
    MatchKind,
    bundle_findings,
    match_finding,
)
from emudhra_check.detections.language_packages import (
    rustls_webpki_finding,
    webpki_findings,
)
from emudhra_check.detections.ports import Context, Skipped
from emudhra_check.detections.runtimes import StoreKind, node_store_findings
from emudhra_check.detections.shared import MATCHER, read_or_skip, release
from emudhra_check.fixes import ELECTRON_FIXED, GO_FALLBACK_FIXED, GO_FIXED
from emudhra_check.limits import MAX_BINARY_BYTES, MAX_PLIST_BYTES
from emudhra_check.lockfiles import LockPackage
from emudhra_check.report import Finding, Level, Subject
from emudhra_check.scope import Executable, FileInterests
from emudhra_check.versions import (
    Version,
    judge_branched,
    parse_version,
    pseudo_version_time,
    with_note,
)

__all__ = [
    "BundledNodeBinaries",
    "ElectronApps",
    "GoBinaries",
    "RustBinaries",
    "UpdaterCaches",
    "electron_app_findings",
    "go_binary_findings",
]

GO_BINARY_RULE = dataclasses.replace(
    GO_FIXED, note="built with an affected toolchain, rebuild"
)
GO_FALLBACK_MODULE = "golang.org/x/crypto/x509roots/fallback"
TOOLCHAIN_DIR = "/Cellar/go/"
X509_VERIFY = b"crypto/x509.(*Certificate).Verify\x00"
NO_VERIFY_NOTE = (
    "crypto/x509 Verify not found, the program may never verify certificates"
)
RUST_NOTE = "rebuild against the fixed crates"
RUSTLS_NO_ROOT_NOTE = (
    "lacks the key blocklist, matters only when the binary uses the system trust store"
)
WEBPKI_CRATES = ("webpki-roots", "webpki-root-certs")
UNPARSED = Version("", (0,))
G3_NAME = "emSign ECC Root CA - G3"


def fallback_finding(where: str, version: str) -> Optional[Finding]:
    """Judge the x509roots fallback module by its pseudo-version time, or None when it is fixed."""
    subject = Subject("go fallback roots", where)
    found = pseudo_version_time(version)
    fixed = pseudo_version_time(GO_FALLBACK_FIXED)
    if found is None or fixed is None:
        detail = f"found {version}: not a pseudo-version, check manually"
        return Finding(Level.WARN, subject, detail)
    if found >= fixed:
        return None
    detail = (
        f"found {version}, fixed {GO_FALLBACK_FIXED}"
        " (embeds emSign ECC Root CA - G3, update the module and rebuild)"
    )
    return Finding(Level.FAIL, subject, detail)


def toolchain_finding(finding: Finding, verifies: bool) -> Finding:
    """Return a toolchain FAIL as WARN when the binary does not hold crypto/x509's Verify."""
    if finding.level is not Level.FAIL or verifies:
        return finding
    detail = with_note(finding.detail, NO_VERIFY_NOTE)
    return Finding(Level.WARN, finding.subject, detail)


def go_binary_findings(
    subject: Subject,
    info: Optional[GoBuildInfo],
    matches: tuple[CertificateMatch, ...],
    verifies: bool,
) -> list[Finding]:
    """Judge a Go binary by its toolchain and fallback module, then list its certificate matches.

    verifies says whether the binary holds the function name of crypto/x509's certificate Verify.
    """
    findings: list[Finding] = []
    if info is None:
        detail = "Go build info unreadable, check it with go version -m"
        findings.append(Finding(Level.WARN, subject, detail))
    elif info.legacy:
        detail = "found a toolchain older than Go 1.18, no fix for that branch, rebuild"
        verdict = Finding(Level.FAIL, subject, detail)
        findings.append(toolchain_finding(verdict, verifies))
    else:
        version = info.go_version[2:]
        verdict = judge_branched(subject, version, GO_BINARY_RULE)
        findings.append(toolchain_finding(verdict, verifies))
        for module in info.modules:
            if module.path == GO_FALLBACK_MODULE:
                finding = fallback_finding(subject.where, module.version)
                if finding is not None:
                    findings.append(finding)
    if matches:
        findings.extend(bundle_findings(subject, matches))
    return findings


def entries(ctx: Context, kind: BinaryKind) -> list[Executable]:
    return [e for e in ctx.index.executables if e.kind is kind]


class GoBinaries:
    """Go programs in the fixed binary directories and under the scan roots."""

    name: ClassVar[str] = "go-binaries"
    interests: ClassVar[FileInterests] = FileInterests(executables=True)

    def run(self, ctx: Context) -> Iterator[Finding]:
        found = entries(ctx, BinaryKind.GO)
        for entry in found:
            if TOOLCHAIN_DIR in str(entry.real) or not ctx.ledger.claim(entry.file_id):
                continue
            subject = Subject("go binary", str(entry.path))
            data = read_or_skip(
                ctx, subject, entry.path, MAX_BINARY_BYTES, entry.file_id
            )
            if isinstance(data, list):
                yield from data
                continue
            try:
                info = go_build_info(data)
                matches = MATCHER.scan(data)
                verifies = data.find(X509_VERIFY) >= 0
            finally:
                release(data)
            yield from go_binary_findings(subject, info, matches, verifies)
        if not found:
            detail = (
                "no Go binaries found in the binary directories or under the scan roots"
            )
            yield Finding(Level.INFO, Subject("go", "binaries"), detail)


def version_key(text: str) -> tuple[int, Version, str]:
    """Order parsed versions first, by version, and the rest by text."""
    parsed = parse_version(text)
    return (0, parsed, text) if parsed is not None else (1, UNPARSED, text)


def webpki_packages(crate: str, versions: frozenset[str]) -> list[LockPackage]:
    """Return one package per version of a crate, each 0.26 wrapper depending on the 1.x versions found."""
    ordered = sorted(versions, key=version_key)
    majors = tuple(f"{crate} {v}" for v in ordered if not v.startswith("0."))
    return [LockPackage(v, majors if v.startswith("0.26.") else ()) for v in ordered]


def with_rust_note(finding: Finding) -> Finding:
    if finding.level is Level.PASS:
        return finding
    return Finding(finding.level, finding.subject, with_note(finding.detail, RUST_NOTE))


def holds_affected_root(
    subject: Subject, matches: tuple[CertificateMatch, ...]
) -> bool:
    """True when a match is the G3 root or a compromised intermediate that the binary would trust."""
    return any(match_finding(subject, m).level is Level.FAIL for m in matches)


def rustls_binary_finding(
    subject: Subject, version: str, affected_root: bool
) -> Finding:
    """Judge a binary's rustls-webpki crate, a FAIL becoming WARN when the binary holds no affected root."""
    finding = rustls_webpki_finding(subject, version)
    if finding.level is not Level.FAIL or affected_root:
        return with_rust_note(finding)
    detail = with_note(finding.detail, RUSTLS_NO_ROOT_NOTE)
    return Finding(Level.WARN, subject, detail)


class RustBinaries:
    """Rust programs whose embedded source paths name the webpki crates."""

    name: ClassVar[str] = "rust-binaries"
    interests: ClassVar[FileInterests] = FileInterests(executables=True)

    def run(self, ctx: Context) -> Iterator[Finding]:
        for entry in entries(ctx, BinaryKind.RUST):
            if not ctx.ledger.claim(entry.file_id):
                continue
            where = str(entry.path)
            subject = Subject("rust binary", where)
            data = read_or_skip(
                ctx, subject, entry.path, MAX_BINARY_BYTES, entry.file_id
            )
            if isinstance(data, list):
                yield from data
                continue
            try:
                versions = rust_crate_versions(data)
                matches = MATCHER.scan(data)
            finally:
                release(data)
            for crate in WEBPKI_CRATES:
                packages = webpki_packages(crate, versions.get(crate, frozenset()))
                for finding in webpki_findings(Subject(crate, where), packages):
                    yield with_rust_note(finding)
            affected_root = holds_affected_root(subject, matches)
            for version in sorted(versions.get("rustls-webpki", frozenset())):
                yield rustls_binary_finding(
                    Subject("rustls-webpki", where), version, affected_root
                )
            if matches:
                yield from bundle_findings(subject, matches)


NODE_GLOBS = frozenset(
    {
        "Library/Application Support/Zed/node/*/bin/node",
        "Library/Application Support/com.raycast.macos/NodeJS/runtime/*/bin/node",
        ".local/share/httptoolkit-server/client/*/bin/node",
        ".cache/codex-runtimes/*/payload",
        "*.app/Contents/Resources/*/bin/node",
    }
)


class BundledNodeBinaries:
    """Node binaries that apps and tools ship outside PATH and the version managers."""

    name: ClassVar[str] = "bundled-node-binaries"
    interests: ClassVar[FileInterests] = FileInterests(
        dir_globs=NODE_GLOBS, executables=True
    )

    def run(self, ctx: Context) -> Iterator[Finding]:
        for entry in entries(ctx, BinaryKind.NODE):
            if not ctx.ledger.claim(entry.file_id):
                continue
            where = str(entry.path)
            subject = Subject("node", where)
            data = read_or_skip(
                ctx, subject, entry.path, MAX_BINARY_BYTES, entry.file_id
            )
            if isinstance(data, list):
                yield from data
                continue
            try:
                version = node_release_version(data) or "unknown"
                matches = MATCHER.scan(data)
                has_store = data.find(ISRG_ROOT_X1_LINE) >= 0
            finally:
                release(data)
            g3 = any(m.label == G3_ECC_ROOT.label for m in matches)
            store = StoreKind.BUNDLED if has_store or g3 else StoreKind.OS
            yield from node_store_findings(subject, version, matches, store, where)


ELECTRON_APP_RULE = dataclasses.replace(ELECTRON_FIXED, note="update the app")
UPDATE_CACHE_RULE = dataclasses.replace(
    ELECTRON_FIXED,
    below=Level.WARN,
    no_fix=Level.WARN,
    note="stale updater cache, delete the directory",
)
APP_SUFFIX = ".app"
UPDATER_CACHE_SUFFIX = ".ShipIt"
FRAMEWORK = Path("Contents/Frameworks/Electron Framework.framework")
FRAMEWORK_PLISTS = ("Versions/A/Resources/Info.plist", "Resources/Info.plist")
FRAMEWORK_BINARY = "Versions/A/Electron Framework"
ASAR = "app.asar"


def electron_app_findings(
    subject: Subject,
    version: Optional[str],
    matches: tuple[CertificateMatch, ...],
    binary: Optional[str] = None,
) -> list[Finding]:
    """Judge an Electron app by its version alone, then list what its binary holds as notes."""
    if version is None:
        detail = "version unreadable, check the app's About window"
        findings = [Finding(Level.WARN, subject, detail)]
        verdict_level = Level.WARN
    else:
        verdict = judge_branched(subject, version, ELECTRON_APP_RULE)
        findings = [verdict]
        verdict_level = verdict.level
    where = Subject(subject.name, binary or subject.where)
    for match in matches:
        if match.label == G3_ECC_ROOT.label and match.kind is MatchKind.FULL:
            if verdict_level is Level.FAIL:
                detail = f"also bundles {G3_NAME} (confirms the version FAIL)"
            elif verdict_level is Level.PASS:
                detail = (
                    f"bundled Node.js root store still lists {G3_NAME},"
                    " the Electron fix blocks the compromised keys"
                )
            else:
                detail = (
                    f"bundled Node.js root store lists {G3_NAME},"
                    " which only a fixed Electron blocks"
                )
            findings.append(Finding(Level.INFO, where, detail))
        else:
            findings.append(match_finding(where, match))
    return findings


def in_updater_cache(path: Path) -> bool:
    return any(part.endswith(UPDATER_CACHE_SUFFIX) for part in path.parts[:-1])


def app_dirs(ctx: Context, interests: FileInterests, cached: bool) -> Iterator[Path]:
    """Yield the indexed .app directories inside or outside updater caches that hold an Electron framework."""
    for indexed in ctx.index.dirs_for(interests):
        path = indexed.path
        if not path.name.endswith(APP_SUFFIX) or in_updater_cache(path) != cached:
            continue
        if ctx.files.is_dir(path / FRAMEWORK):
            yield path


def plist_version(ctx: Context, framework: Path) -> Optional[str]:
    """Return CFBundleVersion from the first readable Info.plist of a framework."""
    for relative in FRAMEWORK_PLISTS:
        data = ctx.files.read_bytes(framework / relative, MAX_PLIST_BYTES)
        if isinstance(data, Skipped):
            continue
        try:
            version = electron_app_version(bytes(data[0 : len(data)]))
        finally:
            release(data)
        if version is not None:
            return version
    return None


class ElectronApps:
    """Electron apps under the scan roots, macOS bundles and Linux app directories, judged by version."""

    name: ClassVar[str] = "electron-apps"
    interests: ClassVar[FileInterests] = FileInterests(
        name_globs=frozenset({ASAR}), dir_globs=frozenset({"*" + APP_SUFFIX})
    )

    def run(self, ctx: Context) -> Iterator[Finding]:
        found = 0
        for app in app_dirs(ctx, self.interests, cached=False):
            found += 1
            yield from self.macos_app(ctx, app / FRAMEWORK)
        for indexed in ctx.index.files_for(self.interests):
            if indexed.path.name == ASAR and indexed.path.parent.name == "resources":
                lines = self.linux_app(ctx, indexed.path.parent.parent)
                found += lines is not None
                yield from lines or []
        if found == 0:
            yield Finding(
                Level.INFO,
                Subject("electron app", "scan roots"),
                "no Electron apps found",
            )

    def macos_app(self, ctx: Context, framework: Path) -> list[Finding]:
        version = plist_version(ctx, framework)
        subject = Subject("electron app", str(framework))
        binary = framework / FRAMEWORK_BINARY
        file_id = ctx.files.file_id(binary)
        if file_id is None:
            return electron_app_findings(subject, version, ())
        if not ctx.ledger.claim(file_id):
            return []
        data = read_or_skip(
            ctx, Subject("electron app", str(binary)), binary, MAX_BINARY_BYTES, file_id
        )
        if isinstance(data, list):
            return data + electron_app_findings(subject, version, ())
        try:
            version = version or electron_version_string(data)
            matches = MATCHER.scan(data)
        finally:
            release(data)
        return electron_app_findings(subject, version, matches, str(binary))

    def linux_app(self, ctx: Context, directory: Path) -> Optional[list[Finding]]:
        """Judge the Electron executable beside resources/app.asar, or None when there is none."""
        for name in ctx.files.list_dir(directory):
            if "." in name:
                continue
            path = directory / name
            file_id = ctx.files.file_id(path)
            if file_id is None:
                continue
            if not ctx.files.charge_binary_read(path):
                detail = "binary budget exhausted, skipped"
                return [Finding(Level.INFO, Subject("scan", str(path)), detail)]
            data = ctx.files.read_bytes(path, MAX_BINARY_BYTES, file_id)
            if isinstance(data, Skipped):
                continue
            try:
                if classify(data) is not BinaryKind.ELECTRON:
                    continue
                version = electron_version_string(data)
                matches = MATCHER.scan(data)
            finally:
                release(data)
            if not ctx.ledger.claim(file_id):
                return []
            subject = Subject("electron app", str(path))
            return electron_app_findings(subject, version, matches)
        return None


class UpdaterCaches:
    """Electron apps left in Squirrel.Mac ShipIt update caches, judged by version only."""

    name: ClassVar[str] = "updater-caches"
    interests: ClassVar[FileInterests] = ElectronApps.interests

    def run(self, ctx: Context) -> Iterator[Finding]:
        for app in app_dirs(ctx, self.interests, cached=True):
            framework = app / FRAMEWORK
            version = plist_version(ctx, framework)
            if version is None:
                binary = framework / FRAMEWORK_BINARY
                data = ctx.files.read_bytes(binary, MAX_BINARY_BYTES)
                if isinstance(data, Skipped):
                    continue
                try:
                    version = electron_version_string(data)
                finally:
                    release(data)
            if version is None:
                continue
            subject = Subject("electron update cache", str(app))
            verdict = judge_branched(subject, version, UPDATE_CACHE_RULE)
            if verdict.level is not Level.PASS:
                yield verdict
