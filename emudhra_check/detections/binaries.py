"""binaries.py: detections of native programs judged by their bytes, never run.

GoBinaries reads the build information of every Go program the walk classified, judges its
toolchain and the x509roots fallback module it embeds, and scans it for the compromised roots.
RustBinaries judges the webpki crates whose source paths a Rust program carries and scans it the
same way. Each claims its binaries in the ledger, so a binary a runtime check already reported is
not reported again.
"""

from __future__ import annotations

import dataclasses
from typing import ClassVar, Iterator, Optional

from emudhra_check.buildinfo import (
    BinaryKind,
    GoBuildInfo,
    go_build_info,
    rust_crate_versions,
)
from emudhra_check.certificates import CertificateMatch, bundle_findings
from emudhra_check.detections.language_packages import (
    rustls_webpki_finding,
    webpki_findings,
)
from emudhra_check.detections.ports import Context
from emudhra_check.detections.shared import MATCHER, read_or_skip, release
from emudhra_check.fixes import GO_FALLBACK_FIXED, GO_FIXED
from emudhra_check.limits import MAX_BINARY_BYTES
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

__all__ = ["GoBinaries", "RustBinaries", "go_binary_findings"]

GO_BINARY_RULE = dataclasses.replace(
    GO_FIXED, note="built with an affected toolchain, rebuild"
)
GO_FALLBACK_MODULE = "golang.org/x/crypto/x509roots/fallback"
TOOLCHAIN_DIR = "/Cellar/go/"
RUST_NOTE = "rebuild against the fixed crates"
WEBPKI_CRATES = ("webpki-roots", "webpki-root-certs")
UNPARSED = Version("", (0,))


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


def go_binary_findings(
    subject: Subject,
    info: Optional[GoBuildInfo],
    matches: tuple[CertificateMatch, ...],
) -> list[Finding]:
    """Judge a Go binary by its toolchain and fallback module, then list its certificate matches."""
    findings: list[Finding] = []
    if info is None:
        detail = "Go build info unreadable, check it with go version -m"
        findings.append(Finding(Level.WARN, subject, detail))
    elif info.legacy:
        detail = "found a toolchain older than Go 1.18, no fix for that branch, rebuild"
        findings.append(Finding(Level.FAIL, subject, detail))
    else:
        version = info.go_version[2:]
        findings.append(judge_branched(subject, version, GO_BINARY_RULE))
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
            if TOOLCHAIN_DIR in str(entry.path) or not ctx.ledger.claim(entry.file_id):
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
            finally:
                release(data)
            yield from go_binary_findings(subject, info, matches)
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
            for version in sorted(versions.get("rustls-webpki", frozenset())):
                finding = rustls_webpki_finding(
                    Subject("rustls-webpki", where), version
                )
                yield with_rust_note(finding)
            if matches:
                yield from bundle_findings(subject, matches)
