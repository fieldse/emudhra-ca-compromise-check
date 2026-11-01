"""trust_stores.py: detections of the compromised certificates in trust store files.

OsTrustStore reads the fixed OS bundle paths and PemBundles every PEM bundle the walk indexed under
the scan roots. Both report each certificate or key found and claim each file in the ledger, so a
file reached by two paths or two detections is reported once. The read helpers here are shared with
the other detection modules through __all__.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar, Iterator, Optional, Union

from emudhra_check.certificates import PEM_BEGIN, Buffer, Matcher, bundle_findings
from emudhra_check.detections.ports import (
    EXCLUDED,
    MISSING,
    TOO_LARGE,
    Context,
    Skipped,
)
from emudhra_check.limits import MAX_BUNDLE_BYTES
from emudhra_check.report import Finding, Level, Subject
from emudhra_check.scope import FileId, FileInterests

__all__ = [
    "OsTrustStore",
    "PemBundles",
    "content_findings",
    "read_or_skip",
    "release",
    "skipped_findings",
]

MATCHER = Matcher()
OS_BUNDLES = (
    Path("/etc/ssl/certs/ca-certificates.crt"),
    Path("/etc/pki/tls/certs/ca-bundle.crt"),
    Path("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"),
    Path("/etc/ssl/ca-bundle.pem"),
    Path("/etc/ssl/cert.pem"),
    Path("/var/lib/ca-certificates/ca-bundle.pem"),
)
MACOS_NOTE = (
    "Apple blocks the intermediates (2026-10-19) and the root (2026-10-23) for its own frameworks;"
    " /etc/ssl/cert.pem above is what curl, git, python3, ruby and perl read. Removing emSign ECC Root CA"
    " - G3 alone leaves the Sectigo cross-signs trusted through AAA Certificate Services"
)


def skipped_findings(subject: Subject, skipped: Skipped) -> list[Finding]:
    """Return the line for a read that gave no bytes: none for a missing or excluded path."""
    if skipped.reason in (MISSING, EXCLUDED):
        return []
    if skipped.reason == TOO_LARGE:
        return [Finding(Level.INFO, subject, "too large to scan, skipped")]
    return [Finding(Level.INFO, subject, f"{skipped.reason}, skipped")]


def release(data: Buffer) -> None:
    """Close a mapped file. Bytes need nothing."""
    close = getattr(data, "close", None)
    if close is not None:
        close()


def read_or_skip(
    ctx: Context,
    subject: Subject,
    path: Path,
    cap: int,
    expect: Optional[FileId] = None,
) -> Union[Buffer, list[Finding]]:
    """Read a file through the Files port, or return the lines that explain why it was not read."""
    data = ctx.files.read_bytes(path, cap, expect)
    if isinstance(data, Skipped):
        return skipped_findings(subject, data)
    return data


def content_findings(
    ctx: Context,
    subject: Subject,
    path: Path,
    expect: Optional[FileId] = None,
    cap: int = MAX_BUNDLE_BYTES,
) -> list[Finding]:
    """Return the content verdict of one file: one line per match, then PASS when none is a FAIL."""
    data = read_or_skip(ctx, subject, path, cap, expect)
    if isinstance(data, list):
        return data
    try:
        return bundle_findings(subject, MATCHER.scan(data))
    finally:
        release(data)


class OsTrustStore:
    """The OS CA bundle files at their fixed paths."""

    name: ClassVar[str] = "os-trust-store"
    interests: ClassVar[FileInterests] = FileInterests()

    def run(self, ctx: Context) -> Iterator[Finding]:
        for path in OS_BUNDLES:
            file_id = ctx.files.file_id(path)
            if file_id is None or not ctx.ledger.claim(file_id):
                continue
            yield from content_findings(
                ctx, Subject("os trust store", str(path)), path, file_id
            )
        if ctx.hostenv.system == "Darwin":
            yield Finding(Level.INFO, Subject("macOS", "system keychain"), MACOS_NOTE)


class PemBundles:
    """PEM bundles the walk indexed under the scan roots, listed only when they hold a match."""

    name: ClassVar[str] = "pem-bundles"
    interests: ClassVar[FileInterests] = FileInterests(
        name_globs=frozenset({"cacert*"}),
        suffixes=frozenset({".pem", ".crt", ".cer", ".bundle"}),
    )

    def run(self, ctx: Context) -> Iterator[Finding]:
        checked = 0
        for indexed in ctx.index.files_for(self.interests):
            subject = Subject("ca-bundle", str(indexed.path))
            data = read_or_skip(
                ctx, subject, indexed.real, MAX_BUNDLE_BYTES, indexed.file_id
            )
            if isinstance(data, list):
                yield from data
                continue
            try:
                if data.find(PEM_BEGIN) < 0 or not ctx.ledger.claim(indexed.file_id):
                    continue
                checked += 1
                matches = MATCHER.scan(data)
            finally:
                release(data)
            if matches:
                yield from bundle_findings(subject, matches)
        yield Finding(
            Level.INFO,
            Subject("ca-bundle", "scan roots"),
            f"checked {checked} PEM files; only files containing an affected certificate are listed",
        )
