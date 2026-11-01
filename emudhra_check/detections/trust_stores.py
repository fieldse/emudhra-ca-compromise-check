"""trust_stores.py: detections of the compromised certificates in trust store files.

OsTrustStore reads the fixed OS bundle paths and PemBundles every PEM bundle the walk indexed under
the scan roots. Both report each certificate or key found and claim each file in the ledger, so a
file reached by two paths or two detections is reported once.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar, Iterator

from emudhra_check.certificates import PEM_BEGIN, bundle_findings
from emudhra_check.detections.ports import Context
from emudhra_check.detections.shared import (
    MATCHER,
    content_findings,
    read_or_skip,
    release,
)
from emudhra_check.limits import MAX_BUNDLE_BYTES
from emudhra_check.report import Finding, Level, Subject
from emudhra_check.scope import FileInterests

__all__ = ["OsTrustStore", "PemBundles"]

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
