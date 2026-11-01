"""trust_stores.py: detections of the compromised certificates in trust store files.

OsTrustStore reads the fixed OS bundle paths, HomebrewTrustStore the Homebrew bundles, the
ca-certificates formula version and the macOS system roots keychain, and PemBundles every PEM bundle
the walk indexed under the scan roots. Each reports every certificate or key found and claims each
file in the ledger, so a file reached by two paths or two detections is reported once.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar, Iterator, Optional

from emudhra_check.certificates import (
    PEM_BEGIN,
    CertificateMatch,
    MatchKind,
    Role,
    bundle_findings,
)
from emudhra_check.detections.ports import Context
from emudhra_check.detections.shared import (
    MATCHER,
    content_findings,
    read_or_skip,
    release,
)
from emudhra_check.fixes import HOMEBREW_CA_FIXED
from emudhra_check.limits import MAX_BUNDLE_BYTES
from emudhra_check.report import Finding, Level, Subject
from emudhra_check.scope import FileInterests
from emudhra_check.versions import brew_formula_version

__all__ = ["HomebrewTrustStore", "OsTrustStore", "PemBundles"]

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


HOMEBREW_FIXED_TEXT = f"{HOMEBREW_CA_FIXED[0].isoformat()}_{HOMEBREW_CA_FIXED[1]}"
FORMULA = "homebrew ca-certificates"
G3_KEYCHAIN_LABEL = "emSign ECC Root CA - G3"
KEYCHAIN_ROOTS = (
    (
        G3_KEYCHAIN_LABEL,
        "which Apple blocks separately for its own frameworks since 2026-10-23",
    ),
    (
        "AAA Certificate Services",
        "which cross-signed all eight compromised intermediates",
    ),
)
STALE_DETAIL = (
    "is stale, the fixed formula leaves these certificates out:"
    " run brew postinstall ca-certificates"
)


def formula_finding(subject: Subject, name: str) -> Finding:
    """Judge a Homebrew ca-certificates Cellar directory name against the first fixed formula."""
    parsed = brew_formula_version(name)
    if parsed is None:
        detail = f"found {name}: not a dated formula version, check manually"
        return Finding(Level.WARN, subject, detail)
    detail = f"found {name}, fixed {HOMEBREW_FIXED_TEXT}"
    if parsed < HOMEBREW_CA_FIXED:
        return Finding(
            Level.FAIL, subject, f"{detail} (upgrade, then check the bundle again)"
        )
    return Finding(Level.PASS, subject, detail)


def newest_formula(names: tuple[str, ...]) -> Optional[str]:
    """Return the newest dated Cellar name, else the last name, or None when there is none."""
    dated = [(brew_formula_version(n), n) for n in names]
    parsed = [(version, n) for version, n in dated if version is not None]
    if parsed:
        return max(parsed)[1]
    return names[-1] if names else None


def is_stale_hit(match: CertificateMatch) -> bool:
    """Return whether a bundle match is one the fixed formula removes."""
    return not (
        match.role is Role.COMPROMISED_INTERMEDIATE and match.kind is MatchKind.KEY_ONLY
    )


class HomebrewTrustStore:
    """Homebrew's CA bundles, its ca-certificates formula version and the macOS keychain it copies."""

    name: ClassVar[str] = "homebrew-trust-store"
    interests: ClassVar[FileInterests] = FileInterests()

    def bundles(self, ctx: Context, prefix: Path) -> list[Path]:
        etc = prefix / "etc"
        openssl = [n for n in ctx.files.list_dir(etc) if n.startswith("openssl")]
        return [etc / "ca-certificates" / "cert.pem"] + [
            etc / n / "cert.pem" for n in openssl
        ]

    def run(self, ctx: Context) -> Iterator[Finding]:
        prefix = ctx.hostenv.brew_prefix
        if prefix is None:
            return
        stale: list[Path] = []
        for path in self.bundles(ctx, prefix):
            file_id = ctx.files.file_id(path)
            if file_id is None or not ctx.ledger.claim(file_id):
                continue
            subject = Subject("homebrew ca bundle", str(path))
            data = read_or_skip(ctx, subject, path, MAX_BUNDLE_BYTES, file_id)
            if isinstance(data, list):
                yield from data
                continue
            try:
                matches = MATCHER.scan(data)
            finally:
                release(data)
            yield from bundle_findings(subject, matches)
            if any(is_stale_hit(m) for m in matches):
                stale.append(path)
        cellar = prefix / "Cellar" / "ca-certificates"
        names = tuple(n for n in ctx.files.list_dir(cellar) if not n.startswith("."))
        newest = newest_formula(names)
        formula = None
        if newest is not None:
            formula = formula_finding(Subject(FORMULA, str(cellar / newest)), newest)
            yield formula
            if formula.level is Level.PASS:
                for path in stale:
                    yield Finding(
                        Level.WARN,
                        Subject("homebrew ca bundle", str(path)),
                        STALE_DETAIL,
                    )
        if ctx.hostenv.system != "Darwin":
            return
        for label, why in KEYCHAIN_ROOTS:
            if not ctx.host.keychain_has(label):
                continue
            detail = f"macOS system roots keychain still lists {label}, {why}"
            yield Finding(Level.INFO, Subject(FORMULA, "keychain"), detail)
            if label == G3_KEYCHAIN_LABEL and formula is not None:
                if formula.level is Level.FAIL:
                    detail = (
                        f"below {HOMEBREW_FIXED_TEXT} copies this root from the keychain"
                        " into its bundle on every install"
                    )
                    yield Finding(Level.WARN, Subject(FORMULA, "post_install"), detail)


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
