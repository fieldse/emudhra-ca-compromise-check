"""trust_stores.py: detections of the compromised certificates in trust store files.

OsTrustStore reads the fixed OS bundle paths, HomebrewTrustStore the Homebrew bundles, the
ca-certificates formula version and the macOS system roots keychain, PemBundles every PEM bundle the
walk indexed under the scan roots, JavaKeystores the cacerts keystores of the Java homes and under the
roots without running keytool, and PerlMozillaCa the Mozilla::CA module perl loads. Each reports
every certificate or key found and claims each file in the ledger, so a file reached by two paths or
two detections is reported once.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar, Iterator, Optional

from emudhra_check.certificates import (
    Buffer,
    CertificateMatch,
    KeystoreKind,
    MatchKind,
    Role,
    bundle_findings,
    has_pem,
    keystore_kind,
)
from emudhra_check.detections.ports import Context
from emudhra_check.detections.shared import (
    MATCHER,
    content_findings,
    find_tool,
    read_or_skip,
    release,
    run_tool,
)
from emudhra_check.fixes import HOMEBREW_CA_FIXED, MOZILLA_CA_FIXED
from emudhra_check.limits import MAX_BUNDLE_BYTES, MAX_FIELD_CHARS
from emudhra_check.report import Finding, Level, Subject
from emudhra_check.scope import FileId, FileInterests
from emudhra_check.versions import brew_formula_version, judge

__all__ = [
    "HomebrewTrustStore",
    "JavaKeystores",
    "OsTrustStore",
    "PemBundles",
    "PerlMozillaCa",
    "keystore_findings",
]

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
    if match.kind is MatchKind.REJECTED:
        return False
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
                if not has_pem(data) or not ctx.ledger.claim(indexed.file_id):
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


JAVA_HOME_KEYSTORES = ("lib/security/cacerts", "jre/lib/security/cacerts")
ENCRYPTED_DETAIL = (
    "password-protected keystore, no compromised certificate found as plain bytes,"
    " check it with keytool"
)


def keystore_findings(
    subject: Subject, data: Buffer, matches: tuple[CertificateMatch, ...]
) -> list[Finding]:
    """Judge a Java keystore: plain stores by their content, an encrypted PKCS12 with no FAIL as WARN, and a
    file of unknown format by its content only when that holds a FAIL."""
    kind = keystore_kind(data)
    findings = bundle_findings(subject, matches)
    if kind is KeystoreKind.UNKNOWN:
        return findings if any(f.level is Level.FAIL for f in findings) else []
    if kind is KeystoreKind.PKCS12_ENCRYPTED and not any(
        f.level is Level.FAIL for f in findings
    ):
        findings = [f for f in findings if f.level is not Level.PASS]
        findings.append(Finding(Level.WARN, subject, ENCRYPTED_DETAIL))
    return findings


def judge_keystore(
    ctx: Context, subject: Subject, path: Path, file_id: FileId
) -> list[Finding]:
    """Read one keystore and judge its bytes, or return the line for one that could not be read."""
    data = read_or_skip(ctx, subject, path, MAX_BUNDLE_BYTES, file_id)
    if isinstance(data, list):
        return data
    try:
        return keystore_findings(subject, data, MATCHER.scan(data))
    finally:
        release(data)


class JavaKeystores:
    """The cacerts keystores of each Java home and every cacerts file under the scan roots."""

    name: ClassVar[str] = "java-keystores"
    interests: ClassVar[FileInterests] = FileInterests(
        name_globs=frozenset({"cacerts"})
    )

    def run(self, ctx: Context) -> Iterator[Finding]:
        for home in ctx.host.java_homes():
            for relative in JAVA_HOME_KEYSTORES:
                path = home / relative
                file_id = ctx.files.file_id(path)
                if file_id is None or not ctx.ledger.claim(file_id):
                    continue
                yield from judge_keystore(
                    ctx, Subject("jdk cacerts", str(path)), path, file_id
                )
        for indexed in ctx.index.files_for(self.interests):
            if not ctx.ledger.claim(indexed.file_id):
                continue
            subject = Subject("java keystore", str(indexed.path))
            yield from judge_keystore(ctx, subject, indexed.real, indexed.file_id)


PERL_VERSION_ARGS = ("-MMozilla::CA", "-e", "print $Mozilla::CA::VERSION")
PERL_BUNDLE_ARGS = ("-MMozilla::CA", "-e", "print Mozilla::CA::SSL_ca_file()")
MODULE_BUNDLE_SUFFIX = "/Mozilla/CA/cacert.pem"


def first_field(output: str) -> str:
    """Return the first line of a tool's output, or an empty string when it is blank or too long."""
    lines = output.strip().splitlines()
    return lines[0].strip() if lines and len(lines[0]) <= MAX_FIELD_CHARS else ""


def mozilla_ca_finding(subject: Subject, version: str, bundle: str) -> Finding:
    """Judge Mozilla::CA by version when it reads its own bundle, else report the bundle it was patched to use."""
    if not bundle or bundle.endswith(MODULE_BUNDLE_SUFFIX):
        return judge(subject, version, MOZILLA_CA_FIXED)
    return Finding(Level.INFO, subject, f"{version} is patched to use {bundle}")


class PerlMozillaCa:
    """The Mozilla::CA module of the perl on PATH: its version and the bundle it hands out."""

    name: ClassVar[str] = "perl-mozilla-ca"
    interests: ClassVar[FileInterests] = FileInterests()

    def run(self, ctx: Context) -> Iterator[Finding]:
        tool = find_tool(ctx, "perl")
        if isinstance(tool, list):
            yield from tool
            return
        result = run_tool(ctx, tool, "perl", PERL_VERSION_ARGS)
        if isinstance(result, list):
            yield from result
            return
        version = first_field(result.stdout) if result.returncode == 0 else ""
        if not version:
            return
        result = run_tool(ctx, tool, "perl", PERL_BUNDLE_ARGS)
        if isinstance(result, list):
            yield from result
            return
        bundle = first_field(result.stdout) if result.returncode == 0 else ""
        yield mozilla_ca_finding(Subject("Mozilla::CA", "host"), version, bundle)
        if not bundle.startswith("/"):
            return
        path = Path(bundle)
        file_id = ctx.files.file_id(path)
        if file_id is not None and ctx.ledger.claim(file_id):
            yield from content_findings(
                ctx, Subject("Mozilla::CA bundle", bundle), path, file_id
            )
