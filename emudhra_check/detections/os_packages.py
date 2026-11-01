"""os_packages.py: the OS ca-certificates package verdict.

CaCertificatesPackage asks dpkg, apk, rpm and pacman, whichever are on PATH, which ca-certificates
build is installed and judges it against the first fixed build of its distribution family.
ca_package_finding holds the rules and is shared with the container probe.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Iterator

from emudhra_check.detections.ports import Context
from emudhra_check.detections.shared import read_or_skip, release, tool_output
from emudhra_check.fixes import (
    APK_FIXED,
    DEB_FIX_DATE,
    DEB_FIXED_BUILDS,
    PACMAN_FIXED,
    RPM_FIXED_BUILDS,
    RPM_TLS_ONLY_BUILDS,
    SUSE_FIXED,
    WOLFI_FIXED,
)
from emudhra_check.limits import MAX_TEXT_BYTES
from emudhra_check.report import Finding, Level, Subject
from emudhra_check.scope import FileInterests
from emudhra_check.versions import apk_compare, dpkg_compare, judge, rpm_compare

__all__ = ["CaCertificatesPackage", "PackageObservation", "ca_package_finding"]

OS_RELEASE = Path("/etc/os-release")
RPM_CVE = "CVE-2026-114406"
WOLFI_IDS = frozenset({"wolfi", "chainguard"})
SUSE_ID_PREFIXES = ("opensuse", "sles", "sled", "sle-")
APK_LINE = re.compile(r"(ca-certificates(?:-bundle)?)-([0-9][^-\s]{0,64}-r[0-9]{1,10})")
DEB_DATE = re.compile(r"[0-9]{8}")
CODE_SIGNING = (
    "TLS bundle fixed, code-signing bundle still trusts emSign Root CS CA - G3"
)


@dataclass(frozen=True)
class PackageObservation:
    """One installed package build as its package manager reports it."""

    manager: str
    version: str
    os_id: str


def dpkg_finding(subject: Subject, version: str) -> Finding:
    for prefix, first_fixed in DEB_FIXED_BUILDS:
        if version.startswith(prefix) and dpkg_compare(version, first_fixed) >= 0:
            return Finding(Level.PASS, subject, f"found {version}, fixed {first_fixed}")
    date = DEB_DATE.match(version)
    if date and date.group() > DEB_FIX_DATE:
        return Finding(Level.PASS, subject, f"found {version}, released after the fix")
    return Finding(Level.FAIL, subject, f"found {version}, released before the fix")


def apk_finding(subject: Subject, version: str, os_id: str) -> Finding:
    fixed = WOLFI_FIXED if os_id in WOLFI_IDS else APK_FIXED
    order = apk_compare(version, fixed)
    if order is None:
        return Finding(
            Level.WARN, subject, f"found {version}, fixed {fixed}: not comparable"
        )
    level = Level.PASS if order >= 0 else Level.FAIL
    return Finding(level, subject, f"found {version}, fixed {fixed}")


def rpm_finding(subject: Subject, version: str, changelog_hits: int) -> Finding:
    if changelog_hits > 0:
        return Finding(
            Level.PASS, subject, f"found {version}, changelog mentions {RPM_CVE}"
        )
    release_part = version.rpartition("-")[2]
    tls_only = dict(RPM_TLS_ONLY_BUILDS)
    for family, pattern, first_fixed in RPM_FIXED_BUILDS:
        if not fnmatch.fnmatchcase(release_part, pattern):
            continue
        fixed = rpm_compare(version, first_fixed) >= 0
        partial = tls_only.get(family)
        if (
            partial is not None
            and rpm_compare(version, partial) >= 0
            and (partial == first_fixed or not fixed)
        ):
            return Finding(Level.WARN, subject, f"found {version}, {CODE_SIGNING}")
        level = Level.PASS if fixed else Level.FAIL
        return Finding(level, subject, f"found {version}, fixed {first_fixed}")
    return Finding(
        Level.WARN,
        subject,
        f"found {version}, unknown package family, the trust-store content check decides",
    )


def ca_package_finding(
    subject: Subject, found: PackageObservation, changelog_hits: int = 0
) -> Finding:
    """Judge one installed ca-certificates build against its family's first fixed build."""
    if found.manager == "dpkg":
        return dpkg_finding(subject, found.version)
    if found.manager == "apk":
        return apk_finding(subject, found.version, found.os_id)
    if found.manager == "rpm":
        return rpm_finding(subject, found.version, changelog_hits)
    if found.manager == "suse":
        level = (
            Level.PASS if rpm_compare(found.version, SUSE_FIXED) >= 0 else Level.FAIL
        )
        return Finding(level, subject, f"found {found.version}, fixed {SUSE_FIXED}")
    return judge(
        subject, found.version.rpartition("-")[0] or found.version, PACMAN_FIXED
    )


def os_id(ctx: Context) -> str:
    """Return the ID field of /etc/os-release, or an empty string."""
    data = read_or_skip(
        ctx, Subject("os-release", str(OS_RELEASE)), OS_RELEASE, MAX_TEXT_BYTES
    )
    if isinstance(data, list):
        return ""
    try:
        text = data[0 : len(data)].decode("utf-8", errors="replace")
    finally:
        release(data)
    for line in text.splitlines():
        key, _, value = line.partition("=")
        if key.strip() == "ID":
            return value.strip().strip("\"'")
    return ""


def name_version_pairs(text: str) -> Iterator[tuple[str, str]]:
    """Yield (name, version) from lines of the form NAME VERSION."""
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2:
            yield parts[0], parts[1]


def stdout_of(
    ctx: Context, tool_name: str, args: list[str]
) -> tuple[list[Finding], str]:
    """Run a package query: the lines for a tool that did not run, and its output when it succeeded."""
    findings, result = tool_output(ctx, tool_name, args)
    if result is None or result.returncode != 0:
        return findings, ""
    return findings, result.stdout


class CaCertificatesPackage:
    """The OS ca-certificates package, through each package manager on PATH."""

    name: ClassVar[str] = "ca-certificates-package"
    interests: ClassVar[FileInterests] = FileInterests()

    def run(self, ctx: Context) -> Iterator[Finding]:
        ident = os_id(ctx)
        yield from self.dpkg(ctx, ident)
        yield from self.apk(ctx, ident)
        if ident.startswith(SUSE_ID_PREFIXES):
            yield from self.suse(ctx, ident)
        else:
            yield from self.rpm(ctx, ident)
        yield from self.pacman(ctx, ident)

    def dpkg(self, ctx: Context, ident: str) -> Iterator[Finding]:
        args = ["-W", "-f=${Package} ${Version}\n", "ca-certificates"]
        findings, out = stdout_of(ctx, "dpkg-query", args)
        yield from findings
        for name, version in name_version_pairs(out):
            found = PackageObservation("dpkg", version, ident)
            yield ca_package_finding(Subject(name, "host"), found)

    def apk(self, ctx: Context, ident: str) -> Iterator[Finding]:
        findings, out = stdout_of(ctx, "apk", ["info", "-v"])
        yield from findings
        for line in out.splitlines():
            match = APK_LINE.fullmatch(line.strip())
            if match:
                found = PackageObservation("apk", match.group(2), ident)
                yield ca_package_finding(Subject(match.group(1), "host"), found)

    def rpm(self, ctx: Context, ident: str) -> Iterator[Finding]:
        args = ["-q", "--qf", "%{VERSION}-%{RELEASE}\n", "ca-certificates"]
        findings, out = stdout_of(ctx, "rpm", args)
        yield from findings
        versions = out.split()
        if not versions:
            return
        _, log = stdout_of(ctx, "rpm", ["-q", "--changelog", "ca-certificates"])
        hits = log.count(RPM_CVE)
        for version in versions:
            found = PackageObservation("rpm", version, ident)
            yield ca_package_finding(Subject("ca-certificates", "host"), found, hits)

    def suse(self, ctx: Context, ident: str) -> Iterator[Finding]:
        args = ["-q", "--qf", "%{VERSION}\n", "ca-certificates-mozilla"]
        findings, out = stdout_of(ctx, "rpm", args)
        yield from findings
        for version in out.split():
            found = PackageObservation("suse", version, ident)
            yield ca_package_finding(Subject("ca-certificates-mozilla", "host"), found)

    def pacman(self, ctx: Context, ident: str) -> Iterator[Finding]:
        findings, out = stdout_of(ctx, "pacman", ["-Q", "ca-certificates-mozilla"])
        yield from findings
        for name, version in name_version_pairs(out):
            found = PackageObservation("pacman", version, ident)
            yield ca_package_finding(Subject(name, "host"), found)
