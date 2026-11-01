"""containers.py: the detection of local Podman images through the in-image probe.

PodmanImages probes each image the preflight listed and judges what the probe reports with the
host's own verdict functions: Node, Bun, Deno and Go by version, certifi, pip and uv by version or
bundle (INFO when the package has no cacert.pem of its own), the ca-certificates package by its
family, and every bundle and keystore by its bytes. An image whose probe did not finish is a WARN
and nothing from it is judged.
"""

from __future__ import annotations

from typing import ClassVar, Iterator

from emudhra_check.certificates import (
    G3_ECC_ROOT,
    CertificateMatch,
    KeystoreKind,
    MatchKind,
    bundle_findings,
    keystore_kind,
)
from emudhra_check.detections.language_packages import Bundle, python_package_finding
from emudhra_check.detections.os_packages import (
    SUSE_ID_PREFIXES,
    PackageObservation,
    ca_package_finding,
)
from emudhra_check.detections.ports import Context, ProbeStatus
from emudhra_check.detections.runtimes import (
    StoreKind,
    bun_version,
    deno_version,
    go_version,
    node_store_findings,
    node_version,
)
from emudhra_check.detections.shared import MATCHER
from emudhra_check.detections.trust_stores import keystore_findings
from emudhra_check.fixes import BUN_FIXED, DENO_FIXED, GO_FIXED
from emudhra_check.probe import ProbePython, ProbeReport, parse_probe_output
from emudhra_check.report import Finding, Level, Subject
from emudhra_check.scope import FileInterests
from emudhra_check.versions import judge, judge_branched

__all__ = ["PodmanImages", "image_findings"]

G3_FULL = (CertificateMatch(G3_ECC_ROOT.label, G3_ECC_ROOT.role, MatchKind.FULL),)
PYTHON_PACKAGES = frozenset({"certifi", "pip", "uv"})
UNFINISHED = {
    ProbeStatus.FAILED: "failed",
    ProbeStatus.TIMEOUT: "timed out",
    ProbeStatus.OVERRUN: "output over its cap",
}


def runtime_findings(where: str, tool: str, line: str) -> list[Finding]:
    """Judge one RT record by its tool's version parser and fix rule."""
    if tool == "bun":
        version = bun_version(line)
        return [judge(Subject("bun", where), version, BUN_FIXED)] if version else []
    if tool == "deno":
        version = deno_version(line)
        return [judge(Subject("deno", where), version, DENO_FIXED)] if version else []
    if tool == "go":
        version = go_version(line)
        return (
            [judge_branched(Subject("go", where), version, GO_FIXED)] if version else []
        )
    return []


def python_finding(
    where: str, python: ProbePython, report: ProbeReport
) -> list[Finding]:
    """Judge one PY record. A linked cacert.pem defers to its target only when the probe dumped and the
    host judged that target, else the version decides."""
    installer = python.installer
    bundle = Bundle.ABSENT if python.bundled == "0" else Bundle.OWN
    target = python.link_target
    if target is not None:
        if target in report.judged_paths:
            bundle = Bundle.LINKED
        else:
            installer = ""
    subject = Subject(python.name, where)
    return python_package_finding(
        subject, python.version, installer=installer, bundle=bundle
    )


def package_wanted(manager: str, os_id: str) -> bool:
    """Return whether a PKG record is the one B1 judges on this OS: suse records on SUSE, rpm elsewhere."""
    suse = os_id.startswith(SUSE_ID_PREFIXES)
    return not (manager == "rpm" and suse) and not (manager == "suse" and not suse)


def image_findings(name: str, report: ProbeReport) -> list[Finding]:
    """Judge every record of one image's probe report."""
    where = f"image:{name}"
    if report == ProbeReport():
        detail = "returned no records, nothing inspected"
        return [Finding(Level.INFO, Subject("probe", where), detail)]
    found: list[Finding] = []
    for node in report.nodes:
        version = node_version(node.version_line) or node.version_line
        store = (
            StoreKind.BUNDLED if node.bundles_g3 or node.bundles_store else StoreKind.OS
        )
        matches: tuple[CertificateMatch, ...] = G3_FULL if node.bundles_g3 else ()
        found += node_store_findings(Subject("node", where), version, matches, store)
    for runtime in report.runtimes:
        found += runtime_findings(where, runtime.tool, runtime.version_line)
    for python in report.pythons:
        if python.name in PYTHON_PACKAGES:
            found += python_finding(where, python, report)
    for version in report.old_pythons:
        detail = f"{version} predates importlib.metadata, certifi and pip not inspected"
        found.append(Finding(Level.WARN, Subject("python3", where), detail))
    for package in report.packages:
        if package_wanted(package.manager, report.os_id):
            observation = PackageObservation(
                package.manager, package.version, report.os_id
            )
            found.append(
                ca_package_finding(
                    Subject(package.name, where), observation, report.changelog_hits
                )
            )
    if report.no_od:
        detail = "image has no od, bundles and keystores not inspected"
        found.append(Finding(Level.INFO, Subject("probe", where), detail))
    for item in report.files:
        hits = MATCHER.scan(item.data)
        located = f"{where} {item.path}"
        if keystore_kind(item.data) is not KeystoreKind.UNKNOWN:
            found += keystore_findings(
                Subject("java keystore", located), item.data, hits
            )
        else:
            found += bundle_findings(Subject("ca-bundle", located), hits)
    for big in report.big:
        detail = f"too large to scan ({big.size} bytes), skipped"
        found.append(
            Finding(Level.INFO, Subject("ca-bundle", f"{where} {big.path}"), detail)
        )
    if report.dropped:
        detail = f"dropped {report.dropped} malformed records"
        found.append(Finding(Level.WARN, Subject("probe", where), detail))
    return found


class PodmanImages:
    """Local Podman images, probed one at a time with -c or -i."""

    name: ClassVar[str] = "podman-images"
    interests: ClassVar[FileInterests] = FileInterests()

    def run(self, ctx: Context) -> Iterator[Finding]:
        if ctx.images is None:
            return
        for name in ctx.images.names:
            run = ctx.images.probe(name)
            if run.status is ProbeStatus.NO_SHELL:
                yield Finding(
                    Level.SKIP, None, f"image:{name} has no shell, not inspected"
                )
            elif run.status in UNFINISHED:
                detail = (
                    f"did not finish ({UNFINISHED[run.status]}), image not inspected"
                )
                yield Finding(Level.WARN, Subject("probe", f"image:{name}"), detail)
            else:
                yield from image_findings(name, parse_probe_output(run.output))
