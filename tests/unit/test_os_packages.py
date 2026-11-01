"""test_os_packages.py: unit tests of emudhra_check/detections/os_packages.py.

Judges every ca-certificates build the research names, on both sides of each fixed build, for dpkg,
apk, rpm, SUSE and pacman, and runs the detection over recorded package manager output.
"""

from __future__ import annotations

import unittest

from emudhra_check.detections.os_packages import (
    CaCertificatesPackage,
    PackageObservation,
    ca_package_finding,
)
from emudhra_check.report import Level, Subject
from tests.unit.fakes import (
    FakeCommands,
    FakeFiles,
    lines,
    located,
    make_context,
    result,
)

PASS, FAIL, WARN = Level.PASS, Level.FAIL, Level.WARN
SUBJECT = Subject("ca-certificates", "host")

DPKG = (
    ("20250419", FAIL),  # OS-003
    ("20250419+deb13u1", PASS),
    ("20230311+deb12u1", FAIL),  # OS-004
    ("20250419~deb12u1", FAIL),
    ("20250419~deb12u2", PASS),
    ("20260816", FAIL),  # OS-005, OS-014
    ("20260816+nmu1", PASS),
    ("20211016", FAIL),  # OS-011
    ("20260816ubuntu0.22.04.1", PASS),
    ("20240203", FAIL),  # OS-012
    ("20260816ubuntu0.24.04.1", PASS),
    ("20260223", FAIL),  # OS-013
    ("20260816ubuntu0.26.04.1", PASS),
    ("20260816ubuntu0.26.10.1", PASS),  # OS-014
    ("20240203~20.04.1ubuntu0.1~esm1", FAIL),  # OS-016
    ("20240203~20.04.1ubuntu0.1~esm2", PASS),
    ("202402031ubuntu0.18.04.1+esm2", FAIL),
    ("202402031ubuntu0.18.04.1+esm3", PASS),
    ("202402031~16.04.1~esm2", FAIL),
    ("202402031~16.04.1~esm3", PASS),
    ("20230311~14.04.1~esm2", FAIL),
    ("20230311~14.04.1~esm3", PASS),
    ("20261101", PASS),
    ("20210119", FAIL),  # OS-009
)
APK = (
    ("20260413-r0", "alpine", FAIL),  # OS-017
    ("20260611-r0", "alpine", FAIL),
    ("20261020-r0", "alpine", PASS),
    ("20261020-r1", "alpine", PASS),
    ("20260909-r2", "wolfi", FAIL),  # OS-019
    ("20260909-r3", "wolfi", PASS),
    ("20260909-r3", "chainguard", PASS),
    ("20260909-r3", "alpine", FAIL),
    ("garbage", "alpine", WARN),
)
RPM = (
    ("2025.2.80_v9.0.304-1.1.fc43", FAIL),  # OS-022
    ("2026.2.92_v9.0.319-2.fc43", PASS),
    ("2026.2.92_v9.0.319-2.fc44", PASS),
    ("2026.2.92_v9.0.319-2.fc45", PASS),
    ("2025.2.80_v9.0.304-6.fc44", FAIL),
    ("2026.2.92_v9.0.319-1.fc44", WARN),  # OS-023
    ("2026.2.92_v9.0.319-100.3.el10_2", PASS),  # OS-025
    ("2026.2.92_v9.0.319-100.2.el10_2", FAIL),
    ("2026.2.92_v9.0.319-100.3.el10_0", PASS),
    ("2026.2.92_v9.0.319-100.2.el10_0", FAIL),
    ("2026.2.92_v9.0.319-90.3.el9_8", PASS),  # OS-026
    ("2026.2.92_v9.0.319-90.2.el9_8", FAIL),
    ("2026.2.92_v9.0.319-90.3.el9_6", PASS),
    ("2026.2.92_v9.0.319-90.2.el9_6", FAIL),
    ("2026.2.92_v9.0.319-90.3.el9_4", FAIL),
    ("2024.2.69_v8.0.303-91.4.el9_4", FAIL),
    ("2026.2.92_v9.0.319-81.3.el8_10", PASS),  # OS-027
    ("2026.2.92_v9.0.319-81.2.el8_10", FAIL),
    ("2026.2.92_v9.0.319-70.3.el7_9", PASS),  # OS-028
    ("2026.2.92_v9.0.319-70.2.el7_9", FAIL),
    ("2026.2.92_v9.0.319-60.3.el6_10", PASS),
    ("2026.2.92_v9.0.319-60.2.el6_10", FAIL),
    ("2026.2.92_v9.0.319-90.0.el9_8", FAIL),  # OS-029
    ("2026.2.92_v9.0.319-90.1.el9_8", FAIL),
    ("2025.2.80_v9.0.305-91.el9", FAIL),  # OS-030, OS-036
    ("2026.2.90_v9.0.316-100.0.el10", FAIL),
    ("2023.2.60_v7.0.306-80.0.el8_8", FAIL),  # OS-031, OS-036
    ("2026.2.90_v9.0.316-90.0.el9", FAIL),  # OS-032
    ("2026.2.92_v9.0.319-91.3.el9", PASS),
    ("2026.2.92_v9.0.319-100.1.el10", WARN),  # OS-033
    ("2025.2.80_v9.0.304-80.2.el8_10", FAIL),  # OS-034
    ("2025.2.80_v9.0.305-102.el10_1", FAIL),
    ("2025.2.80_v9.0.305-102.el10", FAIL),  # OS-035, OS-036
    ("2025.2.80_v9.0.304-80.2.0.1.el8_10", PASS),  # OS-037
    ("2025.2.80_v9.0.305-91.0.1.el9", PASS),
    ("2025.2.80_v9.0.305-102.0.1.el10_2", PASS),
    ("2025.2.80_v9.0.304-80.1.0.1.el8_10", FAIL),
    ("2025.2.76-1.amzn2.0.2", FAIL),  # OS-039
    ("2025.2.76-1.amzn2.0.3", PASS),
    ("2025.2.76-1.0.amzn2023.0.3", FAIL),  # OS-040
    ("2025.2.76-1.0.amzn2023.0.4", PASS),
    ("2025.2.76-1.0.amzn2023.0.5", PASS),  # OS-041
    ("1.0-1.unknown", WARN),
)


def level(manager: str, version: str, os_id: str = "", hits: int = 0) -> Level:
    found = PackageObservation(manager, version, os_id)
    return ca_package_finding(SUBJECT, found, hits).level


class VerdictTest(unittest.TestCase):
    def test_dpkg(self) -> None:
        for version, want in DPKG:
            with self.subTest(version=version):
                self.assertIs(level("dpkg", version), want)

    def test_apk(self) -> None:
        for version, os_id, want in APK:
            with self.subTest(version=version, os_id=os_id):
                self.assertIs(level("apk", version, os_id), want)

    def test_rpm(self) -> None:
        for version, want in RPM:
            with self.subTest(version=version):
                self.assertIs(level("rpm", version), want)

    def test_rpm_changelog_names_the_cve(self) -> None:
        self.assertIs(level("rpm", "2024.2.69_v8.0.303-91.4.el9_4", hits=1), PASS)

    def test_changelog_cannot_lift_a_tls_only_build(self) -> None:
        for version in ("2026.2.92_v9.0.319-1.fc44", "2026.2.92_v9.0.319-100.1.el10"):
            with self.subTest(version=version):
                self.assertIs(level("rpm", version, hits=1), WARN)
        self.assertIs(level("rpm", "1.0-1.unknown", hits=1), PASS)

    def test_rpm_compares_version_before_release(self) -> None:
        self.assertIs(level("rpm", "2026.2.92-95.el9_8"), FAIL)
        self.assertIs(level("rpm", "2026.2.92_v9.0.319-90.3.el9_8"), PASS)

    def test_rpm_detail(self) -> None:
        found = PackageObservation("rpm", "2024.2.69_v8.0.303-91.4.el9_4", "rhel")
        self.assertEqual(
            ca_package_finding(SUBJECT, found).line(),
            "FAIL  ca-certificates [host] found 2024.2.69_v8.0.303-91.4.el9_4, fixed 2026.2.92_v9.0.319-90.3.el9_8",
        )

    def test_suse(self) -> None:  # OS-051 to OS-053
        for version, want in (
            ("2.84", FAIL),
            ("2.90", FAIL),
            ("2.92", PASS),
            ("2.93", PASS),
        ):
            with self.subTest(version=version):
                self.assertIs(level("suse", version, "sles"), want)

    def test_pacman_strips_pkgrel(self) -> None:  # OS-049
        for version, want in (
            ("3.131-1", FAIL),
            ("3.131.1-1", PASS),
            ("3.132-1", PASS),
        ):
            with self.subTest(version=version):
                self.assertIs(level("pacman", version, "arch"), want)

    def test_dpkg_details(self) -> None:
        def detail(version: str) -> str:
            found = PackageObservation("dpkg", version, "debian")
            return ca_package_finding(SUBJECT, found).detail

        self.assertEqual(detail("20250419"), "found 20250419, released before the fix")
        self.assertEqual(
            detail("20250419+deb13u1"), "found 20250419+deb13u1, fixed 20250419+deb13u1"
        )
        self.assertEqual(detail("20261101"), "found 20261101, released after the fix")


OS_RELEASE = b'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nID=debian\n'


class DetectionTest(unittest.TestCase):
    def test_dpkg_output(self) -> None:
        commands = FakeCommands(
            {"dpkg-query": located("/usr/bin/dpkg-query")},
            {("/usr/bin/dpkg-query",): result("ca-certificates 20250419\n")},
        )
        ctx = make_context(FakeFiles({"/etc/os-release": OS_RELEASE}), commands)
        self.assertEqual(
            lines(CaCertificatesPackage(), ctx),
            ["FAIL  ca-certificates [host] found 20250419, released before the fix"],
        )

    def test_apk_output_with_wolfi_id(self) -> None:
        commands = FakeCommands(
            {"apk": located("/sbin/apk")},
            {
                ("/sbin/apk",): result(
                    "musl-1.2.5-r0\nca-certificates-20260909-r3\nca-certificates-bundle-20260909-r2\n"
                )
            },
        )
        files = FakeFiles({"/etc/os-release": b'ID="wolfi"\n'})
        self.assertEqual(
            lines(CaCertificatesPackage(), make_context(files, commands)),
            [
                "PASS  ca-certificates [host] found 20260909-r3, fixed 20260909-r3",
                "FAIL  ca-certificates-bundle [host] found 20260909-r2, fixed 20260909-r3",
            ],
        )

    def test_rpm_reads_the_changelog(self) -> None:
        rpm = "/usr/bin/rpm"
        commands = FakeCommands(
            {"rpm": located(rpm)},
            {
                (rpm, "-q", "--qf"): result("2024.2.69_v8.0.303-91.4.el9_4\n"),
                (rpm, "-q", "--changelog"): result("- Fix CVE-2026-114406\n"),
            },
        )
        got = lines(CaCertificatesPackage(), make_context(FakeFiles(), commands))
        self.assertEqual(
            got,
            [
                "PASS  ca-certificates [host] found 2024.2.69_v8.0.303-91.4.el9_4, changelog mentions CVE-2026-114406"
            ],
        )

    def test_suse_asks_for_the_mozilla_package(self) -> None:
        rpm = "/usr/bin/rpm"
        commands = FakeCommands(
            {"rpm": located(rpm)}, {(rpm, "-q", "--qf"): result("2.92\n")}
        )
        files = FakeFiles({"/etc/os-release": b'ID="opensuse-tumbleweed"\n'})
        self.assertEqual(
            lines(CaCertificatesPackage(), make_context(files, commands)),
            ["PASS  ca-certificates-mozilla [host] found 2.92, fixed 2.92"],
        )
        self.assertEqual(commands.calls[0][-1], "ca-certificates-mozilla")

    def test_excluded_tool_is_not_run(self) -> None:
        commands = FakeCommands(
            {"dpkg-query": located("/x/dpkg-query", permitted=False)}
        )
        self.assertEqual(
            lines(CaCertificatesPackage(), make_context(FakeFiles(), commands)),
            [
                "INFO  dpkg-query [host] found on PATH inside an excluded directory, not run"
            ],
        )
        self.assertEqual(commands.calls, [])

    def test_timeout(self) -> None:
        commands = FakeCommands(
            {"pacman": located("/usr/bin/pacman")},
            {("/usr/bin/pacman",): result(timed_out=True, returncode=-9)},
        )
        self.assertEqual(
            lines(CaCertificatesPackage(), make_context(FakeFiles(), commands)),
            ["WARN  pacman [host] timed out after 60 s, skipped"],
        )


if __name__ == "__main__":
    unittest.main()
