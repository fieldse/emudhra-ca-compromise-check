"""test_versions.py: unit tests of emudhra_check/versions.py.

The dpkg, rpm and apk orderings are literals recorded from dpkg --compare-versions, rpm.vercmp and
apk version -t runs in containers, over the version strings of the OS research claims.
"""

import datetime
import time
import unittest
from unittest import mock

from emudhra_check.report import Finding, Level, Subject
from emudhra_check.versions import (
    FixRule,
    apk_compare,
    brew_formula_version,
    dpkg_compare,
    judge,
    judge_branched,
    parse_version,
    pseudo_version_time,
    rpm_compare,
)

SUBJECT = Subject("node", "host")

# dpkg --compare-versions in debian:trixie (OS-003 to OS-005, OS-011 to OS-016).
DPKG = [
    ("20250419", "20250419+deb13u1", -1),
    ("20250419+deb13u1", "20250419+deb13u1", 0),
    ("20230311+deb12u1", "20250419~deb12u2", -1),
    ("20250419~deb12u1", "20250419~deb12u2", -1),
    ("20250419~deb12u2", "20250419", -1),
    ("20250419~deb12u2", "20250419+deb13u1", -1),
    ("20260816", "20260816+nmu1", -1),
    ("20260816+nmu1", "20260816+nmu2", -1),
    ("20211016", "20260816ubuntu0.22.04.1", -1),
    ("20260816ubuntu0.22.04.1", "20260816ubuntu0.22.04.2", -1),
    ("20240203", "20260816ubuntu0.24.04.1", -1),
    ("20260223", "20260816ubuntu0.26.04.1", -1),
    ("20260816", "20260816ubuntu0.26.10.1", -1),
    ("20260816ubuntu0.26.10.1", "20260816+nmu1", -1),
    ("20240203~20.04.1ubuntu0.1~esm1", "20240203~20.04.1ubuntu0.1~esm2", -1),
    ("202402031ubuntu0.18.04.1+esm2", "202402031ubuntu0.18.04.1+esm3", -1),
    ("202402031~16.04.1~esm2", "202402031~16.04.1~esm3", -1),
    ("20230311~14.04.1~esm2", "20230311~14.04.1~esm3", -1),
    ("1.0~rc1", "1.0", -1),
    ("1.0~rc1", "1.0~", 1),
    ("1.0~~", "1.0~", -1),
    ("1:1.0", "2.0", 1),
    ("1.0-1", "1.0", 1),
    ("1.0a", "1.0", 1),
    ("1.0+", "1.0", 1),
    ("1.0.0", "1.0", 1),
    ("1.01", "1.1", 0),
    ("1.0000000000000000000000000000000002", "1.1", 1),
]

# rpm --eval '%{lua: print(rpm.vercmp(A, B))}' in fedora:44 (OS-022 to OS-040, OS-049, OS-051 to OS-053).
RPM = [
    ("2025.2.80_v9.0.304-1.1.fc43", "2026.2.92_v9.0.319-2.fc43", -1),
    ("2026.2.92_v9.0.319-1.fc44", "2026.2.92_v9.0.319-2.fc44", -1),
    ("2026.2.92_v9.0.319-100.2.el10_2", "2026.2.92_v9.0.319-100.3.el10_2", -1),
    ("2026.2.92_v9.0.319-100.3.el10_0", "2026.2.92_v9.0.319-100.3.el10_2", -1),
    ("2024.2.69_v8.0.303-91.4.el9_4", "2026.2.92_v9.0.319-90.3.el9_8", -1),
    ("2026.2.92_v9.0.319-90.3.el9_6", "2026.2.92_v9.0.319-90.3.el9_8", -1),
    ("2026.2.92_v9.0.319-90.2.el9_6", "2026.2.92_v9.0.319-90.3.el9_6", -1),
    ("2026.2.92_v9.0.319-90.3.el9_4", "2026.2.92_v9.0.319-90.3.el9_8", -1),
    ("2025.2.80_v9.0.304-80.2.el8_10", "2026.2.92_v9.0.319-81.3.el8_10", -1),
    ("2026.2.92_v9.0.319-70.2.el7_9", "2026.2.92_v9.0.319-70.3.el7_9", -1),
    ("2026.2.92_v9.0.319-60.3.el6_10", "2026.2.92_v9.0.319-60.3.el6_10", 0),
    ("2025.2.80_v9.0.305-91.el9", "2026.2.92_v9.0.319-90.3.el9_8", -1),
    ("2025.2.80_v9.0.305-102.el10", "2026.2.92_v9.0.319-100.3.el10_2", -1),
    ("2023.2.60_v7.0.306-80.0.el8_8", "2026.2.92_v9.0.319-81.3.el8_10", -1),
    ("2025.2.80_v9.0.304-80.2.0.1.el8_10", "2025.2.80_v9.0.304-80.2.el8_10", 1),
    ("2025.2.80_v9.0.305-91.0.1.el9", "2025.2.80_v9.0.305-91.el9", 1),
    ("2025.2.80_v9.0.305-102.0.1.el10_2", "2026.2.92_v9.0.319-100.3.el10_2", -1),
    ("2025.2.76-1.amzn2.0.2", "2025.2.76-1.amzn2.0.3", -1),
    ("2025.2.76-1.0.amzn2023.0.3", "2025.2.76-1.0.amzn2023.0.4", -1),
    ("3.131", "3.131.1", -1),
    ("3.132", "3.131.1", 1),
    ("2.84-150200.44.1", "2.92-150200.50.2", -1),
    ("2.92-160000.1.1", "2.92", 1),
    ("2.90-1.1", "2.92-2.1", -1),
    ("2.92", "2.92", 0),
    ("1.0~rc1", "1.0", -1),
    ("1.0^post1", "1.0", 1),
    ("1.0^post1", "1.0.1", -1),
    ("1.01", "1.1", 0),
    ("1.0000000000000000000000000000000002", "1.1", 1),
    ("1.0a", "1.0", 1),
    ("1.a", "1.1", -1),
]

# apk version -t in alpine:3.22 (OS-017, OS-019).
APK = [
    ("20260413-r0", "20261020-r0", -1),
    ("20260611-r0", "20261020-r0", -1),
    ("20261020-r0", "20261020-r1", -1),
    ("20260909-r2", "20260909-r3", -1),
    ("20261020-r0", "20260909-r3", 1),
    ("1.0_rc1", "1.0", -1),
    ("1.0_p1", "1.0", 1),
    ("1.2.1", "1.2", 1),
    ("1.0a", "1.0", 1),
    ("1.0_alpha1", "1.0_beta1", -1),
    ("1.01", "1.1", -1),
    ("1.10", "1.9", 1),
    ("1.0-r10", "1.0-r9", 1),
]


def no_int(*args: object) -> int:
    raise AssertionError("int() called")


class ParseVersionTest(unittest.TestCase):
    def test_eleven_digit_component_is_refused(self) -> None:
        self.assertIsNone(parse_version("1.12345678901"))

    def test_ten_digit_component_is_accepted(self) -> None:
        self.assertIsNotNone(parse_version("1.1234567890"))

    def test_long_text_is_refused_before_int(self) -> None:
        with mock.patch("emudhra_check.versions.int", no_int, create=True):
            self.assertIsNone(parse_version("1." * 600))
            self.assertIsNone(parse_version("1." + "9" * 1024 * 1024))

    def test_not_versions(self) -> None:
        for text in (
            "",
            "v1.2",
            "1..2",
            "1.2-beta",
            "1.2-gamma.1",
            "1.2+",
            "1.2 ",
            "١.2",
            "1.2-rc.1x",
        ):
            with self.subTest(text=text):
                self.assertIsNone(parse_version(text))

    def test_padding_is_equal(self) -> None:
        self.assertEqual(parse_version("1.0"), parse_version("1.0.0"))

    def test_pre_release_order(self) -> None:
        beta5, beta6, release = (
            parse_version(t) for t in ("45.0.0-beta.5", "45.0.0-beta.6", "45.0.0")
        )
        assert beta5 is not None and beta6 is not None and release is not None
        self.assertLess(beta5, beta6)
        self.assertLess(beta6, release)
        self.assertLess(parse_version("1.0.0-alpha.9"), parse_version("1.0.0-rc.1"))
        self.assertLess(parse_version("44.9.1"), beta5)

    def test_build_metadata_is_ignored(self) -> None:
        self.assertEqual(parse_version("1.2.3+build.7"), parse_version("1.2.3"))

    def test_large_input_completes(self) -> None:
        start = time.monotonic()
        parse_version("9" * 1024 * 1024)
        dpkg_compare("1." + "9" * 1024 * 1024, "1.1")
        rpm_compare("1." + "9" * 1024 * 1024, "1.1")
        apk_compare("1." + "9" * 1024 * 1024, "1.1")
        self.assertLess(time.monotonic() - start, 10)


class JudgeTest(unittest.TestCase):
    rule = FixRule.single("1.4.4", Level.FAIL, "bundles its own root store")

    def test_below(self) -> None:
        self.assertEqual(
            judge(SUBJECT, "1.4.3", self.rule),
            Finding(
                Level.FAIL,
                SUBJECT,
                "found 1.4.3, fixed 1.4.4 (bundles its own root store)",
            ),
        )

    def test_at_and_above(self) -> None:
        for found in ("1.4.4", "1.4.10", "2.0"):
            with self.subTest(found=found):
                self.assertEqual(
                    judge(SUBJECT, found, self.rule),
                    Finding(Level.PASS, SUBJECT, f"found {found}, fixed 1.4.4"),
                )

    def test_not_comparable(self) -> None:
        self.assertEqual(
            judge(SUBJECT, "abc", self.rule),
            Finding(
                Level.WARN,
                SUBJECT,
                "found abc, fixed 1.4.4: not comparable, check manually",
            ),
        )


class JudgeBranchedTest(unittest.TestCase):
    rule = FixRule(
        (("22", "22.23.4"), ("24", "24.22.1"), ("26", "26.12.1")),
        1,
        Level.FAIL,
        Level.FAIL,
    )

    def test_rows(self) -> None:
        rows = [
            ("24.22.0", Level.FAIL, "found 24.22.0, fixed 24.22.1"),
            ("24.22.1", Level.PASS, "found 24.22.1, fixed 24.22.1"),
            ("22.23.4", Level.PASS, "found 22.23.4, fixed 22.23.4"),
            (
                "27.0.0",
                Level.PASS,
                "found 27.0.0, newer than highest listed fix 26.12.1",
            ),
            (
                "20.19.0",
                Level.FAIL,
                "found 20.19.0, no fix for branch 20 (highest listed fix 26.12.1)",
            ),
            (
                "v24",
                Level.WARN,
                "found v24: not a plain dotted version, check manually",
            ),
        ]
        for found, level, detail in rows:
            with self.subTest(found=found):
                self.assertEqual(
                    judge_branched(SUBJECT, found, self.rule),
                    Finding(level, SUBJECT, detail),
                )

    def test_note_and_no_fix_level(self) -> None:
        rule = FixRule((("3.13", "3.13.18"),), 2, Level.WARN, Level.INFO, "a note")
        self.assertEqual(
            judge_branched(SUBJECT, "3.12.1", rule),
            Finding(
                Level.INFO,
                SUBJECT,
                "found 3.12.1, no fix for branch 3.12 (highest listed fix 3.13.18) (a note)",
            ),
        )
        self.assertEqual(
            judge_branched(SUBJECT, "3.13.5", rule),
            Finding(Level.WARN, SUBJECT, "found 3.13.5, fixed 3.13.18 (a note)"),
        )

    def test_pre_release_branch(self) -> None:
        rule = FixRule(
            (("44", "44.9.1"), ("45", "45.0.0-beta.6")), 1, Level.FAIL, Level.FAIL
        )
        self.assertEqual(
            judge_branched(SUBJECT, "45.0.0-beta.5", rule).level, Level.FAIL
        )
        self.assertEqual(
            judge_branched(SUBJECT, "45.0.0-beta.6", rule).level, Level.PASS
        )
        self.assertEqual(judge_branched(SUBJECT, "45.0.0", rule).level, Level.PASS)


class PackageCompareTest(unittest.TestCase):
    def check(self, compare: object, rows: list) -> None:
        assert callable(compare)
        for a, b, want in rows:
            with self.subTest(a=a, b=b):
                self.assertEqual(compare(a, b), want)
                self.assertEqual(compare(b, a), -want)

    def test_dpkg(self) -> None:
        self.check(dpkg_compare, DPKG)

    def test_rpm(self) -> None:
        self.check(rpm_compare, RPM)

    def test_apk(self) -> None:
        self.check(apk_compare, APK)

    def test_no_int_in_package_compares(self) -> None:
        with mock.patch("emudhra_check.versions.int", no_int, create=True):
            self.assertEqual(
                rpm_compare("1.0000000000000000000000000000000002", "1.1"), 1
            )
            self.assertEqual(
                dpkg_compare("1.0000000000000000000000000000000002", "1.1"), 1
            )
            self.assertEqual(apk_compare("10000000000000000000000000000000002", "9"), 1)

    def test_apk_malformed(self) -> None:
        self.assertIsNone(apk_compare("1.0_bogus", "1.0"))
        self.assertIsNone(apk_compare("", "1.0"))


class BrewFormulaVersionTest(unittest.TestCase):
    def test_parse(self) -> None:
        self.assertEqual(
            brew_formula_version("2026-09-25_1"), (datetime.date(2026, 9, 25), 1)
        )
        self.assertEqual(
            brew_formula_version("2026-09-25"), (datetime.date(2026, 9, 25), 0)
        )

    def test_order(self) -> None:
        low, fixed, high = (
            brew_formula_version(t)
            for t in ("2026-09-25", "2026-09-25_1", "2026-10-20")
        )
        assert low is not None and fixed is not None and high is not None
        self.assertLess(low, fixed)
        self.assertLess(fixed, high)

    def test_malformed(self) -> None:
        for text in (
            "foo",
            "2026-13-01",
            "2026-09",
            "2026-09-25_",
            "2026-09-25_x",
            "2026.10.20",
            "20260-09-25",
        ):
            with self.subTest(text=text):
                self.assertIsNone(brew_formula_version(text))


class PseudoVersionTest(unittest.TestCase):
    def test_timestamps(self) -> None:
        rows = [
            ("v0.0.0-20261020153306-9f2b28d4331a", "20261020153306"),
            ("v0.0.0-20260916154351-b853e4b620cd", "20260916154351"),
            ("v1.2.4-0.20260916154351-b853e4b620cd", "20260916154351"),
            ("v1.2.3-pre.0.20260916154351-b853e4b620cd", "20260916154351"),
        ]
        for text, want in rows:
            with self.subTest(text=text):
                self.assertEqual(pseudo_version_time(text), want)

    def test_release_tag(self) -> None:
        for text in (
            "v0.43.0",
            "v1.0.0-rc.1",
            "",
            "v0.0.0-2026102015330-9f2b28d4331a",
            "v0.0.0-20261020153306-XYZ",
        ):
            with self.subTest(text=text):
                self.assertIsNone(pseudo_version_time(text))


if __name__ == "__main__":
    unittest.main()
