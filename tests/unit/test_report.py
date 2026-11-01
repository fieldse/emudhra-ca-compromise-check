"""test_report.py: unit tests of emudhra_check/report.py.

Covers the output line format, sanitising of every field, stderr notes and the SUMMARY exit codes.
"""

import io
import unittest

from emudhra_check.report import (
    Finding,
    Level,
    Subject,
    Summary,
    is_shown,
    note,
    sanitise,
)


class LineTest(unittest.TestCase):
    def test_finding_with_subject(self) -> None:
        finding = Finding(Level.FAIL, Subject("ca-bundle", "/x"), "contains y")
        self.assertEqual(finding.line(), "FAIL  ca-bundle [/x] contains y")

    def test_finding_without_subject(self) -> None:
        self.assertEqual(Finding(Level.INFO, None, "").line(), "INFO  ")

    def test_error_level_is_five_wide(self) -> None:
        self.assertEqual(Finding(Level.ERROR, None, "").line(), "ERROR  ")

    def test_every_field_is_sanitised(self) -> None:
        finding = Finding(Level.PASS, Subject("a\nb", "c\rd"), "e\x1bf")
        self.assertEqual(finding.line(), "PASS  a?b [c?d] e?f")


class SanitiseTest(unittest.TestCase):
    def test_newline_cannot_start_a_line(self) -> None:
        self.assertEqual(len(sanitise("a\nFAIL  b").splitlines()), 1)

    def test_spaces_are_kept(self) -> None:
        self.assertEqual(sanitise("a FAIL  b").splitlines(), ["a FAIL  b"])

    def test_escape_and_carriage_return(self) -> None:
        self.assertEqual(sanitise("\x1b[2J\rx"), "?[2J?x")

    def test_line_and_paragraph_separators(self) -> None:
        self.assertEqual(sanitise("a b c"), "a?b?c")

    def test_right_to_left_override(self) -> None:
        self.assertEqual(sanitise("a‮b"), "a?b")

    def test_long_field_is_cut(self) -> None:
        out = sanitise("x" * 2000)
        self.assertEqual(out, "x" * 1024 + "...")

    def test_field_at_the_limit_is_kept(self) -> None:
        self.assertEqual(sanitise("x" * 1024), "x" * 1024)

    def test_lone_surrogate_encodes(self) -> None:
        stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        stream.write(Finding(Level.INFO, Subject("\udcff", "w"), "d").line())
        stream.flush()


class NoteTest(unittest.TestCase):
    def test_note_is_one_line(self) -> None:
        out = note("check", "x\nPASS  y")
        self.assertEqual(len(out.splitlines()), 1)
        self.assertTrue(out.startswith("check: note: "))


class SummaryTest(unittest.TestCase):
    def summary(self, *levels: Level) -> Summary:
        summary = Summary()
        for level in levels:
            summary.add(level)
        return summary

    def test_line(self) -> None:
        summary = self.summary(
            Level.PASS,
            Level.FAIL,
            Level.WARN,
            Level.INFO,
            Level.INFO,
            Level.SKIP,
            Level.ERROR,
        )
        self.assertEqual(
            summary.line(), "SUMMARY pass=1 fail=1 warn=1 info=2 skip=1 error=1"
        )

    def test_exit_codes(self) -> None:
        rows = [
            (Level.PASS, False, 0),
            (Level.PASS, True, 0),
            (Level.INFO, True, 0),
            (Level.SKIP, True, 0),
            (Level.FAIL, False, 1),
            (Level.FAIL, True, 1),
            (Level.WARN, False, 0),
            (Level.WARN, True, 1),
            (Level.ERROR, False, 0),
            (Level.ERROR, True, 1),
        ]
        for level, strict, want in rows:
            with self.subTest(level=level, strict=strict):
                self.assertEqual(self.summary(level).exit_code(strict), want)

    def test_empty_summary_exits_zero(self) -> None:
        self.assertEqual(Summary().exit_code(True), 0)


class ShownTest(unittest.TestCase):
    def test_quiet_hides_pass_info_and_skip(self) -> None:
        for level in Level:
            with self.subTest(level=level):
                self.assertIs(is_shown(level, quiet=False), True)
                self.assertIs(
                    is_shown(level, quiet=True),
                    level in (Level.FAIL, Level.WARN, Level.ERROR),
                )


if __name__ == "__main__":
    unittest.main()
