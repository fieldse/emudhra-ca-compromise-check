"""test_main.py: unit tests of emudhra_check/__main__.py.

Covers the needs_reexec decision table that keeps the archive's own imports under python3 -I -S.
"""

import os
import unittest

from emudhra_check.__main__ import needs_reexec

ARCHIVE = "/out/check.pyz"
INSIDE = ARCHIVE + os.sep + "emudhra_check" + os.sep + "__main__.py"
PYTHON = "/usr/bin/python3"


class NeedsReexecTest(unittest.TestCase):
    def test_table(self) -> None:
        rows = [
            (
                "isolated and no-site set",
                (True, True, PYTHON, ARCHIVE, INSIDE, False),
                False,
            ),
            ("isolated missing", (False, True, PYTHON, ARCHIVE, INSIDE, False), True),
            ("no-site missing", (True, False, PYTHON, ARCHIVE, INSIDE, False), True),
            ("both missing", (False, False, PYTHON, ARCHIVE, INSIDE, False), True),
            (
                "guard variable present",
                (False, False, PYTHON, ARCHIVE, INSIDE, True),
                False,
            ),
            ("empty sys.executable", (False, False, "", ARCHIVE, INSIDE, False), False),
            (
                "not running from an archive",
                (
                    False,
                    False,
                    PYTHON,
                    "/src/emudhra_check/__main__.py",
                    "/src/emudhra_check/__main__.py",
                    False,
                ),
                False,
            ),
            (
                "archive name is a prefix of another file",
                (
                    False,
                    False,
                    PYTHON,
                    "/out/check",
                    "/out/check.pyz/emudhra_check/__main__.py",
                    False,
                ),
                False,
            ),
            ("empty argv[0]", (False, False, PYTHON, "", INSIDE, False), False),
            (
                "relative argv[0], run as ./FILE",
                (
                    False,
                    False,
                    PYTHON,
                    "./check.pyz",
                    os.getcwd() + "/./check.pyz/emudhra_check/__main__.py",
                    False,
                ),
                True,
            ),
            (
                "working directory /, so the module path starts with //",
                (
                    False,
                    False,
                    PYTHON,
                    "/out/../out/check.pyz",
                    "//out/../out/check.pyz/emudhra_check/__main__.py",
                    False,
                ),
                True,
            ),
        ]
        for label, args, want in rows:
            with self.subTest(label):
                self.assertIs(needs_reexec(*args), want)


if __name__ == "__main__":
    unittest.main()
