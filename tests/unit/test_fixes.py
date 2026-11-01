"""test_fixes.py: unit tests of emudhra_check/fixes.py.

Checks that every fixed-version constant names its research claims and that every FixRule's
branch keys agree with its fixed versions.
"""

import ast
import re
import unittest
from pathlib import Path

from emudhra_check import fixes
from emudhra_check.versions import FixRule, parse_version

SOURCE = Path(fixes.__file__).read_text(encoding="utf-8")
CLAIM = re.compile(r"#.*\b[A-Z]+-\d{3}\b")


class FixesTest(unittest.TestCase):
    def test_every_final_names_a_claim(self) -> None:
        lines = SOURCE.splitlines()
        finals = [
            node
            for node in ast.parse(SOURCE).body
            if isinstance(node, ast.AnnAssign)
            and isinstance(node.annotation, ast.Name)
            and node.annotation.id == "Final"
        ]
        self.assertGreater(len(finals), 25)
        for node in finals:
            assert isinstance(node.target, ast.Name)
            with self.subTest(name=node.target.id):
                self.assertRegex(lines[node.lineno - 1], CLAIM)

    def test_branch_keys_match_fixed_versions(self) -> None:
        rules = {
            name: value
            for name, value in vars(fixes).items()
            if isinstance(value, FixRule)
        }
        self.assertGreater(len(rules), 15)
        for name, rule in rules.items():
            for branch, fixed in rule.fixes:
                with self.subTest(name=name, fixed=fixed):
                    self.assertIsNotNone(parse_version(fixed))
                    self.assertEqual(
                        ".".join(fixed.split("-")[0].split(".")[: rule.depth]), branch
                    )


if __name__ == "__main__":
    unittest.main()
