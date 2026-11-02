"""test_register.py: contracts between the rule register, the source, references.html and detections.html.

Checks that every fixed-version and certificate constant in fixes.py and certdata.py has a register
row, that every R-number the register, the source comments and the detections page use is a row on
references.html, that detections.html equals a fresh build from the register, and that the register
rows themselves are well formed.
"""

from __future__ import annotations

import ast
import csv
import importlib.util
import io
import re
import tokenize
import unittest
from pathlib import Path
from types import ModuleType

from emudhra_check.certdata import RECORDS
from emudhra_check.detections import REGISTRY

REPO = Path(__file__).resolve().parents[2]
REGISTER = REPO / "rules" / "detection-rules.csv"
FIXES = REPO / "emudhra_check" / "fixes.py"
REFERENCES = REPO / "references.html"
DETECTIONS = REPO / "detections.html"
BUILD = REPO / "tools" / "build_detections.py"
SOURCE = REPO / "emudhra_check"

STATUSES = frozenset({"VERIFIED", "WEAK", "UNVERIFIABLE", "WRONG"})
KINDS = frozenset({"fact", "decision"})
SHARED = ("Matcher", "Shared")
VERSION = re.compile(r"v?[0-9]")
R_NUMBER = re.compile(r"R([0-9]{3})(?:\s*[–-]\s*R([0-9]{3}))?")
CODE_REF = re.compile(r"emudhra_check/fixes\.py:([0-9,-]+)")
TOKEN_EDGE = r"[\w.~+-]"


def read_register() -> list[dict[str, str]]:
    with open(REGISTER, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def load_builder() -> ModuleType:
    spec = importlib.util.spec_from_file_location("build_detections", BUILD)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixed_versions(node: ast.AST) -> list[str]:
    """Return the version strings in a constant's value, leaving out the first of each string pair.

    A pair is (branch, fixed) in a FixRule or (prefix, fixed) in a build table, so its first string is
    a key, not a fixed version.
    """
    keys = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Tuple) and len(sub.elts) == 2:
            if all(
                isinstance(e, ast.Constant) and isinstance(e.value, str)
                for e in sub.elts
            ):
                keys.add(id(sub.elts[0]))
    return [
        sub.value
        for sub in ast.walk(node)
        if isinstance(sub, ast.Constant)
        and isinstance(sub.value, str)
        and VERSION.match(sub.value)
        and id(sub) not in keys
    ]


def constants(source: str) -> list[tuple[str, int, int, list[str]]]:
    """Return (name, first line, last line, fixed versions) for each annotated top-level constant."""
    out = []
    for node in ast.parse(source).body:
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.value
        ):
            end = node.end_lineno or node.lineno
            out.append((node.target.id, node.lineno, end, fixed_versions(node.value)))
    return out


def cited_lines(code: str) -> set[int]:
    """Return every fixes.py line a register code field cites, expanding ranges."""
    lines: set[int] = set()
    for spans in CODE_REF.findall(code):
        for span in spans.split(","):
            first, _, last = span.partition("-")
            if first:
                lines.update(range(int(first), int(last or first) + 1))
    return lines


def r_numbers(text: str) -> set[str]:
    """Return the R-numbers in a text, expanding ranges such as R065–R068."""
    out = set()
    for first, last in R_NUMBER.findall(text):
        out.update(f"R{n:03d}" for n in range(int(first), int(last or first) + 1))
    return out


def comments(path: Path) -> str:
    """Return the text of every comment in a Python file."""
    tokens = tokenize.generate_tokens(
        io.StringIO(path.read_text(encoding="utf-8")).readline
    )
    return "\n".join(t.string for t in tokens if t.type == tokenize.COMMENT)


def has_token(value: str, version: str) -> bool:
    return (
        re.search(f"(?<!{TOKEN_EDGE}){re.escape(version)}(?!{TOKEN_EDGE})", value)
        is not None
    )


class RegisterCoverageTest(unittest.TestCase):
    rows = read_register()

    def test_every_fixes_constant_has_a_row(self) -> None:
        cited = set().union(*(cited_lines(row["code"]) for row in self.rows))
        for name, first, last, _ in constants(FIXES.read_text(encoding="utf-8")):
            with self.subTest(constant=name):
                self.assertTrue(
                    cited & set(range(first, last + 1)),
                    f"no row cites fixes.py:{first}-{last}",
                )

    def test_every_fixed_version_is_a_row_value(self) -> None:
        for name, _, _, versions in constants(FIXES.read_text(encoding="utf-8")):
            for version in versions:
                with self.subTest(constant=name, version=version):
                    self.assertTrue(
                        any(has_token(row["value"], version) for row in self.rows)
                    )

    def test_every_certificate_is_a_row_value(self) -> None:
        values = " ".join(row["value"] for row in self.rows).upper()
        for record in RECORDS:
            with self.subTest(certificate=record.label):
                self.assertIn(record.sha256.hex().upper(), values)


class RegisterRowsTest(unittest.TestCase):
    rows = read_register()

    def test_ids_are_unique(self) -> None:
        ids = [row["id"] for row in self.rows]
        self.assertEqual(len(ids), len(set(ids)))

    def test_fields(self) -> None:
        names = set(SHARED) | {type(d).__name__ for d in REGISTRY}
        for row in self.rows:
            with self.subTest(rule=row["id"]):
                self.assertIn(row["status"], STATUSES)
                self.assertIn(row["kind"], KINDS)
                self.assertRegex(row["checked"], r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
                self.assertTrue(row["detection"].split())
                self.assertLessEqual(set(row["detection"].split()), names)
                self.assertTrue(row["code"])

    def test_decisions_name_a_basis(self) -> None:
        for row in self.rows:
            with self.subTest(rule=row["id"]):
                self.assertEqual(bool(row["basis"]), row["kind"] == "decision")

    def test_facts_have_a_source(self) -> None:
        for row in self.rows:
            if row["kind"] == "fact" and row["status"] != "WRONG":
                with self.subTest(rule=row["id"]):
                    self.assertTrue(row["refs"].split())


class ReferenceNumbersTest(unittest.TestCase):
    page = set(
        f"R{n}"
        for n in re.findall(
            r"<tr id='r([0-9]{3})'>", REFERENCES.read_text(encoding="utf-8")
        )
    )

    def check(self, where: str, numbers: set[str]) -> None:
        self.assertTrue(numbers, f"no R-numbers found in {where}")
        self.assertEqual(
            numbers - self.page,
            set(),
            f"{where} names R-numbers that references.html lacks",
        )

    def test_register_refs_exist(self) -> None:
        self.check(
            "the register",
            set().union(*(set(row["refs"].split()) for row in read_register())),
        )

    def test_source_comment_refs_exist(self) -> None:
        text = "\n".join(comments(path) for path in sorted(SOURCE.rglob("*.py")))
        self.check("emudhra_check comments", r_numbers(text))

    def test_detections_page_refs_exist(self) -> None:
        links = re.findall(
            r"references\.html#r([0-9]{3})", DETECTIONS.read_text(encoding="utf-8")
        )
        self.check("detections.html", {f"R{n}" for n in links})


class DetectionsPageTest(unittest.TestCase):
    def test_page_equals_a_fresh_build(self) -> None:
        builder = load_builder()
        self.assertEqual(DETECTIONS.read_text(encoding="utf-8"), builder.build(REPO))

    def test_sections_follow_the_registry(self) -> None:
        builder = load_builder()
        names = [name for name, _, _ in builder.SECTIONS]
        self.assertEqual(names, list(SHARED) + [type(d).__name__ for d in REGISTRY])


class HelperSelfTest(unittest.TestCase):
    def test_pairs_drop_their_key(self) -> None:
        source = 'A = F((("22", "22.23.4"), ("24", "24.22.1")), 1)\nB = (("x", "*.el9", "2026.1-1.el9"),)\n'
        tree = ast.parse(source)
        found = [
            fixed_versions(node.value)
            for node in tree.body
            if isinstance(node, ast.Assign)
        ]
        self.assertEqual(found, [["22.23.4", "24.22.1"], ["2026.1-1.el9"]])

    def test_cited_lines_expand_ranges(self) -> None:
        self.assertEqual(
            cited_lines("emudhra_check/fixes.py:15-17 emudhra_check/fixes.py:71,73"),
            {15, 16, 17, 71, 73},
        )

    def test_r_numbers_expand_ranges(self) -> None:
        self.assertEqual(
            r_numbers("OS-003 (R050–R052), OS-019 (R060)"),
            {"R050", "R051", "R052", "R060"},
        )

    def test_version_token_edges(self) -> None:
        self.assertTrue(has_token("2026.10.18, recommended 2026.10.19", "2026.10.19"))
        self.assertFalse(has_token("22.23.45", "22.23.4"))
