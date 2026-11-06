"""test_references.py: contracts between the reference data, references.html and docs/sources.md.

Checks that references.html and docs/sources.md equal a fresh build from rules/references.csv and
rules/sources.csv, that claim and source ids are unique and well formed, that R001 to R358 are all
rows, that every S-number a claim cites is in sources.csv and every source is cited, and that the
page keeps an anchor for every claim and group.
"""

from __future__ import annotations

import csv
import importlib.util
import re
import sys
import unittest
from pathlib import Path
from types import ModuleType

REPO = Path(__file__).resolve().parents[2]
BUILD = REPO / "tools" / "build_references.py"
REFERENCES = REPO / "rules" / "references.csv"
SOURCES = REPO / "rules" / "sources.csv"
PAGE = REPO / "references.html"
INDEX = REPO / "docs" / "sources.md"
LAST_CLAIM = 358
DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
# A source date starts with a year and month and may add a day and an update note.
SOURCE_DATE = re.compile(r"^[0-9]{4}-[0-9]{2}\b")
CITED = re.compile(r"^S([0-9]+)\b", re.M)


def load_builder() -> ModuleType:
    spec = importlib.util.spec_from_file_location("build_references", BUILD)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # dataclasses look the module up in sys.modules while the class is built.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def read(path: Path) -> list[dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


builder = load_builder()


class BuiltFilesTest(unittest.TestCase):
    def test_page_equals_a_fresh_build(self) -> None:
        self.assertEqual(
            PAGE.read_text(encoding="utf-8"),
            builder.build_page(REPO),
            "references.html is stale. Run: python3 -I tools/build_references.py",
        )

    def test_index_equals_a_fresh_build(self) -> None:
        self.assertEqual(
            INDEX.read_text(encoding="utf-8"),
            builder.build_index(REPO),
            "docs/sources.md is stale. Run: python3 -I tools/build_references.py",
        )

    def test_page_keeps_every_anchor(self) -> None:
        page = PAGE.read_text(encoding="utf-8")
        anchors = re.findall(r"id='(r[0-9]{3})'", page)
        self.assertEqual(sorted(anchors), sorted(r["id"].lower() for r in read(REFERENCES)))
        for name, _ in builder.GROUPS:
            with self.subTest(group=name):
                self.assertEqual(page.count(f"id='g-{name}'"), 1)


class ClaimRowsTest(unittest.TestCase):
    rows = read(REFERENCES)

    def test_ids_are_unique(self) -> None:
        ids = [row["id"] for row in self.rows]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_claim_number_is_a_row(self) -> None:
        ids = {row["id"] for row in self.rows}
        missing = [f"R{n:03d}" for n in range(1, LAST_CLAIM + 1) if f"R{n:03d}" not in ids]
        self.assertEqual(missing, [])

    def test_fields(self) -> None:
        groups = {name for name, _ in builder.GROUPS}
        for row in self.rows:
            with self.subTest(claim=row["id"]):
                self.assertRegex(row["id"], r"^R[0-9]{3}$")
                self.assertIn(row["group"], groups)
                self.assertRegex(row["checked"], DATE)
                self.assertTrue(row["item"] and row["claim"] and row["sources"])

    def test_cited_sources_exist(self) -> None:
        known = {row["id"] for row in read(SOURCES)}
        for row in self.rows:
            for number in CITED.findall(row["sources"]):
                with self.subTest(claim=row["id"], source=number):
                    self.assertIn(f"S{number}", known)

    def test_every_line_parses(self) -> None:
        sources = builder.read_sources(REPO)
        self.assertEqual(len(builder.read_claims(REPO, sources)), len(self.rows))


class SourceRowsTest(unittest.TestCase):
    rows = read(SOURCES)

    def test_ids_are_unique(self) -> None:
        ids = [row["id"] for row in self.rows]
        self.assertEqual(len(ids), len(set(ids)))

    def test_fields(self) -> None:
        for row in self.rows:
            with self.subTest(source=row["id"]):
                self.assertRegex(row["id"], r"^S[0-9]+$")
                self.assertTrue(row["title"] and row["publisher"] and row["backs"])
                self.assertRegex(row["url"], r"^https?://\S+$")
                self.assertIn(row["kind"], builder.KINDS)
                if row["date"]:
                    self.assertRegex(row["date"], SOURCE_DATE)

    def test_index_links_every_source(self) -> None:
        index = INDEX.read_text(encoding="utf-8")
        for row in self.rows:
            with self.subTest(source=row["id"]):
                self.assertIn(f"| {row['id']} | [", index)
                self.assertIn(f"]({row['url']})", index)

    def test_every_source_is_cited(self) -> None:
        cited = set()
        for row in read(REFERENCES):
            cited.update(f"S{n}" for n in CITED.findall(row["sources"]))
        orphans = sorted({row["id"] for row in self.rows} - cited, key=lambda s: int(s[1:]))
        self.assertEqual(orphans, [], "sources no claim cites")


class ParserTest(unittest.TestCase):
    sources = {
        "S1": builder.Source("S1", "Bug 1", "https://example.org/1", "Mozilla", "2026-10-18", "primary", "x"),
        "S2": builder.Source("S2", "Tracker", "https://example.org/2", "Tracker", "", "secondary", "y"),
    }

    def parse(self, line: str):  # type: ignore[no-untyped-def]
        return builder.parse_entry(line, self.sources, "R001")

    def test_plain_citation_takes_the_source_fields(self) -> None:
        entry = self.parse("S1")
        self.assertEqual((entry.title, entry.publisher, entry.date), ("Bug 1", "Mozilla", "2026-10-18"))

    def test_empty_date_is_undated(self) -> None:
        self.assertEqual(self.parse("S2").date, "undated")

    def test_fields_replace_the_source_fields(self) -> None:
        entry = self.parse("S1 | title: Bug 1, comment 6 | date: 2026-10-19")
        self.assertEqual((entry.title, entry.publisher, entry.date), ("Bug 1, comment 6", "Mozilla", "2026-10-19"))

    def test_text_line_has_no_source(self) -> None:
        self.assertIsNone(self.parse("Verified by inspecting the image.").source)

    def test_bad_lines_are_errors(self) -> None:
        for line in ("S3", "S1 | colour: red", "S1 | title:", "S1x", "Text | title: x"):
            with self.subTest(line=line):
                with self.assertRaises(ValueError):
                    self.parse(line)

    def test_ranges(self) -> None:
        self.assertEqual(builder.ranges(["R003", "R001", "R002", "R304", "R306"]), "R001–R003, R304, R306")
