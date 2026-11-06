"""test_register.py: contracts between the rule register, the source, references.html and the pages built from it.

Checks that every fixed version in fixes.py has a register row that cites its line and holds it as a
value, that every version a row citing fixes.py holds is still in the constants it cites, that each
FixRule's level and AAA_LEVEL appear in the level column of the rows citing them, that every
certificate in certdata.py is a row value, that every code citation points at lines that exist, that
every R-number the register, the source comments and the detections page use is a row on
references.html, that detections.html and docs/weak-rules.md equal a fresh build from the register
and site/checks.md, that every detections.html anchor site/checks.md links is a section on the page,
and that the register rows themselves are well formed, with a gap for every weak fact and
unverifiable rule.
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

from emudhra_check import fixes
from emudhra_check.certdata import RECORDS
from emudhra_check.detections import REGISTRY
from emudhra_check.report import Level
from emudhra_check.versions import FixRule

REPO = Path(__file__).resolve().parents[2]
REGISTER = REPO / "rules" / "detection-rules.csv"
FIXES = REPO / "emudhra_check" / "fixes.py"
REFERENCES = REPO / "references.html"
DETECTIONS = REPO / "detections.html"
WEAK_RULES = REPO / "docs" / "weak-rules.md"
CHECKS_MD = REPO / "site" / "checks.md"
BUILD = REPO / "tools" / "build_detections.py"
SOURCE = REPO / "emudhra_check"

STATUSES = frozenset({"VERIFIED", "WEAK", "UNVERIFIABLE", "WRONG"})
KINDS = frozenset({"fact", "decision"})
SHARED = ("Matcher", "Shared")
VERSION = re.compile(r"v?[0-9]")
R_NUMBER = re.compile(r"R([0-9]{3})(?:\s*[–-]\s*R([0-9]{3}))?")
CODE_REF = re.compile(r"emudhra_check/fixes\.py:([0-9,-]+)")
CITATION = re.compile(r"^([\w./-]+?)(?::([0-9]+(?:[-,][0-9]+)*))?$")
VALUE_VERSION = re.compile(r"(?<![\w.~+:-])v?[0-9]+\.[0-9]+[\w.~+-]*(?<![.,-])")
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


def located_versions(node: ast.AST) -> list[tuple[str, int]]:
    """Return each fixed version in a constant's value with the source line it is on."""
    found = set(fixed_versions(node))
    return [
        (sub.value, sub.lineno)
        for sub in ast.walk(node)
        if isinstance(sub, ast.Constant)
        and isinstance(sub.value, str)
        and sub.value in found
    ]


def constant_strings(source: str) -> dict[int, set[str]]:
    """Return, for each line of a top-level constant, every string in that whole constant."""
    out: dict[int, set[str]] = {}
    for node in ast.parse(source).body:
        if isinstance(node, ast.AnnAssign) and node.value:
            strings = {
                sub.value
                for sub in ast.walk(node.value)
                if isinstance(sub, ast.Constant) and isinstance(sub.value, str)
            }
            for line in range(node.lineno, (node.end_lineno or node.lineno) + 1):
                out.setdefault(line, set()).update(strings)
    return out


def spans_of(code: str) -> list[tuple[str, int, int]]:
    """Return (path, first, last) for each line span a code field cites, or (path, 0, 0) for a bare path."""
    out = []
    for word in code.split():
        match = CITATION.match(word)
        if match is None:
            out.append((word, -1, -1))
            continue
        path, spans = match.groups()
        if spans is None:
            out.append((path, 0, 0))
            continue
        for span in spans.split(","):
            first, _, last = span.partition("-")
            out.append((path, int(first), int(last or first)))
    return out


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

    def test_every_fixed_version_has_a_row_citing_its_line(self) -> None:
        for node in ast.parse(FIXES.read_text(encoding="utf-8")).body:
            if not (isinstance(node, ast.AnnAssign) and node.value):
                continue
            for version, line in located_versions(node.value):
                with self.subTest(version=version, line=line):
                    self.assertTrue(
                        any(
                            line in cited_lines(row["code"])
                            and has_token(row["value"], version)
                            for row in self.rows
                        ),
                        f"no row cites fixes.py:{line} with {version} as its value",
                    )

    def test_row_versions_are_in_the_constants_they_cite(self) -> None:
        strings = constant_strings(FIXES.read_text(encoding="utf-8"))
        for row in self.rows:
            cited = set().union(
                *(strings.get(line, set()) for line in cited_lines(row["code"]))
            )
            if not cited:
                continue
            for token in VALUE_VERSION.findall(row["value"]):
                if token.endswith(".x"):
                    continue
                with self.subTest(rule=row["id"], version=token):
                    self.assertTrue(
                        any(has_token(text, token) for text in cited),
                        f"{token} is not in the fixes.py constants {row['id']} cites",
                    )

    def test_levels_match_the_rows_citing_them(self) -> None:
        for name, first, last, _ in constants(FIXES.read_text(encoding="utf-8")):
            value = getattr(fixes, name)
            if isinstance(value, FixRule):
                # A row may describe the PASS at or above the fix instead of the verdict below it.
                wanted = {value.below.name, value.no_fix.name, Level.PASS.name}
            elif isinstance(value, Level):
                wanted = {value.name}
            else:
                continue
            for row in self.rows:
                if not cited_lines(row["code"]) & set(range(first, last + 1)):
                    continue
                with self.subTest(constant=name, rule=row["id"]):
                    self.assertTrue(set(row["level"].split("/")) & wanted, row["level"])

    def test_homebrew_fix_is_a_row_value(self) -> None:
        day, revision = fixes.HOMEBREW_CA_FIXED
        version = f"{day.isoformat()}_{revision}"
        self.assertTrue(any(has_token(row["value"], version) for row in self.rows))

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

    def test_code_citations_point_at_existing_lines(self) -> None:
        for row in self.rows:
            for path, first, last in spans_of(row["code"]):
                with self.subTest(rule=row["id"], path=path, first=first):
                    self.assertGreaterEqual(first, 0, f"unreadable citation {path}")
                    target = REPO / path
                    self.assertTrue(target.is_file(), f"{path} does not exist")
                    if first:
                        count = len(target.read_text(encoding="utf-8").splitlines())
                        self.assertTrue(
                            1 <= first <= last <= count, f"{first}-{last} of {count}"
                        )

    def test_decisions_name_a_basis(self) -> None:
        for row in self.rows:
            with self.subTest(rule=row["id"]):
                self.assertEqual(bool(row["basis"]), row["kind"] == "decision")

    def test_weak_facts_and_unverifiable_rules_name_a_gap(self) -> None:
        for row in self.rows:
            wanted = row["status"] == "UNVERIFIABLE" or (
                row["status"] == "WEAK" and row["kind"] == "fact"
            )
            with self.subTest(rule=row["id"]):
                self.assertEqual(bool(row["gap"]), wanted)

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

    def test_weak_rules_page_equals_a_fresh_build(self) -> None:
        builder = load_builder()
        self.assertEqual(WEAK_RULES.read_text(encoding="utf-8"), builder.build_weak_rules(REPO))

    def test_checks_md_anchors_are_sections(self) -> None:
        page = set(re.findall(r'<section class="det" id="(d-[a-z0-9]+)">', DETECTIONS.read_text(encoding="utf-8")))
        linked = set(re.findall(r"detections\.html#(d-[a-z0-9]+)", CHECKS_MD.read_text(encoding="utf-8")))
        self.assertEqual(linked - page, set(), "site/checks.md links sections detections.html lacks")

    def test_sections_follow_the_registry(self) -> None:
        builder = load_builder()
        names = [name for name, _, _ in builder.SECTIONS]
        self.assertEqual(names, list(SHARED) + [type(d).__name__ for d in REGISTRY])


CHECKS_FIXTURE = """\
::: {.stacks}

::: {.eco #c-rt-01 status=fixed}
### Node.js `node` &amp; npm

**Checker rules:** [Node on PATH](detections.html#d-nodehost), [Node managers](detections.html#d-nodeversiondirs)

See also [Node.js on PATH](detections.html#d-nodehost).
:::

::: {.eco #c-rt-02 status=unfixed}
### Oracle JDK 11

**Checker rules:** none. The checker reads only the keystore.
:::

:::
"""


class CardLinksTest(unittest.TestCase):
    def test_parser_reads_cards_and_links(self) -> None:
        builder = load_builder()
        self.assertEqual(
            builder.card_links(CHECKS_FIXTURE),
            [
                ("rt-01", "Node.js node & npm", ["d-nodehost", "d-nodeversiondirs"]),
                ("rt-02", "Oracle JDK 11", []),
            ],
        )

    def test_parser_reads_no_cards(self) -> None:
        self.assertEqual(load_builder().card_links("# Affected software\n"), [])

    def test_unclosed_card_is_an_error(self) -> None:
        with self.assertRaises(ValueError):
            load_builder().card_links("::: {.eco #c-x status=fixed}\n### X\n")

    def test_affected_line_escapes_titles(self) -> None:
        line = load_builder().affected_line([("rt-01", "Node.js node & npm"), ("rt-02", "<b>")])
        self.assertIn(
            "<a href='checks.html#c-rt-01'>Node.js node &amp; npm</a>, <a href='checks.html#c-rt-02'>&lt;b&gt;</a>",
            line,
        )


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

    def test_spans_of(self) -> None:
        self.assertEqual(
            spans_of("emudhra_check/fixes.py:15-17,20 rules/iocs.csv:2 README.md"),
            [
                ("emudhra_check/fixes.py", 15, 17),
                ("emudhra_check/fixes.py", 20, 20),
                ("rules/iocs.csv", 2, 2),
                ("README.md", 0, 0),
            ],
        )

    def test_version_token_edges(self) -> None:
        self.assertTrue(has_token("2026.10.18, recommended 2026.10.19", "2026.10.19"))
        self.assertFalse(has_token("22.23.45", "22.23.4"))
