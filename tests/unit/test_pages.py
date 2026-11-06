"""test_pages.py: unit tests for tools/build_pages.py and the pages it builds.

Holds each committed page to its Markdown source, so a page edited by hand or left stale after a
source change fails here. Also covers the converter's syntax and its reference modes.
"""

from __future__ import annotations

import importlib.util
import re
import unittest
from pathlib import Path
from types import ModuleType

REPO = Path(__file__).resolve().parents[2]
BUILD = REPO / "tools" / "build_pages.py"
SITE = REPO / "site"
REFERENCES = REPO / "references.html"


def load_builder() -> ModuleType:
    spec = importlib.util.spec_from_file_location("build_pages", BUILD)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = load_builder()


def convert(markdown: str, refs: str = "inline") -> str:
    return builder.Converter(markdown.splitlines(), builder.Page(refs)).convert()


class TestCommittedPages(unittest.TestCase):
    def test_each_page_matches_its_source(self) -> None:
        sources = sorted(SITE.glob("*.md"))
        self.assertTrue(sources, "no Markdown pages in site/")
        for source in sources:
            meta, _ = builder.front_matter(
                source.read_text(encoding="utf-8").splitlines()
            )
            target = REPO / meta["output"]
            with self.subTest(page=target.name):
                self.assertEqual(
                    target.read_text(encoding="utf-8"),
                    builder.build(source),
                    f"{target.name} is stale. Run: python3 -I tools/build_pages.py",
                )

    def test_reference_tags_exist(self) -> None:
        anchors = set(
            re.findall(
                r"id=['\"](r[0-9]{3})['\"]", REFERENCES.read_text(encoding="utf-8")
            )
        )
        for source in SITE.glob("*.md"):
            for ref in set(
                re.findall(r"R[0-9]{3}", source.read_text(encoding="utf-8"))
            ):
                with self.subTest(source=source.name, ref=ref):
                    self.assertIn(ref.lower(), anchors)


class TestConverter(unittest.TestCase):
    def test_block_attributes(self) -> None:
        self.assertEqual(
            convert("{: .key}\n**Lead.** Detail."),
            '<p class="key"><strong>Lead.</strong> Detail.</p>',
        )

    def test_heading_with_attributes_opens_a_section(self) -> None:
        html = convert("## One {#one}\n\nText.\n\n## Two\n\nMore.")
        self.assertEqual(html.count("<section"), 1)
        self.assertLess(html.index("</section>"), html.index("<h2>Two</h2>"))

    def test_rule_closes_sections(self) -> None:
        html = convert("## One {#one}\n\nText.\n\n---\n\n<aside>Box</aside>")
        self.assertLess(html.index("</section>"), html.index("<aside>"))

    def test_reference_modes(self) -> None:
        source = "## One {#one}\n\nA claim [R001, R002]."
        inline = convert(source, "inline")
        self.assertIn(
            '<span class="rl">[<a href="references.html#r001">R001</a>', inline
        )
        section = convert(source, "section")
        self.assertNotIn('class="rl"', section)
        self.assertIn("Sources: <a", section)
        none = convert(source, "none")
        self.assertNotIn("R001", none)
        self.assertIn("<p>A claim.</p>", none)

    def test_refs_column_left_out_with_refs_none(self) -> None:
        table = "| Item | Note | Refs |\n|---|---|---|\n| Group |\n| a | b | R001 |"
        self.assertIn('<td class="rf">', convert(table, "inline"))
        none = convert(table, "none")
        self.assertNotIn("Refs", none)
        self.assertIn('<th colspan="2">Group</th>', none)

    def test_check_column(self) -> None:
        table = (
            "| Stack | Check {.check} |\n|---|---|\n| Go | • `go version` • on PATH |"
        )
        html = convert(table)
        self.assertIn(
            '<td class="check"><div class="cmd"><code>go version</code><button', html
        )
        self.assertIn('<span class="muted">on PATH</span>', html)

    def test_pipe_inside_code_span(self) -> None:
        html = convert("| A | B |\n|---|---|\n| x | `a | b` |")
        self.assertIn("<code>a | b</code>", html)

    def test_cell_bullets(self) -> None:
        html = convert("| A | B |\n|---|---|\n| x | • one • two |")
        self.assertIn("<ul><li>one</li><li>two</li></ul>", html)

    def test_auto_anchors(self) -> None:
        source = (
            "## 2. Flow A: a `ca-bundle`\n\n### Step 1. Make a directory\n\n"
            "### Step 1. Make a directory\n\n### Root's [list](x.html)\n\n## Kept {#mine}"
        )
        page = builder.Page("inline", anchors=True)
        html = builder.Converter(source.splitlines(), page).convert()
        self.assertIn('<section id="2-flow-a-a-ca-bundle">', html)
        self.assertIn('<h3 id="step-1-make-a-directory">', html)
        self.assertIn('<h3 id="step-1-make-a-directory-1">', html)
        self.assertIn('<h3 id="roots-list">', html)
        self.assertIn('<section id="mine">', html)
        self.assertNotIn("<h2 id=", convert("## Plain"))

    def test_definition_list(self) -> None:
        html = convert("{: .levels}\nFAIL {.fail}\n: Bad.\n\nWARN\n: Look.")
        self.assertIn('<dl class="levels">', html)
        self.assertIn('<dt class="fail">FAIL</dt><dd>Bad.</dd>', html)

    def test_code_block_is_escaped(self) -> None:
        html = convert("```\na < b && c\n```")
        self.assertIn("<pre>a &lt; b &amp;&amp; c</pre>", html)

    def test_raw_html_passes_through(self) -> None:
        self.assertEqual(convert('<p class="src">x</p>'), '<p class="src">x</p>')

    def test_unclosed_fence_fails(self) -> None:
        with self.assertRaises(builder.BuildError):
            convert("```\nno end")

    def test_row_width_mismatch_fails(self) -> None:
        with self.assertRaises(builder.BuildError):
            convert("| A | B |\n|---|---|\n| x | y | z |")

    def test_reference_only_paragraph(self) -> None:
        source = "## One {#one}\n\nText.\n\n[R001, R002]"
        self.assertIn(
            '<p class="muted refs-line">Sources: <a href="references.html#r001">R001</a>, '
            '<a href="references.html#r002">R002</a></p>',
            convert(source, "inline"),
        )
        section = convert(source, "section")
        self.assertEqual(section.count("Sources:"), 1)
        self.assertLess(section.index("Sources:"), section.index("</section>"))
        self.assertNotIn("R001", convert(source, "none"))

    def test_status_div(self) -> None:
        html = convert("::: {.eco #c-1 status=partial}\n### Item\n\nText.\n:::")
        self.assertIn('<div class="eco" id="c-1" data-status="partial">', html)
        self.assertIn(
            '<h3>Item</h3>\n<p class="status"><span class="chip partial">Partly fixed</span></p>',
            html,
        )

    def test_unknown_status_fails(self) -> None:
        with self.assertRaises(builder.BuildError):
            convert("::: {.eco status=done}\n### Item\n:::")

    def test_status_counts(self) -> None:
        page = builder.Page("inline")
        source = (
            "{{count:all}} items, {{count:fixed}} fixed, {{count:unfixed}} unfixed.\n\n"
            "::: {status=fixed}\n### A\n:::\n\n"
            "::: {status=fixed}\n### B\n:::\n\n"
            "::: {status=os}\n### C\n:::"
        )
        html = page.fill_counts(builder.Converter(source.splitlines(), page).convert())
        self.assertIn("<p>3 items, 2 fixed, 0 unfixed.</p>", html)

    def test_unknown_count_fails(self) -> None:
        with self.assertRaises(builder.BuildError):
            builder.Page("inline").fill_counts("{{count:done}}")


if __name__ == "__main__":
    unittest.main()
