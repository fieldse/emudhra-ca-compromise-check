"""build_references.py: build references.html and docs/sources.md from the reference data.

Reads rules/references.csv, one row per claim, and rules/sources.csv, one row per source. Writes
references.html, the claims page with each claim's sources, and docs/sources.md, the index that
lists each source with the claims citing it. Both files come from the same two tables.

The item, claim, value and note cells of references.csv are HTML fragments. The sources cell holds
one line per entry in the row's source list:
  S12                                   Source 12 as sources.csv describes it.
  S1 | title: Bug 2083449, comment 6    Source 1 with this row's own link text. The keys title,
  S1 | publisher: X | date: 2026-10-19  publisher and date each replace one sources.csv field.
  Verified by inspecting ...            A line not starting with an S-number is shown as plain text.
The date "undated", in sources.csv as an empty cell, means the source carries no date.

Usage: python3 -I tools/build_references.py [--page PATH] [--index PATH]
"""

from __future__ import annotations

import argparse
import csv
import html
import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
REFERENCES = Path("rules") / "references.csv"
SOURCES = Path("rules") / "sources.csv"
STYLESHEET = "site/style.css"
PAGE = "references.html"
INDEX = Path("docs") / "sources.md"
UPDATED = "2026-11-05"
FONTS = (
    "https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800"
    "&family=JetBrains+Mono:wght@400;500;600&display=swap"
)
REFERENCE_FIELDS = ("id", "group", "item", "claim", "value", "checked", "sources", "note")
SOURCE_FIELDS = ("id", "title", "url", "publisher", "date", "kind", "backs")
CITE_KEYS = ("title", "publisher", "date")
KINDS = ("primary", "secondary")
UNDATED = "undated"

# Groups in page order: anchor suffix and heading.
GROUPS = (
    ("incident", "Incident"),
    ("roots", "Root programs"),
    ("exposure", "Exposure"),
    ("os", "OS trust stores"),
    ("java", "Java"),
    ("python", "Python"),
    ("js", "JavaScript runtimes"),
    ("langs", "Other languages"),
    ("apps", "Browsers and apps"),
    ("images", "Container images"),
)
EXTRA_CSS = """
/* References page: the claim cell holds the item, claim, value and note. */
.table-scroll.wide { --w: min(1440px, calc(100vw - 40px)); width: var(--w); max-width: none; margin-left: calc((100% - var(--w)) / 2); }
table.list.refs-table { min-width: 860px; }
.list tr.grp th small { margin-left: 10px; font: 500 13px var(--mono); color: var(--muted); letter-spacing: 0; text-transform: none; }
.refs-table td.clm { min-width: 380px; }
.refs-table td.clm .stk { display: block; margin-bottom: 4px; font-weight: 600; color: var(--ink); min-width: 0; }
.refs-table td.clm p + p { margin-top: 6px; }
.refs-table td.clm .lbl { margin-right: 6px; font: 600 12px var(--mono); color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
.refs-table td.clm .note { color: var(--muted); font-size: 14px; }
.refs-table td.clm .note strong { color: var(--limit); }
.refs-table ol.refs { min-width: 260px; }
.refs-table ol.refs li .sn { color: var(--muted); font: 500 11px var(--mono); white-space: nowrap; }
"""
R_ID = re.compile(r"^R[0-9]{3}$")
S_ID = re.compile(r"^S([0-9]+)$")


@dataclass(frozen=True)
class Source:
    id: str
    title: str
    url: str
    publisher: str
    date: str
    kind: str
    backs: str

    @property
    def number(self) -> int:
        return int(self.id[1:])


@dataclass(frozen=True)
class Entry:
    """One item of a row's source list: a source citation, or plain text when source is None."""

    source: Source | None
    title: str
    publisher: str = ""
    date: str = ""


@dataclass(frozen=True)
class Claim:
    id: str
    group: str
    item: str
    claim: str
    value: str
    checked: str
    entries: tuple[Entry, ...]
    note: str

    @property
    def anchor(self) -> str:
        return self.id.lower()

    @property
    def cited(self) -> list[Source]:
        return [e.source for e in self.entries if e.source is not None]


def read_table(path: Path, fields: tuple[str, ...]) -> list[dict[str, str]]:
    """Return the rows of a CSV table whose header must be exactly fields."""
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if tuple(reader.fieldnames or ()) != fields:
            raise ValueError(f"{path.name}: columns are not {', '.join(fields)}")
        return list(reader)


def read_sources(repo: Path) -> dict[str, Source]:
    """Return the sources by S-number, in file order."""
    out: dict[str, Source] = {}
    for row in read_table(repo / SOURCES, SOURCE_FIELDS):
        if not S_ID.match(row["id"]) or row["id"] in out:
            raise ValueError(f"{SOURCES}: bad or repeated id {row['id']!r}")
        if row["kind"] not in KINDS:
            raise ValueError(f"{row['id']}: unknown kind {row['kind']!r}")
        out[row["id"]] = Source(**row)
    return out


def parse_entry(line: str, sources: dict[str, Source], where: str) -> Entry:
    """Return the entry one line of a sources cell describes."""
    head, *fields = line.split(" | ")
    if not S_ID.match(head):
        if fields or re.match(r"S[0-9]", line):
            raise ValueError(f"{where}: unreadable source line {line!r}")
        return Entry(None, line)
    if head not in sources:
        raise ValueError(f"{where}: {head} is not in {SOURCES}")
    source = sources[head]
    own = {"title": source.title, "publisher": source.publisher, "date": source.date or UNDATED}
    for field in fields:
        key, sep, value = field.partition(": ")
        if not sep or key not in CITE_KEYS or not value:
            raise ValueError(f"{where}: unreadable field {field!r} on {head}")
        own[key] = value
    return Entry(source, own["title"], own["publisher"], own["date"])


def read_claims(repo: Path, sources: dict[str, Source]) -> list[Claim]:
    """Return the claims in page order."""
    groups = {name for name, _ in GROUPS}
    out = []
    for row in read_table(repo / REFERENCES, REFERENCE_FIELDS):
        where = row["id"]
        if not R_ID.match(row["id"]):
            raise ValueError(f"{REFERENCES}: bad id {row['id']!r}")
        if row["group"] not in groups:
            raise ValueError(f"{where}: unknown group {row['group']!r}")
        entries = tuple(
            parse_entry(line, sources, where) for line in row["sources"].splitlines() if line
        )
        fields = {k: v for k, v in row.items() if k != "sources"}
        out.append(Claim(entries=entries, **fields))
    return out


def stylesheet(repo: Path) -> str:
    """Return the site stylesheet, without its comments, plus the references page's additions."""
    text = (repo / STYLESHEET).read_text(encoding="utf-8")
    return re.sub(r"[ \t]*/\*.*?\*/\n?", "", text, flags=re.S) + EXTRA_CSS


def esc(text: str) -> str:
    """Escape text for HTML content and single-quoted attributes that hold no quote."""
    return html.escape(text, quote=False)


def ranges(ids: list[str]) -> str:
    """Return R-numbers as sorted runs, such as R001–R025, R304."""
    numbers = sorted(int(i[1:]) for i in ids)
    runs: list[list[int]] = []
    for n in numbers:
        if runs and n == runs[-1][-1] + 1:
            runs[-1].append(n)
        else:
            runs.append([n])
    return ", ".join(
        f"R{r[0]:03d}" if len(r) == 1 else f"R{r[0]:03d}–R{r[-1]:03d}" for r in runs
    )


def by_group(claims: list[Claim]) -> list[tuple[str, str, list[Claim]]]:
    """Return (anchor suffix, heading, claims) for each group, in page order."""
    return [(name, title, [c for c in claims if c.group == name]) for name, title in GROUPS]


def entry_item(entry: Entry) -> str:
    """Return one list item of a row's sources: the linked title, then publisher, date and S-number."""
    source = entry.source
    if source is None:
        return f"<li>{esc(entry.title)}</li>"
    kind = " · secondary" if source.kind == "secondary" else ""
    return (
        f"<li><a href='{esc(source.url)}'>{esc(entry.title)}</a>"
        f"<span class='meta'>{esc(entry.publisher)} · {esc(entry.date)}{kind} · "
        f"<span class='sn' title='Source {source.number} in docs/sources.md'>{source.id}</span></span></li>"
    )


def claim_cell(claim: Claim) -> str:
    """Return the claim cell: the item, the claim, then the value and the note when present."""
    parts = [f"<span class='stk'>{claim.item}</span>{claim.claim}"]
    if claim.value:
        parts.append(f"<span class='lbl'>Value</span>{claim.value}")
    out = "".join(f"<p>{p}</p>" for p in parts)
    if claim.note:
        out += f"<p class='note'>{claim.note}</p>"
    return f"<td class='clm'>{out}</td>"


def claim_row(claim: Claim) -> str:
    """Return the table row for one claim."""
    items = "".join(entry_item(e) for e in claim.entries)
    return (
        f"<tr id='{claim.anchor}'><td class='tid'><a href='#{claim.anchor}'>{claim.id}</a></td>"
        f"{claim_cell(claim)}<td class='dt'>{claim.checked}</td>"
        f"<td><ol class='refs'>{items}</ol></td></tr>"
    )


def build_page(repo: Path) -> str:
    """Return references.html built from the reference data."""
    sources = read_sources(repo)
    groups = by_group(read_claims(repo, sources))
    toc = "".join(
        f"<li><a href='#g-{name}'>{esc(title)}</a><small>{ranges([c.id for c in rows])}</small></li>"
        for name, title, rows in groups
    )
    body = "\n".join(
        f"<tr class='grp' id='g-{name}'><th colspan='4'>{esc(title)}<small>{ranges([c.id for c in rows])}</small></th></tr>\n"
        + "\n".join(claim_row(c) for c in rows)
        for name, title, rows in groups
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>eMudhra G3 references</title>
<meta name="description" content="Every claim on the eMudhra G3 compromise guide and checks table, with its sources, publisher, date and whether each is primary or secondary.">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="{FONTS}">
<style>
{stylesheet(repo)}
</style>
</head>
<body>

<header class="band">
  <div class="wrap">
    <a class="back" href="./">← Back to the guide</a>
    <p class="tags"><span>eMudhra G3</span><span>CA key compromise</span><span>October 2026</span></p>
    <p class="ids"><a href="./">Guide</a> &nbsp;·&nbsp; <a href="incident.html">Incident</a> &nbsp;·&nbsp; <a href="checks.html">Affected software</a> &nbsp;·&nbsp; <a href="fixes.html">Fixes</a> &nbsp;·&nbsp; <a href="detections.html">Checker rules</a> &nbsp;·&nbsp; <a href="proof.html">Proof</a> &nbsp;·&nbsp; References</p>
    <h1>Claim <span class='hl'>references</span></h1>
    <p>Every claim the guide, the checks table and the detection rules make, with the sources it rests on. Last updated {UPDATED}.</p>
  </div>
</header>

<main class="wrap">

  <nav class='toc read' aria-label='Contents'><h2>Contents</h2><ol>{toc}</ol></nav>

  <section id="refs">
    <h2>Claims and their sources</h2>
    <ul class="plain read">
      <li><strong>Claims</strong> are in our words, one per row. A row gives the item, the claim, then the value it states and a note when it has them.</li>
      <li><strong>Sources</strong> link the vendor, project or tracker document behind the claim, with its publisher and date. A source is primary unless it says secondary. Its S-number is its row in <code>docs/sources.md</code> in the repository.</li>
      <li><strong>Checked</strong> is the date the claim was last checked against its sources.</li>
      <li><strong>Verified rows</strong> say so in the note when the claim was checked by inspecting the package, image, binary or file itself, in a container.</li>
      <li><strong>Disputed rows</strong> state both sides and link both sources.</li>
      <li><strong>Each row</strong> has its own anchor, for example <code>references.html#r005</code>.</li>
    </ul>
    <div class="table-scroll wide"><table class='list refs-table'><thead>
<tr><th>#</th><th>Claim</th><th>Checked</th><th>Sources</th></tr></thead><tbody>
{body}
</tbody></table></div>
  </section>

</main>

<footer>
  <div class="wrap"><p>eMudhra G3 intermediate CA key compromise, October 2026. An independent guide, not affiliated with eMudhra or Sectigo.</p><p>Last updated {UPDATED}. <a href="https://github.com/fieldse/emudhra-ca-compromise-check">Source on GitHub</a>.</p></div>
</footer>

</body>
</html>
"""


def slug(title: str) -> str:
    """Return the GitHub heading anchor for a heading."""
    return re.sub(r"[^a-z0-9 -]", "", title.lower()).replace(" ", "-")


def citing(claims: list[Claim]) -> dict[str, list[Claim]]:
    """Return the claims citing each source, in page order, keyed by S-number."""
    out: dict[str, list[Claim]] = {}
    for claim in claims:
        for source in dict.fromkeys(claim.cited):
            out.setdefault(source.id, []).append(claim)
    return out


def build_index(repo: Path) -> str:
    """Return docs/sources.md built from the reference data."""
    sources = read_sources(repo)
    claims = read_claims(repo, sources)
    cites = citing(claims)
    numbers = sorted(int(c.id[1:]) for c in claims)
    uncited_rows = [c.id for c in sorted(claims, key=lambda c: c.id) if not c.cited]
    home = {sid: rows[0].group for sid, rows in cites.items()}
    lines = [
        "# Sources",
        "",
        f"**This page lists the original public sources behind the numbered claims (R{numbers[0]:03d} to"
        f" R{numbers[-1]:03d}) on [references.html](../references.html).**",
        "",
        "- Each row gives one source, linked by its title, with what it backs and the R-numbers that cite it.",
        "- A primary source is the vendor, project or standards body's own document.",
        "- A secondary source is a community or third-party summary.",
    ]
    if uncited_rows:
        lines.append(
            f"- {join_and(uncited_rows)} have no row here. They rest only on inspection of the file"
            " or image itself."
        )
    lines += ["", "## Contents", ""]
    lines += [f"- [{title}](#{slug(title)})" for _, title in GROUPS]
    for name, title in GROUPS:
        members = sorted(
            (s for s in sources.values() if home.get(s.id) == name), key=lambda s: s.number
        )
        lines += [
            "",
            f"## {title}",
            "",
            "| # | Source | Backs | R-numbers | Kind |",
            "|---|---|---|---|---|",
        ]
        for s in members:
            rnums = ", ".join(sorted(c.id for c in cites[s.id]))
            lines.append(
                f"| {s.id} | [{md_text(s.title)}]({s.url}) · {s.publisher} | {s.backs} | {rnums} | {s.kind} |"
            )
    return "\n".join(lines) + "\n"


def md_text(text: str) -> str:
    """Escape the square brackets of a Markdown link text."""
    return text.replace("[", "\\[").replace("]", "\\]")


def join_and(items: list[str]) -> str:
    """Return items as an English list: A, B and C."""
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Build references.html and docs/sources.md from the reference data."
    )
    parser.add_argument(
        "--page", default=str(REPO / PAGE), help="page output path (default: references.html)"
    )
    parser.add_argument(
        "--index", default=str(REPO / INDEX), help="index output path (default: docs/sources.md)"
    )
    args = parser.parse_args(argv)
    Path(args.page).write_text(build_page(REPO), encoding="utf-8")
    Path(args.index).write_text(build_index(REPO), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
