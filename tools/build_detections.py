"""build_detections.py: build detections.html and docs/weak-rules.md from the rule register.

Reads rules/detection-rules.csv, site/checks.md and site/style.css. Writes detections.html with one
section per detection in the order of the check's registry. Each section links the checks.html cards
that name it and lists its rules with their condition, level, value and sources, with a tag on each
rule that is not verified. Writes docs/weak-rules.md with the status counts, the weak rules by level,
the weak facts and unverifiable rules with their gap text, and every weak decision with its full
condition and basis. Both are dated by the latest checked date in the register, so they are rebuilt
whenever the register or checks.md changes.

Usage: python3 -I tools/build_detections.py [--out PATH] [--weak-out PATH]
"""

from __future__ import annotations

import argparse
import csv
import html
import re
import sys
from collections import Counter
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
REGISTER = Path("rules") / "detection-rules.csv"
STYLESHEET = "site/style.css"
CHECKS = Path("site") / "checks.md"
CARD_START = re.compile(r"^:::\s*\{\.eco\s+#c-([\w.-]+)[^}]*\}\s*$")
RULE_LINK = re.compile(r"detections\.html#(d-[a-z0-9]+)")
OUTPUT = "detections.html"
WEAK_OUTPUT = "docs/weak-rules.md"
PROOF = "https://fieldse.github.io/emudhra-ca-compromise-check/proof.html"
STATUS_WORDS = (
    ("VERIFIED", "verified"),
    ("WEAK", "weak"),
    ("UNVERIFIABLE", "unverifiable"),
    ("WRONG", "under review"),
)
DEFERRED_LEVELS = frozenset({"matcher", "rules"})
LEVEL_ORDER = ("FAIL", "WARN", "INFO", "PASS", "SKIP")
FONTS = (
    "https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800"
    "&family=JetBrains+Mono:wght@400;500;600&display=swap"
)
FIELDS = (
    "id",
    "detection",
    "condition",
    "level",
    "value",
    "code",
    "refs",
    "kind",
    "basis",
    "status",
    "checked",
    "gap",
)

# Matcher and Shared hold rules every detection uses. The 27 detections follow in registry order.
SECTIONS = (
    (
        "Matcher",
        "Certificate matcher",
        "Every bundle, keystore and binary the checker reads goes through this matcher.",
    ),
    (
        "Shared",
        "Rules every detection shares",
        "Rules for any tool the checker runs, version it compares or file it reads.",
    ),
    (
        "OsTrustStore",
        "OS CA bundles",
        "Reads the OS CA bundle files at their standard paths.",
    ),
    (
        "CaCertificatesPackage",
        "OS ca-certificates package",
        "Asks dpkg, apk, rpm or pacman for the installed ca-certificates build.",
    ),
    (
        "HomebrewTrustStore",
        "Homebrew CA bundles",
        "Reads Homebrew's ca-certificates formula and its cert.pem files.",
    ),
    (
        "BunHost",
        "Bun",
        "Runs bun --version from PATH and reads the bun binary.",
    ),
    (
        "NodeHost",
        "Node.js on PATH",
        "Runs node --version from PATH and reads the node binary.",
    ),
    (
        "DenoHost",
        "Deno",
        "Runs deno --version from PATH and reads the deno binary.",
    ),
    (
        "GoToolchain",
        "Go toolchain",
        "Runs go version from PATH and reads the toolchain line of each go.mod.",
    ),
    (
        "CPythonHost",
        "CPython",
        "Runs python3 --version from PATH, and judges the interpreter running the checker.",
    ),
    (
        "ElectronApps",
        "Electron apps",
        "Reads the Electron version of each macOS and Linux app, and its binary.",
    ),
    (
        "UpdaterCaches",
        "Electron updater caches",
        "Reads the Electron version of apps left in Squirrel.Mac ShipIt updater caches.",
    ),
    (
        "NodeVersionDirs",
        "Node.js version managers",
        "Reads Node.js installs made by nvm, volta, asdf, fnm and mise.",
    ),
    (
        "BundledNodeBinaries",
        "Node.js binaries in apps",
        "Reads Node binaries that apps and tools ship outside PATH.",
    ),
    (
        "PythonDistInfo",
        "certifi, pip and uv packages",
        "Reads certifi, pip and uv dist-info directories and their bundles.",
    ),
    (
        "PythonPins",
        "certifi pins",
        "Reads certifi pins in requirements files, poetry.lock, uv.lock and Pipfile.lock.",
    ),
    (
        "HostPythonPackages",
        "certifi and pip of python3",
        "Asks the python3 on PATH which certifi and pip it has.",
    ),
    (
        "UvHost",
        "uv",
        "Runs uv --version from PATH and reads the uv binary.",
    ),
    (
        "ElectronPackages",
        "Electron in node_modules and package.json",
        "Reads node_modules/electron and the Electron versions package.json files declare.",
    ),
    (
        "GoBinaries",
        "Go binaries",
        "Reads the build info of Go binaries in program and bin directories.",
    ),
    (
        "RustBinaries",
        "Rust binaries",
        "Reads the webpki-roots, webpki-root-certs and rustls-webpki versions a Rust binary embeds.",
    ),
    (
        "CargoLocks",
        "Cargo.lock",
        "Reads webpki-roots, webpki-root-certs and rustls-webpki in each Cargo.lock.",
    ),
    (
        "ComposerLocks",
        "composer.lock",
        "Reads composer/ca-bundle in each composer.lock.",
    ),
    (
        "GemfileLocks",
        "Gemfile.lock",
        "Reads excon in each Gemfile.lock.",
    ),
    (
        "MixLocks",
        "mix.lock",
        "Reads castore and Hex certifi in each mix.lock.",
    ),
    (
        "PemBundles",
        "PEM bundles",
        "Reads files whose names suggest a CA bundle.",
    ),
    (
        "JavaKeystores",
        "Java keystores",
        "Reads the cacerts of each Java home and every file named cacerts.",
    ),
    (
        "PerlMozillaCa",
        "Perl Mozilla::CA",
        "Asks the perl on PATH for its Mozilla::CA version and bundle.",
    ),
    (
        "PodmanImages",
        "Podman images",
        "With -c or -i, runs a probe in each local Podman image and judges what it reports.",
    ),
)
SHARED_SECTIONS = ("Matcher", "Shared")
# The tag a rule that is not VERIFIED shows under its ID, with its badge class.
STATUS_TAGS = {
    "WEAK": ("weak", "weak"),
    "UNVERIFIABLE": ("unverifiable", "unv"),
    "WRONG": ("under review", "bad"),
}
EXTRA_CSS = """
/* Detections page */
section.det { display: grid; gap: 12px; scroll-margin-top: 16px; }
section.det h2 small { font: 500 13px var(--mono); color: var(--muted); margin-left: 10px; letter-spacing: 0; }
table.list.rules { min-width: 900px; }
.rules td.rid { font: 700 13px var(--mono); white-space: nowrap; }
.rules td.rid .badge { display: table; margin-top: 6px; text-decoration: none; }
.rules td.lvl { font: 600 13px var(--mono); white-space: nowrap; }
.rules td.val { font: 13px var(--mono); overflow-wrap: anywhere; min-width: 200px; max-width: 320px; }
.rules td.cond .muted { display: block; margin-top: 4px; font-size: 13.5px; }
.rules td.rf { font: 500 13px var(--mono); white-space: nowrap; }
.rules td.rf a { display: block; text-decoration: none; }
.badge { display: inline-block; font: 600 12px var(--mono); padding: 2px 8px; border-radius: 999px;
  border: 1px solid currentColor; white-space: nowrap; }
.badge.weak { color: var(--limit); }
.badge.unv { color: var(--muted); }
.badge.bad { color: var(--bad); }
"""


def read_rules(repo: Path) -> list[dict[str, str]]:
    """Return the register rows in file order."""
    with open(repo / REGISTER, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if tuple(reader.fieldnames or ()) != FIELDS:
            raise ValueError(f"{REGISTER}: columns are not {', '.join(FIELDS)}")
        return list(reader)


def last_updated(rules: list[dict[str, str]]) -> str:
    """Return the latest checked date in the register."""
    return max(rule["checked"] for rule in rules)


def long_date(day: str) -> str:
    """Return an ISO date as D Month YYYY, such as 2 November 2026."""
    parsed = date.fromisoformat(day)
    return f"{parsed.day} {parsed.strftime('%B')} {parsed.year}"


def card_title(text: str) -> str:
    """Return a checks.md card title as plain text, without backticks or HTML entities."""
    return html.unescape(text.replace("`", "")).strip()


def card_links(text: str) -> list[tuple[str, str, list[str]]]:
    """Return (card id, title, linked section anchors) for each checks.md card, in file order.

    A card opens with a ::: {.eco #c-<id> ...} line, has its ### title on the next line and closes
    at a ::: line. Its anchors are every detections.html#d-<name> link inside it, each once.
    """
    cards = []
    card: tuple[str, str, list[str]] | None = None
    expect_title = False
    for number, line in enumerate(text.splitlines(), 1):
        start = CARD_START.match(line)
        if start:
            if card is not None:
                raise ValueError(f"{CHECKS}:{number}: card c-{start.group(1)} opens inside c-{card[0]}")
            card = (start.group(1), "", [])
            expect_title = True
            continue
        if card is None:
            continue
        if expect_title:
            if not line.startswith("### "):
                raise ValueError(f"{CHECKS}:{number}: card c-{card[0]} has no ### title")
            card = (card[0], card_title(line[4:]), card[2])
            expect_title = False
            continue
        if line.strip() == ":::":
            cards.append(card)
            card = None
            continue
        for link in RULE_LINK.findall(line):
            if link not in card[2]:
                card[2].append(link)
    if card is not None:
        raise ValueError(f"{CHECKS}: card c-{card[0]} is not closed")
    return cards


def affected_software(repo: Path, anchors: set[str]) -> dict[str, list[tuple[str, str]]]:
    """Return, for each section anchor, the (card id, title) of the checks.md cards linking it."""
    out: dict[str, list[tuple[str, str]]] = {}
    for card_id, title, links in card_links((repo / CHECKS).read_text(encoding="utf-8")):
        for link in links:
            if link not in anchors:
                raise ValueError(f"{CHECKS}: card c-{card_id} links detections.html#{link}, which has no section")
            out.setdefault(link, []).append((card_id, title))
    return out


def stylesheet(repo: Path) -> str:
    """Return the site stylesheet, without its comments, plus the detections page's additions."""
    text = (repo / STYLESHEET).read_text(encoding="utf-8")
    return re.sub(r"[ \t]*/\*.*?\*/\n?", "", text, flags=re.S) + EXTRA_CSS


def esc(text: str) -> str:
    """Escape text for HTML content and attributes."""
    return html.escape(text, quote=True)


def anchor(name: str) -> str:
    """Return the section anchor for a detection name."""
    return "d-" + name.lower()


def sources_cell(rule: dict[str, str]) -> str:
    """Return the sources cell: links to references.html, or a note when there are none to show."""
    if rule["status"] == "WRONG":
        return "<td class='rf'><span class='muted'>under review</span></td>"
    if rule["status"] == "UNVERIFIABLE":
        return "<td class='rf'><span class='muted'>not reached</span></td>"
    refs = rule["refs"].split()
    if not refs:
        word = "decision" if rule["kind"] == "decision" else "none"
        return f"<td class='rf'><span class='muted'>{word}</span></td>"
    links = "".join(f"<a href='references.html#{r.lower()}'>{r}</a>" for r in refs)
    return f"<td class='rf'>{links}</td>"


def rule_tag(rule: dict[str, str]) -> str:
    """Return the badge for a rule no source fully backs, linked to the proof page's Limitations."""
    if rule["status"] == "VERIFIED":
        return ""
    label, css = STATUS_TAGS[rule["status"]]
    return f"<a class='badge {css}' href='proof.html#limitations'>{label}</a>"


def level_cell(level: str) -> str:
    """Return the Level cell, with matcher linked to its section and rules spelled out."""
    if level == "-":
        return "–"
    words = {"matcher": "<a href='#d-matcher'>matcher</a>", "rules": "per named rule"}
    return "/".join(words.get(part, esc(part)) for part in level.split("/"))


def rule_row(rule: dict[str, str], first: bool) -> str:
    """Return one table row for a rule. The first appearance of a rule carries its anchor."""
    rid = rule["id"].lower()
    row_id = f" id='{rid}'" if first else ""
    basis = f"<span class='muted'>{esc(rule['basis'])}</span>" if rule["basis"] else ""
    level = level_cell(rule["level"])
    return (
        f"<tr{row_id}><td class='rid'><a href='#{rid}'>{esc(rule['id'])}</a>{rule_tag(rule)}</td>"
        f"<td class='cond'>{esc(rule['condition'])}{basis}</td><td class='lvl'>{level}</td>"
        f"<td class='val'>{esc(rule['value'])}</td>{sources_cell(rule)}</tr>"
    )


def affected_line(cards: list[tuple[str, str]]) -> str:
    """Return the line linking a section's checks.html cards, or nothing when none link it."""
    if not cards:
        return ""
    links = ", ".join(f"<a href='checks.html#c-{esc(cid)}'>{esc(title)}</a>" for cid, title in cards)
    return f"\n    <p class=\"read\">Affected software: {links}</p>"


def section(
    name: str,
    title: str,
    text: str,
    rules: list[dict[str, str]],
    cards: list[tuple[str, str]],
    seen: set[str],
) -> str:
    """Return the section for one detection with its rules table."""
    rows = []
    for rule in rules:
        rows.append(rule_row(rule, rule["id"] not in seen))
        seen.add(rule["id"])
    body = "\n".join(rows)
    tag = "" if name in SHARED_SECTIONS else f"<small>{esc(name)}</small>"
    return f"""  <section class="det" id="{anchor(name)}">
    <h2>{esc(title)}{tag}</h2>
    <p class="read">{esc(text)}</p>{affected_line(cards)}
    <div class="table-scroll"><table class='list rules'><thead>
<tr><th>Rule</th><th>Condition</th><th>Level</th><th>Value</th><th>Sources</th></tr></thead><tbody>
{body}
</tbody></table></div>
  </section>"""


def count(n: int, noun: str) -> str:
    """Return a count with its noun, plural unless the count is one."""
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


def build(repo: Path) -> str:
    """Return the detections page built from the register."""
    rules = read_rules(repo)
    names = [name for name, _, _ in SECTIONS]
    by_section: dict[str, list[dict[str, str]]] = {name: [] for name in names}
    for rule in rules:
        for name in rule["detection"].split():
            if name not in by_section:
                raise ValueError(f"{rule['id']}: unknown detection {name}")
            by_section[name].append(rule)
    affected = affected_software(repo, {anchor(name) for name in names})
    updated = last_updated(rules)
    toc = "".join(
        f"<li><a href='#{anchor(name)}'>{esc(title)}</a><small>{count(len(by_section[name]), 'rule')}</small></li>"
        for name, title, _ in SECTIONS
    )
    seen: set[str] = set()
    sections = "\n\n".join(
        section(name, title, text, by_section[name], affected.get(anchor(name), []), seen)
        for name, title, text in SECTIONS
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>eMudhra G3 checker rules</title>
<meta name="description" content="Every rule the eMudhra G3 checker applies, with its level, value and sources.">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="{FONTS}">
<style>
{stylesheet(repo)}</style>
</head>
<body>

<header class="band">
  <div class="wrap">
    <a class="back" href="./">← Back to the guide</a>
    <p class="tags"><span>eMudhra G3</span><span>CA key compromise</span><span>October 2026</span></p>
    <p class="ids"><a href="./">Guide</a> &nbsp;·&nbsp; <a href="incident.html">Incident</a> &nbsp;·&nbsp; <a href="checks.html">Affected software</a> &nbsp;·&nbsp; <a href="fixes.html">Fixes</a> &nbsp;·&nbsp; Checker rules &nbsp;·&nbsp; <a href="proof.html">Proof</a> &nbsp;·&nbsp; <a href="references.html">References</a></p>
    <h1>Checker <span class='hl'>rules</span></h1>
    <p>Every rule the checker applies, in one table per detection. Each row gives what the checker looks
      for, the level it reports, the value it compares and the sources that back it. The rules were last
      checked on {long_date(updated)}.</p>
  </div>
</header>

<main class="wrap">

  <nav class='toc read' aria-label='Contents'><h2>Contents</h2><ol>{toc}</ol></nav>

{sections}

</main>

<footer>
  <div class="wrap"><p>eMudhra G3 intermediate CA key compromise, October 2026. An independent guide, not
    affiliated with eMudhra or Sectigo.</p><p>Last updated {updated}.
    <a href="https://github.com/fieldse/emudhra-ca-compromise-check">Source on GitHub</a>.</p></div>
</footer>

</body>
</html>
"""


def series(items: list[str], last: str = "and") -> str:
    """Join items as an English list: a, b and c."""
    if len(items) < 2:
        return "".join(items)
    return ", ".join(items[:-1]) + f" {last} " + items[-1]


def ids(rules: list[dict[str, str]]) -> str:
    """Return the rule IDs as an English list of code spans."""
    return series([f"`{rule['id']}`" for rule in rules])


def cell(text: str) -> str:
    """Escape the pipes that would split a Markdown table cell."""
    return text.replace("|", "\\|")


def plain(text: str) -> str:
    """Escape the characters Markdown would read as emphasis or an HTML tag in plain register text."""
    return re.sub(r"([\\*<])", r"\\\1", text)


def table(header: tuple[str, ...], rows: list[tuple[str, ...]]) -> str:
    """Return a Markdown table, or a line saying there are none."""
    if not rows:
        return "None."
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(cell(c) for c in row) + " |" for row in rows]
    return "\n".join(lines)


def levels_section(weak: list[dict[str, str]]) -> str:
    """Return the section that sorts the weak rules by the level they can report."""
    fail = [r for r in weak if "FAIL" in r["level"].split("/")]
    rest = [r for r in weak if r not in fail]
    deferred = [r for r in rest if DEFERRED_LEVELS & set(r["level"].split("/"))]
    unlevelled = [r for r in rest if r["level"] == "-"]
    others = [r for r in rest if r not in deferred and r not in unlevelled]
    found = {part for r in others for part in r["level"].split("/")}
    words = [f"`{lv}`" for lv in LEVEL_ORDER if lv in found]
    words += [f"`{lv}`" for lv in sorted(found - set(LEVEL_ORDER))]
    has = "has" if len(fail) == 1 else "have"
    lines = [
        f"**{len(fail)} of the {len(weak)} weak rules {has} `FAIL` as their level:** {ids(fail)}.",
        "",
    ]
    if deferred:
        takes = "takes its" if len(deferred) == 1 else "take their"
        lines.append(
            f"- **{len(deferred)} {takes} level from the certificate matcher or from other rules,**"
            f" which can report `FAIL`: {ids(deferred)}."
        )
    if unlevelled:
        has = "has" if len(unlevelled) == 1 else "have"
        lines.append(f"- **{len(unlevelled)} {has} no level (`-`):** {ids(unlevelled)}.")
    if others:
        lines.append(f"- **The other {len(others)}** report {series(words, 'or')}.")
    return "## Weak rules by level\n\n" + "\n".join(lines).rstrip()


def build_weak_rules(repo: Path) -> str:
    """Return docs/weak-rules.md built from the register."""
    rules = read_rules(repo)
    counts = Counter(rule["status"] for rule in rules)
    weak = [r for r in rules if r["status"] == "WEAK"]
    facts = [r for r in weak if r["kind"] == "fact"]
    decisions = [r for r in weak if r["kind"] == "decision"]
    unverifiable = [r for r in rules if r["status"] == "UNVERIFIABLE"]
    tally = series(
        [
            f"{counts[status]} {'is' if counts[status] == 1 else 'are'} {word}"
            for status, word in STATUS_WORDS
            if counts[status]
        ]
    )
    fact_rows = [(f"`{r['id']}`", r["level"], r["gap"]) for r in facts]
    unverifiable_rows = [(f"`{r['id']}`", r["level"], r["gap"]) for r in unverifiable]
    decision_rows = [
        (f"`{r['id']}`", r["level"], plain(r["condition"]), plain(r["basis"]))
        for r in decisions
    ]
    return f"""# Weak and unverifiable rules

**If a `FAIL` comes from one of these rules, verify it by hand.** The [proof page]({PROOF}) shows how to \
check a rule against its original sources.

Of the {len(rules)} rules the check applies, {tally}. `tools/build_detections.py` writes this page \
from the rule register, `rules/detection-rules.csv`, last updated {last_updated(rules)}.

- A weak fact is a rule that a source backs only in part.
- A weak decision is a project choice with no outside source to check it against.
- An unverifiable rule is one no primary source could be found for.

{levels_section(weak)}

## Weak facts ({len(facts)})

**A source confirms most of each of these claims.** The last column names the part it does not.

{table(("Rule", "Level", "What is weak"), fact_rows)}

## Unverifiable rules ({len(unverifiable)})

**No primary source could be found for these rules.** The last column says why.

{table(("Rule", "Level", "Why"), unverifiable_rows)}

## Weak decisions ({len(decisions)})

**Each of these rules makes a choice that no outside source can check.** The level a rule gives is \
one such choice. The facts a decision rests on are confirmed where a source exists.

{table(("Rule", "Level", "Condition", "Basis"), decision_rows)}

## How the rules were reviewed

LLM agents reviewed each rule in two passes. One pass looked for a source that supports the rule, \
and the other tried to refute it. A rule is `VERIFIED` only when both passes agree, and otherwise it \
takes the worse result. No person ran either pass, so a status guarantees nothing. Treat it as a \
lead to check.

## Checking a rule yourself

1. Find the rule in `rules/detection-rules.csv` or on `detections.html`.
2. Open the R-numbers in its `refs` column on `references.html` and read the source each one links.
3. Compare the source to the rule's condition. If they disagree, the rule is wrong, whatever its \
status says. [Reporting mistakes]({PROOF}#reporting) on the proof page says how to report it.
"""


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Build detections.html and docs/weak-rules.md from the rule register."
    )
    parser.add_argument(
        "--out",
        default=str(REPO / OUTPUT),
        help="detections page path (default: detections.html)",
    )
    parser.add_argument(
        "--weak-out",
        default=str(REPO / WEAK_OUTPUT),
        help="weak rules page path (default: docs/weak-rules.md)",
    )
    args = parser.parse_args(argv)
    Path(args.out).write_text(build(REPO), encoding="utf-8")
    Path(args.weak_out).write_text(build_weak_rules(REPO), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
