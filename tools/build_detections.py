"""build_detections.py: build detections.html from the rule register.

Reads rules/detection-rules.csv and the stylesheet of checks.html, and writes detections.html with
one section per detection in the order of the check's registry. Each section explains what the
detection reads and lists its rules with their level, value, sources and verification status. The
register is the only source of the rule rows, so the page is rebuilt whenever the register changes.

Usage: python3 -I tools/build_detections.py [--out PATH]
"""

from __future__ import annotations

import argparse
import csv
import html
import re
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
REGISTER = Path("rules") / "detection-rules.csv"
CHECKS_PAGE = "checks.html"
OUTPUT = "detections.html"
CHECKED = "2026-11-02"
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
)

# Matcher and Shared hold rules every detection uses. The 27 detections follow in registry order.
SECTIONS = (
    (
        "Matcher",
        "Certificate matcher",
        "Every bundle, keystore and binary the check reads goes through one matcher. It finds the 16"
        " compromised intermediates, the three G3 roots with their two cross-certificates and AAA"
        " Certificate Services by the SHA-256 of"
        " each PEM block, by their DER bytes and by the first base64 line, and by public key when no"
        " full certificate is there. A full intermediate or G3 root is FAIL, AAA is WARN, and a bare"
        " intermediate key is INFO, because fixed software ships those keys as a blocklist.",
    ),
    (
        "Shared",
        "Rules every detection shares",
        "These rules apply wherever the check runs a tool, compares a version or reads a file. A"
        " version it cannot compare, a tool it will not run and a file over its size cap each get a"
        " line of their own instead of a guess.",
    ),
    (
        "OsTrustStore",
        "OS CA bundles",
        "Reads the OS CA bundle files at their standard paths for Debian, Ubuntu, RHEL, Fedora,"
        " openSUSE, Alpine and macOS, and passes each through the certificate matcher. On macOS it adds"
        " a note on what Apple blocks and which tools read /etc/ssl/cert.pem.",
    ),
    (
        "CaCertificatesPackage",
        "OS ca-certificates package",
        "Asks dpkg, apk, rpm or pacman for the installed ca-certificates build and compares it with"
        " the first fixed build for that distribution and release. The distribution comes from"
        " /etc/os-release and, for rpm, from the release part of the version. A family with no listed"
        " fix is WARN and left to the bundle check.",
    ),
    (
        "HomebrewTrustStore",
        "Homebrew CA bundles",
        "Finds the newest ca-certificates formula in Homebrew's Cellar and compares its date and"
        " revision with the fixed formula. It passes Homebrew's cert.pem files through the matcher,"
        " warns when a fixed formula left a stale bundle, and on macOS notes the system roots keychain"
        " the old formula copied from.",
    ),
    (
        "BunHost",
        "Bun",
        "Runs bun --version from PATH and compares it with Bun 1.4.4, the first release whose bundled"
        " roots drop emSign ECC Root CA - G3. It also passes the bun binary through the matcher.",
    ),
    (
        "NodeHost",
        "Node.js on PATH",
        "Runs node --version from PATH and reads the binary node names as process.execPath. It judges"
        " the version against the fixed release on each Node line, then checks whether the binary"
        " still holds emSign ECC Root CA - G3.",
    ),
    (
        "DenoHost",
        "Deno",
        "Runs deno --version from PATH, compares it with Deno 2.9.8 and passes the deno binary"
        " through the matcher. A fixed Deno holds the compromised keys as a blocklist, which shows up"
        " as INFO.",
    ),
    (
        "GoToolchain",
        "Go toolchain",
        "Runs go version from PATH and compares the toolchain with the fixed Go 1.26 and 1.27"
        " releases. It also reads the toolchain line of each go.mod under the scan roots, which only"
        " suggests a toolchain, so a low one is INFO.",
    ),
    (
        "CPythonHost",
        "CPython",
        "Runs python3 --version from PATH, and judges the interpreter running the check when it"
        " differs. A CPython below its fix is WARN, because the fixed releases add a key block in the"
        " ssl module and the pip and certifi checks decide the CA files.",
    ),
    (
        "ElectronApps",
        "Electron apps",
        "Finds Electron apps as macOS bundles and Linux app directories, reads each app's Electron"
        " version from the framework's Info.plist or from the Electron/ string in its binary, and"
        " compares it with the first fixed release on that Electron branch. It also passes the binary"
        " through the matcher.",
    ),
    (
        "UpdaterCaches",
        "Electron updater caches",
        "Looks in Squirrel.Mac ShipIt updater caches for Electron apps an update left behind, judged"
        " by version only. A cached app below its fix is WARN, since the app does not run from the"
        " cache.",
    ),
    (
        "NodeVersionDirs",
        "Node.js version managers",
        "Lists Node.js installs made by nvm, volta, asdf, fnm and mise, takes the version from each"
        " directory name and judges it with the Node rules. It scans each install's binary when"
        " present.",
    ),
    (
        "BundledNodeBinaries",
        "Node.js binaries in apps",
        "Finds Node binaries that apps and tools ship outside PATH and the version managers, reads"
        " the version from the release URL built into each binary, and judges it with the Node"
        " rules.",
    ),
    (
        "PythonDistInfo",
        "certifi, pip and uv packages",
        "Reads certifi, pip and uv dist-info directories under the scan roots and judges the version"
        " in each directory name. A package with no bundle of its own, or whose bundle links out of"
        " the package or comes from a distribution package, is judged by the bundle it uses.",
    ),
    (
        "PythonPins",
        "certifi pins",
        "Reads certifi pins in requirements files, poetry.lock, uv.lock and Pipfile.lock and judges"
        " each pinned version with the certifi rules.",
    ),
    (
        "HostPythonPackages",
        "certifi and pip of python3",
        "Asks the python3 on PATH, from package metadata only, which certifi and pip it has, and"
        " judges them with the same rules as the dist-info check.",
    ),
    (
        "UvHost",
        "uv",
        "Runs uv --version from PATH and compares it with uv 0.13.4, the first release whose bundled"
        " roots drop emSign ECC Root CA - G3. It also passes the uv binary through the matcher.",
    ),
    (
        "ElectronPackages",
        "Electron in node_modules and package.json",
        "Reads the installed node_modules/electron version and the Electron versions package.json"
        " files declare. An installed or exact version below its branch's fix is FAIL, and a range"
        " that starts below the fix is WARN, since it may resolve to a fixed release.",
    ),
    (
        "GoBinaries",
        "Go binaries",
        "Reads the build info of Go binaries in the program directories and scan roots, compares the"
        " toolchain that built each with the fixed Go releases, and checks the x509roots/fallback"
        " module version. It also passes each binary through the matcher.",
    ),
    (
        "RustBinaries",
        "Rust binaries",
        "Reads the webpki-roots, webpki-root-certs and rustls-webpki versions from the registry"
        " source paths a Rust binary embeds, and judges them with the Cargo rules. It also passes"
        " each binary through the matcher.",
    ),
    (
        "CargoLocks",
        "Cargo.lock",
        "Reads webpki-roots, webpki-root-certs and rustls-webpki in each Cargo.lock and judges each"
        " version against the fix on its line. A Cargo.lock inside downloaded crate source is"
        " skipped with INFO.",
    ),
    (
        "ComposerLocks",
        "composer.lock",
        "Reads composer/ca-bundle in each composer.lock and compares it with the fixed 1.4 and 1.6"
        " releases.",
    ),
    (
        "GemfileLocks",
        "Gemfile.lock",
        "Reads excon in each Gemfile.lock and compares it with excon 1.8.0.",
    ),
    (
        "MixLocks",
        "mix.lock",
        "Reads castore and Hex certifi in each mix.lock and compares them with castore 1.0.22 and"
        " certifi 2.18.0.",
    ),
    (
        "PemBundles",
        "PEM bundles",
        "Reads files under the scan roots whose names suggest a CA bundle and that hold a PEM block,"
        " passes each through the matcher, and lists a file only when it holds a certificate the"
        " check looks for.",
    ),
    (
        "JavaKeystores",
        "Java keystores",
        "Reads the cacerts of each Java home and every file named cacerts under the scan roots, as"
        " JKS, JCEKS or PKCS12 without keytool, and passes the certificates through the matcher. A"
        " password-protected PKCS12 is WARN.",
    ),
    (
        "PerlMozillaCa",
        "Perl Mozilla::CA",
        "Asks the perl on PATH for its Mozilla::CA version and the bundle path SSL_ca_file returns."
        " The module's own bundle below 20261020 is FAIL, and a bundle patched to point elsewhere is"
        " judged by content.",
    ),
    (
        "PodmanImages",
        "Podman images",
        "With -c or -i, runs a shell probe in each local Podman image with networking off. The probe"
        " reports runtimes, Python packages and the ca-certificates package, and dumps CA bundles and"
        " keystores, which the check judges with the host rules.",
    ),
)
SHARED_SECTIONS = ("Matcher", "Shared")
STATUS_LABELS = {
    "VERIFIED": ("verified", "ok"),
    "WEAK": ("weak", "weak"),
    "UNVERIFIABLE": ("unverified", "unv"),
    "WRONG": ("under review", "bad"),
}
EXTRA_CSS = """
/* Detections page */
section.det { display: grid; gap: 12px; scroll-margin-top: 16px; }
section.det h2 small { font: 500 13px var(--mono); color: var(--muted); margin-left: 10px; letter-spacing: 0; }
table.list.rules { min-width: 900px; }
.rules td.rid { font: 700 13px var(--mono); white-space: nowrap; }
.rules td.lvl { font: 600 13px var(--mono); white-space: nowrap; }
.rules td.val { font: 13px var(--mono); overflow-wrap: anywhere; min-width: 200px; max-width: 320px; }
.rules td.cond .muted { display: block; margin-top: 4px; font-size: 13.5px; }
.rules td.rf { font: 500 13px var(--mono); white-space: nowrap; }
.rules td.rf a { display: block; text-decoration: none; }
.badge { display: inline-block; font: 600 12px var(--mono); padding: 2px 8px; border-radius: 999px;
  border: 1px solid currentColor; white-space: nowrap; }
.badge.ok { color: var(--good); }
.badge.weak { color: var(--limit); }
.badge.unv { color: var(--muted); }
.badge.bad { color: var(--bad); }
.facts { grid-template-columns: repeat(5, minmax(0, 1fr)); }
@media (max-width: 640px) { .facts { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
.facts div:nth-child(4) b { color: var(--muted); }
.facts div:nth-child(5) b { color: var(--bad); }
dl.levels dt.ok { color: var(--good); }
dl.levels dt.weak { color: var(--limit); }
dl.levels dt.unv { color: var(--muted); }
"""


def read_rules(repo: Path) -> list[dict[str, str]]:
    """Return the register rows in file order."""
    with open(repo / REGISTER, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if tuple(reader.fieldnames or ()) != FIELDS:
            raise ValueError(f"{REGISTER}: columns are not {', '.join(FIELDS)}")
        return list(reader)


def stylesheet(repo: Path) -> str:
    """Return the checks page's stylesheet, without its comments, plus the detections page's additions."""
    text = (repo / CHECKS_PAGE).read_text(encoding="utf-8")
    match = re.search(r"<style>\n(.*?)</style>", text, re.S)
    if match is None:
        raise ValueError(f"{CHECKS_PAGE}: no stylesheet")
    return re.sub(r"[ \t]*/\*.*?\*/\n?", "", match.group(1), flags=re.S) + EXTRA_CSS


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


def rule_row(rule: dict[str, str], first: bool) -> str:
    """Return one table row for a rule. The first appearance of a rule carries its anchor."""
    label, css = STATUS_LABELS[rule["status"]]
    rid = rule["id"].lower()
    row_id = f" id='{rid}'" if first else ""
    basis = f"<span class='muted'>{esc(rule['basis'])}</span>" if rule["basis"] else ""
    level = "–" if rule["level"] == "-" else esc(rule["level"])
    return (
        f"<tr{row_id}><td class='rid'><a href='#{rid}'>{esc(rule['id'])}</a></td>"
        f"<td class='cond'>{esc(rule['condition'])}{basis}</td><td class='lvl'>{level}</td>"
        f"<td class='val'>{esc(rule['value'])}</td>{sources_cell(rule)}"
        f"<td><span class='badge {css}'>{label}</span></td></tr>"
    )


def section(
    name: str, title: str, text: str, rules: list[dict[str, str]], seen: set[str]
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
    <p class="read">{esc(text)}</p>
    <div class="table-scroll"><table class='list rules'><thead>
<tr><th>Rule</th><th>Condition</th><th>Level</th><th>Value</th><th>Sources</th><th>Status</th></tr></thead><tbody>
{body}
</tbody></table></div>
  </section>"""


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
    counts = Counter(rule["status"] for rule in rules)
    kinds = Counter(rule["kind"] for rule in rules)
    toc = "".join(
        f"<li><a href='#{anchor(name)}'>{esc(title)}</a><small>{len(by_section[name])} rules</small></li>"
        for name, title, _ in SECTIONS
    )
    seen: set[str] = set()
    sections = "\n\n".join(
        section(name, title, text, by_section[name], seen)
        for name, title, text in SECTIONS
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>eMudhra G3 detections</title>
<meta name="description" content="Every rule the eMudhra G3 check applies, with its sources and status.">
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
    <p class="ids"><b>eMudhra G3</b> &nbsp;·&nbsp; <a href="./">Guide</a> &nbsp;·&nbsp;
      <a href="checks.html">Checks</a> &nbsp;·&nbsp; Detections &nbsp;·&nbsp;
      <a href="references.html">References</a></p>
    <h1>Detection <span class='hl'>rules</span></h1>
    <p>Every rule the check applies, by detection: what it looks for, the level it reports, the value it
      compares, its sources and whether the sources back it. Checked {CHECKED}.</p>
  </div>
</header>

<main class="wrap">

  <section>
    <div class="facts">
      <div><b>{len(rules)}</b><span>rules</span></div>
      <div><b>{counts["VERIFIED"]}</b><span>verified</span></div>
      <div><b>{counts["WEAK"]}</b><span>weak</span></div>
      <div><b>{counts["UNVERIFIABLE"]}</b><span>unverified</span></div>
      <div><b>{counts["WRONG"]}</b><span>under review</span></div>
    </div>
    <ul class="plain read">
      <li><strong>A rule</strong> is one decision the check makes: a condition it looks for and the level it
        reports. Node.js 22 below 22.23.4 giving <code>FAIL</code> is one rule. A table of eight fixed distro
        builds is eight rules.</li>
      <li><strong>Facts and decisions:</strong> {kinds["fact"]} rules are facts, such as a fixed version, taken
        from a vendor, project or tracker document. {kinds["decision"]} are decisions the project made, such
        as which level a case gets, and each says the reason under its condition.</li>
      <li><strong>Sources:</strong> a verified or weak rule links the rows of the
        <a href="references.html">references page</a> that back it. A decision with no outside source says
        so. An unverified rule and a rule under review show no links.</li>
      <li><strong>Level:</strong> <code>matcher</code> means the certificate matcher's levels apply, and
        <code>rules</code> means the levels of the rules the condition names.</li>
      <li><strong>Rules with problems are shown here too.</strong> {counts["WRONG"]} rules are under review
        because a source contradicts them, and {counts["UNVERIFIABLE"]} could not be checked. A rule under
        review shows no source link until it is fixed, and an unverified rule none until a source is
        reached.</li>
    </ul>
    <dl class="levels read">
      <dt class="ok">verified</dt>
      <dd>Two independent checks against the sources both found that the source states the rule.</dd>
      <dt class="weak">weak</dt>
      <dd>Support is indirect, or the rule is a project decision that no outside source can confirm.</dd>
      <dt class="unv">unverified</dt><dd>No source was reached for the rule.</dd>
      <dt class="fail">under review</dt><dd>A source contradicts the rule. The fix is pending.</dd>
    </dl>
    <p class="read muted">The rules come from the register <code>rules/detection-rules.csv</code> in the
      repository, which also gives each rule's code line.</p>
  </section>

  <nav class='toc read' aria-label='Contents'><h2>Contents</h2><ol>{toc}</ol></nav>

{sections}

</main>

<footer>
  <div class="wrap"><p>eMudhra G3 intermediate CA key compromise, October 2026. Not affiliated with eMudhra,
    Sectigo or any root program.</p><p>Last checked {CHECKED}.
    <a href="https://github.com/fieldse/emudhra-ca-compromise-check">Source on GitHub</a>.</p></div>
</footer>

</body>
</html>
"""


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Build detections.html from the rule register."
    )
    parser.add_argument(
        "--out",
        default=str(REPO / OUTPUT),
        help="output path (default: detections.html)",
    )
    args = parser.parse_args(argv)
    Path(args.out).write_text(build(REPO), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
