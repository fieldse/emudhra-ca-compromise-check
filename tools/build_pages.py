"""build_pages.py: build the guide's HTML pages from their Markdown sources.

Reads each site/*.md page, converts the Markdown subset the pages use, and writes the HTML page
named by its front matter, built from the site/page.html template with the shared stylesheet and
script. Any syntax outside the list below is either plain text or a build error.

Borrowed syntax:
  ---                       Front matter at the top of the file: title, description, output,
                            refs (inline, section or none, see below), and anchors: auto,
                            which gives every heading without attributes GitHub's anchor id and
                            makes each such h2 open a section.
  | a | b |                 GitHub pipe tables. A "|" inside a code span does not split cells.
  ```                       Code block, rendered as a code box with a Copy button.
  {: .cls #id}              kramdown block attributes, on the line before a paragraph, list,
                            table, heading or definition list. A table has no class unless
                            one is set here.
  ## Text {#id .cls}        Heading attributes. A heading with attributes opens a <section>
                            that closes at the next heading of the same or a higher level.
  Term {.cls}               Definition list (Pandoc, PHP Markdown Extra). The term may carry
  : definition              attributes. An indented block continues the definition.
  ::: {.cls tag=main}       Pandoc fenced div. tag= picks the element, <div> by default.
  <...>                     A block whose first line starts with "<" is copied as raw HTML.

Project syntax:
  [R001, R002]              Reference tag linked to references.html. With "refs: section" the
                            tags leave the text and each h2 section ends with a Sources line.
                            With "refs: none" the tags leave the page, raw HTML included.
                            A paragraph that is only a tag becomes a Sources line in place
                            with "refs: inline", and is dropped in the other modes.
  ::: {.cls status=NAME}    Item status on a fenced div: fixed, partial, unfixed or os. The
                            div gets data-status and a status chip after its first heading.
  {{count:NAME}}            Number of divs on the page with that status. {{count:all}}
                            counts every div that has a status.
  Refs column               A table column headed "Refs" renders its R-numbers as links. With
                            "refs: none" the column is left out.
  Name {.check}             A table column whose header has {.check}: each "•" item that is
                            one code span becomes a command box with a copy button, and any
                            other item becomes a muted note.
  Name {.bad} / {.good}     Other header classes go on every cell of that column.
  • a • b                   A table cell starting with "•" becomes a list.
  | Group |                 A one-cell table row becomes a group row across the table.
  ---                       After the front matter, a line of "---" closes every open section.

Usage: python3 -I tools/build_pages.py [--out DIR] [--refs inline|section|none] [PAGE.md ...]
"""

from __future__ import annotations

import argparse
import html
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SITE = REPO / "site"
REFS_PAGE = "references.html"
REFS_MODES = ("inline", "section", "none")
RL_SPAN = re.compile(r'&nbsp;<span class="rl">\[.*?\]</span>')
COPY_ICON = (
    '<svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">'
    '<rect x="5" y="5" width="9" height="9" rx="1.5" fill="none" stroke="currentColor" '
    'stroke-width="1.5"/><path d="M3.5 11H3a1 1 0 0 1-1-1V3a1 1 0 0 1 1-1h7a1 1 0 0 1 1 1v.5" '
    'fill="none" stroke="currentColor" stroke-width="1.5"/></svg>'
)
COPY_BUTTON = f'<button type="button" class="copy" aria-label="Copy command" title="Copy">{COPY_ICON}</button>'

ATTRS = re.compile(r"^\{:\s*([^{}]*)\}$")
TRAILING_ATTRS = re.compile(r"\s*\{:?\s*([^{}]*)\}$")
HEADING = re.compile(r"^(#{1,6})\s+(.*)$")
LIST_ITEM = re.compile(r"^(\s*)(?:[-*]|\d+\.)\s+(.*)$")
FENCE = re.compile(r"^```")
DIV_OPEN = re.compile(r"^:::\s*(\{[^{}]*\}|[\w-]+)\s*$")
DIV_CLOSE = re.compile(r"^:::\s*$")
REF_TAG = re.compile(r"\s*\[(R\d{3}(?:,\s*R\d{3})*)\](?!\()")
REF_ID = re.compile(r"R\d{3}")
LINK = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")
BOLD = re.compile(r"\*\*(.+?)\*\*")
BARE_AMP = re.compile(r"&(?!#?\w+;)")
CODE_SPAN = re.compile(r"(`[^`]+`)")
ONE_CODE_SPAN = re.compile(r"^`[^`]+`$")
REF_ONLY = re.compile(r"^\[R\d{3}(?:,\s*R\d{3})*\]$")
COUNT = re.compile(r"\{\{count:([\w-]+)\}\}")
STATUSES = {
    "fixed": "Fixed",
    "partial": "Partly fixed",
    "unfixed": "No fix yet",
    "os": "Follows the OS store",
}


class BuildError(Exception):
    """A source line the converter does not handle."""


class Page:
    """Per-page build state: the reference mode, the R-numbers met since the last h2 and the
    status of each item div."""

    def __init__(self, refs: str, anchors: bool = False):
        if refs not in REFS_MODES:
            raise BuildError(f"refs must be one of {REFS_MODES}, not {refs!r}")
        self.refs = refs
        self.anchors = anchors
        self.section_refs: list[str] = []
        self.statuses: list[str] = []
        self.slugs: dict[str, int] = {}

    def slug(self, text: str) -> str:
        """Return GitHub's anchor for a heading's text, with -1, -2 on repeats."""
        plain = LINK.sub(r"\1", text).replace("`", "").replace("**", "")
        base = re.sub(r"[^\w\- ]", "", plain.lower()).replace(" ", "-")
        n = self.slugs.get(base, 0)
        self.slugs[base] = n + 1
        return f"{base}-{n}" if n else base

    def fill_counts(self, text: str) -> str:
        """Replace each {{count:NAME}} with the number of item divs that have that status."""

        def count(m: re.Match[str]) -> str:
            name = m.group(1)
            if name == "all":
                return str(len(self.statuses))
            if name not in STATUSES:
                raise BuildError(f"unknown status {name!r} in {m.group(0)}")
            return str(self.statuses.count(name))

        return COUNT.sub(count, text)

    def take_refs(self) -> str:
        """Return the Sources line for the h2 section just closed, and reset the list."""
        refs, self.section_refs = self.section_refs, []
        if self.refs != "section" or not refs:
            return ""
        links = ", ".join(ref_link(r) for r in refs)
        return f'<p class="muted refs-line">Sources: {links}</p>'


def parse_attrs(spec: str) -> dict[str, str]:
    """Parse `.a .b #id key=val` into an attribute dict."""
    attrs: dict[str, str] = {}
    classes = []
    for token in spec.split():
        if token.startswith("."):
            classes.append(token[1:])
        elif token.startswith("#"):
            attrs["id"] = token[1:]
        elif "=" in token:
            key, value = token.split("=", 1)
            attrs[key] = value.strip('"')
        else:
            raise BuildError(f"bad attribute {token!r}")
    if classes:
        attrs = {"class": " ".join(classes), **attrs}
    return attrs


def render_attrs(attrs: dict[str, str]) -> str:
    return "".join(
        f' {k}="{html.escape(v)}"' for k, v in attrs.items() if k != "tag" and v
    )


def split_trailing_attrs(text: str) -> tuple[str, dict[str, str]]:
    match = TRAILING_ATTRS.search(text)
    if not match:
        return text, {}
    return text[: match.start()], parse_attrs(match.group(1))


def ref_link(ref: str) -> str:
    return f'<a href="{REFS_PAGE}#{ref.lower()}">{ref}</a>'


def inline(text: str, page: Page) -> str:
    """Convert inline Markdown: code spans, R-number tags, links and bold."""
    codes: list[str] = []

    def stash(m: re.Match[str]) -> str:
        codes.append(f"<code>{html.escape(m.group(1)[1:-1], quote=False)}</code>")
        return f"\x00{len(codes) - 1}\x00"

    def ref_tag(m: re.Match[str]) -> str:
        refs = REF_ID.findall(m.group(1))
        if page.refs == "section":
            page.section_refs += [r for r in refs if r not in page.section_refs]
        if page.refs != "inline":
            return ""
        return (
            '&nbsp;<span class="rl">['
            + ", ".join(ref_link(r) for r in refs)
            + "]</span>"
        )

    text = CODE_SPAN.sub(stash, text)
    text = BARE_AMP.sub("&amp;", text)
    text = REF_TAG.sub(ref_tag, text)
    text = LINK.sub(lambda m: f'<a href="{m.group(2)}">{m.group(1)}</a>', text)
    text = BOLD.sub(r"<strong>\1</strong>", text)
    return re.sub("\x00(\\d+)\x00", lambda m: codes[int(m.group(1))], text)


def split_row(line: str) -> list[str]:
    """Split a pipe-table row on "|" outside code spans. "\\|" is a literal pipe."""
    body = line.strip()
    body = body[1:] if body.startswith("|") else body
    body = body[:-1] if body.endswith("|") and not body.endswith("\\|") else body
    cells, cell, in_code, i = [], [], False, 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and body[i + 1 : i + 2] == "|":
            cell.append("|")
            i += 2
            continue
        if ch == "`":
            in_code = not in_code
        if ch == "|" and not in_code:
            cells.append("".join(cell).strip())
            cell = []
        else:
            cell.append(ch)
        i += 1
    cells.append("".join(cell).strip())
    return cells


def bullet_items(text: str) -> list[str]:
    return [i.strip() for i in text.split("•") if i.strip()]


def render_cell(text: str, col_class: str, page: Page) -> str:
    if col_class == "rf":
        return "".join(ref_link(r) for r in REF_ID.findall(text))
    if col_class == "check":
        out = []
        for item in bullet_items(text):
            if ONE_CODE_SPAN.match(item):
                command = html.escape(item[1:-1], quote=False)
                out.append(
                    f'<div class="cmd"><code>{command}</code>{COPY_BUTTON}</div>'
                )
            else:
                out.append(f'<span class="muted">{inline(item, page)}</span>')
        return "".join(out)
    if text.startswith("•"):
        return (
            "<ul>"
            + "".join(f"<li>{inline(i, page)}</li>" for i in bullet_items(text))
            + "</ul>"
        )
    return inline(text, page)


def render_table(lines: list[str], attrs: dict[str, str], page: Page) -> str:
    header = [split_trailing_attrs(c) for c in split_row(lines[0])]
    if not re.fullmatch(r"[\s|:-]+", lines[1]):
        raise BuildError(f"table without a separator row: {lines[0]!r}")
    cols = [a.get("class", "rf" if name == "Refs" else "") for name, a in header]
    keep = [not (page.refs == "none" and c == "rf") for c in cols]
    header = [h for h, k in zip(header, keep) if k]
    out = [f'<div class="table-scroll"><table{render_attrs(attrs)}><thead><tr>']
    out += [f"<th>{inline(name, page)}</th>" for name, _ in header]
    out.append("</tr></thead><tbody>\n")
    for line in lines[2:]:
        cells = split_row(line)
        if len(cells) == 1:
            out.append(
                f'<tr class="grp"><th colspan="{len(header)}">{inline(cells[0], page)}</th></tr>\n'
            )
            continue
        if len(cells) != len(cols):
            raise BuildError(
                f"row has {len(cells)} cells, header has {len(cols)}: {line!r}"
            )
        tds = [
            f"<td{render_attrs({'class': c})}>{render_cell(t, c, page)}</td>"
            for t, c, k in zip(cells, cols, keep)
            if k
        ]
        out.append("<tr>" + "".join(tds) + "</tr>\n")
    out.append("</tbody></table></div>")
    return "".join(out)


def indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def dedent(lines: list[str], width: int) -> list[str]:
    return [line[width:] if line[:width].isspace() else line.lstrip() for line in lines]


class Converter:
    """Converts a list of Markdown lines into HTML blocks."""

    def __init__(self, lines: list[str], page: Page):
        self.lines = lines
        self.page = page
        self.i = 0

    def peek(self, offset: int = 0) -> str | None:
        j = self.i + offset
        return self.lines[j] if j < len(self.lines) else None

    def starts_block(self, line: str) -> bool:
        return bool(
            not line.strip()
            or HEADING.match(line)
            or LIST_ITEM.match(line)
            or FENCE.match(line)
            or DIV_OPEN.match(line)
            or DIV_CLOSE.match(line)
            or ATTRS.match(line.strip())
            or line.strip() == "---"
            or line.startswith(("|", "<"))
        )

    def convert(self) -> str:
        out: list[str] = []
        sections: list[int] = []
        attrs: dict[str, str] = {}

        def close(level: int) -> None:
            while sections and sections[-1] >= level:
                if sections.pop() == 2 and (line := self.page.take_refs()):
                    out.append(line)
                out.append("</section>")

        while (line := self.peek()) is not None:
            stripped = line.strip()
            if not stripped:
                self.i += 1
                continue
            if m := ATTRS.match(stripped):
                attrs = parse_attrs(m.group(1))
                self.i += 1
                continue
            if stripped == "---":
                close(0)
                self.i += 1
                continue
            if m := HEADING.match(line):
                level = len(m.group(1))
                text, head_attrs = split_trailing_attrs(m.group(2))
                close(level)
                if self.page.anchors and not head_attrs and "id" not in attrs:
                    if level == 2:
                        head_attrs = {"id": self.page.slug(text)}
                    else:
                        attrs = {**attrs, "id": self.page.slug(text)}
                if head_attrs:
                    if level == 2:
                        self.page.section_refs = []
                    out.append(f"<section{render_attrs(head_attrs)}>")
                    sections.append(level)
                out.append(
                    f"<h{level}{render_attrs(attrs)}>{inline(text, self.page)}</h{level}>"
                )
                self.i += 1
            elif m := DIV_OPEN.match(line):
                spec = m.group(1)
                div_attrs = parse_attrs(
                    spec[1:-1] if spec.startswith("{") else "." + spec
                )
                tag = div_attrs.get("tag", "div")
                status = div_attrs.pop("status", None)
                self.i += 1
                body = Converter(self.take_until_close(), self.page).convert()
                if status is not None:
                    body = self.add_status(status, div_attrs, body)
                out.append(f"<{tag}{render_attrs(div_attrs)}>\n{body}\n</{tag}>")
            elif FENCE.match(line):
                self.i += 1
                code = []
                while (row := self.peek()) is not None and not FENCE.match(row.strip()):
                    code.append(row)
                    self.i += 1
                if row is None:
                    raise BuildError("unclosed code fence")
                self.i += 1
                body = html.escape("\n".join(code), quote=False)
                out.append(
                    f'<div class="code"><button type="button">Copy</button><pre>{body}</pre></div>'
                )
            elif line.startswith("<"):
                raw = []
                while (row := self.peek()) is not None and row.strip():
                    raw.append(row)
                    self.i += 1
                out.append("\n".join(raw))
            elif line.startswith("|"):
                rows = []
                while (row := self.peek()) is not None and row.startswith("|"):
                    rows.append(row)
                    self.i += 1
                out.append(render_table(rows, attrs, self.page))
            elif LIST_ITEM.match(line):
                out.append(self.take_list(attrs))
            elif (nxt := self.peek(1)) is not None and nxt.startswith(": "):
                out.append(self.take_dl(attrs))
            else:
                para: list[str] = []
                while (row := self.peek()) is not None and (
                    not para or not self.starts_block(row)
                ):
                    para.append(row.strip())
                    self.i += 1
                text = " ".join(para)
                if REF_ONLY.match(text):
                    if line := self.sources_line(text):
                        out.append(line)
                else:
                    out.append(
                        f"<p{render_attrs(attrs)}>{inline(text, self.page)}</p>"
                    )
            attrs = {}
        close(0)
        return "\n".join(out)

    def sources_line(self, text: str) -> str:
        """Render a paragraph that is only a reference tag as an in-place Sources line."""
        inline(text, self.page)
        if self.page.refs != "inline":
            return ""
        links = ", ".join(ref_link(r) for r in REF_ID.findall(text))
        return f'<p class="muted refs-line">Sources: {links}</p>'

    def add_status(self, status: str, div_attrs: dict[str, str], body: str) -> str:
        """Record an item div's status, mark the div and put its chip after the first heading."""
        if status not in STATUSES:
            raise BuildError(f"status must be one of {tuple(STATUSES)}, not {status!r}")
        self.page.statuses.append(status)
        div_attrs["data-status"] = status
        chip = f'<p class="status"><span class="chip {status}">{STATUSES[status]}</span></p>'
        heading = re.search(r"</h[1-6]>", body)
        if not heading:
            return f"{chip}\n{body}"
        return f"{body[: heading.end()]}\n{chip}{body[heading.end() :]}"

    def take_until_close(self) -> list[str]:
        depth = 0
        body: list[str] = []
        while (row := self.peek()) is not None:
            self.i += 1
            if DIV_OPEN.match(row):
                depth += 1
            elif DIV_CLOSE.match(row):
                if depth == 0:
                    return body
                depth -= 1
            body.append(row)
        raise BuildError("unclosed ::: container")

    def take_list(self, attrs: dict[str, str]) -> str:
        first = self.peek()
        assert first is not None
        base = indent_of(first)
        tag = "ol" if re.match(r"\s*\d+\.", first) else "ul"
        items: list[tuple[str, list[str]]] = []
        while (row := self.peek()) is not None:
            m = LIST_ITEM.match(row)
            if m and indent_of(row) == base:
                items.append((m.group(2), []))
            elif row.strip() and indent_of(row) > base and items:
                items[-1][1].append(row)
            elif (
                not row.strip()
                and (nxt := self.peek(1)) is not None
                and indent_of(nxt) > base
            ):
                items[-1][1].append(row)
            else:
                break
            self.i += 1
        out = [f"<{tag}{render_attrs(attrs)}>"]
        for text, sub in items:
            inner = Converter(dedent(sub, base + 2), self.page).convert() if sub else ""
            out.append(f"<li>{inline(text, self.page)}{inner}</li>")
        out.append(f"</{tag}>")
        return "\n".join(out)

    def take_dl(self, attrs: dict[str, str]) -> str:
        out = [f"<dl{render_attrs(attrs)}>"]
        while (
            (term := self.peek()) is not None
            and (nxt := self.peek(1)) is not None
            and nxt.startswith(": ")
        ):
            text, dt_attrs = split_trailing_attrs(term.strip())
            self.i += 2
            body = [nxt[2:]]
            while (row := self.peek()) is not None and (
                row.startswith("  ")
                or (not row.strip() and (self.peek(1) or "").startswith("  "))
            ):
                body.append(row)
                self.i += 1
            inner = Converter(dedent(body, 2), self.page).convert()
            if (
                inner.startswith("<p>")
                and inner.endswith("</p>")
                and inner.count("<p>") == 1
            ):
                inner = inner[3:-4]
            out.append(
                f"<dt{render_attrs(dt_attrs)}>{inline(text, self.page)}</dt><dd>{inner}</dd>"
            )
            while (row := self.peek()) is not None and not row.strip():
                self.i += 1
        out.append("</dl>")
        return "\n".join(out)


def front_matter(lines: list[str]) -> tuple[dict[str, str], list[str]]:
    if not lines or lines[0] != "---":
        return {}, lines
    end = lines.index("---", 1)
    meta = dict(line.split(": ", 1) for line in lines[1:end])
    return meta, lines[end + 1 :]


def build(source: Path, refs: str | None = None) -> str:
    meta, body = front_matter(source.read_text(encoding="utf-8").splitlines())
    page = Page(refs or meta.get("refs", "inline"), meta.get("anchors") == "auto")
    template = (SITE / "page.html").read_text(encoding="utf-8")
    html_body = page.fill_counts(Converter(body, page).convert())
    if page.refs == "none":
        html_body = RL_SPAN.sub("", html_body)
    for key, value in {
        "{{title}}": html.escape(meta["title"]),
        "{{description}}": html.escape(meta["description"]),
        "{{css}}": (SITE / "style.css").read_text(encoding="utf-8"),
        "{{script}}": (SITE / "page.js").read_text(encoding="utf-8"),
        "{{body}}": html_body,
    }.items():
        template = template.replace(key, value)
    return template


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--out", type=Path, default=REPO, help="directory or file to write"
    )
    parser.add_argument(
        "--refs", choices=REFS_MODES, help="override the page's refs mode"
    )
    parser.add_argument("pages", nargs="*", type=Path)
    args = parser.parse_args(argv)
    for source in args.pages or sorted(SITE.glob("*.md")):
        meta, _ = front_matter(source.read_text(encoding="utf-8").splitlines())
        target = args.out if args.out.suffix == ".html" else args.out / meta["output"]
        target.write_text(build(source, args.refs), encoding="utf-8")
        print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
