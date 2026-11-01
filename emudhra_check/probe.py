"""probe.py: the wire format between the in-image probe and the host.

render fills the probe template with the certificate lines it greps for and the limits it obeys.
parse_probe_output turns the probe's output into a ProbeReport: runtimes, Python packages, the OS
id, ca-certificates packages and the files it dumped. Every field is bounded and every record is
checked, so a hostile image can drop its own records but cannot forge or enlarge others.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Optional

from emudhra_check.certificates import G3_ECC_ROOT, ISRG_ROOT_X1_LINE
from emudhra_check.limits import (
    MAX_FIELD_CHARS,
    MAX_PROBE_FILE,
    MAX_PROBE_FILES,
    MAX_PROBE_RECORDS,
    MAX_VERSION_COMPONENT_DIGITS,
)

BASE64_LINE = re.compile(r"[A-Za-z0-9+/=]{1,128}")
HEX_LINE = re.compile(
    rb"[ \t]{0,16}[0-9a-f]{2}(?:[ \t]{1,8}[0-9a-f]{2}){0,63}[ \t]{0,16}"
)
SIZE_DIGITS = MAX_VERSION_COMPONENT_DIGITS
KINDS = frozenset(
    {b"NODE", b"RT", b"PY", b"NOPY", b"OS", b"PKG", b"CHG", b"NOOD", b"FILE", b"BIG"}
)


def render(template: str) -> str:
    """Return the probe script with its certificate lines and limits filled in."""
    lines = {
        "@G3_LINE@": G3_ECC_ROOT.pem_line.decode("ascii"),
        "@ISRG_LINE@": ISRG_ROOT_X1_LINE.decode("ascii"),
    }
    for value in lines.values():
        if not BASE64_LINE.fullmatch(value):
            raise ValueError("a probe certificate line is not plain base64")
    values = {
        **lines,
        "@MAX_PROBE_FILE@": str(MAX_PROBE_FILE),
        "@MAX_PROBE_FILES@": str(MAX_PROBE_FILES),
    }
    for key, value in values.items():
        template = template.replace(key, value)
    return template


@dataclass(frozen=True)
class ProbeNode:
    bundles_g3: bool
    bundles_store: bool
    version_line: str


@dataclass(frozen=True)
class ProbeRuntime:
    tool: str
    version_line: str


@dataclass(frozen=True)
class ProbePython:
    """A PY record. bundled is 1 when the package's own cacert.pem exists, 0 when not, - for uv."""

    name: str
    version: str
    installer: str
    bundled: str
    location: str


@dataclass(frozen=True)
class ProbePackage:
    manager: str
    name: str
    version: str


@dataclass(frozen=True)
class ProbeFile:
    path: str
    data: bytes


@dataclass(frozen=True)
class ProbeBig:
    size: str
    path: str


@dataclass(frozen=True)
class ProbeReport:
    nodes: tuple[ProbeNode, ...] = ()
    runtimes: tuple[ProbeRuntime, ...] = ()
    pythons: tuple[ProbePython, ...] = ()
    old_pythons: tuple[str, ...] = ()
    os_id: str = ""
    packages: tuple[ProbePackage, ...] = ()
    changelog_hits: int = 0
    files: tuple[ProbeFile, ...] = ()
    big: tuple[ProbeBig, ...] = ()
    no_od: bool = False
    dropped: int = 0


def text(raw: bytes) -> str:
    """Decode one probe field, cut to MAX_FIELD_CHARS."""
    return raw.decode("utf-8", errors="replace")[:MAX_FIELD_CHARS]


def words(line: bytes, count: int) -> Optional[list[str]]:
    """Split a record line after its kind into count fields, the last taking the rest, or None."""
    parts = line.split(b" ", count)
    if len(parts) != count + 1 or not parts[-1]:
        return None
    return [text(p) for p in parts[1:]]


def size_of(raw: str) -> Optional[int]:
    if not raw.isdigit() or not raw.isascii() or len(raw) > SIZE_DIGITS:
        return None
    return int(raw)


@dataclass
class Collector:
    """The records read so far, each kind capped at MAX_PROBE_RECORDS."""

    kept: dict[bytes, list[object]] = field(default_factory=dict)
    dropped: int = 0

    def add(self, kind: bytes, record: object) -> None:
        records = self.kept.setdefault(kind, [])
        if len(records) < MAX_PROBE_RECORDS:
            records.append(record)
        else:
            self.dropped += 1

    def of(self, kind: bytes) -> list[object]:
        return self.kept.get(kind, [])


def read_file(lines: list[bytes], start: int, size: int) -> tuple[Optional[bytes], int]:
    """Read the hex lines after a FILE record up to END: the bytes when they match size, and the next line."""
    chunks: list[bytes] = []
    total = 0
    index = start
    while index < len(lines):
        line = lines[index]
        if line == b"END":
            data = b"".join(chunks)
            return (data if len(data) == size else None), index + 1
        if not HEX_LINE.fullmatch(line):
            return None, index
        chunk = bytes.fromhex(line.decode("ascii"))
        total += len(chunk)
        if total > size:
            return None, skip_to_end(lines, index)
        chunks.append(chunk)
        index += 1
    return None, index


def skip_to_end(lines: list[bytes], index: int) -> int:
    """Return the index after the next END, or the end of the stream, skipping hex lines only."""
    while index < len(lines) and HEX_LINE.fullmatch(lines[index]):
        index += 1
    if index < len(lines) and lines[index] == b"END":
        return index + 1
    return index


def parse_probe_output(data: bytes) -> ProbeReport:
    """Read the probe's records, dropping and counting every one that is malformed or over its cap."""
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    found = Collector()
    hashes: set[bytes] = set()
    os_id = ""
    changelog = 0
    no_od = False
    index = 0
    while index < len(lines):
        line = lines[index]
        index += 1
        kind = line.split(b" ", 1)[0]
        if kind not in KINDS:
            continue
        if kind == b"FILE":
            fields = words(line, 2)
            size = size_of(fields[0]) if fields else None
            if fields is None or size is None or size > MAX_PROBE_FILE:
                found.dropped += 1
                index = skip_to_end(lines, index)
                continue
            content, index = read_file(lines, index, size)
            if content is None:
                found.dropped += 1
            elif hashlib.sha256(content).digest() not in hashes:
                hashes.add(hashlib.sha256(content).digest())
                found.add(kind, ProbeFile(fields[1], content))
            continue
        if kind == b"NOOD":
            no_od = True
            continue
        record = parse_record(kind, line)
        if record is None:
            found.dropped += 1
        elif kind == b"OS":
            os_id = os_id or str(record)
        elif kind == b"CHG":
            changelog = max(changelog, int(str(record)))
        else:
            found.add(kind, record)
    return ProbeReport(
        nodes=tuple(r for r in found.of(b"NODE") if isinstance(r, ProbeNode)),
        runtimes=tuple(r for r in found.of(b"RT") if isinstance(r, ProbeRuntime)),
        pythons=tuple(r for r in found.of(b"PY") if isinstance(r, ProbePython)),
        old_pythons=tuple(r for r in found.of(b"NOPY") if isinstance(r, str)),
        os_id=os_id,
        packages=tuple(r for r in found.of(b"PKG") if isinstance(r, ProbePackage)),
        changelog_hits=changelog,
        files=tuple(r for r in found.of(b"FILE") if isinstance(r, ProbeFile)),
        big=tuple(r for r in found.of(b"BIG") if isinstance(r, ProbeBig)),
        no_od=no_od,
        dropped=found.dropped,
    )


def parse_record(kind: bytes, line: bytes) -> Optional[object]:
    """Return the value of one line record other than FILE and NOOD, or None when it is malformed."""
    if kind == b"NODE":
        fields = words(line, 3)
        if fields is None or fields[0] not in ("0", "1") or fields[1] not in ("0", "1"):
            return None
        return ProbeNode(fields[0] == "1", fields[1] == "1", fields[2])
    if kind == b"RT":
        fields = words(line, 2)
        return ProbeRuntime(fields[0], fields[1]) if fields else None
    if kind == b"PY":
        fields = words(line, 5)
        if fields is None or fields[3] not in ("0", "1", "-"):
            return None
        return ProbePython(*fields)
    if kind == b"OS":
        return text(line[3:].strip())
    if kind == b"NOPY":
        fields = words(line, 1)
        return fields[0] if fields else None
    if kind == b"PKG":
        fields = words(line, 3)
        return ProbePackage(*fields) if fields else None
    if kind == b"CHG":
        fields = words(line, 2)
        count = size_of(fields[1]) if fields and fields[0] == "rpm" else None
        return str(count) if count is not None else None
    if kind == b"BIG":
        fields = words(line, 2)
        return ProbeBig(fields[0], fields[1]) if fields and size_of(fields[0]) else None
    return None
