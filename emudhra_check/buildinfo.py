"""buildinfo.py: where a native binary or an app's Info.plist stores its toolchain and version.

classify sorts a program candidate into Go, Electron, Node, Rust or other by markers in its bytes.
go_build_info reads the Go build information block, rust_crate_versions the cargo registry paths
rustc embeds, node_release_version and electron_version_string the release strings Node and Electron
carry, and electron_app_version the CFBundleVersion of an Electron framework's Info.plist. Every
reader takes bytes, never runs anything, and returns None or an empty result on malformed input.
"""

from __future__ import annotations

import plistlib
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional, cast

from emudhra_check.certificates import Buffer
from emudhra_check.limits import (
    MAX_BINARY_MATCHES,
    MAX_FIELD_CHARS,
    MAX_GO_MODINFO_BYTES,
    MAX_GO_VERSION_BYTES,
    MAX_NUMBER_DIGITS,
)


class BinaryKind(Enum):
    GO = "go"
    ELECTRON = "electron"
    NODE = "node"
    RUST = "rust"
    OTHER = "other"


EXECUTABLE_MAGICS = (
    bytes.fromhex("7f454c46"),
    bytes.fromhex("feedface"),
    bytes.fromhex("feedfacf"),
    bytes.fromhex("cefaedfe"),
    bytes.fromhex("cffaedfe"),
    bytes.fromhex("cafebabe"),
)
GO_MAGIC = b"\xff Go buildinf:"
GO_HEADER_BYTES = 32
GO_INLINE_STRINGS = 0x2
GO_POINTER_SIZES = (4, 8)
GO_SENTINEL_BYTES = 16
VARINT_MAX_BYTES = 10
NUMBER = rb"[0-9]{1,10}"
DOTTED = NUMBER + rb"\." + NUMBER + rb"\." + NUMBER
ELECTRON_VERSION = re.compile(rb"Electron/(" + DOTTED + rb")")
NODE_RELEASE = re.compile(
    rb"nodejs\.org/download/release/v(" + DOTTED + rb")/node-v(" + DOTTED + rb")"
)
RUST_CRATE = re.compile(
    rb"/(rustls-webpki|webpki-roots|webpki-root-certs)-("
    + DOTTED
    + rb"(?:-alpha\."
    + NUMBER
    + rb")?)/"
)
LONG_DIGITS = re.compile(rb"[0-9]{%d}" % (MAX_NUMBER_DIGITS + 1))
BINARY_PLIST = b"bplist00"


@dataclass(frozen=True)
class GoModule:
    path: str
    version: str


@dataclass(frozen=True)
class GoBuildInfo:
    """The toolchain version and dependency modules of a Go binary, or legacy for one before Go 1.18."""

    go_version: str
    modules: tuple[GoModule, ...]
    legacy: bool


def as_bytes(data: Buffer) -> bytes:
    """Return data typed for re, which reads bytes and mmap objects alike."""
    return cast(bytes, data)


def is_executable(data: Buffer) -> bool:
    """Return whether data starts with an ELF or Mach-O magic."""
    return bytes(data[:4]) in EXECUTABLE_MAGICS


def classify(data: Buffer) -> BinaryKind:
    """Return the kind of native binary data holds: the first of Go, Electron, Node and Rust that matches."""
    if not is_executable(data):
        return BinaryKind.OTHER
    if data.find(GO_MAGIC) >= 0:
        return BinaryKind.GO
    if electron_version_string(data) is not None:
        return BinaryKind.ELECTRON
    if node_release_version(data) is not None:
        return BinaryKind.NODE
    if rust_crate_versions(data):
        return BinaryKind.RUST
    return BinaryKind.OTHER


def uvarint(data: Buffer, start: int) -> Optional[tuple[int, int]]:
    """Read an unsigned varint of at most ten bytes at start, returning its value and the next index."""
    value = 0
    for offset in range(VARINT_MAX_BYTES):
        index = start + offset
        if index >= len(data):
            return None
        byte = data[index : index + 1][0]
        value |= (byte & 0x7F) << (7 * offset)
        if byte < 0x80:
            return value, index + 1
    return None


def length_prefixed(data: Buffer, start: int, cap: int) -> Optional[tuple[bytes, int]]:
    """Read a varint-length string of at most cap bytes that fits inside data."""
    header = uvarint(data, start)
    if header is None:
        return None
    length, begin = header
    if length > cap or length > len(data) - begin:
        return None
    return bytes(data[begin : begin + length]), begin + length


def go_version_text(raw: bytes) -> Optional[str]:
    """Return the go1.N.N toolchain word of a build info version string, or None."""
    text = raw.decode("ascii", errors="replace")
    words = text.split()
    if words and words[0] == "devel" and len(words) > 1:
        words = words[1:]
    if not words or not words[0].startswith("go") or not words[0].isprintable():
        return None
    return words[0]


def go_modules(raw: bytes) -> tuple[GoModule, ...]:
    """Return the dependency modules of a build info module block, with each replacement applied."""
    if len(raw) >= 2 * GO_SENTINEL_BYTES + 1 and raw[-GO_SENTINEL_BYTES - 1] == 0x0A:
        raw = raw[GO_SENTINEL_BYTES:-GO_SENTINEL_BYTES]
    modules: list[GoModule] = []
    for line in raw.decode("utf-8", errors="replace").split("\n"):
        fields = line.split("\t")
        if len(fields) < 3:
            continue
        if fields[0] == "dep":
            modules.append(GoModule(fields[1], fields[2]))
        elif fields[0] == "=>" and modules:
            modules[-1] = GoModule(fields[1], fields[2])
    return tuple(modules)


def go_build_info_at(data: Buffer, start: int) -> Optional[GoBuildInfo]:
    """Read the build information block whose magic is at start, or None when it does not parse."""
    if len(data) - start < GO_HEADER_BYTES:
        return None
    pointer_size, flags = bytes(data[start + 14 : start + 16])
    if pointer_size not in GO_POINTER_SIZES:
        return None
    if not flags & GO_INLINE_STRINGS:
        return GoBuildInfo("", (), True)
    version = length_prefixed(data, start + GO_HEADER_BYTES, MAX_GO_VERSION_BYTES)
    if version is None:
        return None
    text = go_version_text(version[0])
    modinfo = length_prefixed(data, version[1], MAX_GO_MODINFO_BYTES)
    if text is None or modinfo is None:
        return None
    return GoBuildInfo(text, go_modules(modinfo[0]), False)


def go_build_info(data: Buffer) -> Optional[GoBuildInfo]:
    """Return the first Go 1.18+ build information that parses, else a legacy one, else None."""
    legacy = None
    start = data.find(GO_MAGIC)
    for _ in range(MAX_BINARY_MATCHES):
        if start < 0:
            break
        info = go_build_info_at(data, start)
        if info is not None and not info.legacy:
            return info
        legacy = legacy or info
        start = data.find(GO_MAGIC, start + 1)
    return legacy


def rust_crate_versions(data: Buffer) -> dict[str, frozenset[str]]:
    """Return the rustls-webpki, webpki-roots and webpki-root-certs versions in a binary's source paths."""
    found: dict[str, set[str]] = {}
    count = 0
    for match in RUST_CRATE.finditer(as_bytes(data)):
        versions = found.setdefault(match.group(1).decode(), set())
        if match.group(2).decode() not in versions:
            versions.add(match.group(2).decode())
            count += 1
            if count >= MAX_BINARY_MATCHES:
                break
    return {crate: frozenset(versions) for crate, versions in found.items()}


def node_release_version(data: Buffer) -> Optional[str]:
    """Return the Node release a binary names in its own download URL, the version given twice."""
    for count, match in enumerate(NODE_RELEASE.finditer(as_bytes(data))):
        if match.group(1) == match.group(2):
            return match.group(1).decode()
        if count >= MAX_BINARY_MATCHES:
            break
    return None


def electron_version_string(data: Buffer) -> Optional[str]:
    """Return the version an Electron binary carries in its Electron/N.N.N user agent part."""
    match = ELECTRON_VERSION.search(as_bytes(data))
    return match.group(1).decode() if match else None


def electron_app_version(plist: bytes) -> Optional[str]:
    """Return CFBundleVersion of an Info.plist when it is a string, or None for anything unreadable."""
    if not plist.startswith(BINARY_PLIST) and LONG_DIGITS.search(plist):
        return None
    try:
        value = plistlib.loads(plist)
    except Exception:
        # plistlib raises many exception types on malformed input, and a plist here is untrusted.
        return None
    version = value.get("CFBundleVersion") if isinstance(value, dict) else None
    if not isinstance(version, str) or not 0 < len(version) <= MAX_FIELD_CHARS:
        return None
    return version
