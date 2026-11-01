"""lockfiles.py: readers for the lock and manifest formats the package detections judge.

Holds a TOML-subset reader for Cargo.lock, poetry.lock and uv.lock (tables, arrays of tables, basic
strings, string arrays across lines, everything else skipped by bracket and quote balance), JSON
reading with bounded numbers, and readers for requirements files and Pipfile.lock. Every reader is
total: malformed input gives an empty or partial result, never an exception, in time linear in the
input.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Optional, Union

from emudhra_check.limits import MAX_NUMBER_DIGITS

TomlValue = Union[str, tuple[str, ...]]
SPECIAL = re.compile(r"[\"'\[\]{}#\n]")
UNSUPPORTED_STRINGS = ('"""', "'''")


@dataclass(frozen=True)
class TomlTable:
    """One table: its header (empty for the top level) and its string and string-array values."""

    header: str
    values: dict[str, TomlValue]


@dataclass(frozen=True)
class TomlResult:
    """The tables read, and whether the reader skipped a construct it could not balance."""

    tables: tuple[TomlTable, ...]
    complete: bool


@dataclass(frozen=True)
class LockPackage:
    version: str
    dependencies: tuple[str, ...]


class Unbalanced(Exception):
    """A string, array or inline table that does not close where the subset allows."""


def basic_string(text: str, start: int) -> tuple[str, int]:
    """Read the basic string whose opening quote is at start, on one line, and return it and the next index."""
    i = start + 1
    end_of_line = text.find("\n", i)
    if end_of_line < 0:
        end_of_line = len(text)
    while True:
        quote = text.find('"', i, end_of_line)
        if quote < 0:
            raise Unbalanced()
        backslashes = 0
        while text[quote - 1 - backslashes] == "\\":
            backslashes += 1
        if backslashes % 2 == 0:
            raw = text[start + 1 : quote]
            return raw.replace('\\"', '"').replace("\\\\", "\\"), quote + 1
        i = quote + 1


def literal_string(text: str, start: int) -> tuple[str, int]:
    """Read the literal string whose opening quote is at start, on one line."""
    end_of_line = text.find("\n", start + 1)
    end = text.find("'", start + 1, end_of_line if end_of_line >= 0 else len(text))
    if end < 0:
        raise Unbalanced()
    return text[start + 1 : end], end + 1


def string_at(text: str, start: int) -> tuple[str, int]:
    if text.startswith(UNSUPPORTED_STRINGS, start):
        raise Unbalanced()
    if text[start] == '"':
        return basic_string(text, start)
    return literal_string(text, start)


def balanced(text: str, start: int) -> tuple[tuple[str, ...], int]:
    """Skip the array or inline table opening at start, returning the strings directly inside an array."""
    stack = [text[start]]
    items: list[str] = []
    i = start + 1
    while stack:
        match = SPECIAL.search(text, i)
        if match is None:
            raise Unbalanced()
        char = match.group()
        i = match.start()
        if char in "\"'":
            value, i = string_at(text, i)
            if stack == ["["]:
                items.append(value)
            continue
        if char == "#":
            newline = text.find("\n", i)
            i = len(text) if newline < 0 else newline
            continue
        if char in "[{":
            stack.append(char)
        elif char in "]}":
            if (char == "]") != (stack.pop() == "["):
                raise Unbalanced()
        i += 1
    return tuple(items), i


def end_of_line(text: str, start: int) -> int:
    newline = text.find("\n", start)
    return len(text) if newline < 0 else newline + 1


def table_header(line: str) -> Optional[str]:
    """Return the name in a [table] or [[table]] header line, or None for any other line."""
    stripped = line.split("#", 1)[0].strip()
    if stripped.startswith("[[") and stripped.endswith("]]"):
        return stripped[2:-2].strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        return stripped[1:-1].strip()
    return None


def toml_documents(text: str) -> TomlResult:
    """Read the tables of a TOML document in the subset lock files use."""
    if text.startswith("﻿"):
        text = text[1:]
    tables = [TomlTable("", {})]
    complete = True
    i = 0
    while i < len(text):
        line_end = end_of_line(text, i)
        line = text[i:line_end].strip()
        if not line or line.startswith("#"):
            i = line_end
            continue
        if line.startswith("["):
            header = table_header(line)
            if header is None:
                complete = False
            else:
                tables.append(TomlTable(header, {}))
            i = line_end
            continue
        equals = text.find("=", i, line_end)
        if equals < 0:
            complete = False
            i = line_end
            continue
        key = text[i:equals].strip().strip("\"'")
        j = equals + 1
        while j < len(text) and text[j] in " \t":
            j += 1
        try:
            value, i = value_at(text, j, line_end)
        except Unbalanced:
            return TomlResult(tuple(tables), False)
        if value is not None:
            tables[-1].values[key] = value
        if text[i - 1 : i] != "\n":
            i = end_of_line(text, i)
    return TomlResult(tuple(tables), complete)


def value_at(text: str, start: int, line_end: int) -> tuple[Optional[TomlValue], int]:
    """Read the value at start: a string, the strings of an array, or nothing for anything else."""
    if start >= len(text):
        return None, start
    char = text[start]
    if char in "\"'":
        return string_at(text, start)
    if char == "[":
        return balanced(text, start)
    if char == "{":
        _, end = balanced(text, start)
        return None, end
    return None, line_end


def normalise(name: str) -> str:
    """Return a package name lower-cased with _ and . read as -."""
    return name.strip().lower().replace("_", "-").replace(".", "-")


def toml_package_versions(text: str, name: str) -> tuple[list[LockPackage], bool]:
    """Return every [[package]] entry named name, and whether the whole lock was read."""
    result = toml_documents(text)
    want = normalise(name)
    found = []
    for table in result.tables:
        if table.header != "package":
            continue
        package = table.values.get("name")
        version = table.values.get("version")
        if not isinstance(package, str) or not isinstance(version, str):
            continue
        if normalise(package) != want:
            continue
        dependencies = table.values.get("dependencies", ())
        found.append(
            LockPackage(
                version, dependencies if isinstance(dependencies, tuple) else ()
            )
        )
    return found, result.complete


def package_count(text: str) -> int:
    """Return how many [[package]] tables the reader got from a lock."""
    return sum(1 for t in toml_documents(text).tables if t.header == "package")


def bounded_number(literal: str) -> Optional[str]:
    return literal if len(literal) <= MAX_NUMBER_DIGITS else None


def bounded_int(literal: str) -> Optional[int]:
    return int(literal) if bounded_number(literal) is not None else None


def bounded_float(literal: str) -> Optional[float]:
    return float(literal) if bounded_number(literal) is not None else None


def bounded_json(text: str) -> Optional[Any]:
    """Parse JSON with numbers longer than MAX_NUMBER_DIGITS read as None, or return None when it does not parse."""
    try:
        return json.loads(text, parse_int=bounded_int, parse_float=bounded_float)
    except (ValueError, RecursionError):
        return None


def requirement_pins(text: str, name: str) -> list[str]:
    """Return the versions name is pinned to with == in a requirements file."""
    want = normalise(name)
    pins = []
    for line in text.splitlines():
        line = line.lstrip("﻿").split(" #", 1)[0].strip()
        if not line or line.startswith(("-", "#")):
            continue
        spec = line.split(";", 1)[0].strip()
        package, equals, rest = spec.partition("==")
        if not equals or "@" in package:
            continue
        if normalise(package.split("[", 1)[0]) != want:
            continue
        words = rest.lstrip("=").split()
        if words:
            pins.append(words[0])
    return pins


def pipfile_versions(text: str, name: str) -> Optional[list[str]]:
    """Return the == versions of name in a Pipfile.lock, or None when it is not readable JSON."""
    data = bounded_json(text)
    if not isinstance(data, dict):
        return None
    want = normalise(name)
    versions = []
    for section in ("default", "develop"):
        packages = data.get(section)
        if not isinstance(packages, dict):
            continue
        for package, entry in packages.items():
            if not isinstance(entry, dict) or normalise(str(package)) != want:
                continue
            version = entry.get("version")
            if isinstance(version, str) and version.startswith("=="):
                versions.append(version[2:].lstrip("="))
    return versions


def composer_versions(text: str, name: str) -> Optional[list[str]]:
    """Return the versions of name in a composer.lock, without a leading v, or None when it is not readable JSON."""
    data = bounded_json(text)
    if not isinstance(data, dict):
        return None
    versions = []
    for section in ("packages", "packages-dev"):
        packages = data.get(section)
        if not isinstance(packages, list):
            continue
        for package in packages:
            if not isinstance(package, dict) or package.get("name") != name:
                continue
            version = package.get("version")
            if isinstance(version, str):
                versions.append(version[1:] if version.startswith("v") else version)
    return versions


GEM_SPEC = re.compile(r" {2,8}([A-Za-z0-9_.-]{1,64}) \(([0-9][0-9A-Za-z.]{0,63})\)")


def gem_versions(text: str, name: str) -> list[str]:
    """Return the locked versions of a gem in a Gemfile.lock, read line by line."""
    versions = []
    for line in text.splitlines():
        match = GEM_SPEC.fullmatch(line)
        if match and match.group(1) == name:
            versions.append(match.group(2))
    return versions


MIX_ENTRY = re.compile(
    r'"(castore|certifi)": \{:hex, :(castore|certifi), "([0-9][0-9.]{0,63})"'
)


def mix_versions(text: str) -> list[tuple[str, str]]:
    """Return (package, version) for each castore and certifi entry in a mix.lock."""
    return [
        (match.group(1), match.group(3))
        for match in MIX_ENTRY.finditer(text)
        if match.group(1) == match.group(2)
    ]


NPM_VERSION = re.compile(
    r"v?([0-9]{1,10})(?:\.([0-9]{1,10}|[xX*]))?(?:\.([0-9]{1,10}|[xX*]))?(-[0-9A-Za-z.]{1,64})?"
)
NPM_EXACT = re.compile(
    r"=?\s{0,8}v?([0-9]{1,10}\.[0-9]{1,10}\.[0-9]{1,10}(?:-[0-9A-Za-z.]{1,64})?(?:\+[0-9A-Za-z.]{1,64})?)"
)
NPM_NOT_A_RANGE = (
    "workspace:",
    "file:",
    "link:",
    "git",
    "http:",
    "https:",
    "npm:",
    "github:",
    "portal:",
)


def npm_range_lower_bound(spec: str) -> Optional[tuple[str, bool]]:
    """Return the lowest version an npm range allows and whether the range stays inside one major.

    None for a spec that names no registry version (workspace:, file:, git URLs and the like).
    """
    spec = spec.strip()
    if spec.startswith(NPM_NOT_A_RANGE) or "/" in spec:
        return None
    if spec in ("", "*", "x", "X", "latest", "next") or spec.startswith("<"):
        return "", False
    unbounded = "||" in spec or " - " in spec or spec.startswith(">")
    first = spec.split("||", 1)[0].strip().lstrip("^~=>< ")
    match = NPM_VERSION.match(first)
    if match is None:
        return "", False
    major, minor, patch, pre = match.groups()
    parts = [major, minor or "0", patch or "0"]
    lower = ".".join("0" if p in ("x", "X", "*") else p for p in parts) + (pre or "")
    return lower, not unbounded


def npm_exact_version(spec: str) -> Optional[str]:
    """Return the one version an exact npm spec ("43.8.0", "=43.8.0", "v43.8.0") allows, else None."""
    match = NPM_EXACT.fullmatch(spec.strip())
    return match.group(1) if match else None
