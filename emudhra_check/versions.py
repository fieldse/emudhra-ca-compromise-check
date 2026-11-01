"""versions.py: version parsing, ordering and the fixed-version verdicts.

Parses dotted versions with pre-releases, judges a found version against a FixRule, and orders
dpkg, rpm and apk package versions and Homebrew and Go pseudo-version strings. No function calls
int() on an unbounded digit string: long components are refused and package digit runs are compared
by length.
"""

from __future__ import annotations

import datetime
import functools
from dataclasses import dataclass
from typing import Optional

from emudhra_check.limits import MAX_FIELD_CHARS, MAX_VERSION_COMPONENT_DIGITS
from emudhra_check.report import Finding, Level, Subject

ASCII_DIGITS = frozenset("0123456789")
ASCII_LETTERS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
BUILD_CHARS = ASCII_DIGITS | ASCII_LETTERS | frozenset(".-")
PRE_RELEASE_PHASES = {"alpha": 0, "beta": 1, "rc": 2}
RELEASE_PHASE = 3


def is_number(text: str, limit: int = MAX_VERSION_COMPONENT_DIGITS) -> bool:
    """Return whether text is 1 to limit ASCII digits."""
    return 0 < len(text) <= limit and all(c in ASCII_DIGITS for c in text)


@functools.total_ordering
@dataclass(frozen=True, eq=False)
class Version:
    """A dotted numeric version, optionally with -alpha.N, -beta.N or -rc.N and +build."""

    text: str
    release: tuple[int, ...]
    pre: Optional[tuple[int, int]] = None

    def key(self) -> tuple[tuple[int, ...], tuple[int, int]]:
        release = list(self.release)
        while len(release) > 1 and release[-1] == 0:
            release.pop()
        return tuple(release), self.pre if self.pre is not None else (RELEASE_PHASE, 0)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Version) and self.key() == other.key()

    def __lt__(self, other: Version) -> bool:
        return self.key() < other.key()

    def __hash__(self) -> int:
        return hash(self.key())


def parse_version(text: str) -> Optional[Version]:
    """Parse a dotted version, or return None for anything else."""
    if len(text) > MAX_FIELD_CHARS:
        return None
    core, plus, build = text.partition("+")
    if plus and not (build and all(c in BUILD_CHARS for c in build)):
        return None
    release_text, dash, pre_text = core.partition("-")
    parts = release_text.split(".")
    if not all(is_number(p) for p in parts):
        return None
    pre = None
    if dash:
        phase, dot, number = pre_text.partition(".")
        if phase not in PRE_RELEASE_PHASES or not dot or not is_number(number):
            return None
        pre = (PRE_RELEASE_PHASES[phase], int(number))
    return Version(text, tuple(int(p) for p in parts), pre)


@dataclass(frozen=True)
class FixRule:
    """Fixed versions by branch: the branch key is the first depth components of the version."""

    fixes: tuple[tuple[str, str], ...]
    depth: int
    below: Level
    no_fix: Level
    note: str = ""

    @classmethod
    def single(cls, version: str, below: Level, note: str = "") -> FixRule:
        """Return a rule with one fixed version and no branches."""
        return cls((("", version),), 0, below, below, note)

    @property
    def fixed(self) -> str:
        """Return the fixed version of a single-version rule."""
        return self.fixes[0][1]


def with_note(detail: str, note: str) -> str:
    return f"{detail} ({note})" if note else detail


def judge_against(
    subject: Subject, found: str, fixed: str, below: Level, note: str
) -> Finding:
    """Judge found against one fixed version."""
    have = parse_version(found)
    want = parse_version(fixed)
    if have is None or want is None:
        return Finding(
            Level.WARN,
            subject,
            f"found {found}, fixed {fixed}: not comparable, check manually",
        )
    if have >= want:
        return Finding(Level.PASS, subject, f"found {found}, fixed {fixed}")
    return Finding(below, subject, with_note(f"found {found}, fixed {fixed}", note))


def judge(subject: Subject, found: str, rule: FixRule) -> Finding:
    """Judge found against a single-version rule: PASS, the rule's level, or WARN when not comparable."""
    return judge_against(subject, found, rule.fixed, rule.below, rule.note)


def judge_branched(subject: Subject, found: str, rule: FixRule) -> Finding:
    """Judge found against the fixed release of its own branch."""
    have = parse_version(found)
    if have is None:
        return Finding(
            Level.WARN,
            subject,
            f"found {found}: not a plain dotted version, check manually",
        )
    key = ".".join(found.partition("+")[0].partition("-")[0].split(".")[: rule.depth])
    for branch, fixed in rule.fixes:
        if branch == key:
            return judge_against(subject, found, fixed, rule.below, rule.note)
    highest = max(
        rule.fixes, key=lambda fix: parse_version(fix[1]) or Version("", (0,))
    )[1]
    highest_version = parse_version(highest)
    if highest_version is not None and have >= highest_version:
        return Finding(
            Level.PASS,
            subject,
            f"found {found}, newer than highest listed fix {highest}",
        )
    detail = f"found {found}, no fix for branch {key} (highest listed fix {highest})"
    return Finding(rule.no_fix, subject, with_note(detail, rule.note))


def sign(value: int) -> int:
    return (value > 0) - (value < 0)


def compare_digits(a: str, b: str) -> int:
    """Compare two ASCII digit runs as numbers without int()."""
    a = a.lstrip("0")
    b = b.lstrip("0")
    if len(a) != len(b):
        return sign(len(a) - len(b))
    return sign((a > b) - (a < b))


def take(text: str, start: int, chars: frozenset[str]) -> int:
    """Return the end of the run of chars in text that begins at start."""
    end = start
    while end < len(text) and text[end] in chars:
        end += 1
    return end


def dpkg_order(char: str) -> int:
    if char in ASCII_LETTERS:
        return ord(char)
    if char == "~":
        return -1
    return ord(char) + 256


def dpkg_verrevcmp(a: str, b: str) -> int:
    """Compare two dpkg upstream versions or revisions."""
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and a[i] not in ASCII_DIGITS) or (
            j < len(b) and b[j] not in ASCII_DIGITS
        ):
            ac = dpkg_order(a[i]) if i < len(a) and a[i] not in ASCII_DIGITS else 0
            bc = dpkg_order(b[j]) if j < len(b) and b[j] not in ASCII_DIGITS else 0
            if ac != bc:
                return sign(ac - bc)
            i += 1
            j += 1
        i_end = take(a, i, ASCII_DIGITS)
        j_end = take(b, j, ASCII_DIGITS)
        diff = compare_digits(a[i:i_end], b[j:j_end])
        if diff:
            return diff
        i, j = i_end, j_end
    return 0


def dpkg_split(version: str) -> tuple[str, str, str]:
    epoch, colon, rest = version.partition(":")
    if not colon:
        epoch, rest = "0", version
    upstream, dash, revision = rest.rpartition("-")
    if not dash:
        upstream, revision = rest, ""
    return epoch, upstream, revision


def dpkg_compare(a: str, b: str) -> int:
    """Order two Debian package versions as dpkg --compare-versions does: -1, 0 or 1."""
    a_epoch, a_upstream, a_revision = dpkg_split(a)
    b_epoch, b_upstream, b_revision = dpkg_split(b)
    return (
        compare_digits(a_epoch, b_epoch)
        or dpkg_verrevcmp(a_upstream, b_upstream)
        or dpkg_verrevcmp(a_revision, b_revision)
    )


RPM_SEGMENT = ASCII_DIGITS | ASCII_LETTERS


def rpm_compare(a: str, b: str) -> int:
    """Order two rpm version strings as rpmvercmp does: -1, 0 or 1."""
    if a == b:
        return 0
    i = j = 0
    while i < len(a) or j < len(b):
        while i < len(a) and a[i] not in RPM_SEGMENT and a[i] not in "~^":
            i += 1
        while j < len(b) and b[j] not in RPM_SEGMENT and b[j] not in "~^":
            j += 1
        ac = a[i] if i < len(a) else ""
        bc = b[j] if j < len(b) else ""
        if ac == "~" or bc == "~":
            if ac != "~":
                return 1
            if bc != "~":
                return -1
            i += 1
            j += 1
            continue
        if ac == "^" or bc == "^":
            if not ac:
                return -1
            if not bc:
                return 1
            if ac != "^":
                return 1
            if bc != "^":
                return -1
            i += 1
            j += 1
            continue
        if not (ac and bc):
            break
        chars = ASCII_DIGITS if ac in ASCII_DIGITS else ASCII_LETTERS
        i_end = take(a, i, chars)
        j_end = take(b, j, chars)
        if j_end == j:
            return 1 if chars is ASCII_DIGITS else -1
        one, two = a[i:i_end], b[j:j_end]
        diff = (
            compare_digits(one, two)
            if chars is ASCII_DIGITS
            else sign((one > two) - (one < two))
        )
        if diff:
            return diff
        i, j = i_end, j_end
    if i >= len(a) and j >= len(b):
        return 0
    return -1 if i >= len(a) else 1


APK_SUFFIXES = {
    "alpha": 0,
    "beta": 1,
    "pre": 2,
    "rc": 3,
    "cvs": 5,
    "svn": 6,
    "git": 7,
    "hg": 8,
    "p": 9,
}
APK_NO_SUFFIX = (4, "")
LOWER = frozenset("abcdefghijklmnopqrstuvwxyz")


@dataclass(frozen=True)
class ApkVersion:
    numbers: tuple[str, ...]
    letter: str
    suffixes: tuple[tuple[int, str], ...]
    revision: str


def parse_apk(text: str) -> Optional[ApkVersion]:
    """Parse an apk version: dotted numbers, a letter, _suffixes and -rN."""
    if len(text) > MAX_FIELD_CHARS:
        return None
    body, dash, revision = text.partition("-r")
    if dash and not is_number(revision, MAX_FIELD_CHARS):
        return None
    head, *suffix_texts = body.split("_")
    letter = ""
    if head and head[-1] in LOWER:
        head, letter = head[:-1], head[-1]
    numbers = tuple(head.split("."))
    if not all(is_number(n, MAX_FIELD_CHARS) for n in numbers):
        return None
    suffixes = []
    for suffix in suffix_texts:
        end = take(suffix, 0, LOWER)
        name, number = suffix[:end], suffix[end:]
        if name not in APK_SUFFIXES or (
            number and not is_number(number, MAX_FIELD_CHARS)
        ):
            return None
        suffixes.append((APK_SUFFIXES[name], number or "0"))
    return ApkVersion(numbers, letter, tuple(suffixes), revision or "0")


def apk_compare(a: str, b: str) -> Optional[int]:
    """Order two apk versions as apk version -t does: -1, 0, 1, or None when either does not parse."""
    one = parse_apk(a)
    two = parse_apk(b)
    if one is None or two is None:
        return None
    for index, (x, y) in enumerate(zip(one.numbers, two.numbers)):
        if index and (x.startswith("0") or y.startswith("0")):
            diff = sign((x > y) - (x < y))
        else:
            diff = compare_digits(x, y)
        if diff:
            return diff
    if len(one.numbers) != len(two.numbers):
        return sign(len(one.numbers) - len(two.numbers))
    if one.letter != two.letter:
        return sign((one.letter > two.letter) - (one.letter < two.letter))
    count = max(len(one.suffixes), len(two.suffixes))
    pad_one = one.suffixes + (APK_NO_SUFFIX,) * (count - len(one.suffixes))
    pad_two = two.suffixes + (APK_NO_SUFFIX,) * (count - len(two.suffixes))
    for (rank_one, num_one), (rank_two, num_two) in zip(pad_one, pad_two):
        if rank_one != rank_two:
            return sign(rank_one - rank_two)
        diff = compare_digits(num_one or "0", num_two or "0")
        if diff:
            return diff
    return compare_digits(one.revision, two.revision)


def brew_formula_version(text: str) -> Optional[tuple[datetime.date, int]]:
    """Parse a Homebrew ca-certificates Cellar name such as 2026-09-25_1 into its date and revision."""
    stamp, underscore, revision = text.partition("_")
    if underscore and not is_number(revision):
        return None
    year, month, day = (stamp.split("-") + ["", "", ""])[:3]
    if stamp.count("-") != 2 or not (
        is_number(year, 4) and is_number(month, 2) and is_number(day, 2)
    ):
        return None
    try:
        date = datetime.date(int(year), int(month), int(day))
    except ValueError:
        return None
    return date, int(revision) if underscore else 0


HEX = frozenset("0123456789abcdef")
PSEUDO_TIMESTAMP_DIGITS = 14
PSEUDO_HASH_CHARS = 12


def pseudo_version_time(text: str) -> Optional[str]:
    """Return the 14-digit timestamp of a Go pseudo-version, or None for a release tag."""
    if len(text) > MAX_FIELD_CHARS:
        return None
    rest, dash, revision = text.rpartition("-")
    if (
        not dash
        or len(revision) != PSEUDO_HASH_CHARS
        or not all(c in HEX for c in revision)
    ):
        return None
    if (
        len(rest) <= PSEUDO_TIMESTAMP_DIGITS
        or rest[-PSEUDO_TIMESTAMP_DIGITS - 1] not in "-."
    ):
        return None
    stamp = rest[-PSEUDO_TIMESTAMP_DIGITS:]
    return stamp if is_number(stamp, PSEUDO_TIMESTAMP_DIGITS) else None
