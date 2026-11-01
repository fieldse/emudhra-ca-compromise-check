"""shared.py: the read and tool helpers every detection module uses.

Turns a skipped read into its line, reads a file or explains why not, gives the content verdict of a
file, finds a tool on PATH and refuses one inside an excluded directory, and runs a tool with the
timeout line. Holds no verdict rule of its own.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Sequence, Union

from emudhra_check.certificates import Buffer, Matcher, bundle_findings
from emudhra_check.detections.ports import (
    EXCLUDED,
    MISSING,
    TOO_LARGE,
    CommandResult,
    Context,
    Located,
    Skipped,
)
from emudhra_check.limits import COMMAND_TIMEOUT, MAX_BUNDLE_BYTES
from emudhra_check.report import Finding, Level, Subject
from emudhra_check.scope import FileId

__all__ = [
    "MATCHER",
    "content_findings",
    "find_tool",
    "read_or_skip",
    "release",
    "run_tool",
    "skipped_findings",
    "tool_output",
]

MATCHER = Matcher()


def skipped_findings(subject: Subject, skipped: Skipped) -> list[Finding]:
    """Return the line for a read that gave no bytes: none for a missing or excluded path."""
    if skipped.reason in (MISSING, EXCLUDED):
        return []
    if skipped.reason == TOO_LARGE:
        return [Finding(Level.INFO, subject, "too large to scan, skipped")]
    return [Finding(Level.INFO, subject, f"{skipped.reason}, skipped")]


def release(data: Buffer) -> None:
    """Close a mapped file. Bytes need nothing."""
    close = getattr(data, "close", None)
    if close is not None:
        close()


def read_or_skip(
    ctx: Context,
    subject: Subject,
    path: Path,
    cap: int,
    expect: Optional[FileId] = None,
) -> Union[Buffer, list[Finding]]:
    """Read a file through the Files port, or return the lines that explain why it was not read."""
    data = ctx.files.read_bytes(path, cap, expect)
    if isinstance(data, Skipped):
        return skipped_findings(subject, data)
    return data


def content_findings(
    ctx: Context,
    subject: Subject,
    path: Path,
    expect: Optional[FileId] = None,
    cap: int = MAX_BUNDLE_BYTES,
) -> list[Finding]:
    """Return the content verdict of one file: one line per match, then PASS when none is a FAIL."""
    data = read_or_skip(ctx, subject, path, cap, expect)
    if isinstance(data, list):
        return data
    try:
        return bundle_findings(subject, MATCHER.scan(data))
    finally:
        release(data)


def find_tool(ctx: Context, name: str) -> Union[Located, list[Finding]]:
    """Return the tool on the filtered PATH, or the lines for a tool that is absent or excluded."""
    tool = ctx.commands.which(name)
    if tool is None:
        return []
    if not tool.permitted:
        return [
            Finding(
                Level.INFO,
                Subject(name, "host"),
                "found on PATH inside an excluded directory, not run",
            )
        ]
    return tool


def run_tool(
    ctx: Context, tool: Located, name: str, args: Sequence[str]
) -> Union[CommandResult, list[Finding]]:
    """Run a permitted tool, or return the WARN line when it timed out."""
    result = ctx.commands.run(tool, args)
    if result.timed_out:
        return [
            Finding(
                Level.WARN,
                Subject(name, "host"),
                f"timed out after {COMMAND_TIMEOUT} s, skipped",
            )
        ]
    return result


def tool_output(
    ctx: Context, name: str, args: Sequence[str]
) -> tuple[list[Finding], Optional[CommandResult]]:
    """Find and run a tool: the lines for one absent, excluded or timed out, and its result when it ran."""
    tool = find_tool(ctx, name)
    if isinstance(tool, list):
        return tool, None
    result = run_tool(ctx, tool, name, args)
    if isinstance(result, list):
        return result, None
    return [], result
