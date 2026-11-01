"""test_cli.py: unit tests of emudhra_check/cli.py and the Ledger in detections/ports.py.

Covers argument parsing, the header and SUMMARY, the order of notes and findings, the per-detection
exception boundary, internal errors, the registry order, and build_context over real directories.
"""

from __future__ import annotations

import contextlib
import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import ClassVar, Iterator
from unittest import mock

from emudhra_check import cli
from emudhra_check.detections import REGISTRY
from emudhra_check.detections.ports import Context, Ledger
from emudhra_check.hostenv import HostEnvironment
from emudhra_check.report import Finding, Level, Subject
from emudhra_check.scope import FileId, FileInterests, Index, Root, ScanScope
from emudhra_check.versions import Version

ROOT = Root(Path("/scan"), FileId(1, 2), 1)
HOSTENV = HostEnvironment(
    "Linux", Path("/root"), (), None, None, None, None, Version("3.13.5", (3, 13, 5))
)
HEADER = "INFO  eMudhra CA compromise check; scan roots: /scan containers=0"


class FakeFiles:
    def __init__(self, refused: int = 0) -> None:
        self.refused = refused

    def refused_reads(self) -> int:
        return self.refused


def context(
    index: Index = Index(),
    refused: int = 0,
    notes: tuple[str, ...] = (),
    strict: bool = False,
) -> Context:
    return Context(
        ScanScope((ROOT,), frozenset()),
        HOSTENV,
        index,
        FakeFiles(refused),  # type: ignore[arg-type]
        None,  # type: ignore[arg-type]
        None,  # type: ignore[arg-type]
        None,
        Ledger(),
        notes,
        (),
        False,
        strict,
        False,
    )


class Raiser:
    name: ClassVar[str] = "raiser"
    interests: ClassVar[FileInterests] = FileInterests()

    def run(self, ctx: Context) -> Iterator[Finding]:
        yield Finding(Level.INFO, Subject("raiser", "x"), "before")
        raise RuntimeError("boom")


class Passer:
    name: ClassVar[str] = "passer"
    interests: ClassVar[FileInterests] = FileInterests()

    def run(self, ctx: Context) -> Iterator[Finding]:
        yield Finding(Level.PASS, Subject("passer", "y"), "fine")


def run(ctx: Context, registry: tuple = ()) -> tuple[int, list[str]]:
    out: list[str] = []
    code = cli.run(
        ctx, registry, "check", out.append, lambda line: out.append("stderr: " + line)
    )
    return code, out


def main(*argv: str) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        with mock.patch.object(cli.sys, "argv", ["/out/check.pyz", *argv]):
            code = cli.main(list(argv))
    return code, stdout.getvalue(), stderr.getvalue()


class ParseArgsTest(unittest.TestCase):
    def test_options(self) -> None:
        options = cli.parse_args(
            [
                "-r",
                "/a",
                "--root=/b",
                "-x",
                "/c",
                "--exclude=/d",
                "-i",
                "img",
                "-q",
                "-s",
            ]
        )
        self.assertEqual(options.roots, ("/a", "/b"))
        self.assertEqual(options.excludes, ("/c", "/d"))
        self.assertEqual(options.images, ("img",))
        self.assertTrue(options.containers and options.quiet and options.strict)
        self.assertTrue(cli.parse_args(["--containers"]).containers)

    def test_bad_options(self) -> None:
        rows = [
            (["-r"], "Option -r needs an argument"),
            (["-r", ""], "Option -r needs an argument"),
            (["--root"], "Option --root needs an argument"),
            (["--root="], "Option --root needs an argument"),
            (["-x"], "Option -x needs an argument"),
            (["--exclude="], "Option --exclude needs an argument"),
            (["-i"], "Option -i needs an argument"),
            (["--bogus"], "Unknown option: --bogus (try --help)"),
            (["-r=/a"], "Unknown option: -r=/a (try --help)"),
        ]
        for argv, message in rows:
            with self.subTest(argv=argv):
                with self.assertRaises(cli.UsageError) as caught:
                    cli.parse_args(argv)
                self.assertEqual(str(caught.exception), message)

    def test_main_help(self) -> None:
        code, out, err = main("-h")
        self.assertEqual(code, 0)
        self.assertTrue(
            out.startswith("Usage: check.pyz [-r|--root ROOT]... [-x|--exclude DIR]...")
        )
        self.assertIn("AAA Certificate Services is reported as WARN.", out)
        self.assertIn("1 any FAIL (or WARN or ERROR with --strict)", out)
        self.assertEqual(err, "")

    def test_main_bad_option(self) -> None:
        for argv, message in (
            (["--bogus"], "Unknown option: --bogus (try --help)"),
            (["-x"], "Option -x needs an argument"),
        ):
            with self.subTest(argv=argv):
                code, out, err = main(*argv)
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertTrue(err.startswith(message + "\nUsage: check.pyz "))

    def test_exclude_with_a_newline_gives_one_note_line(self) -> None:
        tmp = tempfile.mkdtemp(dir="/tmp")
        try:
            with mock.patch.object(cli, "REGISTRY", ()):
                code, out, err = main("-r", tmp, "-x", "a\nb")
        finally:
            os.rmdir(tmp)
        self.assertEqual(code, 0)
        self.assertEqual(
            err.splitlines(),
            ["check.pyz: note: exclude a?b not found, nothing to skip"],
        )


class RunTest(unittest.TestCase):
    def test_empty_registry(self) -> None:
        code, out = run(context())
        self.assertEqual(
            (code, out),
            (0, [HEADER, "SUMMARY pass=0 fail=0 warn=0 info=1 skip=0 error=0"]),
        )

    def test_notes_go_to_stderr_before_the_header(self) -> None:
        _, out = run(context(notes=("excluding /x (given as /x)",)))
        self.assertEqual(
            out[:2], ["stderr: check: note: excluding /x (given as /x)", HEADER]
        )

    def test_exception_boundary(self) -> None:
        code, out = run(context(), (Raiser(), Passer()))
        self.assertEqual(
            out,
            [
                HEADER,
                "INFO  raiser [x] before",
                "ERROR  detection [raiser] failed: RuntimeError: boom",
                "PASS  passer [y] fine",
                "SUMMARY pass=1 fail=0 warn=0 info=2 skip=0 error=1",
            ],
        )
        self.assertEqual(code, 0)
        self.assertEqual(run(context(strict=True), (Raiser(), Passer()))[0], 1)

    def test_walk_error_notice(self) -> None:
        notice = Finding(
            Level.ERROR,
            Subject("scan", "/scan"),
            "walk failed: RecursionError: maximum recursion depth",
        )
        code, out = run(context(Index(notices=(notice,))))
        self.assertIn(
            "ERROR  scan [/scan] walk failed: RecursionError: maximum recursion depth",
            out,
        )
        self.assertEqual(
            [line for line in out if line.startswith("SUMMARY")],
            ["SUMMARY pass=0 fail=0 warn=0 info=1 skip=0 error=1"],
        )
        self.assertEqual(code, 0)

    def test_refused_reads_note(self) -> None:
        _, out = run(context(refused=3))
        self.assertIn(
            "stderr: check: note: 3 host paths inside excluded directories were not read",
            out,
        )
        _, out = run(context(refused=0))
        self.assertFalse(any("were not read" in line for line in out))

    def test_quiet_hides_info_but_counts_it(self) -> None:
        ctx = context()
        quiet = Context(
            *[
                getattr(ctx, f)
                for f in (
                    "scope",
                    "hostenv",
                    "index",
                    "files",
                    "commands",
                    "host",
                    "images",
                    "ledger",
                )
            ],
            quiet=True,
        )
        self.assertEqual(
            run(quiet)[1], ["SUMMARY pass=0 fail=0 warn=0 info=1 skip=0 error=0"]
        )

    def test_main_internal_error(self) -> None:
        tmp = tempfile.mkdtemp(dir="/tmp")
        try:
            with mock.patch.object(cli, "run", side_effect=KeyError("bad")):
                code, out, err = main("-r", tmp)
        finally:
            os.rmdir(tmp)
        self.assertEqual(code, 2)
        self.assertEqual(err, "check.pyz: internal error: KeyError: 'bad'\n")

    def test_main_check_error(self) -> None:
        code, out, err = main("-r", "/nope")
        self.assertEqual(
            (code, out, err),
            (2, "", "check.pyz: scan root is not a directory: /nope\n"),
        )

    def test_registry_order(self) -> None:
        self.assertEqual(
            tuple(d.name for d in REGISTRY),
            (
                "os-trust-store",
                "pem-bundles",
            ),
        )


class LedgerTest(unittest.TestCase):
    def test_claims(self) -> None:
        ledger = Ledger()
        self.assertTrue(ledger.claim(FileId(1, 5)))
        self.assertFalse(ledger.claim(FileId(1, 5)))
        self.assertTrue(ledger.claim(FileId(2, 5)))

    def test_unstable_inode_is_never_recorded(self) -> None:
        ledger = Ledger()
        self.assertTrue(ledger.claim(FileId(1, 0)))
        self.assertTrue(ledger.claim(FileId(1, 0)))


class BuildContextTest(unittest.TestCase):
    """build_context over real directories, with a brew file beside a Cellar directory."""

    def setUp(self) -> None:
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(dir="/tmp")))
        for name in (
            "brew/bin",
            "brew/Cellar",
            "brew/etc",
            "brew/Caskroom",
            "home",
            "scan/inner",
            "tools/bin",
        ):
            (self.tmp / name).mkdir(parents=True)
        (self.tmp / "brew" / "bin" / "brew").write_text("#!/bin/sh\n")
        (self.tmp / "brew" / "bin" / "brew").chmod(0o755)

    def tearDown(self) -> None:
        subprocess.run(["rm", "-rf", str(self.tmp)], check=False)

    def build(self, *argv: str) -> Context:
        environ = {"PATH": f"{self.tmp}/brew/bin:{self.tmp}/tools/bin:/usr/bin"}
        return cli.build_context(
            cli.parse_args(argv), environ, "Darwin", self.tmp / "home", self.tmp
        )

    def roots(self, ctx: Context) -> list[Path]:
        return [r.path for r in ctx.scope.roots]

    def test_brew_prefix_and_its_roots_without_excludes(self) -> None:
        ctx = self.build("-r", "scan")
        self.assertEqual(ctx.hostenv.brew_prefix, self.tmp / "brew")
        self.assertEqual(
            self.roots(ctx),
            [
                self.tmp / "scan",
                self.tmp / "brew" / "etc",
                self.tmp / "brew" / "Caskroom",
            ],
        )

    def test_exclude_covering_the_brew_path_directory(self) -> None:
        ctx = self.build("-r", "scan", "-x", "brew/bin")
        self.assertIsNone(ctx.hostenv.brew_prefix)
        self.assertEqual(self.roots(ctx), [self.tmp / "scan"])

    def test_path_entry_inside_an_exclude(self) -> None:
        ctx = self.build("-r", "scan", "-x", "tools")
        self.assertNotIn(self.tmp / "tools" / "bin", ctx.hostenv.path_dirs)
        _, out = run(ctx)
        self.assertIn(
            f"stderr: check: note: PATH entry {self.tmp}/tools/bin lies inside an excluded directory, not searched",
            out,
        )

    def test_root_inside_an_exclude(self) -> None:
        ctx = self.build("-r", "scan/inner", "-r", "home", "-x", "scan")
        self.assertNotIn(self.tmp / "scan" / "inner", self.roots(ctx))
        _, out = run(ctx)
        self.assertIn(
            f"stderr: check: note: scan root {self.tmp}/scan/inner lies inside an excluded directory, skipped",
            out,
        )

    def test_header_names_the_roots(self) -> None:
        ctx = self.build("-r", "scan", "-x", "brew")
        self.assertEqual(
            next(line for line in run(ctx)[1] if line.startswith("INFO  eMudhra")),
            f"INFO  eMudhra CA compromise check; scan roots: {self.tmp}/scan containers=0",
        )


if __name__ == "__main__":
    unittest.main()
