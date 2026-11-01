"""test_binaries.py: unit tests of emudhra_check/detections/binaries.py.

Runs GoBinaries and RustBinaries over in-memory classified binaries: Go toolchain and fallback module
verdicts, unreadable and legacy build information, the toolchain's own commands, Rust crates found
by their source paths, trust anchors and blocklist keys, and the ledger that keeps a binary a
runtime check reported from a second report.
"""

from __future__ import annotations

import dataclasses
import unittest
from pathlib import Path
from typing import Optional

from emudhra_check.buildinfo import BinaryKind, GoBuildInfo, GoModule
from emudhra_check.certificates import G3_ECC_ROOT, KNOWN_KEYS, Role
from emudhra_check.detections.binaries import (
    GoBinaries,
    RustBinaries,
    go_binary_findings,
)
from emudhra_check.detections.ports import Context, Ledger
from emudhra_check.detections.shared import MATCHER
from emudhra_check.report import Subject
from emudhra_check.scope import Executable, Index
from tests.unit.fakes import FakeFiles, lines, make_context
from tests.unit.test_buildinfo import ELF, FALLBACK, OLD_FALLBACK, go_blob, modinfo

NEW_FALLBACK = "v0.0.0-20261020153306-9f2b28d4331a"
G3_LINE = "contains emSign ECC Root CA - G3 (removed root)"
INTERMEDIATE_KEYS = b"".join(
    k.spki_value for k in KNOWN_KEYS if k.role is Role.COMPROMISED_INTERMEDIATE
)
G3_KEY = next(k.spki_value for k in KNOWN_KEYS if k.label == G3_ECC_ROOT.label)


def binaries_context(
    kind: BinaryKind, binaries: dict[str, bytes], ledger: Optional[Ledger] = None
) -> Context:
    files = FakeFiles(binaries)
    executables = tuple(
        Executable(Path(p), files.id_of(Path(p)), kind) for p in binaries
    )
    ctx = make_context(files, ledger=ledger)
    return dataclasses.replace(ctx, index=Index(executables=executables))


def go_lines(info: GoBuildInfo, data: bytes = b"") -> list[str]:
    subject = Subject("go binary", "/b/hello")
    return [f.line() for f in go_binary_findings(subject, info, MATCHER.scan(data))]


class GoBinaryFindingsTest(unittest.TestCase):
    def test_toolchain_versions(self) -> None:
        self.assertEqual(
            go_lines(GoBuildInfo("go1.27.2", (), False)),
            [
                "FAIL  go binary [/b/hello] found 1.27.2, fixed 1.27.3 (built with an affected toolchain, rebuild)"
            ],
        )
        self.assertEqual(
            go_lines(GoBuildInfo("go1.27.3", (), False)),
            ["PASS  go binary [/b/hello] found 1.27.3, fixed 1.27.3"],
        )

    def test_old_fallback_fails_and_new_passes(self) -> None:
        old = go_lines(
            GoBuildInfo("go1.27.3", (GoModule(FALLBACK, OLD_FALLBACK),), False),
            G3_ECC_ROOT.der,
        )
        self.assertEqual(
            old,
            [
                "PASS  go binary [/b/hello] found 1.27.3, fixed 1.27.3",
                f"FAIL  go fallback roots [/b/hello] found {OLD_FALLBACK}, fixed {NEW_FALLBACK}"
                " (embeds emSign ECC Root CA - G3, update the module and rebuild)",
                f"FAIL  go binary [/b/hello] {G3_LINE}",
            ],
        )
        new = go_lines(
            GoBuildInfo("go1.27.3", (GoModule(FALLBACK, NEW_FALLBACK),), False)
        )
        self.assertEqual(new, ["PASS  go binary [/b/hello] found 1.27.3, fixed 1.27.3"])

    def test_fallback_release_tag_warns(self) -> None:
        got = go_lines(GoBuildInfo("go1.27.3", (GoModule(FALLBACK, "v0.1.0"),), False))
        self.assertTrue(
            got[1].startswith(
                "WARN  go fallback roots [/b/hello] found v0.1.0: not a pseudo-version"
            )
        )

    def test_legacy_and_unreadable(self) -> None:
        self.assertEqual(
            go_lines(GoBuildInfo("", (), True)),
            [
                "FAIL  go binary [/b/hello] found a toolchain older than Go 1.18, no fix for that branch, rebuild"
            ],
        )
        self.assertEqual(
            [
                f.line()
                for f in go_binary_findings(Subject("go binary", "/b/x"), None, ())
            ],
            [
                "WARN  go binary [/b/x] Go build info unreadable, check it with go version -m"
            ],
        )


class GoBinariesTest(unittest.TestCase):
    def test_binaries_are_read_not_run(self) -> None:
        blob = (
            go_blob(info=modinfo(f"dep\t{FALLBACK}\t{OLD_FALLBACK}\th1:x="))
            + G3_ECC_ROOT.der
        )
        ctx = binaries_context(
            BinaryKind.GO, {"/go/bin/old": blob, "/go/bin/new": go_blob(b"go1.27.3")}
        )
        got = lines(GoBinaries(), ctx)
        self.assertIn("PASS  go binary [/go/bin/new] found 1.27.3, fixed 1.27.3", got)
        self.assertIn(f"FAIL  go binary [/go/bin/old] {G3_LINE}", got)
        self.assertTrue(
            any(
                line.startswith("FAIL  go fallback roots [/go/bin/old]") for line in got
            )
        )
        self.assertEqual(ctx.commands.calls, [])  # type: ignore[attr-defined]

    def test_toolchain_commands_and_claimed_binaries_are_skipped(self) -> None:
        ledger = Ledger()
        ctx = binaries_context(
            BinaryKind.GO,
            {
                "/opt/homebrew/Cellar/go/1.27.3/libexec/bin/go": go_blob(),
                "/usr/local/bin/go": go_blob(),
            },
            ledger,
        )
        ledger.claim(ctx.files.file_id(Path("/usr/local/bin/go")))  # type: ignore[arg-type]
        self.assertEqual(lines(GoBinaries(), ctx), [])

    def test_no_go_binaries(self) -> None:
        self.assertEqual(
            lines(GoBinaries(), make_context()),
            [
                "INFO  go [binaries] no Go binaries found in the binary directories or under the scan roots"
            ],
        )


class RustBinariesTest(unittest.TestCase):
    def rust_lines(self, payload: bytes) -> list[str]:
        ctx = binaries_context(BinaryKind.RUST, {"/fx/bin/r": ELF + payload})
        return lines(RustBinaries(), ctx)

    def test_old_crate_and_a_g3_trust_anchor(self) -> None:
        got = self.rust_lines(b"/rustls-webpki-0.103.13/src/lib.rs\x00" + G3_KEY)
        self.assertEqual(got[0][:43], "FAIL  rustls-webpki [/fx/bin/r] found 0.103")
        self.assertIn("rebuild against the fixed crates", got[0])
        self.assertEqual(
            got[1],
            "FAIL  rust binary [/fx/bin/r] contains the public key of emSign ECC Root CA - G3 (removed root)"
            " as a trust anchor",
        )
        self.assertEqual(len(got), 2)

    def test_fixed_crate_with_its_blocklist(self) -> None:
        got = self.rust_lines(
            b"/rustls-webpki-0.103.16/src/lib.rs\x00" + INTERMEDIATE_KEYS
        )
        self.assertTrue(
            got[0].startswith("PASS  rustls-webpki [/fx/bin/r] found 0.103.16")
        )
        self.assertEqual(
            sum(
                line.startswith("INFO  rust binary [/fx/bin/r] holds the public key")
                for line in got
            ),
            8,
        )
        self.assertEqual(
            got[-1],
            "PASS  rust binary [/fx/bin/r] contains no compromised eMudhra certificate",
        )
        self.assertFalse(any(line.startswith("FAIL") for line in got))

    def test_wrapper_resolves_through_the_same_binary(self) -> None:
        got = self.rust_lines(
            b"/webpki-roots-0.26.11/src/lib.rs/webpki-roots-1.0.9/src/lib.rs"
        )
        self.assertEqual([line[:4] for line in got], ["FAIL", "FAIL"])
        self.assertIn("found 0.26.11, wraps 1.0.9", got[0])
        self.assertIn("found 1.0.9, fixed 1.0.10", got[1])

    def test_wrapper_alone_warns(self) -> None:
        got = self.rust_lines(b"/webpki-roots-0.26.11/src/lib.rs")
        self.assertEqual([line[:4] for line in got], ["WARN"])


if __name__ == "__main__":
    unittest.main()
