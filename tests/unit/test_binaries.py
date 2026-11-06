"""test_binaries.py: unit tests of emudhra_check/detections/binaries.py.

Runs the binary detections over in-memory files: Go toolchain and fallback module verdicts, the
crypto/x509 Verify name that keeps a toolchain FAIL, unreadable and legacy build information, the
toolchain's own commands and bin links to them, Rust crates found by their source paths, trust
anchors and blocklist keys, bundled Node stores, Electron apps judged by version in both layouts,
updater caches, and the ledger that keeps a binary a runtime check reported from a second report.
"""

from __future__ import annotations

import dataclasses
import plistlib
import unittest
from pathlib import Path
from typing import Optional

from emudhra_check.buildinfo import BinaryKind, GoBuildInfo, GoModule
from emudhra_check.certificates import (
    G3_ECC_ROOT,
    ISRG_ROOT_X1_LINE,
    KNOWN_CERTIFICATES,
    KNOWN_KEYS,
    Role,
)
from emudhra_check.detections.binaries import (
    NO_VERIFY_NOTE,
    RUSTLS_NO_ROOT_NOTE,
    X509_VERIFY,
    BundledNodeBinaries,
    ElectronApps,
    GoBinaries,
    RustBinaries,
    UpdaterCaches,
    electron_app_findings,
    go_binary_findings,
)
from emudhra_check.detections.ports import Context, Ledger
from emudhra_check.detections.shared import MATCHER
from emudhra_check.report import Subject
from emudhra_check.scope import Executable, FileId, Index, IndexedDir
from tests.unit.fakes import FakeFiles, lines, make_context
from tests.unit.test_buildinfo import ELF, FALLBACK, OLD_FALLBACK, go_blob, modinfo

NEW_FALLBACK = "v0.0.0-20261020153306-9f2b28d4331a"
G3_LINE = "contains emSign ECC Root CA - G3 (removed root)"
INTERMEDIATE_KEYS = b"".join(
    k.spki_value for k in KNOWN_KEYS if k.role is Role.COMPROMISED_INTERMEDIATE
)
G3_KEY = next(k.spki_value for k in KNOWN_KEYS if k.label == G3_ECC_ROOT.label)
INTERMEDIATE_DER = next(
    c.der for c in KNOWN_CERTIFICATES if c.role is Role.COMPROMISED_INTERMEDIATE
)


def binaries_context(
    kind: BinaryKind,
    binaries: dict[str, bytes],
    ledger: Optional[Ledger] = None,
    real: Optional[dict[str, str]] = None,
) -> Context:
    """Index each binary as an executable, at the real path given for it or at its own path."""
    real = real or {}
    files = FakeFiles(binaries)
    executables = tuple(
        Executable(Path(p), Path(real.get(p, p)), files.id_of(Path(p)), kind)
        for p in binaries
    )
    ctx = make_context(files, ledger=ledger)
    return dataclasses.replace(ctx, index=Index(executables=executables))


def go_lines(info: GoBuildInfo, data: bytes = b"", verifies: bool = True) -> list[str]:
    subject = Subject("go binary", "/b/hello")
    found = go_binary_findings(subject, info, MATCHER.scan(data), verifies)
    return [f.line() for f in found]


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

    def test_affected_toolchain_without_x509_verify_warns(self) -> None:
        self.assertEqual(
            go_lines(GoBuildInfo("go1.27.2", (), False), verifies=False),
            [
                "WARN  go binary [/b/hello] found 1.27.2, fixed 1.27.3 (built with an affected toolchain, rebuild)"
                f" ({NO_VERIFY_NOTE})"
            ],
        )
        self.assertEqual(
            go_lines(GoBuildInfo("", (), True), verifies=False),
            [
                "WARN  go binary [/b/hello] found a toolchain older than Go 1.18, no fix for that branch, rebuild"
                f" ({NO_VERIFY_NOTE})"
            ],
        )

    def test_fixed_toolchain_without_x509_verify_passes(self) -> None:
        self.assertEqual(
            go_lines(GoBuildInfo("go1.27.3", (), False), verifies=False),
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
                for f in go_binary_findings(
                    Subject("go binary", "/b/x"), None, (), False
                )
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

    def test_x509_verify_name_in_the_bytes_decides_fail_or_warn(self) -> None:
        hostname = b"crypto/x509.(*Certificate).VerifyHostname\x00"
        ctx = binaries_context(
            BinaryKind.GO,
            {
                "/b/tls": go_blob(b"go1.27.2") + X509_VERIFY,
                "/b/fmt": go_blob(b"go1.27.2"),
                "/b/host": go_blob(b"go1.27.2") + hostname,
            },
        )
        got = lines(GoBinaries(), ctx)
        self.assertEqual(
            [line.split(" (")[0] for line in got],
            [
                "FAIL  go binary [/b/tls] found 1.27.2, fixed 1.27.3",
                "WARN  go binary [/b/fmt] found 1.27.2, fixed 1.27.3",
                "WARN  go binary [/b/host] found 1.27.2, fixed 1.27.3",
            ],
        )

    def test_bin_link_into_the_go_cellar_is_skipped(self) -> None:
        link = "/opt/homebrew/bin/gofmt"
        ctx = binaries_context(
            BinaryKind.GO,
            {link: go_blob(b"go1.27.1")},
            real={link: "/opt/homebrew/Cellar/go/1.27.1/libexec/bin/gofmt"},
        )
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

    def test_old_crate_and_a_compromised_intermediate_fails(self) -> None:
        got = self.rust_lines(
            b"/rustls-webpki-0.103.14/src/lib.rs\x00" + INTERMEDIATE_DER
        )
        self.assertEqual(
            got[0],
            "FAIL  rustls-webpki [/fx/bin/r] found 0.103.14, fixed 0.103.16"
            " (rebuild against the fixed crates)",
        )
        self.assertTrue(got[1].startswith("FAIL  rust binary [/fx/bin/r] contains EM"))

    def test_old_crate_without_an_affected_root_warns(self) -> None:
        got = self.rust_lines(b"/rustls-webpki-0.103.14/src/lib.rs\x00")
        self.assertEqual(
            got,
            [
                "WARN  rustls-webpki [/fx/bin/r] found 0.103.14, fixed 0.103.16"
                f" ({RUSTLS_NO_ROOT_NOTE})"
            ],
        )

    def test_unfixed_line_without_an_affected_root_warns(self) -> None:
        got = self.rust_lines(
            b"/rustls-webpki-0.102.8/src/lib.rs\x00" + INTERMEDIATE_KEYS
        )
        self.assertTrue(
            got[0].startswith(
                "WARN  rustls-webpki [/fx/bin/r] found 0.102.8, 0.102 and older lines have no fix"
            )
        )
        self.assertIn(RUSTLS_NO_ROOT_NOTE, got[0])
        self.assertFalse(any(line.startswith("FAIL") for line in got))

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


G3_PEM_LINE = G3_ECC_ROOT.pem_line
NODE_URL = b"https://nodejs.org/download/release/v24.22.1/node-v24.22.1-headers.tar.gz"


class BundledNodeBinariesTest(unittest.TestCase):
    def node_lines(self, payload: bytes) -> list[str]:
        ctx = binaries_context(BinaryKind.NODE, {"/fx/bin/n": ELF + NODE_URL + payload})
        return lines(BundledNodeBinaries(), ctx)

    def test_fixed_version_still_bundling_g3_fails(self) -> None:
        self.assertEqual(
            self.node_lines(G3_PEM_LINE),
            [
                "PASS  node [/fx/bin/n] found 24.22.1, fixed 24.22.1",
                "FAIL  node [/fx/bin/n] binary still bundles emSign ECC Root CA - G3 (removed root)",
            ],
        )

    def test_bundled_store_without_g3_passes(self) -> None:
        self.assertEqual(
            self.node_lines(ISRG_ROOT_X1_LINE),
            ["PASS  node [/fx/bin/n] found 24.22.1, fixed 24.22.1"],
        )

    def test_no_bundled_list_is_judged_by_version(self) -> None:
        note = "INFO  node [/fx/bin/n] binary bundles no Node.js root list (a patched build), judged by its version"
        self.assertEqual(
            self.node_lines(b""),
            ["PASS  node [/fx/bin/n] found 24.22.1, fixed 24.22.1", note],
        )
        old = NODE_URL.replace(b"24.22.1", b"24.22.0")
        ctx = binaries_context(BinaryKind.NODE, {"/fx/bin/n": ELF + old})
        self.assertEqual(
            lines(BundledNodeBinaries(), ctx),
            ["FAIL  node [/fx/bin/n] found 24.22.0, fixed 24.22.1", note],
        )

    def test_glob_candidates(self) -> None:
        globs = BundledNodeBinaries.interests.dir_globs
        self.assertTrue(BundledNodeBinaries.interests.executables)
        self.assertIn(".cache/codex-runtimes/*/payload", globs)


FRAMEWORK = "Contents/Frameworks/Electron Framework.framework"


def app_files(app: str, version: Optional[str], binary: bytes) -> dict[str, bytes]:
    fw = f"{app}/{FRAMEWORK}"
    files = {f"{fw}/Versions/A/Electron Framework": binary}
    if version is not None:
        plist = plistlib.dumps({"CFBundleVersion": version}, fmt=plistlib.FMT_BINARY)
        files[f"{fw}/Versions/A/Resources/Info.plist"] = plist
    return files


def apps_context(files: dict[str, bytes], apps: tuple[str, ...]) -> Context:
    fake = FakeFiles(files)
    dirs = tuple(IndexedDir(Path(a), FileId(5, n)) for n, a in enumerate(apps))
    indexed = tuple(f for f in fake.indexed(*files) if f.path.name == "app.asar")
    return make_context(fake, indexed=indexed, dirs=dirs)


class ElectronAppFindingsTest(unittest.TestCase):
    def test_version_decides_and_g3_is_a_note(self) -> None:
        subject = Subject("electron app", "/A/Old.app/fw")
        matches = MATCHER.scan(G3_PEM_LINE)
        old = [
            f.line()
            for f in electron_app_findings(subject, "44.9.0", matches, "/A/bin")
        ]
        self.assertEqual(
            old[0],
            "FAIL  electron app [/A/Old.app/fw] found 44.9.0, fixed 44.9.1 (update the app)",
        )
        self.assertEqual(
            old[1],
            "INFO  electron app [/A/bin] also bundles emSign ECC Root CA - G3 (confirms the version FAIL)",
        )
        fixed = [
            f.line()
            for f in electron_app_findings(subject, "44.9.1", matches, "/A/bin")
        ]
        self.assertEqual(
            fixed[0], "PASS  electron app [/A/Old.app/fw] found 44.9.1, fixed 44.9.1"
        )
        self.assertTrue(
            fixed[1].startswith(
                "INFO  electron app [/A/bin] bundled Node.js root store still lists"
            )
        )
        self.assertEqual(len(fixed), 2)

    def test_g3_note_claims_the_fix_only_on_pass(self) -> None:
        subject = Subject("electron app", "/A/fw")
        matches = MATCHER.scan(G3_PEM_LINE)
        for version in (None, "46.0.0-nightly.20261015"):
            with self.subTest(version=version):
                got = [
                    f.line()
                    for f in electron_app_findings(subject, version, matches, "/A/bin")
                ]
                self.assertTrue(got[0].startswith("WARN  electron app [/A/fw]"))
                self.assertEqual(
                    got[1],
                    "INFO  electron app [/A/bin] bundled Node.js root store lists"
                    " emSign ECC Root CA - G3, which only a fixed Electron blocks",
                )

    def test_no_version(self) -> None:
        got = electron_app_findings(Subject("electron app", "/A/fw"), None, ())
        self.assertEqual(
            [f.line() for f in got],
            [
                "WARN  electron app [/A/fw] version unreadable, check the app's About window"
            ],
        )


class ElectronAppsTest(unittest.TestCase):
    def test_macos_apps(self) -> None:
        files = {
            **app_files("/A/Old.app", "44.9.0", ELF + G3_PEM_LINE),
            **app_files("/A/Fixed.app", "44.9.1", ELF + G3_PEM_LINE),
            **app_files("/A/NoPlist.app", None, ELF + b"Electron/43.8.1"),
            **app_files("/A/Bad.app", None, ELF),
            "/A/Plain.app/Contents/MacOS/Plain": ELF,
        }
        apps = (
            "/A/Old.app",
            "/A/Fixed.app",
            "/A/NoPlist.app",
            "/A/Bad.app",
            "/A/Plain.app",
        )
        got = lines(ElectronApps(), apps_context(files, apps))
        self.assertIn(
            f"FAIL  electron app [/A/Old.app/{FRAMEWORK}] found 44.9.0, fixed 44.9.1 (update the app)",
            got,
        )
        self.assertIn(
            f"PASS  electron app [/A/Fixed.app/{FRAMEWORK}] found 44.9.1, fixed 44.9.1",
            got,
        )
        self.assertIn(
            f"PASS  electron app [/A/NoPlist.app/{FRAMEWORK}] found 43.8.1, fixed 43.8.1",
            got,
        )
        self.assertIn(
            f"WARN  electron app [/A/Bad.app/{FRAMEWORK}] version unreadable, check the app's About window",
            got,
        )
        self.assertFalse(any("Plain.app" in line for line in got))
        self.assertFalse(
            any(line.startswith("FAIL") and "Fixed.app" in line for line in got)
        )

    def test_updater_cache_apps_are_left_to_updater_caches(self) -> None:
        app = "/h/Library/Caches/com.x.ShipIt/update.1/Old.app"
        ctx = apps_context(app_files(app, "43.8.0", ELF), (app,))
        self.assertEqual(
            lines(ElectronApps(), ctx),
            ["INFO  electron app [scan roots] no Electron apps found"],
        )
        self.assertEqual(
            lines(UpdaterCaches(), ctx),
            [
                f"WARN  electron update cache [{app}] found 43.8.0, fixed 43.8.1"
                " (stale updater cache, delete the directory)"
            ],
        )

    def test_fixed_cached_app_prints_nothing(self) -> None:
        app = "/h/Library/Caches/com.x.ShipIt/update.1/New.app"
        ctx = apps_context(app_files(app, "44.9.1", ELF), (app,))
        self.assertEqual(lines(UpdaterCaches(), ctx), [])

    def test_linux_layout(self) -> None:
        files = {
            "/opt/myapp/myapp": ELF + b"Electron/43.8.0",
            "/opt/myapp/libffmpeg.so": ELF + b"Electron/1.0.0",
            "/opt/myapp/resources/app.asar": b"asar",
        }
        got = lines(ElectronApps(), apps_context(files, ()))
        self.assertEqual(
            got,
            [
                "FAIL  electron app [/opt/myapp/myapp] found 43.8.0, fixed 43.8.1 (update the app)"
            ],
        )

    def test_pre_release_in_the_binary_is_judged_with_its_suffix(self) -> None:
        files = {
            **app_files("/A/Beta.app", None, ELF + b"Electron/45.0.0-beta.5 x"),
            "/opt/beta/beta": ELF + b"Electron/45.0.0-beta.5 x",
            "/opt/beta/resources/app.asar": b"asar",
        }
        got = lines(ElectronApps(), apps_context(files, ("/A/Beta.app",)))
        self.assertIn(
            f"FAIL  electron app [/A/Beta.app/{FRAMEWORK}] found 45.0.0-beta.5,"
            " fixed 45.0.0-beta.6 (update the app)",
            got,
        )
        self.assertIn(
            "FAIL  electron app [/opt/beta/beta] found 45.0.0-beta.5,"
            " fixed 45.0.0-beta.6 (update the app)",
            got,
        )
        app = "/h/Library/Caches/com.x.ShipIt/update.1/Beta.app"
        ctx = apps_context(
            app_files(app, None, ELF + b"Electron/45.0.0-beta.5"), (app,)
        )
        self.assertEqual(
            lines(UpdaterCaches(), ctx),
            [
                f"WARN  electron update cache [{app}] found 45.0.0-beta.5, fixed 45.0.0-beta.6"
                " (stale updater cache, delete the directory)"
            ],
        )

    def test_linux_reads_count_against_the_binary_budget(self) -> None:
        files = {
            "/opt/a/a": ELF + b"Electron/43.8.0",
            "/opt/a/resources/app.asar": b"asar",
            "/opt/b/b": ELF + b"Electron/43.8.0",
            "/opt/b/resources/app.asar": b"asar",
        }
        ctx = apps_context(files, ())
        assert isinstance(ctx.files, FakeFiles)
        ctx.files.binary_budget = 10
        self.assertEqual(
            lines(ElectronApps(), ctx),
            [
                "FAIL  electron app [/opt/a/a] found 43.8.0, fixed 43.8.1 (update the app)",
                "INFO  scan [/opt/b/b] binary budget exhausted, skipped",
            ],
        )
        self.assertEqual(ctx.files.binary_spent, len(files["/opt/a/a"]))
        self.assertNotIn(Path("/opt/b/b"), ctx.files.reads)


if __name__ == "__main__":
    unittest.main()
