"""test_trust_stores.py: unit tests of emudhra_check/detections/trust_stores.py.

Runs the trust store detections over in-memory files and recorded tool output: the fixed OS paths,
missing and unreadable files, the macOS note, the Homebrew formula versions and keychain lines, PEM
bundles with and without a match, Java keystores of each kind without keytool, Mozilla::CA by
version and bundle, and the ledger that keeps a file reached twice to one report in either registry
order.
"""

from __future__ import annotations

import base64
import unittest
from pathlib import Path
from typing import Optional

from emudhra_check.certificates import G3_ECC_ROOT, KNOWN_CERTIFICATES, Role
from emudhra_check.detections.ports import UNREADABLE, Ledger, Skipped
from emudhra_check.detections.shared import MATCHER
from emudhra_check.detections.trust_stores import (
    HomebrewTrustStore,
    JavaKeystores,
    OsTrustStore,
    PemBundles,
    PerlMozillaCa,
    keystore_findings,
)
from emudhra_check.report import Level, Subject
from emudhra_check.scope import FileId
from tests.unit.fakes import (
    FakeCommands,
    FakeFiles,
    FakeHost,
    hostenv,
    lines,
    located,
    make_context,
    result,
    run_all,
)

AAA = next(c for c in KNOWN_CERTIFICATES if c.role is Role.CROSS_SIGN_ISSUER_ROOT)
SYSTEM = "/etc/ssl/certs/ca-certificates.crt"


def pem(der: bytes) -> bytes:
    b64 = base64.b64encode(der).decode()
    body = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n".encode()


CLEAN = b"# a bundle with no certificate of interest\n" + pem(b"\x30\x03\x02\x01\x01")
AFFECTED = b"# emSign\n" + pem(G3_ECC_ROOT.der)


class OsTrustStoreTest(unittest.TestCase):
    def test_clean_system_bundle(self) -> None:
        ctx = make_context(FakeFiles({SYSTEM: CLEAN}))
        self.assertEqual(
            lines(OsTrustStore(), ctx),
            [
                "PASS  os trust store [/etc/ssl/certs/ca-certificates.crt] contains no compromised eMudhra certificate"
            ],
        )

    def test_affected_bundle_and_missing_paths(self) -> None:
        ctx = make_context(FakeFiles({"/etc/ssl/cert.pem": AFFECTED + pem(AAA.der)}))
        got = lines(OsTrustStore(), ctx)
        self.assertEqual(
            got[0],
            "FAIL  os trust store [/etc/ssl/cert.pem] contains emSign ECC Root CA - G3 (removed root)",
        )
        self.assertTrue(
            got[1].startswith("WARN  os trust store [/etc/ssl/cert.pem] contains AAA")
        )
        self.assertEqual(len(got), 2)

    def test_link_to_the_same_file_is_reported_once(self) -> None:
        files = FakeFiles(
            {SYSTEM: AFFECTED, "/etc/ssl/cert.pem": AFFECTED},
            ids={SYSTEM: FileId(1, 7), "/etc/ssl/cert.pem": FileId(1, 7)},
        )
        got = lines(OsTrustStore(), make_context(files))
        self.assertEqual(len(got), 1)
        self.assertIn(f"[{SYSTEM}]", got[0])

    def test_unreadable_bundle(self) -> None:
        ctx = make_context(FakeFiles({SYSTEM: Skipped(UNREADABLE)}))
        self.assertEqual(
            lines(OsTrustStore(), ctx),
            [
                "INFO  os trust store [/etc/ssl/certs/ca-certificates.crt] unreadable, skipped"
            ],
        )

    def test_excluded_path_gives_no_line(self) -> None:
        files = FakeFiles({SYSTEM: AFFECTED}, excluded=["/etc/ssl/certs"])
        self.assertEqual(lines(OsTrustStore(), make_context(files)), [])
        self.assertEqual(files.refused_reads(), 1)

    def test_macos_note_names_aaa(self) -> None:
        ctx = make_context(FakeFiles(), env=hostenv("Darwin"))
        got = lines(OsTrustStore(), ctx)
        self.assertEqual(len(got), 1)
        self.assertTrue(got[0].startswith("INFO  macOS [system keychain] Apple blocks"))
        self.assertIn("trusted through AAA Certificate Services", got[0])


class PemBundlesTest(unittest.TestCase):
    def test_only_files_with_a_match_are_listed(self) -> None:
        files = FakeFiles(
            {"/r/a/cacert.pem": AFFECTED, "/r/b.crt": CLEAN, "/r/c.cer": AFFECTED}
        )
        ctx = make_context(
            files, indexed=files.indexed("/r/a/cacert.pem", "/r/b.crt", "/r/c.cer")
        )
        self.assertEqual(
            lines(PemBundles(), ctx),
            [
                "FAIL  ca-bundle [/r/a/cacert.pem] contains emSign ECC Root CA - G3 (removed root)",
                "FAIL  ca-bundle [/r/c.cer] contains emSign ECC Root CA - G3 (removed root)",
                "INFO  ca-bundle [scan roots] checked 3 PEM files; only files containing an affected certificate"
                " are listed",
            ],
        )

    def test_file_without_a_pem_block_is_not_counted(self) -> None:
        files = FakeFiles({"/r/x.pem": G3_ECC_ROOT.der})
        ctx = make_context(files, indexed=files.indexed("/r/x.pem"))
        self.assertEqual(
            lines(PemBundles(), ctx),
            [
                "INFO  ca-bundle [scan roots] checked 0 PEM files; only files containing an affected certificate"
                " are listed"
            ],
        )

    def test_aaa_only_bundle_warns_and_passes(self) -> None:
        files = FakeFiles({"/r/aaa.pem": pem(AAA.der)})
        ctx = make_context(files, indexed=files.indexed("/r/aaa.pem"))
        levels = [f.level for f in PemBundles().run(ctx)]
        self.assertEqual(levels, [Level.WARN, Level.PASS, Level.INFO])

    def test_interests(self) -> None:
        wanted = PemBundles.interests
        for name in ("cacert.pem", "cacerts", "cacert-x", "x.crt", "x.cer", "x.bundle"):
            self.assertTrue(wanted.matches(Path("/r") / name), name)
        self.assertFalse(wanted.matches(Path("/r/x.der")))


BREW = "/opt/homebrew"
BREW_BUNDLE = BREW + "/etc/ca-certificates/cert.pem"
OPENSSL_BUNDLE = BREW + "/etc/openssl@3/cert.pem"
CELLAR = BREW + "/Cellar/ca-certificates/"
G3_LABEL = "emSign ECC Root CA - G3"


def brew_context(
    cellar: tuple[str, ...] = (),
    bundles: Optional[dict[str, bytes]] = None,
    keychain: tuple[str, ...] = (),
    system: str = "Darwin",
):
    files = FakeFiles(dict(bundles or {}), dirs=[CELLAR + name for name in cellar])
    env = hostenv(system, brew_prefix=BREW)
    return make_context(files, host=FakeHost(keychain=keychain), env=env)


def brew_lines(*args, **kwargs) -> list[str]:
    return lines(HomebrewTrustStore(), brew_context(*args, **kwargs))


class HomebrewTrustStoreTest(unittest.TestCase):
    def formula_line(self, *names: str) -> str:
        return [line for line in brew_lines(names) if "Cellar" in line][0]

    def test_formula_versions(self) -> None:
        for name, start in (
            ("2026-09-25", "FAIL"),
            ("2026-09-25_1", "PASS"),
            ("2026-10-20", "PASS"),
            ("foo", "WARN"),
        ):
            got = self.formula_line(name)
            self.assertTrue(
                got.startswith(
                    f"{start}  homebrew ca-certificates [{CELLAR}{name}] found {name}"
                ),
                got,
            )
        self.assertIn("fixed 2026-09-25_1", self.formula_line("2026-09-25"))

    def test_newest_dated_directory_decides(self) -> None:
        got = self.formula_line("2026-09-25", "2026-10-20", ".DS_Store")
        self.assertTrue(got.startswith("PASS") and "[" + CELLAR + "2026-10-20]" in got)

    def test_no_prefix_gives_no_line(self) -> None:
        ctx = make_context(FakeFiles({BREW_BUNDLE: AFFECTED}), env=hostenv("Darwin"))
        self.assertEqual(lines(HomebrewTrustStore(), ctx), [])

    def test_bundles_and_a_link_to_the_same_file(self) -> None:
        files = FakeFiles(
            {BREW_BUNDLE: AFFECTED, OPENSSL_BUNDLE: AFFECTED},
            ids={BREW_BUNDLE: FileId(1, 9), OPENSSL_BUNDLE: FileId(1, 9)},
        )
        ctx = make_context(files, env=hostenv("Linux", brew_prefix=BREW))
        self.assertEqual(
            lines(HomebrewTrustStore(), ctx),
            [
                f"FAIL  homebrew ca bundle [{BREW_BUNDLE}] contains emSign ECC Root CA - G3 (removed root)"
            ],
        )

    def test_aaa_hit_on_a_fixed_formula_is_stale(self) -> None:
        got = brew_lines(("2026-10-20",), {BREW_BUNDLE: pem(AAA.der)}, system="Linux")
        self.assertEqual([line[:4] for line in got], ["WARN", "PASS", "PASS", "WARN"])
        self.assertTrue(
            got[3].startswith(f"WARN  homebrew ca bundle [{BREW_BUNDLE}] is stale"),
            got,
        )

    def test_clean_bundle_on_a_fixed_formula_is_not_stale(self) -> None:
        got = brew_lines(("2026-10-20",), {BREW_BUNDLE: CLEAN}, system="Linux")
        self.assertEqual([line[:4] for line in got], ["PASS", "PASS"])

    def test_keychain_lines(self) -> None:
        got = brew_lines(("2026-10-20",), keychain=(G3_LABEL,))
        self.assertIn(
            "INFO  homebrew ca-certificates [keychain] macOS system roots keychain still lists"
            f" {G3_LABEL}, which Apple blocks separately for its own frameworks since 2026-10-23",
            got,
        )
        self.assertFalse(any("keychain still lists AAA" in line for line in got))
        got = brew_lines(("2026-10-20",), keychain=("AAA Certificate Services",))
        self.assertTrue(
            any("keychain still lists AAA Certificate Services" in line for line in got)
        )

    def test_keychain_not_listed_gives_no_line(self) -> None:
        self.assertFalse(
            any("keychain" in line for line in brew_lines(("2026-09-25",)))
        )

    def test_keychain_lines_only_on_macos(self) -> None:
        got = brew_lines(("2026-09-25",), keychain=(G3_LABEL,), system="Linux")
        self.assertFalse(any("keychain" in line for line in got))

    def test_old_formula_with_g3_in_the_keychain_warns(self) -> None:
        got = brew_lines(("2026-09-25",), keychain=(G3_LABEL,))
        self.assertEqual(
            got[-1],
            "WARN  homebrew ca-certificates [post_install] below 2026-09-25_1 copies this root"
            " from the keychain into its bundle on every install",
        )

    def test_fixed_formula_with_g3_in_the_keychain_does_not_warn(self) -> None:
        got = brew_lines(("2026-09-25_1",), keychain=(G3_LABEL,))
        self.assertFalse(any(line.startswith("WARN") for line in got), got)


ENCRYPTED_OID = bytes.fromhex("06092a864886f70d010706")
JKS = bytes.fromhex("feedfeed") + b"\x00" * 12 + G3_ECC_ROOT.der
JCEKS = bytes.fromhex("cececece") + b"\x00" * 12 + G3_ECC_ROOT.der
P12_PLAIN_CLEAN = b"\x30\x82\x04\x00" + b"\x00" * 64
P12_ENCRYPTED = b"\x30\x82\x04\x00" + ENCRYPTED_OID + b"\x00" * 64
G3_FAIL = "contains emSign ECC Root CA - G3 (removed root)"


def keystore_lines(data: bytes) -> list[str]:
    subject = Subject("java keystore", "/k")
    return [f.line() for f in keystore_findings(subject, data, MATCHER.scan(data))]


class KeystoreFindingsTest(unittest.TestCase):
    def test_plain_stores_are_judged_by_content(self) -> None:
        for data in (JKS, JCEKS, b"\x30\x82\x04\x00" + G3_ECC_ROOT.der):
            self.assertEqual(
                keystore_lines(data), [f"FAIL  java keystore [/k] {G3_FAIL}"]
            )
        self.assertEqual(
            keystore_lines(P12_PLAIN_CLEAN),
            ["PASS  java keystore [/k] contains no compromised eMudhra certificate"],
        )

    def test_encrypted_pkcs12_without_a_match_warns(self) -> None:
        got = keystore_lines(P12_ENCRYPTED)
        self.assertEqual(len(got), 1)
        self.assertTrue(
            got[0].startswith("WARN  java keystore [/k] password-protected")
        )

    def test_encrypted_pkcs12_with_a_match_fails(self) -> None:
        self.assertEqual(
            keystore_lines(P12_ENCRYPTED + G3_ECC_ROOT.der),
            [f"FAIL  java keystore [/k] {G3_FAIL}"],
        )

    def test_encrypted_pkcs12_with_only_aaa_keeps_both_warnings(self) -> None:
        got = keystore_lines(P12_ENCRYPTED + AAA.der)
        self.assertEqual([line[:4] for line in got], ["WARN", "WARN"])
        self.assertIn("AAA Certificate Services", got[0])

    def test_unknown_file_gives_no_line(self) -> None:
        self.assertEqual(keystore_lines(b"not a keystore " + G3_ECC_ROOT.der), [])


class JavaKeystoresTest(unittest.TestCase):
    def test_java_home_and_indexed_stores(self) -> None:
        home = "/opt/jdk"
        files = FakeFiles(
            {
                home + "/lib/security/cacerts": P12_PLAIN_CLEAN,
                home + "/jre/lib/security/cacerts": JKS,
                "/r/app/cacerts": JCEKS,
                "/r/notes/cacerts": b"plain text",
            }
        )
        ctx = make_context(
            files,
            host=FakeHost(java_homes=[home]),
            indexed=files.indexed("/r/app/cacerts", "/r/notes/cacerts"),
        )
        self.assertEqual(
            lines(JavaKeystores(), ctx),
            [
                f"PASS  jdk cacerts [{home}/lib/security/cacerts] contains no compromised eMudhra certificate",
                f"FAIL  jdk cacerts [{home}/jre/lib/security/cacerts] {G3_FAIL}",
                f"FAIL  java keystore [/r/app/cacerts] {G3_FAIL}",
            ],
        )

    def test_store_reached_from_a_home_and_a_root_is_reported_once(self) -> None:
        home_store = "/usr/lib/jvm/java-17/lib/security/cacerts"
        shared = "/etc/ssl/certs/java/cacerts"
        files = FakeFiles(
            {home_store: JKS, shared: JKS},
            ids={home_store: FileId(3, 3), shared: FileId(3, 3)},
        )
        ctx = make_context(
            files,
            host=FakeHost(java_homes=["/usr/lib/jvm/java-17"]),
            indexed=files.indexed(shared),
        )
        self.assertEqual(
            lines(JavaKeystores(), ctx), [f"FAIL  jdk cacerts [{home_store}] {G3_FAIL}"]
        )

    def test_unreadable_store(self) -> None:
        files = FakeFiles({"/r/cacerts": Skipped(UNREADABLE)})
        ctx = make_context(files, indexed=files.indexed("/r/cacerts"))
        self.assertEqual(
            lines(JavaKeystores(), ctx),
            ["INFO  java keystore [/r/cacerts] unreadable, skipped"],
        )

    def test_interests(self) -> None:
        self.assertTrue(JavaKeystores.interests.matches(Path("/r/cacerts")))
        self.assertFalse(JavaKeystores.interests.matches(Path("/r/cacerts.jks")))


PERL = "/usr/bin/perl"
MODULE_BUNDLE = "/usr/local/share/perl/5.36.0/Mozilla/CA/cacert.pem"


def perl_context(
    version: str, bundle: str, files: Optional[FakeFiles] = None, permitted: bool = True
):
    commands = FakeCommands(
        {"perl": located(PERL, permitted)},
        {
            (PERL, "-MMozilla::CA", "-e", "print $Mozilla::CA::VERSION"): result(
                version, 0 if version else 2
            ),
            (PERL, "-MMozilla::CA", "-e", "print Mozilla::CA::SSL_ca_file()"): result(
                bundle
            ),
        },
    )
    return make_context(files or FakeFiles(), commands)


class PerlMozillaCaTest(unittest.TestCase):
    def test_old_module_and_its_bundle_fail(self) -> None:
        ctx = perl_context(
            "20250602", MODULE_BUNDLE, FakeFiles({MODULE_BUNDLE: AFFECTED})
        )
        self.assertEqual(
            lines(PerlMozillaCa(), ctx),
            [
                "FAIL  Mozilla::CA [host] found 20250602, fixed 20261020",
                f"FAIL  Mozilla::CA bundle [{MODULE_BUNDLE}] {G3_FAIL}",
            ],
        )

    def test_fixed_module_passes(self) -> None:
        ctx = perl_context("20261020", MODULE_BUNDLE, FakeFiles({MODULE_BUNDLE: CLEAN}))
        self.assertEqual(
            lines(PerlMozillaCa(), ctx),
            [
                "PASS  Mozilla::CA [host] found 20261020, fixed 20261020",
                f"PASS  Mozilla::CA bundle [{MODULE_BUNDLE}] contains no compromised eMudhra certificate",
            ],
        )

    def test_patched_module_points_at_the_system_bundle(self) -> None:
        ctx = perl_context("20230801", SYSTEM, FakeFiles({SYSTEM: CLEAN}))
        self.assertEqual(
            lines(PerlMozillaCa(), ctx)[0],
            f"INFO  Mozilla::CA [host] 20230801 is patched to use {SYSTEM}",
        )

    def test_empty_bundle_path_is_judged_by_version(self) -> None:
        self.assertEqual(
            lines(PerlMozillaCa(), perl_context("20250602", "")),
            ["FAIL  Mozilla::CA [host] found 20250602, fixed 20261020"],
        )

    def test_module_missing_gives_no_line(self) -> None:
        self.assertEqual(lines(PerlMozillaCa(), perl_context("", "")), [])

    def test_no_perl_gives_no_line(self) -> None:
        self.assertEqual(lines(PerlMozillaCa(), make_context()), [])

    def test_excluded_perl_is_not_run(self) -> None:
        ctx = perl_context("20250602", "", permitted=False)
        self.assertEqual(
            lines(PerlMozillaCa(), ctx),
            ["INFO  perl [host] found on PATH inside an excluded directory, not run"],
        )
        self.assertEqual(ctx.commands.calls, [])  # type: ignore[attr-defined]


class LedgerOrderTest(unittest.TestCase):
    """A fixed bundle also indexed under a root is reported once, by whichever detection runs first."""

    def run_order(self, order: tuple) -> tuple[set, set]:
        files = FakeFiles({SYSTEM: AFFECTED})
        ctx = make_context(files, indexed=files.indexed(SYSTEM), ledger=Ledger())
        found = run_all(order, ctx)
        bundle = [
            f for f in found if f.subject is not None and f.subject.where == SYSTEM
        ]
        self.assertEqual(len(bundle), 1, [f.line() for f in found])
        file_id = files.id_of(Path(SYSTEM))
        return {(file_id, f.level) for f in bundle}, {f.subject.name for f in bundle}

    def test_both_orders_give_the_same_levels(self) -> None:
        first, first_names = self.run_order((OsTrustStore(), PemBundles()))
        second, second_names = self.run_order((PemBundles(), OsTrustStore()))
        self.assertEqual(first, second)
        self.assertEqual(first_names, {"os trust store"})
        self.assertEqual(second_names, {"ca-bundle"})


if __name__ == "__main__":
    unittest.main()
