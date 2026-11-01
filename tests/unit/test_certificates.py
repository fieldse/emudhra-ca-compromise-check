"""test_certificates.py: unit tests of emudhra_check/certificates.py and the generated certdata.py.

Checks the generated records against rules/, the matcher on every PEM wrapping, DER, bare public
keys and hostile PEM input, the verdict levels, and that unaffected bundles give no match. The
fixtures under /out come from tests/run-tests.sh and are skipped when it did not write them.
"""

import base64
import csv
import hashlib
import importlib.util
import time
import unittest
from pathlib import Path
from typing import Any

from emudhra_check import certdata
from emudhra_check.certificates import (
    G3_ECC_ROOT,
    ISRG_ROOT_X1_LINE,
    KNOWN_CERTIFICATES,
    KNOWN_KEYS,
    CertificateMatch,
    KeystoreKind,
    Matcher,
    MatchKind,
    Role,
    bundle_findings,
    keystore_kind,
    pem_blocks,
)
from emudhra_check.report import Finding, Level, Subject

REPO = Path(__file__).resolve().parents[2]
OUT = Path("/out")
SUBJECT = Subject("ca-bundle", "/x")
AAA = next(c for c in KNOWN_CERTIFICATES if c.role is Role.CROSS_SIGN_ISSUER_ROOT)


def load_generator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "generate_certdata", REPO / "tools" / "generate_certdata.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def pem(der: bytes, width: int = 64, eol: str = "\n") -> bytes:
    b64 = base64.b64encode(der).decode()
    lines = [b64[i : i + width] for i in range(0, len(b64), width)]
    return (
        eol.join(
            ["-----BEGIN CERTIFICATE-----", *lines, "-----END CERTIFICATE-----"]
        ).encode()
        + eol.encode()
    )


def needs(path: Path) -> None:
    if not path.exists():
        raise unittest.SkipTest(f"{path} is written by tests/run-tests.sh")


def levels(findings: list) -> list:
    return [f.level for f in findings]


class CertdataTest(unittest.TestCase):
    def test_counts(self) -> None:
        self.assertEqual(len(certdata.RECORDS), 20)
        self.assertEqual(len(KNOWN_CERTIFICATES), 20)
        self.assertEqual(len(KNOWN_KEYS), 12)

    def test_sixteen_intermediates_share_eight_keys(self) -> None:
        intermediates = [
            c for c in KNOWN_CERTIFICATES if c.role is Role.COMPROMISED_INTERMEDIATE
        ]
        self.assertEqual(len(intermediates), 16)
        self.assertEqual(len({c.spki_value for c in intermediates}), 8)

    def test_records_match_iocs_csv(self) -> None:
        with open(REPO / "rules" / "iocs.csv", encoding="utf-8", newline="") as handle:
            rows = {row["sha256"].upper() for row in csv.DictReader(handle)}
        for record in certdata.RECORDS:
            with self.subTest(label=record.label):
                self.assertEqual(hashlib.sha256(record.der).digest(), record.sha256)
                self.assertIn(record.sha256.hex().upper(), rows)
                self.assertIn(record.spki_value, record.der)
                self.assertEqual(record.pem_line, base64.b64encode(record.der)[:64])

    def test_regeneration_equals_committed_module(self) -> None:
        generated = load_generator().render(REPO / "rules")
        self.assertEqual(
            generated,
            (REPO / "emudhra_check" / "certdata.py").read_text(encoding="utf-8"),
        )

    def test_pem_lines_are_distinct(self) -> None:
        self.assertEqual(len({c.pem_line for c in KNOWN_CERTIFICATES}), 20)

    def test_isrg_line(self) -> None:
        self.assertEqual(len(ISRG_ROOT_X1_LINE), 44)

    def test_key_labels_name_the_emudhra_certificate(self) -> None:
        for key in KNOWN_KEYS:
            with self.subTest(label=key.label):
                self.assertNotIn("Sectigo cross-sign", key.label)


class MatcherTest(unittest.TestCase):
    matcher = Matcher()

    def full(self, data: bytes) -> list:
        return [m.label for m in self.matcher.scan(data) if m.kind is MatchKind.FULL]

    def test_out_yara_fixtures_give_one_full_each(self) -> None:
        needs(OUT / "yara" / "cert00.der")
        labels = [c.label for c in sorted(KNOWN_CERTIFICATES, key=lambda c: c.sha256)]
        names = sorted(p.name for p in (OUT / "yara").glob("cert*"))
        self.assertEqual(len(names), 60)
        for name in names:
            with self.subTest(name=name):
                matches = self.matcher.scan((OUT / "yara" / name).read_bytes())
                self.assertEqual(len(matches), 1)
                self.assertIs(matches[0].kind, MatchKind.FULL)
                self.assertIn(matches[0].label, labels)

    def test_each_wrapping_of_each_certificate(self) -> None:
        for certificate in KNOWN_CERTIFICATES:
            for data in (
                certificate.der,
                pem(certificate.der),
                pem(certificate.der, 76, "\r\n"),
            ):
                with self.subTest(label=certificate.label):
                    self.assertEqual(self.full(data), [certificate.label])

    def test_32_column_g3_root_is_found_by_the_pem_pass(self) -> None:
        data = pem(G3_ECC_ROOT.der, 32)
        self.assertNotIn(G3_ECC_ROOT.pem_line, data)
        self.assertNotIn(G3_ECC_ROOT.der, data)
        self.assertEqual(self.full(data), [G3_ECC_ROOT.label])
        self.assertEqual(
            levels(bundle_findings(SUBJECT, self.matcher.scan(data))), [Level.FAIL]
        )

    def test_comment_less_bundle(self) -> None:
        data = b"".join(pem(c.der) for c in KNOWN_CERTIFICATES)
        self.assertEqual(len(self.full(data)), 20)

    def test_bundle_after_comments(self) -> None:
        data = b"# comment line\n" * 7000 + pem(G3_ECC_ROOT.der)
        self.assertEqual(self.full(data), [G3_ECC_ROOT.label])

    def test_pem_line_alone(self) -> None:
        self.assertEqual(
            self.full(b"xx" + G3_ECC_ROOT.pem_line + b"yy"), [G3_ECC_ROOT.label]
        )

    def test_eight_intermediate_keys(self) -> None:
        needs(OUT / "keys" / "intermediates.der")
        matches = self.matcher.scan((OUT / "keys" / "intermediates.der").read_bytes())
        self.assertEqual(len(matches), 8)
        self.assertTrue(
            all(
                m.kind is MatchKind.KEY_ONLY and m.role is Role.COMPROMISED_INTERMEDIATE
                for m in matches
            )
        )
        self.assertEqual(
            levels(bundle_findings(SUBJECT, matches)), [Level.INFO] * 8 + [Level.PASS]
        )

    def test_g3_root_key_alone(self) -> None:
        needs(OUT / "keys" / "g3-ecc-root.der")
        matches = self.matcher.scan((OUT / "keys" / "g3-ecc-root.der").read_bytes())
        self.assertEqual(
            matches,
            (CertificateMatch(G3_ECC_ROOT.label, Role.G3_ROOT, MatchKind.KEY_ONLY),),
        )
        self.assertEqual(
            bundle_findings(SUBJECT, matches),
            [
                Finding(
                    Level.FAIL,
                    SUBJECT,
                    f"contains the public key of {G3_ECC_ROOT.label} as a trust anchor",
                )
            ],
        )

    def test_aaa_key_alone(self) -> None:
        needs(OUT / "keys" / "aaa.der")
        matches = self.matcher.scan((OUT / "keys" / "aaa.der").read_bytes())
        self.assertEqual(
            matches,
            (
                CertificateMatch(
                    AAA.label, Role.CROSS_SIGN_ISSUER_ROOT, MatchKind.KEY_ONLY
                ),
            ),
        )
        self.assertEqual(
            levels(bundle_findings(SUBJECT, matches)), [Level.WARN, Level.PASS]
        )

    def test_full_match_hides_its_key(self) -> None:
        matches = self.matcher.scan(G3_ECC_ROOT.der)
        self.assertEqual([m.kind for m in matches], [MatchKind.FULL])

    def test_begin_markers_without_end_are_linear(self) -> None:
        data = b"-----BEGIN CERTIFICATE-----\n" * 100_000
        start = time.monotonic()
        self.assertEqual(self.matcher.scan(data), ())
        self.assertLess(time.monotonic() - start, 10)

    def test_non_base64_block_is_skipped(self) -> None:
        bad = pem(G3_ECC_ROOT.der).replace(b"\nMII", b"\nM\xffII", 1)
        self.assertEqual(
            self.matcher.scan(
                b"-----BEGIN CERTIFICATE-----\n=\n-----END CERTIFICATE-----\n"
            ),
            (),
        )
        self.assertEqual(list(pem_blocks(bad)), [])
        self.assertEqual(self.full(bad), [])

    def test_block_with_end_too_far_is_skipped(self) -> None:
        data = (
            b"-----BEGIN CERTIFICATE-----\n"
            + b"A" * 40_000
            + b"\n-----END CERTIFICATE-----\n"
            + pem(G3_ECC_ROOT.der)
        )
        self.assertEqual(self.full(data), [G3_ECC_ROOT.label])

    def test_certifi_2026_10_19_has_no_match(self) -> None:
        path = OUT / "certifi" / "cacert-2026.10.19.pem"
        needs(path)
        data = path.read_bytes()
        for root in (
            b"emSign Root CA - G1",
            b"emSign Root CA - C1",
            b"emSign ECC Root CA - C3",
        ):
            self.assertIn(b"# Subject: CN=" + root, data)
        self.assertEqual(self.matcher.scan(data), ())

    def test_certifi_old_bundle_has_the_g3_root(self) -> None:
        path = OUT / "certifi" / "cacert-2026.7.22.pem"
        needs(path)
        self.assertIn(G3_ECC_ROOT.label, self.full(path.read_bytes()))


class BundleFindingsTest(unittest.TestCase):
    def test_no_match_is_pass(self) -> None:
        self.assertEqual(
            bundle_findings(SUBJECT, ()),
            [
                Finding(
                    Level.PASS, SUBJECT, "contains no compromised eMudhra certificate"
                )
            ],
        )

    def test_levels(self) -> None:
        intermediate = next(
            c for c in KNOWN_CERTIFICATES if c.role is Role.COMPROMISED_INTERMEDIATE
        )
        rows = [
            (
                CertificateMatch(
                    intermediate.label, Role.COMPROMISED_INTERMEDIATE, MatchKind.FULL
                ),
                Level.FAIL,
            ),
            (
                CertificateMatch(G3_ECC_ROOT.label, Role.G3_ROOT, MatchKind.FULL),
                Level.FAIL,
            ),
            (
                CertificateMatch(G3_ECC_ROOT.label, Role.G3_ROOT, MatchKind.KEY_ONLY),
                Level.FAIL,
            ),
            (
                CertificateMatch(
                    intermediate.label,
                    Role.COMPROMISED_INTERMEDIATE,
                    MatchKind.KEY_ONLY,
                ),
                Level.INFO,
            ),
            (
                CertificateMatch(
                    AAA.label, Role.CROSS_SIGN_ISSUER_ROOT, MatchKind.FULL
                ),
                Level.WARN,
            ),
            (
                CertificateMatch(
                    AAA.label, Role.CROSS_SIGN_ISSUER_ROOT, MatchKind.KEY_ONLY
                ),
                Level.WARN,
            ),
        ]
        for match, level in rows:
            with self.subTest(match=match):
                self.assertEqual(bundle_findings(SUBJECT, (match,))[0].level, level)

    def test_details(self) -> None:
        self.assertEqual(
            bundle_findings(
                SUBJECT,
                (CertificateMatch(G3_ECC_ROOT.label, Role.G3_ROOT, MatchKind.FULL),),
            )[0].line(),
            "FAIL  ca-bundle [/x] contains emSign ECC Root CA - G3 (removed root)",
        )
        aaa = bundle_findings(
            SUBJECT,
            (CertificateMatch(AAA.label, Role.CROSS_SIGN_ISSUER_ROOT, MatchKind.FULL),),
        )
        self.assertTrue(
            aaa[0].detail.startswith(
                "contains AAA Certificate Services (issued cross-signed copies"
            )
        )


class KeystoreKindTest(unittest.TestCase):
    def test_kinds(self) -> None:
        rows = [
            (bytes.fromhex("feedfeed00000002"), KeystoreKind.JKS),
            (bytes.fromhex("cececece00000002"), KeystoreKind.JCEKS),
            (
                bytes.fromhex("3082100002010330") + b"\x00" * 16,
                KeystoreKind.PKCS12_PLAIN,
            ),
            (
                bytes.fromhex("30821000") + bytes.fromhex("06092a864886f70d010706"),
                KeystoreKind.PKCS12_ENCRYPTED,
            ),
            (bytes.fromhex("308302d5020103"), KeystoreKind.PKCS12_PLAIN),
            (bytes.fromhex("3084000102d5020103"), KeystoreKind.PKCS12_PLAIN),
            (bytes.fromhex("3081ff020103"), KeystoreKind.UNKNOWN),
            (b"", KeystoreKind.UNKNOWN),
            (b"-----BEGIN", KeystoreKind.UNKNOWN),
        ]
        for data, kind in rows:
            with self.subTest(kind=kind):
                self.assertIs(keystore_kind(data), kind)


if __name__ == "__main__":
    unittest.main()
