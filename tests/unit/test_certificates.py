"""test_certificates.py: unit tests of emudhra_check/certificates.py and the generated certdata.py.

Checks the generated records against rules/, the matcher on every PEM wrapping, DER, bare public
keys and hostile PEM input, OpenSSL TRUSTED CERTIFICATE blocks with trusted, rejected and malformed
trust settings, the verdict levels, and that unaffected bundles give no match. The fixtures under
/out come from tests/run-tests.sh and are skipped when it did not write them.
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
    first_der_element,
    has_pem,
    keystore_kind,
    pem_blocks,
    rejected_uses,
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


def trusted_pem(der: bytes, width: int) -> bytes:
    """Wrap DER as an OpenSSL TRUSTED CERTIFICATE block."""
    return (
        pem(der, width)
        .replace(b"BEGIN CERTIFICATE", b"BEGIN TRUSTED CERTIFICATE")
        .replace(b"END CERTIFICATE", b"END TRUSTED CERTIFICATE")
    )


def needs(path: Path) -> None:
    if not path.exists():
        raise unittest.SkipTest(f"{path} is written by tests/run-tests.sh")


def levels(findings: list) -> list:
    return [f.level for f in findings]


class CertdataTest(unittest.TestCase):
    def test_counts(self) -> None:
        self.assertEqual(len(certdata.RECORDS), 22)
        self.assertEqual(len(KNOWN_CERTIFICATES), 22)
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
        self.assertEqual(len({c.pem_line for c in KNOWN_CERTIFICATES}), 22)

    def test_isrg_line(self) -> None:
        self.assertEqual(len(ISRG_ROOT_X1_LINE), 44)

    def test_key_labels_name_the_emudhra_certificate(self) -> None:
        for key in KNOWN_KEYS:
            with self.subTest(label=key.label):
                self.assertNotIn("Sectigo cross-sign", key.label)
                self.assertNotIn("cross-certificate", key.label)

    def test_g3_cross_certificates_match_in_full(self) -> None:
        # emSign ECC Root CA - G3 cross-certified the TLS and CS roots on 2024-07-11 (crt.sh 14658191778, 14658191774).
        wanted = {
            "3094025792039A68AF6E553686410BDAB7C0D4A36B9084CBA64202E35D6EBBDD",
            "7137FA71AD46BA686F746D1014AC57E8E6C6E9AF4AA2F73C0C44A5CF27DEBB59",
        }
        text = (REPO / "rules" / "certs" / "emudhra-g3-roots.pem").read_text()
        ders = [
            base64.b64decode(
                "".join(block.split("-----BEGIN CERTIFICATE-----")[1].split())
            )
            for block in text.split("-----END CERTIFICATE-----")[:-1]
        ]
        found = [d for d in ders if hashlib.sha256(d).hexdigest().upper() in wanted]
        self.assertEqual(len(found), 2)
        for der in found:
            with self.subTest(sha256=hashlib.sha256(der).hexdigest()):
                lines = [
                    f.line() for f in bundle_findings(SUBJECT, Matcher().scan(pem(der)))
                ]
                self.assertEqual(len(lines), 1)
                self.assertRegex(
                    lines[0],
                    r"^FAIL  ca-bundle \[/x\] contains emSign Root (TLS|CS) CA - G3, cross-certificate"
                    r" from emSign ECC Root CA - G3 \(",
                )
                self.assertNotIn("trust anchor", lines[0])


class MatcherTest(unittest.TestCase):
    matcher = Matcher()

    def full(self, data: bytes) -> list:
        return [m.label for m in self.matcher.scan(data) if m.kind is MatchKind.FULL]

    def test_out_yara_fixtures_give_one_full_each(self) -> None:
        needs(OUT / "yara" / "cert00.der")
        labels = [c.label for c in sorted(KNOWN_CERTIFICATES, key=lambda c: c.sha256)]
        names = sorted(p.name for p in (OUT / "yara").glob("cert*"))
        self.assertEqual(len(names), 66)
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
        self.assertEqual(len(self.full(data)), 22)

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

    def test_truncated_block_does_not_swallow_the_next(self) -> None:
        data = b"-----BEGIN CERTIFICATE-----\nMIIBtruncated\n" + pem(
            G3_ECC_ROOT.der, 60
        )
        self.assertNotIn(G3_ECC_ROOT.pem_line, data)
        self.assertNotIn(G3_ECC_ROOT.der, data)
        self.assertEqual(list(pem_blocks(data)), [G3_ECC_ROOT.der])
        self.assertEqual(self.full(data), [G3_ECC_ROOT.label])

    def test_trusted_certificate_block(self) -> None:
        aux = bytes.fromhex("30060c0474657374")
        data = trusted_pem(G3_ECC_ROOT.der + aux, 60)
        self.assertNotIn(G3_ECC_ROOT.pem_line, data)
        self.assertNotIn(b"-----BEGIN CERTIFICATE-----", data)
        self.assertTrue(has_pem(data))
        self.assertEqual(self.full(data), [G3_ECC_ROOT.label])
        self.assertEqual(
            self.full(
                b"# bundle\n" + trusted_pem(AAA.der + aux, 76) + pem(b"\x30\x00")
            ),
            [AAA.label],
        )

    def test_first_der_element(self) -> None:
        self.assertEqual(
            first_der_element(b"\x30\x02\x05\x00tail"), b"\x30\x02\x05\x00"
        )
        self.assertEqual(
            first_der_element(G3_ECC_ROOT.der + b"\x30\x00"), G3_ECC_ROOT.der
        )
        for bad in (
            b"",
            b"\x30",
            b"\x31\x00",
            b"\x30\x85\x01\x01\x01\x01\x01",
            b"\x30\x05ab",
        ):
            with self.subTest(bad=bad):
                self.assertIsNone(first_der_element(bad))

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


# Trust settings in an OpenSSL X509_CERT_AUX: anyExtendedKeyUsage, serverAuth, codeSigning and emailProtection.
ANY_EKU = bytes.fromhex("0604551d2500")
SERVER_AUTH = bytes.fromhex("06082b06010505070301")
CODE_SIGNING = bytes.fromhex("06082b06010505070303")
EMAIL = bytes.fromhex("06082b06010505070304")


def tlv(tag: int, content: bytes) -> bytes:
    """Encode one DER element with a short or two-byte length."""
    if len(content) < 0x80:
        return bytes([tag, len(content)]) + content
    return bytes([tag, 0x82]) + len(content).to_bytes(2, "big") + content


def aux(*fields: bytes) -> bytes:
    return tlv(0x30, b"".join(fields))


REJECT_ONLY = aux(tlv(0xA0, ANY_EKU))
TRUST_ONLY = aux(tlv(0x30, SERVER_AUTH))
TRUST_AND_REJECT = aux(tlv(0x30, SERVER_AUTH), tlv(0xA0, ANY_EKU))
REJECTED_LINE = (
    f"INFO  ca-bundle [/x] holds {G3_ECC_ROOT.label} as a rejected entry, not trusted"
)


def by_label(prefix: str) -> Any:
    return next(c for c in KNOWN_CERTIFICATES if c.label.startswith(prefix))


class RejectedEntryTest(unittest.TestCase):
    matcher = Matcher()

    def lines(self, data: bytes) -> list:
        return [f.line() for f in bundle_findings(SUBJECT, self.matcher.scan(data))]

    def test_rejected_uses(self) -> None:
        alias = tlv(0x0C, b"emSign")
        keyid = tlv(0x04, b"\x01\x02")
        other = tlv(0xA1, tlv(0x30, tlv(0x06, b"\x2a")))
        for value, want in (
            (REJECT_ONLY, {ANY_EKU[2:]}),
            (aux(tlv(0xA0, ANY_EKU + SERVER_AUTH)), {ANY_EKU[2:], SERVER_AUTH[2:]}),
            (aux(tlv(0x30, b""), tlv(0xA0, ANY_EKU)), {ANY_EKU[2:]}),
            (aux(tlv(0xA0, ANY_EKU), alias, keyid, other), {ANY_EKU[2:]}),
            (aux(tlv(0xA0, ANY_EKU * 30)), {ANY_EKU[2:]}),
            (TRUST_AND_REJECT, {ANY_EKU[2:]}),
            (TRUST_ONLY, set()),
            (aux(), set()),
            (aux(tlv(0xA0, b"")), set()),
            (aux(tlv(0x0C, b"emSign")), set()),
        ):
            with self.subTest(aux=value.hex()):
                self.assertEqual(rejected_uses(value), frozenset(want))

    def test_malformed_aux(self) -> None:
        for value in (
            b"",
            aux(tlv(0xA0, ANY_EKU), tlv(0x30, SERVER_AUTH)),
            aux(tlv(0xA0, ANY_EKU), tlv(0xA0, ANY_EKU)),
            aux(tlv(0xA0, ANY_EKU + b"\x05\x00")),
            aux(tlv(0xA0, b"\x06\x00")),
            aux(tlv(0xA0, ANY_EKU), tlv(0x02, b"\x01")),
            REJECT_ONLY + b"\x00",
            REJECT_ONLY[:-1],
            b"\x30\x80" + REJECT_ONLY[2:] + b"\x00\x00",
            b"\x30\x85\x00\x00\x00\x00\x08" + REJECT_ONLY[2:],
            b"\x1f\x08" + REJECT_ONLY[2:],
            aux(bytes([0xA0, 0x84, 0xFF, 0xFF, 0xFF, 0xFF]) + ANY_EKU),
            b"\x31" + REJECT_ONLY[1:],
        ):
            with self.subTest(aux=value.hex()):
                self.assertIsNone(rejected_uses(value))

    def test_rejected_block_is_info_and_the_bundle_passes(self) -> None:
        for width in (64, 76, 32):
            with self.subTest(width=width):
                data = trusted_pem(G3_ECC_ROOT.der + REJECT_ONLY, width)
                self.assertEqual(
                    self.lines(data),
                    [
                        REJECTED_LINE,
                        "PASS  ca-bundle [/x] contains no compromised eMudhra certificate",
                    ],
                )

    def test_trusted_blocks_fail(self) -> None:
        for value in (
            TRUST_ONLY,
            aux(tlv(0xA0, EMAIL)),
            aux(tlv(0xA0, SERVER_AUTH)),
            aux(tlv(0xA0, b"\x05\x00")),
            b"",
        ):
            with self.subTest(aux=value.hex()):
                data = trusted_pem(G3_ECC_ROOT.der + value, 64)
                self.assertEqual(
                    self.lines(data),
                    [f"FAIL  ca-bundle [/x] contains {G3_ECC_ROOT.label}"],
                )

    def test_reject_list_and_trust_list_together(self) -> None:
        # OpenSSL reads the reject list first, so a rejected purpose wins over a trusted one.
        data = trusted_pem(G3_ECC_ROOT.der + TRUST_AND_REJECT, 64)
        self.assertEqual(self.lines(data)[0], REJECTED_LINE)

    def test_the_purpose_rejected_must_be_the_role_s_purpose(self) -> None:
        tls_root = by_label("emSign Root TLS CA - G3")
        cs_root = by_label("emSign Root CS CA - G3")
        tls_ca = by_label("EM DV TLS CA - G3B (")
        cs_ca = by_label("EM OV CS CA - G3B (")
        both = SERVER_AUTH + CODE_SIGNING
        for certificate, reject, rejected in (
            (tls_root, SERVER_AUTH, True),
            (tls_root, CODE_SIGNING, False),
            (tls_ca, SERVER_AUTH, True),
            (tls_ca, EMAIL, False),
            (cs_root, CODE_SIGNING, True),
            (cs_root, SERVER_AUTH, False),
            (cs_ca, CODE_SIGNING, True),
            (cs_ca, SERVER_AUTH, False),
            (G3_ECC_ROOT, both, True),
            (G3_ECC_ROOT, CODE_SIGNING, False),
            (AAA, both, True),
            (AAA, SERVER_AUTH, False),
        ):
            with self.subTest(label=certificate.label, reject=reject.hex()):
                data = trusted_pem(certificate.der + aux(tlv(0xA0, reject)), 64)
                first = self.lines(data)[0]
                self.assertEqual(first.startswith("INFO"), rejected, first)
                self.assertIn(certificate.label, first)

    def test_a_trusted_copy_beside_the_rejected_entry_fails(self) -> None:
        rejected = trusted_pem(G3_ECC_ROOT.der + REJECT_ONLY, 64)
        for other in (
            pem(G3_ECC_ROOT.der),
            trusted_pem(G3_ECC_ROOT.der + TRUST_ONLY, 64),
            G3_ECC_ROOT.der,
            b"cert = '" + G3_ECC_ROOT.pem_line + b"'\n",
        ):
            for data in (rejected + other, other + rejected):
                with self.subTest(other=other[:30], first=data[:5]):
                    self.assertEqual(
                        self.lines(data),
                        [f"FAIL  ca-bundle [/x] contains {G3_ECC_ROOT.label}"],
                    )

    def test_plain_certificate_block_is_unchanged(self) -> None:
        self.assertEqual(
            self.lines(pem(G3_ECC_ROOT.der)),
            [f"FAIL  ca-bundle [/x] contains {G3_ECC_ROOT.label}"],
        )

    def test_rejected_aaa_is_info(self) -> None:
        data = trusted_pem(AAA.der + REJECT_ONLY, 64)
        self.assertEqual(
            self.lines(data),
            [
                f"INFO  ca-bundle [/x] holds {AAA.label} as a rejected entry, not trusted",
                "PASS  ca-bundle [/x] contains no compromised eMudhra certificate",
            ],
        )

    def test_openssl_fixtures(self) -> None:
        needs(OUT / "trusted" / "rejected.pem")
        rows = (
            (
                "rejected.pem",
                [
                    REJECTED_LINE,
                    "PASS  ca-bundle [/x] contains no compromised eMudhra certificate",
                ],
            ),
            (
                "rejected-alias.pem",
                [
                    REJECTED_LINE,
                    "PASS  ca-bundle [/x] contains no compromised eMudhra certificate",
                ],
            ),
            ("trusted.pem", [f"FAIL  ca-bundle [/x] contains {G3_ECC_ROOT.label}"]),
            (
                "both.pem",
                [
                    REJECTED_LINE,
                    "PASS  ca-bundle [/x] contains no compromised eMudhra certificate",
                ],
            ),
            ("email.pem", [f"FAIL  ca-bundle [/x] contains {G3_ECC_ROOT.label}"]),
        )
        for name, want in rows:
            with self.subTest(name=name):
                data = (OUT / "trusted" / name).read_bytes()
                self.assertIn(b"-----BEGIN TRUSTED CERTIFICATE-----", data)
                self.assertEqual(self.lines(data), want)


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


# The PKCS #7 data OID that opens a PKCS12 authSafe, and the encryptedData OID.
DATA = bytes.fromhex("06092a864886f70d010701a0")
ENCRYPTED = bytes.fromhex("06092a864886f70d010706")


class KeystoreKindTest(unittest.TestCase):
    def test_kinds(self) -> None:
        rows = [
            (bytes.fromhex("feedfeed00000002"), KeystoreKind.JKS),
            (bytes.fromhex("cececece00000002"), KeystoreKind.JCEKS),
            (bytes.fromhex("3082100002010330820ff0") + DATA, KeystoreKind.PKCS12_PLAIN),
            (
                bytes.fromhex("3082100002010330820ff0") + DATA + ENCRYPTED,
                KeystoreKind.PKCS12_ENCRYPTED,
            ),
            (
                bytes.fromhex("308302d50002010330830200d0") + DATA,
                KeystoreKind.PKCS12_PLAIN,
            ),
            (
                bytes.fromhex("3084000102d50201033084000102d0") + DATA,
                KeystoreKind.PKCS12_PLAIN,
            ),
            # OpenJDK's probe also accepts BER indefinite length, a one-byte long form and a short form.
            (bytes.fromhex("30800201033080") + DATA, KeystoreKind.PKCS12_PLAIN),
            (bytes.fromhex("3081ff0201033081f0") + DATA, KeystoreKind.PKCS12_PLAIN),
            (bytes.fromhex("30500201033040") + DATA, KeystoreKind.PKCS12_PLAIN),
            (bytes.fromhex("3081ff020103"), KeystoreKind.UNKNOWN),
            (bytes.fromhex("3081ff0201043081f0") + DATA, KeystoreKind.UNKNOWN),
            (bytes.fromhex("3081ff0201033181f0") + DATA, KeystoreKind.UNKNOWN),
            (bytes.fromhex("308500000000010201033050") + DATA, KeystoreKind.UNKNOWN),
            (b"", KeystoreKind.UNKNOWN),
            (b"-----BEGIN", KeystoreKind.UNKNOWN),
        ]
        for data, kind in rows:
            with self.subTest(kind=kind):
                self.assertIs(keystore_kind(data), kind)


if __name__ == "__main__":
    unittest.main()
