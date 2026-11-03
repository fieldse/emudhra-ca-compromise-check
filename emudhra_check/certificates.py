"""certificates.py: how a compromised eMudhra certificate is recognised in bytes.

Builds the known certificates and keys from certdata.py, finds them in PEM bundles, keystores and
binaries by SHA-256 of each PEM block, by DER, by the first base64 line and by the public key, and
turns the matches into findings. An OpenSSL TRUSTED CERTIFICATE block whose reject list holds
anyExtendedKeyUsage or every use the certificate serves is a distrust entry and gives INFO, not
FAIL. Every scan is a bytes.find loop over the buffer, so the cost is linear in its size.
"""

from __future__ import annotations

import binascii
import bisect
import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Iterator, Optional, Protocol

from emudhra_check.certdata import RECORDS
from emudhra_check.fixes import AAA_LEVEL
from emudhra_check.limits import MAX_PEM_BLOCK_BYTES
from emudhra_check.report import Finding, Level, Subject


class Buffer(Protocol):
    """Bytes or a read-only mmap: anything with find, slicing and a length."""

    def find(self, sub: bytes, start: int = ..., end: int = ...) -> int: ...

    def rfind(self, sub: bytes, start: int = ..., end: int = ...) -> int: ...

    def __getitem__(self, index: slice) -> bytes: ...

    def __len__(self) -> int: ...


PEM_BEGIN = b"-----BEGIN CERTIFICATE-----"
PEM_END = b"-----END CERTIFICATE-----"
TRUSTED_BEGIN = b"-----BEGIN TRUSTED CERTIFICATE-----"
TRUSTED_END = b"-----END TRUSTED CERTIFICATE-----"
PEM_WHITESPACE = b"\r\n \t"
BASE64_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
ISRG_ROOT_X1_LINE = b"MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAw"
NO_COMPROMISED = "contains no compromised eMudhra certificate"
AAA_DETAIL = (
    "contains AAA Certificate Services (issued cross-signed copies of all eight compromised intermediates,"
    " revoked 2026-10-19, trusted by clients that skip revocation)"
)


class Role(Enum):
    COMPROMISED_INTERMEDIATE = "compromised intermediate"
    G3_ROOT = "G3 root"
    CROSS_SIGN_ISSUER_ROOT = "cross-sign issuer root"


class MatchKind(Enum):
    FULL = "full"
    KEY_ONLY = "key only"
    REJECTED = "rejected"


@dataclass(frozen=True)
class KnownCertificate:
    label: str
    role: Role
    sha256: bytes
    der: bytes
    spki_value: bytes
    pem_line: bytes


@dataclass(frozen=True)
class KnownKey:
    """A public key and the certificates that carry it, labelled with its eMudhra certificate."""

    label: str
    role: Role
    spki_value: bytes
    certificates: tuple[KnownCertificate, ...]


@dataclass(frozen=True)
class CertificateMatch:
    label: str
    role: Role
    kind: MatchKind


KNOWN_CERTIFICATES: tuple[KnownCertificate, ...] = tuple(
    KnownCertificate(r.label, Role[r.role], r.sha256, r.der, r.spki_value, r.pem_line)
    for r in RECORDS
)
BY_SHA256 = {c.sha256: c for c in KNOWN_CERTIFICATES}
ORDER = {c.label: index for index, c in enumerate(KNOWN_CERTIFICATES)}


def known_keys(certificates: tuple[KnownCertificate, ...]) -> tuple[KnownKey, ...]:
    """Group the certificates by public key, each key named after its certificate that is not a cross-sign."""
    groups: dict[bytes, list[KnownCertificate]] = {}
    for certificate in certificates:
        groups.setdefault(certificate.spki_value, []).append(certificate)
    keys = []
    for spki, group in groups.items():
        named = sorted(group, key=lambda c: ("Sectigo cross-sign" in c.label, c.label))[
            0
        ]
        keys.append(KnownKey(named.label, named.role, spki, tuple(group)))
    return tuple(keys)


KNOWN_KEYS = known_keys(KNOWN_CERTIFICATES)
G3_ECC_ROOT = next(
    c for c in KNOWN_CERTIFICATES if c.label.startswith("emSign ECC Root CA - G3")
)


def has_pem(data: Buffer) -> bool:
    """Return whether data holds a PEM certificate or trusted certificate block."""
    return data.find(PEM_BEGIN) >= 0 or data.find(TRUSTED_BEGIN) >= 0


def first_der_element(der: bytes) -> Optional[bytes]:
    """Return the first DER SEQUENCE in der, the certificate of an OpenSSL trusted certificate."""
    if len(der) < 2 or der[0] != 0x30:
        return None
    if der[1] < 0x80:
        header, length = 2, der[1]
    else:
        width = der[1] & 0x7F
        if not 1 <= width <= 4 or len(der) < 2 + width:
            return None
        header, length = 2 + width, int.from_bytes(der[2 : 2 + width], "big")
    return der[: header + length] if header + length <= len(der) else None


def der_header(data: bytes, pos: int, end: int) -> Optional[tuple[int, int, int]]:
    """Return the tag, content start and content end of the DER element at pos, or None when it does
    not fit before end or uses a form DER forbids."""
    if end - pos < 2 or data[pos] & 0x1F == 0x1F:
        return None
    first = data[pos + 1]
    if first < 0x80:
        start, length = pos + 2, first
    else:
        width = first & 0x7F
        if not 1 <= width <= 4 or end - pos < 2 + width:
            return None
        start = pos + 2 + width
        length = int.from_bytes(data[pos + 2 : start], "big")
    if start + length > end:
        return None
    return data[pos], start, start + length


def oid_contents(data: bytes, start: int, end: int) -> Optional[list[bytes]]:
    """Return the content octets of the OBJECT IDENTIFIERs that fill data[start:end] exactly, or None when
    anything else is there."""
    oids = []
    while start < end:
        header = der_header(data, start, end)
        if header is None or header[0] != 0x06 or header[1] == header[2]:
            return None
        oids.append(data[header[1] : header[2]])
        start = header[2]
    return oids


# X509_CERT_AUX fields in order: trust SEQUENCE OF OID, reject [0], alias UTF8String, keyid OCTET STRING, other [1].
AUX_FIELDS = (0x30, 0xA0, 0x0C, 0x04, 0xA1)


# Content octets of the extended key usage OIDs OpenSSL checks a reject list for.
ANY_EKU = bytes.fromhex("551d2500")
SERVER_AUTH = bytes.fromhex("2b06010505070301")
CODE_SIGNING = bytes.fromhex("2b06010505070303")


def rejected_uses(aux: bytes) -> Optional[frozenset[bytes]]:
    """Return the content octets of each OID in an OpenSSL X509_CERT_AUX reject list.

    Returns None when aux does not parse as exactly one well-formed aux structure.
    """
    header = der_header(aux, 0, len(aux))
    if header is None or header[0] != 0x30 or header[2] != len(aux):
        return None
    pos, end = header[1], header[2]
    rejected: frozenset[bytes] = frozenset()
    field = 0
    while pos < end:
        element = der_header(aux, pos, end)
        if element is None:
            return None
        tag, start, stop = element
        while field < len(AUX_FIELDS) and AUX_FIELDS[field] != tag:
            field += 1
        if field == len(AUX_FIELDS):
            return None
        field += 1
        if tag in (0x30, 0xA0):
            oids = oid_contents(aux, start, stop)
            if oids is None:
                return None
            if tag == 0xA0:
                rejected = frozenset(oids)
        pos = stop
    return rejected


def purposes(label: str) -> frozenset[bytes]:
    """Return the uses a known certificate serves: TLS, code signing, or both for the ECC root and AAA."""
    if " TLS " in label:
        return frozenset({SERVER_AUTH})
    if " CS " in label:
        return frozenset({CODE_SIGNING})
    return frozenset({SERVER_AUTH, CODE_SIGNING})


def is_rejected(certificate: KnownCertificate, aux: bytes) -> bool:
    """Return whether OpenSSL rejects the certificate for every use it serves, as obj_trust does.

    obj_trust rejects on anyExtendedKeyUsage or the purpose checked before it reads the trust list.
    """
    rejected = rejected_uses(aux)
    if rejected is None:
        return False
    return ANY_EKU in rejected or purposes(certificate.label) <= rejected


def pem_spans(
    data: Buffer, begin_marker: bytes = PEM_BEGIN, end_marker: bytes = PEM_END
) -> Iterator[tuple[int, int, bytes]]:
    """Yield the body start, END offset and DER of each decodable PEM block, skipping a BEGIN with no
    END nearby.

    A block runs from the last BEGIN before its END, so a truncated block cannot swallow the next one.
    """
    pos = 0
    no_end_until = 0
    while True:
        begin = data.find(begin_marker, pos)
        if begin < 0:
            return
        start = begin + len(begin_marker)
        window_end = min(len(data), start + MAX_PEM_BLOCK_BYTES + len(end_marker))
        end = data.find(end_marker, max(start, no_end_until), window_end)
        if end < 0:
            no_end_until = window_end - len(end_marker) + 1
            pos = start
            continue
        last = data.rfind(begin_marker, start, end)
        if last >= 0:
            start = last + len(begin_marker)
        body = data[start:end].translate(None, PEM_WHITESPACE)
        pos = end + len(end_marker)
        if body.translate(None, BASE64_ALPHABET):
            continue
        try:
            yield start, end, binascii.a2b_base64(body)
        except binascii.Error:
            continue


def pem_blocks(
    data: Buffer, begin_marker: bytes = PEM_BEGIN, end_marker: bytes = PEM_END
) -> Iterator[bytes]:
    """Yield the DER of each decodable PEM block."""
    for _, _, der in pem_spans(data, begin_marker, end_marker):
        yield der


def found_outside(data: Buffer, needle: bytes, spans: list[tuple[int, int]]) -> bool:
    """Return whether needle occurs in data at an offset outside every one of the sorted spans."""
    starts = [start for start, _ in spans]
    pos = data.find(needle)
    while pos >= 0:
        index = bisect.bisect_right(starts, pos) - 1
        if index < 0 or pos >= spans[index][1]:
            return True
        pos = data.find(needle, spans[index][1])
    return False


class Matcher:
    """Finds the known certificates and keys in a buffer."""

    def __init__(
        self,
        certificates: tuple[KnownCertificate, ...] = KNOWN_CERTIFICATES,
        keys: tuple[KnownKey, ...] = KNOWN_KEYS,
    ) -> None:
        self.certificates = certificates
        self.keys = keys

    def scan(self, data: Buffer) -> tuple[CertificateMatch, ...]:
        """Return each known certificate or key found in data once, with its strongest kind."""
        full: set[bytes] = set()
        rejected: set[bytes] = set()
        rejected_spans: list[tuple[int, int]] = []
        ders: list[bytes] = []
        if data.find(PEM_BEGIN) >= 0:
            ders += pem_blocks(data)
        if data.find(TRUSTED_BEGIN) >= 0:
            for start, end, trusted in pem_spans(data, TRUSTED_BEGIN, TRUSTED_END):
                der = first_der_element(trusted)
                if der is None:
                    continue
                known = BY_SHA256.get(hashlib.sha256(der).digest())
                if known is not None and is_rejected(known, trusted[len(der) :]):
                    rejected.add(known.sha256)
                    rejected_spans.append((start, end))
                else:
                    ders.append(der)
        for der in ders:
            certificate = BY_SHA256.get(hashlib.sha256(der).digest())
            if certificate is not None:
                full.add(certificate.sha256)
        for certificate in self.certificates:
            if certificate.sha256 in full:
                continue
            if data.find(certificate.der) >= 0 or found_outside(
                data, certificate.pem_line, rejected_spans
            ):
                full.add(certificate.sha256)
        matches = [
            (ORDER[c.label], CertificateMatch(c.label, c.role, MatchKind.FULL))
            for c in self.certificates
            if c.sha256 in full
        ]
        matches += [
            (ORDER[c.label], CertificateMatch(c.label, c.role, MatchKind.REJECTED))
            for c in self.certificates
            if c.sha256 in rejected and c.sha256 not in full
        ]
        for key in self.keys:
            if any(c.sha256 in full for c in key.certificates):
                continue
            if data.find(key.spki_value) >= 0:
                matches.append(
                    (
                        ORDER[key.label],
                        CertificateMatch(key.label, key.role, MatchKind.KEY_ONLY),
                    )
                )
        return tuple(match for _, match in sorted(matches, key=lambda pair: pair[0]))


class KeystoreKind(Enum):
    JKS = "JKS"
    JCEKS = "JCEKS"
    PKCS12_PLAIN = "PKCS12 without encryption"
    PKCS12_ENCRYPTED = "PKCS12 with encrypted contents"
    UNKNOWN = "unknown"


JKS_MAGIC = bytes.fromhex("feedfeed")
JCEKS_MAGIC = bytes.fromhex("cececece")
# A PKCS12 file opens with a DER SEQUENCE whose length takes two, three or four bytes.
DER_SEQUENCE_LONG = (
    bytes.fromhex("3082"),
    bytes.fromhex("3083"),
    bytes.fromhex("3084"),
)
ENCRYPTED_DATA_OID = bytes.fromhex("06092a864886f70d010706")


def keystore_kind(data: Buffer) -> KeystoreKind:
    """Classify a Java keystore by its first bytes and, for PKCS12, by the encryptedData OID."""
    head = bytes(data[:4])
    if head == JKS_MAGIC:
        return KeystoreKind.JKS
    if head == JCEKS_MAGIC:
        return KeystoreKind.JCEKS
    if head[:2] in DER_SEQUENCE_LONG:
        if data.find(ENCRYPTED_DATA_OID) >= 0:
            return KeystoreKind.PKCS12_ENCRYPTED
        return KeystoreKind.PKCS12_PLAIN
    return KeystoreKind.UNKNOWN


def match_finding(subject: Subject, match: CertificateMatch) -> Finding:
    """Return the finding for one certificate or key match."""
    if match.kind is MatchKind.REJECTED:
        return Finding(
            Level.INFO,
            subject,
            f"holds {match.label} as a rejected entry, not trusted",
        )
    if match.role is Role.CROSS_SIGN_ISSUER_ROOT:
        return Finding(AAA_LEVEL, subject, AAA_DETAIL)
    if match.kind is MatchKind.FULL:
        return Finding(Level.FAIL, subject, f"contains {match.label}")
    if match.role is Role.G3_ROOT:
        return Finding(
            Level.FAIL,
            subject,
            f"contains the public key of {match.label} as a trust anchor",
        )
    return Finding(
        Level.INFO,
        subject,
        f"holds the public key of {match.label} as a blocklist entry, not a certificate",
    )


def bundle_findings(
    subject: Subject, matches: tuple[CertificateMatch, ...]
) -> list[Finding]:
    """Return one finding per match, then PASS when none of them is a FAIL."""
    findings = [match_finding(subject, match) for match in matches]
    if not any(f.level is Level.FAIL for f in findings):
        findings.append(Finding(Level.PASS, subject, NO_COMPROMISED))
    return findings
