"""lab.py - test fixtures for the eMudhra detection rules.

Runs inside the test container. Recovers each compromised intermediate's private key by
searching 1..255, signs a test leaf for test.invalid with it, serves the chain with
openssl s_server on loopback and captures each handshake to a pcap. Also writes the
PEM, DER and keystore fixtures the YARA tests scan.
"""

import base64
import datetime
import pathlib
import subprocess
import sys
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

CERTS = pathlib.Path(__file__).resolve().parent.parent / "rules" / "certs"
PORT = 4433


def load_pems(path):
    """Return every certificate in a PEM file."""
    return x509.load_pem_x509_certificates(path.read_bytes())


def recover_key(cert):
    """Return the private key of a certificate whose key is below 256, or None."""
    target = cert.public_key().public_numbers()
    for d in range(1, 256):
        key = ec.derive_private_key(d, ec.SECP384R1())
        if key.public_key().public_numbers() == target:
            return d, key
    return None, None


def by_name(certs, cn, cross_signed):
    """Pick the intermediate with this common name, eMudhra-issued or Sectigo cross-signed."""
    for c in certs:
        name = c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        issuer = c.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if name == cn and (issuer == "AAA Certificate Services") == cross_signed:
            return c
    raise SystemExit(f"lab.py: no certificate {cn}")


def make_leaf(issuer_cert, issuer_key, eku):
    """Sign a one-day leaf for test.invalid under the given issuer; return (cert, key)."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    ski = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.invalid")]))
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("test.invalid")]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), critical=False)
        .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
        .sign(issuer_key, hashes.SHA384())
    )
    return cert, key


def make_control_chain():
    """Build an unrelated CA and leaf, for the negative control; return (leaf, key, ca)."""
    ca_key = ec.generate_private_key(ec.SECP384R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Control Test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA384())
    )
    leaf, key = make_leaf(ca, ca_key, x509.oid.ExtendedKeyUsageOID.SERVER_AUTH)
    return leaf, key, ca


def write_pem(path, *certs):
    """Write certificates to a PEM file."""
    path.write_bytes(b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs))


def write_key(path, key):
    """Write a private key to an unencrypted PEM file."""
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))


def capture(out, name, leaf, key, chain, tls_flag):
    """Serve leaf+chain on loopback, complete one handshake and save it as <name>.pcap."""
    d = out / name
    d.mkdir(parents=True, exist_ok=True)
    write_pem(d / "leaf.pem", leaf)
    write_key(d / "leaf.key", key)
    write_pem(d / "chain.pem", *chain)
    pcap = out / f"{name}.pcap"
    dump = subprocess.Popen(["tcpdump", "-i", "lo", "-U", "-w", str(pcap), f"tcp port {PORT}"],
                            stderr=subprocess.DEVNULL)
    server = subprocess.Popen(["openssl", "s_server", "-accept", str(PORT), "-cert", str(d / "leaf.pem"),
                               "-key", str(d / "leaf.key"), "-cert_chain", str(d / "chain.pem"),
                               tls_flag, "-naccept", "1", "-quiet"],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)
    subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{PORT}", tls_flag,
                    "-servername", "test.invalid"],
                   input=b"", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
    server.wait(timeout=20)
    time.sleep(1)
    dump.terminate()
    dump.wait(timeout=10)
    print(f"capture {name}: {pcap.stat().st_size} bytes")


def yara_fixtures(out, inter, roots):
    """Write PEM bundles wrapped at 64 and 76 columns, CRLF and DER copies for the YARA tests."""
    y = out / "yara"
    y.mkdir(parents=True, exist_ok=True)
    for i, c in enumerate(inter + roots):
        der = c.public_bytes(serialization.Encoding.DER)
        (y / f"cert{i:02d}.der").write_bytes(der)
        b64 = base64.b64encode(der).decode()
        for width, eol in ((64, "\n"), (76, "\r\n")):
            lines = [b64[j:j + width] for j in range(0, len(b64), width)]
            body = eol.join(["-----BEGIN CERTIFICATE-----", *lines, "-----END CERTIFICATE-----"]) + eol
            (y / f"cert{i:02d}-w{width}.pem").write_text(body, newline="")


def main():
    """Recover the keys, then write the TLS captures and file fixtures to the output directory."""
    out = pathlib.Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    inter = load_pems(CERTS / "emudhra-g3-compromised-intermediates.pem")
    roots = load_pems(CERTS / "emudhra-g3-roots.pem")
    for c in inter:
        d, _ = recover_key(c)
        cn = c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        print(f"key {cn}: {d}")
        if d is None:
            raise SystemExit(f"lab.py: no small key for {cn}")

    eku = x509.oid.ExtendedKeyUsageOID
    dv_b = by_name(inter, "EM DV TLS CA - G3B", cross_signed=False)
    _, dv_b_key = recover_key(dv_b)
    leaf_a, key_a = make_leaf(dv_b, dv_b_key, eku.SERVER_AUTH)
    cs_c = by_name(inter, "EM OV CS CA - G3C", cross_signed=True)
    _, cs_c_key = recover_key(cs_c)
    leaf_b, key_b = make_leaf(cs_c, cs_c_key, eku.CODE_SIGNING)
    ctl_leaf, ctl_key, ctl_ca = make_control_chain()
    ecc_root = roots[0]

    for name, leaf, issuer in (("a", leaf_a, dv_b), ("b", leaf_b, cs_c)):
        write_pem(out / f"verify-{name}-leaf.pem", leaf)
        write_pem(out / f"verify-{name}-issuer.pem", issuer)

    capture(out, "tls12-dv-g3b-with-root", leaf_a, key_a, [dv_b, ecc_root], "-tls1_2")
    capture(out, "tls12-cs-g3c-cross-signed", leaf_b, key_b, [cs_c], "-tls1_2")
    capture(out, "tls12-control", ctl_leaf, ctl_key, [ctl_ca], "-tls1_2")
    capture(out, "tls13-dv-g3b-with-root", leaf_a, key_a, [dv_b, ecc_root], "-tls1_3")
    yara_fixtures(out, inter, roots)


if __name__ == "__main__":
    main()
