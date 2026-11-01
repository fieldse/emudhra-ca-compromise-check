"""make_binaries.py: builds the fake native programs for the check's binary container cases.

Run inside the container that then runs the check, with the set name as the argument. Each program
is an ELF magic, padding and a payload: Go build information, cargo source paths, or certificates
and keys. The keys come from openssl's output in /out/keys and the certificates from /out/bundles,
never from the check's own tables. Nothing written here is ever run.
"""

import os
import sys

ELF = b"\x7fELF" + b"\x00" * 60
GO_MAGIC = b"\xff Go buildinf:"
START_SENTINEL = bytes.fromhex("3077af0c9274080241e1c107e6d618e6")
END_SENTINEL = bytes.fromhex("f932433186182072008242104116d8f2")
FALLBACK = "golang.org/x/crypto/x509roots/fallback"
OLD_FALLBACK = "v0.0.0-20260916154351-b853e4b620cd"
NEW_FALLBACK = "v0.0.0-20261020153306-9f2b28d4331a"
PAD = b"\x00" * 4096


def read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def write(path: str, data: bytes, mode: int = 0o755) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    os.chmod(path, mode)


def der_items(data: bytes) -> list:
    """Split concatenated DER values into (whole value, content octets) pairs."""
    items, start = [], 0
    while start < len(data):
        first = data[start + 1]
        size = 1 if first < 0x80 else 1 + (first & 0x7F)
        length = (
            first
            if first < 0x80
            else int.from_bytes(data[start + 2 : start + size + 1], "big")
        )
        end = start + 1 + size + length
        items.append((data[start:end], data[start + 1 + size : end]))
        start = end
    return items


def spki_value(path: str) -> bytes:
    """Return the content octets of the SubjectPublicKeyInfo openssl wrote to path."""
    return der_items(read(path))[0][1]


def varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | 0x80 if value else byte)
        if not value:
            return bytes(out)


def go_program(version: str, *deps: str, legacy: bool = False) -> bytes:
    """Return a program holding a Go build information block for the toolchain and dependencies."""
    header = GO_MAGIC + bytes([8, 0 if legacy else 2]) + b"\x00" * 16
    lines = "path\texample.com/hello\nmod\texample.com/hello\t(devel)\t\n"
    lines += "".join(f"dep\t{d}\th1:fixture=\n" for d in deps)
    info = START_SENTINEL + lines.encode() + END_SENTINEL
    body = varint(len(version)) + version.encode() + varint(len(info)) + info
    return ELF + PAD + header + (b"" if legacy else body) + PAD


def go_set(base: str) -> None:
    g3 = read("/out/bundles/g3-ecc-root.der")
    write(
        f"{base}/bin/go-old", go_program("go1.27.2", f"{FALLBACK}\t{OLD_FALLBACK}") + g3
    )
    write(f"{base}/bin/go-new", go_program("go1.27.3", f"{FALLBACK}\t{NEW_FALLBACK}"))
    write(f"{base}/bin/go-legacy", go_program("", legacy=True))


def rust_set(base: str) -> None:
    g3_key = spki_value("/out/keys/g3-ecc-root.der")
    blocklist = b"".join(
        content for _, content in der_items(read("/out/keys/intermediates.der"))
    )
    write(
        f"{base}/bin/rust-old",
        ELF + b"/rustls-webpki-0.103.13/src/lib.rs\x00" + PAD + g3_key,
    )
    write(
        f"{base}/bin/rust-fixed",
        ELF + b"/rustls-webpki-0.103.16/src/lib.rs\x00" + PAD + blocklist,
    )
    write(
        f"{base}/bin/rust-wrapper",
        ELF + b"/webpki-roots-0.26.11/src/lib.rs\x00/webpki-roots-1.0.9/src/lib.rs\x00",
    )


def main() -> None:
    case = sys.argv[1]
    if case == "go":
        go_set("/tmp/fx")
    elif case == "rust":
        rust_set("/tmp/fx")
    elif case == "cargo-home":
        write("/tmp/t/home/.cargo/bin/hello", go_program("go1.27.2"))
    else:
        sys.exit(f"unknown set: {case}")


if __name__ == "__main__":
    os.umask(0o022)
    main()
