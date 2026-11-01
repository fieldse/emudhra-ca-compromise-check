"""test_buildinfo.py: unit tests of emudhra_check/buildinfo.py.

Classifies hand-built binaries, reads Go build information from inline, legacy and broken headers,
collects Rust crate versions, Node release and Electron version strings, and reads Info.plist
versions, including the digit pre-check that guards plistlib on interpreters without a digit limit.
"""

from __future__ import annotations

import plistlib
import unittest

from emudhra_check.buildinfo import (
    GO_MAGIC,
    BinaryKind,
    GoModule,
    classify,
    electron_app_version,
    electron_version_string,
    go_build_info,
    node_release_version,
    rust_crate_versions,
)

ELF = b"\x7fELF" + b"\x00" * 60
START_SENTINEL = bytes.fromhex("3077af0c9274080241e1c107e6d618e6")
END_SENTINEL = bytes.fromhex("f932433186182072008242104116d8f2")
FALLBACK = "golang.org/x/crypto/x509roots/fallback"
OLD_FALLBACK = "v0.0.0-20260916154351-b853e4b620cd"


def varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def modinfo(*deps: str) -> bytes:
    lines = "path\texample.com/hello\nmod\texample.com/hello\t(devel)\t\n" + "".join(
        d + "\n" for d in deps
    )
    return START_SENTINEL + lines.encode() + END_SENTINEL


def go_header(flags: int = 2, pointer_size: int = 8) -> bytes:
    return GO_MAGIC + bytes([pointer_size, flags]) + b"\x00" * 16


def go_blob(version: bytes = b"go1.27.2", info: bytes = b"") -> bytes:
    body = varint(len(version)) + version + varint(len(info)) + info
    return ELF + go_header() + body + b"\x00" * 32


class ClassifyTest(unittest.TestCase):
    def test_rows(self) -> None:
        node = (
            b"https://nodejs.org/download/release/v24.22.1/node-v24.22.1-headers.tar.gz"
        )
        rows = [
            (b"#!/bin/sh\n" + GO_MAGIC, BinaryKind.OTHER),
            (ELF + GO_MAGIC, BinaryKind.GO),
            (
                bytes.fromhex("cffaedfe") + b"Chrome/140 Electron/44.9.1 " + node,
                BinaryKind.ELECTRON,
            ),
            (ELF + node, BinaryKind.NODE),
            (ELF + b"/rustls-webpki-0.103.16/src/lib.rs", BinaryKind.RUST),
            (ELF + b"/webpki-roots-" * 1000, BinaryKind.OTHER),
            (ELF, BinaryKind.OTHER),
            (b"", BinaryKind.OTHER),
        ]
        for data, kind in rows:
            with self.subTest(kind=kind, data=data[:40]):
                self.assertIs(classify(data), kind)


class GoBuildInfoTest(unittest.TestCase):
    def test_inline_header_with_the_fallback_module(self) -> None:
        info = go_build_info(
            go_blob(info=modinfo(f"dep\t{FALLBACK}\t{OLD_FALLBACK}\th1:x="))
        )
        assert info is not None
        self.assertEqual(info.go_version, "go1.27.2")
        self.assertFalse(info.legacy)
        self.assertEqual(info.modules, (GoModule(FALLBACK, OLD_FALLBACK),))

    def test_replacement_replaces_the_dependency_before_it(self) -> None:
        info = go_build_info(
            go_blob(
                info=modinfo(
                    f"dep\t{FALLBACK}\tv0.0.0\th1:x=",
                    f"=>\t{FALLBACK}\t{OLD_FALLBACK}\th1:y=",
                )
            )
        )
        assert info is not None
        self.assertEqual(info.modules, (GoModule(FALLBACK, OLD_FALLBACK),))

    def test_version_with_experiment_suffix(self) -> None:
        info = go_build_info(go_blob(b"go1.27.3 X:boringcrypto"))
        assert info is not None
        self.assertEqual(info.go_version, "go1.27.3")

    def test_legacy_header(self) -> None:
        info = go_build_info(ELF + go_header(flags=0) + b"\x00" * 32)
        assert info is not None
        self.assertTrue(info.legacy)

    def test_eleven_byte_varint(self) -> None:
        self.assertIsNone(
            go_build_info(ELF + go_header() + b"\xff" * 10 + b"\x01" + b"go1.27.2")
        )

    def test_length_beyond_the_data(self) -> None:
        self.assertIsNone(go_build_info(ELF + go_header() + varint(500) + b"go1.27.2"))

    def test_version_longer_than_its_cap(self) -> None:
        self.assertIsNone(go_build_info(go_blob(b"go1." + b"9" * 100)))

    def test_magic_followed_by_garbage(self) -> None:
        self.assertIsNone(go_build_info(ELF + GO_MAGIC + b"\x13\x37garbage"))

    def test_only_the_second_magic_parses(self) -> None:
        data = ELF + GO_MAGIC + b"\x09\x02" + b"\x00" * 40 + go_blob(b"go1.27.3")
        info = go_build_info(data)
        assert info is not None
        self.assertEqual(info.go_version, "go1.27.3")

    def test_no_magic(self) -> None:
        self.assertIsNone(go_build_info(ELF))


class RustCrateVersionsTest(unittest.TestCase):
    def test_versions_by_crate(self) -> None:
        data = (
            ELF
            + b"/rustls-webpki-0.103.13/src/lib.rs\x00/rustls-webpki-0.103.13/src/x.rs"
            + b"/webpki-roots-0.26.11/src/lib.rs/webpki-roots-1.0.9/src/lib.rs"
            + b"/webpki-root-certs-1.0.0-alpha.1/src/lib.rs"
        )
        self.assertEqual(
            rust_crate_versions(data),
            {
                "rustls-webpki": frozenset({"0.103.13"}),
                "webpki-roots": frozenset({"0.26.11", "1.0.9"}),
                "webpki-root-certs": frozenset({"1.0.0-alpha.1"}),
            },
        )

    def test_paths_without_a_version(self) -> None:
        self.assertEqual(
            rust_crate_versions(b"/webpki-roots-/webpki-roots-x.y.z/" * 100), {}
        )


class ReleaseStringsTest(unittest.TestCase):
    def test_node_release_needs_the_same_version_twice(self) -> None:
        url = b"nodejs.org/download/release/v%s/node-v%s-headers.tar.gz"
        self.assertEqual(
            node_release_version(url % (b"24.22.1", b"24.22.1")), "24.22.1"
        )
        self.assertIsNone(node_release_version(url % (b"24.22.1", b"24.22.0")))
        self.assertIsNone(
            node_release_version(b"nodejs.org/download/release/v24/node-v24")
        )

    def test_electron_version(self) -> None:
        self.assertEqual(electron_version_string(b"x Electron/43.8.1 y"), "43.8.1")
        self.assertIsNone(electron_version_string(b"Electron/43.8"))


def xml_plist(body: str) -> bytes:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict>'
        + body
        + "</dict></plist>"
    ).encode()


class ElectronAppVersionTest(unittest.TestCase):
    def test_binary_and_xml_plists(self) -> None:
        binary = plistlib.dumps({"CFBundleVersion": "44.9.1"}, fmt=plistlib.FMT_BINARY)
        self.assertEqual(electron_app_version(binary), "44.9.1")
        xml = xml_plist("<key>CFBundleVersion</key><string>43.8.0</string>")
        self.assertEqual(electron_app_version(xml), "43.8.0")

    def test_unreadable_plists(self) -> None:
        rows = [
            bytes(range(256)) * 4,
            b'<?xml version="1.0"?><!DOCTYPE plist [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;">]>'
            + b"<plist><dict><key>CFBundleVersion</key><string>&b;</string></dict></plist>",
            plistlib.dumps({"CFBundleVersion": 44}, fmt=plistlib.FMT_BINARY),
            xml_plist(
                "<key>CFBundleVersion</key><integer>" + "9" * 100000 + "</integer>"
            ),
            plistlib.dumps(["44.9.1"], fmt=plistlib.FMT_BINARY),
            b"",
        ]
        for data in rows:
            with self.subTest(data=data[:40]):
                self.assertIsNone(electron_app_version(data))

    def test_digit_pre_check(self) -> None:
        xml = xml_plist(
            "<key>CFBundleVersion</key><string>44.9.1</string><key>N</key><integer>"
            + "1" * 33
            + "</integer>"
        )
        self.assertEqual(plistlib.loads(xml)["CFBundleVersion"], "44.9.1")
        self.assertIsNone(electron_app_version(xml))


if __name__ == "__main__":
    unittest.main()
