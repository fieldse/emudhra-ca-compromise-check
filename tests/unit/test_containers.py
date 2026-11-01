"""test_containers.py: unit tests of emudhra_check/detections/containers.py.

Runs PodmanImages over a fake Images port: the recorded probe of a vulnerable Debian image, Node,
runtime, Python and package records, keystores and bundles, and the no-shell, failed, timed-out and
overrun statuses, which judge nothing from the image.
"""

from __future__ import annotations

import dataclasses
import gzip
import unittest

from emudhra_check.certificates import G3_ECC_ROOT
from emudhra_check.detections.containers import PodmanImages
from emudhra_check.detections.ports import ProbeRun, ProbeStatus
from emudhra_check.report import Level
from tests.unit.fakes import lines, make_context
from tests.unit.test_certificates import pem
from tests.unit.test_probe import RECORDED, file_record

IMAGE = "localhost/x:1"
WHERE = f"image:{IMAGE}"
G3_LABEL = G3_ECC_ROOT.label


class FakeImages:
    def __init__(self, runs: dict[str, ProbeRun]) -> None:
        self.names = tuple(runs)
        self.runs = runs

    def probe(self, name: str) -> ProbeRun:
        return self.runs[name]


def image_lines(output: bytes, status: ProbeStatus = ProbeStatus.OK) -> list[str]:
    ctx = dataclasses.replace(
        make_context(), images=FakeImages({IMAGE: ProbeRun(status, output)})
    )
    return lines(PodmanImages(), ctx)


class PodmanImagesTest(unittest.TestCase):
    def test_no_images_without_c(self) -> None:
        self.assertEqual(lines(PodmanImages(), make_context()), [])

    def test_recorded_vulnerable_image(self) -> None:
        got = image_lines(gzip.decompress(RECORDED.read_bytes()))
        self.assertIn(
            f"FAIL  ca-certificates [{WHERE}] found 20230311+deb12u1", " ".join(got)
        )
        self.assertIn(
            f"FAIL  ca-bundle [{WHERE} /etc/ssl/certs/ca-certificates.crt] contains {G3_LABEL}",
            got,
        )

    def test_runtime_and_package_records(self) -> None:
        stream = (
            b"NODE 1 1 v24.22.0\nRT bun 1.4.3\nRT deno deno 2.9.8 (stable, release, x86_64)\n"
            b"RT go go version go1.27.2 linux/amd64\nPY certifi 2026.7.22 pip 1 /usr/lib/python3/site-packages\n"
            b"PY pip 26.2.2 dpkg 1 /usr/lib/python3/dist-packages\nNOPY 3.7.17\nOS alpine\n"
            b"PKG apk ca-certificates-bundle 20260413-r0\n"
        )
        got = image_lines(stream)
        expected_starts = [
            f"FAIL  node [{WHERE}] found 24.22.0",
            f"INFO  node [{WHERE}] binary bundles emSign ECC Root CA - G3",
            f"FAIL  bun [{WHERE}] found 1.4.3",
            f"PASS  deno [{WHERE}] found 2.9.8",
            f"FAIL  go [{WHERE}] found 1.27.2",
            f"FAIL  certifi [{WHERE}] found 2026.7.22",
            f"INFO  pip [{WHERE}] found 26.2.2, installed by dpkg",
            f"WARN  python3 [{WHERE}] 3.7.17 predates importlib.metadata",
            f"FAIL  ca-certificates-bundle [{WHERE}] found 20260413-r0",
        ]
        self.assertEqual(len(got), len(expected_starts), got)
        for line, start in zip(got, expected_starts):
            self.assertTrue(line.startswith(start), (line, start))

    def test_python_packages_without_their_own_bundle(self) -> None:
        stream = (
            b"PY certifi 2025.1.31 debian 0 /usr/lib/python3/dist-packages\n"
            b"PY pip 23.0.1 unknown 0 /usr/lib/python3/dist-packages\n"
            b"PY certifi 2026.7.22 unknown 1 /usr/local/lib/python3.13/site-packages\n"
            b"PY uv 0.13.3 unknown - /usr/local/lib/python3.13/site-packages\n"
            b"PY certifi 2026.7.22 pip L /opt/lib/site-packages\n"
        )
        self.assertEqual(
            image_lines(stream),
            [
                f"INFO  certifi [{WHERE}] found 2025.1.31, no bundled cacert.pem, patched to use the system store",
                f"INFO  pip [{WHERE}] found 23.0.1, no bundled cacert.pem, patched to use the system store",
                f"FAIL  certifi [{WHERE}] found 2026.7.22, fixed 2026.10.18 (vendors its own CA bundle)",
                f"FAIL  uv [{WHERE}] found 0.13.3, fixed 0.13.4 (vendors its own CA bundle)",
                f"FAIL  certifi [{WHERE}] found 2026.7.22, fixed 2026.10.18 (vendors its own CA bundle)",
            ],
        )

    def linked_stream(self, target: bytes) -> bytes:
        return (
            b"PY certifi 2026.7.22 pip L%s /usr/lib/python3/site-packages\n"
            % target.hex().encode()
            + b"LINK "
            + target
            + b"\n"
        )

    def test_linked_bundle_is_judged_by_its_dumped_target(self) -> None:
        stream = self.linked_stream(b"/opt/corp/ca.pem") + file_record(
            b"/opt/corp/ca.pem", pem(G3_ECC_ROOT.der)
        )
        self.assertEqual(
            image_lines(stream),
            [
                f"INFO  certifi [{WHERE}] found 2026.7.22, its cacert.pem links outside the package,"
                " judged by the bundle it resolves to",
                f"FAIL  ca-bundle [{WHERE} /opt/corp/ca.pem] contains {G3_LABEL}",
            ],
        )

    def test_linked_target_with_the_content_of_another_dumped_file(self) -> None:
        bundle = pem(G3_ECC_ROOT.der)
        stream = (
            file_record(b"/etc/ssl/cert.pem", bundle)
            + self.linked_stream(b"/opt/corp/ca.pem")
            + file_record(b"/opt/corp/ca.pem", bundle)
        )
        got = image_lines(stream)
        self.assertIn(
            f"INFO  certifi [{WHERE}] found 2026.7.22, its cacert.pem links outside the package,"
            " judged by the bundle it resolves to",
            got,
        )
        self.assertIn(
            f"FAIL  ca-bundle [{WHERE} /etc/ssl/cert.pem] contains {G3_LABEL}", got
        )

    def test_linked_target_without_a_record_falls_back_to_the_version(self) -> None:
        for extra in (b"", b"BIG 99999999 /opt/corp/ca.pem\n"):
            with self.subTest(extra=extra):
                got = image_lines(self.linked_stream(b"/opt/corp/ca.pem") + extra)
                self.assertEqual(
                    got[0],
                    f"FAIL  certifi [{WHERE}] found 2026.7.22, fixed 2026.10.18 (vendors its own CA bundle)",
                )

    def test_suse_records_only_on_suse(self) -> None:
        stream = b"OS opensuse-leap\nPKG rpm ca-certificates 2.0-1\nPKG suse ca-certificates-mozilla 2.92\n"
        got = image_lines(stream)
        self.assertEqual(
            got, [f"PASS  ca-certificates-mozilla [{WHERE}] found 2.92, fixed 2.92"]
        )

    def test_keystore_and_bundle_files(self) -> None:
        jks = bytes.fromhex("feedfeed") + b"\x00" * 12 + G3_ECC_ROOT.der
        stream = file_record(b"/opt/jdk/lib/security/cacerts", jks) + file_record(
            b"/etc/ssl/cert.pem", b"# empty\n"
        )
        self.assertEqual(
            image_lines(stream),
            [
                f"FAIL  java keystore [{WHERE} /opt/jdk/lib/security/cacerts] contains {G3_LABEL}",
                f"PASS  ca-bundle [{WHERE} /etc/ssl/cert.pem] contains no compromised eMudhra certificate",
            ],
        )

    def test_big_no_od_and_dropped(self) -> None:
        got = image_lines(b"BIG 99999999 /huge.pem\nNOOD\nFILE 9 /x\n")
        self.assertEqual(
            got,
            [
                f"INFO  probe [{WHERE}] image has no od, bundles and keystores not inspected",
                f"INFO  ca-bundle [{WHERE} /huge.pem] too large to scan (99999999 bytes), skipped",
                f"WARN  probe [{WHERE}] dropped 1 malformed records",
            ],
        )

    def test_statuses(self) -> None:
        forged = b"OS debian\nPKG dpkg ca-certificates 20230311+deb12u1\n"
        self.assertEqual(
            image_lines(forged, ProbeStatus.NO_SHELL),
            [f"SKIP  {WHERE} has no shell, not inspected"],
        )
        for status, reason in (
            (ProbeStatus.FAILED, "failed"),
            (ProbeStatus.TIMEOUT, "timed out"),
            (ProbeStatus.OVERRUN, "output over its cap"),
        ):
            with self.subTest(status=status):
                got = image_lines(forged, status)
                self.assertEqual(
                    got,
                    [
                        f"WARN  probe [{WHERE}] did not finish ({reason}), image not inspected"
                    ],
                )

    def test_image_with_no_records(self) -> None:
        self.assertEqual(
            image_lines(b""),
            [f"INFO  probe [{WHERE}] returned no records, nothing inspected"],
        )
        self.assertEqual(image_lines(b"HELLO\n"), image_lines(b""))
        self.assertEqual(image_lines(b"OS debian\n"), [])

    def test_findings_name_the_image(self) -> None:
        ctx = dataclasses.replace(
            make_context(),
            images=FakeImages({IMAGE: ProbeRun(ProbeStatus.OK, b"OS debian\n")}),
        )
        self.assertTrue(
            all(f.level is not Level.ERROR for f in PodmanImages().run(ctx))
        )


if __name__ == "__main__":
    unittest.main()
