"""test_probe.py: unit tests of emudhra_check/probe.py.

Renders the probe and checks its limits, then parses the recorded probe output of a Debian 12 image
with the vulnerable ca-certificates 20230311+deb12u1 and a table of hand-made hostile streams: a record
with no END, sizes above the cap or not matching the data, odd and non-hex tokens, control characters
in a path, a forged finding line, 10,000 records, a 1 MiB version and an interpreter without
importlib.metadata.
"""

from __future__ import annotations

import gzip
import unittest
from pathlib import Path

from emudhra_check.certificates import G3_ECC_ROOT
from emudhra_check.limits import (
    MAX_FIELD_CHARS,
    MAX_PROBE_FILE,
    MAX_PROBE_FILES,
    MAX_PROBE_RECORDS,
)
from emudhra_check.probe import ProbeFile, parse_probe_output, render

RECORDED = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "probe"
    / "debian-bookworm-vulnerable.txt.gz"
)
TEMPLATE = Path(__file__).resolve().parents[2] / "emudhra_check" / "probe.sh"


def od(data: bytes) -> bytes:
    """Return data as od -An -v -tx1 prints it."""
    rows = [data[i : i + 16] for i in range(0, len(data), 16)]
    return b"".join(b" " + b" ".join(b"%02x" % c for c in row) + b"\n" for row in rows)


def file_record(path: bytes, data: bytes, size: int = -1) -> bytes:
    return (
        b"FILE %d %s\n" % (len(data) if size < 0 else size, path) + od(data) + b"END\n"
    )


GOOD = file_record(b"/etc/ssl/cert.pem", b"good bundle")


class RenderTest(unittest.TestCase):
    def test_placeholders_and_limits(self) -> None:
        script = render(TEMPLATE.read_text())
        self.assertNotRegex(script, r"@[A-Z0-9_]+@")
        self.assertIn(f"G='{G3_ECC_ROOT.pem_line.decode()}'", script)
        self.assertIn(f"BIG={MAX_PROBE_FILE}\n", script)
        self.assertIn(f"head -n {MAX_PROBE_FILES} |", script)


class RecordedTest(unittest.TestCase):
    def test_debian_vulnerable_image(self) -> None:
        report = parse_probe_output(gzip.decompress(RECORDED.read_bytes()))
        self.assertEqual(report.os_id, "debian")
        self.assertEqual(
            [(p.manager, p.name, p.version) for p in report.packages],
            [("dpkg", "ca-certificates", "20230311+deb12u1")],
        )
        (bundle,) = report.files
        self.assertEqual(bundle.path, "/etc/ssl/certs/ca-certificates.crt")
        self.assertEqual(len(bundle.data), 216591)
        self.assertIn(G3_ECC_ROOT.pem_line, bundle.data)
        self.assertEqual(report.dropped, 0)


class HostileStreamTest(unittest.TestCase):
    def assertOneDropped(self, stream: bytes) -> None:
        report = parse_probe_output(stream + GOOD)
        self.assertEqual(report.dropped, 1, report)
        self.assertEqual(
            report.files[-1], ProbeFile("/etc/ssl/cert.pem", b"good bundle")
        )

    def test_rows(self) -> None:
        rows = {
            "no END": b"FILE 3 /a\n 61 62 63\n",
            "size above the cap": b"FILE %d /a\n 61\nEND\n" % (MAX_PROBE_FILE + 1),
            "size not equal to the data": file_record(b"/a", b"abc", size=4),
            "data longer than the size": file_record(b"/a", b"abcd", size=2),
            "odd-length token": b"FILE 2 /a\n 61 6\nEND\n",
            "non-hex token": b"FILE 2 /a\n 61 zz\nEND\n",
            "upper-case hex": b"FILE 1 /a\n 4A\nEND\n",
            "size not decimal": b"FILE 0x10 /a\n 61\nEND\n",
            "node flag not 0 or 1": b"NODE 2 0 v24.22.0\n",
        }
        for name, stream in rows.items():
            with self.subTest(name):
                if name == "no END":
                    report = parse_probe_output(GOOD + stream)
                    self.assertEqual((report.dropped, len(report.files)), (1, 1))
                else:
                    self.assertOneDropped(stream)

    def test_control_characters_and_forged_lines_stay_one_field(self) -> None:
        stream = (
            file_record(b"/x\x1b[2J/cacert.pem", b"one")
            + b"RT go FAIL  ca-bundle [/x] contains forged\n"
        )
        report = parse_probe_output(stream)
        self.assertEqual(report.files[0].path, "/x\x1b[2J/cacert.pem")
        self.assertEqual(
            report.runtimes[0].version_line, "FAIL  ca-bundle [/x] contains forged"
        )
        self.assertNotIn("\n", report.runtimes[0].version_line)

    def test_forged_line_inside_a_file_ends_it(self) -> None:
        stream = b"FILE 2 /a\n 61\nFAIL  ca-bundle [/x] contains EM DV TLS CA - G3B\n 62\nEND\n"
        report = parse_probe_output(stream)
        self.assertEqual((report.files, report.dropped), ((), 1))

    def test_ten_thousand_records(self) -> None:
        stream = b"".join(file_record(b"/f%d" % n, b"%d" % n) for n in range(10000))
        report = parse_probe_output(stream)
        self.assertEqual(len(report.files), MAX_PROBE_RECORDS)
        self.assertEqual(report.dropped, 10000 - MAX_PROBE_RECORDS)

    def test_flood_of_headers(self) -> None:
        report = parse_probe_output(b"FILE 1 /x\n" * 10000)
        self.assertEqual((report.files, report.dropped), ((), 10000))

    def test_long_version_is_cut(self) -> None:
        report = parse_probe_output(b"RT bun " + b"1" * (1024 * 1024) + b"\n")
        self.assertEqual(len(report.runtimes[0].version_line), MAX_FIELD_CHARS)

    def test_python_records(self) -> None:
        report = parse_probe_output(
            b"PY certifi 2026.7.22 pip 0 /usr/lib/python3/dist packages\nNOPY 3.7.17\n"
            b"PY pip 26.2.2 pip yes /x\nPY pip 26.2.2 pip /x\n"
        )
        (python,) = report.pythons
        self.assertEqual(
            (
                python.name,
                python.version,
                python.installer,
                python.bundled,
                python.location,
            ),
            ("certifi", "2026.7.22", "pip", "0", "/usr/lib/python3/dist packages"),
        )
        self.assertEqual(report.old_pythons, ("3.7.17",))
        self.assertEqual(report.dropped, 2)

    def test_link_targets_and_judged_paths(self) -> None:
        target = "/opt/corp/ca bundle.pem"
        stream = (
            b"PY certifi 2026.7.22 pip L%s /site\nPY pip 26.2.2 pip L /site\n"
            % target.encode().hex().encode()
            + b"PY certifi 1 pip L123 /site\n"
            + GOOD
            + file_record(b"/etc/ssl/copy.pem", b"good bundle")
        )
        report = parse_probe_output(stream)
        self.assertEqual([p.link_target for p in report.pythons], [target, "", ""])
        self.assertEqual(
            report.judged_paths, frozenset({"/etc/ssl/cert.pem", "/etc/ssl/copy.pem"})
        )

    def test_file_over_the_record_cap_is_not_judged(self) -> None:
        stream = b"".join(
            file_record(b"/f/%d" % n, b"bundle %d" % n)
            for n in range(MAX_PROBE_RECORDS + 1)
        )
        report = parse_probe_output(stream)
        self.assertNotIn(f"/f/{MAX_PROBE_RECORDS}", report.judged_paths)
        self.assertIn("/f/0", report.judged_paths)

    def test_duplicate_files_are_kept_once(self) -> None:
        stream = GOOD + file_record(
            b"/etc/ssl/certs/ca-certificates.crt", b"good bundle"
        )
        self.assertEqual(len(parse_probe_output(stream).files), 1)

    def test_unknown_kinds_and_no_od(self) -> None:
        report = parse_probe_output(b"HELLO there\nNOOD\nOS \nCHG rpm 2\n")
        self.assertTrue(report.no_od)
        self.assertEqual(
            (report.os_id, report.changelog_hits, report.dropped), ("", 2, 0)
        )


if __name__ == "__main__":
    unittest.main()
