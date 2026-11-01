"""test_language_packages.py: unit tests of the Python package detections in language_packages.py.

Covers the certifi, pip and uv verdicts by installer, dist-info directories with their INSTALLER and
bundle, pins in requirements files and locks, the host python3 child (its arguments, the NOPY and
failure rows, the bundles it names) and the uv on PATH by version and binary content.
"""

from __future__ import annotations

import base64
import unittest
from pathlib import Path

from emudhra_check.certificates import G3_ECC_ROOT
from emudhra_check.detections.language_packages import (
    CHILD_SCRIPT,
    HostPythonPackages,
    PythonDistInfo,
    PythonPins,
    UvHost,
    python_package_finding,
)
from emudhra_check.report import Level, Subject
from emudhra_check.scope import FileId, IndexedDir
from tests.unit.fakes import (
    FakeCommands,
    FakeFiles,
    FakeHost,
    hostenv,
    lines,
    located,
    make_context,
    result,
)

SITE = "/r/lib/python3.13/site-packages"
OLD_BUNDLE = (
    b"-----BEGIN CERTIFICATE-----\n"
    + base64.encodebytes(G3_ECC_ROOT.der)
    + b"-----END CERTIFICATE-----\n"
)


def dist_dir(name: str) -> IndexedDir:
    return IndexedDir(Path(f"{SITE}/{name}"), FileId(3, hash(name) % 1000))


class VerdictTest(unittest.TestCase):
    def test_vendoring_installers_judge_the_version(self) -> None:
        for installer in ("pip", "uv", "poetry", "pdm", "pipenv", "unknown", ""):
            with self.subTest(installer=installer):
                got = python_package_finding(
                    Subject("certifi", "x"), "2026.7.22", installer=installer
                )
                self.assertEqual(got[0].level, Level.FAIL)

    def test_first_fix_recommends_the_next(self) -> None:
        got = python_package_finding(
            Subject("certifi", "x"), "2026.10.18", installer="pip"
        )
        self.assertEqual([f.level for f in got], [Level.PASS, Level.INFO])
        self.assertEqual(
            got[1].detail, "2026.10.19 or later restores unaffected emSign roots"
        )
        self.assertEqual(
            len(
                python_package_finding(
                    Subject("certifi", "x"), "2026.10.19", installer="pip"
                )
            ),
            1,
        )

    def test_distro_installer_defers_to_the_bundle(self) -> None:
        got = python_package_finding(Subject("pip", "x"), "23.0.1", installer="brew")
        self.assertEqual(got[0].level, Level.INFO)
        self.assertIn("judged by the bundle it resolves to", got[0].detail)

    def test_pip_and_uv(self) -> None:
        self.assertIs(
            python_package_finding(Subject("pip", "x"), "26.2.1", installer="pip")[
                0
            ].level,
            Level.FAIL,
        )
        self.assertIs(
            python_package_finding(Subject("pip", "x"), "26.2.2", installer="pip")[
                0
            ].level,
            Level.PASS,
        )
        self.assertIs(
            python_package_finding(Subject("uv", "x"), "0.13.3", installer="")[0].level,
            Level.FAIL,
        )
        self.assertIs(
            python_package_finding(Subject("uv", "x"), "0.13.4", installer="")[0].level,
            Level.PASS,
        )


class DistInfoTest(unittest.TestCase):
    def test_pip_installed_certifi(self) -> None:
        files = FakeFiles({f"{SITE}/certifi-2026.7.22.dist-info/INSTALLER": b"pip\n"})
        ctx = make_context(files, dirs=[dist_dir("certifi-2026.7.22.dist-info")])
        self.assertEqual(
            lines(PythonDistInfo(), ctx),
            [
                f"FAIL  certifi [{SITE}/certifi-2026.7.22.dist-info] found 2026.7.22, fixed 2026.10.18"
                " (vendors its own CA bundle)"
            ],
        )

    def test_brew_certifi_is_judged_by_its_bundle(self) -> None:
        files = FakeFiles(
            {
                f"{SITE}/certifi-2026.10.18.dist-info/INSTALLER": b"brew\n",
                f"{SITE}/certifi/cacert.pem": OLD_BUNDLE,
            }
        )
        ctx = make_context(files, dirs=[dist_dir("certifi-2026.10.18.dist-info")])
        got = lines(PythonDistInfo(), ctx)
        self.assertEqual(
            got[0].split("]")[0], f"INFO  certifi [{SITE}/certifi-2026.10.18.dist-info"
        )
        self.assertEqual(
            got[1],
            f"FAIL  certifi bundle [{SITE}/certifi/cacert.pem] contains emSign ECC Root CA - G3 (removed root)",
        )

    def test_brew_without_a_bundle(self) -> None:
        files = FakeFiles({f"{SITE}/pip-26.2.1.dist-info/INSTALLER": b"brew\n"})
        ctx = make_context(files, dirs=[dist_dir("pip-26.2.1.dist-info")])
        self.assertEqual(
            lines(PythonDistInfo(), ctx)[1],
            f"INFO  pip bundle [{SITE}/pip/_vendor/certifi/cacert.pem] no bundled cacert.pem, patched to use"
            " the system store",
        )

    def test_missing_installer_and_other_packages(self) -> None:
        ctx = make_context(
            FakeFiles(),
            dirs=[dist_dir("uv-0.13.4.dist-info"), dist_dir("requests-2.0.dist-info")],
        )
        self.assertEqual(
            lines(PythonDistInfo(), ctx),
            [f"PASS  uv [{SITE}/uv-0.13.4.dist-info] found 0.13.4, fixed 0.13.4"],
        )


class PinsTest(unittest.TestCase):
    def test_each_format(self) -> None:
        files = FakeFiles(
            {
                "/r/requirements-dev.txt": b"certifi==2026.7.22\n",
                "/r/poetry.lock": b'[[package]]\nname = "certifi"\nversion = "2026.10.19"\n',
                "/r/Pipfile.lock": b'{"default": {"certifi": {"version": "==2026.7.22"}}}',
                "/r/uv.lock": b'[[package]]\nname = "certifi"\nversion = "1"\ndescription = """\n',
                "/r/x/Pipfile.lock": b"{broken",
            }
        )
        indexed = files.indexed(
            "/r/requirements-dev.txt",
            "/r/poetry.lock",
            "/r/Pipfile.lock",
            "/r/uv.lock",
            "/r/x/Pipfile.lock",
        )
        got = lines(PythonPins(), make_context(files, indexed=indexed))
        self.assertEqual(
            [line.split(" found")[0] for line in got],
            [
                "FAIL  certifi [/r/requirements-dev.txt]",
                "PASS  certifi [/r/poetry.lock]",
                "FAIL  certifi [/r/Pipfile.lock]",
                "INFO  uv.lock [/r/uv.lock] partly unreadable, 1 packages read",
                "FAIL  certifi [/r/uv.lock]",
                "INFO  Pipfile.lock [/r/x/Pipfile.lock] unreadable, skipped",
            ],
        )


PY = "/usr/bin/python3"


def host_context(
    stdout: str, returncode: int = 0, files: FakeFiles = None, version: str = ""
) -> tuple:
    commands = FakeCommands(
        {"python3": located(PY)},
        {
            (PY, "-I", "-S", "-c"): result(stdout, returncode),
            (PY, "--version"): result(version),
        },
    )
    return make_context(files or FakeFiles(), commands), commands


class HostPythonTest(unittest.TestCase):
    def test_child_arguments_end_with_the_launcher(self) -> None:
        ctx, commands = host_context("")
        lines(HostPythonPackages(), ctx)
        self.assertEqual(commands.calls[0][:5], (PY, "-I", "-S", "-c", CHILD_SCRIPT))
        self.assertEqual(commands.calls[0][-1], PY)

    def test_records_and_their_bundles(self) -> None:
        site = "/usr/lib/python3/dist-packages"
        out = f"certifi\t2026.7.22\tpip\t{site}\npip\t26.2.2\tdpkg\t{site}\n"
        files = FakeFiles({f"{site}/certifi/cacert.pem": OLD_BUNDLE})
        ctx, _ = host_context(out, files=files)
        self.assertEqual(
            lines(HostPythonPackages(), ctx),
            [
                "FAIL  certifi [host python] found 2026.7.22, fixed 2026.10.18 (vendors its own CA bundle)",
                f"FAIL  certifi bundle [{site}/certifi/cacert.pem] contains emSign ECC Root CA - G3 (removed root)",
                "INFO  pip [host python] found 26.2.2, installed by dpkg, judged by the bundle it resolves to",
                f"INFO  pip bundle [{site}/pip/_vendor/certifi/cacert.pem] no bundled cacert.pem, patched to use"
                " the system store",
            ],
        )

    def test_nopy(self) -> None:
        ctx, _ = host_context("NOPY 3.7.17\n")
        self.assertEqual(
            lines(HostPythonPackages(), ctx),
            [
                "WARN  python3 [host] 3.7.17 predates importlib.metadata, certifi and pip not inspected"
            ],
        )

    def test_failure_without_records(self) -> None:
        ctx, _ = host_context("", returncode=1, version="Python 3.7.17\n")
        self.assertEqual(
            lines(HostPythonPackages(), ctx),
            [
                "WARN  python3 [host] 3.7.17 predates importlib.metadata, certifi and pip not inspected"
            ],
        )

    def test_macos_stub_is_not_run(self) -> None:
        commands = FakeCommands({"python3": located(PY)})
        ctx = make_context(
            FakeFiles(), commands, FakeHost(tools=False), env=hostenv("Darwin")
        )
        self.assertEqual(lines(HostPythonPackages(), ctx), [])
        self.assertEqual(commands.calls, [])

    def test_child_script_imports_no_package(self) -> None:
        self.assertNotIn("import certifi", CHILD_SCRIPT)
        self.assertNotIn("_vendor", CHILD_SCRIPT)
        self.assertNotIn("where()", CHILD_SCRIPT)
        compile(CHILD_SCRIPT, "child", "exec")


class UvTest(unittest.TestCase):
    def test_version_and_binary_content(self) -> None:
        uv = located("/usr/local/bin/uv", real="/opt/uv/uv", ino=77)
        files = FakeFiles(
            {"/opt/uv/uv": b"\x7fELF" + G3_ECC_ROOT.der},
            ids={"/opt/uv/uv": FileId(2, 77)},
        )
        commands = FakeCommands(
            {"uv": uv},
            {("/usr/local/bin/uv", "--version"): result("uv 0.13.3 (x 2026-10-01)\n")},
        )
        self.assertEqual(
            lines(UvHost(), make_context(files, commands)),
            [
                "FAIL  uv [host uv] found 0.13.3, fixed 0.13.4 (vendors its own CA bundle)",
                "FAIL  uv [/opt/uv/uv] contains emSign ECC Root CA - G3 (removed root)",
            ],
        )

    def test_claimed_binary_prints_nothing(self) -> None:
        uv = located("/usr/local/bin/uv", ino=5)
        ctx = make_context(FakeFiles(), FakeCommands({"uv": uv}))
        ctx.ledger.claim(uv.file_id)
        self.assertEqual(lines(UvHost(), ctx), [])


if __name__ == "__main__":
    unittest.main()
