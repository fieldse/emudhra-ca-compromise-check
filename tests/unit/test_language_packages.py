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
    CargoLocks,
    ComposerLocks,
    ElectronPackages,
    GemfileLocks,
    HostPythonPackages,
    MixLocks,
    PythonDistInfo,
    PythonPins,
    UvHost,
    electron_range_finding,
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
        for installer in ("brew", "debian"):
            with self.subTest(installer=installer):
                got = python_package_finding(
                    Subject("pip", "x"), "23.0.1", installer=installer
                )
                self.assertEqual(got[0].level, Level.INFO)
                self.assertIn("judged by the bundle it resolves to", got[0].detail)

    def test_no_own_bundle_is_never_a_version_fail(self) -> None:
        for installer in ("pip", "unknown", "debian"):
            with self.subTest(installer=installer):
                got = python_package_finding(
                    Subject("certifi", "x"),
                    "2026.7.22",
                    installer=installer,
                    bundled=False,
                )
                self.assertEqual(
                    [f.line() for f in got],
                    [
                        "INFO  certifi [x] found 2026.7.22, no bundled cacert.pem, patched to use the system store"
                    ],
                )

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
        files = FakeFiles(
            {
                f"{SITE}/certifi-2026.7.22.dist-info/INSTALLER": b"pip\n",
                f"{SITE}/certifi/cacert.pem": OLD_BUNDLE,
            }
        )
        ctx = make_context(files, dirs=[dist_dir("certifi-2026.7.22.dist-info")])
        self.assertEqual(
            lines(PythonDistInfo(), ctx),
            [
                f"FAIL  certifi [{SITE}/certifi-2026.7.22.dist-info] found 2026.7.22, fixed 2026.10.18"
                " (vendors its own CA bundle)"
            ],
        )

    def test_debian_certifi_without_a_bundle(self) -> None:
        files = FakeFiles(
            {f"{SITE}/certifi-2025.1.31.dist-info/INSTALLER": b"debian\n"}
        )
        ctx = make_context(files, dirs=[dist_dir("certifi-2025.1.31.dist-info")])
        self.assertEqual(
            lines(PythonDistInfo(), ctx),
            [
                f"INFO  certifi [{SITE}/certifi-2025.1.31.dist-info] found 2025.1.31, no bundled cacert.pem,"
                " patched to use the system store"
            ],
        )

    def test_debian_certifi_with_a_bundle(self) -> None:
        files = FakeFiles(
            {
                f"{SITE}/certifi-2025.1.31.dist-info/INSTALLER": b"debian\n",
                f"{SITE}/certifi/cacert.pem": OLD_BUNDLE,
            }
        )
        ctx = make_context(files, dirs=[dist_dir("certifi-2025.1.31.dist-info")])
        self.assertEqual(
            lines(PythonDistInfo(), ctx),
            [
                f"INFO  certifi [{SITE}/certifi-2025.1.31.dist-info] found 2025.1.31, installed by debian,"
                " judged by the bundle it resolves to",
                f"FAIL  certifi bundle [{SITE}/certifi/cacert.pem] contains emSign ECC Root CA - G3 (removed root)",
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
            lines(PythonDistInfo(), ctx),
            [
                f"INFO  pip [{SITE}/pip-26.2.1.dist-info] found 26.2.1, no bundled cacert.pem, patched to use"
                " the system store"
            ],
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
                "INFO  pip [host python] found 26.2.2, no bundled cacert.pem, patched to use the system store",
            ],
        )

    def test_debian_and_egg_info_records(self) -> None:
        site = "/usr/lib/python3/dist-packages"
        local = "/usr/local/lib/python3.13/dist-packages"
        out = (
            f"certifi\t2025.1.31\tdebian\t{site}\n"
            f"pip\t23.0.1\tunknown\t{site}\n"
            f"certifi\t2026.7.22\tunknown\t{local}\n"
        )
        files = FakeFiles({f"{local}/certifi/cacert.pem": OLD_BUNDLE})
        ctx, _ = host_context(out, files=files)
        self.assertEqual(
            lines(HostPythonPackages(), ctx),
            [
                "INFO  certifi [host python] found 2025.1.31, no bundled cacert.pem, patched to use the system store",
                "INFO  pip [host python] found 23.0.1, no bundled cacert.pem, patched to use the system store",
                "FAIL  certifi [host python] found 2026.7.22, fixed 2026.10.18 (vendors its own CA bundle)",
                f"FAIL  certifi bundle [{local}/certifi/cacert.pem] contains emSign ECC Root CA - G3 (removed root)",
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

    def test_tool_a_non_root_user_can_change_is_not_run(self) -> None:
        commands = FakeCommands({"python3": located(PY, writable=True)})
        ctx = make_context(FakeFiles(), commands)
        self.assertEqual(
            lines(HostPythonPackages(), ctx),
            ["WARN  python3 [host] not run: python3 is writable by a non-root user"],
        )
        self.assertEqual(commands.calls, [])

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


def run_files(detection, files: dict) -> list:
    fake = FakeFiles(files)
    return lines(detection, make_context(fake, indexed=fake.indexed(*files)))


class ElectronTest(unittest.TestCase):
    def test_installed_and_declared(self) -> None:
        got = run_files(
            ElectronPackages(),
            {
                "/f/old/node_modules/electron/package.json": b'{"name": "electron", "version": "43.8.0"}',
                "/f/new/node_modules/electron/package.json": b'{"name": "electron", "version": "44.9.1"}',
                "/f/new/node_modules/other/package.json": b'{"dependencies": {"electron": "^41.0.0"}}',
                "/f/range/package.json": b'{"devDependencies": {"electron": "^43.8.0"}}',
                "/f/exact/package.json": b'{"devDependencies": {"electron": "=43.8.0"}}',
                "/f/eol/package.json": b'{"dependencies": {"electron": "^41.2.0"}}',
                "/f/open/package.json": b'{"dependencies": {"electron": ">=43.0.0"}}',
                "/f/ws/package.json": b'{"dependencies": {"electron": "workspace:*"}}',
                "/f/num/package.json": b'{"dependencies": {"electron": 44}}',
            },
        )
        by_path = {line.split("]")[0].split("[")[1]: line for line in got}
        self.assertTrue(
            by_path["/f/eol/package.json declared range starts at"].startswith("FAIL")
        )
        self.assertIn(
            "can only install affected versions",
            by_path["/f/eol/package.json declared range starts at"],
        )
        self.assertTrue(
            by_path["/f/range/package.json declared range starts at"].startswith("WARN")
        )
        self.assertIn(
            "a range may resolve higher",
            by_path["/f/range/package.json declared range starts at"],
        )
        self.assertEqual(
            by_path["/f/exact/package.json declared range starts at"],
            "FAIL  electron [/f/exact/package.json declared range starts at] found 43.8.0, fixed 43.8.1: "
            "this version is affected",
        )
        self.assertTrue(
            by_path["/f/open/package.json declared range starts at"].startswith("WARN")
        )
        self.assertIn(
            "unbounded range", by_path["/f/open/package.json declared range starts at"]
        )
        self.assertTrue(
            by_path["/f/old/node_modules/electron/package.json"].startswith("FAIL")
        )
        self.assertTrue(
            by_path["/f/new/node_modules/electron/package.json"].startswith("PASS")
        )
        self.assertEqual(len(got), 6)

    def test_unreadable_package_json(self) -> None:
        deep = b"[" * 1000 + b"]" * 1000
        digits = b'{"version": 1' + b"0" * (8 << 20) + b"}"
        for data in (b"{", deep, digits[:-1]):
            got = run_files(ElectronPackages(), {"/f/package.json": data})
            self.assertEqual(
                got,
                ["INFO  electron [/f/package.json] package.json unreadable, skipped"],
            )
        self.assertEqual(run_files(ElectronPackages(), {"/f/package.json": digits}), [])

    def test_range_on_a_branch_without_a_fix_fails(self) -> None:
        subject = Subject("electron", "x")
        self.assertIs(electron_range_finding(subject, "^41.2.0").level, Level.FAIL)
        self.assertIs(electron_range_finding(subject, "~44.9.0").level, Level.WARN)
        self.assertIs(electron_range_finding(subject, "^46.0.0").level, Level.PASS)
        self.assertIs(
            electron_range_finding(subject, "^45.0.0-beta.6").level, Level.PASS
        )
        self.assertIsNone(electron_range_finding(subject, "file:../e"))

    def test_exact_spec_below_the_fix_fails(self) -> None:
        subject = Subject("electron", "x")
        for spec in ("43.8.0", "=43.8.0", "v43.8.0", "45.0.0-beta.5"):
            with self.subTest(spec=spec):
                finding = electron_range_finding(subject, spec)
                self.assertIs(finding.level, Level.FAIL)
                self.assertIn("this version is affected", finding.detail)
        eol = electron_range_finding(subject, "41.2.0")
        self.assertIs(eol.level, Level.FAIL)
        self.assertEqual(
            eol.detail, "found 41.2.0, this version is affected (no fix on its branch)"
        )
        self.assertEqual(
            electron_range_finding(subject, "=43.8.0").detail,
            "found 43.8.0, fixed 43.8.1: this version is affected",
        )
        for spec in ("43.8.1", "=44.9.1", "45.0.0-beta.6"):
            with self.subTest(spec=spec):
                self.assertIs(electron_range_finding(subject, spec).level, Level.PASS)
        for spec in ("^43.8.0", "~43.8.0", "43.x", "43.8"):
            with self.subTest(spec=spec):
                finding = electron_range_finding(subject, spec)
                self.assertIs(finding.level, Level.WARN)
                self.assertIn("a range may resolve higher", finding.detail)


CARGO_WRAPPER = """\
[[package]]
name = "webpki-roots"
version = "0.26.11"
dependencies = [
 "webpki-roots {}",
]

[[package]]
name = "webpki-roots"
version = "{}"
"""


class CargoTest(unittest.TestCase):
    def test_wrapper_resolution(self) -> None:
        for wrapped, level in (("1.0.9", "FAIL"), ("1.0.10", "PASS")):
            got = run_files(
                CargoLocks(),
                {"/f/Cargo.lock": CARGO_WRAPPER.format(wrapped, wrapped).encode()},
            )
            self.assertEqual(
                got[0],
                f"{level}  webpki-roots [/f/Cargo.lock] found 0.26.11, wraps {wrapped}, fixed 1.0.10",
            )

    def test_wrapper_without_dependencies_warns(self) -> None:
        text = b'[[package]]\nname = "webpki-roots"\nversion = "0.26.11"\n'
        got = run_files(CargoLocks(), {"/f/Cargo.lock": text})
        self.assertTrue(
            got[0].startswith("WARN  webpki-roots [/f/Cargo.lock] found 0.26.11,")
        )

    def test_versions(self) -> None:
        def level(crate: str, version: str) -> str:
            text = f'[[package]]\nname = "{crate}"\nversion = "{version}"\n'.encode()
            return run_files(CargoLocks(), {"/f/Cargo.lock": text})[0].split()[0]

        for crate, version, want in (
            ("webpki-roots", "0.25.4", "FAIL"),
            ("webpki-roots", "0.26.0", "FAIL"),
            ("webpki-roots", "0.26.10", "FAIL"),
            ("webpki-roots", "1.0.9", "FAIL"),
            ("webpki-roots", "1.0.10", "PASS"),
            ("webpki-root-certs", "1.0.9", "FAIL"),
            ("webpki-root-certs", "1.0.10", "PASS"),
            ("rustls-webpki", "0.102.8", "FAIL"),
            ("rustls-webpki", "0.103.15", "FAIL"),
            ("rustls-webpki", "0.103.16", "PASS"),
            ("rustls-webpki", "0.104.0-alpha.7", "FAIL"),
            ("rustls-webpki", "0.104.0-alpha.8", "PASS"),
            ("webpki-roots", "9" * (1 << 20), "WARN"),
        ):
            with self.subTest(crate=crate, version=version[:20]):
                self.assertEqual(level(crate, version), want)

    def test_partly_unreadable(self) -> None:
        text = b'[[package]]\nname = "webpki-roots"\nversion = "0.25.4"\ndescription = \'\'\'\n'
        got = run_files(CargoLocks(), {"/f/Cargo.lock": text})
        self.assertEqual(
            got[-1],
            "INFO  Cargo.lock [/f/Cargo.lock] partly unreadable, 1 packages read",
        )


class OtherLocksTest(unittest.TestCase):
    def test_composer(self) -> None:
        def level(version: str) -> str:
            text = f'{{"packages": [{{"name": "composer/ca-bundle", "version": "{version}"}}]}}'.encode()
            return run_files(ComposerLocks(), {"/f/composer.lock": text})[0].split()[0]

        for version, want in (
            ("1.4.15", "FAIL"),
            ("1.4.16", "PASS"),
            ("1.5.14", "FAIL"),
            ("1.6.0", "PASS"),
        ):
            with self.subTest(version=version):
                self.assertEqual(level(version), want)
        self.assertEqual(
            run_files(ComposerLocks(), {"/f/composer.lock": b"{"}),
            ["INFO  composer.lock [/f/composer.lock] unreadable, skipped"],
        )

    def test_gemfile_crlf(self) -> None:
        text = b"GEM\r\n  specs:\r\n    excon (1.7.3)\r\n"
        self.assertEqual(
            run_files(GemfileLocks(), {"/f/Gemfile.lock": text}),
            ["FAIL  excon [/f/Gemfile.lock] found 1.7.3, fixed 1.8.0"],
        )

    def test_mix(self) -> None:
        text = (
            b'%{\n  "castore": {:hex, :castore, "1.0.22", "e4", [:mix], [], "hexpm", "e4"},\n'
            b'  "castore_fork": {:hex, :castore_fork, "1.0.1", "e4", [:mix], [], "hexpm", "e4"},\n'
            b'  "certifi": {:hex, :certifi, "2.17.0", "81", [:rebar3], [], "hexpm", "81"},\n}\n'
        )
        self.assertEqual(
            run_files(MixLocks(), {"/f/mix.lock": text}),
            [
                "PASS  castore [/f/mix.lock] found 1.0.22, fixed 1.0.22",
                "FAIL  hex certifi [/f/mix.lock] found 2.17.0, fixed 2.18.0",
            ],
        )


if __name__ == "__main__":
    unittest.main()
