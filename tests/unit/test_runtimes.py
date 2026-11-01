"""test_runtimes.py: unit tests of emudhra_check/detections/runtimes.py.

Parses recorded version output of node, bun, deno, go and python3, judges each runtime, judges Node
binaries by their bundled store, and checks that a binary reached as both bun and node is reported
once, as bun, and that version-manager directories are recognised by layout.
"""

from __future__ import annotations

import base64
import unittest
from pathlib import Path

from emudhra_check.certificates import (
    G3_ECC_ROOT,
    ISRG_ROOT_X1_LINE,
    CertificateMatch,
    MatchKind,
    Role,
)
from emudhra_check.detections.runtimes import (
    BunHost,
    CPythonHost,
    DenoHost,
    GoToolchain,
    NodeHost,
    NodeVersionDirs,
    StoreKind,
    bun_version,
    deno_version,
    go_version,
    node_store_findings,
    node_version,
    python_version,
)
from emudhra_check.report import Level, Subject
from emudhra_check.scope import FileId, IndexedDir
from tests.unit.fakes import (
    FakeCommands,
    FakeFiles,
    hostenv,
    lines,
    located,
    make_context,
    result,
    run_all,
)

HUGE = "9" * (1 << 20)
G3_PEM_LINE = base64.b64encode(G3_ECC_ROOT.der)[:64]


class ParserTest(unittest.TestCase):
    def test_recorded_lines(self) -> None:
        self.assertEqual(node_version("v24.22.0\n"), "24.22.0")
        self.assertEqual(bun_version("1.4.4\n"), "1.4.4")
        self.assertEqual(
            deno_version(
                "deno 2.9.8 (stable, release, x86_64-unknown-linux-gnu)\nv8 14.0\ntypescript 5.9\n"
            ),
            "2.9.8",
        )
        self.assertEqual(go_version("go version go1.27.2 linux/amd64\n"), "1.27.2")
        self.assertEqual(go_version("go version go1.27.3 darwin/arm64"), "1.27.3")
        self.assertEqual(
            go_version("go version devel go1.28-abc Mon Oct 1 linux/amd64"), "1.28-abc"
        )
        self.assertEqual(python_version("Python 3.13.5\n"), "3.13.5")

    def test_empty_and_huge(self) -> None:
        for parse in (
            node_version,
            bun_version,
            deno_version,
            go_version,
            python_version,
        ):
            with self.subTest(parse=parse.__name__):
                self.assertIsNone(parse(""))
                self.assertIsNone(parse(HUGE))
                self.assertIsNone(parse("v" + HUGE))


def tool_context(
    name: str, output: str, path: str = "", files: FakeFiles = None, env=None
) -> tuple:
    path = path or f"/usr/bin/{name}"
    commands = FakeCommands({name: located(path, ino=11)}, {(path,): result(output)})
    return make_context(files or FakeFiles(), commands, env=env), commands


class VersionVerdictTest(unittest.TestCase):
    def first(self, detection, name: str, output: str) -> str:
        ctx, _ = tool_context(name, output)
        return lines(detection, ctx)[0]

    def test_bun(self) -> None:
        self.assertTrue(
            self.first(BunHost(), "bun", "1.4.3\n").startswith(
                "FAIL  bun [host] found 1.4.3, fixed 1.4.4"
            )
        )
        self.assertTrue(
            self.first(BunHost(), "bun", "1.4.4\n").startswith(
                "PASS  bun [host] found 1.4.4"
            )
        )

    def test_unparsable_version_output_warns(self) -> None:
        for detection, name in (
            (BunHost(), "bun"),
            (NodeHost(), "node"),
            (DenoHost(), "deno"),
            (GoToolchain(), "go"),
        ):
            for output in ("", HUGE):
                with self.subTest(name=name, output=output[:8]):
                    ctx, _ = tool_context(name, output)
                    got = [line for line in lines(detection, ctx) if "[host]" in line]
                    self.assertEqual(got, [f"WARN  {name} [host] version unreadable"])

    def test_deno(self) -> None:
        two_lines = "deno {} (stable, release, x86_64-unknown-linux-gnu)\nv8 14.1\n"
        self.assertTrue(
            self.first(DenoHost(), "deno", two_lines.format("2.9.7")).startswith(
                "FAIL  deno [host] found 2.9.7"
            )
        )
        self.assertTrue(
            self.first(DenoHost(), "deno", two_lines.format("2.9.8")).startswith(
                "PASS  deno [host] found 2.9.8"
            )
        )

    def test_go(self) -> None:
        self.assertEqual(
            self.first(GoToolchain(), "go", "go version go1.27.2 linux/amd64\n"),
            "FAIL  go [host] found 1.27.2, fixed 1.27.3 (CVE-2026-111943, rebuild binaries after upgrading)",
        )
        self.assertTrue(
            self.first(
                GoToolchain(), "go", "go version go1.27.3 darwin/arm64"
            ).startswith("PASS")
        )
        self.assertTrue(
            self.first(GoToolchain(), "go", "go version devel go1.28-abc x").startswith(
                "WARN"
            )
        )

    def test_go_mod_toolchain_minimum(self) -> None:
        files = FakeFiles(
            {"/r/go.mod": b"module x\n\ngo 1.26\n\ntoolchain go1.27.2 // pinned\n"}
        )
        ctx = make_context(files, indexed=files.indexed("/r/go.mod"))
        self.assertEqual(
            lines(GoToolchain(), ctx),
            [
                "INFO  go [/r/go.mod toolchain minimum] found 1.27.2, fixed 1.27.3 (a minimum, not a pin;"
                " the installed go and the built binaries decide)"
            ],
        )

    def test_cpython(self) -> None:
        env = hostenv(running="3.13.5")
        for output, want in (
            ("Python 3.13.5\n", "WARN  python3 [host] found 3.13.5, fixed 3.13.18"),
            ("Python 3.13.18\n", "PASS  python3 [host] found 3.13.18, fixed 3.13.18"),
            (
                "Python 3.10.12\n",
                "WARN  python3 [host] found 3.10.12, end-of-life, no fix",
            ),
        ):
            with self.subTest(output=output):
                ctx, _ = tool_context("python3", output, env=env)
                self.assertTrue(lines(CPythonHost(), ctx)[0].startswith(want))

    def test_cpython_running_interpreter_when_it_differs(self) -> None:
        ctx, _ = tool_context(
            "python3", "Python 3.13.5\n", env=hostenv(running="3.9.25")
        )
        got = lines(CPythonHost(), ctx)
        self.assertEqual(
            got[1], "WARN  python3 [running] found 3.9.25, end-of-life, no fix"
        )
        ctx, _ = tool_context(
            "python3", "Python 3.9.25\n", env=hostenv(running="3.9.25")
        )
        self.assertEqual(len(lines(CPythonHost(), ctx)), 1)


SUBJECT = Subject("node", "host")


class NodeStoreTest(unittest.TestCase):
    def levels(self, data: bytes) -> list:
        files = FakeFiles({"/fx/bin/node": data}, ids={"/fx/bin/node": FileId(2, 1000)})
        commands = FakeCommands(
            {"node": located("/fx/bin/node", ino=1000)},
            {("/fx/bin/node", "--version"): result("v24.22.1\n")},
        )
        ctx = make_context(files, commands)
        return [(f.level, f.subject.where) for f in NodeHost().run(ctx)]

    def test_fixed_version_with_the_g3_root_fails(self) -> None:
        got = self.levels(b"\x7fELF" + ISRG_ROOT_X1_LINE + G3_PEM_LINE)
        self.assertEqual(got, [(Level.PASS, "host"), (Level.FAIL, "/fx/bin/node")])

    def test_fixed_version_with_isrg_only_passes(self) -> None:
        self.assertEqual(
            self.levels(b"\x7fELF" + ISRG_ROOT_X1_LINE), [(Level.PASS, "host")]
        )

    def test_no_store_is_info(self) -> None:
        self.assertEqual(self.levels(b"\x7fELF plain"), [(Level.INFO, "host")])

    def test_old_version_with_root_is_confirmed(self) -> None:
        g3 = CertificateMatch(G3_ECC_ROOT.label, Role.G3_ROOT, MatchKind.FULL)
        got = node_store_findings(SUBJECT, "24.22.0", (g3,), StoreKind.BUNDLED, "/n")
        self.assertEqual([f.level for f in got], [Level.FAIL, Level.INFO])
        self.assertIn("confirms the version FAIL", got[1].detail)
        missing = node_store_findings(SUBJECT, "24.22.0", (), StoreKind.BUNDLED, "/n")
        self.assertIn("does not bundle", missing[1].detail)

    def test_not_installed(self) -> None:
        self.assertEqual(
            lines(NodeHost(), make_context()), ["INFO  node [host] not installed"]
        )

    def test_excluded_link(self) -> None:
        commands = FakeCommands({"node": located("/tmp/t/links/node", permitted=False)})
        self.assertEqual(
            lines(NodeHost(), make_context(commands=commands)),
            ["INFO  node [host] found on PATH inside an excluded directory, not run"],
        )
        self.assertEqual(commands.calls, [])


class BunBeforeNodeTest(unittest.TestCase):
    def test_one_binary_reached_as_bun_and_node(self) -> None:
        real = "/usr/local/bin/bun"
        files = FakeFiles(
            {real: b"\x7fELF" + G3_ECC_ROOT.der}, ids={real: FileId(2, 50)}
        )
        commands = FakeCommands(
            {
                "bun": located(real, ino=50),
                "node": located("/usr/local/bin/node", real=real, ino=50),
            },
            {
                (real, "--version"): result("1.4.3\n"),
                ("/usr/local/bin/node",): result("v24.3.0\n"),
            },
        )
        found = run_all((BunHost(), NodeHost()), make_context(files, commands))
        content = [
            f for f in found if f.subject is not None and f.subject.where == real
        ]
        self.assertEqual([f.subject.name for f in content], ["bun"])
        self.assertFalse(
            any(f.subject is not None and f.subject.name == "node" for f in found)
        )


class VersionDirsTest(unittest.TestCase):
    def test_layouts(self) -> None:
        dirs = [
            "/root/.nvm/versions/node/v24.22.0",
            "/root/.volta/tools/image/node/24.22.0",
            "/root/.asdf/installs/nodejs/24.22.0",
            "/root/.local/share/fnm/node-versions/v24.22.0",
            "/root/.local/share/mise/installs/node/24.22.0",
            "/root/.local/share/mise/installs/node/24.22.0/bin",
            "/root/.nvm/versions/node/system",
        ]
        indexed = [IndexedDir(Path(d), FileId(4, i)) for i, d in enumerate(dirs)]
        got = lines(NodeVersionDirs(), make_context(FakeFiles(), dirs=indexed))
        self.assertEqual(len(got), 5)
        self.assertTrue(all(line.startswith("FAIL  node [/root/") for line in got))
        self.assertIn(
            "FAIL  node [/root/.local/share/mise/installs/node/24.22.0] found 24.22.0",
            got[4],
        )

    def test_none_found(self) -> None:
        self.assertEqual(
            lines(NodeVersionDirs(), make_context()),
            [
                "INFO  node [version managers] no nvm, volta, asdf, fnm or mise installs under scan roots"
            ],
        )

    def test_binary_is_read(self) -> None:
        base = "/root/.local/share/fnm/node-versions/v24.22.1"
        files = FakeFiles(
            {
                f"{base}/installation/bin/node": b"\x7fELF"
                + ISRG_ROOT_X1_LINE
                + G3_PEM_LINE
            }
        )
        indexed = [IndexedDir(Path(base), FileId(4, 1))]
        got = lines(NodeVersionDirs(), make_context(files, dirs=indexed))
        self.assertEqual(
            got,
            [
                f"PASS  node [{base}] found 24.22.1, fixed 24.22.1",
                f"FAIL  node [{base}/installation/bin/node] binary still bundles"
                " emSign ECC Root CA - G3 (removed root)",
            ],
        )


if __name__ == "__main__":
    unittest.main()
