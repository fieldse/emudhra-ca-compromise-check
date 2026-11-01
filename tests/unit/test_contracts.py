"""test_contracts.py: architecture and safety contracts over the emudhra_check source.

Parses every module under emudhra_check/ with ast and checks the import, file-system, process,
output and layering rules of acceptance criteria 1, 2 and 9. Each rule has a self-test that feeds
the checker a synthetic module breaking it, so a rule that cannot fire is caught.
"""

from __future__ import annotations

import ast
import sys
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

PACKAGE = "emudhra_check"
SOURCE = Path(__file__).resolve().parents[2] / PACKAGE

MAIN = PACKAGE + ".__main__"
CLI = PACKAGE + ".cli"
DETECTIONS = PACKAGE + ".detections"
ADAPTERS = PACKAGE + ".adapters"
PORTS = DETECTIONS + ".ports"
FILESYSTEM = ADAPTERS + ".filesystem"
PROCESS = ADAPTERS + ".process"
PLATFORM = ADAPTERS + ".platform"
PODMAN = ADAPTERS + ".podman"

FS_MODULES = frozenset({FILESYSTEM, PROCESS})
FS_NAMES = frozenset(
    {
        "os.walk",
        "os.fwalk",
        "os.open",
        "os.listdir",
        "os.scandir",
        "os.stat",
        "os.lstat",
        "os.access",
        "os.readlink",
        "os.path.exists",
        "os.path.lexists",
        "os.path.isdir",
        "os.path.isfile",
        "os.path.islink",
        "os.path.realpath",
        "os.path.getsize",
        "mmap",
        "glob",
        "shutil",
    }
)
PATH_IO_METHODS = frozenset(
    {
        "iterdir",
        "glob",
        "rglob",
        "read_text",
        "read_bytes",
        "write_text",
        "write_bytes",
        "open",
        "exists",
        "is_dir",
        "is_file",
        "is_symlink",
        "stat",
        "lstat",
        "resolve",
        "readlink",
        "touch",
        "mkdir",
        "unlink",
    }
)
SUBPROCESS_ALLOWED = frozenset(
    {
        "subprocess.Popen",
        "subprocess.PIPE",
        "subprocess.DEVNULL",
        "subprocess.TimeoutExpired",
    }
)
BANNED_MODULES = frozenset(
    {
        "pty",
        "multiprocessing",
        "pickle",
        "marshal",
        "shelve",
        "importlib.import_module",
        "socket",
        "ssl",
        "urllib",
        "http",
        "ftplib",
        "smtplib",
        "imaplib",
        "poplib",
        "xmlrpc",
        "asyncio",
        "ctypes",
        "os.fork",
        "os.forkpty",
        "os.system",
        "os.popen",
    }
)
BANNED_PREFIXES = ("os.exec", "os.spawn", "os.posix_spawn")
BANNED_BUILTINS = frozenset({"eval", "exec", "compile", "__import__"})
CONFINED = (
    ("platform", "platform", frozenset({PLATFORM, CLI})),
    ("importlib.resources", "resources", frozenset({PODMAN})),
    ("sys.stdout", "stdio", frozenset({CLI, MAIN})),
    ("sys.stderr", "stdio", frozenset({CLI, MAIN})),
    ("sys.argv", "argv", frozenset({CLI, MAIN})),
    ("sys.version_info", "argv", frozenset({CLI, MAIN})),
)
POPEN_KEYWORDS = ("cwd", "stdin", "executable", "env", "start_new_session")


@dataclass(frozen=True)
class Module:
    name: str
    source: str
    is_package: bool = False

    @property
    def package(self) -> str:
        return self.name if self.is_package else self.name.rpartition(".")[0]


def under(name: str, prefix: str) -> bool:
    """Return whether a dotted name equals prefix or lies below it."""
    return name == prefix or name.startswith(prefix + ".")


def kind(name: str) -> str:
    """Classify a module as detection, adapter, entry or core."""
    if under(name, DETECTIONS):
        return "detection"
    if under(name, ADAPTERS):
        return "adapter"
    if name in (CLI, MAIN):
        return "entry"
    return "core"


def load_tree(root: Path = SOURCE) -> dict[str, Module]:
    """Read every module of the package from disk."""
    modules = {}
    for path in sorted(root.rglob("*.py")):
        parts = path.relative_to(root.parent).with_suffix("").parts
        is_package = parts[-1] == "__init__"
        name = ".".join(parts[:-1] if is_package else parts)
        modules[name] = Module(name, path.read_text(encoding="utf-8"), is_package)
    return modules


def absolute(module: Module, node: ast.ImportFrom) -> str:
    """Return the absolute module name an ImportFrom refers to."""
    if node.level == 0:
        return node.module or ""
    base = module.package.split(".")
    base = base[: len(base) - (node.level - 1)]
    return ".".join(base + ([node.module] if node.module else []))


class Usage(ast.NodeVisitor):
    """Collect the qualified names, calls and imports one module uses."""

    def __init__(self, module: Module) -> None:
        self.module = module
        self.aliases: dict[str, str] = {}
        self.names: list[tuple[str, int]] = []
        self.imports: list[tuple[str, int]] = []
        self.calls: list[ast.Call] = []
        tree = ast.parse(module.source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        self.aliases[alias.asname] = alias.name
                    else:
                        top = alias.name.partition(".")[0]
                        self.aliases[top] = top
                    self.names.append((alias.name, node.lineno))
                    self.imports.append((alias.name, node.lineno))
            elif isinstance(node, ast.ImportFrom):
                base = absolute(module, node)
                for alias in node.names:
                    full = base + "." + alias.name if base else alias.name
                    self.aliases[alias.asname or alias.name] = full
                    self.names.append((full, node.lineno))
                    self.imports.append((full, node.lineno))
        self.visit(tree)

    def dotted(self, node: ast.expr) -> Optional[str]:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id)
        if isinstance(node, ast.Attribute):
            base = self.dotted(node.value)
            return base + "." + node.attr if base else None
        return None

    def visit_Attribute(self, node: ast.Attribute) -> None:
        name = self.dotted(node)
        if name:
            self.names.append((name, node.lineno))
        else:
            self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        name = self.dotted(node)
        if name:
            self.names.append((name, node.lineno))

    def visit_Call(self, node: ast.Call) -> None:
        self.calls.append(node)
        self.generic_visit(node)

    def builtin_call(self, node: ast.Call) -> Optional[str]:
        """Return the builtin a call names, when its name is not imported."""
        if isinstance(node.func, ast.Name) and node.func.id not in self.aliases:
            return node.func.id
        return None


def receiver_is_exempt(usage: Usage, receiver: ast.expr) -> bool:
    """Return whether a method call's receiver is a module, the Files port or package data."""
    if usage.dotted(receiver):
        return True
    if isinstance(receiver, ast.Name) and receiver.id == "files":
        return True
    if isinstance(receiver, ast.Attribute) and receiver.attr == "files":
        return True
    for node in ast.walk(receiver):
        if (
            isinstance(node, ast.Call)
            and usage.dotted(node.func) == "importlib.resources.files"
        ):
            return True
    return False


def mentions(usage: Usage, node: ast.expr, name: str) -> bool:
    """Return whether an expression refers to a qualified name anywhere inside it."""
    return any(
        isinstance(n, (ast.Name, ast.Attribute)) and usage.dotted(n) == name
        for n in ast.walk(node)
    )


def module_violations(module: Module) -> Iterator[str]:
    """Yield the per-module rule violations of one module."""
    usage = Usage(module)
    where = kind(module.name)
    for name, line in usage.names:
        tag = f"{module.name}:{line}"
        if any(under(name, f) for f in FS_NAMES) and module.name not in FS_MODULES:
            yield f"{tag}: filesystem: {name}"
        if under(name, "subprocess"):
            if module.name != PROCESS:
                yield f"{tag}: subprocess: {name}"
            elif name != "subprocess" and name not in SUBPROCESS_ALLOWED:
                yield f"{tag}: subprocess: {name}"
        if name == "os.execve":
            if module.name != MAIN:
                yield f"{tag}: exec: {name}"
        elif name.startswith(BANNED_PREFIXES) or any(
            under(name, b) for b in BANNED_MODULES
        ):
            yield f"{tag}: banned: {name}"
        for prefix, rule, allowed in CONFINED:
            if under(name, prefix) and module.name not in allowed:
                yield f"{tag}: {rule}: {name}"
        if where == "detection" and under(name, ADAPTERS):
            yield f"{tag}: layer: detection imports {name}"
    for name, line in usage.imports:
        if where == "core" and (
            under(name, DETECTIONS)
            or under(name, ADAPTERS)
            or under(name, CLI)
            or name == MAIN
        ):
            yield f"{module.name}:{line}: layer: core imports {name}"
    for call in usage.calls:
        tag = f"{module.name}:{call.lineno}"
        builtin = usage.builtin_call(call)
        if builtin in BANNED_BUILTINS:
            yield f"{tag}: banned: {builtin}"
        if builtin == "print" and module.name != CLI:
            yield f"{tag}: print: print"
        if builtin == "open" and module.name not in FS_MODULES:
            yield f"{tag}: filesystem: open"
        func = call.func
        if isinstance(func, ast.Attribute) and func.attr in PATH_IO_METHODS:
            if module.name not in FS_MODULES and not receiver_is_exempt(
                usage, func.value
            ):
                yield f"{tag}: filesystem: .{func.attr}()"
        for keyword in call.keywords:
            if keyword.arg == "shell" and not (
                isinstance(keyword.value, ast.Constant) and keyword.value.value is False
            ):
                yield f"{tag}: shell: shell= is not False"
        qualified = usage.dotted(func)
        if qualified == "os.open":
            flags = call.args[1:2] + [
                k.value for k in call.keywords if k.arg == "flags"
            ]
            if not any(mentions(usage, f, "os.O_RDONLY") for f in flags):
                yield f"{tag}: os.open: flags without os.O_RDONLY"
        if qualified == "subprocess.Popen":
            yield from popen_violations(usage, call, tag)


def popen_violations(usage: Usage, call: ast.Call, tag: str) -> Iterator[str]:
    """Yield the missing or wrong keywords of one Popen call."""
    given = {k.arg: k.value for k in call.keywords if k.arg}
    for keyword in POPEN_KEYWORDS:
        if keyword not in given:
            yield f"{tag}: popen: missing {keyword}="
    cwd = given.get("cwd")
    if cwd is not None and not (isinstance(cwd, ast.Constant) and cwd.value == "/"):
        yield f"{tag}: popen: cwd is not '/'"
    stdin = given.get("stdin")
    if stdin is not None and usage.dotted(stdin) != "subprocess.DEVNULL":
        yield f"{tag}: popen: stdin is not subprocess.DEVNULL"
    session = given.get("start_new_session")
    if session is not None and not (
        isinstance(session, ast.Constant) and session.value is True
    ):
        yield f"{tag}: popen: start_new_session is not True"


def stdlib_violations(modules: dict[str, Module]) -> Iterator[str]:
    """Yield imports of anything outside the standard library and the package."""
    stdlib = getattr(sys, "stdlib_module_names")
    for module in modules.values():
        for name, line in Usage(module).imports:
            top = name.partition(".")[0]
            if top != PACKAGE and top not in stdlib:
                yield f"{module.name}:{line}: stdlib: {name}"


def import_targets(module: Module, modules: dict[str, Module]) -> set[str]:
    """Return the package modules one module imports."""
    targets = set()
    for name, _ in Usage(module).imports:
        while name and name not in modules:
            name = name.rpartition(".")[0]
        if name:
            targets.add(name)
    return targets


def cycle_violations(modules: dict[str, Module]) -> Iterator[str]:
    """Yield one line per import cycle among the core modules."""
    core = {name for name in modules if kind(name) == "core"}
    graph = {
        name: sorted(import_targets(modules[name], modules) & core - {name})
        for name in sorted(core)
    }
    state: dict[str, int] = {}
    found: list[str] = []

    def visit(name: str, stack: list[str]) -> None:
        state[name] = 1
        for target in graph[name]:
            if state.get(target) == 1:
                found.append(" -> ".join(stack[stack.index(target) :] + [target]))
            elif target not in state:
                visit(target, stack + [target])
        state[name] = 2

    for name in graph:
        if name not in state:
            visit(name, [name])
    for cycle in found:
        yield f"{PACKAGE}: cycle: {cycle}"


def declared_all(module: Module) -> frozenset[str]:
    """Return the names a module lists in __all__."""
    for node in ast.parse(module.source).body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets
        ):
            if isinstance(node.value, (ast.List, ast.Tuple)):
                return frozenset(
                    e.value for e in node.value.elts if isinstance(e, ast.Constant)
                )
    return frozenset()


def sibling_violations(modules: dict[str, Module]) -> Iterator[str]:
    """Yield detection imports of a sibling that bypass the sibling's __all__."""
    siblings = {n for n in modules if n.startswith(DETECTIONS + ".") and n != PORTS}
    for name in sorted(siblings):
        module = modules[name]
        for node in ast.walk(ast.parse(module.source)):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in siblings:
                        yield f"{name}:{node.lineno}: sibling: imports module {alias.name}"
            elif isinstance(node, ast.ImportFrom):
                base = absolute(module, node)
                for alias in node.names:
                    if base + "." + alias.name in siblings:
                        yield f"{name}:{node.lineno}: sibling: imports module {base}.{alias.name}"
                    elif (
                        base in siblings
                        and base != name
                        and alias.name not in declared_all(modules[base])
                    ):
                        yield f"{name}:{node.lineno}: sibling: {base}.{alias.name} is not in __all__"


def violations(modules: dict[str, Module], with_stdlib: bool = False) -> list[str]:
    """Return every contract violation in a set of modules."""
    found = [v for m in modules.values() for v in module_violations(m)]
    found += cycle_violations(modules)
    found += sibling_violations(modules)
    if with_stdlib:
        found += stdlib_violations(modules)
    return found


def one(name: str, source: str, is_package: bool = False) -> dict[str, Module]:
    return {name: Module(name, source, is_package)}


def rules(found: list[str]) -> set[str]:
    return {v.split(": ")[1] for v in found}


HAS_STDLIB_NAMES = hasattr(sys, "stdlib_module_names")
STDLIB_SKIP = "sys.stdlib_module_names arrived in 3.10, the 3.13 run covers it"


class PackageContractsTest(unittest.TestCase):
    def test_package_has_modules(self) -> None:
        self.assertIn(MAIN, load_tree())

    def test_package_meets_every_contract(self) -> None:
        self.assertEqual(violations(load_tree()), [])

    @unittest.skipUnless(HAS_STDLIB_NAMES, STDLIB_SKIP)
    def test_package_imports_only_the_standard_library(self) -> None:
        self.assertEqual(list(stdlib_violations(load_tree())), [])


class CheckerSelfTest(unittest.TestCase):
    """Each rule reports a module written to break it."""

    def assertFlags(self, modules: dict[str, Module], rule: str) -> None:
        self.assertIn(rule, rules(violations(modules)))

    @unittest.skipUnless(HAS_STDLIB_NAMES, STDLIB_SKIP)
    def test_third_party_import(self) -> None:
        self.assertTrue(
            list(stdlib_violations(one(PACKAGE + ".scope", "import requests\n")))
        )

    def test_listdir_in_a_detection(self) -> None:
        self.assertFlags(
            one(DETECTIONS + ".trust_stores", "import os\nos.listdir(p)\n"),
            "filesystem",
        )

    def test_from_import_of_a_file_function(self) -> None:
        self.assertFlags(
            one(PACKAGE + ".scope", "from os.path import realpath\nrealpath(p)\n"),
            "filesystem",
        )

    def test_builtin_open_in_core(self) -> None:
        self.assertFlags(one(PACKAGE + ".report", "open('x')\n"), "filesystem")

    def test_path_method_in_core(self) -> None:
        self.assertFlags(
            one(PACKAGE + ".scope", "from pathlib import Path\nPath(p).read_bytes()\n"),
            "filesystem",
        )

    def test_mmap_in_a_detection(self) -> None:
        self.assertFlags(one(DETECTIONS + ".binaries", "import mmap\n"), "filesystem")

    def test_files_port_call_is_allowed(self) -> None:
        source = "def f(ctx, p):\n    return ctx.files.read_bytes(p, 1), ctx.files.is_dir(p)\n"
        self.assertEqual(violations(one(DETECTIONS + ".trust_stores", source)), [])

    def test_os_open_without_read_only(self) -> None:
        self.assertFlags(
            one(FILESYSTEM, "import os\nos.open(p, os.O_WRONLY)\n"), "os.open"
        )

    def test_subprocess_run_in_process(self) -> None:
        self.assertFlags(
            one(PROCESS, "import subprocess\nsubprocess.run(a)\n"), "subprocess"
        )

    def test_subprocess_outside_process(self) -> None:
        self.assertFlags(one(PACKAGE + ".scope", "import subprocess\n"), "subprocess")

    def test_popen_without_its_keywords(self) -> None:
        source = "import subprocess\nsubprocess.Popen(a, stdin=subprocess.DEVNULL, env=e, executable=x)\n"
        self.assertFlags(one(PROCESS, source), "popen")

    def test_popen_with_another_cwd(self) -> None:
        source = (
            "import subprocess\nsubprocess.Popen(a, cwd='/tmp', stdin=subprocess.DEVNULL, env=e,"
            " executable=x, start_new_session=True)\n"
        )
        self.assertFlags(one(PROCESS, source), "popen")

    def test_shell_true(self) -> None:
        self.assertFlags(
            one(PROCESS, "import subprocess\nsubprocess.Popen(a, shell=True)\n"),
            "shell",
        )

    def test_execve_outside_main(self) -> None:
        self.assertFlags(one(CLI, "import os\nos.execve(a, b, c)\n"), "exec")

    def test_other_exec_in_main(self) -> None:
        self.assertFlags(one(MAIN, "import os\nos.execv(a, b)\n"), "banned")

    def test_system_call(self) -> None:
        self.assertFlags(
            one(PACKAGE + ".versions", "import os\nos.system('x')\n"), "banned"
        )

    def test_eval(self) -> None:
        self.assertFlags(one(PACKAGE + ".versions", "eval('1')\n"), "banned")

    def test_network_module(self) -> None:
        self.assertFlags(
            one(PACKAGE + ".probe", "from urllib import request\n"), "banned"
        )

    def test_import_module(self) -> None:
        self.assertFlags(
            one(PACKAGE + ".probe", "import importlib\nimportlib.import_module('x')\n"),
            "banned",
        )

    def test_platform_in_core(self) -> None:
        self.assertFlags(one(PACKAGE + ".hostenv", "import platform\n"), "platform")

    def test_resources_outside_podman(self) -> None:
        self.assertFlags(one(CLI, "from importlib import resources\n"), "resources")

    def test_print_in_scope(self) -> None:
        self.assertFlags(one(PACKAGE + ".scope", "print('x')\n"), "print")

    def test_stderr_write_in_core(self) -> None:
        self.assertFlags(
            one(PACKAGE + ".report", "import sys\nsys.stderr.write('x')\n"), "stdio"
        )

    def test_argv_in_core(self) -> None:
        self.assertFlags(one(PACKAGE + ".scope", "import sys\nx = sys.argv\n"), "argv")

    def test_version_info_in_a_detection(self) -> None:
        self.assertFlags(
            one(DETECTIONS + ".runtimes", "import sys\nx = sys.version_info\n"), "argv"
        )

    def test_detection_imports_an_adapter(self) -> None:
        source = "from ..adapters.filesystem import LocalFiles\n"
        self.assertFlags(one(DETECTIONS + ".trust_stores", source), "layer")

    def test_core_imports_a_detection(self) -> None:
        self.assertFlags(
            one(PACKAGE + ".report", "from emudhra_check.detections import REGISTRY\n"),
            "layer",
        )

    def test_two_module_cycle(self) -> None:
        modules = {
            PACKAGE + ".a": Module(PACKAGE + ".a", "from emudhra_check import b\n"),
            PACKAGE + ".b": Module(PACKAGE + ".b", "from . import a\n"),
        }
        self.assertFlags(modules, "cycle")

    def test_sibling_name_outside_all(self) -> None:
        modules = {
            DETECTIONS
            + ".runtimes": Module(
                DETECTIONS + ".runtimes", "__all__ = ['go_version']\n"
            ),
            DETECTIONS
            + ".binaries": Module(
                DETECTIONS + ".binaries", "from .runtimes import node_version\n"
            ),
        }
        self.assertFlags(modules, "sibling")

    def test_sibling_name_inside_all_is_allowed(self) -> None:
        modules = {
            DETECTIONS
            + ".runtimes": Module(
                DETECTIONS + ".runtimes", "__all__ = ['go_version']\n"
            ),
            DETECTIONS
            + ".binaries": Module(
                DETECTIONS + ".binaries", "from .runtimes import go_version\n"
            ),
        }
        self.assertEqual(violations(modules), [])

    def test_sibling_module_import(self) -> None:
        modules = {
            DETECTIONS
            + ".runtimes": Module(DETECTIONS + ".runtimes", "__all__ = []\n"),
            DETECTIONS
            + ".binaries": Module(DETECTIONS + ".binaries", "from . import runtimes\n"),
        }
        self.assertFlags(modules, "sibling")


if __name__ == "__main__":
    unittest.main()
