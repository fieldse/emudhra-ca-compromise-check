"""make_trees.py: builds the exclude and hostile-input trees for the check's container cases.

Run inside the container that then runs the check, with the case name as the argument, so FIFOs,
mode bits and symlinks live in the container's own file system. Each case gets only its own tree.
The affected bundle is certifi 2026.7.22's and the clean one certifi 2026.10.18's, copied from /out.
"""

import os
import sys

OUT = "/out/certifi"
AFFECTED = open(f"{OUT}/cacert-2026.7.22.pem", "rb").read()
CLEAN = open(f"{OUT}/cacert-2026.10.18.pem", "rb").read()
MARKER_TOOLS = ("node", "go", "python3", "brew", "bun", "deno", "perl", "uv", "podman")
CHAIN_DEPTH = 2000
SPARSE_BYTES = 100 * 1024 * 1024
LINE_BYTES = 32 * 1024 * 1024
DIGITS = 1024 * 1024


def write(path: str, data: bytes, mode: int = 0o644) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    os.chmod(path, mode)


def marker(path: str, name: str) -> None:
    """Write an executable script that leaves /tmp/EXECUTED-NAME if anything runs it."""
    write(path, f"#!/bin/sh\n: >/tmp/EXECUTED-{name}\n".encode(), 0o755)


def exclude_tree(base: str) -> None:
    """The secret folder with an affected bundle, the open folder with a clean one, and the links into secret."""
    write(f"{base}/secret/cacert.pem", AFFECTED)
    os.makedirs(f"{base}/secret/sub", exist_ok=True)
    os.makedirs(f"{base}/secret/b", exist_ok=True)
    write(f"{base}/open/cacert.pem", CLEAN)
    os.symlink(f"{base}/secret", f"{base}/link-to-secret")
    os.symlink(f"{base}/secret", f"{base}/via")
    os.symlink(f"{base}/loop", f"{base}/loop")
    write(f"{base}/root/clean.pem", CLEAN)
    os.symlink(f"{base}/secret/cacert.pem", f"{base}/root/link.pem")
    os.mkfifo(f"{base}/secret/fifo.pem")
    os.symlink(f"{base}/secret/fifo.pem", f"{base}/root/fifo-link.pem")
    for name in MARKER_TOOLS:
        marker(f"{base}/excl/tools/bin/{name}", name)
    marker(f"{base}/cwd/node", "cwd-node")


def case_tree(base: str) -> None:
    """Secret spelled with a capital, so a lower-case exclude names nothing on a case-sensitive volume."""
    write(f"{base}/Secret/cacert.pem", AFFECTED)
    write(f"{base}/open/cacert.pem", CLEAN)


def glob_tree(base: str) -> None:
    """A folder whose name is a glob, and a sibling the glob would match."""
    write(f"{base}/glob[x]*?/cacert.pem", AFFECTED)
    write(f"{base}/globxa/cacert.pem", CLEAN)


def nested_tree(base: str) -> None:
    write(f"{base}/a/b/cacert.pem", AFFECTED)
    write(f"{base}/a/cacert.pem", CLEAN)


def root_parent_tree() -> None:
    """Two affected bundles in the container's own file system, one to exclude."""
    write("/tmp/exclroot/cacert.pem", AFFECTED)
    write("/tmp/openroot/cacert.pem", AFFECTED)
    os.makedirs("/tmp/scan", exist_ok=True)
    write("/tmp/scan/cacert.pem", AFFECTED)


def chain(base: str) -> None:
    """A directory chain CHAIN_DEPTH deep with an affected bundle at the bottom, built by relative steps."""
    os.makedirs(base, exist_ok=True)
    fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
    for _ in range(CHAIN_DEPTH):
        os.mkdir("d", dir_fd=fd)
        child = os.open("d", os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
        os.close(fd)
        fd = child
    out = os.open("cacert.pem", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=fd)
    os.write(out, AFFECTED)
    os.close(out)
    os.close(fd)


def hostile_tree(base: str) -> None:
    """Every hostile input of the plan's hostile case, under one root."""
    write(f"{base}/cacert.pem", AFFECTED)
    os.makedirs(f"{base}/fifo", exist_ok=True)
    os.mkfifo(f"{base}/fifo/cacert.pem")
    os.symlink(f"{base}/fifo/cacert.pem", f"{base}/fifo-link.pem")
    write(f"{base}/empty.pem", b"")
    write(os.fsencode(base) + b"/cacert-\xff.pem", AFFECTED)
    os.symlink(f"{base}/loop.pem", f"{base}/loop.pem")
    os.symlink(f"{base}/xloop", f"{base}/xloop")
    write(f"{base}/m000/cacert.pem", AFFECTED, 0o000)
    with open(f"{base}/sparse.crt", "wb") as f:
        f.truncate(SPARSE_BYTES)
    write(f"{base}/x\nPASS  ca-bundle [/etc/ssl/cert.pem] clean/cacert.pem", AFFECTED)
    write(f"{base}/esc\x1b[2J.pem", AFFECTED)
    chain(f"{base}/chain")
    digits = b"9" * DIGITS
    write(
        f"{base}/digits/Cargo.lock",
        b'version = 3\n\n[[package]]\nname = "webpki-roots"\nversion = "'
        + digits
        + b'"\n',
    )
    write(f"{base}/digits/requirements.txt", b"certifi==" + digits + b"\n")
    near = {
        "Gemfile.lock": b"excon (",
        "mix.lock": b'"castore": {:hex, :castore, "',
        "requirements.txt": b"certifi==",
        "package.json": b'"electron": "',
    }
    for name, prefix in near.items():
        write(
            f"{base}/near/{name}",
            (prefix * (LINE_BYTES // len(prefix) + 1))[:LINE_BYTES],
        )
    write(f"{base}/a0444/cacert.pem", AFFECTED)
    os.chmod(f"{base}/a0444", 0o444)
    write(f"{base}/a0111/bin/tool", b"\x7fELF" + b"\0" * 64, 0o111)


def main() -> None:
    case = sys.argv[1]
    if case == "exclude":
        exclude_tree("/tmp/t")
    elif case == "case":
        case_tree("/tmp/t")
    elif case == "glob":
        glob_tree("/tmp/t")
    elif case == "nested":
        exclude_tree("/tmp/t")
        nested_tree("/tmp/t")
    elif case == "root-parent":
        root_parent_tree()
    elif case == "hostile":
        hostile_tree("/tmp/hostile")
    else:
        sys.exit(f"unknown tree: {case}")


if __name__ == "__main__":
    os.umask(0o022)
    main()
