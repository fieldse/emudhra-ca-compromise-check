"""buildinfo.py: where a native binary stores its toolchain and version.

Holds BinaryKind and classify, which the walk uses to sort program candidates. classify reports
OTHER for every input until the readers for Go, Electron, Node and Rust binaries are added.
"""

from __future__ import annotations

from enum import Enum


class BinaryKind(Enum):
    GO = "go"
    ELECTRON = "electron"
    NODE = "node"
    RUST = "rust"
    OTHER = "other"


def classify(data: bytes) -> BinaryKind:
    """Return the kind of binary data holds."""
    return BinaryKind.OTHER
