"""__init__.py: the detections package and its one ordered registry.

REGISTRY lists one instance of every detection class. Its order is the output order.
"""

from __future__ import annotations

from emudhra_check.detections.language_packages import (
    CargoLocks,
    ComposerLocks,
    ElectronPackages,
    GemfileLocks,
    HostPythonPackages,
    MixLocks,
    PythonDistInfo,
    PythonPins,
    UvHost,
)
from emudhra_check.detections.os_packages import CaCertificatesPackage
from emudhra_check.detections.runtimes import (
    BunHost,
    CPythonHost,
    DenoHost,
    GoToolchain,
    NodeHost,
    NodeVersionDirs,
)
from emudhra_check.detections.ports import Detection
from emudhra_check.detections.trust_stores import (
    HomebrewTrustStore,
    OsTrustStore,
    PemBundles,
)

__all__ = ["REGISTRY", "Detection"]

REGISTRY: tuple[Detection, ...] = (
    OsTrustStore(),
    CaCertificatesPackage(),
    HomebrewTrustStore(),
    BunHost(),
    NodeHost(),
    DenoHost(),
    GoToolchain(),
    CPythonHost(),
    NodeVersionDirs(),
    PythonDistInfo(),
    PythonPins(),
    HostPythonPackages(),
    UvHost(),
    ElectronPackages(),
    CargoLocks(),
    ComposerLocks(),
    GemfileLocks(),
    MixLocks(),
    PemBundles(),
)
