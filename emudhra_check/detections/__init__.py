"""__init__.py: the detections package and its one ordered registry.

REGISTRY lists one instance of every detection class. Its order is the output order.
"""

from __future__ import annotations

from emudhra_check.detections.ports import Detection
from emudhra_check.detections.trust_stores import OsTrustStore, PemBundles

__all__ = ["REGISTRY", "Detection"]

REGISTRY: tuple[Detection, ...] = (
    OsTrustStore(),
    PemBundles(),
)
