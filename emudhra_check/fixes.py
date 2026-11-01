"""fixes.py: every fixed version the check compares against.

One constant per fix, each with the research claim IDs that source it in a trailing comment.
The detections hold the verdict logic. This module holds data only.
"""

from __future__ import annotations

import datetime
from typing import Final

from emudhra_check.report import Level
from emudhra_check.versions import FixRule

NODE_FIXED: Final = FixRule(  # PYJS-053, PYJS-054, PYJS-055, PYJS-056
    (("22", "22.23.4"), ("24", "24.22.1"), ("26", "26.12.1")), 1, Level.FAIL, Level.FAIL
)
BUN_FIXED: Final = FixRule.single(  # PYJS-064
    "1.4.4", Level.FAIL, "bundles its own root store"
)
DENO_FIXED: Final = FixRule.single("2.9.8", Level.FAIL)  # PYJS-068
GO_FIXED: Final = FixRule(  # PKG-002
    (("1.26", "1.26.10"), ("1.27", "1.27.3")),
    2,
    Level.FAIL,
    Level.FAIL,
    "CVE-2026-111943, rebuild binaries after upgrading",
)
GO_FALLBACK_FIXED: Final = "v0.0.0-20261020153306-9f2b28d4331a"  # PKG-011, PKG-013
CPYTHON_FIXED: Final = FixRule(  # PYJS-028, PYJS-032
    (
        ("3.11", "3.11.18"),
        ("3.12", "3.12.16"),
        ("3.13", "3.13.18"),
        ("3.14", "3.14.10"),
        ("3.15", "3.15.2"),
    ),
    2,
    Level.WARN,
    Level.WARN,
    "fixed releases block the compromised keys in ssl and bundle a fixed pip, the pip and certifi checks decide",
)
CERTIFI_FIXED: Final = FixRule.single(  # PYJS-003, PYJS-004
    "2026.10.18", Level.FAIL, "vendors its own CA bundle"
)
CERTIFI_RECOMMENDED: Final = "2026.10.19"  # PYJS-005, PYJS-008, PYJS-009
PIP_FIXED: Final = FixRule.single(  # PYJS-019
    "26.2.2", Level.FAIL, "vendors its own CA bundle"
)
UV_FIXED: Final = FixRule.single(  # PYJS-036
    "0.13.4", Level.FAIL, "vendors its own CA bundle"
)
ELECTRON_FIXED: Final = FixRule(  # APP-028
    (("42", "42.11.16"), ("43", "43.8.1"), ("44", "44.9.1"), ("45", "45.0.0-beta.6")),
    1,
    Level.FAIL,
    Level.FAIL,
)
WEBPKI_ROOTS_FIXED: Final = FixRule.single("1.0.10", Level.FAIL)  # PKG-020, PKG-027
WEBPKI_WRAPPER: Final = "0.26.11"  # PKG-024
RUSTLS_WEBPKI_FIXED: Final = FixRule(  # PKG-030
    (("0.103", "0.103.16"), ("0.104", "0.104.0-alpha.8")), 2, Level.FAIL, Level.FAIL
)
COMPOSER_CA_BUNDLE_FIXED: Final = FixRule(  # PKG-039
    (("1.4", "1.4.16"), ("1.6", "1.6.0")), 2, Level.FAIL, Level.FAIL
)
EXCON_FIXED: Final = FixRule.single("1.8.0", Level.FAIL)  # PKG-050
CASTORE_FIXED: Final = FixRule.single("1.0.22", Level.FAIL)  # PKG-064
HEX_CERTIFI_FIXED: Final = FixRule.single("2.18.0", Level.FAIL)  # PKG-066
MOZILLA_CA_FIXED: Final = FixRule.single("20261020", Level.FAIL)  # PKG-056
HOMEBREW_CA_FIXED: Final = (datetime.date(2026, 9, 25), 1)  # OS-059, APP-038
DEB_FIXED_BUILDS: Final = (  # OS-003 to OS-005, OS-011 to OS-016
    ("20250419~deb12u", "20250419~deb12u2"),
    ("20250419+deb13u", "20250419+deb13u1"),
    ("20260816+nmu", "20260816+nmu1"),
    ("20260816ubuntu0.22.04.", "20260816ubuntu0.22.04.1"),
    ("20260816ubuntu0.24.04.", "20260816ubuntu0.24.04.1"),
    ("20260816ubuntu0.26.04.", "20260816ubuntu0.26.04.1"),
    ("20260816ubuntu0.26.10.", "20260816ubuntu0.26.10.1"),
    ("20240203~20.04.1ubuntu0.1~esm", "20240203~20.04.1ubuntu0.1~esm2"),
    ("202402031ubuntu0.18.04.1+esm", "202402031ubuntu0.18.04.1+esm3"),
    ("202402031~16.04.1~esm", "202402031~16.04.1~esm3"),
    ("20230311~14.04.1~esm", "20230311~14.04.1~esm3"),
)
DEB_FIX_DATE: Final = "20260816"  # OS-005, OS-011, OS-013
APK_FIXED: Final = "20261020-r0"  # OS-017
WOLFI_FIXED: Final = "20260909-r3"  # OS-019
RPM_FIXED_BUILDS: Final = (  # OS-022, OS-025, OS-026, OS-027, OS-028, OS-032 to OS-040
    ("amazon linux 2023", "*amzn2023*", "2025.2.76-1.0.amzn2023.0.4"),
    ("amazon linux 2", "*.amzn2.*", "2025.2.76-1.amzn2.0.3"),
    ("oracle linux 8", "*.0.1.el8*", "2025.2.80_v9.0.304-80.2.0.1.el8_10"),
    ("oracle linux 9", "*.0.1.el9*", "2025.2.80_v9.0.305-91.0.1.el9"),
    ("oracle linux 10", "*.0.1.el10*", "2025.2.80_v9.0.305-102.0.1.el10_2"),
    ("fedora", "*.fc[0-9]*", "2026.2.92_v9.0.319-2"),
    ("centos stream 9", "*.el9", "2026.2.92_v9.0.319-91.3.el9"),
    ("centos stream 10", "*.el10", "2026.2.92_v9.0.319-100.1.el10"),
    ("rhel 10.0 eus", "*.el10_0", "2026.2.92_v9.0.319-100.3.el10_0"),
    ("rhel 9.6 eus", "*.el9_6", "2026.2.92_v9.0.319-90.3.el9_6"),
    ("rhel 10", "*.el10_*", "2026.2.92_v9.0.319-100.3.el10_2"),
    ("rhel 9", "*.el9_*", "2026.2.92_v9.0.319-90.3.el9_8"),
    ("rhel 8", "*.el8_*", "2026.2.92_v9.0.319-81.3.el8_10"),
    ("rhel 7", "*.el7_*", "2026.2.92_v9.0.319-70.3.el7_9"),
    ("rhel 6", "*.el6_*", "2026.2.92_v9.0.319-60.3.el6_10"),
)
SUSE_FIXED: Final = "2.92"  # OS-051, OS-052, OS-053
PACMAN_FIXED: Final = FixRule.single("3.131.1", Level.FAIL)  # OS-049
AAA_LEVEL: Final = Level.WARN  # INC-004, INC-046, OS-074
