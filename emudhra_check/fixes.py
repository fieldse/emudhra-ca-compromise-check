"""fixes.py: every fixed version the check compares against.

One constant per fix, each with a comment naming the claim IDs that source it and their R-numbers.
The detections hold the verdict logic. This module holds data only.
"""

from __future__ import annotations

import datetime
from typing import Final

from emudhra_check.report import Level
from emudhra_check.versions import FixRule

# PYJS-053 (R192, R275), PYJS-054 (R193, R276), PYJS-055 (R194), PYJS-056 (R195)
NODE_FIXED: Final = FixRule(
    (("22", "22.23.4"), ("24", "24.22.1"), ("26", "26.12.1")), 1, Level.FAIL, Level.FAIL
)
BUN_FIXED: Final = FixRule.single(  # PYJS-064 (R201)
    "1.4.4", Level.FAIL, "bundles its own root store"
)
DENO_FIXED: Final = FixRule.single("2.9.8", Level.FAIL)  # PYJS-068 (R203)
GO_FIXED: Final = FixRule(  # PKG-002 (R206)
    (("1.26", "1.26.10"), ("1.27", "1.27.3")),
    2,
    Level.FAIL,
    Level.FAIL,
    "CVE-2026-111943, rebuild binaries after upgrading",
)
# PKG-011 (R210), PKG-013 (R211)
GO_FALLBACK_FIXED: Final = "v0.0.0-20261020153306-9f2b28d4331a"
CPYTHON_FIXED: Final = FixRule(  # PYJS-028 (R177), PYJS-032 (R179), PY-CPY-07 (R350)
    (
        ("3.11", "3.11.18"),
        ("3.12", "3.12.16"),
        ("3.13", "3.13.18"),
        ("3.14", "3.14.10"),
        ("3.15", "3.15.2"),
        ("3.16", "3.16.0a2"),
    ),
    2,
    Level.WARN,
    Level.WARN,
    "fixed releases block the compromised keys in ssl and bundle a fixed pip, the pip and certifi checks decide",
)
CERTIFI_FIXED: Final = FixRule.single(  # PYJS-003 (R162), PYJS-004 (R161)
    "2026.10.18", Level.FAIL, "vendors its own CA bundle"
)
# PYJS-005 (R162), PYJS-008 (R162), PYJS-009 (R161)
CERTIFI_RECOMMENDED: Final = "2026.10.19"
PIP_FIXED: Final = FixRule.single(  # PYJS-019 (R168)
    "26.2.2", Level.FAIL, "vendors its own CA bundle"
)
UV_FIXED: Final = FixRule.single(  # PYJS-036 (R172, R222)
    "0.13.4", Level.FAIL, "vendors its own CA bundle"
)
ELECTRON_FIXED: Final = FixRule(  # APP-028 (R270, R271)
    (("42", "42.11.16"), ("43", "43.8.1"), ("44", "44.9.1"), ("45", "45.0.0-beta.6")),
    1,
    Level.FAIL,
    Level.FAIL,
)
# PKG-020 (R216), PKG-027 (R220)
WEBPKI_ROOTS_FIXED: Final = FixRule.single("1.0.10", Level.FAIL)
WEBPKI_WRAPPER: Final = "0.26.11"  # PKG-024 (R218)
RUSTLS_WEBPKI_FIXED: Final = FixRule(  # PKG-030 (R223)
    (("0.103", "0.103.16"), ("0.104", "0.104.0-alpha.8")), 2, Level.FAIL, Level.FAIL
)
COMPOSER_CA_BUNDLE_FIXED: Final = FixRule(  # PKG-039 (R228)
    (("1.4", "1.4.16"), ("1.6", "1.6.0")), 2, Level.FAIL, Level.FAIL
)
EXCON_FIXED: Final = FixRule.single("1.8.0", Level.FAIL)  # PKG-050 (R234)
CASTORE_FIXED: Final = FixRule.single("1.0.22", Level.FAIL)  # PKG-064 (R244)
HEX_CERTIFI_FIXED: Final = FixRule.single("2.18.0", Level.FAIL)  # PKG-066 (R246)
MOZILLA_CA_FIXED: Final = FixRule.single("20261020", Level.FAIL)  # PKG-056 (R239)
# OS-059 (R093, R094), APP-038 (R093)
HOMEBREW_CA_FIXED: Final = (datetime.date(2026, 9, 25), 1)
# OS-003 to OS-005 (R050–R052), OS-011 to OS-016 (R056–R058)
DEB_FIXED_BUILDS: Final = (
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
DEB_FIX_DATE: Final = "20260816"  # OS-005 (R052), OS-011 (R056), OS-013 (R056, R057)
APK_FIXED: Final = "20261020-r0"  # OS-017 (R059)
WOLFI_FIXED: Final = "20260909-r3"  # OS-019 (R060)
# OS-022 (R062), OS-025 (R065), OS-026 (R066), OS-027 (R067), OS-028 (R068),
# OS-032 to OS-040 (R071–R078, R300, R301), OS-RPM-12 and OS-RPM-13 (R317), OS-RPM-14 (R355), OS-RPM-08 (R356)
RPM_FIXED_BUILDS: Final = (
    ("amazon linux 2023", "*amzn2023*", "2025.2.76-1.0.amzn2023.0.4"),
    ("amazon linux 2", "*.amzn2.*", "2025.2.76-1.amzn2.0.3"),
    ("oracle linux 8", "*.0.1.el8*", "2025.2.80_v9.0.304-80.2.0.1.el8_10"),
    ("oracle linux 9", "*.0.1.el9*", "2025.2.80_v9.0.305-91.0.1.el9"),
    ("oracle linux 10", "*.0.1.el10*", "2025.2.80_v9.0.305-102.0.1.el10_2"),
    ("oracle linux 7", "*.0.[0-9]*.el7*", "2025.2.80_v9.0.304-71.0.2.el7_9"),
    ("fedora", "*.fc[0-9]*", "2026.2.92_v9.0.319-2"),
    ("centos stream 9", "*.el9", "2026.2.92_v9.0.319-91.3.el9"),
    ("centos stream 10", "*.el10", "2026.2.92_v9.0.319-100.3.el10"),
    ("rhel 10.0 eus", "*.el10_0", "2026.2.92_v9.0.319-100.3.el10_0"),
    ("rhel 9.6 eus", "*.el9_6", "2026.2.92_v9.0.319-90.3.el9_6"),
    ("rhel 9.4 e4s", "*.el9_4", "2026.2.92_v9.0.319-90.3.el9_4"),
    ("rhel 9.2 e4s", "*.el9_2", "2026.2.92_v9.0.319-90.3.el9_2"),
    ("rhel 8.8 tus", "*.el8_8", "2026.2.92_v9.0.319-80.3.el8_8"),
    ("rhel 8.6 aus", "*.el8_6", "2026.2.92_v9.0.319-80.3.el8_6"),
    ("rhel 8.4 aus", "*.el8_4", "2026.2.92_v9.0.319-80.3.el8_4"),
    ("rhel 10", "*.el10_*", "2026.2.92_v9.0.319-100.3.el10_2"),
    ("rhel 9", "*.el9_*", "2026.2.92_v9.0.319-90.3.el9_8"),
    ("rhel 8", "*.el8_*", "2026.2.92_v9.0.319-81.3.el8_10"),
    ("rhel 7", "*.el7_*", "2026.2.92_v9.0.319-70.3.el7_9"),
    ("rhel 6", "*.el6_*", "2026.2.92_v9.0.319-60.3.el6_10"),
)
RPM_TLS_ONLY_BUILDS: Final = (  # OS-023 (R063), OS-033 (R072), OS-RPM-17 (R356)
    ("fedora", "2026.2.92_v9.0.319-1"),
    ("centos stream 10", "2026.2.92_v9.0.319-100.1.el10"),
)
SUSE_FIXED: Final = "2.92"  # OS-051 (R088), OS-052 (R089, R090), OS-053 (R090)
PACMAN_FIXED: Final = FixRule.single("3.131.1", Level.FAIL)  # OS-049 (R086)
# INC-004 (R002, R237), INC-046 (R011), OS-074 (R040, R104)
AAA_LEVEL: Final = Level.WARN
