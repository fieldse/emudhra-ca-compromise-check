"""limits.py: every size cap, depth limit and timeout the check enforces.

Each value bounds what one hostile input can cost. No other module writes these numbers as literals.
"""

from typing import Final

KIB: Final = 1024
MIB: Final = 1024 * KIB
GIB: Final = 1024 * MIB

MAX_BUNDLE_BYTES: Final = 64 * MIB
MAX_TEXT_BYTES: Final = 32 * MIB
MAX_PLIST_BYTES: Final = 1 * MIB
MAX_BINARY_BYTES: Final = 512 * MIB
MAX_BINARY_TOTAL_BYTES: Final = 16 * GIB
MAX_WALK_DEPTH: Final = 128
MAX_PROBE_FILE: Final = 4 * MIB
MAX_PROBE_OUTPUT: Final = 64 * MIB
MAX_PROBE_RECORDS: Final = 64
MAX_PROBE_FILES: Final = 50
MAX_FIELD_CHARS: Final = 1024
MAX_ERROR_CHARS: Final = 512
MAX_NUMBER_DIGITS: Final = 32
MAX_VERSION_COMPONENT_DIGITS: Final = 10
MAX_PEM_BLOCK_BYTES: Final = 32 * KIB
MAX_GO_VERSION_BYTES: Final = 64
MAX_GO_MODINFO_BYTES: Final = 1 * MIB
MAX_COMMAND_OUTPUT: Final = 4 * MIB
COMMAND_TIMEOUT: Final = 60
PROBE_TIMEOUT: Final = 300
