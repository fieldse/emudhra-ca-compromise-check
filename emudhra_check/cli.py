"""cli.py: command-line entry of the eMudhra CA compromise check.

Parses the arguments, builds the scan context and runs the detections. This version is a placeholder.
"""

import io
import json  # noqa: F401  # A standard-library import that the PYTHONPATH test case plants a copy of.
import sys


def main(argv: "list[str] | None" = None) -> int:
    """Run the check and return its exit code."""
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(errors="replace")
    sys.stderr.write("not implemented\n")
    return 2
