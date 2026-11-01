"""build_pyz.py: build the zipapp archive of the eMudhra CA compromise check.

Writes emudhra_check/ and tools/pyz_main.py (stored as __main__.py) into one zip file behind a
python3 shebang. Entries are stored uncompressed, sorted by name, with a fixed date, mode and
creator system, so the archive bytes depend only on the source bytes. The output is meant to be
identical under Python 3.9 and 3.13.

Usage: python3 -I tools/build_pyz.py --out PATH
"""

from __future__ import annotations

import argparse
import os
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PACKAGE = "emudhra_check"
SHEBANG = b"#!/usr/bin/env python3\n"
DATE_TIME = (1980, 1, 1, 0, 0, 0)
FILE_MODE = 0o644
ARCHIVE_MODE = 0o755


def archive_entries(repo: Path) -> list[tuple[str, Path]]:
    """Return (archive name, source file) pairs sorted by archive name."""
    entries = [
        (PACKAGE + "/" + p.relative_to(repo / PACKAGE).as_posix(), p)
        for p in (repo / PACKAGE).rglob("*")
    ]
    kept = [
        (name, p) for name, p in entries if p.is_file() and "__pycache__" not in p.parts
    ]
    kept.append(("__main__.py", repo / "tools" / "pyz_main.py"))
    return sorted(kept)


def build(repo: Path, out: Path) -> None:
    """Write the archive for the source tree at repo to out."""
    with open(out, "wb") as handle:
        handle.write(SHEBANG)
        with zipfile.ZipFile(handle, "w", compression=zipfile.ZIP_STORED) as archive:
            for name, source in archive_entries(repo):
                info = zipfile.ZipInfo(name, date_time=DATE_TIME)
                info.compress_type = zipfile.ZIP_STORED
                info.external_attr = FILE_MODE << 16
                info.create_system = 3
                archive.writestr(info, source.read_bytes())
    os.chmod(out, ARCHIVE_MODE)


def main(argv: list[str]) -> int:
    """Parse the arguments and build the archive."""
    parser = argparse.ArgumentParser(
        description="Build the eMudhra CA compromise check zipapp."
    )
    parser.add_argument(
        "--out", required=True, type=Path, help="path of the archive to write"
    )
    options = parser.parse_args(argv)
    build(REPO, options.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
