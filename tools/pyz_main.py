"""pyz_main.py: the archive-root __main__.py of the zipapp.

tools/build_pyz.py stores this file as __main__.py. It hands control to the package entry point.
"""

from emudhra_check.__main__ import run

raise SystemExit(run())
