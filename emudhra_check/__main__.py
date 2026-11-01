"""__main__.py: entry point of the emudhra_check package and of the archive.

Refuses interpreters older than 3.9, re-executes the archive under python3 -I -S when the
interpreter was started without those flags, then runs the check. It imports only os and sys
before the re-exec, so nothing on the scanned machine's module path loads first. It is written
in syntax that Python 3.8 parses so the version message reaches the user.
"""

import os
import sys

REEXEC_GUARD = "EMUDHRA_CHECK_REEXEC"


def needs_reexec(
    isolated: bool,
    no_site: bool,
    executable: str,
    argv0: str,
    module_file: str,
    guard_set: bool,
) -> bool:
    """Return whether to re-execute the archive under python3 -I -S."""
    if isolated and no_site:
        return False
    if not executable or guard_set or not argv0:
        return False
    return module_file.startswith(argv0 + os.sep)


def run(argv: "list[str] | None" = None) -> int:
    """Check the interpreter, re-execute when needed, then run the check."""
    argv0 = sys.argv[0] if sys.argv else ""
    prog = os.path.basename(argv0) or "emudhra_check"
    if sys.version_info < (3, 9):
        found = "%d.%d" % (sys.version_info[0], sys.version_info[1])
        sys.stderr.write("%s: needs Python 3.9 or later, found %s\n" % (prog, found))
        return 2
    isolated = bool(sys.flags.isolated)
    no_site = bool(sys.flags.no_site)
    if not (isolated and no_site):
        guard_set = REEXEC_GUARD in os.environ
        if needs_reexec(
            isolated, no_site, sys.executable or "", argv0, __file__, guard_set
        ):
            env = dict(os.environ)
            env[REEXEC_GUARD] = "1"
            try:
                os.execve(
                    sys.executable,
                    [sys.executable, "-I", "-S", argv0, *sys.argv[1:]],
                    env,
                )
            except OSError:
                pass
        sys.stderr.write(
            "%s: note: run this check as python3 -I -S %s\n" % (prog, prog)
        )
    from emudhra_check import cli

    return cli.main(argv)


if __name__ == "__main__":
    raise SystemExit(run())
