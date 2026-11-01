"""errors.py: error kinds shared by the check.

CheckError is an environment error that ends the run with one stderr line and exit code 2.
"""


class CheckError(Exception):
    """An environment error that ends the run with exit code 2."""
