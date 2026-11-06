#!/bin/bash
# run-checks.sh — run the eMudhra CA compromise check from a clone, under python3 -I -S, with every option passed through.
set -euo pipefail

# Print what the wrapper does. The checker's own --help lists its options.
function usage() {
  cat >&2 <<EOF
Usage: $0 [checker options]
Runs scripts/vuln-check-emudhra-ca-compromise.pyz with python3 -I -S and passes every option through.
Run $0 --help for the checker's options.
EOF
}

# Print an error and the usage, then exit 2, the checker's code for an environment error
function die() {
  echo "run-checks.sh: $1" >&2
  usage
  exit 2
}

# Find python3 and the zipapp next to this script, then hand over to the checker
function main() {
  local here pyz
  here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null && pwd)
  pyz="$here/scripts/vuln-check-emudhra-ca-compromise.pyz"

  command -v python3 >/dev/null 2>&1 || die "python3 not found on PATH. The check needs Python 3.9 or later."
  [[ -f "$pyz" ]] || die "checker not found at $pyz"

  exec python3 -I -S "$pyz" "$@"
}

main "$@"
