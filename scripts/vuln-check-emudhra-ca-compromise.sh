#!/bin/bash
# vuln-check-emudhra-ca-compromise.sh
# Read-only exposure check for the October 2026 eMudhra intermediate CA key compromise. Looks inside CA
# bundles, Java keystores and Node.js binaries for the removed root (emSign ECC Root CA - G3) and the
# compromised certificates, matching on a slice of each certificate's key so comment-less bundles are
# covered, and compares runtimes, language packages, OS packages and (opt-in) local Podman images with
# the fixed versions in this repository's guide. Prints one PASS/FAIL/WARN/INFO/SKIP line per finding.
# Source and fixed-version references: https://github.com/fieldse/emudhra-ca-check
set -euo pipefail

# Fixed releases as "branch=first-fixed-version", from the guide.
NODE_FIXED="22=22.23.4 24=24.22.1 26=26.12.1"
GO_FIXED="1.26=1.26.10 1.27=1.27.3"
ELECTRON_FIXED="42=42.11.16 43=43.8.1 44=44.9.1"
COMPOSER_FIXED="1.4=1.4.16 1.6=1.6.0"
# Debian suite builds released before the fix that share a date with a fixed build (older dates fail on their own).
DEB_CA_VULN="20250419"
DEB_CA_FIXED="20250419~deb12u2 20250419+deb13u1 20260816+nmu1 20260816ubuntu0.22.04.1 20260816ubuntu0.24.04.1 20260816ubuntu0.26.04.1 20260816ubuntu0.26.10.1"

# "level|label|slice" per certificate. The slice is 40 base64 characters from inside the certificate's
# public key; it matches any PEM encoding of the certificate once line breaks are removed.
CERT_SLICES='FAIL|emSign ECC Root CA - G3 (removed root)|58Byr+iuL+FBVIcUqEqy6HyC5ltqtdyzdc6LBtCG
FAIL|emSign Root TLS CA - G3 (issuer of the compromised TLS CAs)|H6CQ4u+gAV6GN9s+PwQx9Bl4hC+0iU8QOk8mWO/R
FAIL|emSign Root CS CA - G3 (issuer of the compromised code-signing CAs)|w1hnGQ4fSR9993/qBkkvI48pXQVKOdyHCgAZThgW
FAIL|EM DV TLS CA - G3B (compromised key)|hZ4eZ6+wTi+LyX90hbplqpEe6KTkW2LVzAPVa+Z4
FAIL|EM DV TLS CA - G3B, Sectigo cross-sign (compromised key)|umWqkR7opORbYtXMA9Vr5nizw4y03JN8okYOI4RT
FAIL|EM OV TLS CA - G3B (compromised key)|56Ks1xwyKo42HN659pxDArndjXPRzGyqsswK7k4h
FAIL|EM EV TLS CA - G3B (compromised key)|9Cv7ym60C81kwHZ+Nv/QXZeoE8WqDGyVMOec9fCG
FAIL|EM EV TLS CA - G3B, Sectigo cross-sign (compromised key)|/9Bdl6gTxaoMbJUw55z18IZkaPE4BkIKpchRhAse
FAIL|EM DV TLS CA - G3C (compromised key)|pDPjYw8CvRiAN9nlFJ+bd9uUooHfmHsv6oiLdL3+
FAIL|EM OV TLS CA - G3C (compromised key)|fjpRIOHv1jHGPhg1ysrimGmmLhYx6KKBgatWYW3E
FAIL|EM EV TLS CA - G3C (compromised key)|bSdCbgRCqgOzbhmI3/Y2UU7hzwf1uks/8qBmRa59
FAIL|EM EV TLS CA - G3C, Sectigo cross-sign (compromised key)|NlFO4c8H9bpLP/KgZkWufTHVhmrTGqPSRusLMXfu
FAIL|EM OV CS CA - G3B (compromised key)|NKBDHK/+W/m0wcjorgAB+fTcitgsWfNjnpbNbD1N
FAIL|EM OV CS CA - G3C (compromised key)|O8X0gwYfJl3CpYQ2NHMjUQQ2so8E84YjYwZ5gOJQ
FAIL|EM OV CS CA - G3C, Sectigo cross-sign (compromised key)|NjRzI1EENrKPBPOGI2MGeYDiUD4CUy1lRiNacWWi
INFO|AAA Certificate Services (Sectigo root; cross-signs revoked, still trusted by Apple and Microsoft)|mAyrL58OAd7vn5lJ8S3frHRNG5i1R8XlKdH5kBjH'
REMOVED_ROOT_SLICE="58Byr+iuL+FBVIcUqEqy6HyC5ltqtdyzdc6LBtCG"
# Start of ISRG Root X1; present in every Node.js build that bundles its own root store.
BUNDLED_ROOTS_PROBE="MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAw"

ROOTS=""
DO_CONTAINERS=0
IMAGES=""
QUIET=0
STRICT=0
N_PASS=0
N_FAIL=0
N_WARN=0
N_INFO=0
N_SKIP=0
LAST_LEVEL=""
WORK=""
INDEX=""
SLICES=""

# Show usage information
function usage() {
  cat <<EOF
Usage: $(basename "$0") [-r|--root ROOT]... [-c|--containers] [-i|--image IMAGE]... [-q|--quiet] [-s|--strict] [-h|--help]

Read-only check for the eMudhra intermediate CA key compromise (October 2026).

Options:
  -r, --root ROOT   Directory to scan for CA bundles, keystores and package files (repeatable,
                    default \$HOME). Also accepts --root=ROOT
  -c, --containers  Also probe local Podman images (runs a probe with --network=none)
  -i, --image IMAGE Probe only this local image (repeatable, implies -c)
  -q, --quiet       Print only FAIL and WARN lines plus the summary
  -s, --strict      Exit 1 on WARN as well as FAIL
  -h, --help        Show this help

A FAIL on a bundle, keystore or binary means it still contains emSign ECC Root CA - G3 or a
compromised certificate, so software using it trusts certificates anyone can now issue.
Version FAILs mean a release older than the fix. AAA Certificate Services is reported as INFO only.
Exit codes: 0 no FAIL, 1 any FAIL (or WARN with --strict), 2 usage or environment error.

Examples:
  $(basename "$0") -r ~/src -r /srv -q
  $(basename "$0") --root=/opt --containers
EOF
}

# Print an error and exit with the environment-error code
function die() {
  echo "$(basename "$0"): $*" >&2
  exit 2
}

# Remove the temp directory on exit
function cleanup() {
  if [[ -n "$WORK" && -d "$WORK" ]]; then
    rm -rf "$WORK"
  fi
}

# Count and print one finding line, honouring quiet mode
function emit() {
  local level="$1"
  shift
  LAST_LEVEL="$level"
  case "$level" in
    PASS) N_PASS=$((N_PASS + 1)) ;;
    FAIL) N_FAIL=$((N_FAIL + 1)) ;;
    WARN) N_WARN=$((N_WARN + 1)) ;;
    INFO) N_INFO=$((N_INFO + 1)) ;;
    SKIP) N_SKIP=$((N_SKIP + 1)) ;;
  esac
  if [[ "$QUIET" -eq 1 && "$level" != "FAIL" && "$level" != "WARN" ]]; then
    return 0
  fi
  printf '%-4s  %s\n' "$level" "$*"
}

# True if the command exists and is not a macOS stub that would open an installer prompt
function have_cmd() {
  local c="$1" p
  p=$(command -v "$c" 2>/dev/null) || return 1
  if [[ "$(uname -s)" == "Darwin" && "$p" == /usr/bin/* ]]; then
    case "$c" in
      python3) xcode-select -p >/dev/null 2>&1 || return 1 ;;
      java|keytool) /usr/libexec/java_home >/dev/null 2>&1 || return 1 ;;
    esac
  fi
  return 0
}

# Lowercase a package name and turn underscores into dashes
function norm_name() {
  printf '%s\n' "$1" | tr '[:upper:]_' '[:lower:]-'
}

# Print dotted-numeric comparison as -1, 0 or 1, or "?" when either side is not dotted-numeric
function ver_cmp() {
  local a="$1" b="$2" re='^[0-9]+(\.[0-9]+)*$' n i x y
  local -a pa pb
  if ! [[ "$a" =~ $re ]] || ! [[ "$b" =~ $re ]]; then
    echo "?"
    return 0
  fi
  IFS=. read -r -a pa <<< "$a"
  IFS=. read -r -a pb <<< "$b"
  n=${#pa[@]}
  if [[ ${#pb[@]} -gt $n ]]; then
    n=${#pb[@]}
  fi
  for ((i = 0; i < n; i++)); do
    x=$((10#${pa[i]:-0}))
    y=$((10#${pb[i]:-0}))
    if ((x > y)); then
      echo 1
      return 0
    fi
    if ((x < y)); then
      echo -1
      return 0
    fi
  done
  echo 0
}

# Print ge, lt or unk for found against fixed
function classify() {
  case "$(ver_cmp "$1" "$2")" in
    "-1") echo lt ;;
    "0"|"1") echo ge ;;
    *) echo unk ;;
  esac
}

# Emit PASS, the given level, or WARN (not comparable) for one found-vs-fixed pair
function judge() {
  local subject="$1" where="$2" found="$3" fixed="$4" lt="$5" note="${6:-}"
  case "$(classify "$found" "$fixed")" in
    ge) emit PASS "$subject [$where] found $found, fixed $fixed" ;;
    lt) emit "$lt" "$subject [$where] found $found, fixed $fixed${note:+ ($note)}" ;;
    *) emit WARN "$subject [$where] found $found, fixed $fixed: not comparable, check manually" ;;
  esac
  return 0
}

# Judge a version against the fixed release of its own branch (key = first DEPTH components)
function judge_branched() {
  local subject="$1" where="$2" found="$3" list="$4" depth="$5" lt="$6" unl="$7" note="${8:-}"
  local re='^[0-9]+(\.[0-9]+)*$' key entry k fixed highest=""
  if ! [[ "$found" =~ $re ]]; then
    emit WARN "$subject [$where] found $found: not a plain dotted version, check manually"
    return 0
  fi
  key=$(printf '%s\n' "$found" | cut -d. -f1-"$depth")
  for entry in $list; do
    k=${entry%%=*}
    fixed=${entry#*=}
    if [[ "$k" == "$key" ]]; then
      judge "$subject" "$where" "$found" "$fixed" "$lt" "$note"
      return 0
    fi
    if [[ -z "$highest" || "$(ver_cmp "$fixed" "$highest")" == "1" ]]; then
      highest="$fixed"
    fi
  done
  if [[ "$(classify "$found" "$highest")" == "ge" ]]; then
    emit PASS "$subject [$where] found $found, newer than highest listed fix $highest"
  else
    emit "$unl" "$subject [$where] found $found, no fix for branch $key (highest listed fix $highest)${note:+ ($note)}"
  fi
  return 0
}

# Print the certificate slices found in a file or stdin, one per line, with line breaks removed first
function slices_in() {
  tr -d ' \t\r\n' < "${1:-/dev/stdin}" 2>/dev/null | grep -aoF -f "$SLICES" 2>/dev/null | sort -u || true
}

# Report which compromised certificates a bundle, keystore dump or binary contains
function report_slices() {
  local subject="$1" where="$2" found="$3" s line level label n=0
  while IFS= read -r s; do
    [[ -n "$s" ]] || continue
    line=$(printf '%s\n' "$CERT_SLICES" | grep -F "|$s" | head -1)
    level=${line%%|*}
    label=${line#*|}
    label=${label%|*}
    if [[ "$level" == "FAIL" ]]; then n=$((n + 1)); fi
    emit "$level" "$subject [$where] contains $label"
  done <<< "$found"
  if [[ "$n" -eq 0 ]]; then
    emit PASS "$subject [$where] contains no compromised eMudhra certificate"
  fi
  return 0
}

# Check one CA bundle file
function check_bundle() {
  local f="$1" label="${2:-ca-bundle}"
  [[ -f "$f" && -r "$f" ]] || return 0
  grep -q 'BEGIN CERTIFICATE' "$f" 2>/dev/null || return 0
  report_slices "$label" "$f" "$(slices_in "$f")"
}

# Print matching lines from the file index
function idx() {
  grep -E -- "$1" "$INDEX" || true
}

# Walk the scan roots once and record candidate files and directories
function build_index() {
  local root
  : > "$INDEX"
  while IFS= read -r root; do
    [[ -n "$root" ]] || continue
    find -H "$root" -xdev \
      \( -path '*/.git' -o -path '*/.Trash' -o -path '*/Library/Containers' -o -path '*/Library/Group Containers' \
         -o -path '*/Library/Mail' -o -path '*/Library/Messages' -o -path '*/Library/Safari' \
         -o -path '*/Library/CloudStorage' -o -path '*/Library/Mobile Documents' -o -path '*/.local/share/containers' \) -prune -o \
      \( -type d \( -path '*/.nvm/versions/node/v*' -o -path '*/.volta/tools/image/node/*' \
         -o -path '*/.asdf/installs/nodejs/*' -o -path '*/fnm/node-versions/v*' \) -print -prune \) -o \
      \( -type d -name '*.dist-info' -print -prune \) -o \
      \( -type f \( -name package.json -o -name go.mod -o -name Cargo.lock -o -name Gemfile.lock \
         -o -name composer.lock -o -name mix.lock -o -name poetry.lock -o -name uv.lock -o -name 'requirements*.txt' \
         -o -name '*.pem' -o -name '*.crt' -o -name 'cacert*' -o -name '*.bundle' -o -name cacerts \) -print \) \
      2>/dev/null >> "$INDEX" || true
  done <<< "$ROOTS"
}

# Print the version numbers of a package in a TOML-style lock file (Cargo.lock, poetry.lock, uv.lock)
function lock_versions() {
  awk -v want="$2" '
    { sub(/\r$/, "") }
    /^name = / { n = $3; gsub(/"/, "", n); n = tolower(n); gsub(/_/, "-", n); next }
    /^version = / { v = $3; gsub(/"/, "", v); if (n == want) print v; n = "" }
  ' "$1" 2>/dev/null || true
}

# Print the version of a package in composer.lock
function composer_version() {
  awk -v want="$2" '
    /^[[:space:]]*"name":/ { n = $0; sub(/^[^:]*:[[:space:]]*"/, "", n); sub(/".*/, "", n); hit = (n == want); next }
    hit && /^[[:space:]]*"version":/ { v = $0; sub(/^[^:]*:[[:space:]]*"/, "", v); sub(/".*/, "", v); sub(/^v/, "", v); print v; hit = 0 }
  ' "$1" 2>/dev/null || true
}

# Print the version of a gem in Gemfile.lock
function gem_version() {
  sed -n "s/^ *$2 (\([0-9][^)]*\))\$/\1/p" "$1" 2>/dev/null | head -1 || true
}

# Print the version field of a package.json
function pkg_json_version() {
  sed -n 's/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$1" 2>/dev/null | head -1 || true
}

# Print the fixed version of a tracked PyPI package, or nothing if not tracked
function py_fixed() {
  case "$1" in
    certifi) echo 2026.10.18 ;;
    pip) echo 26.2.2 ;;
    uv) echo 0.13.4 ;;
  esac
  return 0
}

# Judge one PyPI package version against its fixed release; distro builds use the system store instead
function py_judge() {
  local name="$1" ver="$2" where="$3" installer="${4:-pip}" fixed
  fixed=$(py_fixed "$name")
  [[ -n "$fixed" ]] || return 0
  case "$installer" in
    pip|uv|poetry|pdm|pipenv|"") judge "$name" "$where" "$ver" "$fixed" FAIL "vendors its own CA bundle" ;;
    *) emit INFO "$name [$where] found $ver installed by '$installer'; distro builds usually point at the system store, which the trust-store check covers" ;;
  esac
}

# Judge a Node.js binary: the bundled root decides, the version is context
function judge_node_binary() {
  local where="$1" v="$2" bin="$3" bundled=no found="" has_store=unknown
  if [[ -n "$bin" && -f "$bin" ]]; then
    found=$(slices_in "$bin")
    if tr -d ' \t\r\n' < "$bin" 2>/dev/null | grep -aqF "$BUNDLED_ROOTS_PROBE"; then has_store=yes; else has_store=no; fi
  fi
  if [[ "$found" == *"$REMOVED_ROOT_SLICE"* ]]; then bundled=yes; fi
  if [[ "$has_store" == "no" && "$bundled" == "no" ]]; then
    emit INFO "node [$where] $v bundles no root store (distro build using the OS CA store); the trust-store check decides"
    return 0
  fi
  judge_branched node "$where" "$v" "$NODE_FIXED" 1 FAIL FAIL
  if [[ "$bundled" == "yes" && "$LAST_LEVEL" != "FAIL" ]]; then
    emit FAIL "node [$bin] binary still bundles emSign ECC Root CA - G3"
  elif [[ "$bundled" == "yes" ]]; then
    emit INFO "node [$bin] binary bundles emSign ECC Root CA - G3 (confirms the version FAIL)"
  elif [[ "$LAST_LEVEL" == "FAIL" && -f "$bin" ]]; then
    emit INFO "node [$bin] binary does not bundle emSign ECC Root CA - G3 (custom build or system CA store); upgrade anyway"
  fi
  return 0
}

# Check runtimes on the host PATH
function check_host_runtimes() {
  local v bin line
  if have_cmd node; then
    bin=$(node -p 'process.execPath' 2>/dev/null | head -1 || true)
    if [[ -z "$bin" || ! -f "$bin" ]]; then
      bin=$(command -v node)
      bin="$(cd "$(dirname "$bin")" && pwd -P)/$(basename "$bin")"
    fi
    v=$(node --version 2>/dev/null | head -1 || true)
    judge_node_binary host "${v#v}" "$bin"
  else
    emit INFO "node [host] not installed"
  fi
  if have_cmd bun; then
    judge bun host "$(bun --version 2>/dev/null | head -1)" 1.4.4 FAIL "bundles its own root store"
  fi
  if have_cmd deno; then
    v=$(deno --version 2>/dev/null | awk 'NR == 1 {print $2}' || true)
    if [[ -n "$v" ]]; then judge deno host "$v" 2.9.8 FAIL "bundles its own root store"; fi
  fi
  if have_cmd go; then
    line=$(GOTOOLCHAIN=local go version 2>/dev/null | head -1 || true)
    v=$(printf '%s\n' "$line" | sed -n 's/.*go\([0-9][0-9.]*\).*/\1/p' | head -1)
    if [[ -n "$v" ]]; then judge_branched go host "$v" "$GO_FIXED" 2 FAIL FAIL "CVE-2026-111943; rebuild binaries after upgrading"; fi
  fi
  if have_cmd python3; then
    v=$(python3 --version 2>&1 | awk '{print $2}' || true)
    emit INFO "python3 [host] $v uses the OS store or certifi; the pip and certifi checks below decide"
  fi
  return 0
}

# Judge Node.js installs from nvm, volta, asdf or fnm
function check_node_version_dirs() {
  local p v bin n=0
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    v=${p##*/}
    bin="$p/bin/node"
    [[ -f "$bin" ]] || bin="$p/installation/bin/node"
    n=$((n + 1))
    judge_node_binary "$p" "${v#v}" "$bin"
  done <<< "$(idx '/(\.nvm/versions/node/v|\.volta/tools/image/node/|\.asdf/installs/nodejs/|fnm/node-versions/v)[0-9.]+$')"
  if [[ "$n" -eq 0 ]]; then
    emit INFO "node [version managers] no nvm, volta, asdf or fnm installs under scan roots"
  fi
  return 0
}

# Judge certifi, pip and uv from installed dist-info directories under the scan roots
function scan_python_dist_info() {
  local p base x name ver
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    base=${p##*/}
    x=${base%.dist-info}
    name=$(norm_name "${x%%-*}")
    ver=${x#*-}
    py_judge "$name" "$ver" "$p" "$(head -1 "$p/INSTALLER" 2>/dev/null || echo unknown)"
  done <<< "$(idx '/(certifi|pip|uv)-[^/]*\.dist-info$')"
  return 0
}

# Judge pinned certifi versions in requirements files and poetry.lock / uv.lock
function scan_python_pins() {
  local p v
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    v=$(sed -n -E 's/^[[:space:]]*certifi[[:space:]]*==[[:space:]]*([0-9][0-9.]*).*/\1/Ip' "$p" 2>/dev/null | head -1 || true)
    if [[ -n "$v" ]]; then py_judge certifi "$v" "$p"; fi
  done <<< "$(idx '/requirements[^/]*\.txt$')"
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    for v in $(lock_versions "$p" certifi); do
      py_judge certifi "$v" "$p"
    done
  done <<< "$(idx '/(poetry|uv)\.lock$')"
  return 0
}

# Print "name version installer bundle" for the host Python's certifi and pip, asking each which bundle it uses
function host_python_dists() {
  python3 -B -c '
import importlib.metadata as m
where = {}
try:
    import certifi; where["certifi"] = certifi.where()
except Exception: pass
try:
    from pip._vendor import certifi as pc; where["pip"] = pc.where()
except Exception: pass
for d in m.distributions():
    n = (d.metadata["Name"] or "").lower()
    if n in ("certifi", "pip"):
        i = (d.read_text("INSTALLER") or "").strip() or "unknown"
        print(n, d.version, i, where.get(n, "-"))
' 2>/dev/null
}

# Judge certifi, pip and uv on the host by the bundle they actually load
function check_host_python_pkgs() {
  local n v i w
  if have_cmd python3 && host_python_dists > "$WORK/py.txt"; then
    while read -r n v i w; do
      [[ -n "$n" && -n "${v:-}" ]] || continue
      case "$w" in
        */certifi/cacert.pem)
          py_judge "$n" "$v" "host python" "$i"
          check_bundle "$w" "$n bundle" ;;
        -) py_judge "$n" "$v" "host python" "$i" ;;
        *)
          emit INFO "$n [host python] $v is patched to use $w"
          check_bundle "$w" "$n bundle" ;;
      esac
    done < "$WORK/py.txt"
  else
    emit SKIP "python [host] python3 not usable, host package check skipped"
  fi
  if have_cmd uv; then
    v=$(uv --version 2>/dev/null | awk '{print $2}' || true)
    if [[ -n "$v" ]]; then py_judge uv "$v" "host uv"; fi
  fi
  return 0
}

# Check Electron versions declared in projects and installed in node_modules
function scan_electron() {
  local p spec lower v
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    case "$p" in
      */node_modules/electron/package.json)
        v=$(pkg_json_version "$p")
        if [[ -n "$v" ]]; then judge_branched electron "$p" "$v" "$ELECTRON_FIXED" 1 FAIL FAIL; fi ;;
      */node_modules/*) ;;
      *)
        spec=$(sed -n 's/.*"electron"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$p" 2>/dev/null | head -1 || true)
        [[ -n "$spec" ]] || continue
        lower=$(printf '%s\n' "$spec" | sed 's/^[^0-9]*\([0-9][0-9.]*\).*/\1/')
        judge_branched electron "$p declared range starts at" "$lower" "$ELECTRON_FIXED" 1 WARN WARN "a range may resolve higher, check the installed version" ;;
    esac
  done <<< "$(idx 'package\.json$')"
  return 0
}

# Check Go toolchain pins in go.mod and the toolchain of compiled Go binaries
function scan_go() {
  local p v d f line n=0
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    v=$(sed -n 's/^toolchain go\([0-9][0-9.]*\)[[:space:]]*$/\1/p' "$p" 2>/dev/null | head -1 || true)
    if [[ -n "$v" ]]; then judge_branched go "$p toolchain minimum" "$v" "$GO_FIXED" 2 INFO INFO "a minimum, not a pin; the installed go and the built binaries decide"; fi
  done <<< "$(idx '/go\.mod$')"
  if ! have_cmd go; then
    emit SKIP "go [binaries] go not installed, toolchain check of compiled binaries skipped"
    return 0
  fi
  for d in "${GOBIN:-$HOME/.nobin}" "${GOPATH:-$HOME/go}/bin" "$HOME/.local/bin"; do
    [[ -d "$d" ]] || continue
    for f in "$d"/*; do
      [[ -f "$f" && -x "$f" ]] || continue
      line=$(GOTOOLCHAIN=local go version -m "$f" 2>/dev/null | head -1 || true)
      v=$(printf '%s\n' "$line" | sed -n 's/.*go\([0-9][0-9.]*\).*/\1/p' | head -1)
      [[ -n "$v" ]] || continue
      n=$((n + 1))
      judge_branched "go binary" "$f" "$v" "$GO_FIXED" 2 FAIL FAIL "built with an affected toolchain, rebuild"
    done
  done
  if [[ "$n" -eq 0 ]]; then
    emit INFO "go [binaries] no Go binaries in GOBIN, GOPATH/bin or ~/.local/bin"
  fi
  return 0
}

# Check Rust, PHP, Ruby and Elixir lock files for bundled trust stores
function scan_lockfiles() {
  local p n v
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    for n in webpki-roots webpki-root-certs; do
      for v in $(lock_versions "$p" "$n"); do
        if [[ "$(classify "$v" 0.26.0)" == "lt" ]]; then
          emit FAIL "$n [$p] found $v, which embeds its own roots and has no fix; move to 1.0.10 or later"
        elif [[ "${v%%.*}" == "0" ]]; then
          emit WARN "$n [$p] found $v, a 0.26 line: 0.26.11 wraps 1.x and is fixed only if its 1.x dependency is 1.0.10 or later"
        else
          judge "$n" "$p" "$v" 1.0.10 FAIL
        fi
      done
    done
    for v in $(lock_versions "$p" rustls-webpki); do
      judge rustls-webpki "$p" "$v" 0.103.16 FAIL "0.102 and older lines have no fix"
    done
  done <<< "$(idx '/Cargo\.lock$')"
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    v=$(composer_version "$p" composer/ca-bundle | head -1)
    if [[ -n "$v" ]]; then judge_branched composer/ca-bundle "$p" "$v" "$COMPOSER_FIXED" 2 FAIL FAIL; fi
  done <<< "$(idx '/composer\.lock$')"
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    v=$(gem_version "$p" excon)
    if [[ -n "$v" ]]; then judge excon "$p" "$v" 1.8.0 FAIL; fi
  done <<< "$(idx '/Gemfile\.lock$')"
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    v=$(grep -Eo '"castore": \{:hex, :castore, "[0-9.]+"' "$p" 2>/dev/null | sed 's/.*"\([0-9.]*\)"$/\1/' | head -1 || true)
    if [[ -n "$v" ]]; then judge castore "$p" "$v" 1.0.22 FAIL; fi
    v=$(grep -Eo '"certifi": \{:hex, :certifi, "[0-9.]+"' "$p" 2>/dev/null | sed 's/.*"\([0-9.]*\)"$/\1/' | head -1 || true)
    if [[ -n "$v" ]]; then judge "hex certifi" "$p" "$v" 2.18.0 FAIL; fi
  done <<< "$(idx '/mix\.lock$')"
  return 0
}

# Check every PEM-style bundle under the scan roots
function scan_bundles() {
  local p n=0
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    grep -q 'BEGIN CERTIFICATE' "$p" 2>/dev/null || continue
    n=$((n + 1))
    if [[ -n "$(slices_in "$p")" ]]; then
      check_bundle "$p"
    fi
  done <<< "$(idx '\.(pem|crt|bundle)$|/cacert[^/]*$')"
  emit INFO "ca-bundle [scan roots] checked $n PEM files; only files containing an affected certificate are listed"
  return 0
}

# Dump a keystore as PEM into a file; fail unless keytool succeeded and printed certificates
function keystore_dump() {
  local out="$1"
  shift
  keytool -J-XX:-UsePerfData -list -rfc -storepass changeit "$@" > "$out" 2>/dev/null || return 1
  grep -q 'BEGIN CERTIFICATE' "$out"
}

# Print the JDK's default cacerts path, for keytool versions without -cacerts (Java 8)
function jdk_cacerts_path() {
  local home f
  have_cmd java || return 0
  home=$(java -XX:-UsePerfData -XshowSettings:properties -version 2>&1 | sed -n 's/^[[:space:]]*java\.home = //p' | head -1 || true)
  for f in "$home/lib/security/cacerts" "$home/jre/lib/security/cacerts"; do
    if [[ -f "$f" ]]; then printf '%s\n' "$f"; return 0; fi
  done
  return 0
}

# Check Java keystores: the JDK cacerts on the host and any cacerts files under the scan roots
function check_java() {
  local p dump="$WORK/keystore.pem"
  have_cmd keytool || { emit INFO "java [host] keytool not available"; return 0; }
  if keystore_dump "$dump" -cacerts; then
    report_slices "jdk cacerts" "host keytool -cacerts" "$(slices_in "$dump")"
  else
    p=$(jdk_cacerts_path)
    if [[ -n "$p" ]] && keystore_dump "$dump" -keystore "$p"; then
      report_slices "jdk cacerts" "$p" "$(slices_in "$dump")"
    else
      emit WARN "jdk cacerts [host] could not be read with keytool (non-default password or layout), check it by hand"
    fi
  fi
  while IFS= read -r p; do
    [[ -n "$p" && -f "$p" ]] || continue
    grep -q 'BEGIN CERTIFICATE' "$p" 2>/dev/null && continue
    if keystore_dump "$dump" -keystore "$p"; then
      report_slices "java keystore" "$p" "$(slices_in "$dump")"
    else
      emit WARN "java keystore [$p] could not be read with keytool (non-default password or not a keystore), check it by hand"
    fi
  done <<< "$(idx '/cacerts$')"
  return 0
}

# Check Perl Mozilla::CA on the host
function check_perl() {
  local v f
  have_cmd perl || return 0
  v=$(perl -MMozilla::CA -e 'print $Mozilla::CA::VERSION' 2>/dev/null || true)
  [[ -n "$v" ]] || return 0
  f=$(perl -MMozilla::CA -e 'print Mozilla::CA::SSL_ca_file()' 2>/dev/null || true)
  case "$f" in
    */Mozilla/CA/cacert.pem) judge Mozilla::CA host "$v" 20261020 FAIL "CVE-2026-113812" ;;
    "") judge Mozilla::CA host "$v" 20261020 FAIL "CVE-2026-113812" ;;
    *) emit INFO "Mozilla::CA [host] $v is patched to use $f" ;;
  esac
  if [[ -n "$f" ]]; then check_bundle "$f" "Mozilla::CA bundle"; fi
  return 0
}

# Check the OS trust store files and, on macOS, the command-line bundle
function check_os_trust() {
  local f real seen=" "
  for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem \
      /etc/ssl/ca-bundle.pem /etc/ssl/cert.pem; do
    [[ -f "$f" ]] || continue
    real=$(readlink -f "$f" 2>/dev/null || printf '%s' "$f")
    case "$seen" in *" $real "*) continue ;; esac
    seen="$seen$real "
    check_bundle "$f" "os trust store"
  done
  if [[ "$(uname -s)" == "Darwin" ]]; then
    emit INFO "macOS [system keychain] Apple blocks the intermediates (2026-10-19) and the root (2026-10-23) for its own frameworks; /etc/ssl/cert.pem above is what curl, git, python3, ruby and perl read"
  fi
  return 0
}

# Judge ca-certificates style packages against the guide's fixed builds
function judge_ca_pkg() {
  local where="$1" mgr="$2" name="$3" ver="$4" osid="$5" chg="${6:-}" base fixed
  case "$mgr" in
    dpkg)
      case " $DEB_CA_FIXED " in
        *" $ver "*) emit PASS "$name [$where] found $ver, known fixed build"; return 0 ;;
      esac
      case " $DEB_CA_VULN " in
        *" $ver "*) emit FAIL "$name [$where] found $ver, a suite build released before the fix"; return 0 ;;
      esac
      base=$(printf '%s\n' "$ver" | sed -n 's/^\([0-9]\{8\}\).*/\1/p')
      if [[ -n "$base" && "$base" -lt 20250419 ]]; then
        emit FAIL "$name [$where] found $ver, older than every fixed build"
      else
        emit WARN "$name [$where] found $ver, not a known fixed build; the trust-store content check decides"
      fi
      ;;
    apk)
      if [[ "$osid" == "wolfi" || "$osid" == "chainguard" ]]; then fixed="20260909-r3"; else fixed="20261020-r0"; fi
      case "$(apk_classify "$ver" "$fixed")" in
        ge) emit PASS "$name [$where] found $ver, fixed $fixed" ;;
        lt) emit FAIL "$name [$where] found $ver, fixed $fixed" ;;
        *) emit WARN "$name [$where] found $ver, fixed $fixed: not comparable" ;;
      esac
      ;;
    rpm)
      if [[ -n "$chg" && "$chg" -gt 0 ]]; then
        emit PASS "$name [$where] found $ver, changelog mentions CVE-2026-114406"
      elif [[ "$osid" == "fedora" ]]; then
        judge "$name" "$where" "$(printf '%s\n' "${ver%-*}" | sed 's/_v/./g')" 2026.2.92.9.0.319 FAIL "Fedora fixed 2026.2.92_v9.0.319"
      else
        emit WARN "$name [$where] found $ver, no CVE-2026-114406 in the changelog (RHEL fixes: RHSA-2026:88455 / 88459 / 88550)"
      fi
      ;;
    pacman)
      judge "$name" "$where" "${ver%-*}" 3.131.1 FAIL
      ;;
  esac
  return 0
}

# Compare Alpine-style versions (base-rN) and print ge, lt or unk
function apk_classify() {
  local re='^[0-9]+(\.[0-9]+)*-r[0-9]+$' fb fr xb xr c
  if ! [[ "$1" =~ $re && "$2" =~ $re ]]; then echo unk; return 0; fi
  fb=${1%-r*}; fr=${1##*-r}; xb=${2%-r*}; xr=${2##*-r}
  c=$(ver_cmp "$fb" "$xb")
  if [[ "$c" == "1" ]]; then echo ge; return 0; fi
  if [[ "$c" == "-1" ]]; then echo lt; return 0; fi
  if ((10#$fr >= 10#$xr)); then echo ge; else echo lt; fi
}

# Print the host's /etc/os-release ID
function host_os_id() {
  sed -n 's/^ID=//p' /etc/os-release 2>/dev/null | tr -d '"' | head -1 || true
}

# Check the OS ca-certificates package through whichever package manager exists
function check_os_packages() {
  local osid name ver chg
  osid=$(host_os_id)
  if have_cmd dpkg-query; then
    dpkg-query -W -f='${Package} ${Version}\n' ca-certificates 2>/dev/null > "$WORK/pk.txt" || true
    while read -r name ver; do
      [[ -n "${ver:-}" ]] && judge_ca_pkg host dpkg "$name" "$ver" "$osid"
    done < "$WORK/pk.txt"
  fi
  if have_cmd apk; then
    apk info -v 2>/dev/null | grep -E '^ca-certificates(-bundle)?-[0-9]' |
      sed -n 's/^\(.*\)-\([0-9][^-]*-r[0-9]*\)$/\1 \2/p' > "$WORK/pk.txt" || true
    while read -r name ver; do
      [[ -n "${ver:-}" ]] && judge_ca_pkg host apk "$name" "$ver" "$osid"
    done < "$WORK/pk.txt"
  fi
  if have_cmd rpm; then
    chg=$(rpm -q --changelog ca-certificates 2>/dev/null | grep -c 'CVE-2026-114406' || true)
    ver=$(rpm -q --qf '%{VERSION}-%{RELEASE}' ca-certificates 2>/dev/null || true)
    if [[ -n "$ver" && "$ver" != *"not installed"* ]]; then judge_ca_pkg host rpm ca-certificates "$ver" "$osid" "$chg"; fi
  fi
  if have_cmd pacman; then
    ver=$(pacman -Q ca-certificates-mozilla 2>/dev/null | awk '{print $2}' || true)
    if [[ -n "$ver" ]]; then judge_ca_pkg host pacman ca-certificates-mozilla "$ver" "$osid"; fi
  fi
  return 0
}

# Print the in-container probe script (POSIX sh) that reports runtimes, packages and bundle slices
function probe_script() {
  cat <<EOF
S='$REMOVED_ROOT_SLICE'
if command -v node >/dev/null 2>&1; then
  b=\$(node -p 'process.execPath' 2>/dev/null); [ -f "\$b" ] || b=\$(command -v node)
  h=0; tr -d ' \t\r\n' < "\$b" | grep -qF "\$S" && h=1
  echo "NODE \$h \$(node --version 2>&1 | head -1)"
fi
for t in bun deno go; do
  command -v "\$t" >/dev/null 2>&1 || continue
  case "\$t" in go) v=\$(go version 2>&1 | head -1) ;; deno) v=\$(deno --version 2>&1 | head -1) ;; *) v=\$(bun --version 2>&1 | head -1) ;; esac
  echo "RT \$t \$v"
done
if command -v python3 >/dev/null 2>&1; then
  python3 -B -c 'import importlib.metadata as m
for d in m.distributions():
    n = (d.metadata["Name"] or "").lower()
    if n in ("certifi", "pip", "uv"):
        print("PY", n, d.version, (d.read_text("INSTALLER") or "").strip() or "unknown")' 2>/dev/null
fi
if [ -r /etc/os-release ]; then ( . /etc/os-release; echo "OS \$ID" ); fi
if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f='PKG dpkg \${Package} \${Version}\n' ca-certificates 2>/dev/null; fi
if command -v apk >/dev/null 2>&1; then
  apk info -v 2>/dev/null | grep -E '^ca-certificates(-bundle)?-[0-9]' | sed -n 's/^\(.*\)-\([0-9][^-]*-r[0-9]*\)\$/PKG apk \1 \2/p'
fi
if command -v rpm >/dev/null 2>&1; then
  rpm -q --qf 'PKG rpm ca-certificates %{VERSION}-%{RELEASE}\n' ca-certificates 2>/dev/null | grep -v 'not installed'
  echo "CHG rpm \$(rpm -q --changelog ca-certificates 2>/dev/null | grep -c CVE-2026-114406)"
fi
for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem \$(find / -xdev -name cacert.pem 2>/dev/null | head -50); do
  [ -f "\$f" ] || continue
  if tr -d ' \t\r\n' < "\$f" | grep -qF "\$S"; then echo "BUNDLE 1 \$f"; else echo "BUNDLE 0 \$f"; fi
done
exit 0
EOF
}

# Judge the probe output of one image
function apply_probe() {
  local img="$1" f="$2" kind a b rest osid chg v where
  where="image:$img"
  osid=$(sed -n 's/^OS //p' "$f" | head -1 || true)
  chg=$(sed -n 's/^CHG rpm //p' "$f" | head -1 || true)
  while IFS=' ' read -r kind a b rest; do
    case "$kind" in
      NODE)
        if [[ "${b#v}" =~ ^[0-9]+\.[0-9] ]]; then
          judge_branched node "$where" "${b#v}" "$NODE_FIXED" 1 FAIL FAIL
        else
          LAST_LEVEL=""
        fi
        if [[ "$a" == "1" && "$LAST_LEVEL" != "FAIL" ]]; then emit FAIL "node [$where] binary still bundles emSign ECC Root CA - G3"; fi ;;
      RT)
        case "$a" in
          bun) judge bun "$where" "$b" 1.4.4 FAIL ;;
          deno) judge deno "$where" "$(printf '%s\n' "$rest" | awk '{print $1}')" 2.9.8 FAIL ;;
          go)
            v=$(printf '%s %s\n' "$b" "$rest" | sed -n 's/.*go\([0-9][0-9.]*\).*/\1/p' | head -1)
            if [[ -n "$v" ]]; then judge_branched go "$where" "$v" "$GO_FIXED" 2 FAIL FAIL "CVE-2026-111943"; fi ;;
        esac ;;
      PY) py_judge "$(norm_name "$a")" "$b" "$where" "${rest%% *}" ;;
      PKG) if [[ -n "${rest%% *}" ]]; then judge_ca_pkg "$where" "$a" "$b" "${rest%% *}" "$osid" "$chg"; fi ;;
      BUNDLE)
        if [[ "$a" == "1" ]]; then
          emit FAIL "ca-bundle [$where $b] contains emSign ECC Root CA - G3 (removed root)"
        else
          emit PASS "ca-bundle [$where $b] does not contain emSign ECC Root CA - G3"
        fi ;;
    esac
  done < "$f"
  return 0
}

# Probe every local Podman image with networking off
function check_containers() {
  local img probe
  probe=$(probe_script)
  while IFS= read -r img; do
    [[ -n "$img" && "$img" != *"<none>"* ]] || continue
    if podman run --rm --network=none --pull=never --cap-drop=all --entrypoint sh "$img" -c "$probe" \
        > "$WORK/probe.out" 2>/dev/null < /dev/null; then
      apply_probe "$img" "$WORK/probe.out"
    else
      emit SKIP "image:$img has no shell or the probe failed, not inspected"
    fi
  done < "$WORK/images.txt"
  return 0
}

# Fail early if a core utility the checks rely on is missing
function require_tools() {
  local t
  for t in find grep sed awk tr cut head sort mktemp rm uname dirname basename; do
    command -v "$t" >/dev/null 2>&1 || die "required utility not found: $t"
  done
}

# Fail early if -c was requested but Podman is unusable
function preflight_containers() {
  have_cmd podman || die "-c needs podman, which was not found"
  if [[ -n "$IMAGES" ]]; then
    local img
    while IFS= read -r img; do
      [[ -n "$img" ]] || continue
      podman image exists "$img" 2>/dev/null || die "image not found locally (or podman is not running): $img"
    done <<< "$IMAGES"
    printf '%s' "$IMAGES" > "$WORK/images.txt"
    return 0
  fi
  podman images --format '{{.Repository}}:{{.Tag}}' > "$WORK/images.txt" 2>"$WORK/podman.err" ||
    die "podman images failed: $(head -1 "$WORK/podman.err")"
}

# Print the final counts and return the exit code
function summarize() {
  printf 'SUMMARY pass=%d fail=%d warn=%d info=%d skip=%d\n' "$N_PASS" "$N_FAIL" "$N_WARN" "$N_INFO" "$N_SKIP"
  if ((N_FAIL > 0)); then return 1; fi
  if ((STRICT == 1 && N_WARN > 0)); then return 1; fi
  return 0
}

# Parse arguments, run the checks, print the summary
function main() {
  local root
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -r|--root)
        if [[ $# -lt 2 || -z "$2" ]]; then echo "Option $1 needs an argument" >&2; usage >&2; exit 2; fi
        ROOTS="${ROOTS}$2"$'\n'
        shift 2 ;;
      --root=*)
        if [[ -z "${1#--root=}" ]]; then echo "Option --root needs an argument" >&2; usage >&2; exit 2; fi
        ROOTS="${ROOTS}${1#--root=}"$'\n'
        shift ;;
      -c|--containers) DO_CONTAINERS=1; shift ;;
      -i|--image)
        if [[ $# -lt 2 || -z "$2" ]]; then echo "Option $1 needs an argument" >&2; usage >&2; exit 2; fi
        IMAGES="${IMAGES}$2"$'\n'
        DO_CONTAINERS=1
        shift 2 ;;
      -q|--quiet) QUIET=1; shift ;;
      -s|--strict) STRICT=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) echo "Unknown option: $1 (try --help)" >&2; usage >&2; exit 2 ;;
    esac
  done
  require_tools
  if [[ -z "$ROOTS" ]]; then
    ROOTS="$HOME"$'\n'
  fi
  local resolved=""
  while IFS= read -r root; do
    [[ -n "$root" ]] || continue
    [[ -d "$root" ]] || die "scan root is not a directory: $root"
    root=$(cd "$root" && pwd -P)
    case $'\n'"$resolved" in *$'\n'"$root"$'\n'*) continue ;; esac
    resolved="${resolved}${root}"$'\n'
  done <<< "$ROOTS"
  ROOTS="$resolved"

  WORK=$(mktemp -d "${TMPDIR:-/tmp}/emudhra-check.XXXXXX") || die "cannot create a temp directory"
  trap cleanup EXIT
  INDEX="$WORK/index.txt"
  SLICES="$WORK/slices.txt"
  printf '%s\n' "$CERT_SLICES" | awk -F'|' '{print $3}' > "$SLICES"
  if [[ "$DO_CONTAINERS" -eq 1 ]]; then
    preflight_containers
  fi

  cd /
  export GOTOOLCHAIN=local PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
  emit INFO "eMudhra CA compromise check; scan roots: $(printf '%s' "$ROOTS" | tr '\n' ' ')containers=$DO_CONTAINERS"
  build_index

  check_os_trust
  check_os_packages
  check_host_runtimes
  check_node_version_dirs
  scan_python_dist_info
  scan_python_pins
  check_host_python_pkgs
  scan_electron
  scan_go
  scan_lockfiles
  scan_bundles
  check_java
  check_perl
  if [[ "$DO_CONTAINERS" -eq 1 ]]; then
    check_containers
  fi

  summarize
}

main "$@"
