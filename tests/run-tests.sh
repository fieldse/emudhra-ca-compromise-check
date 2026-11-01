#!/bin/bash
# run-tests.sh — test the YARA and Sigma rules and the check script against certificate files and real CA bundles, in containers.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
LAB_IMAGE="emudhra-ca-compromise-check-lab:latest"
# Images are pinned by their multi-arch index digest. The tag each digest came from is in its comment.
# eclipse-temurin:21.0.13_9-jre, a JDK released after the fix.
JAVA_IMAGE="docker.io/library/eclipse-temurin@sha256:0b99b3376fbb50dbf9c0af8535fdd5b8eb0d3fdfc8b1e4967f383b6919f6901a"
# eclipse-temurin:21.0.8_9-jre, a JDK released before the fix, whose cacerts still holds emSign ECC Root CA - G3.
JAVA_OLD_IMAGE="docker.io/library/eclipse-temurin@sha256:66bb900643426ad01996d25bada7d56751913f9cec3b827fcb715d2ec9a0fbfc"
# python:3.13.17-slim-trixie, used to download certifi.
PY_IMAGE="docker.io/library/python@sha256:d98cc29d3266e535dd9da1099688d9cb3ca4753813571e071763d17725460962"
# python:3.9-slim, the oldest supported interpreter.
PY39_IMAGE="docker.io/library/python@sha256:2d97f6910b16bd338d3060f261f53f144965f755599aab1acda1e13cf1731b1b"
# python:3.8-slim, an interpreter below the supported minimum.
PY38_IMAGE="docker.io/library/python@sha256:1d52838af602b4b5a831beb13a0e4d073280665ea7be7f69ce2382f29c5a613f"
# alpine:3.22, a BusyBox userland.
ALPINE_IMAGE="docker.io/library/alpine@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f"
# A certifi release from before the incident, the first release that drops emSign ECC Root CA - G3,
# and the release that restores the unaffected emSign roots. Each wheel is checked against its SHA-256.
CERTIFI_OLD="2026.7.22"
CERTIFI_OLD_SHA256="62f22742b58a1a33014a2b6b706588a8d7e2a88ae7bd1a6ebe8c992928483775"
CERTIFI_FIXED="2026.10.18"
CERTIFI_FIXED_SHA256="73191c47aaa79da394e8fee2dbc2ec827432cab56311122c9e47abf79e390f62"
CERTIFI_RECOMMENDED="2026.10.19"
CERTIFI_RECOMMENDED_SHA256="42d35340cc5b9ba78e818ddbff0c5b1c2b779de448a340fd1b989f5fa8670e1b"
ENGINE=""
OUT=""
N_PASS=0
N_FAIL=0

# Show usage information
function usage() {
  cat <<EOF
Usage: $(basename "$0") [-e|--engine docker|podman] [-k|--keep] [-h|--help]

Builds a test image, writes each eMudhra certificate as DER and PEM, fetches real CA bundles from
before and after the fix, and checks that the rules and the check script flag exactly the affected
files. Network is used only to build and pull images and fetch certifi. The tests run with --network=none.

Options:
  -e, --engine ENGINE  Container engine (default: docker if it responds, else podman)
  -k, --keep           Keep the fixture directory and print its path
  -h, --help           Show this help

Example: $(basename "$0") -e podman
EOF
}

# Print an error and exit
function die() {
  echo "$(basename "$0"): $*" >&2
  exit 2
}

# Pick a working container engine
function pick_engine() {
  if [[ -n "$ENGINE" ]]; then
    "$ENGINE" info >/dev/null 2>&1 || die "$ENGINE does not respond"
    return 0
  fi
  local e
  for e in docker podman; do
    if command -v "$e" >/dev/null 2>&1 && "$e" info >/dev/null 2>&1; then
      ENGINE="$e"
      return 0
    fi
  done
  die "no working docker or podman"
}

# Record one result line
function check() {
  local name="$1" want="$2" got="$3"
  if [[ "$want" == "$got" ]]; then
    N_PASS=$((N_PASS + 1))
    printf 'PASS  %s\n' "$name"
  else
    N_FAIL=$((N_FAIL + 1))
    printf 'FAIL  %s\n      want: %s\n      got:  %s\n' "$name" "${want:-<none>}" "${got:-<none>}"
  fi
}

# Run a command in a container with the repo read-only and the fixture directory writable
function run_in() {
  local image="$1"
  shift
  "$ENGINE" run --rm --network=none -v "$REPO":/repo:ro -v "$OUT":/out "$image" "$@"
}

# Build the test image, write the certificate fixtures and fetch the certifi bundles
function make_fixtures() {
  "$ENGINE" build -q -t "$LAB_IMAGE" -f "$REPO/tests/Containerfile" "$REPO/tests" >/dev/null
  local image
  for image in "$JAVA_IMAGE" "$JAVA_OLD_IMAGE" "$PY_IMAGE" "$PY39_IMAGE" "$PY38_IMAGE" "$ALPINE_IMAGE"; do
    "$ENGINE" pull -q "$image" >/dev/null
  done
  write_cert_fixtures
  fetch_certifi
}

# Write each certificate as DER, as PEM wrapped at 64 columns, and as PEM wrapped at 76 with CRLF
function write_cert_fixtures() {
  run_in "$LAB_IMAGE" python3 -I -c "
import base64, glob, os, ssl
os.makedirs('/out/yara', exist_ok=True)
pems = []
for f in sorted(glob.glob('/repo/rules/certs/*.pem')):
    for blk in open(f).read().split('-----END CERTIFICATE-----')[:-1]:
        pems.append(blk[blk.index('-----BEGIN'):] + '-----END CERTIFICATE-----')
for i, pem in enumerate(pems):
    der = ssl.PEM_cert_to_DER_cert(pem)
    open(f'/out/yara/cert{i:02d}.der', 'wb').write(der)
    b64 = base64.b64encode(der).decode()
    for width, eol in ((64, '\\n'), (76, '\\r\\n')):
        lines = [b64[j:j + width] for j in range(0, len(b64), width)]
        body = eol.join(['-----BEGIN CERTIFICATE-----', *lines, '-----END CERTIFICATE-----']) + eol
        open(f'/out/yara/cert{i:02d}-w{width}.pem', 'w', newline='').write(body)
"
}

# Download the pre-fix, fixed and recommended certifi wheels, check their SHA-256 and extract each CA bundle (needs network)
function fetch_certifi() {
  mkdir -p "$OUT/certifi"
  "$ENGINE" run --rm -v "$OUT/certifi":/dl "$PY_IMAGE" sh -c \
    "for v in $CERTIFI_OLD $CERTIFI_FIXED $CERTIFI_RECOMMENDED; do pip download -q --no-deps -d /dl certifi==\$v || exit 1; done"
  printf '%s  %s\n' \
    "$CERTIFI_OLD_SHA256" "certifi-$CERTIFI_OLD-py3-none-any.whl" \
    "$CERTIFI_FIXED_SHA256" "certifi-$CERTIFI_FIXED-py3-none-any.whl" \
    "$CERTIFI_RECOMMENDED_SHA256" "certifi-$CERTIFI_RECOMMENDED-py3-none-any.whl" >"$OUT/certifi/SHA256SUMS"
  "$ENGINE" run --rm --network=none -v "$OUT/certifi":/dl -w /dl "$PY_IMAGE" sha256sum --quiet -c SHA256SUMS \
    || die "a certifi wheel does not match its recorded SHA-256"
  "$ENGINE" run --rm --network=none -v "$OUT/certifi":/dl "$PY_IMAGE" python3 -I -c "
import glob, zipfile
for w in glob.glob('/dl/certifi-*.whl'):
    v = w.split('-')[1]
    open(f'/dl/cacert-{v}.pem', 'wb').write(zipfile.ZipFile(w).read('certifi/cacert.pem'))
"
}




# Write a JKS keystore holding one intermediate, and copy each JDK's cacerts with its G3 alias count
function make_java_fixtures() {
  run_in "$JAVA_IMAGE" sh -c 'keytool -importcert -noprompt -alias t -file /out/yara/cert00-w64.pem \
    -keystore /out/yara/test.jks -storetype JKS -storepass changeit >/dev/null 2>&1'
  local tag image
  for tag in old fixed; do
    image="$JAVA_IMAGE"
    [[ "$tag" == "old" ]] && image="$JAVA_OLD_IMAGE"
    run_in "$image" sh -c "cp \"\$JAVA_HOME/lib/security/cacerts\" /out/jdk-$tag-cacerts; \
      keytool -list -cacerts -storepass changeit 2>/dev/null | grep -ciE 'emsign_?ecc_?root_?ca_*g3|emsigneccrootcag3' || true" \
      >"$OUT/jdk-$tag-g3-aliases.txt"
  done
}

# Run YARA over the fixtures, a JKS keystore, the JDK cacerts and the test image's system files
function test_yara() {
  local rules=/repo/rules/yara/emudhra-ca.yar got want
  got=$(run_in "$LAB_IMAGE" sh -c "yara -r $rules /out/yara | awk '{print \$1}' | sort | uniq -c | awk '{print \$2\"=\"\$1}' | tr '\n' ' '")
  check "yara fixtures (16 intermediates, 3 roots, DER + 2 PEM wrappings each, 1 JKS)" \
    "eMudhra_G3_compromised_intermediate=49 eMudhra_G3_root=9" "${got% }"

  local tag
  for tag in old fixed; do
    want=$([[ "$(tr -d '[:space:]' <"$OUT/jdk-$tag-g3-aliases.txt")" -gt 0 ]] && echo "hit" || echo "no hit")
    got=$(run_in "$LAB_IMAGE" sh -c "yara $rules /out/jdk-$tag-cacerts | grep -q eMudhra_G3_root && echo hit || echo 'no hit'")
    check "yara $tag JDK cacerts agrees with keytool (G3 alias: $want)" "$want" "$got"
  done
  check "pre-fix JDK still carries the G3 root" "hit" \
    "$([[ "$(tr -d '[:space:]' <"$OUT/jdk-old-g3-aliases.txt")" -gt 0 ]] && echo hit || echo 'no hit')"

  for tag in "$CERTIFI_OLD|hit" "$CERTIFI_FIXED|no hit"; do
    got=$(run_in "$LAB_IMAGE" sh -c "yara $rules /out/certifi/cacert-${tag%%|*}.pem | grep -q eMudhra_G3_root && echo hit || echo 'no hit'")
    check "yara certifi ${tag%%|*}" "${tag#*|}" "$got"
  done

  got=$(run_in "$LAB_IMAGE" sh -c "yara -r $rules /usr/bin /usr/sbin /usr/lib 2>/dev/null | wc -l | tr -d ' '")
  check "yara false positives in system binaries and libraries" "0" "$got"

  want=$(run_in "$LAB_IMAGE" sh -c "ls /usr/share/ca-certificates/mozilla | grep -q '^emSign_ECC_Root_CA_-_G3' && echo hit || echo 'no hit'")
  got=$(run_in "$LAB_IMAGE" sh -c "yara $rules /etc/ssl/certs/ca-certificates.crt | grep -q eMudhra_G3_root && echo hit || echo 'no hit'")
  check "yara system bundle agrees with the trust store's file list" "$want" "$got"
}

# Check the Sigma rule's structure and that it lists all 19 thumbprints from the certificate files
function test_sigma() {
  local got
  got=$(run_in "$LAB_IMAGE" python3 -I -c "
import csv, glob, hashlib, ssl, yaml
r = yaml.safe_load(open(glob.glob('/repo/rules/sigma/*.yml')[0]))
assert {'title', 'id', 'logsource', 'detection', 'level'} <= set(r), 'missing keys'
listed = {t.rsplit(chr(92), 1)[1] for t in r['detection']['selection_thumbprint']['TargetObject|contains']}
blocks = set()
for f in glob.glob('/repo/rules/certs/*.pem'):
    for blk in open(f).read().split('-----END CERTIFICATE-----')[:-1]:
        pem = blk[blk.index('-----BEGIN'):] + '-----END CERTIFICATE-----'
        blocks.add(hashlib.sha1(ssl.PEM_cert_to_DER_cert(pem)).hexdigest().upper())
rows = list(csv.DictReader(open('/repo/rules/iocs.csv')))
want = {row['sha1'] for row in rows if row['role'] != 'cross-sign issuer root'}
assert want <= blocks, 'an iocs.csv row has no certificate block'
print('ok' if listed == want and len(want) == 19 else f'mismatch {len(listed)} {len(want)}')
" 2>&1 | tail -1)
  check "sigma rule structure and thumbprints (not converted to a SIEM query)" "ok" "$got"
}

# Check the Python lint tools in the test image
function test_python() {
  local got
  got=$(run_in "$LAB_IMAGE" sh -c "flake8 --version >/dev/null && black --version >/dev/null && mypy --version >/dev/null && echo ok")
  check "flake8, black and mypy run in the test image" "ok" "$got"
  got=$(run_in "$LAB_IMAGE" sh -c "cd /tmp && : >empty.py && out=\$(mypy --cache-dir=/dev/null --python-version 3.9 empty.py 2>&1) \
    && ! printf '%s' \"\$out\" | grep -qi 'warning\|error' && echo ok")
  check "mypy accepts a Python 3.9 target" "ok" "$got"
}

# Lint the shell scripts and check the exposure script against the test image's bundle
function test_scripts() {
  local got want
  got=$(run_in "$LAB_IMAGE" sh -c "shellcheck -S warning /repo/scripts/*.sh /repo/tests/*.sh >/dev/null 2>&1 && echo clean || echo findings")
  check "shellcheck -S warning" "clean" "$got"
  want=$(run_in "$LAB_IMAGE" sh -c "yara /repo/rules/yara/emudhra-ca.yar /etc/ssl/certs/ca-certificates.crt | grep -q . && echo FAIL || echo PASS")
  got=$(run_in "$LAB_IMAGE" sh -c "bash /repo/scripts/vuln-check-emudhra-ca-compromise.sh -r /etc/ssl 2>/dev/null \
    | grep -F '/etc/ssl/certs/ca-certificates.crt' | grep -q '^FAIL' && echo FAIL || echo PASS")
  check "check script agrees with YARA on the system bundle" "$want" "$got"
  local v exp
  for v in "$CERTIFI_OLD|FAIL" "$CERTIFI_FIXED|PASS"; do
    exp="${v#*|}"
    got=$(run_in "$LAB_IMAGE" sh -c "mkdir -p /tmp/c && cp /out/certifi/cacert-${v%%|*}.pem /tmp/c/cacert.pem && \
      bash /repo/scripts/vuln-check-emudhra-ca-compromise.sh -r /tmp/c 2>/dev/null \
      | grep -F '/tmp/c/cacert.pem' | grep -q '^FAIL' && echo FAIL || echo PASS")
    check "check script on certifi ${v%%|*} bundle" "$exp" "$got"
    got=$(run_in "$LAB_IMAGE" sh -c "mkdir -p /tmp/d/certifi-${v%%|*}.dist-info && \
      echo pip >/tmp/d/certifi-${v%%|*}.dist-info/INSTALLER && \
      bash /repo/scripts/vuln-check-emudhra-ca-compromise.sh -r /tmp/d 2>/dev/null \
      | grep -F 'certifi-${v%%|*}.dist-info' | grep -q '^FAIL' && echo FAIL || echo PASS")
    check "check script on certifi ${v%%|*} version" "$exp" "$got"
  done
}

# Parse arguments, build fixtures and run every test
function main() {
  local keep=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -e|--engine) [[ $# -ge 2 ]] || die "$1 needs a value"; ENGINE="$2"; shift 2 ;;
      -k|--keep)   keep=1; shift ;;
      -h|--help)   usage; exit 0 ;;
      *)           usage >&2; exit 2 ;;
    esac
  done
  pick_engine
  OUT=$(mktemp -d "${TMPDIR:-/tmp}/emudhra-tests.XXXXXX")
  if [[ "$keep" -eq 0 ]]; then
    trap 'rm -rf "$OUT"' EXIT
  fi
  make_fixtures
  make_java_fixtures
  test_yara
  test_sigma
  test_python
  test_scripts
  printf '\n%d passed, %d failed\n' "$N_PASS" "$N_FAIL"
  if [[ "$keep" -eq 1 ]]; then
    echo "fixtures: $OUT"
  fi
  [[ "$N_FAIL" -eq 0 ]]
}

main "$@"
