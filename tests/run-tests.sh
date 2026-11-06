#!/bin/bash
# run-tests.sh — test the YARA and Sigma rules and the check script against certificate files and real CA bundles, in containers.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
LAB_IMAGE="emudhra-ca-compromise-check-lab:latest"
# The python:3.9-slim image with its own trust store fixed and pip removed, for the check cases on 3.9.
CHECK39_IMAGE="emudhra-ca-compromise-check-py39:latest"
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
# The committed zipapp in scripts/, with its SHA-256 file beside it.
PYZ_NAME="vuln-check-emudhra-ca-compromise.pyz"
# A certifi release from before the incident, the first release that drops emSign ECC Root CA - G3,
# and the release that restores the unaffected emSign roots. Each wheel is checked against its SHA-256.
CERTIFI_OLD="2026.7.22"
CERTIFI_OLD_SHA256="62f22742b58a1a33014a2b6b706588a8d7e2a88ae7bd1a6ebe8c992928483775"
CERTIFI_FIXED="2026.10.18"
CERTIFI_FIXED_SHA256="73191c47aaa79da394e8fee2dbc2ec827432cab56311122c9e47abf79e390f62"
CERTIFI_RECOMMENDED="2026.10.19"
CERTIFI_RECOMMENDED_SHA256="42d35340cc5b9ba78e818ddbff0c5b1c2b779de448a340fd1b989f5fa8670e1b"
# The archive run without -I -S, with a json.py and an fnmatch.py on PYTHONPATH that leave a marker if imported
PYTHONPATH_CASE='mkdir -p /tmp/evil && for m in json fnmatch; do
  echo "open(\"/tmp/EXECUTED-$m\", \"w\").close()" >/tmp/evil/$m.py; done
PYTHONPATH=/tmp/evil python3 /out/check.pyz --bogus 2>/tmp/err; echo "exit=$?"
for m in json fnmatch; do if test -e /tmp/EXECUTED-$m; then echo "EXECUTED $m"; fi; done
head -1 /tmp/err'
# A python3 wrapper first on PATH that drops -I and -S and keeps argv[0], so sys.executable is the wrapper
WRAPPER_CASE='mkdir -p /tmp/wrap && cat >/tmp/wrap/python3 <<"W"
#!/bin/bash
args=()
for a in "$@"; do case "$a" in -I|-S) ;; *) args+=("$a") ;; esac; done
exec -a "$0" /usr/bin/python3.13 "${args[@]}"
W
chmod +x /tmp/wrap/python3
PATH=/tmp/wrap:$PATH timeout 30 python3 /out/check.pyz --bogus 2>/tmp/err; echo "exit=$?"
echo "notes=$(grep -c "note: run this check as python3 -I -S" /tmp/err)"'
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

# Run a command as an unprivileged user with no capabilities, so file mode bits apply
function run_unprivileged() {
  local image="$1"
  shift
  "$ENGINE" run --rm --network=none --cap-drop=all --user 65534:65534 -v "$REPO":/repo:ro -v "$OUT":/out "$image" "$@"
}

# Build the test image, write the certificate fixtures and fetch the certifi bundles
function make_fixtures() {
  "$ENGINE" build -q -t "$LAB_IMAGE" -f "$REPO/tests/Containerfile" "$REPO/tests" >/dev/null
  local image
  for image in "$JAVA_IMAGE" "$JAVA_OLD_IMAGE" "$PY_IMAGE" "$PY39_IMAGE" "$PY38_IMAGE" "$ALPINE_IMAGE"; do
    "$ENGINE" image inspect "$image" >/dev/null 2>&1 || "$ENGINE" pull -q "$image" >/dev/null
  done
  "$ENGINE" build -q -t "$CHECK39_IMAGE" -f "$REPO/tests/Containerfile.py39" "$REPO/tests" >/dev/null
  run_in "$LAB_IMAGE" python3 -I /repo/tools/build_pyz.py --out /out/check.pyz
  write_cert_fixtures
  write_key_fixtures
  fetch_certifi
  write_bundle_fixtures
  write_trusted_fixtures
  require_clean_system_bundles
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

# Write each certificate's SubjectPublicKeyInfo as openssl prints it, and bare-key files for the matcher tests
function write_key_fixtures() {
  run_in "$LAB_IMAGE" python3 -I -c "
import glob, hashlib, os, ssl, subprocess
os.makedirs('/out/keys', exist_ok=True)
intermediates = {}
for f in sorted(glob.glob('/repo/rules/certs/*.pem')):
    for blk in open(f).read().split('-----END CERTIFICATE-----')[:-1]:
        pem = blk[blk.index('-----BEGIN'):] + '-----END CERTIFICATE-----\n'
        der = ssl.PEM_cert_to_DER_cert(pem)
        pub = subprocess.run(['openssl', 'x509', '-pubkey', '-noout'], input=pem.encode(), capture_output=True, check=True).stdout
        spki = subprocess.run(['openssl', 'pkey', '-pubin', '-outform', 'DER'], input=pub, capture_output=True, check=True).stdout
        open(f'/out/keys/spki-{hashlib.sha256(der).hexdigest()}.der', 'wb').write(spki)
        name = next(line[2:].strip() for line in blk.split('\n') if line.startswith('# '))
        if name.startswith('EM '):
            intermediates[spki] = name
        if name == 'emSign ECC Root CA - G3':
            open('/out/keys/g3-ecc-root.der', 'wb').write(spki)
        if name == 'AAA Certificate Services':
            open('/out/keys/aaa.der', 'wb').write(spki)
assert len(intermediates) == 8, len(intermediates)
open('/out/keys/intermediates.der', 'wb').write(b''.join(sorted(intermediates)))
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

# Write certifi 2026.7.22's bundle in other layouts, and a bundle of the AAA root alone
function write_bundle_fixtures() {
  run_in "$LAB_IMAGE" python3 -I -c "
import base64, os, ssl
os.makedirs('/out/bundles', exist_ok=True)
text = open('/out/certifi/cacert-$CERTIFI_OLD.pem').read()
ders = [ssl.PEM_cert_to_DER_cert(b[b.index('-----BEGIN'):] + '-----END CERTIFICATE-----')
        for b in text.split('-----END CERTIFICATE-----')[:-1]]
def wrap(ders, width, eol):
    out = []
    for der in ders:
        b64 = base64.b64encode(der).decode()
        out += ['-----BEGIN CERTIFICATE-----', *[b64[i:i + width] for i in range(0, len(b64), width)],
                '-----END CERTIFICATE-----']
    return eol.join(out) + eol
def write(name, body):
    open('/out/bundles/' + name, 'w', newline='').write(body)
write('crlf76.pem', wrap(ders, 76, '\r\n'))
write('w32.pem', wrap(ders, 32, '\n'))
write('commentless.pem', wrap(ders, 64, '\n'))
write('comments100k.pem', '# padding comment line before the first certificate\n' * 2000 + text)
aaa = open('/repo/rules/certs/sectigo-aaa-certificate-services.pem').read()
write('aaa.pem', aaa[aaa.index('-----BEGIN'):])
roots = open('/repo/rules/certs/emudhra-g3-roots.pem').read()
for blk in roots.split('-----END CERTIFICATE-----')[:-1]:
    if next(l[2:].strip() for l in blk.split('\n') if l.startswith('# ')) == 'emSign ECC Root CA - G3':
        der = ssl.PEM_cert_to_DER_cert(blk[blk.index('-----BEGIN'):] + '-----END CERTIFICATE-----')
        open('/out/bundles/g3-ecc-root.der', 'wb').write(der)
"
}

# Write emSign ECC Root CA - G3 as OpenSSL TRUSTED CERTIFICATE blocks with rejected uses only, trusted uses only,
# both, and only emailProtection rejected
function write_trusted_fixtures() {
  run_in "$LAB_IMAGE" sh -c 'set -e
    mkdir -p /out/trusted
    t() { name=$1; shift; openssl x509 -inform DER -in /out/bundles/g3-ecc-root.der "$@" -trustout -out "/out/trusted/$name"; }
    t rejected.pem -addreject anyExtendedKeyUsage
    t rejected-alias.pem -addreject anyExtendedKeyUsage -setalias emSign
    t trusted.pem -addtrust serverAuth
    t both.pem -addtrust serverAuth -addreject anyExtendedKeyUsage
    t email.pem -addreject emailProtection'
}

# Stop when YARA finds a compromised certificate in a check image's own system bundle, since every case reads it
function require_clean_system_bundles() {
  local image
  for image in "$LAB_IMAGE" "$CHECK39_IMAGE"; do
    "$ENGINE" run --rm --network=none "$image" cat /etc/ssl/certs/ca-certificates.crt >"$OUT/system-bundle.crt"
    run_in "$LAB_IMAGE" sh -c "yara /repo/rules/yara/emudhra-ca.yar /out/system-bundle.crt | grep -q ." \
      && die "YARA finds a compromised certificate in the system bundle of $image"
  done
  rm -f "$OUT/system-bundle.crt"
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
  # One keystore of each kind holding cert00, each named cacerts in its own directory, written by keytool
  # in the pre-fix JDK image, with the count of entries keytool lists in each.
  run_in "$JAVA_OLD_IMAGE" sh -c 'set -e
    k() { d=/out/java/$1; shift; mkdir -p "$d"
      keytool -importcert "$@" -noprompt -alias cert00 -file /out/yara/cert00-w64.pem -keystore "$d/cacerts" \
        -storepass changeit >/dev/null 2>&1
      keytool -list -keystore "$d/cacerts" -storepass changeit 2>/dev/null | grep -c trustedCertEntry >"$d.entries"; }
    k jks -storetype JKS; k jceks -storetype JCEKS; k p12; k p12-plain -J-Dkeystore.pkcs12.certProtectionAlgorithm=NONE'
  for tag in old fixed; do
    mkdir -p "$OUT/java/jdk-$tag"
    cp "$OUT/jdk-$tag-cacerts" "$OUT/java/jdk-$tag/cacerts"
  done
}

# Run YARA over the fixtures, a JKS keystore, the JDK cacerts and the test image's system files
function test_yara() {
  local rules=/repo/rules/yara/emudhra-ca.yar got want
  got=$(run_in "$LAB_IMAGE" sh -c "yara -r $rules /out/yara | awk '{print \$1}' | sort | uniq -c | awk '{print \$2\"=\"\$1}' | tr '\n' ' '")
  check "yara fixtures (16 intermediates, 5 G3 root certificates, DER + 2 PEM wrappings each, 1 JKS)" \
    "eMudhra_G3_compromised_intermediate=49 eMudhra_G3_root=15" "${got% }"

  local tag
  for tag in old fixed; do
    want=$([[ "$(tr -d '[:space:]' <"$OUT/jdk-$tag-g3-aliases.txt")" -gt 0 ]] && echo "hit" || echo "no hit")
    got=$(run_in "$LAB_IMAGE" sh -c "yara $rules /out/jdk-$tag-cacerts | grep -q eMudhra_G3_root && echo hit || echo 'no hit'")
    check "yara $tag JDK cacerts agrees with keytool (G3 alias: $want)" "$want" "$got"
  done
  check "pre-fix JDK still carries the G3 root" "hit" \
    "$([[ "$(tr -d '[:space:]' <"$OUT/jdk-old-g3-aliases.txt")" -gt 0 ]] && echo hit || echo 'no hit')"
  got=$(cd "$OUT/java" && for k in jks jceks p12 p12-plain; do printf '%s=%s ' "$k" "$(tr -d '[:space:]' <"$k.entries")"; done)
  check "keytool lists cert00 in each fixture keystore" "jks=1 jceks=1 p12=1 p12-plain=1" "${got% }"

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

# Check the Sigma rule's structure and that it lists all 21 thumbprints from the certificate files
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
print('ok' if listed == want and len(want) == 21 else f'mismatch {len(listed)} {len(want)}')
" 2>&1 | tail -1)
  check "sigma rule structure and thumbprints (not converted to a SIEM query)" "ok" "$got"
}

# Compare the generated certificate data with openssl and the test image, and scan its system files
function test_certdata() {
  local got
  got=$(run_in "$LAB_IMAGE" python3 -I -c "
import sys
sys.path.insert(0, '/repo')
from emudhra_check.certdata import RECORDS
bad = []
for r in RECORDS:
    spki = open(f'/out/keys/spki-{r.sha256.hex()}.der', 'rb').read()
    n = spki[1] & 0x7f if spki[1] & 0x80 else 0
    if spki[2 + n:] != r.spki_value:
        bad.append(r.label)
print('ok' if not bad and len(RECORDS) == 22 else 'mismatch: ' + ', '.join(bad))
")
  check "certdata public keys match openssl" "ok" "$got"
  got=$(run_in "$LAB_IMAGE" python3 -I -c "
import sys
sys.path.insert(0, '/repo')
from emudhra_check.certificates import ISRG_ROOT_X1_LINE
text = open('/usr/share/ca-certificates/mozilla/ISRG_Root_X1.crt').read()
body = ''.join(text.split('-----BEGIN CERTIFICATE-----')[1].split('-----END')[0].split())
print('ok' if body.startswith(ISRG_ROOT_X1_LINE.decode()) else 'mismatch')
")
  check "ISRG Root X1 line starts the test image's ISRG Root X1" "ok" "$got"
  got=$(run_in "$LAB_IMAGE" python3 -I -c "
import os, stat, sys
sys.path.insert(0, '/repo')
from emudhra_check.certificates import Matcher
matcher, hits = Matcher(), []
for top in ('/usr/bin', '/usr/sbin', '/usr/lib'):
    for root, dirs, files in os.walk(top):
        for name in files:
            path = os.path.join(root, name)
            if stat.S_ISREG(os.lstat(path).st_mode) and matcher.scan(open(path, 'rb').read()):
                hits.append(path)
print(len(hits), *hits)
")
  check "matcher false positives in system binaries and libraries" "0" "$got"
}

# Run the unit suite, the lint tools, the version gate and the archive's isolation cases
function test_python() {
  # The summary line names the skips: the two mode-bit tests skip as root, and the two standard-library
  # contract tests skip on 3.9.
  local got discover="cd /repo && python3 -I -m unittest discover -q -s /repo/tests/unit -t /repo"
  local summary=">/tmp/log 2>&1; if grep -q '^OK' /tmp/log; then tail -1 /tmp/log; else cat /tmp/log; fi"
  got=$(run_in "$LAB_IMAGE" sh -c "flake8 --version >/dev/null && black --version >/dev/null && mypy --version >/dev/null && echo ok")
  check "flake8, black and mypy run in the test image" "ok" "$got"
  got=$(run_in "$LAB_IMAGE" sh -c "cd /tmp && : >empty.py && out=\$(mypy --cache-dir=/dev/null --python-version 3.9 empty.py 2>&1) \
    && ! printf '%s' \"\$out\" | grep -qi 'warning\|error' && echo ok")
  check "mypy accepts a Python 3.9 target" "ok" "$got"
  got=$(run_in "$LAB_IMAGE" sh -c "$discover $summary")
  check "unit tests on Python 3.13" "OK (skipped=2)" "$got"
  got=$(run_in "$PY39_IMAGE" sh -c "$discover $summary")
  check "unit tests on Python 3.9" "OK (skipped=4)" "$got"
  got=$(run_unprivileged "$LAB_IMAGE" sh -c "$discover -p test_adapter_filesystem.py $summary")
  check "file-system adapter tests as an unprivileged user" "OK" "$got"
  got=$(run_in "$PY38_IMAGE" sh -c "python3 -I -S /out/check.pyz 2>&1; echo \"exit=\$?\"" | tr '\n' ' ')
  check "archive refuses Python 3.8" "check.pyz: needs Python 3.9 or later, found 3.8 exit=2 " "$got"
  got=$(run_in "$LAB_IMAGE" sh -c "cd /repo && black --check --quiet --extend-exclude 'emudhra_check/certdata\.py' . 2>&1 && echo ok")
  check "black --check" "ok" "$got"
  got=$(run_in "$LAB_IMAGE" sh -c "cd /repo && flake8 . 2>&1 && echo ok")
  check "flake8" "ok" "$got"
  got=$(run_in "$LAB_IMAGE" sh -c "cd /repo && mypy --cache-dir=/dev/null 2>&1 | grep -v '^Success' ; echo ok")
  check "mypy" "ok" "$got"
  got=$(run_in "$LAB_IMAGE" python3 -I -c "
import zipfile
z = zipfile.ZipFile('/out/check.pyz')
bad = [n for n in z.namelist() if any(s in z.read(n) for s in (b'/Users/', b'/home/'))]
print('clean' if bad == [] else ' '.join(bad))
")
  check "archive holds no home paths" "clean" "$got"
  got=$(run_in "$LAB_IMAGE" sh -c "cd /repo/scripts && sha256sum -c --quiet $PYZ_NAME.sha256 2>&1 && echo ok")
  check "committed archive matches its SHA-256 file" "ok" "$got"
  got=$(run_in "$LAB_IMAGE" sh -c "cmp /repo/scripts/$PYZ_NAME /out/check.pyz 2>&1 && echo same")
  check "committed archive equals a fresh build on Python 3.13" "same" "$got"
  got=$(run_in "$PY39_IMAGE" sh -c "python3 -I /repo/tools/build_pyz.py --out /tmp/check.pyz \
    && cmp /repo/scripts/$PYZ_NAME /tmp/check.pyz 2>&1 && echo same")
  check "committed archive equals a fresh build on Python 3.9" "same" "$got"
  got=$(run_in "$LAB_IMAGE" sh -c "$PYTHONPATH_CASE" | tr '\n' ' ')
  check "archive ignores planted modules on PYTHONPATH" "exit=2 Unknown option: --bogus (try --help) " "$got"
  got=$(run_in "$LAB_IMAGE" bash -c "$WRAPPER_CASE" | tr '\n' ' ')
  check "archive re-executes once through a wrapper that drops -I -S" "exit=2 notes=1 " "$got"
}

# Run one tests/expect case. "# args:", "# setup:", "# cwd:", "# timeout:", "# user: nobody", "# caps: default",
# "# exit:" and "# summaries:" set the run. Cases run without capabilities unless "# caps: default" is given.
# A "!" line is a forbidden substring, a "!^" line a forbidden line start, a "~" line a required substring, and
# every other line must appear as an exact output line. A /tmp/EXECUTED-* file left by a marker tool prints a
# "MARKER" line. Setup may set PY to the interpreter's absolute path before changing PATH.
function check_case() {
  local label="$1" image="$2" file="$3" name args setup cwd secs want_exit summaries out got_exit count line problems=""
  local -a engine_args=(--rm --network=none)
  name="$(basename "$file" .txt)"
  args=$(sed -n 's/^# args: //p' "$file")
  setup=$(sed -n 's/^# setup: //p' "$file")
  cwd=$(sed -n 's/^# cwd: //p' "$file")
  secs=$(sed -n 's/^# timeout: //p' "$file")
  want_exit=$(sed -n 's/^# exit: //p' "$file")
  summaries=$(sed -n 's/^# summaries: //p' "$file")
  if [[ "$(sed -n "s/^# caps: //p" "$file")" != "default" ]]; then
    engine_args+=(--cap-drop=all)
  fi
  if [[ "$(sed -n "s/^# user: //p" "$file")" == "nobody" ]]; then
    engine_args+=(--user 65534:65534)
  fi
  out=$("$ENGINE" run "${engine_args[@]}" -v "$REPO":/repo:ro -v "$OUT":/out "$image" sh -c \
    "PY=python3; ${setup:-:}; cd ${cwd:-/tmp}; timeout ${secs:-120} \"\$PY\" -I -S /out/check.pyz $args 2>&1; rc=\$?
    for m in /tmp/EXECUTED-*; do if test -e \"\$m\"; then echo \"MARKER \$m\"; fi; done; echo \"exit=\$rc\"")
  got_exit="${out##*exit=}"
  out="${out%exit=*}"
  [[ "$got_exit" == "${want_exit:-0}" ]] || problems+=" exit=$got_exit"
  count=$(grep -c '^SUMMARY ' <<<"$out" || true)
  [[ "$count" == "${summaries:-1}" ]] || problems+=" summaries=$count"
  while IFS= read -r line; do
    case "$line" in
      '# '*|'') ;;
      '!^'*) if awk -v p="${line#!^}" 'index($0, p) == 1 { f = 1 } END { exit !f }' <<<"$out"; then
          problems+=" forbidden line: ${line#!^}"; fi ;;
      '!'*) if grep -Fq -- "${line#!}" <<<"$out"; then problems+=" forbidden: ${line#!}"; fi ;;
      '~'*) grep -Fq -- "${line#\~}" <<<"$out" || problems+=" missing substring: ${line#\~}" ;;
      *) grep -Fxq -- "$line" <<<"$out" || problems+=" missing: $line" ;;
    esac
  done <"$file"
  check "check $name on $label" "ok" "${problems:-ok}"
}

# Run every tests/expect case through the archive on Python 3.13 and 3.9, then the committed archive through
# its shebang
function test_check() {
  local file got
  for file in "$REPO"/tests/expect/*.txt; do
    check_case "3.13" "$LAB_IMAGE" "$file"
    check_case "3.9" "$CHECK39_IMAGE" "$file"
  done
  got=$(run_in "$LAB_IMAGE" sh -c "cd /repo/scripts && ./$PYZ_NAME -h >/tmp/o 2>&1; echo \"exit=\$?\"; \
    head -1 /tmp/o | cut -d ' ' -f 1-2; grep -c 'note: run this check' /tmp/o || true" | tr '\n' ' ')
  check "committed archive runs through its shebang and re-executes under -I -S" "exit=0 Usage: $PYZ_NAME 0 " "$got"
}

# Run the rendered probe with dash in the test image and with BusyBox in Alpine, each holding the pre-fix JDK's
# cacerts, then judge its output on the host side: the system bundle verdict must agree with YARA and the keystore FAIL
function test_probe_live() {
  local label image want got judged where
  run_in "$LAB_IMAGE" python3 -I -c "
import sys
sys.path.insert(0, '/repo')
from emudhra_check.probe import render
open('/out/probe.sh', 'w').write(render(open('/repo/emudhra_check/probe.sh').read()))
"
  for label in dash busybox; do
    image="$LAB_IMAGE"
    [[ "$label" == busybox ]] && image="$ALPINE_IMAGE"
    run_in "$image" sh -c "cat /etc/ssl/certs/ca-certificates.crt" >"$OUT/probe-bundle-$label.crt"
    want=$(run_in "$LAB_IMAGE" sh -c "yara /repo/rules/yara/emudhra-ca.yar /out/probe-bundle-$label.crt | grep -q . && echo FAIL || echo PASS")
    run_in "$image" sh -c "mkdir -p /opt/jdk/lib/security && cp /out/jdk-old-cacerts /opt/jdk/lib/security/cacerts \
      && sh /out/probe.sh" >"$OUT/probe-$label.txt"
    judged=$(run_in "$LAB_IMAGE" python3 -I -c "
import sys
sys.path.insert(0, '/repo')
from emudhra_check.detections.containers import image_findings
from emudhra_check.probe import parse_probe_output
for finding in image_findings('$label', parse_probe_output(open('/out/probe-$label.txt', 'rb').read())):
    print(finding.line())
")
    where="image:$label /etc/ssl/certs/ca-certificates.crt"
    got=$(grep -F "ca-bundle [$where]" <<<"$judged" | grep -q '^FAIL' && echo FAIL || echo PASS)
    check "probe under $label agrees with YARA on the image bundle" "$want" "$got"
    got=$(grep -cF "FAIL  java keystore [image:$label /opt/jdk/lib/security/cacerts] contains emSign ECC Root CA - G3" \
      <<<"$judged" || true)
    check "probe under $label reads the JDK keystore" "1" "$got"
    got=$(grep -c "dropped\|did not finish\|no od" <<<"$judged" || true)
    check "probe under $label drops no records" "0" "$got"
  done
  # A pip-installed certifi whose cacert.pem links to an affected bundle under a name the probe does not search for
  run_in "$LAB_IMAGE" sh -c "P=\$(python3 -I -c 'import sysconfig; print(sysconfig.get_paths()[\"purelib\"])') \
    && mkdir -p \$P/certifi \$P/certifi-$CERTIFI_OLD.dist-info /opt/corp \
    && printf 'Metadata-Version: 2.1\nName: certifi\nVersion: $CERTIFI_OLD\n' >\$P/certifi-$CERTIFI_OLD.dist-info/METADATA \
    && echo pip >\$P/certifi-$CERTIFI_OLD.dist-info/INSTALLER \
    && cp /out/certifi/cacert-$CERTIFI_OLD.pem /opt/corp/ca.pem && ln -s /opt/corp/ca.pem \$P/certifi/cacert.pem \
    && sh /out/probe.sh" >"$OUT/probe-linked.txt"
  judged=$(run_in "$LAB_IMAGE" python3 -I -c "
import sys
sys.path.insert(0, '/repo')
from emudhra_check.detections.containers import image_findings
from emudhra_check.probe import parse_probe_output
for finding in image_findings('linked', parse_probe_output(open('/out/probe-linked.txt', 'rb').read())):
    print(finding.line())
")
  got=$(grep -cFx -e "INFO  certifi [image:linked] found $CERTIFI_OLD, its cacert.pem links outside the package, judged by the bundle it resolves to" \
    -e "FAIL  ca-bundle [image:linked /opt/corp/ca.pem] contains emSign ECC Root CA - G3 (removed root)" <<<"$judged" || true)
  check "probe dumps the affected bundle a certifi cacert.pem links to" "2" "$got"
  # A certifi laid out as Debian bookworm ships it: the upstream cacert.pem beside a core.py whose where() is patched
  run_in "$LAB_IMAGE" sh -c "P=\$(python3 -I -c 'import sysconfig; print(sysconfig.get_paths()[\"purelib\"])') \
    && mkdir -p \$P/certifi \$P/certifi-2022.9.24.dist-info \
    && printf 'Metadata-Version: 2.1\nName: certifi\nVersion: 2022.9.24\n' >\$P/certifi-2022.9.24.dist-info/METADATA \
    && printf '%s\n' \"DEBIAN_CA_CERTS_PATH = '/etc/ssl/certs/ca-certificates.crt'\" 'def where() -> str:' \
      '    return DEBIAN_CA_CERTS_PATH' >\$P/certifi/core.py \
    && cp /out/certifi/cacert-$CERTIFI_OLD.pem \$P/certifi/cacert.pem && sh /out/probe.sh" >"$OUT/probe-patched.txt"
  judged=$(run_in "$LAB_IMAGE" python3 -I -c "
import sys
sys.path.insert(0, '/repo')
from emudhra_check.detections.containers import image_findings
from emudhra_check.probe import parse_probe_output
for finding in image_findings('patched', parse_probe_output(open('/out/probe-patched.txt', 'rb').read())):
    print(finding.line())
")
  got=$(grep -cFx "INFO  certifi [image:patched] found 2022.9.24, where() patched to return the system store (Debian), its cacert.pem is not used" \
    <<<"$judged" || true)
  check "probe reads Debian's patched where() in certifi's core.py" "1" "$got"
}

# Lint the test scripts, the probe, the fake podman and run-checks.sh
function test_scripts() {
  local got
  got=$(run_in "$LAB_IMAGE" sh -c "shellcheck -S warning /repo/tests/*.sh >/dev/null 2>&1 && echo clean || echo findings")
  check "shellcheck -S warning" "clean" "$got"
  got=$(run_in "$LAB_IMAGE" sh -c "shellcheck -s sh /repo/emudhra_check/probe.sh && shellcheck /repo/tests/fixtures/fake-podman && echo clean")
  check "shellcheck on the probe and the fake podman" "clean" "$got"
  got=$(run_in "$LAB_IMAGE" sh -c "shellcheck /repo/run-checks.sh && echo clean")
  check "shellcheck on run-checks.sh" "clean" "$got"
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
  # The check cases run without capabilities or as an unprivileged user, so the fixtures must be world-readable
  chmod -R a+rX "$OUT"
  test_yara
  test_sigma
  test_certdata
  test_python
  test_check
  test_probe_live
  test_scripts
  printf '\n%d passed, %d failed\n' "$N_PASS" "$N_FAIL"
  if [[ "$keep" -eq 1 ]]; then
    echo "fixtures: $OUT"
  fi
  [[ "$N_FAIL" -eq 0 ]]
}

main "$@"
