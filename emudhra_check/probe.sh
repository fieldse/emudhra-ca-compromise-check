# probe.sh: the in-image probe of the eMudhra CA compromise check, POSIX sh, run with no network.
# It prints one record per line for the host to judge: runtimes, Python packages, the OS id, the
# ca-certificates package, and every CA bundle and Java keystore as od hex lines between FILE and END.
# The host fills in the placeholders between @ signs before the run.
G='@G3_LINE@'
I='@ISRG_LINE@'
BIG=@MAX_PROBE_FILE@

if command -v node >/dev/null 2>&1; then
  b=$(node -p 'process.execPath' 2>/dev/null)
  [ -f "$b" ] || b=$(command -v node)
  g=0
  s=0
  grep -qF -- "$G" "$b" 2>/dev/null && g=1
  grep -qF -- "$I" "$b" 2>/dev/null && s=1
  echo "NODE $g $s $(node --version 2>&1 | head -n 1)"
fi

for t in bun deno go; do
  command -v "$t" >/dev/null 2>&1 || continue
  case "$t" in
    go) v=$(GOTOOLCHAIN=local go version 2>&1 | head -n 1) ;;
    deno) v=$(deno --version 2>&1 | head -n 1) ;;
    *) v=$(bun --version 2>&1 | head -n 1) ;;
  esac
  echo "RT $t $v"
done

if command -v python3 >/dev/null 2>&1; then
  python3 -I -S -c '
import sys
if sys.version_info < (3, 8):
    sys.stdout.write("NOPY %d.%d.%d\n" % sys.version_info[:3])
    sys.exit(0)
import os
import site
import importlib.metadata as metadata


def venv(path):
    here = os.path.dirname(path)
    for candidate in (here, os.path.dirname(here)):
        if os.path.isfile(os.path.join(candidate, "pyvenv.cfg")):
            return candidate
    return None


home = venv(sys.argv[1]) or venv(sys.executable)
if home:
    paths = [os.path.join(home, "lib", "python%d.%d" % sys.version_info[:2], "site-packages")]
else:
    paths = list(site.getsitepackages())
paths.append(site.getusersitepackages())
bundles = {"certifi": "certifi/cacert.pem", "pip": "pip/_vendor/certifi/cacert.pem"}
for dist in metadata.distributions(path=paths):
    name = (dist.metadata["Name"] or "").lower()
    if name in ("certifi", "pip", "uv"):
        installer = (dist.read_text("INSTALLER") or "").strip().splitlines()
        location = str(dist.locate_file(""))
        bundled = "-"
        if name in bundles:
            bundle = os.path.join(location, bundles[name])
            bundled = "0"
            if os.path.isfile(bundle):
                package = os.path.realpath(os.path.join(location, name)) + os.sep
                bundled = "1" if os.path.realpath(bundle).startswith(package) else "L"
        fields = (name, dist.version, installer[0] if installer else "unknown", bundled, location)
        sys.stdout.write("PY " + " ".join(fields) + "\n")
' "$(command -v python3)" 2>/dev/null
fi

if [ -r /etc/os-release ]; then
  echo "OS $(sed -n 's/^ID=//p' /etc/os-release | head -n 1 | tr -d "\"'")"
fi
# shellcheck disable=SC2016
if command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W -f='PKG dpkg ${Package} ${Version}\n' ca-certificates 2>/dev/null
fi
if command -v apk >/dev/null 2>&1; then
  apk info -v 2>/dev/null | sed -n 's/^\(ca-certificates\(-bundle\)\{0,1\}\)-\([0-9][^-]*-r[0-9]*\)$/PKG apk \1 \3/p'
fi
if command -v rpm >/dev/null 2>&1; then
  rpm -q --qf 'PKG rpm ca-certificates %{VERSION}-%{RELEASE}\n' ca-certificates 2>/dev/null | grep '^PKG'
  rpm -q --qf 'PKG suse ca-certificates-mozilla %{VERSION}\n' ca-certificates-mozilla 2>/dev/null | grep '^PKG'
  echo "CHG rpm $(rpm -q --changelog ca-certificates 2>/dev/null | grep -c CVE-2026-114406)"
fi
if command -v pacman >/dev/null 2>&1; then
  pacman -Q ca-certificates-mozilla 2>/dev/null | sed 's/^/PKG pacman /'
fi

if ! command -v od >/dev/null 2>&1; then
  echo NOOD
  exit 0
fi

dump() {
  [ -f "$1" ] || return 0
  n=$(wc -c < "$1" 2>/dev/null) || return 0
  n=$((n + 0))
  if [ "$n" -gt "$BIG" ]; then
    echo "BIG $n $1"
  else
    echo "FILE $n $1"
    od -An -v -tx1 "$1" 2>/dev/null
    echo END
  fi
}

for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt \
  /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/ssl/ca-bundle.pem /etc/ssl/cert.pem \
  /var/lib/ca-certificates/ca-bundle.pem; do
  dump "$f"
done
find / -xdev \( -name cacert.pem -o -name cacerts \) -type f 2>/dev/null | head -n @MAX_PROBE_FILES@ | while IFS= read -r f; do
  dump "$f"
done
exit 0
