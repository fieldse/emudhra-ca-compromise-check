# eMudhra G3 CA compromise check

This repository checks whether your stack still trusts the compromised eMudhra G3 certificates. Eight eMudhra G3 intermediate CAs have private keys small enough for anyone to compute, so anyone can issue certificates under them. Sectigo cross-signed all eight under its `AAA Certificate Services` root with the same keys. Browsers on default settings block the chains through pushed revocation data, apart from a startup gap in new Firefox ESR 115 profiles and forks that drop OneCRL, such as GNU IceCat built from ESR 153.5.1. Everything that carries its own trust store needs its own update: OS `ca-certificates` packages, JDK `cacerts`, Python, Node.js, Bun and Deno, Go, Rust, PHP, Ruby, Perl and Elixir packages, Electron apps, developer tools and container images.

To check by hand, [read the guide](https://fieldse.github.io/emudhra-ca-compromise-check/) for what happened and what to fix first. The [checks page](https://fieldse.github.io/emudhra-ca-compromise-check/checks.html) gives a read-only command and the fixed version for each item. The [references page](https://fieldse.github.io/emudhra-ca-compromise-check/references.html) gives the sources for every claim. To check automatically, run the read-only check in [Quick start](#quick-start).

## Contents

- [Quick start](#quick-start)
- [Options](#options)
- [What the check reads](#what-the-check-reads)
- [What the check runs](#what-the-check-runs)
- [Verdicts and exit codes](#verdicts-and-exit-codes)
- [Limitations](#limitations)
- [Changes from the Bash script](#changes-from-the-bash-script)
- [Verify and rebuild](#verify-and-rebuild)
- [The AAA cross-sign path](#the-aaa-cross-sign-path)
- [Repository layout](#repository-layout)

## Quick start

The check is one file, `vuln-check-emudhra-ca-compromise.pyz`, a Python zipapp. It needs Python 3.9 or later and no packages, and it only reads files.

```bash
curl -fLO https://raw.githubusercontent.com/fieldse/emudhra-ca-compromise-check/v2.0.0/scripts/vuln-check-emudhra-ca-compromise.pyz
curl -fLO https://raw.githubusercontent.com/fieldse/emudhra-ca-compromise-check/v2.0.0/scripts/vuln-check-emudhra-ca-compromise.pyz.sha256
shasum -a 256 -c vuln-check-emudhra-ca-compromise.pyz.sha256

python3 -I -S vuln-check-emudhra-ca-compromise.pyz -r ~ -q                      # scan home, print problems only
python3 -I -S vuln-check-emudhra-ca-compromise.pyz -r ~/src -x ~/src/vendor -q  # skip one directory
python3 -I -S vuln-check-emudhra-ca-compromise.pyz --root=/opt --containers     # also probe local Podman images
python3 -I -S vuln-check-emudhra-ca-compromise.pyz --help                       # all options
```

The supported run line is `python3 -I -S vuln-check-emudhra-ca-compromise.pyz`. `-I -S` keeps the scanned machine's Python settings, `site` and `.pth` files out of the check. Run any other way, such as `./vuln-check-emudhra-ca-compromise.pyz` through its shebang or `python3` without the flags, Python imports `site` and runs the machine's `.pth` files before the check starts. The archive then re-executes itself under `-I -S` and prints a note, but only after that startup.

## Options

| Option | Meaning |
|---|---|
| `-r, --root ROOT` | Directory to scan for CA bundles, keystores, binaries and package files. Repeatable, default `$HOME`. On macOS, `/Applications`, `~/Applications` and Homebrew's `etc` and `Caskroom` are always added |
| `-x, --exclude DIR` | Never enter this directory. Repeatable. Matched by the directory itself, so case, symlinks and glob characters do not matter |
| `-c, --containers` | Also probe every local Podman image, with networking off |
| `-i, --image IMAGE` | Probe only this local image. Repeatable, implies `-c` |
| `-q, --quiet` | Print only `FAIL`, `WARN` and `ERROR` lines plus the summary |
| `-s, --strict` | Exit 1 on `WARN` and `ERROR` as well as `FAIL` |

## What the check reads

- **Certificates and keys inside files.** CA bundles, Java keystores (JKS, JCEKS and PKCS12, read directly without `keytool`), and the Node.js, Bun, Deno, Go and Rust binaries and Electron apps it finds. It matches each certificate and its public key, in PEM or DER, so bundles without comments are covered. A compromised key held as a blocklist entry is reported as `INFO`. So is an OpenSSL `TRUSTED CERTIFICATE` entry whose trust settings list only rejected uses, since it distrusts the certificate.
- **Trust stores.** The OS bundle files, Homebrew's bundle and its `ca-certificates` formula version, notes on the macOS system roots keychain, and the `cacerts` of each Java home (`JAVA_HOME`, the `java` on `PATH`, and `java_home` on macOS).
- **OS packages.** `ca-certificates` through dpkg, apk, rpm and pacman.
- **Runtimes.** Node.js (including nvm, volta, asdf, fnm and mise installs and Node binaries that apps ship), Bun, Deno, Go and CPython.
- **Language packages.** certifi, pip and uv, certifi pins in requirements files, `poetry.lock`, `uv.lock` and `Pipfile.lock`, Electron in `package.json` and `node_modules`, Rust `webpki-roots`, `webpki-root-certs` and `rustls-webpki` in `Cargo.lock` and in binaries, `composer/ca-bundle`, `excon`, `castore`, Hex `certifi` and Perl `Mozilla::CA`. A certifi or pip with no `cacert.pem` of its own, as Debian ships them, uses the system store and is `INFO`. A `Cargo.lock` inside downloaded crate source, under Cargo's `registry/src` or `git/checkouts` directories, is `INFO` and is not read, since it does not decide what a local build uses.
- **Binaries and apps.** Go binaries (toolchain and the `x509roots/fallback` module), Rust binaries, Electron apps on macOS and Linux judged by their Electron version, and apps left in ShipIt updater caches. Programs are read in `GOBIN`, each `GOPATH/bin`, `~/.cargo/bin`, `~/.local/bin`, `/usr/local/bin`, Homebrew's `bin` and the scan roots.
- **Container images**, when you opt in with `-c` or `-i`: runtimes, Python packages, the `ca-certificates` package, CA bundles and Java keystores inside each image.

It never runs a binary it judges. Electron 44.9.1 counts as fixed, as Electron's advisory says, though every fixed Electron release checked still carries the G3 root, because the fix blocks the intermediates and leaves the root in place. The [guide](https://fieldse.github.io/emudhra-ca-compromise-check/#helper) lists what it doesn't check yet.

## What the check runs

For version answers the check runs `node`, `bun`, `deno`, `go`, `python3`, `uv` and `perl` from `PATH`, and `podman` from `PATH` with `-c`. On macOS it runs `/usr/bin/security`, `/usr/bin/xcode-select` and `/usr/libexec/java_home` by absolute path. A tool in an excluded directory is skipped.

Run as root, the check does not run a tool whose file, or any directory above it, is not owned by root or is group- or world-writable. A sticky directory such as `/nix/store` counts as safe when the entries below it are owned by root. For such a tool it prints `WARN  TOOL [host] not run: TOOL is writable by a non-root user`, still reads the tool's binary for the compromised certificates, and takes Node's version from the binary. With `-c`, such a `podman` stops the run with exit 2. On a machine whose `PATH` tools you don't trust, scan from a clean account or pass `-x` for those directories.

## Verdicts and exit codes

- `FAIL`: a bundle, keystore or binary still holds `emSign ECC Root CA - G3` or a compromised certificate, or a release is older than its fix.
- `WARN`: needs manual review. `AAA Certificate Services` is reported here.
- `INFO`: context, such as a compromised key held as a blocklist entry or a certificate held as a rejected entry.
- `ERROR`: a check that failed to run. The rest of the run continues.

The check exits 1 on any `FAIL`, 2 on a usage or environment error, and 0 otherwise. A `WARN` or `ERROR` alone leaves the exit code at 0, so a check that failed to run does not fail the run. Pass `--strict` to exit 1 on `WARN` and `ERROR` as well, for a CI gate that must notice them. The last line is `SUMMARY pass=N fail=N warn=N info=N skip=N error=N`.

A stock Mac fails `--strict` on the `AAA Certificate Services` line for `/etc/ssl/cert.pem` until Apple updates that file. Apple has said only that a future macOS update will fix it.

## Limitations

- An exclude matches the excluded directory itself. A subdirectory of it that is bind-mounted at another path under a scan root is walked at that path. Exclude the mount point as well.
- A file above 32 MiB is read through `mmap`. If another process truncates it during the read, the run ends with `SIGBUS`.
- Run as root, the tool ownership check reads owner and mode bits only. An ACL that lets a non-root user change a tool or a directory above it is not seen.

## Changes from the Bash script

The zipapp replaces the earlier Bash script. Its output keeps the same line format, with these changes a user will see:

- `AAA Certificate Services` is `WARN`, not `INFO`, so `--strict` fails on it.
- An exact Electron version below its branch's fix (`"43.8.0"` or `"=43.8.0"` in `package.json`) is `FAIL`, because it can install only that version. Ranges (`^`, `~`, `N.x`) below the fix stay `WARN`. A declared Electron line names the `package.json` path and opens its detail with `pins V` for an exact spec or `range starts at V` for a range.
- rpm package lines print the full VERSION-RELEASE as `rpm -q` shows it, for example `found 2025.2.80_v9.0.304-6.fc44, fixed 2026.2.92_v9.0.319-2`.
- The `checked N PEM files` count includes linked files, so `/etc/ssl/certs` counts each certificate a link points to.
- A Rust binary's `rustls-webpki` below 0.103.16 is `WARN` when the same binary holds neither the G3 root nor a compromised intermediate. That crate lacks the key blocklist, which matters only when the binary uses the system trust store. It stays `FAIL` when the binary holds one of those certificates. uv 0.13.4, which uv's advisory calls fixed, gets this `WARN`.
- `ERROR` lines can appear, and `SUMMARY` gains ` error=N`.

The Bash script is still in commit `354e951` as `scripts/vuln-check-emudhra-ca-compromise.sh`, for anyone who needs a shell-only check. It has no `-x` and misses the binaries, Electron apps and keystores listed above.

## Verify and rebuild

The `.sha256` file checks the download. To see what is inside the archive before running it:

```bash
unzip -l vuln-check-emudhra-ca-compromise.pyz
unzip -p vuln-check-emudhra-ca-compromise.pyz emudhra_check/cli.py | less
```

The archive is reproducible. `tools/build_pyz.py` gives the same bytes under Python 3.9 and Python 3.13, and the test suite compares the committed archive with fresh builds under both. To rebuild it yourself, run the build at the release tag in a container of the test suite's Python 3.9 image and compare:

```bash
git clone https://github.com/fieldse/emudhra-ca-compromise-check.git
cd emudhra-ca-compromise-check && git checkout v2.0.0 && mkdir -p rebuild
docker run --rm --network=none -v "$PWD":/repo:ro -v "$PWD/rebuild":/out \
  docker.io/library/python@sha256:2d97f6910b16bd338d3060f261f53f144965f755599aab1acda1e13cf1731b1b \
  python3 -I /repo/tools/build_pyz.py --out /out/check.pyz
cmp rebuild/check.pyz scripts/vuln-check-emudhra-ca-compromise.pyz && echo identical
```

That digest is `python:3.9-slim` (Python 3.9.25). The Python 3.13 build runs in the test image from `tests/Containerfile`: Debian trixie at `docker.io/library/debian@sha256:4c25275446ca371766b8b093c696782eabce06263fccacb8d5d813b3dc44b308` with Debian's `python3` (3.13.5).

## The AAA cross-sign path

Sectigo's cross-signed copies of the compromised intermediates reuse the same weak keys. A store that has dropped `emSign ECC Root CA - G3` but still holds `AAA Certificate Services` can still trust a forged chain through those copies. The check reports the AAA root as `WARN`, and the checks page has an AAA column for every item.

## Repository layout

| Path | Holds |
|---|---|
| `index.html`, `checks.html`, `references.html` | The guide, the checks table and the claim references |
| `scripts/vuln-check-emudhra-ca-compromise.pyz` | The read-only check, a Python zipapp, with its `.sha256` file |
| `emudhra_check/` | The check's source, which the zipapp holds |
| `tools/build_pyz.py`, `tools/pyz_main.py` | The reproducible archive build and the archive's entry point |
| `rules/iocs.csv`, `rules/certs/` | The 16 compromised certificates and the G3 roots, with fingerprints |
| `rules/yara/`, `rules/sigma/` | A YARA rule for the certificates in files, and a Sigma rule for a G3 certificate added to a trusted store |
| `tests/` | Unit tests and container tests for the check, the archive and the rules |
