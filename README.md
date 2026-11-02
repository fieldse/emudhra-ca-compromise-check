# eMudhra G3 CA compromise check

**Does your stack still trust the compromised eMudhra G3 certificates?** Eight eMudhra G3 intermediate CAs have private keys below 256, so anyone can compute the keys and issue certificates under them. Sectigo cross-signed all eight under its `AAA Certificate Services` root with the same keys. Browsers on default settings block chains through these intermediates, but anything with its own trust store needs its own update.

- **Check by hand:** use the guide pages.
  - The [guide](https://fieldse.github.io/emudhra-ca-compromise-check/) covers what happened and what to fix first.
  - The [checks page](https://fieldse.github.io/emudhra-ca-compromise-check/checks.html) gives a read-only command and the fixed version for each item.
  - The [detections page](https://fieldse.github.io/emudhra-ca-compromise-check/detections.html) lists every rule the check applies, with its sources and verification status.
  - The [references page](https://fieldse.github.io/emudhra-ca-compromise-check/references.html) gives the sources for every claim.
- **Check automatically:** run the read-only check in [Quickstart](#quickstart).

## Contents

- [Safety](#safety)
- [Quickstart](#quickstart)
- [Usage](#usage)
- [What it checks](#what-it-checks)
- [Limitations](#limitations)
- [Verification](#verification)
- [Changes from the Bash script](#changes-from-the-bash-script)
- [Repository layout](#repository-layout)
- [Sources](#sources)
- [Contribution](#contribution)
- [License](#license)

## Safety

- **Read-only:** it reads files and changes nothing on your system.
- **No network for images:** it checks container images with `--network=none` and never pulls an image.
- **Runs only a fixed list of programs:** `node`, `bun`, `deno`, `go`, `python3`, `uv` and `perl` from `PATH` to read their versions, `podman` with `-c`, and on macOS `/usr/bin/security`, `/usr/bin/xcode-select` and `/usr/libexec/java_home` by absolute path. [Commands it runs](#commands-it-runs) gives the details.
- **Runs nothing else it finds:** every other binary it comes across while scanning is read as data and never run.
- **Skips user-writable tools as root:** run as root, it does not run a PATH tool that a non-root user could change.
- **Needs Python 3.9 or later** and no packages. No root needed.

## Quickstart

The check is one file, `vuln-check-emudhra-ca-compromise.pyz`, a Python zipapp.

```bash
curl -fLO https://raw.githubusercontent.com/fieldse/emudhra-ca-compromise-check/v2.0.0/scripts/vuln-check-emudhra-ca-compromise.pyz
curl -fLO https://raw.githubusercontent.com/fieldse/emudhra-ca-compromise-check/v2.0.0/scripts/vuln-check-emudhra-ca-compromise.pyz.sha256
shasum -a 256 -c vuln-check-emudhra-ca-compromise.pyz.sha256

python3 -I -S vuln-check-emudhra-ca-compromise.pyz -r ~ -q                      # scan home, print problems only
python3 -I -S vuln-check-emudhra-ca-compromise.pyz -r ~/src -x ~/src/vendor -q  # skip one directory
python3 -I -S vuln-check-emudhra-ca-compromise.pyz --root=/opt --containers     # also probe local Podman images
python3 -I -S vuln-check-emudhra-ca-compromise.pyz --help                       # all options
```

Always start the check with `python3 -I -S vuln-check-emudhra-ca-compromise.pyz`. `-I -S` keeps the scanned machine's Python settings, `site` and `.pth` files out of the check.

If you start it any other way, such as `./vuln-check-emudhra-ca-compromise.pyz` through its shebang or `python3` without the flags, Python imports `site` and runs the machine's `.pth` files before the check starts. The archive then re-executes itself under `-I -S` and prints a note, but by then those files have already run.

## Usage

### Reading the results

Each output line reads `LEVEL subject [location] detail`. The last line is `SUMMARY pass=N fail=N warn=N info=N skip=N error=N`.

- `FAIL`: a bundle, keystore or binary still holds one of the three G3 roots (`emSign ECC Root CA - G3`, `emSign Root TLS CA - G3` or `emSign Root CS CA - G3`) or a compromised intermediate, or a release is older than its fix.
- `WARN`: needs a manual look, such as a store that holds `AAA Certificate Services`.
- `INFO`: context, such as a compromised key on a blocklist or a certificate marked as rejected.
- `PASS`: fixed, or no compromised certificate found.
- `ERROR`: a check failed to run, and the run carried on without it.
- `SKIP`: an image with no shell, not inspected.

Exit codes:

- `0`: no `FAIL`, even with `WARN` or `ERROR` lines.
- `1`: any `FAIL`, or any `WARN` or `ERROR` with `--strict`.
- `2`: usage or environment error.

Use `--strict` for a CI gate that must also catch warnings and checks that failed to run.

A stock Mac fails `--strict` on the `AAA Certificate Services` line for `/etc/ssl/cert.pem` until Apple updates that file. Apple has said only that a future macOS update will fix it.

### What it scans by default

With no `-r`, the check scans `$HOME`. On macOS it always adds these, with or without `-r`:

- `/Applications`
- `~/Applications`
- Homebrew's `etc` and `Caskroom`

It also reads the programs in these directories:

- `GOBIN` and each `GOPATH/bin`
- `~/.cargo/bin`
- `~/.local/bin`
- `/usr/local/bin`
- Homebrew's `bin`

It reads the OS CA bundle files at their standard paths. It reads the `cacerts` of each Java home it finds through `JAVA_HOME`, the `java` on `PATH`, and `java_home` on macOS.

### Options

- `-r`, `--root ROOT`: directory to scan for CA bundles, keystores, binaries and package files. Repeatable. Default `$HOME`.
- `-x`, `--exclude DIR`: never enter this directory. Repeatable.
- `-c`, `--containers`: also check every local Podman image, with networking off.
- `-i`, `--image IMAGE`: check only this local image. Repeatable, implies `-c`.
- `-q`, `--quiet`: print only `FAIL`, `WARN` and `ERROR` lines plus the summary.
- `-s`, `--strict`: exit 1 on `WARN` and `ERROR` as well as `FAIL`.
- `--help`: every option.

### Excluding a directory (`-x`)

- `-x` matches the directory by its identity on disk, so letter case, symlinks and glob characters in the path don't change what it excludes.
- A tool in an excluded directory is skipped and not run.
- If a subdirectory of an excluded directory is bind-mounted at another path inside a scanned directory, the check scans it at that path unless you exclude the mount point too.

### Commands it runs

- From `PATH` it runs `node`, `bun`, `deno`, `go`, `python3`, `uv` and `perl` to read their versions (`--version`, or `go version`).
  - `node -p process.execPath` names the binary the check then reads.
  - `python3 -I -S -c` runs a short script that reads certifi and pip from package metadata.
  - `perl -MMozilla::CA -e` prints the module's version and the bundle path it hands out.
- With `-c` or `-i` it runs `podman` from `PATH`, which starts a probe in each image with `--network=none`.
- On macOS it runs `/usr/bin/security`, `/usr/bin/xcode-select` and `/usr/libexec/java_home` by absolute path.
- It runs nothing else. Every other binary it finds while scanning is read as data.

### Running as root

Run as root, the check does not run a tool if the tool's file, or any directory above it, is not owned by root or is group- or world-writable.

- A sticky directory such as `/nix/store` counts as safe when the entries below it are owned by root.
- For such a tool it prints `WARN  TOOL [host] not run: TOOL is writable by a non-root user`.
- It still reads that tool's binary for the compromised certificates.
- For `node`, it takes the version from the binary instead of running it.
- With `-c`, a `podman` that fails this test stops the run with exit 2.
- On a machine whose `PATH` tools you don't trust, scan from a clean account or pass `-x` for those directories.

## What it checks

Browsers on default settings block chains through the compromised intermediates with pushed revocation data. The gaps are a startup window in new Firefox ESR 115 profiles, and forks that drop OneCRL, such as GNU IceCat built from ESR 153.5.1. Everything that carries its own trust store needs its own update: OS `ca-certificates` packages, JDK `cacerts`, Python, Node.js, Bun and Deno, Go, Rust, PHP, Ruby, Perl and Elixir packages, Electron apps, developer tools and container images.

The check works through this list in order and prints its lines in the same order.

| # | Check |
|---|---|
| 1 | OS CA bundle files at their standard paths |
| 2 | OS `ca-certificates` package, through dpkg, apk, rpm and pacman |
| 3 | Homebrew's CA bundles, its `ca-certificates` formula version, and notes on the macOS system roots keychain that formula copies |
| 4 | `bun` on PATH: its version and the roots its binary holds |
| 5 | `node` on PATH, by version and by the binary `process.execPath` names |
| 6 | `deno` on PATH: its version, and the roots and blocked keys its binary holds |
| 7 | `go` on PATH, and the toolchain minimums `go.mod` files declare |
| 8 | `python3` on PATH, and the interpreter running the check when it differs |
| 9 | Electron apps, as macOS bundles and Linux app directories, by their Electron version (see [Electron](#electron)) |
| 10 | Electron apps left in Squirrel.Mac ShipIt updater caches, by version only |
| 11 | Node.js installs from nvm, volta, asdf, fnm and mise |
| 12 | Node binaries that apps and tools ship outside PATH and the version managers |
| 13 | certifi, pip and uv `dist-info` directories |
| 14 | certifi pins in requirements files, `poetry.lock`, `uv.lock` and `Pipfile.lock` |
| 15 | certifi and pip as the `python3` on PATH sees them, read from package metadata only |
| 16 | `uv` on PATH: its version and the roots its binary holds |
| 17 | Electron in `node_modules`, and the Electron versions `package.json` files declare |
| 18 | Go binaries: the toolchain they were built with and the `x509roots/fallback` module |
| 19 | Rust binaries whose embedded source paths name `webpki-roots`, `webpki-root-certs` or `rustls-webpki` |
| 20 | `webpki-roots`, `webpki-root-certs` and `rustls-webpki` in `Cargo.lock` |
| 21 | `composer/ca-bundle` in `composer.lock` |
| 22 | `excon` in `Gemfile.lock` |
| 23 | `castore` and Hex `certifi` in `mix.lock` |
| 24 | PEM bundles in the scanned directories, listed only when they hold a certificate the check looks for |
| 25 | The `cacerts` of each Java home, and every `cacerts` file in the scanned directories |
| 26 | Perl `Mozilla::CA` for the `perl` on PATH: its version and the bundle it hands out |
| 27 | Local Podman images, one at a time, with `-c` or `-i` |

The [detections page](https://fieldse.github.io/emudhra-ca-compromise-check/detections.html) gives each of these checks with every rule it applies: the condition, the level it reports, the value it compares, the sources and the rule's verification status. The rules live in `rules/detection-rules.csv`, and `tools/build_detections.py` builds the page from that file.

### How it reads files

- It identifies each certificate by its content and its public key, in PEM or DER, so it finds certificates in bundles that have no comments.
- It reads Java keystores in JKS, JCEKS and PKCS12 directly, without `keytool`.
- A compromised key held as a blocklist entry is `INFO`.
- An OpenSSL `TRUSTED CERTIFICATE` entry whose trust settings list only rejected uses is `INFO`, because that entry distrusts the certificate.
- A certifi or pip with no `cacert.pem` of its own, as Debian ships them, uses the system store and is `INFO`.
- A `Cargo.lock` inside downloaded crate source, under Cargo's `registry/src` or `git/checkouts` directories, is `INFO` and is not read, because it does not decide what a local build uses.
- Inside each container image it reads runtimes, Python packages, the `ca-certificates` package, CA bundles and Java keystores.

### AAA cross-sign path

Sectigo's cross-signed copies of the compromised intermediates reuse the same weak keys. A store that has dropped `emSign ECC Root CA - G3` but still holds `AAA Certificate Services` can still trust a forged chain through those copies. The check reports the AAA root as `WARN`, and the checks page has an AAA column for every item.

### Electron

Electron's advisory gives the first fixed release on each branch: 42.11.16, 43.8.1, 44.9.1 and 45.0.0-beta.6. The check compares each Electron version with the fixed release on its own branch.

- An installed Electron below its branch's fix is `FAIL`.
- An Electron on a branch older than 42, which has no fix, is `FAIL`.
- An exact version in `package.json` below its branch's fix (`"43.8.0"` or `"=43.8.0"`) is `FAIL`, because it can install only that version.
- A range (`^`, `~`, `N.x`) that starts below the fix is `WARN`, because it may resolve to a fixed release.

Every fixed Electron release checked still lists `emSign ECC Root CA - G3` in its bundled Node.js roots, because the fix blocks the compromised keys and leaves the root list alone. On a fixed app the check reports that root as `INFO`.

## Limitations

- The [guide](https://fieldse.github.io/emudhra-ca-compromise-check/#helper) lists what the check doesn't cover yet.
- A file above 32 MiB is read through `mmap`, so if another process truncates it during the read, the run ends with `SIGBUS`.
- Run as root, the check decides whether a tool is safe to run from its owner and mode bits only, so it misses an ACL that lets a non-root user change the tool or a directory above it.

## Verification

The test suite runs the check against real CA bundles and JDK keystores, and against test binaries, from before and after each fix.

- Each test case runs in a container with networking off, under Python 3.13 and Python 3.9.
- The suite needs the network only to build and pull its images and download certifi.
- It uses Docker if Docker responds, else Podman. Its `-e` option picks one.

```bash
git clone https://github.com/fieldse/emudhra-ca-compromise-check.git
cd emudhra-ca-compromise-check
tests/run-tests.sh
```

The lines below are from the suite's expected output.

### certifi

The certifi 2026.7.22 and 2026.10.18 wheels, checked against their SHA-256. Cases `tests/expect/d1-certifi-old-version.txt` and `d1-certifi-fixed-version.txt`.

```text
FAIL  certifi [/tmp/d/certifi-2026.7.22.dist-info] found 2026.7.22, fixed 2026.10.18 (vendors its own CA bundle)
PASS  certifi [/tmp/d/certifi-2026.10.18.dist-info] found 2026.10.18, fixed 2026.10.18
```

### JDK cacerts

The `cacerts` of `eclipse-temurin:21.0.8_9-jre`, released before the fix, and `eclipse-temurin:21.0.13_9-jre`, released after it. Case `tests/expect/a4-keystores.txt`.

```text
FAIL  java keystore [/out/java/jdk-old/cacerts] contains emSign ECC Root CA - G3 (removed root)
PASS  java keystore [/out/java/jdk-fixed/cacerts] contains no compromised eMudhra certificate
```

### Debian ca-certificates

The first two lines are recorded output from checking a Debian 12 image with `ca-certificates` 20230311+deb12u1, in `tests/unit/test_containers.py`. The third is the Debian 13 test image with 20250419+deb13u1, case `tests/expect/a1-os-trust-store.txt`.

```text
FAIL  ca-certificates [image:localhost/x:1] found 20230311+deb12u1
FAIL  ca-bundle [image:localhost/x:1 /etc/ssl/certs/ca-certificates.crt] contains emSign ECC Root CA - G3 (removed root)
PASS  ca-certificates [host] found 20250419+deb13u1, fixed 20250419+deb13u1
```

### Electron app

Two test app bundles with Electron 44.9.0 and 44.9.1. Case `tests/expect/e4-electron-apps.txt`.

```text
FAIL  electron app [/tmp/apps/Old.app/Contents/Frameworks/Electron Framework.framework] found 44.9.0, fixed 44.9.1 (update the app)
PASS  electron app [/tmp/apps/Fixed.app/Contents/Frameworks/Electron Framework.framework] found 44.9.1, fixed 44.9.1
```

### Go binary

Two test programs built with Go 1.27.2 and Go 1.27.3. Case `tests/expect/e1-go-binaries.txt`.

```text
FAIL  go binary [/tmp/fx/bin/go-old] found 1.27.2, fixed 1.27.3 (built with an affected toolchain, rebuild)
PASS  go binary [/tmp/fx/bin/go-new] found 1.27.3, fixed 1.27.3
```

### Verify and rebuild the archive

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

The image digest above is `python:3.9-slim` (Python 3.9.25). The Python 3.13 build runs in the test image from `tests/Containerfile`: Debian trixie at `docker.io/library/debian@sha256:4c25275446ca371766b8b093c696782eabce06263fccacb8d5d813b3dc44b308` with Debian's `python3` (3.13.5).

## Changes from the Bash script

The zipapp replaces an earlier Bash script and keeps its output line format. Its output differs in these ways:

- `AAA Certificate Services` is now `WARN` (it was `INFO`), so `--strict` fails on it.
- An exact Electron version below its branch's fix is now `FAIL` (see [Electron](#electron)).
- Ranges below the fix stay `WARN`.
- The line for an Electron version declared in `package.json` names the file's path, and its detail starts with `pins V` for an exact spec or `range starts at V` for a range.
- rpm package lines print the full VERSION-RELEASE as `rpm -q` shows it, for example `found 2025.2.80_v9.0.304-6.fc44, fixed 2026.2.92_v9.0.319-2`.
- The `checked N PEM files` count includes linked files, so `/etc/ssl/certs` counts each certificate a link points to.
- `rustls-webpki` below 0.103.16 in a Rust binary is `WARN` when the same binary holds none of the three G3 roots and no compromised intermediate.
  - It stays `FAIL` when the binary holds one of those certificates.
  - Those versions lack the blocklist of compromised keys, which matters only when the binary uses the system trust store.
  - uv 0.13.4, which uv's advisory calls fixed, gets this `WARN`.
- `ERROR` lines are new, and `SUMMARY` gains ` error=N`.

The Bash script is still in commit `354e951` as `scripts/vuln-check-emudhra-ca-compromise.sh`, for anyone who needs a shell-only check. It has no `-x`, and it misses the binaries, Electron apps and keystores the zipapp reads.

## Repository layout

| Path | Holds |
|---|---|
| `index.html`, `checks.html`, `detections.html`, `references.html` | The guide, the checks page, the detections page and the references page |
| `rules/detection-rules.csv` | The rule register: every rule the check applies, with its code line, sources and verification status |
| `scripts/vuln-check-emudhra-ca-compromise.pyz` | The read-only check, a Python zipapp, with its `.sha256` file |
| `emudhra_check/` | The check's source, which the zipapp holds |
| `tools/build_pyz.py`, `tools/pyz_main.py` | The reproducible archive build and the archive's entry point |
| `tools/build_detections.py` | Builds `detections.html` from the rule register |
| `rules/iocs.csv`, `rules/certs/` | The 16 compromised certificates and the G3 roots, with fingerprints |
| `rules/yara/`, `rules/sigma/` | A YARA rule for the certificates in files, and a Sigma rule for a G3 certificate added to a trusted store |
| `tests/` | Unit tests and container tests for the check, the archive and the rules |
| `LICENSE` | The MIT license |

## Sources

Every claim in the guide and the checks page, including each fixed version, comes from a vendor, project or tracker document.
The [references page](https://fieldse.github.io/emudhra-ca-compromise-check/references.html) lists each claim with its sources, checked 2026-10-31. Rows R304 to R348 were added on 2026-11-02, when every detection rule was checked against its sources.

## Contribution

Found something wrong? Have an improvement? Open an [issue](https://github.com/fieldse/emudhra-ca-compromise-check/issues) or contact me on [LinkedIn](https://www.linkedin.com/in/mattfields-dev/).

If you find this useful, please let me know.

## License

[MIT](LICENSE)
