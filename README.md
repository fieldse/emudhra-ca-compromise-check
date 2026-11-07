# eMudhra G3 CA compromise check

**A read-only check for software on a machine, or in a local container image, that still trusts the compromised eMudhra G3 certificates or runs a release older than its fix.** Eight eMudhra G3 intermediate CAs were issued with private keys that are integers below 256, so anyone can recover the keys from the public certificates and issue certificates under them. Browsers on default settings block chains through these intermediates, but anything with its own trust store, such as an OS `ca-certificates` package, a JDK `cacerts` file, a language runtime, an Electron app or a container image, needs its own update.

- **Check by hand:** the guide's [manual checks](https://fieldse.github.io/emudhra-ca-compromise-check/#manual) give the command and fixed version for each stack. The [Affected software page](https://fieldse.github.io/emudhra-ca-compromise-check/checks.html) lists all 130 items.
- **Check automatically:** run the read-only check in [Quickstart](#quickstart).

**Documentation:** [How the check works](docs/how-it-works.md) · [Verifying a finding](https://fieldse.github.io/emudhra-ca-compromise-check/proof.html) · [Checker rules](https://fieldse.github.io/emudhra-ca-compromise-check/detections.html) · [Weak and unverifiable rules](docs/weak-rules.md) · [Source index](docs/sources.md)

## Contents

- [Safety](#safety)
- [Quickstart](#quickstart)
- [Usage](#usage)
- [What it checks](#what-it-checks)
- [Limitations](#limitations)
- [Tests and reproducible build](#tests-and-reproducible-build)
- [Repository layout](#repository-layout)
- [Sources](#sources)
- [Contribution](#contribution)
- [License](#license)

## Safety

**The check reads files and changes nothing. It runs a short, fixed list of programs and treats everything else it finds as data.**

- **Read-only:** it reads files and changes nothing on the system.
- **No network for images:** it checks container images with `--network=none` and never pulls an image.
- **Fixed list of programs:** it runs language runtimes and package managers from `PATH` to read versions, `podman` with `-c` or `-i`, and three macOS system tools by absolute path. [Commands it runs](#commands-it-runs) names each one.
- **Nothing else:** every other binary it comes across while scanning is read as data and never run.
- **Root runs:** as root, it does not run a `PATH` tool that a non-root user could change. [Running as root](#running-as-root) gives the rule.

## Quickstart

**The check is one file, `vuln-check-emudhra-ca-compromise.pyz`, a Python zipapp: a zip archive that `python3` runs as a program. It needs Python 3.9 or later, no packages and no root.**

Always start the check with `python3 -I -S vuln-check-emudhra-ca-compromise.pyz`. `-I -S` keeps the scanned machine's Python settings, `site` and `.pth` files out of the check.

```bash
curl -fLO https://raw.githubusercontent.com/fieldse/emudhra-ca-compromise-check/v2.1.0/scripts/vuln-check-emudhra-ca-compromise.pyz
curl -fLO https://raw.githubusercontent.com/fieldse/emudhra-ca-compromise-check/v2.1.0/scripts/vuln-check-emudhra-ca-compromise.pyz.sha256
shasum -a 256 -c vuln-check-emudhra-ca-compromise.pyz.sha256

python3 -I -S vuln-check-emudhra-ca-compromise.pyz -r ~ -q                      # scan home, print problems only
python3 -I -S vuln-check-emudhra-ca-compromise.pyz -r ~/src -x ~/src/vendor -q  # skip one directory
python3 -I -S vuln-check-emudhra-ca-compromise.pyz --root=/opt --containers     # also probe local container images
python3 -I -S vuln-check-emudhra-ca-compromise.pyz --help                       # all options
```

- **Why the flags matter:** started any other way, such as `./vuln-check-emudhra-ca-compromise.pyz` through its shebang or `python3` without the flags, Python imports `site` and runs the machine's `.pth` files before the check starts. The archive then re-executes itself under `-I -S` and prints a note, but those files have already run.
- **From a clone:** run `./run-checks.sh` at the repository root. It starts the archive in `scripts/` with `python3 -I -S` and passes every option through, so `./run-checks.sh -r ~ -q` is the first run above. The release download has no `run-checks.sh`, so start a downloaded archive with the `python3 -I -S` line.
- **Checking the download:** the `.sha256` file checks the archive. [Inspecting and rebuilding the archive](#inspecting-and-rebuilding-the-archive) shows how to list what is inside and how to rebuild it byte for byte.

## Usage

### Reading the results

**Each output line reads `LEVEL subject [location] detail`, and the `FAIL` lines are the things to fix.** The last line is `SUMMARY pass=N fail=N warn=N info=N skip=N error=N`.

Two lines from the test suite show the shape. They come from the certifi 2026.7.22 and 2026.10.18 wheels, checked against their SHA-256, cases `tests/expect/d1-certifi-old-version.txt` and `d1-certifi-fixed-version.txt`:

```text
FAIL  certifi [/tmp/d/certifi-2026.7.22.dist-info] found 2026.7.22, fixed 2026.10.18 (vendors its own CA bundle)
PASS  certifi [/tmp/d/certifi-2026.10.18.dist-info] found 2026.10.18, fixed 2026.10.18
```

The six levels:

- `FAIL`: something to fix. One of these:
  - A bundle, keystore or binary holds one of the three eMudhra G3 root certificates (`emSign ECC Root CA - G3`, `emSign Root TLS CA - G3` or `emSign Root CS CA - G3`), as a self-signed certificate or as the cross-certificate `emSign ECC Root CA - G3` issued to the TLS or CS root.
  - It holds one of the 16 compromised intermediates.
  - A release is older than its fix.
- `WARN`: needs a manual look, such as a store that holds `AAA Certificate Services`.
- `INFO`: context, such as a compromised key on a blocklist or a certificate marked as rejected.
- `PASS`: fixed, or no compromised certificate found.
- `ERROR`: a check failed to run, and the run carried on without it.
- `SKIP`: an image with no shell, not inspected.

**Why `AAA Certificate Services` is `WARN`:** Sectigo cross-signed all eight compromised intermediates under its `AAA Certificate Services` root, and the copies reuse the same weak keys. A store that has dropped `emSign ECC Root CA - G3` but still holds `AAA Certificate Services` can still trust a forged chain through those copies. Each card on the Affected software page has an AAA root line.

[Details in a line](docs/how-it-works.md#details-in-a-line) says what the text at the end of a line means, and [How a finding is judged](docs/how-it-works.md#how-a-finding-is-judged) says which findings are `INFO` instead of `FAIL`.

**Verifying a finding:** the [proof page](https://fieldse.github.io/emudhra-ca-compromise-check/proof.html) shows how to check a finding against the original sources with a shell, `openssl`, `curl` and a browser, without trusting the check.

Exit codes:

- `0`: no `FAIL`, even with `WARN` or `ERROR` lines.
- `1`: any `FAIL`, or any `WARN` or `ERROR` with `--strict`.
- `2`: usage or environment error.

**`--strict` for CI:** a CI gate that must also catch warnings and checks that failed to run needs `--strict`. A stock Mac fails `--strict` on the `AAA Certificate Services` line for `/etc/ssl/cert.pem` until Apple updates that file. Apple has said only that a future macOS update will fix it.

### What it scans by default

**With no `-r`, the check scans `$HOME`.** It also reads the OS CA bundle files at their standard paths, and the `cacerts` of each Java home it finds through `JAVA_HOME`, the `java` on `PATH`, and `java_home` on macOS.

- **On macOS, with or without `-r`,** it always adds:
  - `/Applications`
  - `~/Applications`
  - Homebrew's `etc` and `Caskroom`, when `brew` is on `PATH` in a directory beside a `Cellar`
- **Program directories** it always reads:
  - `GOBIN` and each `GOPATH/bin`
  - `~/.cargo/bin`
  - `~/.local/bin`
  - `/usr/local/bin`
  - Homebrew's `bin`

### Options

`--help` prints every option. The ones below cover most runs:

| Option | What it does |
|---|---|
| `-r`, `--root ROOT` | Directory to scan for CA bundles, keystores, binaries and package files. Repeatable. Default `$HOME` |
| `-x`, `--exclude DIR` | Never enter this directory. Repeatable |
| `-c`, `--containers` | Also check every local container image through `podman`, with networking off |
| `-i`, `--image IMAGE` | Check only this local image. Repeatable, implies `-c` |
| `-q`, `--quiet` | Print only `FAIL`, `WARN` and `ERROR` lines plus the summary |
| `-s`, `--strict` | Exit 1 on `WARN` and `ERROR` as well as `FAIL` |

### Excluding a directory (`-x`)

**`-x` matches a directory by its identity on disk,** so letter case, symlinks and glob characters in the path don't change what it excludes.

- A tool in an excluded directory is skipped and not run.
- If a subdirectory of an excluded directory is bind-mounted at another path inside a scanned directory, the check scans it at that path unless the mount point is excluded too.

### Commands it runs

**The check runs the programs below and nothing else.** Every other binary it finds while scanning is read as data.

- **Runtimes from `PATH`:** `node`, `bun`, `deno`, `go`, `python3`, `uv` and `perl`, to read their versions (`--version`, or `go version`).
  - `node -p process.execPath` names the binary the check then reads.
  - `python3 -I -S -c` runs a short script that reads certifi and pip from package metadata.
  - `perl -MMozilla::CA -e` prints the module's version and the bundle path it hands out.
- **Package managers from `PATH`,** to read the installed `ca-certificates` package: `dpkg-query -W`, `apk info -v`, `rpm -q` (with `rpm -q --changelog ca-certificates` for the CVE, or `ca-certificates-mozilla` on SUSE) and `pacman -Q`.
- **`podman` from `PATH`,** with `-c` or `-i`, which starts a probe in each image with `--network=none`.
- **Three macOS tools by absolute path:** `/usr/bin/security`, `/usr/bin/xcode-select` and `/usr/libexec/java_home`.

### Running as root

**If the check runs as root, it refuses to run a `PATH` tool that a non-root user could change.** [Running as root](docs/how-it-works.md#running-as-root) in How the check works gives the test and what the check does instead.

If you don't trust a machine's `PATH` tools, scan from a clean account or pass `-x` for their directories to keep them out of the run.

## What it checks

**The check looks for the compromised certificates and for versions below their fix, in 27 items that run in a fixed order.** The table below lists them in that order, which is also the order of the output lines.

- **What it looks for:** the 16 compromised intermediates, the three eMudhra G3 roots and their two cross-certificates, and `AAA Certificate Services`, in trust stores, CA bundles, Java keystores, binaries and container images. It also looks for installed or pinned software older than the release that fixed it.
- **How it matches a certificate:** by SHA-256 fingerprint, by the certificate's raw DER bytes, by the first base64 line of its PEM text, or by the public key alone.
- **More detail:** [Where it looks](docs/how-it-works.md#where-it-looks) and [How a finding is judged](docs/how-it-works.md#how-a-finding-is-judged) in How the check works, and every rule with its condition, level and sources on the [Checker rules page](https://fieldse.github.io/emudhra-ca-compromise-check/detections.html).

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
| 9 | Electron apps, as macOS bundles and Linux app directories, by their Electron version (see [Electron versions](docs/how-it-works.md#electron-versions)) |
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
| 27 | Local container images through `podman`, one at a time, with `-c` or `-i` |

The rules live in `rules/detection-rules.csv`, and `tools/build_detections.py` builds the Checker rules page (`detections.html`) from that file.

## Limitations

**[How the check works](docs/how-it-works.md#what-it-does-not-cover-yet) lists what the check doesn't cover yet.** Three limits apply to how it reads:

- A file above 32 MiB is read through `mmap`, so if another process truncates it during the read, the run ends with `SIGBUS`.
- Run as root, the check decides whether a tool is safe to run from its owner and mode bits only, so it misses an ACL that lets a non-root user change the tool or a directory above it.
- Under a scan root, it reads a program only from a `bin` or `sbin` directory outside `node_modules`, an app's `Contents/MacOS`, or a path where an app ships its own Node. A Go or Rust binary in another folder, such as `go-bin/`, is skipped even when `-r` names that folder.

## Tests and reproducible build

**The test suite runs the check against real CA bundles, JDK keystores and test binaries from before and after each fix.** Each test case runs in a container with networking off, under Python 3.13 and Python 3.9.

- The suite needs the network only to build and pull its images and download certifi.
- It uses `docker` if it responds, else `podman`. Its `-e` option picks one.

```bash
git clone https://github.com/fieldse/emudhra-ca-compromise-check.git
cd emudhra-ca-compromise-check
tests/run-tests.sh
```

### Expected output

The lines below are from the suite's expected output.

**JDK cacerts:** the `cacerts` of `eclipse-temurin:21.0.8_9-jre`, released before the fix, and `eclipse-temurin:21.0.13_9-jre`, released after it. Case `tests/expect/a4-keystores.txt`.

```text
FAIL  java keystore [/out/java/jdk-old/cacerts] contains emSign ECC Root CA - G3 (removed root)
PASS  java keystore [/out/java/jdk-fixed/cacerts] contains no compromised eMudhra certificate
```

**Debian ca-certificates:** the first two lines are recorded output from checking a Debian 12 image with `ca-certificates` 20230311+deb12u1, in `tests/unit/test_containers.py`. The third is the Debian 13 test image with 20250419+deb13u1, case `tests/expect/a1-os-trust-store.txt`.

```text
FAIL  ca-certificates [image:localhost/x:1] found 20230311+deb12u1
FAIL  ca-bundle [image:localhost/x:1 /etc/ssl/certs/ca-certificates.crt] contains emSign ECC Root CA - G3 (removed root)
PASS  ca-certificates [host] found 20250419+deb13u1, fixed 20250419+deb13u1
```

### Inspecting and rebuilding the archive

**The `.sha256` file checks the download, and the archive rebuilds to the same bytes under Python 3.9 and Python 3.13.** To see what is inside the archive before running it:

```bash
unzip -l vuln-check-emudhra-ca-compromise.pyz
unzip -p vuln-check-emudhra-ca-compromise.pyz emudhra_check/cli.py | less
```

`tools/build_pyz.py` gives the same bytes under both Python versions, and the test suite compares the committed archive with fresh builds under both. To rebuild it, run the build at the release tag in a container of the test suite's Python 3.9 image and compare:

```bash
git clone https://github.com/fieldse/emudhra-ca-compromise-check.git
cd emudhra-ca-compromise-check && git checkout v2.1.0 && mkdir -p rebuild
docker run --rm --network=none -v "$PWD":/repo:ro -v "$PWD/rebuild":/out \
  docker.io/library/python@sha256:2d97f6910b16bd338d3060f261f53f144965f755599aab1acda1e13cf1731b1b \
  python3 -I /repo/tools/build_pyz.py --out /out/check.pyz
cmp rebuild/check.pyz scripts/vuln-check-emudhra-ca-compromise.pyz && echo identical
```

The image digest above is `python:3.9-slim` (Python 3.9.25). The Python 3.13 build runs in the test image from `tests/Containerfile`: Debian trixie at `docker.io/library/debian@sha256:4c25275446ca371766b8b093c696782eabce06263fccacb8d5d813b3dc44b308` with Debian's `python3` (3.13.5).

## Repository layout

| Path | Holds |
|---|---|
| `index.html`, `incident.html`, `fixes.html`, `checks.html`, `proof.html`, `references.html`, `detections.html` | The guide, the incident page, the fixes page, the Affected software page, the proof page, the references page and the Checker rules page |
| `docs/how-it-works.md`, `docs/weak-rules.md`, `docs/sources.md` | How the check works, the weak and unverifiable rules, and the original sources behind the references page |
| `PROOF.md` | A pointer to the proof page and its source |
| `rules/detection-rules.csv` | The rule register: every rule the check applies, with its code line, sources and verification status |
| `scripts/vuln-check-emudhra-ca-compromise.pyz` | The read-only check, a Python zipapp, with its `.sha256` file |
| `run-checks.sh` | Runs the check from a clone under `python3 -I -S`, passing every option through |
| `emudhra_check/` | The check's source, which the zipapp holds |
| `tools/build_pyz.py`, `tools/pyz_main.py` | The reproducible archive build and the archive's entry point |
| `tools/build_detections.py` | Builds `detections.html` and `docs/weak-rules.md` from the rule register |
| `rules/references.csv`, `rules/sources.csv`, `tools/build_references.py` | Every claim with its sources, and the tool that builds `references.html` and `docs/sources.md` from them |
| `site/`, `tools/build_pages.py` | The Markdown sources, stylesheet and template of the guide, incident, fixes, Affected software and proof pages, and the tool that builds their HTML from them |
| `rules/iocs.csv`, `rules/certs/` | The 16 compromised certificates, the three G3 roots and their two cross-certificates, and AAA Certificate Services, with fingerprints |
| `rules/yara/`, `rules/sigma/` | A YARA rule for the certificates in files, and a Sigma rule for a G3 certificate added to a trusted store |
| `tests/` | Unit tests and container tests for the check, the archive and the rules |
| `LICENSE` | The MIT license |

## Sources

**Every claim in the guide and the Affected software page, including each fixed version, comes from a vendor, project or tracker document.** The [references page](https://fieldse.github.io/emudhra-ca-compromise-check/references.html) lists each claim, R001 to R358, with its sources and the date each was checked. [docs/sources.md](docs/sources.md) lists the original source behind each numbered claim.

## Contribution

**A wrong rule or an improvement goes in an [issue](https://github.com/fieldse/emudhra-ca-compromise-check/issues).** [Reporting mistakes](https://fieldse.github.io/emudhra-ca-compromise-check/proof.html#reporting) on the proof page says what a report needs. For anything else, contact me on [LinkedIn](https://www.linkedin.com/in/mattfields-dev/).

If you find this useful, please let me know.

## License

[MIT](LICENSE)
