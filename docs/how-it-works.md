# How the check works

This page explains why a `FAIL` or `WARN` line from the check got that level.

## How a finding is judged

**A finding is a certificate match or a version below its fix. Each finding gets a level of `FAIL`, `WARN` or `INFO`, and the check also reports `PASS`, `ERROR` and `SKIP`.** [Reading the results](../README.md#reading-the-results) in the README says what each one means.

These lines come from the test suite's expected output, cases `tests/expect/a4-keystores.txt`, `e4-electron-apps.txt` and `e6-updater-caches.txt`:

```text
FAIL  java keystore [/out/java/jdk-old/cacerts] contains emSign ECC Root CA - G3 (removed root)
FAIL  java keystore [/out/java/jks/cacerts] contains EM DV TLS CA - G3B (compromised key)
INFO  electron app [/tmp/apps/Old.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework] also bundles emSign ECC Root CA - G3 (confirms the version FAIL)
WARN  electron update cache [/tmp/home/Library/Caches/com.example.app.ShipIt/update.x/Old.app] found 43.8.0, fixed 43.8.1 (stale updater cache, delete the directory)
```

### Details in a line

**The detail at the end of a line names what matched or why the line got its level.** The rule IDs are rows in the rule register, [`rules/detection-rules.csv`](../rules/detection-rules.csv).

| Detail in the line | What it means | Rules |
|---|---|---|
| `(removed root)` | The match is `emSign ECC Root CA - G3`, as a full certificate, or as a bare key read `as a trust anchor` | CERT-17, CERT-22, CERT-23, RT-NODE-07 |
| `(compromised key)` | The match is one of the 16 compromised intermediates | CERT-01 to CERT-16, CERT-21 |
| `(compromised key) as a blocklist entry, not a certificate` | A compromised intermediate's public key alone, as some fixes ship it to block the key. `INFO` | CERT-24 |
| `(issuer of the compromised TLS CAs)`, `(issuer of the compromised code-signing CAs)` | The match is `emSign Root TLS CA - G3` or `emSign Root CS CA - G3`, self-signed or as a cross-certificate from `emSign ECC Root CA - G3` | CERT-18, CERT-19, CERT-22, CERT-34, CERT-35 |
| `as a rejected entry, not trusted` | An OpenSSL `TRUSTED CERTIFICATE` entry that rejects every use the certificate serves. `INFO` | CERT-26 |
| `AAA Certificate Services (issued cross-signed copies of all eight compromised intermediates, …)` | The Sectigo root above the cross-signs. `WARN` | CERT-20, CERT-25 |
| `(confirms the version FAIL)` | A Node binary or Electron app whose version already fails also holds `emSign ECC Root CA - G3`. The root line is `INFO` | RT-NODE-08, EL-09 |
| `(vendors its own CA bundle)` | certifi, pip or uv below its fix | PY-CERTIFI-01, PY-PIP-01, PY-UV-01 |
| `(update the app)` | An Electron app below its branch's fix | EL-01 to EL-05 |
| `(stale updater cache, delete the directory)` | An Electron app below its fix in a ShipIt updater cache. `WARN` | EL-12 |
| `(built with an affected toolchain, rebuild)` | A Go binary built with a toolchain below its fix | RT-GO-06 |
| `(crypto/x509 Verify not found, the program may never verify certificates)` | The same Go binary without the function name `crypto/x509.(*Certificate).Verify`. `WARN` | RT-GO-13 |

Two other parts of a line:

- **rpm versions:** rpm package lines print the full VERSION-RELEASE as `rpm -q` shows it, for example `found 2025.2.80_v9.0.304-6.fc44, fixed 2026.2.92_v9.0.319-2`.
- **PEM file count:** the `checked N PEM files` count includes linked files, so `/etc/ssl/certs` counts each certificate a link points to.

### Certificates

#### The 22 certificates

**The check looks for 22 certificates, listed with their fingerprints in [`rules/iocs.csv`](../rules/iocs.csv).**

- An intermediate CA is a certificate authority that a root vouches for and that signs other certificates.
- A cross-sign is a second certificate for the same CA and key, issued by a different root.

The 22 are:

- the 16 compromised intermediates: eight issued by eMudhra and eight Sectigo cross-signs of the same keys
- the three G3 roots: `emSign ECC Root CA - G3`, `emSign Root TLS CA - G3` and `emSign Root CS CA - G3`
- the two cross-certificates `emSign ECC Root CA - G3` issued to the TLS and CS roots
- `AAA Certificate Services`, the Sectigo root that issued the cross-signs

The [incident page](../incident.html) says how the weak keys came about, what an attacker can do with them, and how clients reach the intermediates through these roots.

#### Four ways to match

**The check finds a certificate in a bundle, keystore or binary in four ways.**

1. **SHA-256 fingerprint:** the SHA-256 hash of each decoded PEM certificate. The fingerprint names one certificate exactly.
2. **DER bytes:** the certificate's raw binary form anywhere in the file, as keystores and binaries store it.
3. **First base64 line:** the first 64 characters of the certificate's PEM text, for a PEM certificate embedded in a binary.
4. **Public key:** the key alone, when no full certificate matched. Some programs store a root as a bare key.

#### Levels for a match

**A full compromised intermediate, G3 root or G3 cross-certificate is `FAIL`, apart from two exceptions, and so is a G3 root's key alone. Every other match is `WARN` or `INFO`.**

- **Full certificate:** a compromised intermediate, a G3 root or a G3 cross-certificate is `FAIL`, with two exceptions for `emSign ECC Root CA - G3` below.
- **G3 root key alone:** a G3 root's public key alone is `FAIL`, read as a trust anchor.
  - A trust anchor is a key a program trusts without checking any certificate above it.
- **Intermediate key alone:** a compromised intermediate's public key alone is `INFO`, read as a blocklist entry.
  - Some fixes ship the eight raw keys as a blocklist, such as rustls-webpki 0.103.16, which Deno 2.9.8 uses.
  - Go and composer/ca-bundle block the same keys by their SHA-256 hashes.
- **`AAA Certificate Services`:** `WARN`.
- **Rejected entry:** an OpenSSL `TRUSTED CERTIFICATE` entry whose reject list holds `anyExtendedKeyUsage`, or every use the certificate serves, is `INFO`, because OpenSSL then rejects it.
  - The uses are `serverAuth` for the TLS roots and intermediates, `codeSigning` for the code-signing ones, and both for emSign ECC Root CA - G3 and AAA.
  - An entry that rejects only other uses, such as `emailProtection`, is still trusted for TLS and stays `FAIL`.

#### Why the removed root counts

**A store that still holds the removed root can trust a chain through the compromised intermediates, so the check reports that root as `FAIL`,** apart from the two exceptions below.

- **Mozilla:** removed `emSign ECC Root CA - G3` in NSS 3.131.1.
- **Linux distributions:** most fixed their `ca-certificates` package by removing it too.
- **Why the root was removed:** Red Hat says not every client that uses the system CA store can distrust only specific intermediates.

[`references.html`](../references.html) gives the source for each of these claims. The [proof page](https://fieldse.github.io/emudhra-ca-compromise-check/proof.html) Flow B checks the weak key and the root's removal step by step.

#### Two exceptions for the removed root

**Both exceptions cover a full `emSign ECC Root CA - G3`.**

- **Electron apps:** in an Electron app's binary the root is always `INFO`.
  - Electron's fix blocks the compromised keys and leaves the root list alone, so the check judges the app by its version.
- **Node binaries:** in a Node binary whose version already fails, the root is `INFO`, with the detail "confirms the version FAIL".

### Versions

#### Where a version comes from

**The check reads a version from one of these sources.**

- the tool's own version output, or package metadata
- a lockfile or manifest
- a directory name: a `dist-info` directory, a Homebrew `Cellar` directory, or a Node version-manager directory
- the release URL inside a Node binary
- a Go program's build information, or the crate paths a Rust program embeds
- the `Info.plist` of a macOS Electron framework, or the `Electron/N.N.N` string in a Linux Electron executable

#### How a version is compared

**The check compares each version with the first fixed release on its own branch.**

- For example, Go 1.26 and Go 1.27 each have their own fix.

#### Levels below a fix

**A version below its fix is `FAIL` for most software.** Some rules give a lower level, for example:

- CPython below its fix is `WARN`.
- An Electron range in `package.json` that starts below the fix, and an Electron app in a ShipIt updater cache, are `WARN`. [Electron versions](#electron-versions) gives the reasons.
- rustls-webpki below its fix in a Rust binary that holds no affected root is `WARN`.
- A Go binary built with a toolchain below the fix is `WARN` when it does not hold the function name `crypto/x509.(*Certificate).Verify`, because it may never verify a certificate. An obfuscated build can hide the name, so the check does not report it as `PASS`.
- A `go.mod` toolchain line below the fix is `INFO`, because it sets a minimum and pins nothing.
- A certifi or pip whose `core.py` carries Debian's patch, which makes `where()` return the system store, is `INFO`. Debian and Ubuntu packages patch it this way, and some still ship the upstream `cacert.pem` beside it. That unused file is judged by its content. A package with no `cacert.pem` and no Debian patch is judged by its version.

A Debian or Ubuntu `ca-certificates` build that matches no known fixed build and is not dated after the fix is `FAIL`.

#### Electron versions

**Electron's advisory gives the first fixed release on each branch: 42.11.16, 43.8.1, 44.9.1 and 45.0.0-beta.6.**

- An installed Electron below its branch's fix is `FAIL`.
- An Electron on a branch older than 42, which has no fix, is `FAIL`.
- An exact version in `package.json` below its branch's fix (`"43.8.0"` or `"=43.8.0"`) is `FAIL`, because it can install only that version.
- A range (`^`, `~`, `N.x`) that starts below the fix is `WARN`, because it may resolve to a fixed release.
- An Electron app below its fix in a ShipIt updater cache is `WARN`, because the app does not run from there.
- The line for an Electron version declared in `package.json` names the file's path, and its detail starts with `pins V` for an exact spec or `range starts at V` for a range.

Every fixed Electron release checked still lists `emSign ECC Root CA - G3` in its bundled Node.js roots, because the fix blocks the compromised keys and leaves the root list alone. On a fixed app the check reports that root as `INFO`.

#### Versions it cannot compare

**A version the check cannot compare is usually `WARN`, for a manual look.** A version-manager directory whose name is not a version is skipped.

#### Where the rules live

**The fixed versions live in `emudhra_check/fixes.py`. Each rule has a row in the rule register, [`rules/detection-rules.csv`](../rules/detection-rules.csv).**

- **Register row:** each row names the rule's condition, level and code line.
- **Fact rules:** a fact rule states something an outside source can confirm. Its row also lists its sources.
- **Decision rules:** a decision rule is a design choice, such as the level a finding gets. Its row names its basis and may have no source.

[Weak and unverifiable rules](weak-rules.md) lists each rule that rests on a weak source or none, and says why.

## Where it looks

**The check reads six kinds of source: trust stores and CA bundles, Java keystores, binaries and apps, runtimes and packages, lockfiles and manifests, and container images.** The README's [What it checks](../README.md#what-it-checks) lists all 27 checks in the order they run.

| Ecosystem | What the check reads |
|---|---|
| Trust stores and CA bundles | OS, Homebrew and Perl CA bundles, and the PEM bundles in the scanned directories. [Details below](#trust-stores-and-ca-bundles) |
| Java keystores | The `cacerts` of each Java home it finds, and every `cacerts` file in the scanned directories. It reads JKS, JCEKS and PKCS12 itself, without `keytool` |
| Binaries and apps | Go and Rust programs, Electron apps, and the Node binaries that apps ship. Each is read as data, scanned for embedded certificates and keys, and judged by the Go toolchain, Rust crate, Electron or Node version it records |
| Runtimes and packages | `node`, `bun`, `deno`, `go`, `python3` and `uv` on `PATH`, Node installs from version managers, and installed certifi, pip and uv packages. The Bun, Deno, Node and uv binaries are also scanned for embedded roots |
| Lockfiles and manifests | Rust, Python, PHP, Ruby, Elixir and Electron versions pinned in lockfiles and manifests, and Go toolchain lines. [Details below](#lockfiles-and-manifests) |
| Containers | Local container images, with `-c` or `-i`. A probe runs inside each image with networking off and reports its runtimes, Python packages, `ca-certificates` package, CA bundles and Java keystores |

Under a scan root, a program is read only from a `bin` or `sbin` directory outside `node_modules`, an app's `Contents/MacOS`, or a path where an app ships its own Node. [What it does not cover yet](#what-it-does-not-cover-yet) lists the programs this misses.

### Trust stores and CA bundles

- The OS CA bundle files at their standard paths
- The installed OS `ca-certificates` package
- Homebrew's bundles and its `ca-certificates` formula
- Perl `Mozilla::CA`
- The PEM bundles in the scanned directories, including the ones packages carry

A file counts as a bundle when it is named `cacert*` or ends in `.pem`, `.crt`, `.cer` or `.bundle`, and holds at least one PEM block.

### Lockfiles and manifests

- **Rust:** crates in `Cargo.lock`
- **Python:** certifi pins in requirements files, `poetry.lock`, `uv.lock` and `Pipfile.lock`. In `Pipfile.lock` it reads the `default` and `develop` sections, not custom categories
- **PHP, Ruby and Elixir:** packages in `composer.lock`, `Gemfile.lock` and `mix.lock`
- **Electron:** versions in `package.json`
- **Go:** toolchain lines in `go.mod`

## What it does not do

**The check reads files and changes nothing. Its own code opens no network connection, and it runs only a fixed list of tools.**

### Limits on what it touches

- **System changes:** it reads files and changes nothing on the system.
- **Network:** the check's own code opens no network connection.
  - The tools it starts run with `GOTOOLCHAIN=local`, so `go` does not fetch a toolchain.
  - It probes images with networking off and never pulls an image.
- **Traffic:** it does not inspect TLS connections or the certificates a server presents.
  - It finds trust in files only.
- **Programs it runs:** it runs only a fixed list of tools, which the README's [Commands it runs](../README.md#commands-it-runs) lists. Every other binary is read as data.
  - **Runtimes on `PATH`:** to read their versions and where their binary or CA bundle lives.
  - **Package managers:** to read the `ca-certificates` package and, through rpm, its changelog.
  - **A container tool,** with `-c` or `-i`: to probe images.
    - Inside each image, with networking off, the probe runs the image's own runtimes (`node`, `bun`, `deno`, `go`, `python3`), its package tool (`dpkg-query`, `apk`, `rpm` or `pacman`), and `od` and `find`.
  - **Three macOS system tools:** to read the system roots keychain, the developer tools path and the Java homes.

### Running as root

**If the check runs as root, it refuses to run a `PATH` tool that a non-root user could change.** A tool counts as changeable when its file, or any directory above it, is group- or world-writable or is not owned by root.

- A sticky directory such as `/nix/store` counts as safe when the entries below it are owned by root.
- For a refused tool it prints `WARN  TOOL [host] not run: TOOL is writable by a non-root user`.
- It still reads that tool's binary for the compromised certificates.
- For `node`, it takes the version from the binary instead of running it.
- With `-c`, a `podman` that fails this test stops the run with exit 2.

### What it does not cover yet

**The check does not cover these yet, so check them by hand.**

- **Electron apps on Windows:** It reads macOS and Linux app layouts only. Fixed Electron binaries still contain the G3 root, because the fix blocks the intermediates and leaves the root in place. So it judges apps by their Electron version.
- **Other apps:** It has no version check for Firefox ESR 115, LibreOffice, Godot, Docker Desktop or Git for Windows. Bundles and keystores inside them are read only when they sit under a scan root.
- **Paths outside the scan roots:** Add those directories with `-r`. It misses JDKs that are not `JAVA_HOME`, the `java` on `PATH` or (on macOS) listed by `java_home`, Debian’s `/etc/ssl/certs/java/cacerts` when no JDK it reads links to it, and Go and Rust binaries outside the directories above.
- **Programs in other folders:** Under a scan root it reads Go and Rust binaries in `bin`, `sbin` and `Contents/MacOS` directories, and skips them in a folder such as `go-bin`, even when `-r` names that folder.
- **Some OS bundles:** It doesn’t read the Red Hat-family code-signing and email bundles.
- **Packages without a version check:** Composer itself, Ruby `httpclient`, Go’s `x/crypto/x509roots/fallback` in `go.mod` (it is checked inside Go binaries), conda, Pixi, uv-managed Python, CPython’s bundled pip, Dart and Flutter.
- **Platform stores:** The macOS system keychain (reported as notes only), Windows trust lists, iOS, Android and Bottlerocket.
- **Inside images:** The image probe doesn’t read Go or Rust binaries, Electron apps or lock files.

## The YARA rule

The repository also ships `rules/yara/emudhra-ca.yar`, which matches the G3 root and the compromised intermediates in any file, and `rules/iocs.csv` with 22 certificates: the 16 compromised intermediates, the G3 roots and the AAA Certificate Services root. A hit for the compromised intermediates inside Deno 2.9.8 or later likely comes from Deno’s own distrust list, so judge Deno by its version.

## Further reading

- [`incident.html`](../incident.html): what happened, why the certificates are dangerous and who is exposed.
- [Proof page](https://fieldse.github.io/emudhra-ca-compromise-check/proof.html): how to verify a finding from the original sources, step by step.
- [Checker rules](../detections.html): every rule the check applies, with its condition, level and sources.
- [`references.html`](../references.html): the sources for every claim, by R-number.
