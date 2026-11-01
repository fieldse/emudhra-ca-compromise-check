# eMudhra G3 CA compromise check

This repository checks whether your stack still trusts the compromised eMudhra G3 certificates. Eight eMudhra G3 intermediate CAs have private keys small enough for anyone to compute, so anyone can issue certificates under them. Sectigo cross-signed all eight under its `AAA Certificate Services` root with the same keys. Browsers on default settings block the chains through pushed revocation data, apart from a startup gap in new Firefox ESR 115 profiles and forks that drop OneCRL, such as GNU IceCat built from ESR 153.5.1. Everything that carries its own trust store needs its own update: OS `ca-certificates` packages, JDK `cacerts`, Python, Node.js, Bun and Deno, Go, Rust, PHP, Ruby, Perl and Elixir packages, Electron apps, developer tools and container images.

To check by hand, [read the guide](https://fieldse.github.io/emudhra-ca-compromise-check/) for what happened and what to fix first. The [checks page](https://fieldse.github.io/emudhra-ca-compromise-check/checks.html) gives a read-only command and the fixed version for each item. The [references page](https://fieldse.github.io/emudhra-ca-compromise-check/references.html) gives the sources for every claim. To check automatically, run the read-only script in [Quick start](#quick-start).

## Contents

- [Quick start](#quick-start)
- [What the script checks](#what-the-script-checks)
- [The AAA cross-sign path](#the-aaa-cross-sign-path)
- [Repository layout](#repository-layout)

## Quick start

```bash
git clone https://github.com/fieldse/emudhra-ca-compromise-check.git
cd emudhra-ca-compromise-check
./scripts/vuln-check-emudhra-ca-compromise.sh -r ~/src -r /srv -q      # scan two trees, print problems only
./scripts/vuln-check-emudhra-ca-compromise.sh --root=/opt --containers  # also probe local Podman images
./scripts/vuln-check-emudhra-ca-compromise.sh --help                    # all options
```

With no `-r`, the script scans `$HOME`. It always reads the OS bundle files and the host JDK's `cacerts`. `-c` probes every local Podman image with networking off, and `-i IMAGE` probes one.

`FAIL` means a bundle, keystore or binary still holds `emSign ECC Root CA - G3` or a compromised certificate, or a release is older than its fix. `WARN` needs manual review. The script exits 0 when nothing fails, 1 on any `FAIL` (or any `WARN` with `--strict`) and 2 on a usage or environment error, so it can gate CI.

## What the script checks

- Certificates inside CA bundles, Java keystores and Node.js binaries, matched on a slice of each certificate's public key so bundles without comments are covered.
- OS `ca-certificates` packages, through dpkg, apk, rpm and pacman.
- The Node.js (including nvm, volta, asdf and fnm installs), Bun, Deno and Go runtimes.
- Language packages: certifi, pip and uv, Electron in `package.json`, Go toolchain pins and binaries, Rust `webpki-roots`, `webpki-root-certs` and `rustls-webpki`, `composer/ca-bundle`, `excon`, `castore`, Hex `certifi` and Perl `Mozilla::CA`.
- Container images, when you opt in with `-c` or `-i`.

It reports `AAA Certificate Services` as `INFO` only, and it doesn't read installed app bundles (Electron apps, browsers, JetBrains IDEs). It treats Electron 44.9.1 as fixed, as Electron's advisory does. Every fixed Electron release checked still carries the G3 root, because the fix blocks the intermediates and leaves the root in place. The [guide](https://fieldse.github.io/emudhra-ca-compromise-check/#helper) lists every gap.

## The AAA cross-sign path

Sectigo's cross-signed copies of the compromised intermediates reuse the same weak keys. A store that has dropped `emSign ECC Root CA - G3` but still holds `AAA Certificate Services` can still trust a forged chain through those copies. The checks page has an AAA column for every item.

## Repository layout

| Path | Holds |
|---|---|
| `index.html`, `checks.html`, `references.html` | The guide, the checks table and the claim references |
| `scripts/vuln-check-emudhra-ca-compromise.sh` | The read-only check script |
| `rules/iocs.csv`, `rules/certs/` | The 16 compromised certificates and the G3 roots, with fingerprints |
| `rules/yara/`, `rules/sigma/` | A YARA rule for the certificates in files, and a Sigma rule for a G3 certificate added to a trusted store |
| `tests/` | Container tests for the script |
