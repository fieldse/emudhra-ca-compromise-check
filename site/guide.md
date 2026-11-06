---
title: eMudhra G3 CA compromise check
description: How to check whether your stack still trusts the compromised eMudhra G3 certificates, with a read-only checker, one check command per stack and the fixed versions.
output: index.html
refs: none
---

<header class="band">
  <div class="wrap">
    <p class="tags"><span>eMudhra G3</span><span>CA key compromise</span><span>October 2026</span></p>
    <p class="ids">Guide &nbsp;·&nbsp; <a href="incident.html">Incident</a> &nbsp;·&nbsp; <a href="checks.html">Affected software</a> &nbsp;·&nbsp; <a href="fixes.html">Fixes</a> &nbsp;·&nbsp; <a href="detections.html">Checker rules</a> &nbsp;·&nbsp; <a href="proof.html">Proof</a> &nbsp;·&nbsp; <a href="references.html">References</a></p>
    <h1><span class='hl'>eMudhra G3</span> CA compromise<br>Are you affected?</h1>
    <p>Eight eMudhra G3 intermediate certificate authorities (CAs) have private keys anyone can compute&nbsp;<span class="rl">[<a href="references.html#r001">R001</a>, <a href="references.html#r002">R002</a>]</span>. With them, anyone can issue a certificate for any website&nbsp;<span class="rl">[<a href="references.html#r004">R004</a>]</span>. OS packages, runtimes, JDKs, apps and container images carry their own trust stores, the lists of certificates they trust, so each needs its own update&nbsp;<span class="rl">[<a href="references.html#r038">R038</a>, <a href="references.html#r039">R039</a>]</span>. <a href="#helper">Jump to the checker</a>.</p>
  </div>
</header>

::: {tag=main .wrap}

<nav class="toc read" aria-label="Contents"><h2>Contents</h2><ol>
  <li><a href="#tldr">TL;DR</a><span>Who is affected and where to start</span></li>
  <li><a href="#vuln">The vulnerability</a><span>The weak keys and what an attacker can do</span></li>
  <li><a href="#manual">Manual checks</a><span>Check each stack by hand, with affected and fixed versions</span></li>
  <li><a href="#helper">Automated checker</a><span>A read-only check that runs in one pass</span></li>
  <li><a href="#proof">Verifying a finding</a><span>Check any finding yourself from the original sources</span></li>
  <li><a href="#resources">Documentation</a><span>How it works, its rules and its sources</span></li>
  <li><a href="#help">Need help?</a><span>Help from Blacklight Security</span></li>
  <li><a href="#sources">References</a><span>The sources behind this page, grouped by publisher</span></li>
</ol></nav>

## TL;DR {#tldr}

{: .key}
**Update every OS package, runtime, JDK, app and container image that still trusts the compromised certificates.**

{: .read}
An updated OS doesn’t fix the others. The usual misses are pip and certifi in each Python venv, Node.js, JDKs, Electron apps, the macOS command-line tools and container images [R038, R039].

Either of these finds them:

{: .notes}
- The [manual checks](#manual) give a check command and the fixed version for each stack.
- The [checker](#helper) scans your machine in one read-only pass and reports what still trusts the compromised certificates or sits below its fix.

{: .read}
If a store can’t be updated today, its card on the [fixes page](fixes.html#caveats) gives a stopgap under Until a fix ships.

## The vulnerability {#vuln}

{: .key}
**In October 2026 the certificate authority eMudhra was found to have made eight of its intermediate CAs with private keys anyone can calculate. Anyone can now forge a certificate for any website, and any software not yet updated to distrust those CAs will accept it [R001, R004].**

{: .intro}
The problem
: - A certificate authority (CA) signs the certificates that prove a website or program is genuine. Clients trust whatever a trusted CA signs.
  - Eight eMudhra G3 intermediate CAs have private keys below 256, so anyone can work them out from the public certificates [R001].
  - Clients trust the eight through three eMudhra G3 root CAs, including emSign ECC Root CA - G3 [R001, R005].
  - Sectigo also gave each of the eight a second certificate, a cross-sign, under its AAA Certificate Services root with the same key. That makes 16 affected certificates [R002].

Impact
: - Anyone can also make malware look signed by a trusted publisher on Windows [R004].

{: .muted .read}
The [incident page](incident.html) has the cause, the downstream impact, who is exposed and a timeline.

## Manual checks {#manual}

{: .key}
**Check each stack you run by hand, if you’d rather not run the [checker](#helper) or want to confirm what it found.**

{: .read}
Most stacks keep their own trust store, so updating one leaves the others as they were. A fixed OS store doesn’t fix Node.js, pip, a JDK or an Electron app, and a container trusts only the bundle inside its image [R038, R039]. Run the checks on every host and inside every image you ship.

Each stack below has up to two kinds of check:

{: .notes}
- **Version check.** Prints the installed version. Compare it with the table under the commands.
- **Content check.** Looks for the G3 or AAA Certificate Services root in the store itself. The comment above each command says what an affected result looks like.

### Certificates to look for {#fingerprints}

{: .read}
To search a bundle or keystore by fingerprint, use these. The repository’s `rules/iocs.csv` lists all 16 compromised intermediates and cross-signs with their serials and SHA-256 fingerprints [R003]. It has no row for AAA Certificate Services, so take that fingerprint from this table.

{: .list .fps}
| Certificate | SHA-256 {.fp} | Refs |
|---|---|---|
| emSign ECC Root CA - G3 | `86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B` | R005 |
| emSign Root TLS CA - G3 | `7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D` | R006 |
| emSign Root CS CA - G3 | `F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5` | R006 |
| AAA Certificate Services | `D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4` | R007 |

{: .read}
Jump to: [Debian and Ubuntu](#m-debian) · [Alpine](#m-alpine) · [RHEL, AlmaLinux, Rocky](#m-rhel) · [macOS](#m-macos) · [Homebrew](#m-brew) · [Java](#m-java) · [certifi](#m-certifi) · [pip](#m-pip) · [uv](#m-uv) · [Node.js](#m-node) · [Bun and Deno](#m-bun) · [Go](#m-go) · [Rust](#m-rust) · [PHP, Ruby, Perl, Elixir](#m-pkgs) · [Electron apps](#m-electron) · [Container images](#m-images)

{: .muted .read}
The [Affected software page](checks.html) has all 130 items, with the AAA status of each.

::: {.stacks}

::: {.eco #m-debian}
### Debian and Ubuntu

The system CA bundle, from the `ca-certificates` package [R050, R051, R052, R055, R056, R057, R298].

```
# Installed version
dpkg-query -W ca-certificates

# Roots still in the bundle. Prints nothing on a fixed system
openssl crl2pkcs7 -nocrl -certfile /etc/ssl/certs/ca-certificates.crt \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign ECC Root CA - G3|AAA Certificate Services'
```

{: .caveats}
| Release | Affected {.bad} | Fixed in {.good} |
|---|---|---|
| Debian 13 | `20250419` | `20250419+deb13u1` |
| Debian 12 | `20230311+deb12u1`, `20250419~deb12u1` | `20250419~deb12u2` |
| Debian forky, sid | `20260816` and earlier | `20260816+nmu1` |
| Debian 11 | `20210119` | No fix yet |
| Ubuntu 22.04 | `20211016` (release build) | `20260816ubuntu0.22.04.1` |
| Ubuntu 24.04 | `20240203` (release build) | `20260816ubuntu0.24.04.1` |
| Ubuntu 26.04 | `20260223` (release build) | `20260816ubuntu0.26.04.1` |
| Ubuntu 26.10 | `20260816` (release build) | `20260816ubuntu0.26.10.1` |

[Fixing OS trust stores →](fixes.html#a-os)
:::

::: {.eco #m-alpine}
### Alpine

The system CA bundle, from the `ca-certificates` package [R059].

```
# Installed version
apk info -v 2>/dev/null | grep ca-certificates

# Roots still in the bundle. Prints nothing on a fixed system
openssl crl2pkcs7 -nocrl -certfile /etc/ssl/certs/ca-certificates.crt \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign ECC Root CA - G3|AAA Certificate Services'
```

{: .caveats}
| Branch | Affected {.bad} | Fixed in {.good} |
|---|---|---|
| 3.20 image | `20260413-r0` | `20261020-r0` |
| edge image | `20260611-r0` | `20261020-r0` |

`20261020-r0` is the fix on every branch.

[Fixing OS trust stores →](fixes.html#a-os)
:::

::: {.eco #m-rhel}
### RHEL, AlmaLinux and Rocky Linux

The system TLS bundle and the code-signing bundle, both from the `ca-certificates` package. AlmaLinux and Rocky Linux ship the same builds as RHEL [R064, R069, R073, R074, R075].

```
# Installed version
rpm -q ca-certificates

# Roots still in the TLS bundle. Prints nothing on a fixed system
openssl crl2pkcs7 -nocrl -certfile /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign ECC Root CA - G3|AAA Certificate Services'

# Roots still in the code-signing bundle. Prints nothing on a fixed system
openssl crl2pkcs7 -nocrl -certfile /etc/pki/ca-trust/extracted/pem/objsign-ca-bundle.pem \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign Root CS CA - G3|emSign ECC Root CA - G3|AAA Certificate Services'
```

{: .caveats}
| Release | Affected {.bad} | Fixed in {.good} |
|---|---|---|
| 10 | Builds before `2026.2.92_v9.0.319-100.3` | `2026.2.92_v9.0.319-100.3.el10_2` |
| 9 | Builds before `2026.2.92_v9.0.319-90.3` | `2026.2.92_v9.0.319-90.3.el9_8` |
| 8 | Builds before `2026.2.92_v9.0.319-81.3` | `2026.2.92_v9.0.319-81.3.el8_10` |

The current `rockylinux:8`, `:9` and `:10` images are affected until you upgrade `ca-certificates` in them.

[Fixing OS trust stores →](fixes.html#a-os)
:::

::: {.eco #m-macos}
### macOS

`/etc/ssl/cert.pem`, the bundle that curl, git, python3, ruby, perl and openssl from macOS trust. Re-run the check after every macOS update [R098, R099, R102, R104].

```
# macOS version
sw_vers -productVersion

# Roots still in the bundle. Prints nothing on a fixed system
openssl crl2pkcs7 -nocrl -certfile /etc/ssl/cert.pem \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign ECC Root CA - G3|AAA Certificate Services'
```

{: .caveats}
| Version | Affected {.bad} | Fixed in {.good} |
|---|---|---|
| 26.6.2 (25G83) | Yes, checked 2026-10-31 | No fix yet |
| 27.2 | Yes, per the community tracker. Not confirmed by Apple | No fix yet |

Apple names no fixed version. Its interim steps remove the roots, and the [fixes page](fixes.html#s-os) has them.

[Fixing OS trust stores →](fixes.html#a-os)
:::

::: {.eco #m-brew}
### Homebrew

Homebrew’s own CA bundle, from its `ca-certificates` formula [R093, R094].

```
# Installed version
brew list --versions ca-certificates

# Roots still in the bundle. Prints nothing on a fixed install
openssl crl2pkcs7 -nocrl -certfile "$(brew --prefix)/etc/ca-certificates/cert.pem" \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign ECC Root CA - G3|AAA Certificate Services'
```

{: .caveats}
| Formula | Affected {.bad} | Fixed in {.good} |
|---|---|---|
| `ca-certificates` | `2026-09-25` and earlier | `2026-09-25_1`, or `2026-10-20` (current) |

[Every OS item, with Homebrew →](checks.html#g-os)
:::

::: {.eco #m-java}
### Java

The `cacerts` keystore in each JDK or JRE. Run the `keytool` of the JDK you are checking [R114, R118, R120, R121].

```
# Compromised roots by fingerprint. Prints nothing on a fixed build
keytool -list -cacerts -storepass changeit | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'

# Compromised roots by owner name. Prints nothing on a fixed build
keytool -list -v -cacerts -storepass changeit | grep -E 'Owner: .*(emSign ECC Root CA - G3|AAA Certificate Services)'
```

{: .caveats}
| JDK line | Affected (OpenJDK’s list) {.bad} |
|---|---|
| 27 | `27.0.1.0.2` and earlier |
| 25 | `25.0.5.0.2` and earlier |
| 21 | `21.0.13.0.2` and earlier |
| 17 | `17.0.21.0.2` and earlier |
| 11 | `11.0.32.1` and earlier |
| 8 | `8u504` and earlier |

A fixed build’s release note names JDK-8395690 and CVE-2026-114820. Vendor version numbers differ, so check each vendor’s fixed build on the [Affected software page](checks.html#g-java).

[Fixing Java →](fixes.html#a-java)
:::

::: {.eco #m-certifi}
### Python certifi

The CA bundle that requests, HTTPX and other Python clients load from the certifi package. Check it in every venv [R160, R162, R164, R181, R182].

```
# Bundle path
python -m certifi

# Prints 1 if the bundle holds the G3 root, 0 if not
grep -c 'Label: "emSign ECC Root CA - G3"' "$(python -m certifi)"

# Prints 1 if the bundle holds the AAA root, 0 if not
grep -c 'Comodo AAA Services root' "$(python -m certifi)"
```

{: .caveats}
| Root | Affected {.bad} | Fixed in {.good} |
|---|---|---|
| G3 | `2019.3.9` to `2026.7.22` | `2026.10.19` or later |
| AAA | `2025.1.31` and earlier, including `2018.11.29` | `2026.10.19` or later |

`2026.10.18` is the advisory’s first patched release, but it also drops emSign roots that were not affected.

[Fixing Python →](fixes.html#a-python)
:::

::: {.eco #m-pip}
### pip

pip vendors its own copy of certifi, so a fixed OS store or certifi package doesn’t protect an old pip. Each venv has its own pip [R167, R168, R171].

```
# Installed version
python -m pip --version

# Lists every pip copy under your home directory that still holds the G3 root
find ~ -path '*/pip/_vendor/certifi/cacert.pem' -exec grep -l 'Label: "emSign ECC Root CA - G3"' {} + 2>/dev/null
```

{: .caveats}
| Versions | Affected {.bad} | Fixed in {.good} |
|---|---|---|
| All | `26.2.1` and earlier hold the G3 root | `26.2.2`, which vendors certifi 2026.10.19 |
| Bundled with Python 3.11 and 3.12 | `24.0` and `25.0.1` hold the G3 and AAA roots | `26.2.2` |

Upgrade pip in every venv.

[Fixing Python →](fixes.html#a-python)
:::

::: {.eco #m-uv}
### uv

uv carries its own root list inside its binary [R172, R173].

```
# Installed version
uv --version

# Prints a count above 0 on an affected build, 0 on a fixed one.
# Confirmed on Linux x86_64 builds only
grep -ac 'emSign ECC Root CA - G3' "$(command -v uv)"
```

{: .caveats}
| Tool | Affected {.bad} | Fixed in {.good} |
|---|---|---|
| uv | `0.13.3` and earlier | `0.13.4` removes the root. `0.13.5` also rejects the compromised keys |

[Fixing Python →](fixes.html#a-python)
:::

::: {.eco #m-node}
### Node.js

Node compiles a root list into its binary, and only a Node upgrade changes it [R190, R192, R195].

```
# Installed version
node --version

# Prints 1 if the binary holds the G3 root, 0 if not.
# Confirmed on Linux x86_64 builds only
grep -ac 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' "$(command -v node)"
```

{: .caveats}
| Line | Affected {.bad} | Fixed in {.good} |
|---|---|---|
| 26 | `26.12.0` and earlier | `26.12.1` |
| 24 | `24.22.0` and earlier | `24.22.1` |
| 22 | `22.23.3` and earlier | `22.23.4` |
| 20 | Every release (end of life) | No fix. Move to a supported line |

[Fixing JavaScript runtimes →](fixes.html#a-js)
:::

::: {.eco #m-bun}
### Bun and Deno

Both carry their own root list inside their binary [R201, R203].

```
# Installed versions
bun --version
deno --version

# Each prints a count above 0 on an affected build, 0 on a fixed one
grep -ac 'emSign ECC Root CA - G3' "$(command -v bun)"
grep -ac 'emSign ECC Root CA - G3' "$(command -v deno)"
```

{: .caveats}
| Runtime | Affected {.bad} | Fixed in {.good} |
|---|---|---|
| Bun | `1.4.3` and earlier | `1.4.4` |
| Deno | `2.9.7` and earlier | `2.9.8` |

[Fixing JavaScript runtimes →](fixes.html#a-js)
:::

::: {.eco #m-go}
### Go

Go’s denylist for the compromised certificates is compiled into each program. A program has it only if it was built with go1.26.10, go1.27.3 or later [R205, R206, R209].

```
# Toolchain version
go version

# Toolchain a program was built with
go version ./your-binary

# Known vulnerabilities in a built program
govulncheck -mode binary ./your-binary
```

{: .caveats}
| Line | Affected {.bad} | Fixed in {.good} |
|---|---|---|
| 1.27 | `1.27.0` to `1.27.2` | `1.27.3`, then rebuild |
| 1.26 | `1.26.9` and earlier | `1.26.10`, then rebuild |

[Fixing other languages →](fixes.html#a-langs)
:::

::: {.eco #m-rust}
### Rust

The root crates compile their roots into each program, so rebuild after updating. Run the checks in the project root [R215, R216, R218, R220, R223].

```
# Locked versions of the root and verifier crates
grep -A1 'name = "webpki-roots"' Cargo.lock
grep -A1 'name = "webpki-root-certs"' Cargo.lock
grep -A1 'name = "rustls-webpki"' Cargo.lock
```

{: .caveats}
| Crate | Affected {.bad} | Fixed in {.good} |
|---|---|---|
| `webpki-roots` | `1.0.9` and earlier 1.x, and `0.26.0` to `0.26.10` | `1.0.10` |
| `webpki-root-certs` | `1.0.9` and earlier 1.x, and `0.26.10` and earlier | `1.0.10` |
| `rustls-webpki` | `0.103.15` and earlier | `0.103.16` |

[Fixing other languages →](fixes.html#a-langs)
:::

::: {.eco #m-pkgs}
### PHP, Ruby, Perl and Elixir packages

Packages that ship their own CA bundle. Run each check in the project root [R227, R234, R236, R239, R244, R246].

```
# PHP
grep -A3 '"name": "composer/ca-bundle"' composer.lock

# Ruby
grep -E '^    excon ' Gemfile.lock
grep -E '^    httpclient ' Gemfile.lock

# Perl
grep -o 'Mozilla-CA-[0-9]*' cpanfile.snapshot | sort -u

# Elixir and Erlang
grep '"castore"' mix.lock
grep '"certifi"' mix.lock rebar.lock
```

{: .caveats}
| Package | Affected {.bad} | Fixed in {.good} |
|---|---|---|
| `composer/ca-bundle` | `1.5.14` and earlier, `1.4.15` and earlier | `1.6.0` or `1.4.16` |
| `excon` | `1.7.3` and earlier | `1.8.0` |
| `httpclient` | `2.9.0`, the latest release (AAA path) | No fix yet |
| `Mozilla::CA` | Before `20261020` | `20261020` |
| `castore` | `1.0.21` and earlier | `1.0.22` |
| Hex `certifi` | `2.17.0` and earlier | `2.18.0`, then a clean rebuild |

[Fixing other languages →](fixes.html#a-langs)
:::

::: {.eco #m-electron}
### Electron apps

Each Electron app ships its own Electron, so the fix is the app’s own release on a fixed Electron. Fixed releases still contain the G3 root, so the version is the check. Both commands read it without running the app [R270, R272, R273, R274].

```
# Electron version of an installed macOS app
plutil -extract CFBundleVersion raw "/Applications/<App>.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Resources/Info.plist"

# Electron version from an app's main binary, on macOS or Linux
grep -a -o 'Electron/[0-9][0-9.]*' "<app binary>" | sort -u
```

{: .caveats}
| Line | Affected {.bad} | Fixed in {.good} |
|---|---|---|
| 45 | `45.0.0-alpha.1` to below `45.0.0-beta.6` | `45.0.0-beta.6` or later |
| 44 | `44.0.0-alpha.1` to below `44.9.1` | `44.9.1` |
| 43 | `43.0.0-alpha.1` to below `43.8.1` | `43.8.1` |
| 42 and older | Below `42.11.16` | `42.11.16` |

[Fixing browsers and apps →](fixes.html#a-apps)
:::

::: {.eco #m-images}
### Container images

A container trusts only the bundle inside its image, so check every image you build or run [R294, R295, R298, R299].

```
# Copy the bundle out of an image with a shell
docker run --rm --network none --entrypoint cat <image> /etc/ssl/certs/ca-certificates.crt > bundle.pem

# Or, for an image with no shell
id=$(docker create <image> x); docker cp "$id":/etc/ssl/certs/ca-certificates.crt bundle.pem; docker rm "$id"

# Roots still in the bundle. Prints nothing when neither is there
openssl crl2pkcs7 -nocrl -certfile bundle.pem \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign ECC Root CA - G3|AAA Certificate Services'
```

{: .caveats}
| Image | Affected {.bad} | Fixed in {.good} |
|---|---|---|
| Any image | Built before its distro’s fixed `ca-certificates` | Rebuild on a fixed base, or upgrade `ca-certificates` in the build |
| distroless `static-debian12`, `base-debian12` | `ca-certificates` `20250419~deb12u1`, with the G3 and AAA roots. No fix on 2026-10-31 | distroless `static-debian13` (`20250419+deb13u1`) |

[Fixing container images →](fixes.html#a-images)
:::

:::

## Automated checker {.read #helper}

{: .key}
**A free, read-only checker runs these checks against your machine in one pass.**

<p class="src"><a href="https://github.com/fieldse/emudhra-ca-compromise-check"><svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg><span>Source on GitHub</span></a></p>

### What it is

{: .notes}
- One file, `vuln-check-emudhra-ca-compromise.pyz`, a Python zipapp: a zip archive that `python3` runs as a program.
- It needs Python 3.9 or later, no packages and no root.
- It reads files and changes nothing. Its own code opens no network connection.
- It is open source, under the MIT license.

### What it does

It looks in these places for the compromised certificates and for software older than its fix:

{: .notes}
- OS, Homebrew and Perl trust stores, and the CA bundles in the directories it scans
- Java keystores
- Runtimes and packages: Node.js, Bun, Deno, Go, Python, certifi, pip and uv
- Go and Rust programs, and Electron apps
- Lockfiles and manifests for Rust, Python, PHP, Ruby, Elixir, Electron and Go
- Local container images, when you ask for them

The [Checker rules page](detections.html) lists what it looks for, with each rule’s condition, level and source. [Documentation](#resources) explains how it works, and [Verifying a finding](#proof) shows how to check a result.

### What the checker can’t see

**The checker misses these, so check them by hand.**

{: .notes}
- Electron apps on Windows, because it reads only macOS and Linux app layouts
- Go and Rust binaries outside a `bin`, `sbin` or `Contents/MacOS` directory, such as `go-bin/`, even when `-r` names that folder
- Go and Rust binaries, Electron apps and lockfiles inside container images
- When the checker runs as root, an ACL that lets a non-root user change a tool, because the checker looks only at owner and mode bits
- A file above 32 MiB that another process truncates during the read, which ends the run with `SIGBUS`

{: .muted}
[What it does not cover yet](https://github.com/fieldse/emudhra-ca-compromise-check/blob/main/docs/how-it-works.md#what-it-does-not-cover-yet) has the full list.

### Usage

Run the checker with `./run-checks.sh`, which starts it with `python3 -I -S` to keep the machine’s own Python settings out of the check.

```
# Get the checker
git clone https://github.com/fieldse/emudhra-ca-compromise-check.git
cd emudhra-ca-compromise-check

# Optional, recommended: review the source
# Don't blindly run scripts from strangers!
unzip -l scripts/vuln-check-emudhra-ca-compromise.pyz
unzip -p scripts/vuln-check-emudhra-ca-compromise.pyz emudhra_check/cli.py | less
less run-checks.sh

# Scan your home directory and report problems only
./run-checks.sh -q

# Also check local container images
./run-checks.sh -q -c
```

{: .muted}
The archive holds the same code as `emudhra_check/` in the repository, and rebuilds from it to the same bytes. The [README](https://github.com/fieldse/emudhra-ca-compromise-check#inspecting-and-rebuilding-the-archive) shows how.

**Options**

These options change where the checker looks and when it fails:

{: .list .tbl}
| Option | What it does |
|---|---|
| `-r DIR` | Scan `DIR` instead of your home directory |
| `-x DIR` | Never enter `DIR` |
| `-q` | Print only `FAIL`, `WARN` and `ERROR` lines and the summary |
| `-c` | Also probe every local Podman image, with networking off. Docker images aren’t probed |
| `-i IMAGE` | Probe only this local image |
| `--strict` | Exit 1 on a `WARN` or `ERROR` as well, for CI |
| `--help` | Print every option |

### Reading results

With `-q` the checker prints only problems, at one of three levels:

{: .levels}
FAIL {.fail}
: Something to fix. A bundle, keystore or binary still holds a G3 root or a compromised certificate, or a release is older than its fix.

WARN
: Needs manual review. A store that holds AAA Certificate Services shows here, because the Sectigo cross-signs chain to it [R040].

ERROR
: A check that failed to run. The rest of the run continues.

Each line reads `LEVEL subject [location] detail`. This one comes from the test suite, run against the certifi 2026.7.22 wheel:

```text
FAIL  certifi [/tmp/d/certifi-2026.7.22.dist-info] found 2026.7.22, fixed 2026.10.18 (vendors its own CA bundle)
```

The last line is `SUMMARY pass=N fail=N warn=N info=N skip=N error=N`.

The checker exits 1 on any `FAIL`, 2 on a usage or environment error, and 0 otherwise.

## Verifying a finding {.read #proof}

{: .key}
**You can check any finding yourself from the original sources, without trusting the checker.**

{: .read}
The [proof page](proof.html) maps each output line to the steps that verify it, with a shell, `openssl`, `curl` and a browser. Start at [Find your finding](proof.html#find-your-finding).

## Documentation {#resources}

{: .key}
**These documents describe how the checker works, the rules it applies and the sources behind them.**

<ul class="resources">
  <li><a href="https://github.com/fieldse/emudhra-ca-compromise-check/blob/main/docs/how-it-works.md">How the check works</a><span>What it reads, how it matches certificates and how it picks a level</span></li>
  <li><a href="detections.html">Checker rules</a><span>Every rule the checker applies, with its condition, level and source</span></li>
  <li><a href="https://github.com/fieldse/emudhra-ca-compromise-check/blob/main/docs/weak-rules.md">Weak and unverifiable rules</a><span>The rules that rest on a weak source or none, and why</span></li>
  <li><a href="https://github.com/fieldse/emudhra-ca-compromise-check/blob/main/docs/sources.md">Source index</a><span>Every source by S-number, with the date it was checked</span></li>
</ul>

---

<aside class="cta" id="help" aria-label="Get help from Blacklight Security">
  <span class="label">Blacklight Security</span>
  <h3>Need help?</h3>
  <p>Our in-house team at <a href="https://blacklight.security/">Blacklight Security</a> can find every trust store, keystore, bundle and image across your systems that still trusts the compromised certificates, help you replace them, and look for signs that a certificate issued under them was used against you.</p>
  <div class="actions">
    <a class="btn btn-primary" href="https://blacklight.security/contact">Contact us →</a>
    <a class="btn btn-ghost" href="https://blacklight.security/">Our services</a>
  </div>
</aside>

## References {#sources}

{: .muted .read}
Every claim on these pages has a numbered row on the [references page](references.html), with its source, publisher and the date it was checked. The primary sources behind this page are below, grouped by who published them.

#### Root programs and browsers

<ul class="sources"><li><a href='https://bugzilla.mozilla.org/show_bug.cgi?id=2083449'>Bug 2083449 - eMudhra: Private key compromise of Intermediate Certificates</a><span class='muted'> · Mozilla</span></li><li><a href='https://github.com/TrustedRootProgram/Program-Requirements/blob/main/Announcements.md'>Announcements - Microsoft Trusted Root Certificate Program</a><span class='muted'> · Microsoft</span></li><li><a href='https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/'>Protecting Firefox users following the compromise of eMudhra intermediate certificates</a><span class='muted'> · Mozilla</span></li><li><a href='https://www.microsoft.com/en-us/msrc/blog/2026/10/microsoft-response-to-compromised-emudhra-certificate-authority-keys'>Microsoft's response to compromised eMudhra certificate authority keys</a><span class='muted'> · Microsoft</span></li><li><a href='https://support.apple.com/en-us/149555'>About the compromised eMudhra intermediate CAs</a><span class='muted'> · Apple</span></li><li><a href='https://chromium.googlesource.com/chromium/src/+/5a6a4e78597add03dd32bc233e03f3145cd99b65/net/data/ssl/chrome_root_store/root_store.textproto'>Chrome Root Store v42 root_store.textproto</a><span class='muted'> · Chromium</span></li><li><a href='https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/'>Protecting Chrome and Android Users from Compromised eMudhra Intermediate CA Certificates</a><span class='muted'> · Google</span></li><li><a href='https://bugzilla.mozilla.org/show_bug.cgi?id=2084101'>Bug 2084101 - Remove eMudhra emSign Root CA - G3 from NSS</a><span class='muted'> · Mozilla</span></li><li><a href='https://bugzilla.mozilla.org/show_bug.cgi?id=2086788'>Bug 2086788 - Firefox 115 ESR may still trust the compromised eMudhra certificates</a><span class='muted'> · Mozilla</span></li><li><a href='https://bugzilla.mozilla.org/show_bug.cgi?id=2085612'>Bug 2085612 - eMudhra: Access to CRLs blocked for certain User-Agent headers</a><span class='muted'> · Mozilla</span></li><li><a href='https://product-details.mozilla.org/1.0/firefox_versions.json'>Mozilla product-details firefox_versions.json</a><span class='muted'> · Mozilla</span></li><li><a href='https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/root_store.textproto'>Chrome Root Store v43 root_store.textproto</a><span class='muted'> · Chromium</span></li><li><a href='https://raw.githubusercontent.com/nss-dev/nss/master/lib/ckfw/builtins/certdata.txt'>NSS master certdata.txt</a><span class='muted'> · Mozilla</span></li><li><a href='https://github.com/nss-dev/nss'>NSS certdata.txt at release tags NSS_3_130 to NSS_3_132</a><span class='muted'> · Mozilla</span></li></ul>

#### The CAs and the disclosure

<ul class="sources"><li><a href='https://bugzilla.mozilla.org/attachment.cgi?id=9670867'>eMudhra response to Chrome Root Program questions on Bug 2083449</a><span class='muted'> · eMudhra</span></li><li><a href='https://www.sectigo.com/resource-library/advisory-on-compromised-emudhra-intermediate-certificates'>Advisory on compromised eMudhra intermediate certificates</a><span class='muted'> · Sectigo</span></li><li><a href='https://www.openwall.com/lists/oss-security/2026/10/20/1'>oss-security: eMudhra Intermediates Compromise</a><span class='muted'> · Openwall</span></li><li><a href='https://www.einpresswire.com/article/951482814/emudhra-to-exit-global-ssl-tls-certificate-business'>eMudhra to Exit global SSL/TLS Certificate Business</a><span class='muted'> · EIN Presswire</span></li><li><a href='https://emudhra.com/en/post/certificate-security-incident'>eMudhra status page, Update 7</a><span class='muted'> · eMudhra</span></li></ul>

#### CVE records and advisories

<ul class="sources"><li><a href='https://cveawg.mitre.org/api/cve/CVE-2026-111943'>CVE record CVE-2026-111943</a><span class='muted'> · CVE Program</span></li><li><a href='https://pkg.go.dev/vuln/GO-2026-6809'>GO-2026-6809</a><span class='muted'> · Go</span></li><li><a href='https://cveawg.mitre.org/api/cve/CVE-2026-114406'>CVE record CVE-2026-114406</a><span class='muted'> · CVE Program</span></li><li><a href='https://cveawg.mitre.org/api/cve/CVE-2026-114820'>CVE record CVE-2026-114820</a><span class='muted'> · CVE Program</span></li><li><a href='https://www.oracle.com/security-alerts/alert-cve-2026-114820.html'>Oracle Security Alert Advisory - CVE-2026-114820</a><span class='muted'> · Oracle</span></li><li><a href='https://cveawg.mitre.org/api/cve/CVE-2026-91403'>CVE record CVE-2026-91403</a><span class='muted'> · CVE Program</span></li><li><a href='https://www.oracle.com/security-alerts/alert-cve-2026-91403.html'>Oracle Security Alert Advisory - CVE-2026-91403</a><span class='muted'> · Oracle</span></li><li><a href='https://cveawg.mitre.org/api/cve/CVE-2026-113812'>CVE record CVE-2026-113812</a><span class='muted'> · CVE Program</span></li><li><a href='https://cveawg.mitre.org/api/cve/CVE-2026-115570'>CVE record CVE-2026-115570</a><span class='muted'> · CVE Program</span></li><li><a href='https://github.com/electron/electron/security/advisories/GHSA-jr5w-w6x2-84p9'>Mitigation for compromised eMudhra intermediate certificates (GHSA-jr5w-w6x2-84p9)</a><span class='muted'> · Electron</span></li><li><a href='https://cveawg.mitre.org/api/cve/CVE-2026-113470'>CVE record CVE-2026-113470</a><span class='muted'> · CVE Program</span></li><li><a href='https://github.com/dart-lang/sdk/security/advisories/GHSA-frr6-h895-5pxp'>TLS MitM vulnerability on Android, Windows, and Linux due to compromised eMudhra intermediate CA certificates</a><span class='muted'> · Dart</span></li></ul>

#### Platforms and runtimes

<ul class="sources"><li><a href='https://access.redhat.com/security/vulnerabilities/RHSB-2026-012'>RHSB-2026-012 Certificate compromise - eMudhra</a><span class='muted'> · Red Hat</span></li><li><a href='https://openjdk.org/emudhra'>Compromised Certificates and OpenJDK Java Runtimes</a><span class='muted'> · OpenJDK</span></li><li><a href='https://www.oracle.com/java/technologies/javase/27-0-1-0-3-relnotes.html'>Oracle JDK 27.0.1.0.3 release notes</a><span class='muted'> · Oracle</span></li><li><a href='https://nodejs.org/api/cli.html'>Command-line API</a><span class='muted'> · Node.js</span></li><li><a href='https://www.ibm.com/support/pages/node/7294729'>Security Bulletin: eMudhra CA Certificate Compromise (CVE-2026-91403 and CVE-2026-114820)</a><span class='muted'> · IBM</span></li><li><a href='https://github.com/golang/go/commit/90617fb7ceb59cf08bee7826bb51b8c8fb8c11de'>Go commit 90617fb</a><span class='muted'> · Go</span></li><li><a href='https://github.com/python/cpython/issues/160040'>ssl: distrust compromised eMudhra intermediate CA keys</a><span class='muted'> · Python Software Foundation</span></li></ul>

:::

<footer>
  <div class="wrap"><p>eMudhra G3 intermediate CA key compromise, October 2026. An independent guide, not affiliated with eMudhra or Sectigo.</p><p>Last updated 2026-11-05. <a href="https://github.com/fieldse/emudhra-ca-compromise-check">Source on GitHub</a>.</p></div>
</footer>
