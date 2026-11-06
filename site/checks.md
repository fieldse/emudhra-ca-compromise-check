---
title: eMudhra G3 CA compromise: affected software
description: Every trust store, runtime, package, app and container image that carried the compromised eMudhra G3 certificates, with a read-only check, vulnerable and fixed versions, and AAA cross-sign status.
output: checks.html
refs: inline
---

<header class="band">
  <div class="wrap">
    <a class="back" href="index.html">← Back to the guide</a>
    <p class="tags"><span>eMudhra G3</span><span>CA key compromise</span><span>October 2026</span></p>
    <p class="ids"><a href="index.html">Guide</a> &nbsp;·&nbsp; <a href="incident.html">Incident</a> &nbsp;·&nbsp; Affected software &nbsp;·&nbsp; <a href="fixes.html">Fixes</a> &nbsp;·&nbsp; <a href="detections.html">Checker rules</a> &nbsp;·&nbsp; <a href="proof.html">Proof</a> &nbsp;·&nbsp; <a href="references.html">References</a></p>
    <h1><span class='hl'>eMudhra G3</span> CA compromise<br>Affected software</h1>
    <p>One card per trust store, runtime, package, app and image: where it keeps its certificates, a read-only check, the vulnerable and fixed versions, and whether it holds the AAA root. Last updated 2026-11-05.</p>
  </div>
</header>

::: {tag=main .wrap}

<div class="facts">
  <div><b>{{count:all}}</b><span>items</span></div>
  <div><b>{{count:fixed}}</b><span>fixed</span></div>
  <div><b>{{count:partial}}</b><span>partly fixed</span></div>
  <div><b>{{count:unfixed}}</b><span>no fix yet</span></div>
</div>

<nav class="toc read" aria-label="Contents"><h2>Contents</h2><ol>
  <li><a href="#how">How to use this page</a><span>Where to run the checks and how to read a card</span></li>
  <li><a href="#g-os">OS trust stores</a><span>Linux distributions, Homebrew, macOS, iOS, Windows and Android</span></li>
  <li><a href="#g-java">Java</a><span>JDK builds by vendor, the Debian Java keystore and application truststores</span></li>
  <li><a href="#g-python">Python</a><span>certifi, pip, uv, CPython, conda and Pixi</span></li>
  <li><a href="#g-js">JavaScript runtimes</a><span>Node.js, Bun, Deno and npm packages with a vendored bundle</span></li>
  <li><a href="#g-langs">Other languages</a><span>Go, Rust, PHP, Ruby, Perl, Elixir, Erlang, .NET, curl, Dart and Flutter</span></li>
  <li><a href="#g-apps">Browsers and apps</a><span>Browsers, Electron apps, Docker, Podman and other tools</span></li>
  <li><a href="#g-images">Container images</a><span>Base images and how to read the bundle inside any image</span></li>
</ol></nav>

## How to use this page {#how}

{: .notes}
- Check the items you use, on every host and inside every image you ship.
- {{count:os}} items have no trust store of their own and use the OS store, so check the OS cards for them.
- Each card’s **AAA root** line says whether that store also holds AAA Certificate Services. Sectigo’s cross-signs chain the compromised intermediates to it, so a store that trusts it for TLS can still accept a forged chain [R040].

## OS trust stores {#g-os}

{: .key}
**Update the OS `ca-certificates` package and confirm the compromised roots are gone from its bundle. Items marked Follows the OS store take their fix from these cards.**

::: {.stacks}

::: {.eco #c-os-01 status=fixed}
### Debian 13 (trixie)

**Where to look:** `/etc/ssl/certs/ca-certificates.crt`

```
# Installed version
dpkg-query -W ca-certificates

# Roots still in the bundle. Affected if this prints anything
openssl crl2pkcs7 -nocrl -certfile /etc/ssl/certs/ca-certificates.crt \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign ECC Root CA - G3|AAA Certificate Services'

# Root files the package installed. Affected if this prints anything
ls /usr/share/ca-certificates/mozilla/ \
  | grep -E 'emSign_ECC_Root_CA_-_G3|Comodo_AAA'
```

The last two print nothing on a fixed system. Fixed packages still carry emSign Root CA - G1, emSign Root CA - C1 and emSign ECC Root CA - C3, so match the full G3 name.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `20250419` | `20250419+deb13u1` |

**AAA root:** Removed by the fix (Debian ships it as `Comodo AAA Services root`). Present in `20250419`.

**Checker rules:** [OS ca-certificates package](detections.html#d-cacertificatespackage), [OS CA bundles](detections.html#d-ostruststore)

[R050, R053, R054]
:::

::: {.eco #c-os-02 status=fixed}
### Debian 12 (bookworm)

**Where to look:** `/etc/ssl/certs/ca-certificates.crt`

```
# Installed version
dpkg-query -W ca-certificates

# Roots still in the bundle. Affected if this prints anything
openssl crl2pkcs7 -nocrl -certfile /etc/ssl/certs/ca-certificates.crt \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign ECC Root CA - G3|AAA Certificate Services'

# Root files the package installed. Affected if this prints anything
ls /usr/share/ca-certificates/mozilla/ \
  | grep -E 'emSign_ECC_Root_CA_-_G3|Comodo_AAA'
```

The last two print nothing on a fixed system. Fixed packages still carry emSign Root CA - G1, emSign Root CA - C1 and emSign ECC Root CA - C3, so match the full G3 name.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `20230311+deb12u1` | `20250419~deb12u2` |
| `20250419~deb12u1`, as in the distroless Debian 12 images | `20250419~deb12u2` |

**AAA root:** Removed by the fix. Present in `20230311+deb12u1`.

**Checker rules:** [OS ca-certificates package](detections.html#d-cacertificatespackage), [OS CA bundles](detections.html#d-ostruststore)

[R051, R298, R053, R054]
:::

::: {.eco #c-os-03 status=fixed}
### Debian forky (testing) and sid (unstable)

**Where to look:** `/etc/ssl/certs/ca-certificates.crt`

```
# Installed version
dpkg-query -W ca-certificates

# Roots still in the bundle. Affected if this prints anything
openssl crl2pkcs7 -nocrl -certfile /etc/ssl/certs/ca-certificates.crt \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign ECC Root CA - G3|AAA Certificate Services'

# Root files the package installed. Affected if this prints anything
ls /usr/share/ca-certificates/mozilla/ \
  | grep -E 'emSign_ECC_Root_CA_-_G3|Comodo_AAA'
```

The last two print nothing on a fixed system. Fixed packages still carry emSign Root CA - G1, emSign Root CA - C1 and emSign ECC Root CA - C3, so match the full G3 name.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `20260816` and earlier | `20260816+nmu1` |

**AAA root:** Not in `20260816+nmu1`, which also blocklists it. Unfixed builds not checked for AAA.

**Checker rules:** [OS ca-certificates package](detections.html#d-cacertificatespackage), [OS CA bundles](detections.html#d-ostruststore)

[R052, R053]
:::

::: {.eco #c-os-04 status=unfixed}
### Debian 11 (bullseye)

**Where to look:** `/etc/ssl/certs/ca-certificates.crt`

```
# Installed version
dpkg-query -W ca-certificates

# Roots still in the bundle. Affected if this prints anything
openssl crl2pkcs7 -nocrl -certfile /etc/ssl/certs/ca-certificates.crt \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign ECC Root CA - G3|AAA Certificate Services'
```

Both roots print on the bullseye release package.

{: .caveats}
| Vulnerable {.bad} | Fixed {.bad} |
|---|---|
| `20210119` (release) | None listed |
| `20250419~deb12u1~deb11u1` (last bullseye-security build, not downloadable on 2026-10-31, not checked) | None listed |

**AAA root:** Present in `20210119`.

**Checker rules:** [OS ca-certificates package](detections.html#d-cacertificatespackage), [OS CA bundles](detections.html#d-ostruststore)

[R055, R053]
:::

::: {.eco #c-os-05 status=fixed}
### Ubuntu 22.04, 24.04, 26.04, 26.10

**Where to look:** `/etc/ssl/certs/ca-certificates.crt`

```
# Installed version
dpkg-query -W ca-certificates

# Roots still in the bundle. Affected if this prints anything
openssl crl2pkcs7 -nocrl -certfile /etc/ssl/certs/ca-certificates.crt \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign ECC Root CA - G3|AAA Certificate Services'
```

Prints nothing on a fixed system.

{: .caveats}
| Applies to | Vulnerable {.bad} | Fixed {.good} |
|---|---|---|
| 22.04 | `20211016` (release pocket) | `20260816ubuntu0.22.04.1` |
| 24.04 | `20240203` (release pocket) | `20260816ubuntu0.24.04.1` |
| 26.04 | `20260223` (release pocket) | `20260816ubuntu0.26.04.1` |
| 26.10 | `20260816` (release pocket) | `20260816ubuntu0.26.10.1` |

**AAA root:** Present in the unfixed 22.04 and 24.04 builds, gone from every fixed build. Never present in the 26.04 and 26.10 release builds.

**Checker rules:** [OS ca-certificates package](detections.html#d-cacertificatespackage), [OS CA bundles](detections.html#d-ostruststore)

[R056, R057]
:::

::: {.eco #c-os-06 status=fixed}
### Ubuntu ESM 14.04, 16.04, 18.04, 20.04

**Where to look:** `/etc/ssl/certs/ca-certificates.crt`

```
# Installed version
dpkg-query -W ca-certificates

# Roots still in the bundle. Affected if this prints anything
openssl crl2pkcs7 -nocrl -certfile /etc/ssl/certs/ca-certificates.crt \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign ECC Root CA - G3|AAA Certificate Services'
```

ESM builds need Ubuntu Pro. Versions are from the advisory and were not inspected.

{: .caveats}
| Applies to | Vulnerable {.bad} | Fixed {.good} |
|---|---|---|
| 20.04 | Builds before the USN-8944-2 versions | `20240203~20.04.1ubuntu0.1~esm2` |
| 18.04 | Builds before the USN-8944-2 versions | `202402031ubuntu0.18.04.1+esm3` |
| 16.04 | Builds before the USN-8944-2 versions | `202402031~16.04.1~esm3` |
| 14.04 | Builds before the USN-8944-2 versions | `20230311~14.04.1~esm3` |

**AAA root:** Removed by the fix, per the advisory. Not inspected.

**Checker rules:** [OS ca-certificates package](detections.html#d-cacertificatespackage), [OS CA bundles](detections.html#d-ostruststore)

[R058]
:::

::: {.eco #c-os-07 status=fixed}
### Alpine 3.20 to 3.24 and edge

**Where to look:** `/etc/ssl/certs/ca-certificates.crt`

```
# Installed version
apk info -v 2>/dev/null | grep ca-certificates

# Roots still in the bundle. Affected if this prints anything
openssl crl2pkcs7 -nocrl -certfile /etc/ssl/certs/ca-certificates.crt \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign ECC Root CA - G3|AAA Certificate Services'
```

The bundle check prints nothing on a fixed system.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `20260413-r0` (3.20 image) | `20261020-r0` on every branch |
| `20260611-r0` (edge image) | `20261020-r0` on every branch |

**AAA root:** Never present in any Alpine bundle checked.

**Checker rules:** [OS ca-certificates package](detections.html#d-cacertificatespackage), [OS CA bundles](detections.html#d-ostruststore)

[R059]
:::

::: {.eco #c-os-08 status=fixed}
### Wolfi and Chainguard images

**Where to look:** `/etc/ssl/certs/ca-certificates.crt`

```
# Installed version
apk info -v 2>/dev/null | grep ca-certificates

# Roots still in the bundle. Affected if this prints anything
openssl crl2pkcs7 -nocrl -certfile /etc/ssl/certs/ca-certificates.crt \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign ECC Root CA - G3|AAA Certificate Services'
```

The static image has no shell or package manager. Copy /etc/ssl/certs/ca-certificates.crt out of the image and run the bundle check on the copy.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `20260909-r2` and earlier | `20260909-r3` (first fix) |
| `20260909-r2` and earlier | `20261020-r0` (current, in wolfi-base) |
| `20260909-r2` and earlier | Chainguard static image built 28 Oct 2026 |

**AAA root:** Not in `20261020-r0` or the 28 October static image. Older builds not checked.

**Checker rules:** [Podman images](detections.html#d-podmanimages), [OS ca-certificates package](detections.html#d-cacertificatespackage), [OS CA bundles](detections.html#d-ostruststore)

[R060, R061]
:::

::: {.eco #c-os-09 status=fixed}
### Fedora 43, 44, 45

**Where to look:** `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`, `objsign-ca-bundle.pem`

```
# Installed version
rpm -q ca-certificates

# Roots still in the TLS bundle. Affected if this prints anything
openssl crl2pkcs7 -nocrl -certfile /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign ECC Root CA - G3|AAA Certificate Services'

# Roots still in the code-signing bundle. Affected if this prints anything
openssl crl2pkcs7 -nocrl -certfile /etc/pki/ca-trust/extracted/pem/objsign-ca-bundle.pem \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign Root CS CA - G3|emSign ECC Root CA - G3|AAA Certificate Services'
```

The bundle checks print nothing on a fixed system. The -1 build passes the TLS check and fails the code-signing check.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `2025.2.80_v9.0.304-1.1.fc43` (F43 release) | `2026.2.92_v9.0.319-2` (.fc43, .fc44, .fc45) |
| `2026.2.92_v9.0.319-1` (still trusts emSign Root CS CA - G3 for code signing) | `2026.2.92_v9.0.319-2` (.fc43, .fc44, .fc45) |

**AAA root:** Not in any -2 bundle (TLS, email, code signing). Unfixed builds not checked for AAA.

**Checker rules:** [OS ca-certificates package](detections.html#d-cacertificatespackage), [OS CA bundles](detections.html#d-ostruststore)

[R062, R063]
:::

::: {.eco #c-os-10 status=fixed}
### RHEL 10, 9, 8 (and EUS)

**Where to look:** `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`, `objsign-ca-bundle.pem`

```
# Installed version
rpm -q ca-certificates

# Latest changelog entries
rpm -q --changelog ca-certificates | head -12

# Roots still in the TLS bundle. Affected if this prints anything
openssl crl2pkcs7 -nocrl -certfile /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign ECC Root CA - G3|AAA Certificate Services'

# Roots still in the code-signing bundle. Affected if this prints anything
openssl crl2pkcs7 -nocrl -certfile /etc/pki/ca-trust/extracted/pem/objsign-ca-bundle.pem \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign Root CS CA - G3|emSign ECC Root CA - G3|AAA Certificate Services'
```

The bundle checks print nothing on a fixed system. Only the .3 builds are advisory versions. The .0 to .2 builds are intermediate steps.

{: .caveats}
| Applies to | Vulnerable {.bad} | Fixed {.good} |
|---|---|---|
| 10 | Builds before `2026.2.92_v9.0.319-100.3` | `2026.2.92_v9.0.319-100.3.el10_2`, 10.0 EUS `-100.3.el10_0` |
| 9 | Builds before `2026.2.92_v9.0.319-90.3` | `2026.2.92_v9.0.319-90.3.el9_8`, 9.6 EUS `-90.3.el9_6`, 9.4 and 9.2 Update Services for SAP Solutions `-90.3.el9_4` and `-90.3.el9_2` |
| 8 | Builds before `2026.2.92_v9.0.319-81.3` | `2026.2.92_v9.0.319-81.3.el8_10`, 8.8 TUS and E4S `-80.3.el8_8`, 8.6 AUS and EUS Long-Life `-80.3.el8_6`, 8.4 AUS `-80.3.el8_4` |

**AAA root:** Removed in the .1 step. Unfixed 2025 and 2026 builds hold it in the email and code-signing bundles. Older builds hold it in the TLS bundle too.

**Checker rules:** [OS ca-certificates package](detections.html#d-cacertificatespackage), [OS CA bundles](detections.html#d-ostruststore)

[R064, R065, R066, R067, R069, R070, R317]
:::

::: {.eco #c-os-11 status=fixed}
### RHEL 7 and 6 ELS

**Where to look:** `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`, `objsign-ca-bundle.pem`

```
# Installed version
rpm -q ca-certificates
```

Versions are from the advisories and were not inspected.

{: .caveats}
| Applies to | Vulnerable {.bad} | Fixed {.good} |
|---|---|---|
| 7 ELS | Builds before the advisory versions | `2026.2.92_v9.0.319-70.3.el7_9` |
| 6 ELS | Builds before the advisory versions | `2026.2.92_v9.0.319-60.3.el6_10` |

**AAA root:** Not checked.

**Checker rules:** [OS ca-certificates package](detections.html#d-cacertificatespackage), [OS CA bundles](detections.html#d-ostruststore)

[R068]
:::

::: {.eco #c-os-12 status=fixed}
### AlmaLinux 8, 9, 10

**Where to look:** `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`, `objsign-ca-bundle.pem`

```
# Installed version
rpm -q ca-certificates

# Roots still in the TLS bundle. Affected if this prints anything
openssl crl2pkcs7 -nocrl -certfile /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign ECC Root CA - G3|AAA Certificate Services'

# Roots still in the code-signing bundle. Affected if this prints anything
openssl crl2pkcs7 -nocrl -certfile /etc/pki/ca-trust/extracted/pem/objsign-ca-bundle.pem \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign Root CS CA - G3|emSign ECC Root CA - G3|AAA Certificate Services'
```

The bundle checks print nothing on a fixed system.

{: .caveats}
| Applies to | Vulnerable {.bad} | Fixed {.good} |
|---|---|---|
| 8 | `2025.2.80_v9.0.304-80.2.el8_10` | `2026.2.92_v9.0.319-81.3.el8_10` |
| 9 | `2025.2.80_v9.0.305-91.el9` | `2026.2.92_v9.0.319-90.3.el9_8` |
| 10 | `2025.2.80_v9.0.305-102.el10_1` | `2026.2.92_v9.0.319-100.3.el10_2` |

**AAA root:** Removed. The fixed builds hold neither G3 nor AAA.

**Checker rules:** [OS ca-certificates package](detections.html#d-cacertificatespackage), [OS CA bundles](detections.html#d-ostruststore)

[R073]
:::

::: {.eco #c-os-13 status=fixed}
### Rocky Linux 8, 9, 10

**Where to look:** `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`, `objsign-ca-bundle.pem`

```
# Installed version
rpm -q ca-certificates

# Roots still in the TLS bundle. Affected if this prints anything
openssl crl2pkcs7 -nocrl -certfile /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign ECC Root CA - G3|AAA Certificate Services'

# Roots still in the code-signing bundle. Affected if this prints anything
openssl crl2pkcs7 -nocrl -certfile /etc/pki/ca-trust/extracted/pem/objsign-ca-bundle.pem \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign Root CS CA - G3|emSign ECC Root CA - G3|AAA Certificate Services'
```

The bundle checks print nothing on a fixed system. The current rockylinux:8, :9 and :10 images fail until the package is upgraded or the image rebuilt. An upgrade installs the fixed build.

{: .caveats}
| Applies to | Vulnerable {.bad} | Fixed {.good} |
|---|---|---|
| 8 | `2023.2.60_v7.0.306-80.0.el8_8` (current image), `2025.2.80_v9.0.304-80.2.el8_10` | `2026.2.92_v9.0.319-81.3.el8_10` |
| 9 | `2025.2.80_v9.0.305-91.el9` (current image) | `2026.2.92_v9.0.319-90.3.el9_8` |
| 10 | `2025.2.80_v9.0.305-102.el10` (current image) | `2026.2.92_v9.0.319-100.3.el10_2` |

**AAA root:** Removed by the fix. Unfixed 2025 builds hold it in the email and code-signing bundles. `2023.2.60_v7.0.306-80.0.el8_8` also holds it in the TLS bundle.

**Checker rules:** [OS ca-certificates package](detections.html#d-cacertificatespackage), [OS CA bundles](detections.html#d-ostruststore)

[R074, R075, R070]
:::

::: {.eco #c-os-14 status=fixed}
### Oracle Linux 7, 8, 9, 10

**Where to look:** `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`, `objsign-ca-bundle.pem`

```
# Installed version
rpm -q ca-certificates

# Roots still in the TLS bundle. Affected if this prints anything
openssl crl2pkcs7 -nocrl -certfile /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign ECC Root CA - G3|AAA Certificate Services'
```

The bundle checks print nothing on a fixed system.

{: .caveats}
| Applies to | Vulnerable {.bad} | Fixed {.good} |
|---|---|---|
| 7 | Not identified (builds before the fixes) | `2025.2.80_v9.0.304-71.0.2.el7_9` |
| 8 | Not identified (builds before the fixes) | `2025.2.80_v9.0.304-80.2.0.1.el8_10` or `2026.2.92_v9.0.319-81.3.el8_10` |
| 9 | Not identified (builds before the fixes) | `2025.2.80_v9.0.305-91.0.1.el9` or `2026.2.92_v9.0.319-90.3.el9_8` |
| 10 | Not identified (builds before the fixes) | `2025.2.80_v9.0.305-102.0.1.el10_2` or `2026.2.92_v9.0.319-100.3.el10_2` |

**AAA root:** Not in either set of fixed builds.

**Checker rules:** [OS ca-certificates package](detections.html#d-cacertificatespackage), [OS CA bundles](detections.html#d-ostruststore)

[R076, R355]
:::

::: {.eco #c-os-15 status=fixed}
### CentOS Stream 9

**Where to look:** `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`, `objsign-ca-bundle.pem`

```
# Installed version
rpm -q ca-certificates

# Roots still in the TLS bundle. Affected if this prints anything
openssl crl2pkcs7 -nocrl -certfile /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign ECC Root CA - G3|AAA Certificate Services'

# Roots still in the code-signing bundle. Affected if this prints anything
openssl crl2pkcs7 -nocrl -certfile /etc/pki/ca-trust/extracted/pem/objsign-ca-bundle.pem \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign Root CS CA - G3|emSign ECC Root CA - G3|AAA Certificate Services'
```

The bundle checks print nothing on a fixed system.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `2026.2.90_v9.0.316-90.0.el9` | `2026.2.92_v9.0.319-91.3.el9` |

**AAA root:** Not in the fixed TLS bundle.

**Checker rules:** [OS ca-certificates package](detections.html#d-cacertificatespackage), [OS CA bundles](detections.html#d-ostruststore)

[R071]
:::

::: {.eco #c-os-16 status=fixed}
### CentOS Stream 10

**Where to look:** `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`, `objsign-ca-bundle.pem`

```
# Installed version
rpm -q ca-certificates

# Roots still in the TLS bundle. Affected if this prints anything
openssl crl2pkcs7 -nocrl -certfile /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign ECC Root CA - G3|AAA Certificate Services'

# Roots still in the code-signing bundle. Affected if this prints anything
openssl crl2pkcs7 -nocrl -certfile /etc/pki/ca-trust/extracted/pem/objsign-ca-bundle.pem \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign Root CS CA - G3|emSign ECC Root CA - G3|AAA Certificate Services'
```

The TLS check prints nothing on -100.1. The code-signing check prints emSign Root CS CA - G3.

{: .caveats}
| Applies to | Vulnerable {.bad} | Fixed {.good} |
|---|---|---|
| TLS | `2026.2.90_v9.0.316-100.0.el10` | `2026.2.92_v9.0.319-100.1.el10` |
| Code signing | `2026.2.92_v9.0.319-100.1.el10` (current on the mirror) and `-100.2.el10` | `2026.2.92_v9.0.319-100.3.el10`, built in Koji, not yet on the public mirror on 2026-11-02 |

**AAA root:** Not in the -100.1 TLS bundle. `-100.0` holds it in the email and code-signing bundles.

**Checker rules:** [OS ca-certificates package](detections.html#d-cacertificatespackage), [OS CA bundles](detections.html#d-ostruststore)

[R072, R070, R356]
:::

::: {.eco #c-os-17 status=fixed}
### Amazon Linux 2

**Where to look:** `ca-certificates` RPM

```
# Installed version
rpm -q ca-certificates

# Latest changelog entries
rpm -q --changelog ca-certificates | head -20
```

The 0.3 changelog names the removed root emSign Root CA - G3. The bundle shows emSign ECC Root CA - G3 is gone.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `2025.2.76-1.amzn2.0.2` | `2025.2.76-1.amzn2.0.3` |
| `2025.2.76-1.amzn2.0.2` | `2025.2.76-1.amzn2.0.4` (also removes AAA) |

**AAA root:** Not in 0.3 or 0.4. Amazon says it has not trusted AAA for TLS since mid-2025.

**Checker rules:** [OS ca-certificates package](detections.html#d-cacertificatespackage), [OS CA bundles](detections.html#d-ostruststore)

[R077, R080]
:::

::: {.eco #c-os-18 status=fixed}
### Amazon Linux 2023

**Where to look:** `ca-certificates` RPM

```
# Installed version
rpm -q ca-certificates

# Latest changelog entries
rpm -q --changelog ca-certificates | head -20
```

A plain dnf update ca-certificates leaves the current image on the unfixed 0.3 build.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `2025.2.76-1.0.amzn2023.0.3` (current image, also after a plain update) | `2025.2.76-1.0.amzn2023.0.4` with `--releasever 2023.12.20261026` |
| `2025.2.76-1.0.amzn2023.0.3` (current image, also after a plain update) | `2025.2.76-1.0.amzn2023.0.5` with `--releasever=latest` (also removes AAA) |

**AAA root:** Not in 0.5. Amazon says it has not trusted AAA for TLS since mid-2025.

**Checker rules:** [OS ca-certificates package](detections.html#d-cacertificatespackage), [OS CA bundles](detections.html#d-ostruststore)

[R078, R079, R080]
:::

::: {.eco #c-os-19 status=unfixed}
### Amazon Linux 2027 preview

**Where to look:** `ca-certificates` RPM

```
# Installed version
rpm -q ca-certificates
```

{: .caveats}
| Vulnerable {.bad} | Fixed {.bad} |
|---|---|
| Preview `ca-certificates` | No fix yet (Pending Fix) |

**AAA root:** Not checked.

**Checker rules:** [OS CA bundles](detections.html#d-ostruststore), [OS ca-certificates package](detections.html#d-cacertificatespackage)

[R081]
:::

::: {.eco #c-os-20 status=fixed}
### Bottlerocket

**Where to look:** Node OS image (built-in CA bundle)

No read-only command.

Compare the node's Bottlerocket version with 1.68.0. No read-only on-node command was confirmed.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `1.67.0` (SDK 0.80.0) and earlier | `1.68.0` (SDK 0.81.1, curl bundle 2026-10-20) |

**AAA root:** Not in the 2026-10-20 curl bundle behind 1.68.0. Node images not checked.

**Checker rules:** None. Compare the node's Bottlerocket version with the table above.

[R082, R083, R084, R085]
:::

::: {.eco #c-os-21 status=fixed}
### Arch Linux

**Where to look:** `/etc/ssl/certs/ca-certificates.crt`

```
# Installed version
pacman -Q ca-certificates-mozilla

# Roots still in the bundle. Affected if this prints anything
openssl crl2pkcs7 -nocrl -certfile /etc/ssl/certs/ca-certificates.crt \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign ECC Root CA - G3|AAA Certificate Services'

# AAA anchors and the uses they are trusted for
trust list --filter=ca-anchors | grep -i -A2 'AAA'
```

The bundle check prints nothing on a fixed system. The trust list still shows Comodo AAA Services root, limited to email protection.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `3.131-1` and earlier | `3.131.1-1` |
| `3.131-1` and earlier | `3.132-1` (current) |

**AAA root:** Email-only. Kept in the trust source for email protection and left out of the TLS bundle.

**Checker rules:** [OS ca-certificates package](detections.html#d-cacertificatespackage), [OS CA bundles](detections.html#d-ostruststore)

[R086, R087]
:::

::: {.eco #c-os-22 status=partial}
### openSUSE Tumbleweed

**Where to look:** `/var/lib/ca-certificates/ca-bundle.pem`

```
# Machine architecture
uname -m

# Installed version
rpm -q ca-certificates-mozilla

# Roots still in the bundle. Affected if this prints anything
openssl crl2pkcs7 -nocrl -certfile /var/lib/ca-certificates/ca-bundle.pem \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign ECC Root CA - G3|AAA Certificate Services'
```

The bundle check prints nothing on a fixed system. aarch64 had no fixed build on 2026-10-31.

{: .caveats}
| Applies to | Vulnerable {.bad} | Fixed {.good} |
|---|---|---|
| x86_64 | `2.90-1.1` (x86_64 and aarch64) | `2.92-2.1` |
| aarch64 | `2.90-1.1` (x86_64 and aarch64) | No fix yet on 2026-10-31 |

**AAA root:** Never present in any SUSE bundle checked.

**Checker rules:** [OS ca-certificates package](detections.html#d-cacertificatespackage), [OS CA bundles](detections.html#d-ostruststore)

[R090, R092]
:::

::: {.eco #c-os-23 status=unfixed}
### openSUSE Leap 15.6

**Where to look:** `/var/lib/ca-certificates/ca-bundle.pem`

```
# Installed version
rpm -q ca-certificates-mozilla

# Roots still in the bundle. Affected if this prints anything
openssl crl2pkcs7 -nocrl -certfile /var/lib/ca-certificates/ca-bundle.pem \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign ECC Root CA - G3|AAA Certificate Services'
```

The bundle check prints the G3 root on 2.84-150200.44.1.

{: .caveats}
| Vulnerable {.bad} | Fixed {.bad} |
|---|---|
| `2.84-150200.44.1` (newest offered) | No fix yet on 2026-10-31 |

**AAA root:** Never present in any SUSE bundle checked.

**Checker rules:** [OS ca-certificates package](detections.html#d-cacertificatespackage), [OS CA bundles](detections.html#d-ostruststore)

[R091, R092]
:::

::: {.eco #c-os-24 status=fixed}
### SLES 15, SLES 16, openSUSE Leap 16.0

**Where to look:** `/var/lib/ca-certificates/ca-bundle.pem`

```
# Installed version
rpm -q ca-certificates-mozilla

# Roots still in the bundle. Affected if this prints anything
openssl crl2pkcs7 -nocrl -certfile /var/lib/ca-certificates/ca-bundle.pem \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign ECC Root CA - G3|AAA Certificate Services'
```

The bundle check prints nothing on a fixed system.

{: .caveats}
| Applies to | Vulnerable {.bad} | Fixed {.good} |
|---|---|---|
| SLES 15 | `2.84-150200.44.1` | `2.92-150200.50.2` |
| SLES 16, Leap 16.0 |  | `2.92-160000.1.1` |

**AAA root:** Never present in any SUSE bundle checked.

**Checker rules:** [OS ca-certificates package](detections.html#d-cacertificatespackage), [OS CA bundles](detections.html#d-ostruststore)

[R088, R089, R092]
:::

::: {.eco #c-os-25 status=fixed}
### Homebrew ca-certificates

**Where to look:** `$(brew --prefix)/etc/ca-certificates/cert.pem`

```
# Installed version
brew list --versions ca-certificates

# Roots still in the bundle. Affected if this prints anything
openssl crl2pkcs7 -nocrl -certfile "$(brew --prefix)/etc/ca-certificates/cert.pem" | openssl pkcs7 -print_certs -noout | grep -E 'emSign ECC Root CA - G3|AAA Certificate Services'
```

The bundle check prints nothing on a fixed install.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `2026-09-25` and earlier | `2026-09-25_1` |
| `2026-09-25` and earlier | `2026-10-20` (current) |

**AAA root:** Excluded by public key from 2026-09-25_1. On macOS an unfixed install also pulls it in from the system keychain.

**Checker rules:** [Homebrew CA bundles](detections.html#d-homebrewtruststore)

[R093, R094, R095, R096]
:::

::: {.eco #c-os-26 status=unfixed}
### macOS /etc/ssl/cert.pem (curl, git, python3, ruby, perl, openssl)

**Where to look:** `/etc/ssl/cert.pem`

```
# macOS version
sw_vers -productVersion

# Roots still in the bundle. Affected if this prints anything
openssl crl2pkcs7 -nocrl -certfile /etc/ssl/cert.pem \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign ECC Root CA - G3|AAA Certificate Services'
```

Prints both root names on macOS 26.6.2 (checked 2026-10-31). Re-run after every macOS update.

{: .caveats}
| Vulnerable {.bad} | Fixed {.bad} |
|---|---|
| 26.6.2 (25G83), checked 2026-10-31 | No fix yet. Apple names no version. |
| 27.2, per the community tracker (not confirmed by Apple) | No fix yet. Apple names no version. |

**AAA root:** Present on 26.6.2.

**Checker rules:** [OS CA bundles](detections.html#d-ostruststore)

[R098, R099, R100, R102, R103]
:::

::: {.eco #c-os-27 status=fixed}
### macOS system trust (Safari, Mail, Apple frameworks)

**Where to look:** `/System/Library/Keychains/SystemRootCertificates.keychain`

```
# Prints the root if the system keychain holds it
security find-certificate -a -c "emSign ECC Root CA - G3" -Z /System/Library/Keychains/SystemRootCertificates.keychain

# Prints the root if the system keychain holds it
security find-certificate -a -c "AAA Certificate Services" -Z /System/Library/Keychains/SystemRootCertificates.keychain
```

Both roots still print on macOS 26.6.2. Apple's block arrives as separate configuration data, so this output does not show exposure.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| Devices that have not received Apple's configuration updates | Automatic: 12 TLS certificates blocked from 19 Oct 2026, emSign ECC Root CA - G3 from 23 Oct 2026 |

**AAA root:** Present in the keychain on 26.6.2. Apple's block covers the six Sectigo cross-signs.

**Checker rules:** None. [OS CA bundles](detections.html#d-ostruststore) and [Homebrew CA bundles](detections.html#d-homebrewtruststore) add a note about the system keychain but don't judge it. Run the commands above.

[R097, R101]
:::

::: {.eco #c-os-28 status=fixed}
### iOS and iPadOS

**Where to look:** System trust (Apple configuration updates)

No read-only command.

No user-side check. The block arrives without a software update.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| Devices that have not received Apple's configuration updates | Automatic: TLS certificates from 19 Oct 2026, G3 root from 23 Oct 2026 |

**AAA root:** Not checked. Apple's block covers the six Sectigo cross-signs.

**Checker rules:** None. There is no user-side check.

[R097, R105]
:::

::: {.eco #c-os-29 status=fixed}
### Windows

**Where to look:** Disallowed CTL and trusted root list (CTL Updater)

```
REM CTL Updater settings
reg query HKLM\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate
```

Shows the CTL Updater settings. Microsoft's own check, certutil -f -verifyCTL DisallowedWU | findstr SequenceNumber, contacts Windows Update. Microsoft gives 01dd5f6ca45c9d86 as the CTL with the eMudhra block.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| Devices without the 20 Oct 2026 Disallowed CTL | Disallowed CTL `01dd5f6ca45c9d86` (20 Oct 2026) |
| Devices with automatic updates off or no internet access | Root removal 26 Oct 2026: KB5134133 (Windows 11), KB5134137 (Windows Server 2025) |

**AAA root:** Removed from the trust list on 26 Oct 2026. Microsoft calls it a cross-sign, but its thumbprint is the AAA root's (disputed).

**Checker rules:** None. Run the command above.

[R106, R107, R108, R109]
:::

::: {.eco #c-os-30 status=fixed}
### Android

**Where to look:** System trust store (Google Play services)

No read-only command.

No command-line check. Restarting the device triggers the update.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| Devices without the 19 Oct 2026 Play services update | Google Play services update, about 22:00 UTC on 19 Oct 2026 |

**AAA root:** Not checked. The community tracker suggests disabling it by hand on devices without the update.

**Checker rules:** None. Restart the device to trigger the update.

[R110, R111]
:::

:::

## Java {#g-java}

{: .key}
**Most JDKs carry their own `cacerts` store, which an OS update doesn’t change. Run each JDK’s own keytool against its store.**

::: {.stacks}

::: {.eco #c-java-01 status=fixed}
### Upstream OpenJDK 27 (jdk.java.net)

**Where to look:** `$JAVA_HOME/lib/security/cacerts`

```
# G3 or AAA root by fingerprint. Affected if this prints anything
keytool -list -cacerts -storepass changeit \
  | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'

# G3 or AAA root by owner name. Affected if this prints anything
keytool -list -v -cacerts -storepass changeit \
  | grep -E 'Owner: .*(emSign ECC Root CA - G3|AAA Certificate Services)'
```

Both print nothing on a fixed build. Run the keytool of the JDK you are checking.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `27.0.1.0.2` and earlier | `27.0.1.0.3` |

**AAA root:** Present in 27.0.1 and 27.0.1.0.2. Removed in 27.0.1.0.3.

**Checker rules:** [Java keystores](detections.html#d-javakeystores)

[R127, R114, R120, R121]
:::

::: {.eco #c-java-02 status=partial}
### Other OpenJDK builds (Homebrew, FreeBSD, vendors not listed here)

**Where to look:** The build's own `lib/security/cacerts`

```
# G3 or AAA root by fingerprint. Affected if this prints anything
keytool -list -cacerts -storepass changeit \
  | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'

# G3 or AAA root by owner name. Affected if this prints anything
keytool -list -v -cacerts -storepass changeit \
  | grep -E 'Owner: .*(emSign ECC Root CA - G3|AAA Certificate Services)'
```

Homebrew and FreeBSD OpenJDK don't use the OS store. Run the keytool of the JDK you are checking.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| OpenJDK's list: `27.0.1.0.2`, `25.0.5.0.2`, `21.0.13.0.2`, `17.0.21.0.2`, `11.0.32.1`, `8u504` and earlier | A build whose release note names JDK-8395690 and CVE-2026-114820 |

**AAA root:** Present in OpenJDK's own `cacerts` until JDK-8395690 removed `comodoaaaca`

**Checker rules:** [Java keystores](detections.html#d-javakeystores)

[R114, R118, R150, R117, R120, R121]
:::

::: {.eco #c-java-03 status=fixed}
### Oracle JDK 21, 25, 27

**Where to look:** `$JAVA_HOME/lib/security/cacerts`

```
# G3 or AAA root by fingerprint. Affected if this prints anything
keytool -list -cacerts -storepass changeit \
  | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'

# G3 or AAA root by owner name. Affected if this prints anything
keytool -list -v -cacerts -storepass changeit \
  | grep -E 'Owner: .*(emSign ECC Root CA - G3|AAA Certificate Services)'
```

Both print nothing on a fixed build. Run the keytool of the JDK you are checking.

{: .caveats}
| Applies to | Vulnerable {.bad} | Fixed {.good} |
|---|---|---|
| 21 | `21.0.13.0.2` and earlier | `21.0.13.0.3` |
| 25 | `25.0.5.0.2` and earlier | `25.0.5.0.3` |
| 27 | `27.0.1.0.2` and earlier | `27.0.1.0.3` |

**AAA root:** Present before the fix (inspected in 25.0.5.0.2). The .0.3 builds remove `comodoaaaca [jdk]`.

**Checker rules:** [Java keystores](detections.html#d-javakeystores)

[R128, R130, R131, R120, R121]
:::

::: {.eco #c-java-04 status=fixed}
### Oracle JDK 8

**Where to look:** `$JAVA_HOME/jre/lib/security/cacerts`

```
# JDK version and build
java -version

# G3 or AAA root by owner name. Affected if this prints anything
keytool -list -v -keystore "$JAVA_HOME/jre/lib/security/cacerts" -storepass changeit \
  | grep -E 'Owner: .*(emSign ECC Root CA - G3|AAA Certificate Services)'

# G3 or AAA root by fingerprint. Affected if this prints anything
keytool -list -v -keystore "$JAVA_HOME/jre/lib/security/cacerts" -storepass changeit \
  | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'
```

java -version shows the build number after the update number, b32 or b33. The keytool lines print nothing on a fixed build. Disputed: Oracle's 2026-10-21 alert lists 8u511 with no build number. Check the build number, b32 or b33, as well as the update number.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `8u511 b32` (and `8u511-perf-b32`) and earlier | `8u511 b33` |

**AAA root:** Present before the fix. 8u511 b33 removes `comodoaaaca [jdk]` with the three emSign roots. Not inspected.

**Checker rules:** [Java keystores](detections.html#d-javakeystores)

[R129, R128, R122, R120, R121]
:::

::: {.eco #c-java-05 status=unfixed}
### Oracle JDK 11, 17

**Where to look:** `$JAVA_HOME/lib/security/cacerts`

```
# G3 or AAA root by fingerprint. Affected if this prints anything
keytool -list -cacerts -storepass changeit \
  | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'

# G3 or AAA root by owner name. Affected if this prints anything
keytool -list -v -cacerts -storepass changeit \
  | grep -E 'Owner: .*(emSign ECC Root CA - G3|AAA Certificate Services)'
```

Both print nothing on a fixed build. Run the keytool of the JDK you are checking.

{: .caveats}
| Applies to | Vulnerable {.bad} | Fixed {.good} |
|---|---|---|
| 11 | `11.0.33.0.2` and earlier | Fixed build not confirmed. Run the check |
| 17 | `17.0.21.0.2` and earlier | Fixed build not confirmed. Run the check |

**AAA root:** Not checked

**Checker rules:** [Java keystores](detections.html#d-javakeystores)

[R128, R120, R121]
:::

::: {.eco #c-java-06 status=unfixed}
### Oracle GraalVM for JDK and GraalVM Enterprise Edition

**Where to look:** `$JAVA_HOME/lib/security/cacerts`

```
# G3 or AAA root by fingerprint. Affected if this prints anything
keytool -list -cacerts -storepass changeit \
  | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'

# G3 or AAA root by owner name. Affected if this prints anything
keytool -list -v -cacerts -storepass changeit \
  | grep -E 'Owner: .*(emSign ECC Root CA - G3|AAA Certificate Services)'
```

Both print nothing on a fixed build. Run the keytool of the JDK you are checking.

{: .caveats}
| Applies to | Vulnerable {.bad} | Fixed {.bad} |
|---|---|---|
| GraalVM for JDK 17 | `17.0.21.0.2` and earlier | None found |
| GraalVM for JDK 21 | `21.0.13.0.2` and earlier | None found |
| GraalVM EE 21 | `21.3.20.0.2` and earlier | None found |

**AAA root:** Not checked

**Checker rules:** [Java keystores](detections.html#d-javakeystores)

[R132, R120, R121]
:::

::: {.eco #c-java-07 status=fixed}
### Eclipse Temurin 17, 21, 25, 27

**Where to look:** `$JAVA_HOME/lib/security/cacerts`

```
# G3 or AAA root by fingerprint. Affected if this prints anything
keytool -list -cacerts -storepass changeit \
  | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'

# G3 or AAA root by owner name. Affected if this prints anything
keytool -list -v -cacerts -storepass changeit \
  | grep -E 'Owner: .*(emSign ECC Root CA - G3|AAA Certificate Services)'
```

Both print nothing on a fixed build. OpenJDK's CheckCerts reports a BAD ROOT: CN=emSign Root CA - G1,… line on fixed Temurin. That result is expected, because Temurin keeps G1 on purpose.

{: .caveats}
| Applies to | Vulnerable {.bad} | Fixed {.good} |
|---|---|---|
| 17 | `17.0.20.1+1` and earlier | `17.0.21+9` |
| 21 | `21.0.12.1+1` and earlier | `21.0.13+9` |
| 25 | `25.0.4.1+1` and earlier | `25.0.5+8` (disputed: a third-party test read it as pre-fix. Adoptium lists it fixed and the image has no G3) |
| 27 | `27+35` | `27.0.1.0.2+1` |

**AAA root:** Never present in the Temurin builds checked. G3 is the exposed root.

**Checker rules:** [Java keystores](detections.html#d-javakeystores)

[R134, R135, R136, R137, R138, R133, R140, R141, R125, R120, R121]
:::

::: {.eco #c-java-08 status=unfixed}
### Eclipse Temurin 27-jre image tag

**Where to look:** `$JAVA_HOME/lib/security/cacerts` inside the image

```
# JDK version in the image
docker run --rm --pull never --network none eclipse-temurin:27-jre java -version

# G3 or AAA root by fingerprint in the image. Affected if this prints anything
docker run --rm --pull never --network none eclipse-temurin:27-jre keytool -list -cacerts -storepass changeit \
  | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'
```

--pull never keeps the check on images already on the machine. The tag is fixed once java -version reports 27.0.1.0.2+1 and the grep prints nothing.

{: .caveats}
| Vulnerable {.bad} | Fixed {.bad} |
|---|---|
| `27+35`, still served by the tag on 2026-10-31 | No fixed image yet on 2026-10-31. The `27.0.1.0.2+1` binaries are fixed |

**AAA root:** No pre-fix Temurin build checked holds AAA. G3 is the exposed root.

**Checker rules:** [Podman images](detections.html#d-podmanimages), [Java keystores](detections.html#d-javakeystores)

[R138, R140]
:::

::: {.eco #c-java-09 status=unfixed}
### Eclipse Temurin 8, 11

**Where to look:** 8: `jre/lib/security/cacerts` under a JDK home. 11: `$JAVA_HOME/lib/security/cacerts`

```
# Which cacerts path this JDK has
ls -l "$JAVA_HOME/jre/lib/security/cacerts" "$JAVA_HOME/lib/security/cacerts" 2>/dev/null

# G3 or AAA root by owner name. Affected if this prints anything
keytool -list -v -keystore "$JAVA_HOME/jre/lib/security/cacerts" -storepass changeit \
  | grep -E 'Owner: .*(emSign ECC Root CA - G3|AAA Certificate Services)'

# G3 or AAA root by fingerprint. Affected if this prints anything
keytool -list -v -keystore "$JAVA_HOME/jre/lib/security/cacerts" -storepass changeit \
  | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'

# G3 or AAA root by fingerprint. Affected if this prints anything
keytool -list -cacerts -storepass changeit \
  | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'
```

The -keystore lines are for 8. Use whichever path ls finds. The -cacerts line is for 11. Temurin 8 and 11 name G3 cn=emsign_ecc_root_ca_-_g3,..., which OpenJDK's alias-based delete misses.

{: .caveats}
| Applies to | Vulnerable {.bad} | Fixed {.bad} |
|---|---|---|
| 8 | `8u504-b01` and earlier (latest on 2026-10-31) | No fix yet. Still vulnerable on 2026-10-31 |
| 11 | `11.0.32.1+1` and earlier (latest on 2026-10-31) | No fix yet. Still vulnerable on 2026-10-31 |

**AAA root:** Not present. G3 is the exposed root.

**Checker rules:** [Java keystores](detections.html#d-javakeystores)

[R139, R140, R119, R122, R120, R121]
:::

::: {.eco #c-java-10 status=fixed}
### Amazon Corretto 8, 11, 17, 21, 25, 27

**Where to look:** `$JAVA_HOME/lib/security/cacerts`, or `jre/lib/security/cacerts` under a Corretto 8 home

```
# G3 or AAA root by fingerprint. Affected if this prints anything
keytool -list -cacerts -storepass changeit \
  | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'

# G3 or AAA root by owner name. Affected if this prints anything
keytool -list -v -cacerts -storepass changeit \
  | grep -E 'Owner: .*(emSign ECC Root CA - G3|AAA Certificate Services)'

# G3 or AAA root by fingerprint. Affected if this prints anything
keytool -list -v -keystore "$JAVA_HOME/jre/lib/security/cacerts" -storepass changeit \
  | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'
```

Use the -keystore line on Corretto 8. Both copies of G3 match the fingerprint grep. Fixed builds still list emSign Root CA - C1 and emSign ECC Root CA - C3. A reply on Corretto's issue tracker says they are unrelated.

{: .caveats}
| Applies to | Vulnerable {.bad} | Fixed {.good} |
|---|---|---|
| 8 | `8.512.08.1` and earlier | `8.512.09.1` |
| 11 | `11.0.33.0.9` and earlier | `11.0.33.0.10` |
| 17 | `17.0.21.0.10` and earlier | `17.0.21.0.11` |
| 21 | `21.0.13.0.10` and earlier | `21.0.13.0.11` |
| 25 | `25.0.5.0.9` and earlier | `25.0.5.0.10` |
| 27 | `27.0.1.0.10` and earlier | `27.0.1.0.11` |

**AAA root:** Present before the fix. Removed in the fixed 8 and 21 builds (inspected). 11, 17, 25 and 27 rest on the changelogs.

**Checker rules:** [Java keystores](detections.html#d-javakeystores)

[R142, R143, R144, R145, R146, R122, R120, R121]
:::

::: {.eco #c-java-11 status=os}
### OS-packaged OpenJDK (RHEL and UBI RPMs, also Fedora, Oracle Linux, Arch, Gentoo)

**Where to look:** The OS Java store. On RHEL and UBI, `$JAVA_HOME/lib/security/cacerts` links to `/etc/pki/java/cacerts`

```
# Installed version
rpm -q ca-certificates

# Where the JDK’s cacerts links
ls -l "$JAVA_HOME/lib/security/cacerts" /etc/pki/java/cacerts

# G3 or AAA root by owner name. Affected if this prints anything
keytool -list -v -keystore /etc/pki/java/cacerts -storepass changeit \
  | grep -E 'Owner: .*(emSign ECC Root CA - G3|AAA Certificate Services)'
```

The keytool line prints nothing once the OS store is fixed. The fixed ca-certificates versions are in the OS rows.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| Follows the OS `ca-certificates` package | Update `ca-certificates`. The UBI 9 `openjdk-21-runtime` image of 2026-10-22 is already clean |

**AAA root:** Absent from the UBI 9 system Java store (image of 2026-10-22). Other distros not checked.

**Checker rules:** [Java keystores](detections.html#d-javakeystores), [OS ca-certificates package](detections.html#d-cacertificatespackage)

[R147, R148, R150]
:::

::: {.eco #c-java-12 status=partial}
### Red Hat build of OpenJDK (portable and Windows)

**Where to look:** Its own `lib/security/cacerts`, separate from `ca-certificates`

```
# G3 or AAA root by fingerprint. Affected if this prints anything
keytool -list -cacerts -storepass changeit \
  | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'

# G3 or AAA root by owner name. Affected if this prints anything
keytool -list -v -cacerts -storepass changeit \
  | grep -E 'Owner: .*(emSign ECC Root CA - G3|AAA Certificate Services)'
```

Update this build on its own. An OS ca-certificates update doesn't reach it. Both lines print nothing on a fixed build.

{: .caveats}
| Applies to | Vulnerable {.bad} | Fixed {.good} |
|---|---|---|
| 17 | Not checked | 17.0.21 for Windows (RHSA-2026:89916) describes the CVE-2026-91403 fix and lists CVE-2026-114820 among its CVEs. Root removal not confirmed. Run the check |
| 21, 25 | Not checked | Not checked |

**AAA root:** Not checked

**Checker rules:** [Java keystores](detections.html#d-javakeystores)

[R149, R120, R121]
:::

::: {.eco #c-java-13 status=fixed}
### Azul Zulu subscriber (SA) builds

**Where to look:** `$JAVA_HOME/lib/security/cacerts`

```
# JDK version and build
java -version

# G3 or AAA root by fingerprint. Affected if this prints anything
keytool -list -cacerts -storepass changeit \
  | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'

# G3 or AAA root by owner name. Affected if this prints anything
keytool -list -v -cacerts -storepass changeit \
  | grep -E 'Owner: .*(emSign ECC Root CA - G3|AAA Certificate Services)'
```

Compare the Zulu build number in java -version with the fixed list. Zulu 21.53.114 reports JDK 21.0.12.1.103+1.

{: .caveats}
| Applies to | Vulnerable {.bad} | Fixed {.good} |
|---|---|---|
| 27 | SA builds older than Azul's 2026-10-24 fix list | `27.30.110` |
| 25 | SA builds older than Azul's 2026-10-24 fix list | `25.37.116`, or July-based `25.35.304` |
| 21 | SA builds older than Azul's 2026-10-24 fix list | `21.53.114`, or `21.51.304` |
| 17 | SA builds older than Azul's 2026-10-24 fix list | `17.69.114`, or `17.67.304` |
| 11 | SA builds older than Azul's 2026-10-24 fix list | `11.91.114`, or `11.89.304` |
| 8 | SA builds older than Azul's 2026-10-24 fix list | `8.97.0.112`, or `8.95.0.304` |

**AAA root:** Not checked. Subscriber builds were not inspected.

**Checker rules:** [Java keystores](detections.html#d-javakeystores)

[R151, R120, R121]
:::

::: {.eco #c-java-14 status=unfixed}
### Azul Zulu free (Community) builds

**Where to look:** `$JAVA_HOME/lib/security/cacerts`

```
# G3 or AAA root by fingerprint. Affected if this prints anything
keytool -list -cacerts -storepass changeit \
  | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'

# G3 or AAA root by owner name. Affected if this prints anything
keytool -list -v -cacerts -storepass changeit \
  | grep -E 'Owner: .*(emSign ECC Root CA - G3|AAA Certificate Services)'
```

Current free builds print both G3 and AAA. Disputed: Azul's 2026-10-24 notes say the update removes the roots, but the free 21.0.13-21.54 image still holds them.

{: .caveats}
| Applies to | Vulnerable {.bad} | Fixed {.bad} |
|---|---|---|
| 21 | `21.0.13-21.54` (pushed 2026-10-29) and earlier | None found. Still vulnerable on 2026-10-31 |
| Other lines | Not inspected | None found. Azul's fix list has subscriber builds only |

**AAA root:** Present in 21.0.12.1-21.52 and 21.0.13-21.54

**Checker rules:** [Java keystores](detections.html#d-javakeystores)

[R152, R151, R120, R121]
:::

::: {.eco #c-java-15 status=unfixed}
### Microsoft Build of OpenJDK

**Where to look:** `$JAVA_HOME/lib/security/cacerts`

```
# G3 or AAA root by fingerprint. Affected if this prints anything
keytool -list -cacerts -storepass changeit \
  | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'

# G3 or AAA root by owner name. Affected if this prints anything
keytool -list -v -cacerts -storepass changeit \
  | grep -E 'Owner: .*(emSign ECC Root CA - G3|AAA Certificate Services)'
```

Microsoft names G3 cn=emsign_ecc_root_ca_-_g3,..., so OpenJDK's alias-based delete misses it. Match by fingerprint.

{: .caveats}
| Applies to | Vulnerable {.bad} | Fixed {.bad} |
|---|---|---|
| 21 | `21.0.13.0.2` (current on 2026-10-31) | No fix yet. Still vulnerable on 2026-10-31 |
| 25 | `25.0.5.0.2` (current on 2026-10-31) | No fix yet. Still vulnerable on 2026-10-31 |
| 11, 17 | Not checked | Not checked |

**AAA root:** Present in the `21-ubuntu` and `25-ubuntu` images of 2026-10-30

**Checker rules:** [Java keystores](detections.html#d-javakeystores)

[R153, R119, R120, R121]
:::

::: {.eco #c-java-16 status=fixed}
### SapMachine 21

**Where to look:** `$JAVA_HOME/lib/security/cacerts`

```
# G3 or AAA root by fingerprint. Affected if this prints anything
keytool -list -cacerts -storepass changeit \
  | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'

# G3 or AAA root by owner name. Affected if this prints anything
keytool -list -v -cacerts -storepass changeit \
  | grep -E 'Owner: .*(emSign ECC Root CA - G3|AAA Certificate Services)'
```

Both print nothing on a fixed build. Run the keytool of the JDK you are checking.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `21.0.13.0.2` and earlier | `21.0.13.0.3` |

**AAA root:** Present in 21.0.13.0.2. Removed in 21.0.13.0.3.

**Checker rules:** [Java keystores](detections.html#d-javakeystores)

[R154, R120, R121]
:::

::: {.eco #c-java-17 status=fixed}
### BellSoft Liberica 21

**Where to look:** `$JAVA_HOME/lib/security/cacerts`

```
# G3 or AAA root by fingerprint. Affected if this prints anything
keytool -list -cacerts -storepass changeit \
  | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'

# G3 or AAA root by owner name. Affected if this prints anything
keytool -list -v -cacerts -storepass changeit \
  | grep -E 'Owner: .*(emSign ECC Root CA - G3|AAA Certificate Services)'
```

Both print nothing on a fixed build. Run the keytool of the JDK you are checking.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `21.0.12.1+1` and earlier | `21.0.13.0.3+5` |

**AAA root:** Present in 21.0.12.1+1. Removed in 21.0.13.0.3+5.

**Checker rules:** [Java keystores](detections.html#d-javakeystores)

[R155, R120, R121]
:::

::: {.eco #c-java-18 status=fixed}
### IBM Semeru 17, 21, 25

**Where to look:** `$JAVA_HOME/lib/security/cacerts`

```
# G3 or AAA root by fingerprint. Affected if this prints anything
keytool -list -cacerts -storepass changeit \
  | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'

# G3 or AAA root by owner name. Affected if this prints anything
keytool -list -v -cacerts -storepass changeit \
  | grep -E 'Owner: .*(emSign ECC Root CA - G3|AAA Certificate Services)'
```

Semeru 17 and later name G3 cn_emsign_ecc_root_ca__g3,... [jdk]. Both lines print nothing on a fixed build.

{: .caveats}
| Applies to | Vulnerable {.bad} | Fixed {.good} |
|---|---|---|
| 17 | `17.0.0.0` to `17.0.20.15` | `17.0.21.0` |
| 21 | `21.0.0.0` to `21.0.12.15` | `21.0.13.0` |
| 25 | `25.0.0.0` to `25.0.4.15` | `25.0.5.0` |

**AAA root:** Not checked

**Checker rules:** [Java keystores](detections.html#d-javakeystores)

[R156, R119, R120, R121]
:::

::: {.eco #c-java-19 status=unfixed}
### IBM Semeru 8, 11

**Where to look:** 8: `jre/lib/security/cacerts` under a JDK home. 11: `$JAVA_HOME/lib/security/cacerts`

```
# Which cacerts path this JDK has
ls -l "$JAVA_HOME/jre/lib/security/cacerts" "$JAVA_HOME/lib/security/cacerts" 2>/dev/null

# G3 or AAA root by fingerprint. Affected if this prints anything
keytool -list -v -keystore "$JAVA_HOME/jre/lib/security/cacerts" -storepass changeit \
  | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'

# G3 or AAA root by fingerprint. Affected if this prints anything
keytool -list -cacerts -storepass changeit \
  | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'
```

The -keystore line is for 8. Use whichever path ls finds. The -cacerts line is for 11.

{: .caveats}
| Applies to | Vulnerable {.bad} | Fixed {.bad} |
|---|---|---|
| 8 | `8.0.302.0` to `8.0.504.5` | No fix named by IBM (bulletin of 2026-10-29) |
| 11 | `11.0.12.0` to `11.0.32.15` | No fix named by IBM (bulletin of 2026-10-29) |

**AAA root:** Not checked

**Checker rules:** [Java keystores](detections.html#d-javakeystores)

[R156, R119, R122, R120, R121]
:::

::: {.eco #c-java-20 status=unfixed}
### Debian and Ubuntu Java keystore

**Where to look:** `/etc/ssl/certs/java/cacerts`

```
# G3 or AAA root by owner name. Affected if this prints anything
keytool -list -v -keystore /etc/ssl/certs/java/cacerts -storepass changeit \
  | grep -E 'Owner: .*(emSign ECC Root CA - G3|AAA Certificate Services)'

# G3 or AAA root by fingerprint. Affected if this prints anything
keytool -list -keystore /etc/ssl/certs/java/cacerts -storepass changeit \
  | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'
```

A hit after the ca-certificates update means the keystore was never rebuilt.

{: .caveats}
| Vulnerable {.bad} | Fixed {.bad} |
|---|---|
| Any keystore built before the OS fix and not rebuilt since | No package update refreshes it. Rebuild it by hand after updating `ca-certificates` |

**AAA root:** Not checked

**Checker rules:** [Java keystores](detections.html#d-javakeystores)

[R157, R158, R120, R121]
:::

::: {.eco #c-java-21 status=unfixed}
### Application truststores (JKS, PKCS12)

**Where to look:** Any truststore file an application ships or loads

```
# Truststore files under the current directory
find . -type f \( -name '*.jks' -o -name '*.p12' -o -name 'cacerts' \) 2>/dev/null

# G3 or AAA root by owner name. Affected if this prints anything
keytool -list -v -keystore /path/to/truststore.jks -storepass <password> \
  | grep -E 'Owner: .*(emSign ECC Root CA - G3|AAA Certificate Services)'

# G3 or AAA root by fingerprint. Affected if this prints anything
keytool -list -v -keystore /path/to/truststore.jks -storepass <password> \
  | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'
```

Use the file's own password. Fixing the JDK's cacerts does not change these files.

{: .caveats}
| Vulnerable {.bad} | Fixed {.bad} |
|---|---|
| Any file that holds G3 or AAA | No vendor fix. Remove the roots from the file |

**AAA root:** Depends on the file. Both greps look for it

**Checker rules:** [Java keystores](detections.html#d-javakeystores) reads only files named `cacerts`. For other truststores, run the commands above.

[R159, R120, R121]
:::

:::

## Python {#g-python}

{: .key}
**certifi and pip carry their own copy of the CA bundle in every environment and venv. Check each copy, not only the system Python.**

::: {.stacks}

::: {.eco #c-python-01 status=fixed}
### certifi

**Where to look:** `site-packages/certifi/cacert.pem` in every environment

```
# Path of the certifi bundle
python -m certifi

# 1 if the bundle holds the G3 root, 0 if not
grep -c 'Label: "emSign ECC Root CA - G3"' "$(python -m certifi)"

# 1 if the bundle holds the AAA root, 0 if not
grep -c 'Comodo AAA Services root' "$(python -m certifi)"

# Every emSign root in the bundle
grep 'Label: "emSign' "$(python -m certifi)"

# Every installed certifi under your home directory
find ~ -type d -name 'certifi-*.dist-info' 2>/dev/null

# Every certifi bundle under your home directory that holds G3 or the AAA root. Affected if this prints anything
find ~ -path '*/certifi/cacert.pem' -exec grep -lE 'Label: "emSign ECC Root CA - G3"|Comodo AAA Services root' {} + 2>/dev/null
```

Each grep -c prints 1 when the bundle holds that root and 0 when it does not. Fixed bundles still list emSign Root CA - G1, and 2026.10.19 also lists C1 and C3. The last find lists every certifi copy under your home directory that holds G3 or the AAA root, pip's vendored copies included.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `2019.3.9` to `2026.7.22` (G3 root) | `2026.10.19` or later (target) |
| `2025.1.31` and earlier, including `2018.11.29` (AAA root) | `2026.10.18` is the GHSA's first patched release but drops the unaffected emSign roots |

**AAA root:** Present in 2025.1.31 and earlier, including 2018.11.29. Absent from 2025.4.26 onward

**Checker rules:** [certifi, pip and uv packages](detections.html#d-pythondistinfo), [certifi and pip of python3](detections.html#d-hostpythonpackages), [PEM bundles](detections.html#d-pembundles)

[R160, R161, R162, R163, R164, R165]
:::

::: {.eco #c-python-02 status=fixed}
### certifi pins in lockfiles

**Where to look:** `requirements*.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`

```
# certifi pins in requirements files
grep -iE '^certifi' requirements*.txt

# certifi pins in Poetry and uv lockfiles
grep -A1 '^name = "certifi"' poetry.lock uv.lock

# certifi pin in Pipfile.lock
grep -A8 '"certifi": {' Pipfile.lock
```

Run in the project root. Pin 2026.10.19 or later.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| Pins from `2019.3.9` to `2026.7.22` (G3 root) | `certifi==2026.10.19` or later |
| Pins of `2025.1.31` or earlier (AAA root) | `certifi==2026.10.19` or later |

**AAA root:** Follows the pinned version. 2025.1.31 and earlier hold it

**Checker rules:** [certifi pins](detections.html#d-pythonpins)

[R166, R160, R164, R162]
:::

::: {.eco #c-python-03 status=fixed}
### pip (vendored certifi)

**Where to look:** `site-packages/pip/_vendor/certifi/cacert.pem` in every venv and base install

```
# pip version
python -m pip --version

# Vendored certifi version and bundle path
python -m pip debug 2>/dev/null | grep -i certifi

# Every venv under your home directory
find ~ -name pyvenv.cfg 2>/dev/null

# pip version in each of those venvs
find ~ -name pyvenv.cfg 2>/dev/null \
  | while IFS= read -r c; do "${c%/pyvenv.cfg}/bin/python" -m pip --version 2>/dev/null; done

# Every pip copy under your home directory that holds G3. Affected if this prints anything
find ~ -path '*/pip/_vendor/certifi/cacert.pem' -exec grep -l 'Label: "emSign ECC Root CA - G3"' {} + 2>/dev/null
```

pip debug prints the vendored bundle's path and certifi version. The loop prints the pip version in every venv under your home directory. The last find lists every pip copy that still holds G3. A fixed OS store does not protect an old pip.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `26.2.1` and earlier (G3 root) | `26.2.2` (vendors certifi 2026.10.19) |
| `24.0` and `25.0.1` (G3 and AAA roots) | `26.2.2` (vendors certifi 2026.10.19) |

**AAA root:** Present in pip 24.0 and 25.0.1. Absent from 26.2.1 and 26.2.2

**Checker rules:** [certifi, pip and uv packages](detections.html#d-pythondistinfo), [certifi and pip of python3](detections.html#d-hostpythonpackages), [PEM bundles](detections.html#d-pembundles)

[R167, R168, R169, R171]
:::

::: {.eco #c-python-04 status=os}
### Debian python3-pip

**Where to look:** Uses `/etc/ssl/certs/ca-certificates.crt`

```
# Vendored certifi version and bundle path
python3 -m pip debug 2>/dev/null | grep -i certifi
```

Debian's pip reports the system bundle path here. Check that bundle with the OS trust store rows.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| Follows the system `ca-certificates` package | A fixed `ca-certificates` package |

**AAA root:** Follows the system bundle

**Checker rules:** [certifi and pip of python3](detections.html#d-hostpythonpackages), [OS CA bundles](detections.html#d-ostruststore), [OS ca-certificates package](detections.html#d-cacertificatespackage), [certifi, pip and uv packages](detections.html#d-pythondistinfo)

[R170, R167]
:::

::: {.eco #c-python-05 status=fixed}
### uv

**Where to look:** Compiled into the `uv` binary (`webpki-root-certs`)

```
# Installed version
uv --version

# Count of G3 root names in the binary. Affected if above 0
grep -ac 'emSign ECC Root CA - G3' "$(command -v uv)"

# Variables that point TLS at another bundle
env | grep -E '^SSL_CERT_(FILE|DIR)='
```

The binary grep prints a count above 0 on an affected build and 0 on a fixed one. Confirmed on Linux x86_64 builds only. If SSL_CERT_FILE or SSL_CERT_DIR is set, uv trusts only that source, so check it too.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `0.13.3` and earlier | `0.13.4` (root removed) |
| `0.13.3` and earlier | `0.13.5` (also rejects the compromised keys) |

**AAA root:** Not found in 0.13.3 or 0.13.4 (Linux x86_64 builds checked)

**Checker rules:** [uv](detections.html#d-uvhost), [certifi, pip and uv packages](detections.html#d-pythondistinfo), [Rust binaries](detections.html#d-rustbinaries)

[R172, R173, R175]
:::

::: {.eco #c-python-06 status=fixed}
### uv-managed CPython

**Where to look:** uv's managed interpreters and the venvs built on them

```
# Python builds that uv manages
uv python list --only-installed
```

After uv 0.13.5, run uv python upgrade. Venvs pinned to an older patch release keep the old interpreter and its pip.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| Managed builds installed before uv `0.13.5` | uv `0.13.5`, then `uv python upgrade` (3.11 and newer) |
| Managed 3.9 and 3.10 builds, which uv 0.13.5 did not update. 3.8 and older were not checked | uv `0.13.5`, then `uv python upgrade` (3.11 and newer) |

**AAA root:** Follows the bundled pip. pip 26.2.2 does not hold it

**Checker rules:** [certifi, pip and uv packages](detections.html#d-pythondistinfo), [CPython](detections.html#d-cpythonhost)

[R174, R176, R168, R179]
:::

::: {.eco #c-python-07 status=fixed}
### CPython 3.13, 3.14, 3.15 (bundled pip)

**Where to look:** The pip that `ensurepip` installs into new venvs

```
# Installed version
python3 --version

# pip version
python3 -m pip --version
```

Upgrading Python does not change pip in existing venvs. Upgrade pip in each one.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| Releases before `3.15.1`, `3.14.9`, `3.13.17` | `3.15.1`, `3.14.9`, `3.13.17` (pip 26.2.2) |

**AAA root:** Not checked for the older bundled pip. pip 26.2.2 does not hold it

**Checker rules:** [certifi and pip of python3](detections.html#d-hostpythonpackages), [certifi, pip and uv packages](detections.html#d-pythondistinfo), [CPython](detections.html#d-cpythonhost)

[R176, R168, R171]
:::

::: {.eco #c-python-08 status=fixed}
### CPython ssl key block (CVE-2026-115557)

**Where to look:** The interpreter's `ssl` module

```
# Installed version
python3 --version
```

The block works only while certificate verification is on. 3.13.18, 3.12.16 and 3.11.18 are source-only releases with no python.org installers.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| Earlier patch releases of each line | `3.15.2` |
| Earlier patch releases of each line | `3.14.10` |
| Earlier patch releases of each line | `3.13.18` |
| Earlier patch releases of each line | `3.12.16` |
| Earlier patch releases of each line | `3.11.18` |

**AAA root:** The block matches the key, so it also rejects the Sectigo cross-signs under the AAA root

**Checker rules:** [CPython](detections.html#d-cpythonhost)

[R177]
:::

::: {.eco #c-python-09 status=partial}
### CPython 3.11, 3.12 (bundled pip)

**Where to look:** pip 24.0 (current 3.11) and 25.0.1 (current 3.12), installed into every new venv

```
# Installed version
python3 --version

# pip version
python -m pip --version
```

Run the second command inside each venv created by 3.11 or 3.12.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| Every 3.11 and 3.12 release (current releases bundle pip 24.0 and 25.0.1) | No bundled pip fix. Upgrade pip to 26.2.2 in each venv |
| Every 3.11 and 3.12 release (current releases bundle pip 24.0 and 25.0.1) | `3.11.18` and `3.12.16` add the `ssl` key block |

**AAA root:** Present. pip 24.0 and 25.0.1 both hold it

**Checker rules:** [CPython](detections.html#d-cpythonhost), [certifi and pip of python3](detections.html#d-hostpythonpackages), [certifi, pip and uv packages](detections.html#d-pythondistinfo)

[R178, R168, R177, R171]
:::

::: {.eco #c-python-10 status=unfixed}
### CPython 3.10 and older

**Where to look:** Bundled pip

```
# Installed version
python3 --version
```

{: .caveats}
| Vulnerable {.bad} | Fixed {.bad} |
|---|---|
| 3.9 and 3.10 (bundled pip trusts G3). Older lines: end of life, bundled pip not checked | No fix. End of life |

**AAA root:** Not checked

**Checker rules:** [CPython](detections.html#d-cpythonhost), [certifi and pip of python3](detections.html#d-hostpythonpackages), [certifi, pip and uv packages](detections.html#d-pythondistinfo)

[R179]
:::

::: {.eco #c-python-11 status=fixed}
### python.org macOS installer (bundled certifi)

**Where to look:** `/Library/Frameworks/Python.framework/Versions/3.*/`

```
# certifi version for each python.org install
for p in /Library/Frameworks/Python.framework/Versions/3.*/bin/python3; do echo "$p"; "$p" -m pip show certifi 2>/dev/null \
  | grep -i '^version'; done
```

Each installation needs its own pip install --upgrade certifi, run with that interpreter.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| Bundled certifi from `2019.3.9` to `2026.7.22` | certifi `2026.10.19` or later |

**AAA root:** Follows the certifi version. 2025.1.31 and earlier hold it

**Checker rules:** [certifi and pip of python3](detections.html#d-hostpythonpackages), [certifi, pip and uv packages](detections.html#d-pythondistinfo)

[R180, R160, R164, R162]
:::

::: {.eco #c-python-12 status=fixed}
### requests, HTTPX

**Where to look:** The installed `certifi`, or the file in `REQUESTS_CA_BUNDLE` or `CURL_CA_BUNDLE` (requests)

```
# certifi version
python -c 'import certifi; print(certifi.__version__)'

# Variables that point TLS at another bundle
env | grep -E '^(REQUESTS|CURL)_CA_BUNDLE='
```

If either variable is set, check the file it names.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| certifi from `2019.3.9` to `2026.7.22` | certifi `2026.10.19` or later |

**AAA root:** Follows the certifi version

**Checker rules:** [certifi, pip and uv packages](detections.html#d-pythondistinfo), [certifi and pip of python3](detections.html#d-hostpythonpackages)

[R181, R182, R160, R162]
:::

::: {.eco #c-python-13 status=os}
### truststore

**Where to look:** The OS trust store

No read-only command.

Check the OS trust store instead.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| Follows the OS store | A fixed OS store |

**AAA root:** Follows the OS store

**Checker rules:** [OS CA bundles](detections.html#d-ostruststore), [OS ca-certificates package](detections.html#d-cacertificatespackage)

[R183]
:::

::: {.eco #c-python-14 status=fixed}
### conda (base environment)

**Where to look:** `ssl/cacert.pem` under the base directory (`Library/ssl/cacert.pem` on Windows), plus `certifi`

```
# Installed versions and their channels
conda list --name base --show-channel-urls "^(conda|certifi|ca-certificates)$"

# Base directory that holds the bundle
conda info --base
```

The second command prints the base directory that holds the bundle.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| conda before `26.9.4`, unless certifi and ca-certificates already meet the minimums | conda `26.9.4` |
| `ca-certificates` below the channel minimum | `ca-certificates` `2026.10.20` (Anaconda main) or `2026.10.19` (conda-forge) |
| `certifi` before `2026.10.19` | `certifi` `2026.10.19` |

**AAA root:** Not checked

**Checker rules:** [PEM bundles](detections.html#d-pembundles), [certifi, pip and uv packages](detections.html#d-pythondistinfo)

[R184]
:::

::: {.eco #c-python-15 status=fixed}
### conda environments other than base

**Where to look:** Each environment's own `certifi` and `ca-certificates`

```
# Every environment
conda env list

# Installed versions
conda list --name <env> "^(certifi|ca-certificates)$"
```

Updating base does not update the other environments. Repeat for each one.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `ca-certificates` below the channel minimum | `ca-certificates` `2026.10.20` (Anaconda main) or `2026.10.19` (conda-forge) |
| `certifi` before `2026.10.19` | `certifi` `2026.10.19` |

**AAA root:** Not checked

**Checker rules:** [PEM bundles](detections.html#d-pembundles), [certifi, pip and uv packages](detections.html#d-pythondistinfo)

[R185, R184]
:::

::: {.eco #c-python-16 status=fixed}
### mamba, libmamba (conda-forge)

**Where to look:** The environment where mamba is installed

```
# Installed versions
conda list --name base "^(mamba|libmamba)$"
```

conda-forge rebuilt these without a version change. Compare the build string as well as the version.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| Builds before the conda-forge rebuild | Rebuilt builds that carry the CA minimum |

**AAA root:** Not checked

**Checker rules:** None. Run the command above.

[R186]
:::

::: {.eco #c-python-17 status=unfixed}
### Anaconda main on osx-64, linux-ppc64le, linux-s390x

**Where to look:** `ca-certificates` and `certifi` from Anaconda main

```
# Install details, including the platform
conda info
```

The platform line shows whether the install is on one of the retired platforms.

{: .caveats}
| Vulnerable {.bad} | Fixed {.bad} |
|---|---|
| Every CA package build on these platforms | No fix yet |

**AAA root:** Not checked

**Checker rules:** [PEM bundles](detections.html#d-pembundles), [certifi, pip and uv packages](detections.html#d-pythondistinfo)

[R187]
:::

::: {.eco #c-python-18 status=fixed}
### Pixi (standalone binary)

**Where to look:** Compiled into the `pixi` binary

```
# Installed version
pixi --version
```

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| Before `0.82.1` | `0.82.1` |

**AAA root:** Not checked

**Checker rules:** [Rust binaries](detections.html#d-rustbinaries)

[R188]
:::

::: {.eco #c-python-19 status=fixed}
### sigstore, virtualenv

**Where to look:** Installed packages in each environment

```
# Installed versions
python -m pip show sigstore virtualenv
```

The PSF lists these minimums. The reason for each fix is unconfirmed.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| sigstore before `4.5.1` | sigstore `4.5.1` |
| virtualenv before `21.14.12` | virtualenv `21.14.12` |

**AAA root:** Not checked

**Checker rules:** None. Run the command above.

[R189]
:::

:::

## JavaScript runtimes {#g-js}

{: .key}
**Node.js, Bun and Deno carry their root list inside the binary, and some npm packages vendor their own bundle. Update the runtime and check each project’s `node_modules`.**

::: {.stacks}

::: {.eco #c-js-01 status=fixed}
### Node.js 22, 24, 26

**Where to look:** Compiled into the `node` binary (PEM text)

```
# Installed version
node --version

# 1 if the binary holds the G3 root, 0 if not
grep -ac 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' "$(command -v node)"

# Every node binary under your home directory that holds the G3 root. Affected if this prints anything
find ~ -type f -name node -perm -u+x -exec grep -la 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' {} + 2>/dev/null

# Extra CA file Node.js loads, if one is set
echo "$NODE_EXTRA_CA_CERTS"
```

The grep -ac prints 1 if the binary holds the G3 root and 0 if not. The find lists every node binary under your home directory that still holds it. Confirmed on Linux x86_64 builds only. If NODE_EXTRA_CA_CERTS names a file, check that file too.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `22.23.3` and earlier | `22.23.4` |
| `24.22.0` and earlier | `24.22.1` |
| `26.12.0` and earlier | `26.12.1` |

**AAA root:** Not found in the 22, 24 and 26 builds checked (Linux x64)

**Checker rules:** [Node.js on PATH](detections.html#d-nodehost), [Node.js version managers](detections.html#d-nodeversiondirs), [Node.js binaries in apps](detections.html#d-bundlednodebinaries)

[R192, R193, R194, R190, R191, R196, R198]
:::

::: {.eco #c-js-02 status=unfixed}
### Node.js 20

**Where to look:** Compiled into the `node` binary (PEM text)

```
# Installed version
node --version

# 1 if the binary holds the G3 root, 0 if not
grep -ac 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' "$(command -v node)"
```

End of life since 2026-04-30. Move to 22.23.4, 24.22.1 or 26.12.1.

{: .caveats}
| Vulnerable {.bad} | Fixed {.bad} |
|---|---|
| All 20.x, last release `20.20.2` | No fix |

**AAA root:** Not found in 20.20.2 (Linux x64 build checked)

**Checker rules:** [Node.js on PATH](detections.html#d-nodehost), [Node.js version managers](detections.html#d-nodeversiondirs), [Node.js binaries in apps](detections.html#d-bundlednodebinaries)

[R195]
:::

::: {.eco #c-js-03 status=partial}
### npm packages with a vendored CA bundle

**Where to look:** `node_modules`

```
# Files under node_modules that embed the G3 root. Affected if this prints anything
grep -rlF 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' node_modules 2>/dev/null
```

Run in the project root. Lists any file that embeds the G3 root as PEM text, including inside JavaScript. A DER copy would not match.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| None named by any advisory (2026-10-17 to 2026-10-31) | No advisory to follow |

**AAA root:** Not checked

**Checker rules:** [PEM bundles](detections.html#d-pembundles)

[R200, R192]
:::

::: {.eco #c-js-04 status=fixed}
### Bun

**Where to look:** Compiled into the `bun` binary (`root_certs.der`)

```
# Installed version
bun --version

# Count of G3 root names in the binary. Affected if above 0
grep -ac 'emSign ECC Root CA - G3' "$(command -v bun)"
```

The grep prints a count above 0 on an affected build and 0 on a fixed one. Confirmed on Linux x86_64 builds only. A fixed build still names emSign Root CA - G1.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `1.4.3` and earlier | `1.4.4` |

**AAA root:** Not found in 1.4.3 or 1.4.4 (Linux x64 builds checked)

**Checker rules:** [Bun](detections.html#d-bunhost)

[R201]
:::

::: {.eco #c-js-05 status=fixed}
### Deno

**Where to look:** Compiled into the `deno` binary (bundled Mozilla roots by default)

```
# Installed version
deno --version

# Count of G3 root names in the binary. Affected if above 0
grep -ac 'emSign ECC Root CA - G3' "$(command -v deno)"

# Store Deno uses. Empty means the bundled roots
echo "$DENO_TLS_CA_STORE"
```

The grep prints a count above 0 on an affected build and 0 on a fixed one. Confirmed on Linux x86_64 builds only. An empty DENO_TLS_CA_STORE means the bundled roots.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `2.9.7` and earlier | `2.9.8` |

**AAA root:** Present in 2.9.7. Absent from 2.9.8

**Checker rules:** [Deno](detections.html#d-denohost)

[R203, R204, R202]
:::

:::

## Other languages {#g-langs}

{: .key}
**Go, Rust, PHP, Ruby, Perl, Elixir, .NET, curl and Dart either bundle a root list in a package or follow the OS store. A bundled list needs a package update, and a compiled program needs a rebuild.**

::: {.stacks}

::: {.eco #c-langs-01 status=fixed}
### Go toolchain (crypto/x509)

**Where to look:** No bundle. Linux reads the first system bundle found, from `/etc/ssl/certs/ca-certificates.crt`. `SSL_CERT_FILE` and `SSL_CERT_DIR` override it. macOS and Windows use the platform verifier

```
# Go version the module asks for
grep -nE '^(go|toolchain) ' go.mod

# Installed version
go version

# Go version the binary was built with
go version ./your-binary

# Checks the binary against the Go vulnerability database
govulncheck -mode binary ./your-binary

# Variables that point TLS at another bundle
env | grep -E '^SSL_CERT_(FILE|DIR)='
```

A binary has the denylist only if it was built with go1.26.10, go1.27.3 or later. govulncheck checks the binary against GO-2026-6809.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| 1.26.9 and earlier | 1.26.10, then rebuild |
| 1.27.0 to 1.27.2 | 1.27.3, then rebuild |

**AAA root:** No store of its own. The 1.26.10 and 1.27.3 key denylist also rejects the AAA cross-signs, including through the macOS and Windows verifiers

**Checker rules:** [Go toolchain](detections.html#d-gotoolchain), [Go binaries](detections.html#d-gobinaries)

[R205, R206, R207, R208, R209]
:::

::: {.eco #c-langs-02 status=fixed}
### golang.org/x/crypto/x509roots/fallback

**Where to look:** Embedded in the binary. Used only when no system roots or platform verifier exist, or when `GODEBUG=x509usefallbackroots=1`

```
# Module version in go.mod and go.sum
grep -n 'x509roots/fallback' go.mod go.sum

# Module version built into the binary
go version -m ./your-binary | grep x509roots/fallback

# G3 or AAA SHA-256 fingerprint in the binary. Affected if it prints the G3 fingerprint
grep -aoiE '86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b|d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4' ./your-binary \
  | sort -u

# GODEBUG settings
env | grep GODEBUG
```

The module has no tagged releases, so compare the date in the pseudo-version. The binary grep prints the G3 fingerprint for a binary built with the old bundle. The AAA match in a binary was not tested. govulncheck reports nothing for this module, because the Go vulnerability database has no advisory for it.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| v0.0.0-20260916154351-b853e4b620cd and earlier | v0.0.0-20261020153306-9f2b28d4331a, then rebuild |

**AAA root:** In v0.0.0-20250203165127-fa5273e46196 and earlier. Dropped in v0.0.0-20250512154111-9f6bf8449a9f. The module has no key block. A binary built with Go 1.26.10 or 1.27.3 has the toolchain's key denylist

**Checker rules:** [Go binaries](detections.html#d-gobinaries)

[R210, R211, R212, R213, R214, R207, R238]
:::

::: {.eco #c-langs-03 status=partial}
### Rust webpki-roots

**Where to look:** Compiled into the program. Version in `Cargo.lock`

```
# Locked version
grep -A1 'name = "webpki-roots"' Cargo.lock

# Which crates pull it in, and at which version
cargo tree -i webpki-roots
```

Cargo.lock can list 0.26.11 and a 1.x entry together. 0.26.11 is fixed only when the 1.x entry is 1.0.10 or later. If cargo tree says the name is ambiguous, add the version, as in webpki-roots@0.26.11. Rebuild after updating.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| 1.0.9 and earlier 1.x | 1.0.10 (1.0.11 also drops C1 and C3) |
| 0.26.0 to 0.26.10 | 0.26.11 with a 1.x entry of 1.0.10 or later |
| 0.26.11 with a 1.x entry below 1.0.10 | Update the 1.x entry to 1.0.10 |
| 0.25.x and older | None on these lines. Move to 1.0.10 |

**AAA root:** In 0.26.9 and earlier, including 0.25.4. Dropped in 0.26.10. No key block of its own. rustls-webpki 0.103.16 adds one

**Checker rules:** [Cargo.lock](detections.html#d-cargolocks), [Rust binaries](detections.html#d-rustbinaries)

[R215, R216, R217, R218, R219, R224, R226, R223]
:::

::: {.eco #c-langs-04 status=fixed}
### Rust webpki-root-certs

**Where to look:** Compiled into the program. Version in `Cargo.lock`

```
# Locked version
grep -A1 'name = "webpki-root-certs"' Cargo.lock

# Which crates pull it in, and at which version
cargo tree -i webpki-root-certs

# Count of G3 root names in the binary. Affected if above 0
grep -ac 'emSign ECC Root CA - G3' ./your-binary
```

0.26.11 is fixed only when Cargo.lock also has a 1.x entry of 1.0.10 or later. The binary grep printed 0 on a uv build that uses 1.0.10.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| 1.0.9 and earlier 1.x | 1.0.10 |
| 0.26.10 and earlier | 0.26.11 with a 1.x entry of 1.0.10 or later |
| 0.26.11 with a 1.x entry below 1.0.10 | Update the 1.x entry to 1.0.10 |

**AAA root:** In 0.26.9 and earlier. Dropped in 0.26.10. No key block of its own

**Checker rules:** [Cargo.lock](detections.html#d-cargolocks), [Rust binaries](detections.html#d-rustbinaries)

[R220, R221, R224, R226, R222]
:::

::: {.eco #c-langs-05 status=fixed}
### Rust rustls-webpki

**Where to look:** No store. The certificate verifier, version in `Cargo.lock`

```
# Locked version
grep -A1 'name = "rustls-webpki"' Cargo.lock

# Which crates pull it in, and at which version
cargo tree -i rustls-webpki
```

RUSTSEC-2026-0382 patches only 0.103.16 and later 0.103.x, and 0.104.0-alpha.8 and later.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| 0.103.15 and earlier | 0.103.16 |
| 0.104.0-alpha.1 to alpha.7 | 0.104.0-alpha.8 |

**AAA root:** No store. 0.103.16 and 0.104.0-alpha.8 reject the eight compromised keys whatever roots are configured, so they also reject the AAA cross-signs

**Checker rules:** [Cargo.lock](detections.html#d-cargolocks), [Rust binaries](detections.html#d-rustbinaries)

[R223, R224, R226]
:::

::: {.eco #c-langs-06 status=os}
### Rust rustls-native-certs, rustls-platform-verifier

**Where to look:** No bundle. `SSL_CERT_FILE` if set, else the Windows store, the macOS keychain or the Linux OpenSSL bundle

```
# Which crates pull it in, and at which version
cargo tree -i rustls-native-certs

# Which crates pull it in, and at which version
cargo tree -i rustls-platform-verifier

# Variables that point TLS at another bundle
env | grep -E '^SSL_CERT_(FILE|DIR)='
```

Then check the OS store. rustls-native-certs trusts every root in the store and ignores OS distrust settings, so the root must be gone from the store itself.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| Follows the OS store | Fix the OS store |

**AAA root:** Follows the OS store. No key block. Pair with rustls-webpki 0.103.16

**Checker rules:** [OS CA bundles](detections.html#d-ostruststore), [OS ca-certificates package](detections.html#d-cacertificatespackage)

[R225, R226, R223]
:::

::: {.eco #c-langs-07 status=fixed}
### PHP composer/ca-bundle

**Where to look:** The system bundle when found, else `vendor/composer/ca-bundle/res/cacert.pem`

```
# Locked version
grep -A3 '"name": "composer/ca-bundle"' composer.lock

# Installed version
composer show composer/ca-bundle

# G3 (86:A1:EC:BA) or AAA (D7:A7:A0:FB) fingerprints in the bundle. Affected if this prints anything
awk -v cmd='openssl x509 -noout -fingerprint -sha256' '/BEGIN CERT/{c=""} {c=c $0 "\n"} /END CERT/{printf "%s", c | cmd; close(cmd)}' vendor/composer/ca-bundle/res/cacert.pem \
  | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'
```

The fingerprint check prints one line per match and nothing on a clean bundle. 86:A1:EC:BA is the G3 root, D7:A7:A0:FB the AAA root.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| 1.5.14 and earlier | 1.6.0 |
| 1.4.15 and earlier | 1.4.16 |

**AAA root:** In 1.5.6 and 1.4.7 and earlier. Dropped in 1.5.7 and 1.4.8. 1.6.0 and 1.4.16 add findDistrustedCertificate, a key check whose list includes the AAA cross-signs

**Checker rules:** [composer.lock](detections.html#d-composerlocks), [PEM bundles](detections.html#d-pembundles)

[R227, R228, R229, R230, R238]
:::

::: {.eco #c-langs-08 status=fixed}
### Composer

**Where to look:** The `composer` tool, through composer/ca-bundle

```
# Installed version
composer --version
```

There is no fixed 2.10.x. Move to 2.11.0 or the 2.2.31 LTS.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| 2.10.3 and earlier | 2.11.0 |
| 2.2.30 and earlier LTS | 2.2.31 LTS |

**AAA root:** 2.11.0 and 2.2.31 reject the compromised intermediates even when the system store trusts their roots. 2.2.31 requires composer/ca-bundle 1.4.16, whose key list covers the AAA cross-signs

**Checker rules:** None. Run the command above.

[R231, R229]
:::

::: {.eco #c-langs-09 status=os}
### PHP

**Where to look:** No bundle. `openssl.cafile` or `openssl.capath` if set (empty by default), else the system store

```
# Bundle paths PHP’s OpenSSL reads
php -r 'var_dump(openssl_get_cert_locations());'

# G3 (86:A1:EC:BA) or AAA (D7:A7:A0:FB) fingerprints in the bundle. Affected if this prints anything
awk -v cmd='openssl x509 -noout -fingerprint -sha256' '/BEGIN CERT/{c=""} {c=c $0 "\n"} /END CERT/{printf "%s", c | cmd; close(cmd)}' /etc/ssl/certs/ca-certificates.crt \
  | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'
```

If ini_cafile is set, run the fingerprint check on that file instead. The bundle path shown is the Debian and Ubuntu one. The fingerprint check prints one line per match and nothing on a clean bundle. 86:A1:EC:BA is the G3 root, D7:A7:A0:FB the AAA root.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| Follows the OS store or the configured file | Fix the OS store or the configured file |

**AAA root:** Follows the OS store or the configured file. Not checked

**Checker rules:** [OS CA bundles](detections.html#d-ostruststore), [OS ca-certificates package](detections.html#d-cacertificatespackage)

[R232, R238]
:::

::: {.eco #c-langs-10 status=os}
### RubyGems, Bundler

**Where to look:** OpenSSL's default CA locations, plus one bundled GlobalSign Root CA - R3 file for rubygems.org

```
# RubyGems environment and paths
gem env

# Bundle file and directory Ruby’s OpenSSL reads
ruby -ropenssl -e 'puts OpenSSL::X509::DEFAULT_CERT_FILE, OpenSSL::X509::DEFAULT_CERT_DIR'

# G3 (86:A1:EC:BA) or AAA (D7:A7:A0:FB) fingerprints in the bundle. Affected if this prints anything
awk -v cmd='openssl x509 -noout -fingerprint -sha256' '/BEGIN CERT/{c=""} {c=c $0 "\n"} /END CERT/{printf "%s", c | cmd; close(cmd)}' /etc/ssl/certs/ca-certificates.crt \
  | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'
```

The bundle path shown is the Debian and Ubuntu one. Use the file Ruby's OpenSSL reports if it differs. The fingerprint check prints one line per match and nothing on a clean bundle. 86:A1:EC:BA is the G3 root, D7:A7:A0:FB the AAA root.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| Follows the OS store | Fix the OS store |

**AAA root:** None bundled. The bundled file holds only GlobalSign Root CA - R3. Otherwise follows the OS store

**Checker rules:** [OS CA bundles](detections.html#d-ostruststore), [OS ca-certificates package](detections.html#d-cacertificatespackage)

[R233, R238]
:::

::: {.eco #c-langs-11 status=fixed}
### Ruby excon

**Where to look:** OpenSSL's default CA locations plus the gem's `data/cacert.pem`

```
# Locked version
grep -E '^    excon ' Gemfile.lock

# G3 (86:A1:EC:BA) or AAA (D7:A7:A0:FB) fingerprints in the bundle. Affected if this prints anything
awk -v cmd='openssl x509 -noout -fingerprint -sha256' '/BEGIN CERT/{c=""} {c=c $0 "\n"} /END CERT/{printf "%s", c | cmd; close(cmd)}' "$(gem contents excon | grep 'data/cacert.pem$')" | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'
```

The fingerprint check prints one line per match and nothing on a clean bundle. 86:A1:EC:BA is the G3 root, D7:A7:A0:FB the AAA root. Run the same check on vendored copies, such as vendor/bundle/ruby/*/gems/excon-*/data/cacert.pem.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| 1.7.3 and earlier | 1.8.0 |

**AAA root:** In 1.2.5 and earlier. Dropped in 1.2.6. No key block. Also trusts the OS store

**Checker rules:** [Gemfile.lock](detections.html#d-gemfilelocks), [PEM bundles](detections.html#d-pembundles)

[R234, R235, R238]
:::

::: {.eco #c-langs-12 status=unfixed}
### Ruby httpclient

**Where to look:** The gem's `lib/httpclient/cacert.pem`, loaded by default

```
# Locked version
grep -E '^    httpclient ' Gemfile.lock

# G3 (86:A1:EC:BA) or AAA (D7:A7:A0:FB) fingerprints in the bundle. Affected if this prints anything
awk -v cmd='openssl x509 -noout -fingerprint -sha256' '/BEGIN CERT/{c=""} {c=c $0 "\n"} /END CERT/{printf "%s", c | cmd; close(cmd)}' "$(gem contents httpclient | grep 'httpclient/cacert.pem$')" | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'
```

On 2.9.0 the fingerprint check prints the AAA root (D7:A7:A0:FB) and not the G3 root.

{: .caveats}
| Vulnerable {.bad} | Fixed {.bad} |
|---|---|
| 2.9.0, the latest release (AAA path) | No fix yet (still vulnerable on 2026-10-31) |

**AAA root:** Yes. The 2.9.0 bundle is Mozilla data from 2015 with the AAA root and no G3 root. Removing G3 elsewhere does not cover it

**Checker rules:** [PEM bundles](detections.html#d-pembundles)

[R236, R237, R238]
:::

::: {.eco #c-langs-13 status=fixed}
### Perl Mozilla::CA

**Where to look:** `lib/Mozilla/CA/cacert.pem`. IO::Socket::SSL clients use it only when no usable system store exists

```
# Locked version in cpanfile.snapshot
grep -o 'Mozilla-CA-[0-9]*' cpanfile.snapshot | sort -u

# Installed version
perl -MMozilla::CA -e 'print "$Mozilla::CA::VERSION\n"'

# G3 (86:A1:EC:BA) or AAA (D7:A7:A0:FB) fingerprints in the bundle. Affected if this prints anything
awk -v cmd='openssl x509 -noout -fingerprint -sha256' '/BEGIN CERT/{c=""} {c=c $0 "\n"} /END CERT/{printf "%s", c | cmd; close(cmd)}' "$(perl -MMozilla::CA -e 'print Mozilla::CA::SSL_ca_file()')" | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'
```

The fingerprint check prints one line per match and nothing on a clean bundle. 86:A1:EC:BA is the G3 root, D7:A7:A0:FB the AAA root.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| Before 20261020 (CVE-2026-113812) | 20261020 |

**AAA root:** In 20250202 and earlier. Dropped in 20250602. The 20261020 build denylist names AAA so it cannot return. No key block

**Checker rules:** [Perl Mozilla::CA](detections.html#d-perlmozillaca), [PEM bundles](detections.html#d-pembundles)

[R239, R240, R241, R242, R243, R238]
:::

::: {.eco #c-langs-14 status=fixed}
### Elixir castore

**Where to look:** `priv/cacerts.pem` in the package, path from `CAStore.file_path/0`

```
# Locked version
grep '"castore"' mix.lock

# Dependency tree
mix deps.tree

# G3 (86:A1:EC:BA) or AAA (D7:A7:A0:FB) fingerprints in the bundle. Affected if this prints anything
awk -v cmd='openssl x509 -noout -fingerprint -sha256' '/BEGIN CERT/{c=""} {c=c $0 "\n"} /END CERT/{printf "%s", c | cmd; close(cmd)}' deps/castore/priv/cacerts.pem \
  | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'
```

The fingerprint check prints one line per match and nothing on a clean bundle. 86:A1:EC:BA is the G3 root, D7:A7:A0:FB the AAA root.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| 1.0.21 and earlier | 1.0.22 |

**AAA root:** In 1.0.13 and earlier. Dropped in 1.0.14. No key block

**Checker rules:** [mix.lock](detections.html#d-mixlocks), [PEM bundles](detections.html#d-pembundles)

[R244, R245, R248, R238]
:::

::: {.eco #c-langs-15 status=fixed}
### Hex certifi (Erlang, Elixir)

**Where to look:** Compiled into the `certifi` module from `priv/cacerts.pem`

```
# Locked version
grep '"certifi"' mix.lock rebar.lock

# Dependency tree
mix deps.tree

# G3 (86:A1:EC:BA) or AAA (D7:A7:A0:FB) fingerprints in the bundle. Affected if this prints anything
awk -v cmd='openssl x509 -noout -fingerprint -sha256' '/BEGIN CERT/{c=""} {c=c $0 "\n"} /END CERT/{printf "%s", c | cmd; close(cmd)}' deps/certifi/priv/cacerts.pem \
  | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'
```

The fingerprint check prints one line per match and nothing on a clean bundle. 86:A1:EC:BA is the G3 root, D7:A7:A0:FB the AAA root. In a rebar3 project the file is under _build/default/lib/certifi/priv/. The compiled module keeps the old roots until the dependency is cleaned and rebuilt.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| 2.17.0 and earlier | 2.18.0, then a clean rebuild |

**AAA root:** In 2.14.0 and earlier. Dropped in 2.15.0. No key block

**Checker rules:** [mix.lock](detections.html#d-mixlocks), [PEM bundles](detections.html#d-pembundles)

[R246, R247, R248, R238]
:::

::: {.eco #c-langs-16 status=os}
### Erlang/OTP public_key

**Where to look:** No bundle. `public_key:cacerts_get/0` loads the OS store

```
# Where the code picks its trust store
grep -rnE 'cacerts_get|cacertfile|CAStore|certifi' --include='*.ex' --include='*.exs' --include='*.erl' .

# G3 (86:A1:EC:BA) or AAA (D7:A7:A0:FB) fingerprints in the bundle. Affected if this prints anything
awk -v cmd='openssl x509 -noout -fingerprint -sha256' '/BEGIN CERT/{c=""} {c=c $0 "\n"} /END CERT/{printf "%s", c | cmd; close(cmd)}' /etc/ssl/certs/ca-certificates.crt \
  | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'
```

The grep shows whether code uses the OS store or a bundle package. The bundle path is the Debian and Ubuntu one. The fingerprint check prints one line per match and nothing on a clean bundle. 86:A1:EC:BA is the G3 root, D7:A7:A0:FB the AAA root.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| Follows the OS store | Fix the OS store |

**AAA root:** Follows the OS store. Not checked

**Checker rules:** [OS CA bundles](detections.html#d-ostruststore), [OS ca-certificates package](detections.html#d-cacertificatespackage)

[R249, R244, R246, R238]
:::

::: {.eco #c-langs-17 status=os}
### .NET

**Where to look:** No bundle. Windows certificate store, macOS trust settings, Linux OpenSSL locations (`SSL_CERT_FILE`, `SSL_CERT_DIR`, then `/etc/ssl/certs`)

```
# Variables that point TLS at another bundle
env | grep -E '^SSL_CERT_(FILE|DIR)='

# G3 (86:A1:EC:BA) or AAA (D7:A7:A0:FB) fingerprints in the bundle. Affected if this prints anything
awk -v cmd='openssl x509 -noout -fingerprint -sha256' '/BEGIN CERT/{c=""} {c=c $0 "\n"} /END CERT/{printf "%s", c | cmd; close(cmd)}' /etc/ssl/certs/ca-certificates.crt \
  | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'
```

Linux. The bundle path is the Debian and Ubuntu one. On Linux the Disallowed store has no effect on chain building. The fingerprint check prints one line per match and nothing on a clean bundle. 86:A1:EC:BA is the G3 root, D7:A7:A0:FB the AAA root.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| Follows the OS store | Fix the OS store |

**AAA root:** Follows the OS store. Not checked

**Checker rules:** [OS CA bundles](detections.html#d-ostruststore), [OS ca-certificates package](detections.html#d-cacertificatespackage)

[R250, R251, R238]
:::

::: {.eco #c-langs-18 status=fixed}
### curl cacert.pem

**Where to look:** `cacert.pem`, also shipped as `ca-bundle.crt` or `curl-ca-bundle.crt`. Schannel builds use the Windows store

```
# Bundled CA files under the current directory
find . -name 'cacert*.pem' -o -name 'ca-bundle.crt' -o -name 'curl-ca-bundle.crt'

# Date of the bundle
grep -m1 'as of' cacert.pem

# G3 (86:A1:EC:BA) or AAA (D7:A7:A0:FB) fingerprints in the bundle. Affected if this prints anything
awk -v cmd='openssl x509 -noout -fingerprint -sha256' '/BEGIN CERT/{c=""} {c=c $0 "\n"} /END CERT/{printf "%s", c | cmd; close(cmd)}' cacert.pem \
  | grep -iE '86:A1:EC:BA:08:9C:4A:8D|D7:A7:A0:FB:5D:7E:27:31'

# curl version and TLS library
curl -V

# Variables that point TLS at another bundle
env | grep -E '^(CURL_CA_BUNDLE|SSL_CERT_FILE|SSL_CERT_DIR)='

# On Windows, the bundle file curl finds
where curl-ca-bundle.crt
```

The fingerprint check prints one line per match and nothing on a clean bundle. 86:A1:EC:BA is the G3 root, D7:A7:A0:FB the AAA root. Run the last command on Windows.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| cacert-2026-09-25 and earlier | cacert-2026-10-20 |

**AAA root:** None in revisions from 2025-08-12 on. Earlier revisions not checked. No key block

**Checker rules:** [PEM bundles](detections.html#d-pembundles)

[R252, R253, R254, R238]
:::

::: {.eco #c-langs-19 status=fixed}
### Dart, Flutter

**Where to look:** The OS store, but on Android and Windows `dart:io` checks chains with its own BoringSSL and ignores OS blocklists. Web, iOS and macOS are not affected

```
# Installed version
dart --version

# Installed version
flutter --version
```

Apps built with an older SDK stay exposed until rebuilt and redeployed. On Linux, apps are exposed only where the system ca-certificates bundle is old.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| Dart before 3.13.7 (GHSA-frr6-h895-5pxp) | Dart 3.13.7 or 3.14.0-315.3.beta, then rebuild |
| Flutter before 3.47.8 | Flutter 3.47.8 or 3.50.0-0.2.pre, then rebuild |

**AAA root:** Not checked. The fix distrusts the intermediates in BoringSSL. Whether it blocks by key, which would cover the AAA cross-signs, was not confirmed

**Checker rules:** None. Run the commands above.

[R255, R256]
:::

:::

## Browsers and apps {#g-apps}

{: .key}
**Chrome, Edge, Firefox and Safari receive block lists without a full update. Electron apps and the other tools here need their own update.**

::: {.stacks}

::: {.eco #c-apps-01 status=fixed}
### Google Chrome

**Where to look:** Chrome Root Store and CRLSet, both built into Chrome

No read-only command.

No local check. The CRLSet applies without an update or restart.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| Root Store v42 and earlier still hold the G3 root | CRLSet of 2026-10-17 blocks the keys. Root Store `v43` drops the root (Google's planned date for all devices: 2026-10-27) |

**AAA root:** Not in the Chrome Root Store (v41 to v43). The CRLSet blocks the AAA cross-signs by key

**Checker rules:** None. There is no local check.

[R257, R258]
:::

::: {.eco #c-apps-02 status=fixed}
### Microsoft Edge and WebView2

**Where to look:** Edge trust list and CRLSet, delivered by component updates

No read-only command.

Keep Edge component updates on.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| Edge trust list before 2026-10-27 still held the G3 roots | CRLSet block through component updates, then the trust list of 2026-10-27 |

**AAA root:** Removed from the Edge trust list on 2026-10-27 (disputed: Microsoft calls it a cross-sign, but its thumbprint is the AAA root)

**Checker rules:** None. Keep Edge component updates on.

[R259]
:::

::: {.eco #c-apps-03 status=fixed}
### Firefox (desktop and Android)

**Where to look:** Bundled NSS roots, which still trust the G3 root in 159.0, plus OneCRL from Remote Settings and a built-in copy

```
# Firefox version and bundled NSS version
about:support
```

Open it in the address bar. It shows the Firefox version and the bundled NSS version.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| Desktop `158.0` and earlier with Remote Settings disabled or unreachable | OneCRL push of 2026-10-17. Built in from `158.0.1`, key-based entries from `159.0` |
| Android `158.0.1` | Android `158.0.2` |

**AAA root:** Present but trusted for email only

**Checker rules:** None. Open about:support in the address bar.

[R260, R261, R262, R263, R266]
:::

::: {.eco #c-apps-04 status=fixed}
### Firefox ESR 153

**Where to look:** Bundled NSS 3.125, which still trusts the G3 root, plus OneCRL

```
# Firefox version and bundled NSS version
about:support
```

Open it in the address bar. It shows the Firefox version and the bundled NSS version.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `153.5.0` and earlier with Remote Settings disabled or unreachable | `153.5.1` (OneCRL built in). `153.6.0` adds key-based entries |

**AAA root:** Present but trusted for email only

**Checker rules:** None. Open about:support in the address bar.

[R260, R261, R262, R263]
:::

::: {.eco #c-apps-05 status=partial}
### Firefox ESR 115

**Where to look:** Bundled NSS 3.90.6, which still trusts the G3 root, plus OneCRL loaded after 20 idle seconds

```
# Firefox version and bundled NSS version
about:support
```

Open it in the address bar. Every released 115.x can trust the chains in a new profile until OneCRL loads.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `115.43.0` and earlier with Remote Settings disabled or unreachable | `115.43.1` per CVE-2026-113470 (disputed) |
| `115.43.1` and `115.44.0` in a new profile, until OneCRL loads after 20 idle seconds. `115.43.1` with Remote Settings disabled may never load the built-in list (disputed) | No fix yet. `115.45.0` closes the gap and was not released on 2026-10-31 |

**AAA root:** Present but trusted for email only. Once OneCRL loaded, the AAA cross-sign test hosts were blocked too

**Checker rules:** None. Open about:support in the address bar.

[R264, R261, R262]
:::

::: {.eco #c-apps-06 status=partial}
### Firefox forks without OneCRL (GNU IceCat)

**Where to look:** Bundled NSS roots, with no OneCRL

No read-only command.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| IceCat built from ESR 153.5.1 | Unconfirmed. The reporter's IceCat build from ESR 153.6.0 source passed the tracker test |

**AAA root:** Not checked

**Checker rules:** None. There is no read-only check.

[R265]
:::

::: {.eco #c-apps-07 status=fixed}
### Thunderbird

**Where to look:** Bundled NSS roots plus OneCRL

No read-only command.

Help > About shows the version.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `158.0` and `153.5` with Remote Settings disabled or unreachable | `158.0.1` and `153.5.1`. Current releases are `159.0` and ESR `153.6.0` |

**AAA root:** Not checked in Thunderbird

**Checker rules:** None. Check the version in Help > About.

[R267]
:::

::: {.eco #c-apps-08 status=fixed}
### NSS bundled in other apps

**Where to look:** The NSS copy an app ships (`lib/ckfw/builtins/certdata.txt` in the NSS source)

No read-only command.

Check which NSS version the app bundles.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `3.131` and earlier | `3.131.1`, `3.132` |

**AAA root:** Present, trusted for email only

**Checker rules:** None. Compare the app's NSS version with the table above.

[R268]
:::

::: {.eco #c-apps-09 status=fixed}
### Safari, Mail and Apple frameworks

**Where to look:** Apple trust data, pushed to devices

No read-only command.

No check needed. Command-line tools that read /etc/ssl/cert.pem are covered in the OS section.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| None found for Safari, Mail and apps on Apple's frameworks | Trust data since 2026-10-19 (12 certificates) and 2026-10-23 (G3 root), with no software update |

**AAA root:** Apple blocks the six AAA cross-signs directly

**Checker rules:** None. No check is needed.

[R269]
:::

::: {.eco #c-apps-10 status=fixed}
### Electron 42, 43 and 45 beta

**Where to look:** macOS: `Contents/Frameworks/Electron Framework.framework` in the app bundle. Linux: the app's main binary

```
# Electron version of the app
plutil -extract CFBundleVersion raw "/Applications/<App>.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Resources/Info.plist"

# Electron version from the app binary
grep -a -o 'Electron/[0-9][0-9.]*' "<app binary>" | sort -u

# 1 if Electron holds the G3 root. Fixed releases print 1 too
grep -ac 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' "/Applications/<App>.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework"
```

The first two read the Electron version without running the app, and the second also works on a Linux app's main binary. The third prints 1 on every Electron release checked, fixed ones included. A G3 root inside a fixed Electron binary is expected, because Electron's fix blocks the intermediates and leaves the root in place. Use it only to confirm a bundled Node.js root store.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| Below `42.11.16` | `42.11.16` per the advisory |
| `43.0.0-alpha.1` to below `43.8.1` | `43.8.1` per the advisory |
| `45.0.0-alpha.1` to below `45.0.0-beta.6` | `45.0.0-beta.6` per the advisory |

**AAA root:** Not checked

**Checker rules:** [Electron apps](detections.html#d-electronapps), [Electron updater caches](detections.html#d-updatercaches), [Electron in node_modules and package.json](detections.html#d-electronpackages)

[R270, R272, R273, R274, R275, R271]
:::

::: {.eco #c-apps-11 status=fixed}
### Electron 44

**Where to look:** macOS: `Contents/Frameworks/Electron Framework.framework` in the app bundle. Linux: the app's main binary

```
# Electron version of the app
plutil -extract CFBundleVersion raw "/Applications/<App>.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Resources/Info.plist"

# Electron version from the app binary
grep -a -o 'Electron/[0-9][0-9.]*' "<app binary>" | sort -u

# 1 if Electron holds the G3 root. Fixed releases print 1 too
grep -ac 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' "/Applications/<App>.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework"
```

The first two read the Electron version without running the app, and the second also works on a Linux app's main binary. The third prints 1 on every Electron release checked, fixed ones included. A G3 root inside a fixed Electron binary is expected, because Electron's fix blocks the intermediates and leaves the root in place. Use it only to confirm a bundled Node.js root store.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `44.0.0-alpha.1` to below `44.9.1` | `44.9.1` per the advisory |

**AAA root:** Not checked

**Checker rules:** [Electron apps](detections.html#d-electronapps), [Electron updater caches](detections.html#d-updatercaches), [Electron in node_modules and package.json](detections.html#d-electronpackages)

[R271, R270, R273, R274, R275]
:::

::: {.eco #c-apps-12 status=fixed}
### Visual Studio Code

**Where to look:** `Visual Studio Code.app/Contents/Frameworks/Electron Framework.framework` on macOS, and the remote server's bundled Node.js

```
# Electron version of the app
plutil -extract CFBundleVersion raw "/Applications/Visual Studio Code.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Resources/Info.plist"

# 1 if Electron holds the G3 root. Fixed releases print 1 too
grep -ac 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' "/Applications/Visual Studio Code.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework"
```

1.144.0 reports Electron 43.8.3. The second command prints 1 on Electron 43.8.3 too, so judge the fix by the Electron version.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| Desktop `1.143.1` and earlier (Electron `43.7.7`, below the advisory's `43.8.1`). Disputed: the community tracker lists 1.143.1 as patched | Desktop `1.144.0` (Electron `43.8.3`) |
| Remote server `1.143.0` and earlier (Node.js `24.21.0`) | Remote server `1.143.1` (Node.js `24.22.1`) |

**AAA root:** Not checked

**Checker rules:** [Electron apps](detections.html#d-electronapps), [Electron updater caches](detections.html#d-updatercaches)

[R276, R277, R273, R275]
:::

::: {.eco #c-apps-13 status=fixed}
### Obsidian

**Where to look:** `Obsidian.app/Contents/Frameworks/Electron Framework.framework` on macOS

```
# Electron version of the app
plutil -extract CFBundleVersion raw "/Applications/Obsidian.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Resources/Info.plist"
```

1.14.5 reports Electron 43.8.3. The update needs a reinstall from Obsidian's website.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| Below `1.14.5` (Electron `43.7.5`) | `1.14.5` (Electron `43.8.3`) |

**AAA root:** Not checked

**Checker rules:** [Electron apps](detections.html#d-electronapps)

[R278, R273]
:::

::: {.eco #c-apps-14 status=fixed}
### Other Electron apps

**Where to look:** macOS: `Contents/Frameworks/Electron Framework.framework` in the app bundle. Linux: the app's main binary

```
# Electron version of the app
plutil -extract CFBundleVersion raw "/Applications/<App>.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Resources/Info.plist"

# Electron version from the app binary
grep -a -o 'Electron/[0-9][0-9.]*' "<app binary>" | sort -u

# 1 if Electron holds the G3 root. Fixed releases print 1 too
grep -ac 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' "/Applications/<App>.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework"
```

The first two read the Electron version without running the app, and the second also works on a Linux app's main binary. The third prints 1 on every Electron release checked, fixed ones included. A G3 root inside a fixed Electron binary is expected, because Electron's fix blocks the intermediates and leaves the root in place. Use it only to confirm a bundled Node.js root store.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| Apps on Electron below `42.11.16`, `43.0.0-alpha.1` to below `43.8.1`, `44.0.0-alpha.1` to below `44.9.1`, or `45.0.0-alpha.1` to below `45.0.0-beta.6` | The app's own release on Electron `42.11.16`, `43.8.1`, `44.9.1` or `45.0.0-beta.6` or later |

**AAA root:** Not checked

**Checker rules:** [Electron apps](detections.html#d-electronapps), [Electron updater caches](detections.html#d-updatercaches)

[R272, R270, R271, R273, R274, R275]
:::

::: {.eco #c-apps-15 status=fixed}
### Git for Windows

**Where to look:** `ucrt64\etc\ssl\certs\ca-bundle.crt` under the Git install (MinGit layout)

```
# Installed version
git --version
```

2.56.0.windows.3 or later is fixed.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `2.56.0(2)` and earlier | `2.56.0(3)` |

**AAA root:** Absent from 2.56.0(2) and 2.56.0(3)

**Checker rules:** None. Run the command above.

[R279]
:::

::: {.eco #c-apps-16 status=fixed}
### certbot

**Where to look:** certifi `cacert.pem` pinned by certbot

```
# Installed version
certbot --version
```

5.9.0 or later pins certifi 2026.10.19.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `5.8.0` (certifi `2026.7.22`) and earlier Docker images, and other builds made with `tools/pip_install.py`. Other installs use whatever certifi is installed | `5.9.0` (certifi `2026.10.19`). Disputed. The community tracker still lists certbot as pending |

**AAA root:** Absent from certifi 2026.07.22 and 2026.10.19 in the certbot images

**Checker rules:** [certifi, pip and uv packages](detections.html#d-pythondistinfo), [PEM bundles](detections.html#d-pembundles)

[R280, R303]
:::

::: {.eco #c-apps-17 status=unfixed}
### containerd

**Where to look:** Go toolchain built into the `containerd` binary

```
# Go version the binary was built with
grep -a -o 'go1\.[0-9]*\.[0-9]*' "$(command -v containerd)" | head -1
```

Prints the Go version the binary was built with.

{: .caveats}
| Vulnerable {.bad} | Fixed {.bad} |
|---|---|
| `v2.4.2` and earlier | No fix yet. Go 1.27.3 and 1.26.10 are merged but unreleased |

**AAA root:** Not checked

**Checker rules:** [Go binaries](detections.html#d-gobinaries)

[R281]
:::

::: {.eco #c-apps-18 status=fixed}
### Docker Engine

**Where to look:** Go toolchain built into `docker`, `dockerd` and `containerd`

```
# Installed version
docker version

# Go version the binary was built with
grep -a -o 'go1\.[0-9]*\.[0-9]*' "$(command -v dockerd)" | head -1
```

29.9.2 or later, built with go1.26.10, is fixed.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `29.9.1` and earlier (go1.26.9) | `29.9.2` (go1.26.10), including its static containerd binary |

**AAA root:** Not checked

**Checker rules:** [Go binaries](detections.html#d-gobinaries)

[R282]
:::

::: {.eco #c-apps-19 status=fixed}
### Docker Desktop

**Where to look:** Docker Desktop and its bundled Engine

No read-only command.

Docker Desktop > About shows the version.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `4.96.0` and earlier | `4.96.3` |
| `4.96.1` and `4.96.2`, partial fix | `4.96.3`, the first without the partial-fix note. Disputed. The community tracker lists 4.96.2 |

**AAA root:** Not checked

**Checker rules:** [Go binaries](detections.html#d-gobinaries) reads the Docker CLI binaries in the app. It doesn't read the engine inside the app's VM, and it can pass the partly fixed 4.96.1 and 4.96.2. Check the version in Docker Desktop > About.

[R283]
:::

::: {.eco #c-apps-20 status=fixed}
### GitHub CLI

**Where to look:** Go toolchain built into `gh`

```
# Installed version
gh --version
```

2.102.1 or later is fixed.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `2.102.0` and earlier (go1.27.1) | `2.102.1` (go1.27.3) |

**AAA root:** Not checked

**Checker rules:** [Go binaries](detections.html#d-gobinaries)

[R284]
:::

::: {.eco #c-apps-21 status=unfixed}
### Podman

**Where to look:** Go toolchain built into `podman`

```
# Installed version
podman version
```

It shows the Go version Podman was built with.

{: .caveats}
| Vulnerable {.bad} | Fixed {.bad} |
|---|---|
| `6.1.4`, `5.8.9` and earlier | No fix yet. `6.2.0-rc1` does not mention eMudhra |

**AAA root:** Not checked

**Checker rules:** [Go binaries](detections.html#d-gobinaries)

[R285]
:::

::: {.eco #c-apps-22 status=os}
### podman machine VM (macOS, Windows)

**Where to look:** `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem` inside the VM

```
# VM ca-certificates version and G3 count. Affected if the count is above 0
podman machine ssh 'rpm -q ca-certificates; grep -c "emSign ECC Root CA - G3" /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem'
```

A count above 0 means the VM still trusts the G3 root.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| A VM with an unfixed Fedora ca-certificates | Fedora ca-certificates `2026.2.92_v9.0.319`, per the community tracker |

**AAA root:** Not checked

**Checker rules:** None. Run the command above.

[R286]
:::

::: {.eco #c-apps-23 status=unfixed}
### Godot

**Where to look:** `thirdparty/certs/` CA file in the engine source (`ca-bundle.crt` in Godot 4, `ca-certificates.crt` in Godot 3)

No read-only command.

Help > About Godot shows the version.

{: .caveats}
| Vulnerable {.bad} | Fixed {.bad} |
|---|---|
| `4.7.2-stable` and the 4.7 and 4.6 branches | No fix yet. Fixed on master only (merged 2026-10-21) |
| `3.6.3-stable` and the 3.x branch | No fix yet |

**AAA root:** Present in Godot 3.6.3 and the 3.x branch. Absent from the Godot 4 bundles

**Checker rules:** None. Check the version in Help > About Godot.

[R287, R288]
:::

::: {.eco #c-apps-24 status=fixed}
### LibreOffice 26.8

**Where to look:** Bundled NSS, version set in `download.lst`

No read-only command.

Help > About shows the version.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `26.8.1` and earlier | `26.8.2` (NSS `3.131.1` in RC1, `3.132` in RC2). Disputed. The community tracker lists LibreOffice as pending |

**AAA root:** Present in NSS 3.131.1 and 3.132, trusted for email only

**Checker rules:** None. Check the version in Help > About.

[R289, R268]
:::

::: {.eco #c-apps-25 status=unfixed}
### LibreOffice 26.2

**Where to look:** Bundled NSS, version set in `download.lst`

No read-only command.

Help > About shows the version.

{: .caveats}
| Vulnerable {.bad} | Fixed {.bad} |
|---|---|
| `26.2.6` (NSS `3.128`) | No fix yet. `26.2.7` RC2 bundles NSS `3.132`, RC3 due week 44 |

**AAA root:** Not checked for NSS 3.128. Present in NSS 3.132, trusted for email only

**Checker rules:** None. Check the version in Help > About.

[R290, R268]
:::

::: {.eco #c-apps-26 status=unfixed}
### OpenHarmony

**Where to look:** System CA set in `security_certificate_manager`

No read-only command.

{: .caveats}
| Vulnerable {.bad} | Fixed {.bad} |
|---|---|
| Not checked. The community tracker lists OpenHarmony as pending | No fix yet. Pull request 722 is merged to master with no release |

**AAA root:** Not checked

**Checker rules:** None. There is no read-only check.

[R291]
:::

::: {.eco #c-apps-27 status=fixed}
### JetBrains Runtime 25 (25.0.4.1)

**Where to look:** `lib/security/cacerts` and `lib/security/blocked.certs` in the JBR directory

```
# JBR build
grep IMPLEMENTOR_VERSION "<jbr>/release"

# Block list entries. 0 means the block list is missing
grep -c -i 0164D7CEAE5BB909 "<jbr>/lib/security/blocked.certs"

# Any emSign or Comodo AAA entry in cacerts
keytool -list -keystore "<jbr>/lib/security/cacerts" -storepass changeit \
  | grep -iE 'emsign|comodoaaa'
```

Run these against the JBR directory. A blocked.certs count of 0 means the block list is missing. On b635.79 a byte search of cacerts finds no emSign or AAA Certificate Services entry. The keytool line was not run.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| Builds before `b635.78` (not checked) | `b635.78` block list |
| `b635.78` blocks the 16 certificates but keeps the G3 and AAA roots in `cacerts` | `b635.79` removes both roots |

**AAA root:** In the `b635.78` `cacerts`, removed in `b635.79`. Both block the 16 compromised certificates, cross-signs included

**Checker rules:** [Java keystores](detections.html#d-javakeystores)

[R292, R293]
:::

:::

## Container images {#g-images}

{: .key}
**A container trusts only the bundle inside its image. Check the image itself and rebuild on a fixed base.**

::: {.stacks}

::: {.eco #c-images-01 status=os}
### Any container image

**Where to look:** `/etc/ssl/certs/ca-certificates.crt` or the distro's bundle inside the image

```
# Copy the image’s bundle out
docker run --rm --network none --entrypoint cat <image> /etc/ssl/certs/ca-certificates.crt > bundle.pem

# The same copy for an image with no shell
id=$(docker create <image> x)
docker cp "$id":/etc/ssl/certs/ca-certificates.crt bundle.pem
docker rm "$id"

# Roots still in the copied bundle. Affected if this prints anything
openssl crl2pkcs7 -nocrl -certfile bundle.pem \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign ECC Root CA - G3|AAA Certificate Services'
```

Use the second form for images with no shell. The trailing x stands in for a command, since distroless images set none, and the container is never started. The last command prints nothing when neither root is in the bundle.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| Any image built before its distro's fixed ca-certificates | Rebuild on a fixed base, or upgrade ca-certificates in the build |

**AAA root:** Check for it along with the G3 root. Some images still hold it

**Checker rules:** [Podman images](detections.html#d-podmanimages), [OS ca-certificates package](detections.html#d-cacertificatespackage)

[R294, R295]
:::

::: {.eco #c-images-02 status=os}
### debian and ubuntu official images

**Where to look:** None in the base image. It comes from whatever a later build step installs

```
# Bundle files and the ca-certificates version in the image
docker run --rm --network none --entrypoint sh <image> -c 'ls /etc/ssl/certs; dpkg-query -W ca-certificates'
```

On the base images both commands find nothing. Run it on your built image to see what a later layer installed.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| No bundle in `debian:bookworm-20261027`, `debian:bookworm-20261005-slim` or `ubuntu:noble-20261024.1` | Depends on the ca-certificates a later layer installs |

**AAA root:** No bundle in the base image

**Checker rules:** [Podman images](detections.html#d-podmanimages), [OS ca-certificates package](detections.html#d-cacertificatespackage)

[R296]
:::

::: {.eco #c-images-03 status=fixed}
### alpine

**Where to look:** `/etc/ssl/certs/ca-certificates.crt`, package version in `/lib/apk/db/installed`

```
# Installed ca-certificates version in the image
docker run --rm --network none --entrypoint sh alpine:<tag> -c 'grep -A2 "^P:ca-certificates" /lib/apk/db/installed'
```

20261020-r0 is fixed.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `3.24.2` (ca-certificates-bundle `20260909-r0`) | `3.24.3` (`20261020-r0`) |

**AAA root:** Absent from 3.24.2 and 3.24.3

**Checker rules:** [Podman images](detections.html#d-podmanimages), [OS ca-certificates package](detections.html#d-cacertificatespackage)

[R297]
:::

::: {.eco #c-images-04 status=unfixed}
### distroless Debian 12 (static-debian12, base-debian12)

**Where to look:** `/etc/ssl/certs/ca-certificates.crt`, package version in `/var/lib/dpkg/status.d/ca-certificates`

```
# Copy the dpkg entry and the bundle out without starting the container
id=$(docker create gcr.io/distroless/static-debian12:latest x)
docker cp "$id":/var/lib/dpkg/status.d/ca-certificates ca-certificates.status
docker cp "$id":/etc/ssl/certs/ca-certificates.crt bundle.pem
docker rm "$id"

# Installed ca-certificates version
grep '^Version' ca-certificates.status

# Roots still in the copied bundle. Affected if this prints anything
openssl crl2pkcs7 -nocrl -certfile bundle.pem \
  | openssl pkcs7 -print_certs -noout \
  | grep -E 'emSign ECC Root CA - G3|AAA Certificate Services'
```

Distroless has no shell, so this copies the dpkg status entry and the bundle out without starting the container. The trailing x stands in for a command, since the image sets none. 20250419~deb12u1 is unfixed. Check base-debian12 the same way.

{: .caveats}
| Vulnerable {.bad} | Fixed {.bad} |
|---|---|
| `:latest` with ca-certificates `20250419~deb12u1`, still vulnerable on 2026-10-31 | No fix yet |

**AAA root:** Present

**Checker rules:** None. Run the commands above.

[R298, R295]
:::

::: {.eco #c-images-05 status=fixed}
### distroless Debian 13 (static-debian13)

**Where to look:** `/etc/ssl/certs/ca-certificates.crt`, package version in `/var/lib/dpkg/status.d/ca-certificates`

```
# Copy the dpkg entry out without starting the container
id=$(docker create gcr.io/distroless/static-debian13:latest x)
docker cp "$id":/var/lib/dpkg/status.d/ca-certificates ca-certificates.status
docker rm "$id"

# Installed ca-certificates version
grep '^Version' ca-certificates.status
```

The trailing x stands in for a command, since the image sets none. 20250419+deb13u1 is fixed.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| None seen | `:latest` with ca-certificates `20250419+deb13u1` |

**AAA root:** Absent

**Checker rules:** None. Run the commands above.

[R299, R295]
:::

::: {.eco #c-images-06 status=unfixed}
### Rocky Linux (rockylinux/rockylinux)

**Where to look:** `/etc/pki/ca-trust/extracted/pem/` (TLS, email and code-signing bundles)

```
# Installed ca-certificates version in the image
docker run --rm --network none --entrypoint rpm rockylinux/rockylinux:9 -q ca-certificates
```

2026.2.92_v9.0.319 builds are fixed. Check every bundle in /etc/pki/ca-trust/extracted/pem/, since AAA sits in the email and code-signing bundles.

{: .caveats}
| Vulnerable {.bad} | Fixed {.bad} |
|---|---|
| `:8` ships `2023.2.60_v7.0.306-80.0.el8_8`, with G3 and AAA in the TLS bundle | `2026.2.92_v9.0.319-81.3.el8_10` via dnf upgrade or a rebuild |
| `:9` ships `2025.2.80_v9.0.305-91.el9` | `2026.2.92_v9.0.319-90.3.el9_8` via dnf upgrade or a rebuild |
| `:10` ships `2025.2.80_v9.0.305-102.el10` | `2026.2.92_v9.0.319-100.3.el10_2` via dnf upgrade or a rebuild |

**AAA root:** Rocky 9 and 10 unfixed builds: absent from the TLS bundle, present in the email and code-signing bundles. The rockylinux:8 image holds it in the TLS bundle too

**Checker rules:** [Podman images](detections.html#d-podmanimages), [OS ca-certificates package](detections.html#d-cacertificatespackage)

[R300]
:::

::: {.eco #c-images-07 status=unfixed}
### Amazon Linux (amazonlinux)

**Where to look:** System bundle from the `ca-certificates` RPM

```
# Installed ca-certificates version in the image
docker run --rm --network none --entrypoint rpm amazonlinux:2023 -q ca-certificates

# Latest changelog entries
docker run --rm --network none --entrypoint rpm amazonlinux:2023 -q --changelog ca-certificates \
  | head -20
```

On AL2023 a plain dnf update keeps 0.3. Add --releasever=latest when you upgrade in the build.

{: .caveats}
| Vulnerable {.bad} | Fixed {.bad} |
|---|---|
| `amazonlinux:2023` with `2025.2.76-1.0.amzn2023.0.3` | `0.4` with `--releasever 2023.12.20261026`, or `0.5` with `--releasever=latest` |
| `amazonlinux:2` with `2025.2.76-1.amzn2.0.2` | `2025.2.76-1.amzn2.0.3` |

**AAA root:** Amazon says it has been untrusted for TLS since 2025. AL2 0.4 and AL2023 0.5 remove it from the package

**Checker rules:** [Podman images](detections.html#d-podmanimages), [OS ca-certificates package](detections.html#d-cacertificatespackage)

[R301]
:::

::: {.eco #c-images-08 status=fixed}
### python official images

**Where to look:** `/etc/ssl/certs/ca-certificates.crt` and pip's vendored certifi

```
# Installed ca-certificates version in the image
docker run --rm --network none --entrypoint dpkg-query python:3.13-slim-bookworm -W ca-certificates

# certifi version that pip vendors in the image
docker run --rm --network none --entrypoint sh python:3.13-slim-bookworm -c 'grep __version__ /usr/local/lib/python3*/site-packages/pip/_vendor/certifi/__init__.py'
```

Only python:3.13-slim-bookworm was checked. Run the same on the tag you use.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| None seen in python:3.13-slim-bookworm on 2026-10-31 | Debian ca-certificates `20250419~deb12u2`, pip certifi `2026.10.19` |

**AAA root:** Not checked in the Debian bundle. Absent from certifi 2026.10.19

**Checker rules:** [Podman images](detections.html#d-podmanimages), [OS ca-certificates package](detections.html#d-cacertificatespackage), [certifi and pip of python3](detections.html#d-hostpythonpackages)

[R302]
:::

::: {.eco #c-images-09 status=fixed}
### certbot/certbot images

**Where to look:** certifi `cacert.pem` under `/usr/local/lib/python3.14/site-packages/certifi/`, and the Alpine bundle

```
# certifi version in the image
docker run --rm --network none --entrypoint sh certbot/certbot:<tag> -c 'grep __version__ /usr/local/lib/python3*/site-packages/certifi/__init__.py'

# Installed ca-certificates version in the image
docker run --rm --network none --entrypoint sh certbot/certbot:<tag> -c 'grep -A2 "^P:ca-certificates" /lib/apk/db/installed'
```

certifi 2026.10.19 and Alpine 20261020-r0 are fixed. The certbot/dns-* images were not checked.

{: .caveats}
| Vulnerable {.bad} | Fixed {.good} |
|---|---|
| `v5.8.0` (certifi `2026.07.22`, Alpine `20260611-r0`) | `v5.9.0` (certifi `2026.10.19`, Alpine `20261020-r0`) |

**AAA root:** Absent from both images' certifi

**Checker rules:** [Podman images](detections.html#d-podmanimages), [certifi and pip of python3](detections.html#d-hostpythonpackages), [OS ca-certificates package](detections.html#d-cacertificatespackage)

[R303]
:::

:::

:::

<footer>
  <div class="wrap"><p>eMudhra G3 intermediate CA key compromise, October 2026. An independent guide, not affiliated with eMudhra or Sectigo.</p><p>Last updated 2026-11-05. <a href="https://github.com/fieldse/emudhra-ca-compromise-check">Source on GitHub</a>.</p></div>
</footer>
