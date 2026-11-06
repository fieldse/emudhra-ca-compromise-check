---
title: eMudhra G3 CA compromise: fixing each area
description: How to fix each area after the eMudhra G3 CA compromise, where the obvious fix falls short, and what to do until a fix ships: OS trust stores, Java, Python, JavaScript runtimes, other languages, apps and container images.
output: fixes.html
refs: none
---

<header class="band">
  <div class="wrap">
    <a class="back" href="index.html">← Back to the guide</a>
    <p class="tags"><span>eMudhra G3</span><span>CA key compromise</span><span>October 2026</span></p>
    <p class="ids"><a href="index.html">Guide</a> &nbsp;·&nbsp; <a href="incident.html">Incident</a> &nbsp;·&nbsp; <a href="checks.html">Affected software</a> &nbsp;·&nbsp; Fixes &nbsp;·&nbsp; <a href="detections.html">Checker rules</a> &nbsp;·&nbsp; <a href="proof.html">Proof</a> &nbsp;·&nbsp; <a href="references.html">References</a></p>
    <h1><span class='hl'>eMudhra G3</span> CA compromise<br>Fixing each area</h1>
    <p>The <a href="index.html#manual">manual checks</a> tell you whether something is affected. This page says how to fix each area, where the obvious fix falls short, and what to do when there’s no fix yet.</p>
  </div>
</header>

::: {tag=main .wrap}

<nav class="toc read" aria-label="Contents"><h2>Contents</h2><ol>
  <li><a href="#mitigate">Remove AAA Certificate Services with G3</a><span>The rule for every store you fix by hand</span></li>
  <li><a href="#a-os">OS trust stores</a><span>Linux, macOS, Windows and Android</span></li>
  <li><a href="#a-java">Java</a><span>Every JDK, the Debian Java keystore and application truststores</span></li>
  <li><a href="#a-python">Python</a><span>pip, certifi, venvs, uv, Pixi and conda</span></li>
  <li><a href="#a-js">JavaScript runtimes</a><span>Node.js, Bun, Deno and node_modules</span></li>
  <li><a href="#a-langs">Other languages</a><span>Go, Rust, PHP, Ruby, Perl, .NET, Dart and the CA packages they use</span></li>
  <li><a href="#a-apps">Browsers and apps</a><span>Firefox ESR 115, Electron and apps with their own bundle</span></li>
  <li><a href="#a-images">Container images</a><span>Base images, distroless images and the podman machine VM</span></li>
  <li><a href="#sources">Sources</a><span>Where each claim comes from</span></li>
</ol></nav>

## Remove AAA Certificate Services with G3 {.read #mitigate}

{: .key}
**Remove AAA Certificate Services along with emSign ECC Root CA - G3. Removing G3 alone leaves the six Sectigo TLS cross-signs trusted through AAA [R040, R104].**

{: .read}
Mozilla advised distributions that cannot block the intermediates to consider removing AAA Certificate Services, emSign Root TLS CA - G3 and emSign ECC Root CA - G3 [R047, R048].

## Fixes by area {#caveats}

::: {.eco #a-os}
### OS trust stores

**Fix:** update the OS. Most Linux distributions removed `emSign ECC Root CA - G3` from their CA package [R049]. Windows blocks the eight keys through the Disallowed CTL [R106, R107], and Android received its block through Google Play services on 19 October 2026 [R110].

#### Where the fix falls short

{: .notes}
- **Check for `AAA Certificate Services` as well as G3.** Unfixed Debian packages and the Ubuntu 22.04 and 24.04 release builds hold it [R053, R057]. Unfixed Red Hat-family packages hold it in the email and code-signing bundles [R070].
- **Check the code-signing bundle on Fedora and CentOS Stream 10.** Fedora’s first update and CentOS Stream 10’s current build take G3 out of TLS trust but still trust `emSign Root CS CA - G3` for code signing [R063, R072].
- **Match RHEL against the .3 builds.** On RHEL only the .3 builds are advisory versions [R069].
- **Fix `/etc/ssl/cert.pem` on macOS by hand.** curl, git, python3, ruby, perl and openssl from macOS or the Command Line Tools trust `/etc/ssl/cert.pem` and skip Apple’s block and revocation checks [R098]. macOS 26.6.2 ships it with both roots, and its `/usr/bin/curl` completes HTTPS to hosts serving the compromised chains (checked 2026-10-31) [R099, R100].
- **Keep the removed roots out on Windows.** On 26 October 2026 Windows removed seven certificates, including one Microsoft calls an AAA Certificate Services cross-sign, whose thumbprint is the AAA root’s [R106, R107]. Microsoft says software that doesn’t reliably check revocation or its disallowed list can still accept the compromised chains if it keeps or restores trust in the removed roots [R109].
- **Update Windows apps that carry their own CA bundle.** The community tracker says they need their own update [R109].

#### No fix yet

These releases had no fixed package on 2026-10-31:

{: .caveats}
| Release | Newest package checked |
|---|---|
| Debian 11 | Still trusts the G3 and AAA roots [R055] |
| openSUSE Leap 15.6 | Still trusts the G3 root [R091] |
| openSUSE Tumbleweed on aarch64 | Still trusts the G3 root [R090] |
| Amazon Linux 2027 preview | No fixed package [R081] |

{: #s-os}
#### Until a fix ships

{: .notes}
- **macOS:** Remove the roots from `/etc/ssl/cert.pem` with Apple’s interim steps, which remove `emSign ECC Root CA - G3` and optionally `AAA Certificate Services` [R104]. A macOS update can replace the file, so re-check it after every update [R103]. The community tracker reports that 27.2 undid hand edits [R102].
- **Bottlerocket 1.67.0 and earlier:** Apply AWS’s `settings.pki` override. It sets `trusted = false` for emSign ECC Root CA - G3, C3 and C1 through `apiclient apply` until the node runs 1.68.0 [R085]. The override does not list AAA, which is not in the bundle 1.67.0 uses [R085, R084].
- **Disconnected Windows devices:** Deliver the updated CTLs another way, because without automatic updates or internet access the CTL Updater cannot fetch them [R108]. Microsoft gives `01dd5f6ca45c9d86` as the sequence number of the Disallowed CTL with the eMudhra block [R106].
- **Android devices without the Play services block:** Restart first, which triggers the update [R110]. Failing that, the community tracker suggests disabling `emSign ECC Root CA - G3` and `AAA Certificate Services` under Settings, Trusted credentials, System [R111].

[Every OS item, command and fixed version →](checks.html#g-os)
:::

::: {.eco #a-java}
### Java

**Fix:** upgrade each JDK to a build that removes both G3 and `AAA Certificate Services`, then restart every running JVM [R116, R117]. A JVM keeps the old store until it restarts [R126].

#### Where the fix falls short

{: .notes}
- **Check every JDK on the machine.** Each installation has its own `cacerts` [R126].
- **Grep for fingerprints and owner names.** The same G3 root sits under four alias styles [R119]. `keytool -list` prints SHA-256 fingerprints by default and `-v` adds the owner, so grep for both [R120, R121].
- **Rebuild Debian and Ubuntu’s Java keystore after updating `ca-certificates`.** The package update doesn’t refresh `/etc/ssl/certs/java/cacerts` [R157]. Run these as root to rebuild it [R158]:

  ```
  rm -f /etc/ssl/certs/java/cacerts
  update-ca-certificates --fresh
  ```
- **Clean application truststores by hand.** They keep the roots until you remove them. Run the `keytool -delete` from the stopgap below with `-keystore` and the file’s password [R159].
- **Update Homebrew and FreeBSD OpenJDK on their own.** They carry their own store and need their own update [R150].
- **Don’t go by the version number.** The .0.2 builds from OpenJDK, Oracle and SapMachine still hold G3 and AAA, but Temurin 27.0.1.0.2+1 is fixed [R127, R131, R154, R138]. Azul’s fixed Zulu 21 subscriber build reports JDK 21.0.12.1, and the free 21.0.13 build still holds all four roots [R151, R152].
- **Expect one `BAD ROOT` line on fixed Temurin.** It keeps G1 on purpose, so OpenJDK’s `CheckCerts` prints `BAD ROOT: CN=emSign Root CA - G1,…` there [R141, R125].
- **Expect emSign C1 and C3 in fixed Corretto.** A reply on Corretto’s issue tracker says they don’t chain to the compromised intermediates [R146].

#### No fix yet

These builds had no fix on 2026-10-31:

{: .caveats}
| Build | Status |
|---|---|
| Temurin 8 and 11 | Still trusts G3 [R139] |
| `eclipse-temurin:27-jre` | Still trusts G3 [R138] |
| The free Azul Zulu 21 build (disputed) | Still holds G3 and AAA [R152] |
| Microsoft Build of OpenJDK 21 and 25 | Still holds G3 and AAA [R153] |
| IBM Semeru 8 and 11 | IBM names no fix [R156] |
| Oracle GraalVM | No fixed build was found [R132] |

{: #s-java}
#### Until a fix ships

{: .notes}
- **Delete G3 and AAA from each `cacerts` under the vendor’s own alias.** OpenJDK’s stopgap [R123]:
  1. Back up the file.
  2. Run `keytool -delete -cacerts -alias "emsigneccrootcag3 [jdk]"` for each of the four `[jdk]` aliases.
  3. Ignore "does not exist" errors.
  4. Restart running JVMs.
- **Find the alias first on Temurin, Microsoft and Corretto.** The `[jdk]` alias names miss Temurin, Microsoft and Corretto’s second copy. Run the fingerprint check with `grep -B1` first to print each matching entry’s alias [R119, R120].
- **On JDK 8, point keytool at the file.** Use `-keystore "$JAVA_HOME/jre/lib/security/cacerts"` in place of `-cacerts` [R122].
- **Turn on revocation checking as a last resort.** For TLS clients, OpenJDK suggests adding `-Dcom.sun.net.ssl.checkRevocation=true -Dcom.sun.security.enableCRLDP=true` to the `java` command line. For signed JARs on JDK 17 and later, it suggests `jarsigner -verify -revcheck -strict` on each JAR [R124].

[Every Java item, command and fixed version →](checks.html#g-java)
:::

::: {.eco #a-python}
### Python

**Fix:** upgrade pip to 26.2.2 and certifi to 2026.10.19 in every venv [R168, R162]. Python 3.15.2, 3.14.10, 3.13.18, 3.12.16 and 3.11.18 add an `ssl` block on the compromised keys that also catches the Sectigo cross-signs [R177].

#### Where the fix falls short

{: .notes}
- **Upgrade pip in every venv.** Each venv keeps its own pip, so upgrading the interpreter leaves existing venvs on their old pip [R171, R176]. A venv has a `pyvenv.cfg` at its root, so search for that file to find them all [R171].
- **Treat venvs made by Python 3.11 and 3.12 as affected.** Current releases bundle pip 24.0 and 25.0.1, both holding G3 and the AAA root. A reply on the PSF thread says security releases will not upgrade them [R178].
- **Don’t count on a fixed OS store to fix pip.** pip always trusts its vendored certifi. From pip 24.2 on Python 3.10 and later it also trusts the OS store [R167, R169].
- **Skip certifi 2026.10.18.** GHSA-6q48-6c7w-9gw2 names it as the first patched release, and the PSF recommends 2026.10.19 [R162]. 2026.10.18 removed every emSign root, including the unaffected G1, C1 and C3, and users reported broken connections [R161]. 2026.10.19 restores those three and still leaves out G3 [R162].
- **Check old certifi pins for AAA.** The advisory range starts at 2019.03.09 and covers the G3 root only. Every certifi up to 2025.1.31, including 2018.11.29, holds the AAA root [R164].
- **Fix certifi for requests and HTTPX, and the OS store for truststore.** requests and HTTPX use certifi, and truststore uses the OS store [R181, R182, R183].
- **Run `uv python upgrade` for uv-managed interpreters.** After uv 0.13.5, it replaces the managed 3.11 and newer interpreters [R174].
- **Upgrade standalone Pixi.** It needs 0.82.1 [R188].
- **Update conda’s CA packages in every environment.** Updating `base` leaves the others alone [R185].

#### No fix yet

{: .notes}
- Python 3.10 and older are end of life and get no fix [R179].
- Anaconda main has no fixed CA packages for osx-64, linux-ppc64le or linux-s390x [R187].

{: #s-python}
#### Until a fix ships

{: .notes}
- **Bootstrap uv through the OS verifier:** `--system-certs`, `UV_SYSTEM_CERTS=true` or `system-certs = true` in `uv.toml` make uv verify with the operating system instead of its bundled roots, for example `UV_SYSTEM_CERTS=true uv self update`. Fix the OS store first [R175].
- **Point uv at a fixed bundle:** `SSL_CERT_FILE` or `SSL_CERT_DIR` replaces uv’s default certificate source entirely, so a fixed file such as the `cacert.pem` from certifi 2026.10.19 takes over [R175, R162].
- **Point requests at a fixed bundle:** `REQUESTS_CA_BUNDLE` or `CURL_CA_BUNDLE` makes requests use that file instead of certifi [R181]. These settings do not help pip, which keeps its vendored roots and only adds the extra CAs [R169].

[Every Python item, command and fixed version →](checks.html#g-python)
:::

::: {.eco #a-js}
### JavaScript runtimes

**Fix:** upgrade each runtime to its fixed release. Node.js’s fixed releases move to NSS 3.131.1, which drops G3, and reject chains with blocked public keys [R191, R192, R193, R194, R196].

#### Where the fix falls short

{: .notes}
- **Don’t rely on extra CA settings.** `NODE_EXTRA_CA_CERTS`, `--use-system-ca` and `NODE_USE_SYSTEM_CA=1` add certificates to the bundled roots. Node does not apply the system’s distrust settings [R198].
- **Upgrade Deno 2.9.7.** It also holds the AAA root [R204].
- **Confirm the fix by grepping the binary.** Node stores its roots as PEM text, so the first base64 line of the G3 root appears in an affected binary and not in a fixed one [R192, R193, R194]. Bun and Deno store DER, so grep their binaries for the subject string `emSign ECC Root CA - G3` [R201, R203].
- **Grep `node_modules` in each project.** Electron’s is the only npm advisory for this incident between 2026-10-17 and 2026-10-31, and no advisory names a package with a vendored bundle. An advisory search cannot prove that no package vendors the root [R200].

  ```
  # Lists each file under node_modules that holds the G3 root. Prints nothing if none does
  grep -rlF 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' node_modules 2>/dev/null
  ```

#### No fix yet

{: .notes}
- Node.js 20 has been end of life since 2026-04-30. Its last release, 20.20.2, still bundles G3 [R195].

{: #s-js}
#### Until a fix ships

{: .notes}
- **Node.js on Linux:** Run it with `--use-openssl-ca` once the distribution store is fixed. The flag replaces the bundled roots with OpenSSL’s default store, which most Linux distributions maintain. This was not tested against a fixed store [R199].
- **Deno:** Run it with `DENO_TLS_CA_STORE=system` once the OS store is fixed. The variable picks the system store, the bundled Mozilla roots or both, in order, and defaults to the bundled roots [R202]. Upgrade to 2.9.8 anyway, because it was not traced which 2.9.7 code path loads the AAA root [R204].

[Every JavaScript runtime item, command and fixed version →](checks.html#g-js)
:::

::: {.eco #a-langs}
### Other languages

**Fix:** upgrade to a release that blocks the eight compromised public keys. Go 1.26.10 and 1.27.3, `rustls-webpki` 0.103.16, and `composer/ca-bundle` 1.6.0 and 1.4.16 match those keys, which Sectigo’s cross-signs share [R207, R223, R229]. Composer 2.11.0 and 2.2.31 reject the intermediates even when the system store trusts their roots [R231].

#### Where the fix falls short

{: .notes}
- **Pin the Go fallback roots by hand.** `golang.org/x/crypto/x509roots/fallback` embeds its own roots and has no entry in the Go vulnerability database, so `govulncheck` misses an old pin [R210, R213]. Pin `v0.0.0-20261020153306-9f2b28d4331a` or later and rebuild [R211, R214].
- **Check both `webpki-roots` lines in the Rust lock file.** `webpki-roots` 0.26.11 holds no roots and is safe only when the lock file also resolves the 1.x crate to 1.0.10 or later [R218, R220].
- **Fix the OS store for PHP, RubyGems, Bundler, Erlang/OTP `public_key`, .NET and `rustls-native-certs`.** They follow the OS store [R232, R233, R249, R250, R225]. `rustls-native-certs` ignores OS distrust settings, and .NET on Linux ignores the `Disallowed` store, so remove the root from the store itself [R225, R251].
- **Rebuild Dart and Flutter apps for Android and Windows.** Those apps ignore OS blocklists. Rebuild them with Dart 3.13.7 or Flutter 3.47.8 [R255, R256].
- **Take AAA out too where a package removes only G3.** `webpki-roots`, `excon`, `castore`, Hex `certifi`, `Mozilla::CA` and curl’s `cacert.pem` remove the G3 root [R217, R234, R244, R246, R240, R252]. That leaves the cross-signs unblocked wherever the AAA root is trusted [R237].
- **Upgrade old pins that hold AAA.** The releases in the table below bundle the AAA root as well as G3, and so does everything before them. Upgrade them to the first release after the incident.

{: .caveats}
| Package | Holds AAA in this release and earlier |
|---|---|
| `webpki-roots` | `0.26.9` [R219] |
| `webpki-root-certs` | `0.26.9` [R221] |
| `composer/ca-bundle` 1.5 | `1.5.6` [R230] |
| `composer/ca-bundle` 1.4 | `1.4.7` [R230] |
| `excon` | `1.2.5` [R235] |
| `Mozilla::CA` | `20250202` [R242] |
| `castore` | `1.0.13` [R245] |
| Hex `certifi` | `2.14.0` [R247] |
| Go fallback bundle | The February 2025 bundle [R212] |

#### No fix yet

{: .notes}
- RUSTSEC-2026-0381 patches nothing else below `webpki-roots` 1.0.10, so 0.25.x and older have no fix [R216, R218].
- `httpclient` 2.9.0, the latest release, loads its own bundle by default and has no fix [R236]. That bundle is Mozilla data from 2015 with the AAA root and no G3 root, so a check for G3 alone passes it [R236, R237].

{: #s-langs}
#### Until a fix ships

{: .notes}
- **`SSL_CERT_FILE`:** Point Go, curl, .NET on Linux and `rustls-native-certs` at curl’s `cacert-2026-10-20.pem`, which holds neither the G3 root nor the AAA root [R252, R253]. All four read `SSL_CERT_FILE` [R208, R254, R250, R225]. The curl tool reads it and `CURL_CA_BUNDLE` only when it uses no native store, and a Schannel build on Windows ignores both [R254]. From Go 1.27, setting it on macOS or Windows turns off Go’s platform verifier [R208].
- **.NET on Linux:** Remove the roots from the OpenSSL bundle. .NET ignores the `Disallowed` store when it builds chains on Linux [R250, R251].
- **Go containers:** Keep a fixed CA bundle in the image and leave `GODEBUG=x509usefallbackroots=1` unset. Go then uses the system roots and never the embedded fallback bundle [R210].
- **Perl:** Give it a fixed, usable system store. IO::Socket::SSL clients such as LWP and HTTP::Tiny load `Mozilla::CA` only when no usable system store is found [R243].

[Every item for other languages, with commands and fixed versions →](checks.html#g-langs)
:::

::: {.eco #a-apps}
### Browsers and apps

**Fix:** update each app to its fixed release. Browsers on default settings block the intermediates without an update, apart from a Firefox ESR 115 startup gap [R264].

#### Where the fix falls short

{: .notes}
- **Don’t go by CVE-2026-113470 for Firefox ESR 115.** It still lists 115.43.1 as fixed [R264]. ESR 115 has no released fix for new profiles. It loads OneCRL only after 20 seconds without input, and the fix is in an unreleased 115.45.0 [R264].
- **Check Firefox forks that drop OneCRL.** A fork that drops OneCRL, such as GNU IceCat built from ESR 153.5.1, still trusted the intermediates [R265].
- **Update every Electron app.** There is no app-side workaround [R272].
- **Don’t judge Electron by a root grep.** The fix blocks the intermediates and leaves the G3 root in place [R271]. Grepping the binary for the root’s PEM line shows the bundled Node.js store, and it matches on fixed releases too [R275].
- **Upgrade VS Code desktop to 1.144.0.** 1.143.1 changed only the remote server’s Node.js [R276, R277].
- **Upgrade Docker Desktop to 4.96.3.** It is the first release whose notes drop the partial-fix warning. The community tracker lists 4.96.2 [R283].
- **Upgrade to certbot 5.9.0 and LibreOffice 26.8.2.** Both shipped fixes that the community tracker still lists as pending [R280, R289].
- **Upgrade JBR to b635.79.** b635.78 blocks all 16 certificates but its cacerts keeps the G3 and AAA roots. b635.79 removes them [R292, R293].
- **Check Godot 3 for AAA.** It bundles AAA as well as the G3 root [R288].

#### No fix yet

These projects had not released a fix on 2026-10-31:

{: .caveats}
| Project | Status |
|---|---|
| containerd | Merged the Go update on 20 October and has not released it [R281] |
| Podman | No stable release since 12 October [R285] |
| Godot | Fix on master only [R287] |
| OpenHarmony | Merged a change with no release [R291] |
| LibreOffice 26.2 | Waits on 26.2.7 [R290] |

{: #s-apps}
#### Until a fix ships

{: .notes}
- **Firefox ESR 115:** Leave a new profile idle for 20 seconds before first use, so it loads OneCRL. Once OneCRL loaded, the tracker’s test page showed none of the 14 chains trusted [R264].

[Every browser and app item, with commands and fixed versions →](checks.html#g-apps)
:::

::: {.eco #a-images}
### Container images

**Fix:** check each image and rebuild it [R295]. Patching the host does not fix its containers, because each container trusts the bundle inside its image [R294].

#### Where the fix falls short

{: .notes}
- **Check the built image on Debian and Ubuntu bases.** The base images carry no bundle. Whichever later layer installs ca-certificates sets what the image trusts [R296].
- **Read images with no shell without running them.** Copy the bundle or the dpkg status entry out with create and cp [R295, R298].
- **Upgrade ca-certificates in Rocky Linux and Amazon Linux images.** The current `rockylinux:8`, `:9` and `:10` images still ship unfixed builds [R075]. So does `amazonlinux:2023` [R301]. The upgrade for each is under Until a fix ships.
- **Move to Alpine 3.24.3 and the certbot v5.9.0 image.** Both are fixed. Alpine 3.24.2 and certbot v5.8.0 still hold the G3 root [R297, R303].

{: #s-images}
#### Until a fix ships

{: .notes}
- **Base images that lag:** Upgrade ca-certificates in the image build. On rockylinux:8, :9 and :10, `dnf upgrade ca-certificates` installs the fixed builds [R300, R074]. On amazonlinux:2023, add `--releasever=latest` to the update, or it keeps the unfixed build [R301, R079].
- **Distroless images:** Move them to Debian 13. static-debian13 ships the fixed ca-certificates 20250419+deb13u1 [R299]. The Debian 12 images had no fix on 2026-10-31 [R298].
- **podman machine VM:** Update the VM’s own ca-certificates. The VM keeps a store separate from the host, and the community tracker gives Fedora 2026.2.92_v9.0.319 as fixed [R286].

[Every container image item, with commands and fixed versions →](checks.html#g-images)
:::

## Sources {#sources}

{: .read}
The [references page](references.html) lists the sources for every claim on this page, with each source’s publisher and date.

:::

<footer>
  <div class="wrap"><p>eMudhra G3 intermediate CA key compromise, October 2026. An independent guide, not affiliated with eMudhra or Sectigo.</p><p>Last updated 2026-11-05. <a href="https://github.com/fieldse/emudhra-ca-compromise-check">Source on GitHub</a>.</p></div>
</footer>
