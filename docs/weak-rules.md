# Weak and unverifiable rules

**If a `FAIL` comes from one of these rules, verify it by hand.** The [proof page](https://fieldse.github.io/emudhra-ca-compromise-check/proof.html) shows how to check a rule against its original sources.

Of the 186 rules the check applies, 116 are verified, 68 are weak and 2 are unverifiable. `tools/build_detections.py` writes this page from the rule register, `rules/detection-rules.csv`, last updated 2026-11-04.

- A weak fact is a rule that a source backs only in part.
- A weak decision is a project choice with no outside source to check it against.
- An unverifiable rule is one no primary source could be found for.

## Weak rules by level

**10 of the 68 weak rules have `FAIL` as their level:** `CERT-21`, `CERT-23`, `OS-DEB-13`, `OS-RPM-01`, `OS-RPM-02`, `OS-PAC-01`, `RT-GO-06`, `LK-WR-01`, `LK-WRC-01` and `LK-POD-02`.

- **14 take their level from the certificate matcher or from other rules,** which can report `FAIL`: `CERT-27`, `CERT-29`, `CERT-30`, `RT-NODE-13`, `RT-BUN-02`, `RT-DENO-02`, `RT-GO-12`, `PY-UV-02`, `PY-PINS-02`, `EL-11`, `LK-RUST-01`, `LK-RUST-03`, `LK-POD-01` and `LK-POD-05`.
- **1 has no level (`-`):** `RT-GO-11`.
- **The other 43** report `WARN`, `INFO`, `PASS` or `SKIP`.

## Weak facts (10)

**A source confirms most of each of these claims.** The last column names the part it does not.

| Rule | Level | What is weak |
|---|---|---|
| `CERT-29` | matcher | The six bundle paths it reads are all sourced. The list misses `/etc/pki/ca-trust/extracted/pem/objsign-ca-bundle.pem` (RHEL and Fedora code signing) and `/etc/pki/tls/cacert.pem`, which are read only when they sit under a scan root. |
| `OS-RPM-01` | FAIL | Amazon Linux 2023: 0.4 is the first fix for CVE-2026-113470. Amazon later issued 0.5 for CVE-2026-114406, which removes more roots of the same operators. Amazon does not list what 0.4 still holds, so whether 0.4 is fully clean is open. |
| `OS-RPM-02` | FAIL | Amazon Linux 2: 0.3 is the first fix for CVE-2026-113470. Amazon later issued 0.4 for CVE-2026-114406. Whether 0.3 is fully clean is open for the same reason. |
| `OS-RPM-16` | WARN | The -2 build and the code-signing gap are confirmed. The -1 changelog does not list the G3 TLS root as removed, so "TLS bundle fixed" rests on the NSS 3.131.1 release note. |
| `OS-PAC-01` | FAIL | Arch publishes no advisory. The fix rests on the NSS 3.131.1 release note and on the package tracking the NSS version. |
| `OS-BREW-07` | WARN | The pre-fix Homebrew formula copies keychain roots only when `security verify-cert` accepts them. That it copies this G3 root rests on a lab finding, and Apple does not say whether a blocked root still passes after 2026-10-23. |
| `PY-DISTRO-01` | INFO | The `debian` and `rpm` installer cases are sourced. `dpkg`, `apk` and `brew` are not, because Homebrew installs with pip and Alpine's installer writes no INSTALLER file. |
| `PY-PINS-02` | rules/INFO | Neither Poetry nor uv documents the `[[package]]` lock layout. The rule rests on the tools' own lock files. |
| `LK-WR-01` | FAIL | FAIL follows RustSec, which counts every release below 0.26 as affected. The G3 premise holds only from 0.17.0. Releases up to 0.16.0 hold AAA Certificate Services and no G3 root, which would make them WARN under the AAA rule. |
| `LK-WRC-01` | FAIL | The rule never fires, because crates.io has no webpki-root-certs release below 0.26.4. It shares its code path with LK-WR-01. |

## Unverifiable rules (2)

**No primary source could be found for these rules.** The last column says why.

| Rule | Level | Why |
|---|---|---|
| `PY-CPY-08` | - | A design rule about the macOS `/usr/bin/python3` stub, which behaves differently without developer tools. No Apple primary source describes the stub's behaviour. |
| `LK-POD-04` | rules | Reuses about 30 OS package values that were checked under their own rules, not here. Choosing the SUSE or rpm record by `os-release` ID is a project decision. |

## Weak decisions (58)

**Each of these rules makes a choice that no outside source can check.** The level a rule gives is one such choice. The facts a decision rests on are confirmed where a source exists.

| Rule | Level | Condition | Basis |
|---|---|---|---|
| `CERT-21` | FAIL | Full match (certificate bytes) of a compromised intermediate | Design: a trusted copy of a compromised intermediate lets anyone issue certificates under it, so a full match is FAIL |
| `CERT-23` | FAIL | G3 root public key (SPKI) present with no full certificate, read as a trust anchor | Design: a store can hold a trust anchor as a bare public key, as rustls webpki-roots does |
| `CERT-24` | INFO | Compromised intermediate public key present with no full certificate, read as a blocklist entry | Design: fixed runtimes ship the eight compromised keys as a blocklist, so a bare intermediate key is read as a block entry |
| `CERT-25` | WARN | Any AAA Certificate Services match (full or key only), revoked cross-sign issuer trusted by clients that skip revocation | Project decision: AAA Certificate Services is WARN, since it is a live root that some clients still trust and that the cross-signs chain to |
| `CERT-27` | matcher | How a match is found: SHA-256 of each decoded PEM block, raw DER bytes, the first base64 line outside rejected entries, then the public key value for a key-only match | Design: match by content and key in PEM and DER so bundles without comments are covered |
| `CERT-28` | PASS | A judged file whose matches include no FAIL gets an extra PASS line 'contains no compromised eMudhra certificate' | Design: report a judged file that holds no compromised certificate |
| `CERT-30` | matcher/INFO | Indexed file named cacert\* or ending .pem, .crt, .cer or .bundle that holds a PEM block is judged by the matcher and listed only when it has a match. One INFO line gives the count checked | Design: scan only file names that commonly hold PEM bundles |
| `CERT-33` | WARN | PKCS12 keystore with encrypted contents and no FAIL, reported as 'password-protected keystore, check it with keytool' (PASS line dropped) | Design: a password-protected PKCS #12 cannot be read without the password, so it gets a manual check |
| `OS-DEB-12` | PASS | dpkg version matching no fixed prefix whose leading 8-digit date is later than the fix date, reported as 'released after the fix' | Inference: every fixed Debian and Ubuntu build carries the 20260816 data or later |
| `OS-DEB-13` | FAIL | Any other dpkg version (no fixed prefix reached, date not after 20260816), reported as 'released before the fix'. Covers Ubuntu release pockets | Design: a dpkg build no fixed prefix matches and dated on or before 20260816 predates the fix |
| `OS-APK-03` | WARN | apk version that does not parse, not comparable | Design: a version the check cannot compare gets a manual check |
| `OS-RPM-18` | PASS | rpm changelog of ca-certificates mentions the CVE: PASS for any build of a known family, even below its fix and for Fedora and CentOS Stream 10 builds below their TLS-only build, and for an unknown family. A TLS-only build stays WARN | Design: a ca-certificates changelog that names CVE-2026-114406 is taken as a fixed build |
| `OS-RPM-19` | WARN | rpm release matching no family pattern and no changelog hit, unknown family, trust-store content decides | Design: an rpm family with no listed fix is left to the trust store content check |
| `OS-BREW-02` | WARN | Cellar name that is not a dated formula version, check manually | Design: a Cellar name the check cannot date gets a manual check |
| `OS-BREW-04` | WARN | Formula PASS but a bundle still holds a match other than a key-only intermediate or a rejected entry, stale, run brew postinstall ca-certificates | Design: the fixed formula filters the roots in its post-install step, so a bundle written before the upgrade can be stale |
| `OS-BREW-05` | INFO | macOS: SystemRootCertificates keychain lists emSign ECC Root CA - G3 (Apple blocks it for its own frameworks since 2026-10-23) | Design: the keychain entry is context, since Apple blocks the root for its own frameworks |
| `RT-NODE-05` | PASS | Node major with no listed fix at or above the highest listed fix (27 and later), reported as 'newer than highest listed fix' | Inference: Node 27 and later are cut from main after the root removal merged |
| `RT-NODE-08` | INFO | Node version FAIL and binary holds the G3 root, reported as 'confirms the version FAIL' | Design: the root confirms a version FAIL and adds no new verdict |
| `RT-NODE-09` | INFO | Node version FAIL and a read binary lacks the G3 root, reported as 'custom build or system CA store, upgrade anyway' | Design: a FAIL version without the root still needs the upgrade |
| `RT-NODE-11` | INFO | No node on PATH, not installed | Design: say when a tool is not installed |
| `RT-NODE-13` | rules | Node binaries shipped by apps, classified by release URL, are judged by embedded version and content with the Node rules | Design: list the apps known to ship their own Node binary |
| `RT-BUN-02` | matcher | bun binary judged by the certificate matcher | Design: a runtime's own binary is scanned for the certificates |
| `RT-DENO-02` | matcher | deno binary judged by the certificate matcher. A fixed Deno's blocked keys come out as INFO through CERT-24 | Design: a fixed Deno carries the compromised keys as a blocklist, which the key-only rule reports as INFO |
| `RT-GO-04` | PASS | Go minor with no listed fix at or above 1.27.3 (1.28 and later) | Inference: Go's advisory range leaves every release from 1.27.3 on unaffected |
| `RT-GO-05` | INFO | go.mod 'toolchain goX' below fix (a minimum, not a pin) | Design: a go.mod toolchain line suggests a toolchain and does not pin it, so it is INFO |
| `RT-GO-06` | FAIL | Go binary build info names a toolchain below fix and the binary holds the function name crypto/x509.(\*Certificate).Verify, reported as 'built with an affected toolchain, rebuild' | Design: a binary built by an affected toolchain lacks the crypto/x509 denylist, so it is FAIL. Owner decision 2026-11-04, 80/20: only when it holds crypto/x509's Verify, otherwise RT-GO-13 |
| `RT-GO-08` | WARN | Go build info unreadable, check with go version -m | Design: unreadable build info gets a manual check with go version -m |
| `RT-GO-10` | WARN | Fallback module version that is not a pseudo-version, check manually | Design: a fallback module version that is not a pseudo-version cannot be dated |
| `RT-GO-11` | - | Go binaries whose resolved path is under a Homebrew /Cellar/go/ path are skipped, including bin links into it | Design: the Homebrew Go toolchain's own binaries are judged as the toolchain |
| `RT-GO-12` | matcher/INFO | Go binary content matches take the matcher levels. No Go binaries found is INFO | Design: a Go binary's bytes are scanned for the certificates |
| `RT-GO-13` | WARN | Go binary that RT-GO-06 or RT-GO-07 would report FAIL but that does not hold the function name crypto/x509.(\*Certificate).Verify, reported as 'crypto/x509 Verify not found, the program may never verify certificates' | Owner decision 2026-11-04, 80/20: a binary that does not hold crypto/x509's Verify may never verify certificates, and an obfuscated build can hide the name, so it is WARN |
| `RT-GEN-01` | WARN | Version command output unreadable, reported as 'version unreadable'. Bun, Node and uv binaries are still scanned, and Node is then judged by the release its binary names (RT-NODE-10) | Design: a version the tool does not print readably gets a manual check |
| `RT-GEN-02` | WARN | Found or fixed version not a plain dotted version, check manually | Design: only plain dotted versions and alpha, beta and rc pre-releases are compared |
| `RT-GEN-03` | INFO/WARN | A tool on PATH inside an excluded directory is INFO, not run. A root run with a tool a non-root user can write is WARN, not run, and its binary is still read. A command that timed out is WARN, skipped | Design: never run a tool in an excluded directory or one a non-root user can change |
| `RT-GEN-04` | INFO | A file over its size cap is INFO 'too large to scan, skipped'. Another unreadable file is INFO with the reason. A missing or excluded file gives no line | Design: size caps keep the scan bounded |
| `PY-CPY-03` | WARN | CPython 3.13 below fix | Project decision: CPython below its fix is WARN, since the pip and certifi checks decide the bundled CA files |
| `PY-CPY-04` | WARN | CPython 3.14 below fix | Project decision: CPython below its fix is WARN, since the pip and certifi checks decide the bundled CA files |
| `PY-CPY-05` | WARN | CPython 3.15 below fix | Project decision: CPython below its fix is WARN, since the pip and certifi checks decide the bundled CA files |
| `PY-CPY-06` | WARN | CPython branch older than 3.11, reported as 'end-of-life, no fix' | Project decision: an end-of-life CPython branch is WARN, as for the other CPython rules |
| `PY-UV-02` | matcher | uv binary judged by the certificate matcher | Design: a tool's own binary is scanned for the certificates |
| `PY-LINK-01` | INFO | A cacert.pem that links outside the package is INFO, and the bundle it resolves to is judged by content. In an image whose probe did not dump the target, the version decides | Design: a bundle linked out of its package is judged by the file it resolves to |
| `EL-08` | WARN | App version unreadable, reported as 'check the app's About window' | Design: an app whose version the check cannot read gets a manual check |
| `EL-09` | INFO | Version FAIL and binary holds the full G3 root, reported as 'confirms the version FAIL' | Design: the root confirms a version FAIL and adds no new verdict |
| `EL-11` | matcher/INFO | Other matches in an Electron binary take the matcher levels. No Electron apps is INFO. An exhausted Linux binary budget is INFO | Design: other matches in an Electron binary take the matcher levels |
| `EL-12` | WARN | Electron .app inside a \*.ShipIt updater cache below its branch fix, reported as 'stale updater cache, delete the directory'. PASS is not printed | Design: a stale updater cache is WARN, since the app does not run from it |
| `EL-15` | WARN | Declared range whose lowest version is below its branch fix, reported as 'a range may resolve higher, check the installed version' | Owner decision of 2026-11-01: a range that starts below the fix may resolve to a fixed release, so it is WARN |
| `EL-18` | WARN/INFO | Unbounded spec (\|\|, ' - ', >..., \*, x, latest, next, \<...) is WARN 'unbounded range, check the installed version'. A non-registry spec (workspace:, file:, link:, git, http(s):, npm:, github:, portal:, any '/') gives no line. A package.json inside node_modules other than electron's own is skipped. Unreadable is INFO | Design: a spec the check cannot bound gets a manual check, and non-registry specs are skipped |
| `LK-WR-04` | WARN | webpki-roots 0.26.11 wrapper whose 1.x dependency cannot be resolved | Design: a wrapper whose 1.x dependency the check cannot find gets a manual check |
| `LK-RUST-01` | rules | Crate versions read from cargo registry source paths embedded in a Rust binary are judged by the webpki-roots, webpki-root-certs and rustls-webpki rules, with the note 'rebuild against the fixed crates' | Design: read crate versions from the registry source paths a Rust binary embeds |
| `LK-RUST-02` | WARN | rustls-webpki FAIL in a Rust binary that holds no affected root is WARN 'lacks the key blocklist, matters only when the binary uses the system trust store' | Owner rule of 2026-11-01 that known vulnerable is FAIL, applied by the agent: an old rustls-webpki in a binary with no affected root is WARN |
| `LK-RUST-03` | matcher | Rust binary content matches take the matcher levels | Design: a Rust binary's bytes are scanned for the certificates |
| `LK-CARGO-01` | INFO | Cargo.lock under registry/src/\<index>-\<16 hex>/ or git/checkouts/\<repo>-\<16 hex>/ is INFO 'inside downloaded crate source, does not decide local builds' and is not read | Design: a Cargo.lock inside downloaded crate source does not decide a local build |
| `LK-CARGO-02` | INFO | Cargo.lock partly unreadable, with the count read | Design: report how much of a partly unreadable lock was read |
| `LK-COMP-04` | PASS/INFO | composer/ca-bundle minor with no listed fix at or above 1.6.0 (1.7 and later) is PASS. An unreadable composer.lock is INFO | Inference: composer/ca-bundle 1.7 and later are cut after the fix |
| `LK-POD-01` | rules | An image's node is judged by the Node rules, its version always judged. G3 comes from a grep for the G3 root's first base64 line. A grep for the ISRG Root X1 line tells whether it bundles a root list, and a missing list is a note (RT-NODE-06) | Design: judge an image's Node with the host Node rules from a shell probe |
| `LK-POD-02` | FAIL | An image's bun below 1.4.4, deno below 2.9.8, or go (GOTOOLCHAIN=local) below its branch fix. These runtimes get no binary content scan in images | Design: judge an image's runtimes by version only, without a binary scan |
| `LK-POD-05` | matcher | Dumped files (the six OS bundle paths, linked certifi and pip bundle targets, every cacert.pem and cacerts found) are judged as keystores when the format is known, else as bundles | Design: dump the standard bundles and every cacert.pem and cacerts file from an image |
| `LK-POD-06` | SKIP/WARN/INFO | Probe states: no shell is SKIP. Failed, timed out or over-cap output is WARN, image not inspected. No records is INFO. No od is INFO, bundles not inspected. A file over its cap is INFO. Dropped malformed records are WARN | Design: caps and probe states keep an image probe bounded |

## How the rules were reviewed

LLM agents reviewed each rule in two passes. One pass looked for a source that supports the rule, and the other tried to refute it. A rule is `VERIFIED` only when both passes agree, and otherwise it takes the worse result. No person ran either pass, so a status guarantees nothing. Treat it as a lead to check.

## Checking a rule yourself

1. Find the rule in `rules/detection-rules.csv` or on `detections.html`.
2. Open the R-numbers in its `refs` column on `references.html` and read the source each one links.
3. Compare the source to the rule's condition. If they disagree, the rule is wrong, whatever its status says. [Reporting mistakes](https://fieldse.github.io/emudhra-ca-compromise-check/proof.html#reporting) on the proof page says how to report it.
