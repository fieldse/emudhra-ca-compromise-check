# Sources

**This page lists the original public sources behind the numbered claims (R001 to R358) on [references.html](../references.html).**

- Each row gives one source, linked by its title, with what it backs and the R-numbers that cite it.
- A primary source is the vendor, project or standards body's own document.
- A secondary source is a community or third-party summary.
- R099, R298 and R302 have no row here. They rest only on inspection of the file or image itself.

## Contents

- [Incident](#incident)
- [Root programs](#root-programs)
- [Exposure](#exposure)
- [OS trust stores](#os-trust-stores)
- [Java](#java)
- [Python](#python)
- [JavaScript runtimes](#javascript-runtimes)
- [Other languages](#other-languages)
- [Browsers and apps](#browsers-and-apps)
- [Container images](#container-images)

## Incident

| # | Source | Backs | R-numbers | Kind |
|---|---|---|---|---|
| S1 | [Bug 2083449 - eMudhra: Private key compromise of Intermediate Certificates](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449) · Mozilla | Mozilla's incident bug, with the key recovery, timeline, eMudhra's statements and Chrome's questions | R001, R002, R007, R008, R009, R010, R011, R012, R013, R014, R016, R018, R027, R028, R032, R036, R041, R237 | primary |
| S2 | [impacted-intermediates.json (community tracker)](https://emudhra.we-have-a-problem.com/impacted-intermediates.json) · emudhra.we-have-a-problem.com | The 16 compromised certificates with serials, dates and revocation times | R001, R002, R003, R011, R237 | secondary |
| S3 | [Announcements - Microsoft Trusted Root Certificate Program](https://github.com/TrustedRootProgram/Program-Requirements/blob/0fc6bfef5a36c073db756748e945b334bc87ba1f/Announcements.md) · Microsoft | Microsoft's dated Windows and Edge actions, the seven removed roots by thumbprint and the CTL sequence number | R002, R003, R006, R033, R034, R106, R107, R237, R259 | primary |
| S4 | [Protecting Firefox users following the compromise of eMudhra intermediate certificates](https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/) · Mozilla | OneCRL timing, Firefox 158.0.1 and ESR releases, NSS 3.131.1 and Firefox for Android 158.0.2 | R004, R010, R012, R014, R027, R030, R260, R266 | primary |
| S5 | [Microsoft's response to compromised eMudhra certificate authority keys](https://www.microsoft.com/en-us/msrc/blog/2026/10/microsoft-response-to-compromised-emudhra-certificate-authority-keys) · Microsoft | Windows and Edge actions, the impact of the code-signing keys and the eMudhra roots still under evaluation | R004, R014, R032, R033, R034, R038, R106, R107, R108, R109, R259 | primary |
| S6 | [About the compromised eMudhra intermediate CAs](https://support.apple.com/en-us/149555) · Apple | Apple's blocks of 19 and 23 October, the 12 TLS certificates and the /etc/ssl/cert.pem gap on macOS | R005, R035, R040, R044, R097, R098, R101, R103, R104, R105, R269, R295 | primary |
| S7 | [roots.json (community tracker)](https://emudhra.we-have-a-problem.com/roots.json) · emudhra.we-have-a-problem.com | Fingerprints, roles and root-store inclusion of the four roots, including AAA Certificate Services | R005, R006, R007, R034, R238, R259 | secondary |
| S8 | [Chrome Root Store v42 root_store.textproto](https://chromium.googlesource.com/chromium/src/+/5a6a4e78597add03dd32bc233e03f3145cd99b65/net/data/ssl/chrome_root_store/root_store.textproto) · Chromium | Chrome Root Store version 42, which still holds emSign ECC Root CA - G3 | R005, R031, R042, R258 | primary |
| S9 | [eMudhra response to Chrome Root Program questions on Bug 2083449](https://bugzilla.mozilla.org/attachment.cgi?id=9670867) · eMudhra | eMudhra's 28 October answers to Chrome's questions, with certificate counts, migration routes and the 15 November target | R008, R009, R016 | primary |
| S10 | [Protecting Chrome and Android Users from Compromised eMudhra Intermediate CA Certificates](https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/) · Google | Chrome CRLSet block at 19:45 UTC, Android block through Google Play services, no CT-logged leaf certificates and the expected root store removal | R010, R013, R014, R026, R031, R036, R046, R110, R257, R258 | primary |
| S11 | [Advisory on compromised eMudhra intermediate certificates](https://www.sectigo.com/resource-library/advisory-on-compromised-emudhra-intermediate-certificates) · Sectigo | Sectigo revoked the eight cross-signs on 19 October and ended the cross-signing relationship | R011 | primary |
| S12 | [oss-security: eMudhra Intermediates Compromise](https://www.openwall.com/lists/oss-security/2026/10/20/1) · Mozilla, via Openwall | Mozilla's 19 October notice to distributions, with root SPKI hashes and advice to remove three roots | R012, R047, R048 | primary |
| S13 | [eMudhra Intermediate CA Compromise](https://emudhra.we-have-a-problem.com/) · emudhra.we-have-a-problem.com | Community tracker covering CT exposure, Apple dates, per-distribution workarounds and a list of patched software | R014, R035, R038, R040, R044, R046, R089, R090, R094, R100, R109, R111, R237, R276, R280, R283, R286, R289, R291 | secondary |
| S14 | [eMudhra to Exit global SSL/TLS Certificate Business](https://www.einpresswire.com/article/951482814/emudhra-to-exit-global-ssl-tls-certificate-business) · EIN Presswire | eMudhra's 22 October release on leaving the TLS business, keeping the G1 roots and publishing a root-cause report | R015, R018 | primary |
| S15 | [eMudhra status page, Update 7](https://emudhra.com/en/post/certificate-security-incident) · eMudhra | eMudhra's status updates, including the KPMG appointment and the promised independent review and CCADB report | R017, R018 | primary |
| S16 | [RHSB-2026-012 Certificate compromise - eMudhra](https://access.redhat.com/security/vulnerabilities/RHSB-2026-012) · Red Hat | Red Hat says the incident is not a software vulnerability, lists the CVEs that apply and the affected RHEL 6 to 10 and UBI | R019, R021 | primary |
| S17 | [CVE record CVE-2026-111944](https://cveawg.mitre.org/api/cve/CVE-2026-111944) · CVE Program | The CVE API returns no record for this ID | R019 | primary |
| S18 | [CVE record CVE-2026-111943](https://cveawg.mitre.org/api/cve/CVE-2026-111943) · CVE Program | Go's CVE record for the crypto/x509 denylist, with affected ranges | R020, R205, R206, R224 | primary |
| S19 | [GO-2026-6809](https://pkg.go.dev/vuln/GO-2026-6809) · Go | Go vulnerability entry for CVE-2026-111943, a denylist in crypto/x509 Verify, published 21 October | R020, R205 | primary |
| S20 | [CVE record CVE-2026-114406](https://cveawg.mitre.org/api/cve/CVE-2026-114406) · CVE Program | Red Hat's CVE record, with fixed ca-certificates builds per RHEL release | R021 | primary |
| S21 | [CVE record CVE-2026-114820](https://cveawg.mitre.org/api/cve/CVE-2026-114820) · CVE Program | Oracle's CVE record for Java SE and GraalVM, with affected versions and CVSS 9.1 | R022, R112, R128 | primary |
| S22 | [Oracle Security Alert Advisory - CVE-2026-114820](https://www.oracle.com/security-alerts/alert-cve-2026-114820.html) · Oracle | Oracle Java updates that remove the impacted roots, revision 1 on 24 October and revision 2 on 30 October | R022, R128, R129, R132 | primary |
| S23 | [Compromised Certificates and OpenJDK Java Runtimes](https://openjdk.org/emudhra) · OpenJDK | OpenJDK guidance mapping CVE-2026-114820 to JDK-8395690, with the interim fix of deleting four keystore aliases | R022, R037, R114, R118, R119, R122, R123, R124, R125, R126, R150, R157, R158 | primary |
| S24 | [CVE record CVE-2026-91403](https://cveawg.mitre.org/api/cve/CVE-2026-91403) · CVE Program | Oracle's CVE record, published 21 October, which does not name eMudhra | R023, R113 | primary |
| S25 | [Oracle Security Alert Advisory - CVE-2026-91403](https://www.oracle.com/security-alerts/alert-cve-2026-91403.html) · Oracle | Oracle's first alert, 21 October: Java updates that distrust the intermediates | R023, R129 | primary |
| S26 | [CVE record CVE-2026-113812](https://cveawg.mitre.org/api/cve/CVE-2026-113812) · CVE Program | CPANSec record for Mozilla::CA before 20261020 | R024, R239, R243 | primary |
| S27 | [CVE record CVE-2026-115570](https://cveawg.mitre.org/api/cve/CVE-2026-115570) · CVE Program | GitHub's CVE record for Electron, with fixed versions | R025, R270 | primary |
| S28 | [Mitigation for compromised eMudhra intermediate certificates (GHSA-jr5w-w6x2-84p9)](https://github.com/electron/electron/security/advisories/GHSA-jr5w-w6x2-84p9) · Electron | Electron's advisory, with fixed versions and no app-side workaround | R025, R270, R271, R272 | primary |
| S29 | [crt.sh: EM DV TLS CA - G3B](https://crt.sh/?sha256=42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493) · crt.sh | SHA-256, serial and issuer of this eMudhra-issued intermediate | R304 | primary |
| S30 | [crt.sh: EM OV TLS CA - G3B](https://crt.sh/?sha256=98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B) · crt.sh | SHA-256, serial and issuer of this eMudhra-issued intermediate | R304 | primary |
| S31 | [crt.sh: EM EV TLS CA - G3B](https://crt.sh/?sha256=E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838) · crt.sh | SHA-256, serial and issuer of this eMudhra-issued intermediate | R304 | primary |
| S32 | [crt.sh: EM DV TLS CA - G3C](https://crt.sh/?sha256=0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19) · crt.sh | SHA-256, serial and issuer of this eMudhra-issued intermediate | R304 | primary |
| S33 | [crt.sh: EM OV TLS CA - G3C](https://crt.sh/?sha256=CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F) · crt.sh | SHA-256, serial and issuer of this eMudhra-issued intermediate | R304 | primary |
| S34 | [crt.sh: EM EV TLS CA - G3C](https://crt.sh/?sha256=432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3) · crt.sh | SHA-256, serial and issuer of this eMudhra-issued intermediate | R304 | primary |
| S35 | [crt.sh: EM OV CS CA - G3B](https://crt.sh/?sha256=9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4) · crt.sh | SHA-256, serial and issuer of this eMudhra-issued intermediate | R304 | primary |
| S36 | [crt.sh: EM OV CS CA - G3C](https://crt.sh/?sha256=4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1) · crt.sh | SHA-256, serial and issuer of this eMudhra-issued intermediate | R304 | primary |
| S37 | [Bug 2083449, comment 0](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449#c0) · Mozilla | Lists the eight eMudhra-issued intermediates with their CCADB IDs | R304 | primary |
| S38 | [crt.sh: EM DV TLS CA - G3B cross-sign](https://crt.sh/?sha256=45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE) · crt.sh | SHA-256 and serial of this Sectigo cross-sign, issued by AAA Certificate Services | R305 | primary |
| S39 | [crt.sh: EM OV TLS CA - G3B cross-sign](https://crt.sh/?sha256=5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699) · crt.sh | SHA-256 and serial of this Sectigo cross-sign, issued by AAA Certificate Services | R305 | primary |
| S40 | [crt.sh: EM EV TLS CA - G3B cross-sign](https://crt.sh/?sha256=579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512) · crt.sh | SHA-256 and serial of this Sectigo cross-sign, issued by AAA Certificate Services | R305 | primary |
| S41 | [crt.sh: EM DV TLS CA - G3C cross-sign](https://crt.sh/?sha256=62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72) · crt.sh | SHA-256 and serial of this Sectigo cross-sign, issued by AAA Certificate Services | R305 | primary |
| S42 | [crt.sh: EM OV TLS CA - G3C cross-sign](https://crt.sh/?sha256=7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489) · crt.sh | SHA-256 and serial of this Sectigo cross-sign, issued by AAA Certificate Services | R305 | primary |
| S43 | [crt.sh: EM EV TLS CA - G3C cross-sign](https://crt.sh/?sha256=FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F) · crt.sh | SHA-256 and serial of this Sectigo cross-sign, issued by AAA Certificate Services | R305 | primary |
| S44 | [crt.sh: EM OV CS CA - G3B cross-sign](https://crt.sh/?sha256=A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8) · crt.sh | SHA-256 and serial of this Sectigo cross-sign, issued by AAA Certificate Services | R305 | primary |
| S45 | [crt.sh: EM OV CS CA - G3C cross-sign](https://crt.sh/?sha256=84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD) · crt.sh | SHA-256 and serial of this Sectigo cross-sign, issued by AAA Certificate Services | R305 | primary |
| S46 | [crt.sh: emSign ECC Root CA - G3](https://crt.sh/?sha256=86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B) · crt.sh | SHA-256 and serial of this self-signed G3 root | R306 | primary |
| S47 | [crt.sh: emSign Root TLS CA - G3](https://crt.sh/?sha256=7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D) · crt.sh | SHA-256 and serial of this self-signed G3 root | R306 | primary |
| S48 | [crt.sh: emSign Root CS CA - G3](https://crt.sh/?sha256=F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5) · crt.sh | SHA-256 and serial of this self-signed G3 root | R306 | primary |
| S49 | [ca-certificates 20230311+deb12u1 mozilla/certdata.txt](https://sources.debian.org/src/ca-certificates/20230311%2Bdeb12u1/mozilla/certdata.txt/) · Debian | Debian's copy of Mozilla's certdata.txt, with the fingerprint and serial of emSign ECC Root CA - G3 | R306 | primary |
| S50 | [crt.sh: AAA Certificate Services](https://crt.sh/?sha256=D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4) · crt.sh | Serial 1 and the SHA-256 of AAA Certificate Services | R307 | primary |
| S51 | [ca-certificates 20230311+deb12u1 mozilla/certdata.txt (raw file)](https://sources.debian.org/data/main/c/ca-certificates/20230311%2Bdeb12u1/mozilla/certdata.txt) · Debian | Debian's raw certdata.txt, with AAA Certificate Services (Comodo AAA Services root) at serial 1 and its SHA-256 | R307 | primary |
| S52 | [crt.sh search by subject key identifier](https://crt.sh/?ski=E21E2FE71C19390E554B62C120245735248A2514) · crt.sh | Finds two certificates for a compromised key, the eMudhra certificate and its Sectigo cross-sign | R308 | primary |
| S53 | [Bug 2083449, comment 5](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449#c5) · Mozilla | The eight compromised keys date from 30 April 2025 and all used integers below 256 | R308 | primary |
| S54 | [crt.sh: emSign Root TLS CA - G3, issued by emSign ECC Root CA - G3](https://crt.sh/?id=14658191778) · crt.sh | Cross-certificate from emSign ECC Root CA - G3, dated 11 July 2024, with the same key as the self-signed root | R309 | primary |
| S55 | [crt.sh: emSign Root CS CA - G3, issued by emSign ECC Root CA - G3](https://crt.sh/?id=14658191774) · crt.sh | Cross-certificate from emSign ECC Root CA - G3, dated 11 July 2024, with the same key as the self-signed root | R309 | primary |
| S56 | [crt.sh search, emSign Root TLS CA - G3 key](https://crt.sh/?ski=E13AAB217CF1E34D54AED472B7FD8B5942209054) · crt.sh | Every certificate that carries the emSign Root TLS CA - G3 key | R309 | primary |
| S57 | [crt.sh search, emSign Root CS CA - G3 key](https://crt.sh/?ski=687403F885CA8D5450571D16E0C8DE450DABCD2D) · crt.sh | Every certificate that carries the emSign Root CS CA - G3 key | R309 | primary |
| S58 | [AAACertificateServices.crl](http://crl.comodoca.com/AAACertificateServices.crl) · Sectigo | All eight cross-sign serials revoked with reason CA Compromise, with a revocation date field of 14 May 2025 | R310 | primary |
| S59 | [Bug 2083449, comments 6 and 13](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449#c13) · Mozilla | Sectigo says AAA stays trusted by Microsoft and Apple, and completed revoking the cross-signs on 19 October | R310 | primary |

## Root programs

| # | Source | Backs | R-numbers | Kind |
|---|---|---|---|---|
| S60 | [oss-security: NSS 3.131.1 Release - Important Security Updates](https://www.openwall.com/lists/oss-security/2026/10/20/30) · Openwall | Relays Mozilla's NSS 3.131.1 announcement of the three emSign root removals and their bugs | R027, R029 | secondary |
| S61 | [Bug 2084101 - Remove eMudhra emSign Root CA - G3 from NSS](https://bugzilla.mozilla.org/show_bug.cgi?id=2084101) · Mozilla | NSS removal of emSign ECC Root CA - G3, landed 20 October | R029, R268 | primary |
| S62 | [NSS master certdata.txt](https://raw.githubusercontent.com/nss-dev/nss/NSS_3_131_1_RTM/lib/ckfw/builtins/certdata.txt) · Mozilla | NSS 3.131.1 root list, without the G3, C1 and C3 roots and still with emSign Root CA - G1 | R029, R032 | primary |
| S63 | [CVE record CVE-2026-113470](https://cveawg.mitre.org/api/cve/CVE-2026-113470) · CVE Program | Mozilla's CVE record, with fixed Firefox and Thunderbird versions | R030, R261, R264 | primary |
| S64 | [Bug 2086788 - Firefox 115 ESR may still trust the compromised eMudhra certificates](https://bugzilla.mozilla.org/show_bug.cgi?id=2086788) · Mozilla | Firefox ESR 115 can miss OneCRL after an idle start, fixed in a 115.45.0 pre-release | R030, R261, R264 | primary |
| S65 | [Mozilla product-details firefox_versions.json](https://product-details.mozilla.org/1.0/firefox_versions.json) · Mozilla | Current Firefox release and ESR version numbers | R030, R263, R264 | primary |
| S66 | [Chrome Root Store v43 root_store.textproto](https://chromium.googlesource.com/chromium/src/+/8793082f793c2533dccf28e83e33f0e700c52d28/net/data/ssl/chrome_root_store/root_store.textproto) · Chromium | Chrome Root Store version 43, without emSign ECC Root CA - G3 and still with emSign Root CA - G1 | R031, R032 | primary |

## Exposure

| # | Source | Backs | R-numbers | Kind |
|---|---|---|---|---|
| S67 | [Oracle JDK 27.0.1.0.3 release notes](https://www.oracle.com/java/technologies/javase/27-0-1-0-3-relnotes.html) · Oracle | Oracle JDK 27.0.1.0.3, 24 October, removes the four aliases | R037, R117, R130 | primary |
| S68 | [TLS MitM vulnerability on Android, Windows, and Linux due to compromised eMudhra intermediate CA certificates](https://github.com/dart-lang/sdk/security/advisories/GHSA-frr6-h895-5pxp) · Dart | Dart and Flutter fixed versions and platform scope | R038, R255, R294 | primary |
| S69 | [Command-line API](https://nodejs.org/api/cli.html) · Node.js | Node's bundled store is a Mozilla snapshot fixed at release, and the options that switch to the system store | R039, R190, R198, R199 | primary |
| S70 | [Security Bulletin: eMudhra CA Certificate Compromise (CVE-2026-91403 and CVE-2026-114820)](https://www.ibm.com/support/pages/node/7294729) · IBM | IBM Semeru affected ranges, fixed releases and alias names per version | R039, R156, R159 | primary |
| S71 | [NSS certdata.txt at release tags NSS_3_130 to NSS_3_132](https://github.com/nss-dev/nss) · Mozilla | emSign ECC Root CA - G3 is in NSS 3.130 and 3.131 and gone from 3.131.1 and 3.132, with the AAA trust bits | R041, R262, R268 | primary |
| S72 | [Chrome Root Store v43 root_store.textproto](https://chromium.googlesource.com/chromium/src/+/8793082f793c2533dccf28e83e33f0e700c52d28/net/data/ssl/chrome_root_store/root_store.textproto) · Chromium | Chrome Root Store version 43, with the G3 root removed | R042, R258 | primary |
| S73 | [Go commit 90617fb](https://github.com/golang/go/commit/90617fb7ceb59cf08bee7826bb51b8c8fb8c11de) · Go | The eight SPKI SHA-256 hashes Go blocks and the checks in verify.go | R043, R207 | primary |
| S74 | [rustls-webpki 0.103.16 crate](https://static.crates.io/crates/rustls-webpki/rustls-webpki-0.103.16.crate) · crates.io | rustls-webpki 0.103.16 ships the eight compromised public keys and rejects any chain that uses them | R043, R223 | primary |
| S75 | [ssl: distrust compromised eMudhra intermediate CA keys](https://github.com/python/cpython/issues/160040) · Python Software Foundation | CPython's ssl check matches the public key, covers cross-signs and does not apply to CERT_NONE | R043, R177 | primary |
| S76 | [Bug 2085612 - eMudhra: Access to CRLs blocked for certain User-Agent headers](https://bugzilla.mozilla.org/show_bug.cgi?id=2085612) · Mozilla | eMudhra's report on CRL and OCSP requests blocked by user agent, and third-party tests that dispute its hostname list | R045 | primary |
| S77 | [webpki-roots 1.0.9 src/lib.rs](https://raw.githubusercontent.com/rustls/webpki-roots/v/1.0.9/webpki-roots/src/lib.rs) · rustls | webpki-roots stores each trust anchor as a public key without the certificate | R311 | primary |
| S78 | [RFC 7468, Textual Encodings of PKIX, PKCS, and CMS Structures](https://www.rfc-editor.org/rfc/rfc7468.txt) · IETF | A strict PEM encoder writes base64 lines of exactly 64 characters except the last | R312 | primary |
| S79 | [crypto/x509/x509_trust.c at openssl-3.5.0](https://github.com/openssl/openssl/blob/openssl-3.5.0/crypto/x509/x509_trust.c) · OpenSSL | How OpenSSL applies the trust and reject lists of a TRUSTED CERTIFICATE | R351 | primary |
| S80 | [crypto/x509/x_x509a.c at openssl-3.5.0](https://github.com/openssl/openssl/blob/openssl-3.5.0/crypto/x509/x_x509a.c) · OpenSSL | The X509_CERT_AUX structure that carries the trust and reject lists | R351 | primary |

## OS trust stores

| # | Source | Backs | R-numbers | Kind |
|---|---|---|---|---|
| S81 | [CVE-2026-114406](https://access.redhat.com/security/cve/CVE-2026-114406) · Red Hat | Red Hat's CVE description, Critical rating and reason for the root removals | R049, R064 | primary |
| S82 | [Bug 2556376 - Update to mitigate current issues with eMudhra](https://bugzilla.redhat.com/show_bug.cgi?id=2556376) · Red Hat | Fedora's plan to remove emSign ECC Root CA - G3 and AAA, and the -1 build still trusting emSign Root CS CA - G3 for code signing | R049, R063 | primary |
| S83 | [\[DSA 6572-1\] ca-certificates security update](https://lists.debian.org/debian-security-announce/2026/msg00487.html) · Debian | Debian removes emSign ECC Root CA - G3 and Comodo AAA Services root, 20 October | R049, R050, R053 | primary |
| S84 | [DSA-6572-1](https://security-tracker.debian.org/tracker/DSA-6572-1) · Debian | trixie 20250419 is vulnerable and 20250419+deb13u1 is fixed | R050 | primary |
| S85 | [Debian ca-certificates packages (archive)](https://deb.debian.org/debian/pool/main/c/ca-certificates/) · Debian | Every ca-certificates version offered to bullseye, bookworm, trixie, forky and sid | R050, R051, R052, R053, R054, R055 | primary |
| S86 | [DLA-4845-1](https://security-tracker.debian.org/tracker/DLA-4845-1) · Debian | bookworm 20230311+deb12u1 is vulnerable and 20250419~deb12u2 is fixed | R051 | primary |
| S87 | [Information on source package ca-certificates](https://security-tracker.debian.org/tracker/source-package/ca-certificates) · Debian | ca-certificates versions per Debian release, with DSA-6572-1 and DLA-4845-1 | R051, R052, R055 | primary |
| S88 | [Debian Bug report logs - #1151413](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1151413) · Debian | Found in 20250419, fixed in 20260816+nmu1 and 20250419+deb13u1 | R052 | primary |
| S89 | [USN-8944-1: ca-certificates update](https://ubuntu.com/security/notices/USN-8944-1) · Canonical | Fixed versions for Ubuntu 22.04, 24.04, 26.04 and 26.10 | R056, R057 | primary |
| S90 | [Ubuntu ca-certificates packages (archive)](http://ports.ubuntu.com/ubuntu-ports/pool/main/c/ca-certificates/) · Canonical | Release and security ca-certificates packages for Ubuntu 22.04, 24.04, 26.04 and 26.10 | R056, R057 | primary |
| S91 | [USN-8944-2: ca-certificates update](https://ubuntu.com/security/notices/USN-8944-2) · Canonical | ESM fixes for Ubuntu 14.04 to 20.04, removing emSign ECC Root CA - G3 and Comodo AAA Services root | R058 | primary |
| S92 | [Package index](https://pkgs.alpinelinux.org/packages?name=ca-certificates&arch=) · Alpine Linux | ca-certificates 20261020-r0 on edge, built 20 October | R059 | primary |
| S93 | [Alpine images and repositories](https://dl-cdn.alpinelinux.org/alpine/) · Alpine Linux | Alpine 3.20 to 3.24 and edge releases and their ca-certificates packages | R059 | primary |
| S94 | [ca-certificates.yaml commit history and commit 5542b69](https://github.com/wolfi-dev/os/commits/f496047b03a9e93d95fc00e59fdd68dbd176ba07/ca-certificates.yaml) · Wolfi | Wolfi 20260909 epoch 3 removes emSign ECC Root CA - G3, C1 and C3, merged 20 October | R060 | primary |
| S95 | [ca-certificates.yaml (main)](https://raw.githubusercontent.com/wolfi-dev/os/f496047b03a9e93d95fc00e59fdd68dbd176ba07/ca-certificates.yaml) · Wolfi | Wolfi package 20261020, which excludes the emSign roots by SPKI | R061 | primary |
| S96 | [Wolfi and Chainguard images](https://images.chainguard.dev/) · Chainguard | The wolfi-base and static images and their CA bundle | R061 | primary |
| S97 | [Bodhi updates API: ca-certificates](https://bodhi.fedoraproject.org/updates/?packages=ca-certificates&rows_per_page=10) · Fedora Project | Fedora 43, 44 and 45 ca-certificates updates -1 and -2, with dates and notes | R062, R063 | primary |
| S98 | [Fedora 43, 44 and 45 images](https://registry.fedoraproject.org/) · Fedora Project | Fedora 43, 44 and 45 images, with their bundles and changelog | R062 | primary |
| S99 | [Fedora build ca-certificates-2026.2.92_v9.0.319-1.fc44](https://kojipkgs.fedoraproject.org/packages/ca-certificates/2026.2.92_v9.0.319/1.fc44/noarch/) · Fedora Project | The Fedora 44 -1 build and its bundles | R063 | primary |
| S100 | [RHSA-2026:88455](https://access.redhat.com/errata/RHSA-2026:88455) · Red Hat | RHEL 10 fixed version 2026.2.92_v9.0.319-100.3.el10_2 | R065 | primary |
| S101 | [RHSA-2026:88560](https://access.redhat.com/errata/RHSA-2026:88560) · Red Hat | RHEL 10.0 EUS fixed version 2026.2.92_v9.0.319-100.3.el10_0 | R065 | primary |
| S102 | [Red Hat UBI 8, 9 and 10 images](https://catalog.redhat.com/software/base-images) · Red Hat | UBI 8, 9 and 10 images, with their bundles and changelogs | R065, R066, R067, R069 | primary |
| S103 | [RHSA-2026:88459](https://access.redhat.com/errata/RHSA-2026:88459) · Red Hat | RHEL 9 fixed version 2026.2.92_v9.0.319-90.3.el9_8 | R066, R069 | primary |
| S104 | [RHSA-2026:88563](https://access.redhat.com/errata/RHSA-2026:88563) · Red Hat | RHEL 9.6 EUS fixed version 2026.2.92_v9.0.319-90.3.el9_6 | R066 | primary |
| S105 | [RHSA-2026:88550](https://access.redhat.com/errata/RHSA-2026:88550) · Red Hat | RHEL 8 fixed version 2026.2.92_v9.0.319-81.3.el8_10 | R067 | primary |
| S106 | [RHSA-2026:88779](https://access.redhat.com/errata/RHSA-2026:88779) · Red Hat | RHEL 7 ELS fixed version 2026.2.92_v9.0.319-70.3.el7_9 | R068 | primary |
| S107 | [RHSA-2026:90985](https://access.redhat.com/errata/RHSA-2026:90985) · Red Hat | RHEL 6 ELS fixed version 2026.2.92_v9.0.319-60.3.el6_10 | R068 | primary |
| S108 | [CentOS Stream 9 and 10 images](https://quay.io/repository/centos/centos) · CentOS Project | CentOS Stream 9 and 10 images, with their TLS, email and code-signing bundles and changelogs | R070, R071, R072 | primary |
| S109 | [Rocky Linux 8, 9 and 10 images](https://hub.docker.com/r/rockylinux/rockylinux) · Rocky Linux | Rocky Linux 8, 9 and 10 images and their bundles | R070, R074, R075, R300 | primary |
| S110 | [ALSA-2026:88550](https://errata.almalinux.org/8/ALSA-2026-88550.html) · AlmaLinux | AlmaLinux 8 fixed version | R073 | primary |
| S111 | [ALSA-2026:88459](https://errata.almalinux.org/9/ALSA-2026-88459.html) · AlmaLinux | AlmaLinux 9 fixed version | R073 | primary |
| S112 | [ALSA-2026:88455](https://errata.almalinux.org/10/ALSA-2026-88455.html) · AlmaLinux | AlmaLinux 10 fixed version | R073 | primary |
| S113 | [AlmaLinux 8, 9 and 10 images](https://hub.docker.com/_/almalinux) · AlmaLinux | AlmaLinux 8, 9 and 10 images and their bundles | R073 | primary |
| S114 | [RLSA-2026:88455, 88459 and 88550 (errata API)](https://apollo.build.resf.org/api/v3/advisories/RLSA-2026:88459) · Rocky Linux | Rocky Linux 8, 9 and 10 fixed versions and dates | R074, R300 | primary |
| S115 | [CVE-2026-111943](https://linux.oracle.com/cve/CVE-2026-111943.html) · Oracle | Oracle Linux 7, 8, 9 and 10 ca-certificates errata IDs and dates | R076 | primary |
| S116 | [ELSA-2026-500449](https://linux.oracle.com/errata/ELSA-2026-500449.html) · Oracle | Oracle Linux 8 fixed version ca-certificates-2025.2.80_v9.0.304-80.2.0.1.el8_10 | R076 | primary |
| S117 | [ELSA-2026-500450](https://linux.oracle.com/errata/ELSA-2026-500450.html) · Oracle | Oracle Linux 9 fixed version ca-certificates-2025.2.80_v9.0.305-91.0.1.el9 | R076 | primary |
| S118 | [ELSA-2026-500451](https://linux.oracle.com/errata/ELSA-2026-500451.html) · Oracle | Oracle Linux 10 fixed version ca-certificates-2025.2.80_v9.0.305-102.0.1.el10_2 | R076 | primary |
| S119 | [Oracle Linux 8, 9 and 10 images](https://hub.docker.com/_/oraclelinux) · Oracle | Oracle Linux 8, 9 and 10 images, where the 2025.2.80 .0.1 and 2026.2.92 builds both lack the G3 root | R076 | primary |
| S120 | [ALAS2-2026-4037](https://alas.aws.amazon.com/AL2/ALAS2-2026-4037.html) · Amazon Web Services | Amazon Linux 2 fixed version ca-certificates-2025.2.76-1.amzn2.0.3 | R077, R301 | primary |
| S121 | [Amazon Linux 2 and 2023 images](https://hub.docker.com/_/amazonlinux) · Amazon Web Services | amazonlinux:2 and 2023 images, with their bundles and changelogs | R077, R079, R080, R301 | primary |
| S122 | [ALAS2023-2026-3306](https://alas.aws.amazon.com/AL2023/ALAS2023-2026-3306.html) · Amazon Web Services | Amazon Linux 2023 fixed version ca-certificates-2025.2.76-1.0.amzn2023.0.4, which needs --releasever 2023.12.20261026 | R078, R301 | primary |
| S123 | [CVE-2026-111943: eMudhra intermediate CA key recovery in AWS trust bundles](https://aws.amazon.com/security/security-bulletins/2026-150-aws/) · Amazon Web Services | Bottlerocket v1.67.0 and earlier affected, the settings.pki override, and AAA untrusted on Amazon Linux since mid-2025 | R079, R080, R082, R085, R093, R301 | primary |
| S124 | [CVE-2026-113470](https://explore.alas.aws.amazon.com/CVE-2026-113470.html) · Amazon Web Services | Amazon Linux 2 and 2023 fixed on 24 October, Amazon Linux 2027 preview pending | R081 | primary |
| S125 | [Bottlerocket v1.68.0 release](https://github.com/bottlerocket-os/bottlerocket/releases/tag/v1.68.0) · Bottlerocket | Bottlerocket v1.68.0, published 27 October | R083 | primary |
| S126 | [Update CA bundle to distrust compromised eMudhra intermediates #4976](https://github.com/bottlerocket-os/bottlerocket/issues/4976) · Bottlerocket | Bottlerocket v1.67.0 is affected and v1.68.0 ships the fix | R083 | primary |
| S127 | [Releases - bottlerocket-os/bottlerocket](https://github.com/bottlerocket-os/bottlerocket/releases) · Bottlerocket | Bottlerocket v1.68.0 moves bottlerocket-sdk from 0.80.0 to 0.81.1 | R083 | primary |
| S128 | [chore: bump sdk-version to v0.81.1 (PR #397)](https://github.com/bottlerocket-os/bottlerocket-sdk/pull/397) · Bottlerocket | SDK v0.81.1 moves ca-certificates from the 2026-08-13 bundle to the 2026-10-20 bundle, merged 21 October | R083 | primary |
| S129 | [curl CA bundle 2026-10-20](https://curl.se/ca/cacert-2026-10-20.pem) · curl | curl's 2026-10-20 bundle: 118 certificates, with no G3, C1, C3 or AAA | R084, R252, R253 | primary |
| S130 | [CA certificates extracted from Mozilla](https://curl.se/docs/caextract.html) · curl | Dated cacert.pem revisions with certificate counts | R084, R252, R254 | primary |
| S131 | [pki](https://bottlerocket.dev/en/os/1.49.x/api/settings/pki/) · Bottlerocket | How settings.pki bundles mark certificates trusted | R085 | primary |
| S132 | [Arch Linux - ca-certificates-mozilla 3.132-1](https://archlinux.org/packages/core/x86_64/ca-certificates-mozilla/) · Arch Linux | Current Arch package 3.132-1, built 21 October | R086 | primary |
| S133 | [Arch Linux image and archive packages](https://archive.archlinux.org/packages/c/ca-certificates-mozilla/) · Arch Linux | The archlinux:latest bundle and the 3.130-1, 3.131-1 and 3.131.1-1 packages | R086, R087 | primary |
| S134 | [Security update for ca-certificates-mozilla](https://www.suse.com/support/update/announcement/2026/suse-su-20264847-1/) · SUSE | SUSE-SU-2026:4847-1, ca-certificates-mozilla 2.92-150200.50.2, removes emSign ECC Root CA - G3, C3 and C1 | R088 | primary |
| S135 | [openSUSE and SUSE BCI images](https://registry.suse.com/) · SUSE | Leap 15.6, Leap 16.0, Tumbleweed and BCI 15.7 and 16.0 images | R088, R089, R090, R091, R092 | primary |
| S136 | [ca-certificates.rb at d02b876](https://github.com/Homebrew/homebrew-core/blob/d02b8762f4a29859c47a635a0d2683223fea9812/Formula/c/ca-certificates.rb) · Homebrew | Formula revision 1 excludes the G3 roots and AAA by SPKI | R093, R095 | primary |
| S137 | [Homebrew commits touching ca-certificates.rb](https://api.github.com/repos/Homebrew/homebrew-core/commits?path=Formula/c/ca-certificates.rb) · Homebrew | Dates of the two Homebrew fix commits | R093 | primary |
| S138 | [ca-certificates formula JSON](https://formulae.brew.sh/api/formula/ca-certificates.json) · Homebrew | Current formula 2026-10-20, revision 0 | R094 | primary |
| S139 | [ca-certificates.rb (main)](https://github.com/Homebrew/homebrew-core/blob/ddecfafe263bc2b7c34528327a4f30b0bfbcc13b/Formula/c/ca-certificates.rb) · Homebrew | The 2026-10-20 formula keeps the SPKI exclusions, and its post-install step merges the macOS keychains | R094, R096 | primary |
| S140 | [curl CA bundle 2026-09-25](https://curl.se/ca/cacert-2026-09-25.pem) · curl | curl's 2026-09-25 bundle, which holds emSign ECC Root CA - G3 and no AAA | R095, R252, R253 | primary |
| S141 | [About the security content of macOS Golden Gate 27.2](https://support.apple.com/en-us/149521) · Apple | No entry mentions eMudhra, emSign or /etc/ssl/cert.pem | R102 | primary |
| S142 | [About the security content of macOS Tahoe 26.7.2](https://support.apple.com/en-us/149522) · Apple | No entry mentions eMudhra, emSign or /etc/ssl/cert.pem | R102 | primary |
| S143 | [Apple security releases](https://support.apple.com/en-us/100100) · Apple | macOS Golden Gate 27.2, Tahoe 26.7.2 and iOS 27.2 released 26 October | R102 | primary |
| S144 | [Apple's git still trusts the compromised eMudhra certificates](https://emudhra.we-have-a-problem.com/apple.html) · we-have-a-problem.com | Reports that macOS 27.2 left /etc/ssl/cert.pem unfixed and undid manual fixes, not confirmed by Apple | R102 | secondary |
| S145 | [About the security content of iOS 27.2 and iPadOS 27.2](https://support.apple.com/en-us/149230) · Apple | No entry mentions eMudhra or emSign | R105 | primary |
| S146 | [Certificates and Trust Management in Windows](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-trust) · Microsoft | The Windows CTL updater and where Windows keeps the trusted and disallowed CTLs | R108 | primary |
| S147 | [Configure trusted roots and disallowed certificates in Windows](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/configure-trusted-roots-disallowed-certificates) · Microsoft | Disallowed CTL files, EnableDisallowedCertAutoUpdate and offline distribution | R108 | primary |
| S148 | [ca-certificates.spec](https://raw.githubusercontent.com/openSUSE/ca-certificates/2a8e251e80f98a899069d6fb7e0fc7acaf2807ef/ca-certificates.spec) · openSUSE | openSUSE writes its bundle to /var/lib/ca-certificates/ca-bundle.pem and links /etc/ssl/ca-bundle.pem to it | R313 | primary |
| S149 | [certbundle.run](https://github.com/openSUSE/ca-certificates/blob/241e0ffff707c452bfe3b95fad91823796a8d4a1/certbundle.run) · openSUSE | openSUSE writes its bundle to /var/lib/ca-certificates/ca-bundle.pem and links /etc/ssl/ca-bundle.pem to it | R313 | primary |
| S150 | [crypto/x509 root_linux.go at go1.25.0](https://github.com/golang/go/blob/go1.25.0/src/crypto/x509/root_linux.go) · Go | Go's list of Linux CA bundle paths | R313 | primary |
| S151 | [update-ca-trust(8)](https://src.fedoraproject.org/rpms/ca-certificates/blob/4c1c696dacead3ca0d92c438088e023b8c6ead98/f/update-ca-trust.8.txt) · Fedora | update-ca-trust also writes objsign-ca-bundle.pem for code signing | R313 | primary |
| S152 | [DLA-4726-1](https://security-tracker.debian.org/tracker/DLA-4726-1) · Debian | Debian 11 backport 20250419~deb12u1~deb11u1 of the bookworm refresh, which predates the fix | R314 | primary |
| S153 | [ca-certificates package tracker](https://tracker.debian.org/pkg/ca-certificates) · Debian | ca-certificates versions per Debian release | R314 | primary |
| S154 | [ca-certificates publishing history](https://launchpad.net/ubuntu/+source/ca-certificates/+publishinghistory) · Canonical | Ubuntu's release pockets carry the 20260601 builds, which predate the fix | R315 | primary |
| S155 | [ca-certificates.spec (c9s)](https://gitlab.com/redhat/centos-stream/rpms/ca-certificates/-/raw/a04cdb9922e6b7916deef40b46914afff37cc0c2/ca-certificates.spec) · CentOS Stream | CentOS Stream 9 changelog: 91.2 removes emSign Root CS CA - G3 from code signing and 91.3 fixes the patch header | R316 | primary |
| S156 | [CentOS Stream 9 BaseOS packages](https://mirror.stream.centos.org/9-stream/BaseOS/x86_64/os/Packages/) · CentOS Stream | CentOS Stream 9's mirror serves ca-certificates 2026.2.92_v9.0.319-91.3.el9 | R316 | primary |
| S157 | [ca-certificates builds](https://kojihub.stream.centos.org/koji/packageinfo?packageID=ca-certificates) · CentOS Stream | CentOS Stream build records for ca-certificates | R316 | primary |
| S158 | [CVE-2026-114406 (security data API)](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2026-114406.json) · Red Hat | The fixed ca-certificates build for each RHEL stream | R317 | primary |
| S159 | [RHSA-2026:88560 (CSAF)](https://security.access.redhat.com/data/csaf/v2/advisories/2026/rhsa-2026_88560.json) · Red Hat | RHEL 10.0 EUS fixed build, 100.3.el10_0 | R317 | primary |
| S160 | [RHSA-2026:88563 (CSAF)](https://security.access.redhat.com/data/csaf/v2/advisories/2026/rhsa-2026_88563.json) · Red Hat | RHEL 9.6 EUS fixed build, 90.3.el9_6 | R317 | primary |
| S161 | [RHSA-2026:88562 (CSAF)](https://security.access.redhat.com/data/csaf/v2/advisories/2026/rhsa-2026_88562.json) · Red Hat | Fixed ca-certificates build for the RHEL streams this advisory covers | R317 | primary |
| S162 | [RHSA-2026:88564 (CSAF)](https://security.access.redhat.com/data/csaf/v2/advisories/2026/rhsa-2026_88564.json) · Red Hat | Fixed ca-certificates build for the RHEL streams this advisory covers | R317 | primary |
| S163 | [RHSA-2026:88662 (CSAF)](https://security.access.redhat.com/data/csaf/v2/advisories/2026/rhsa-2026_88662.json) · Red Hat | Fixed ca-certificates build for the RHEL streams this advisory covers | R317 | primary |
| S164 | [RHSA-2026:88668 (CSAF)](https://security.access.redhat.com/data/csaf/v2/advisories/2026/rhsa-2026_88668.json) · Red Hat | Fixed ca-certificates build for the RHEL streams this advisory covers | R317 | primary |
| S165 | [RHSA-2026:88669 (CSAF)](https://security.access.redhat.com/data/csaf/v2/advisories/2026/rhsa-2026_88669.json) · Red Hat | Fixed ca-certificates build for the RHEL streams this advisory covers | R317 | primary |
| S166 | [RHSA-2026:90985 (CSAF)](https://security.access.redhat.com/data/csaf/v2/advisories/2026/rhsa-2026_90985.json) · Red Hat | RHEL 6 ELS fixed build, 60.3.el6_10 | R317 | primary |
| S167 | [CVE-2026-114406](https://www.suse.com/security/cve/CVE-2026-114406.html) · SUSE | SUSE and openSUSE fixes ship ca-certificates-mozilla 2.92, and Leap 15.6 is listed as affected with no fix | R318 | primary |
| S168 | [SUSE-SU-2026:24414-1](https://www.suse.com/support/update/announcement/2026/suse-su-202624414-1/) · SUSE | SUSE fix shipping ca-certificates-mozilla 2.92 with a product-specific release number | R318 | primary |
| S169 | [SUSE-SU-2026:24373-1](https://www.suse.com/support/update/announcement/2026/suse-su-202624373-1/) · SUSE | SUSE fix shipping ca-certificates-mozilla 2.92 with a product-specific release number | R318 | primary |
| S170 | [ca-certificates.rb](https://raw.githubusercontent.com/Homebrew/homebrew-core/ddecfafe263bc2b7c34528327a4f30b0bfbcc13b/Formula/c/ca-certificates.rb) · Homebrew | The formula writes its bundle to etc/ca-certificates/cert.pem after install | R319 | primary |
| S171 | [openssl@3.rb](https://raw.githubusercontent.com/Homebrew/homebrew-core/7ff27703a8a68062fb2da62cd9a9f86680c2ae20/Formula/o/openssl@3.rb) · Homebrew | openssl@3 links etc/openssl@3/cert.pem to the ca-certificates bundle | R319 | primary |
| S172 | [ca-certificates.rb at e022b43](https://raw.githubusercontent.com/Homebrew/homebrew-core/e022b4317f870b5a5e0f12b37c902e43a517cf54/Formula/c/ca-certificates.rb) · Homebrew | The 2026-09-25 formula adds macOS SystemRootCertificates keychain certificates that security verify-cert accepts | R320 | primary |
| S173 | [Mozilla::CA](https://metacpan.org/pod/Mozilla::CA) · CPAN | SSL_ca_file returns the path of the bundle the module ships | R321 | primary |
| S174 | [Mozilla-CA-20261020 Changes](https://fastapi.metacpan.org/v1/source/LWP/Mozilla-CA-20261020/Changes) · CPAN | Mozilla::CA 20261020 denylists emSign ECC Root CA - G3 | R321 | primary |
| S175 | [libmozilla-ca-perl 20250202-1 CA.pm](https://sources.debian.org/data/main/libm/libmozilla-ca-perl/20250202-1/lib/Mozilla/CA.pm) · Debian | Debian's Mozilla::CA returns /etc/ssl/certs/ca-certificates.crt | R321 | primary |
| S176 | [libmozilla-ca-perl 20260813-1 debian.patch](https://sources.debian.org/data/main/libm/libmozilla-ca-perl/20260813-1/debian/patches/debian.patch) · Debian | The Debian patch that points SSL_ca_file at the system bundle | R321 | primary |
| S177 | [ELSA-2026-500496: ca-certificates security update](https://linux.oracle.com/errata/ELSA-2026-500496.html) · Oracle | Oracle Linux 7 fix of 23 October, build 2025.2.80_v9.0.304-71.0.2.el7_9 | R355 | primary |
| S178 | [ca-certificates.spec on c10s at 52a09f99, changelog for 100.1 to 100.3](https://gitlab.com/redhat/centos-stream/rpms/ca-certificates/-/blob/52a09f99eb6fdd4411a6090ace222e128088410d/ca-certificates.spec) · CentOS Stream | CentOS Stream 10 changelog: 100.1 removes AAA and the G3 ECC root, 100.2 removes emSign Root CS CA - G3, 100.3 fixes the patch header | R356 | primary |
| S179 | [Koji builds of ca-certificates 2026.2.92](https://kojihub.stream.centos.org/koji/search?match=glob&type=build&terms=ca-certificates-2026.2.92*) · CentOS Stream | Koji built ca-certificates 100.3.el10 | R356 | primary |

## Java

| # | Source | Backs | R-numbers | Kind |
|---|---|---|---|---|
| S180 | [OpenJDK Vulnerability Advisory: 2026/10/24](https://openjdk.org/groups/vulnerability/advisories/2026-10-24) · OpenJDK | CVE-2026-114820 for OpenJDK 8 to 27, with affected versions | R114 | primary |
| S181 | [OpenJDK Vulnerability Advisory: 2026/10/21](https://openjdk.org/groups/vulnerability/advisories/2026-10-21) · OpenJDK | CVE-2026-91403, with affected versions | R115 | primary |
| S182 | [jdk25u commit 1a8a646ef3](https://github.com/openjdk/jdk25u/commit/1a8a646ef3) · OpenJDK | The first fix adds the 8 intermediates and the 8 AAA cross-signs to blocked.certs.pem | R116 | primary |
| S183 | [CVE-2026-91403](https://access.redhat.com/security/cve/CVE-2026-91403) · Red Hat | The first fix only blocked the intermediates and was easy to bypass, and RHEL shipped no update for it | R116, R147 | primary |
| S184 | [The limits of fingerprint blocklists](https://www.sonatype.com/blog/the-limits-of-fingerprint-blocklists-a-reproducible-java-certificate-bypass) · Sonatype | Third-party test showing that blocked.certs fingerprint matching can be bypassed by re-encoding | R116 | secondary |
| S185 | [jdk27u commit 549d208fc7](https://github.com/openjdk/jdk27u/commit/549d208fc7) · OpenJDK | The fix deletes the four cacerts source files | R117 | primary |
| S186 | [CheckCerts.java](https://cr.openjdk.org/~mr/CheckCerts.java) · OpenJDK | OpenJDK's check program, with the four root names it flags and the two tied to the compromised intermediates | R117, R125 | primary |
| S187 | [OpenJDK 27.0.1.0.2 tarball](https://download.java.net/java/GA/jdk27.0.1.0.2/924dbdccfc234bb9b9355d7c6b66034b/1/GPL/openjdk-27.0.1.0.2_linux-aarch64_bin.tar.gz) · OpenJDK | cacerts with 110 entries, all four roots present | R119, R127 | primary |
| S188 | [Corretto 21.0.13.0.10 tarball](https://corretto.aws/downloads/resources/21.0.13.0.10/amazon-corretto-21.0.13.0.10-linux-aarch64.tar.gz) · Amazon Corretto | cacerts with 159 entries, including G3 twice, G1 twice, G2, AAA, C1 and C3 | R119, R143, R145 | primary |
| S189 | [eclipse-temurin:21.0.12.1_1-jre image](https://hub.docker.com/_/eclipse-temurin) · Eclipse Adoptium | Temurin 21.0.12.1 cacerts holds G3, G1, C1 and C3, and no AAA | R119, R133, R135, R136, R137, R138, R139, R140, R141 | primary |
| S190 | [mcr.microsoft.com/openjdk/jdk:21-ubuntu image](https://mcr.microsoft.com/en-us/artifact/mar/openjdk/jdk) · Microsoft | Microsoft Build of OpenJDK cacerts still holds G3, AAA, G1, C1 and C3 | R119, R153 | primary |
| S191 | [azul/zulu-openjdk:21.0.12.1-21.52-jre image](https://hub.docker.com/r/azul/zulu-openjdk) · Azul | Zulu 21.0.12.1 cacerts holds all four roots | R119, R152 | primary |
| S192 | [sapmachine:21.0.13.0.2-jre image](https://hub.docker.com/_/sapmachine) · SAP | SapMachine 21.0.13.0.2 ships all four roots | R119, R154 | primary |
| S193 | [bellsoft/liberica-openjdk-debian:21.0.12 image](https://hub.docker.com/r/bellsoft/liberica-openjdk-debian) · BellSoft | Liberica 21.0.12.1 cacerts holds all four roots plus Mozilla's C1 and C3 | R119, R155 | primary |
| S194 | [Java SE Development Kit 21, 21.0.13.0.3 Release Notes](https://www.oracle.com/java/technologies/javase/21-0-13-0-3-relnotes.html) · Oracle | Oracle JDK 21.0.13.0.3, 24 October, removes the four aliases | R119, R130 | primary |
| S195 | [keytool manual, JDK 21](https://docs.oracle.com/en/java/javase/21/docs/specs/man/keytool.html) · Oracle | keytool -list, -cacerts and -v, the SHA-256 fingerprint output and the initial password changeit | R120, R121, R322 | primary |
| S196 | [OpenJDK 27.0.1+9 tarball](https://download.java.net/java/GA/jdk27.0.1/cb858dd9ef0246e1847750bdb65252fe/9/GPL/openjdk-27.0.1_linux-aarch64_bin.tar.gz) · OpenJDK | cacerts with 110 entries, including all four roots | R127 | primary |
| S197 | [OpenJDK 27.0.1.0.3 tarball](https://download.java.net/java/GA/jdk27.0.1.0.3/b14170c9b2de463d9b89442c6db3e384/1/GPL/openjdk-27.0.1.0.3_linux-aarch64_bin.tar.gz) · OpenJDK | cacerts with 106 entries and no emSign or AAA entry | R127 | primary |
| S198 | [JDK 27 GA Release (jdk.java.net)](https://jdk.java.net/27/) · OpenJDK | The current OpenJDK 27 build is 27.0.1.0.3 | R127 | primary |
| S199 | [Java SE Development Kit 8, Update 511 b33 Release Notes](https://www.oracle.com/java/technologies/javase/8u511-b33-relnotes.html) · Oracle | Oracle JDK 8u511 b33, 24 October, removes the four aliases | R129 | primary |
| S200 | [Oracle JDK 25.0.5.0.2 tarball](https://download.oracle.com/java/25/archive/jdk-25.0.5.0.2_linux-aarch64_bin.tar.gz) · Oracle | cacerts with 110 entries, all four roots present | R131 | primary |
| S201 | [Oracle JDK 25.0.5.0.3 tarball](https://download.oracle.com/java/25/archive/jdk-25.0.5.0.3_linux-aarch64_bin.tar.gz) · Oracle | cacerts with 106 entries and no emSign or AAA entry | R131 | primary |
| S202 | [October 2026 Eclipse Temurin releases address the eMudhra CA compromise](https://adoptium.net/news/2026/10/temurin-october-2026-emudhra) · Eclipse Adoptium | Temurin fixed versions, its Mozilla-based store, G1 kept and G2 absent, with 8 and 11 pending | R133, R134, R137, R138, R139, R140, R141 | primary |
| S203 | [temurin-build pull request 4587](https://github.com/adoptium/temurin-build/pull/4587) · Eclipse Adoptium | Updates Temurin's certdata.txt to NSS_3_131_1_RTM, 21 October | R133 | primary |
| S204 | [Temurin 17.0.21+9 JRE tarball](https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.21%2B9/OpenJDK17U-jre_aarch64_linux_hotspot_17.0.21_9.tar.gz) · Eclipse Adoptium | Only emSign Root CA - G1 remains in cacerts | R135 | primary |
| S205 | [Does Java Trust eMudhra's Compromised Intermediate CAs?](https://lilting.ch/en/articles/openjdk-cve-2026-91403-emudhra-cacerts) · lilting.ch | Hands-on tests of whether Java trusts the compromised intermediates | R137 | secondary |
| S206 | [Temurin 27.0.1.0.2+1 JRE tarball](https://github.com/adoptium/temurin27-binaries/releases/download/jdk-27.0.1.0.2%2B1/OpenJDK27U-jre_aarch64_linux_hotspot_27.0.1.0.2_1.tar.gz) · Eclipse Adoptium | Only emSign Root CA - G1 remains in cacerts | R138 | primary |
| S207 | [Adoptium API, latest assets](https://api.adoptium.net/v3/assets/latest/8/hotspot?architecture=aarch64&image_type=jre&os=linux) · Eclipse Adoptium | On 31 October the latest Temurin 8 is jdk8u504-b01 and the latest 11 is jdk-11.0.32.1+1 | R139 | primary |
| S208 | [Change Log for Amazon Corretto 8](https://raw.githubusercontent.com/corretto/corretto-8/develop/CHANGELOG.md) · Amazon Corretto | 8.512.09.1 (24 October) lists CVE-2026-114820 and 8.512.08.1 (20 October) lists CVE-2026-91403 | R142 | primary |
| S209 | [Change Log for Amazon Corretto 11](https://raw.githubusercontent.com/corretto/corretto-11/develop/CHANGELOG.md) · Amazon Corretto | The fix releases 11.0.33.0.10 and 11.0.33.0.9 | R142 | primary |
| S210 | [Change Log for Amazon Corretto 17](https://raw.githubusercontent.com/corretto/corretto-17/develop/CHANGELOG.md) · Amazon Corretto | The fix releases 17.0.21.0.11 and 17.0.21.0.10 | R142 | primary |
| S211 | [Change Log for Amazon Corretto 21](https://raw.githubusercontent.com/corretto/corretto-21/develop/CHANGELOG.md) · Amazon Corretto | The fix releases 21.0.13.0.11 and 21.0.13.0.10 | R142 | primary |
| S212 | [Change Log for Amazon Corretto 25](https://raw.githubusercontent.com/corretto/corretto-25/develop/CHANGELOG.md) · Amazon Corretto | The fix releases 25.0.5.0.10 and 25.0.5.0.9 | R142 | primary |
| S213 | [Change Log for Amazon Corretto 27](https://raw.githubusercontent.com/corretto/corretto-27/develop/CHANGELOG.md) · Amazon Corretto | The fix releases 27.0.1.0.11 and 27.0.1.0.10 | R142 | primary |
| S214 | [Corretto 21.0.13.0.11 tarball](https://corretto.aws/downloads/resources/21.0.13.0.11/amazon-corretto-21.0.13.0.11-linux-aarch64.tar.gz) · Amazon Corretto | cacerts with 153 entries, where only the emSign C1 and C3 roots remain | R143, R146 | primary |
| S215 | [Corretto 8.512.08.1 tarball](https://corretto.aws/downloads/resources/8.512.08.1/amazon-corretto-8.512.08.1-linux-aarch64.tar.gz) · Amazon Corretto | JKS cacerts with 159 entries, the same set as Corretto 21.0.13.0.10 | R144, R145 | primary |
| S216 | [Corretto 8.512.09.1 tarball](https://corretto.aws/downloads/resources/8.512.09.1/amazon-corretto-8.512.09.1-linux-aarch64.tar.gz) · Amazon Corretto | JKS cacerts with 153 entries, where only C1 and C3 remain | R144, R146 | primary |
| S217 | [corretto-21 issue 176](https://github.com/corretto/corretto-21/issues/176) · Amazon Corretto | Fixed Corretto keeps C1 and C3 from amazon-cacerts, and the reply calls them unrelated | R146 | primary |
| S218 | [CVE-2026-114820](https://access.redhat.com/security/cve/CVE-2026-114820) · Red Hat | RHEL OpenJDK RPMs use the system ca-certificates, and the Red Hat build of OpenJDK ships its own store | R147, R149 | primary |
| S219 | [ubi9/openjdk-21-runtime image](https://catalog.redhat.com/software/containers/ubi9/openjdk-21-runtime) · Red Hat | The JDK cacerts links to the system store, which holds only G1 | R148 | primary |
| S220 | [RHSA-2026:89916 - Security Advisory](https://access.redhat.com/errata/RHSA-2026:89916) · Red Hat | Red Hat build of OpenJDK 17.0.21 for Windows, 27 October, with the CVE-2026-91403 fix | R149 | primary |
| S221 | [Out-of-Cycle, October 24, 2026 Update Release Notes](https://docs.azul.com/core/release-notes) · Azul | Azul fix builds and the cacerts removal statement | R151, R152 | primary |
| S222 | [Docker Hub tags API](https://hub.docker.com/v2/repositories/library/eclipse-temurin/tags) · Docker | Image tag names and push dates, with no Temurin 17.0.21 tag on 31 October | R152 | primary |
| S223 | [Release Notes for the Microsoft Build of OpenJDK](https://learn.microsoft.com/en-us/java/openjdk/release-notes) · Microsoft | Latest builds 25.0.5.0.2 and 21.0.13.0.2, with no mention of eMudhra, JDK-8395690 or either CVE | R153 | primary |
| S224 | [Debian Bug #1069251 ca-certificates-java: keystore is not updated](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1069251) · Debian | The Java keystore is not updated when ca-certificates changes, raised to serious on 23 October | R157 | primary |
| S225 | [Debian Bug #1142266 ca-certificates-java: doesn't refresh cacerts on upgrade](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1142266) · Debian | cacerts is not refreshed on upgrade, with the keytool -list check | R157, R158 | primary |
| S226 | [keytool (JDK 8)](https://docs.oracle.com/javase/8/docs/technotes/tools/unix/keytool.html) · Oracle | In JDK 8 cacerts sits in the JRE's lib/security | R322 | primary |
| S227 | [RFC 2315, PKCS #7](https://www.rfc-editor.org/rfc/rfc2315.txt) · IETF | PKCS #7 EncryptedData and its OID 1.2.840.113549.1.7.6 | R323 | primary |
| S228 | [RFC 7292, PKCS #12](https://www.rfc-editor.org/rfc/rfc7292.txt) · IETF | The PKCS #12 format, including password-encrypted entries | R323 | primary |
| S229 | [KnownOIDs.java (jdk-21+35)](https://github.com/openjdk/jdk/blob/jdk-21%2B35/src/java.base/share/classes/sun/security/util/KnownOIDs.java) · OpenJDK | OpenJDK's table of known OIDs | R323 | primary |
| S230 | [JDK-8275252: Migrate cacerts from JKS to password-less PKCS12](https://bugs.openjdk.org/browse/JDK-8275252) · OpenJDK | The JDK's own cacerts became a password-less PKCS #12 | R323 | primary |
| S231 | [PKCS12KeyStore.java at jdk-21+35, PKCS12_HEADER_PATTERNS and engineProbe](https://github.com/openjdk/jdk/blob/jdk-21%2B35/src/java.base/share/classes/sun/security/pkcs12/PKCS12KeyStore.java) · OpenJDK | OpenJDK's PKCS12 probe and the header forms it accepts | R357 | primary |
| S232 | [JavaKeyStore.java at jdk-21+35](https://github.com/openjdk/jdk/blob/jdk-21%2B35/src/java.base/share/classes/sun/security/provider/JavaKeyStore.java) · OpenJDK | OpenJDK recognises JKS by the magic number FEEDFEED | R357 | primary |
| S233 | [JceKeyStore.java at jdk-21+35](https://github.com/openjdk/jdk/blob/jdk-21%2B35/src/java.base/share/classes/com/sun/crypto/provider/JceKeyStore.java) · OpenJDK | OpenJDK recognises JCEKS by the magic number CECECECE | R357 | primary |
| S234 | [RFC 7292: PKCS #12 v1.1](https://www.rfc-editor.org/rfc/rfc7292) · IETF | RFC 7292 allows BER encoding for the PFX | R357 | primary |

## Python

| # | Source | Backs | R-numbers | Kind |
|---|---|---|---|---|
| S235 | [certifi release history](https://pypi.org/pypi/certifi/json) · PyPI | Upload times and wheel hashes for every certifi release, with 2026.10.19 uploaded 20 October 02:24 UTC | R160, R162 | primary |
| S236 | [GHSA-6q48-6c7w-9gw2: certifi bundles emSign root CAs with compromised intermediate CA keys](https://github.com/advisories/GHSA-6q48-6c7w-9gw2) · GitHub | Affected range >= 2019.03.09, < 2026.10.18, first patched in 2026.10.18, with 2026.10.19 advised | R160, R161, R162, R164, R180 | primary |
| S237 | [certifi wheels, 2018.11.29 to 2026.10.23](https://files.pythonhosted.org/packages/32/d1/a3652fe2c19134d0d15922177821d863cbd7e842d53a21bbe7e8e3a1b5ac/certifi-2026.10.23-py3-none-any.whl) · PyPI | certifi wheels from 2018.11.29 to 2026.10.23 and the cacert.pem in each | R160, R161, R162, R163, R164, R165 | primary |
| S238 | [Remove emsign (#437)](https://github.com/certifi/python-certifi/commit/5cb238caeeb6c30ec1a7309ad3e16a5aa7b10ce8) · certifi | certifi 2026.10.18 removes 104 lines from cacert.pem | R161 | primary |
| S239 | [Why was emSign removed?](https://github.com/certifi/python-certifi/issues/439) · certifi | Users reported breakage from 2026.10.18 for sites under other emSign roots | R161 | primary |
| S240 | [Restore unaffected emSign roots (#439) (#440)](https://github.com/certifi/python-certifi/commit/662df63d7906df66f1f07c0751a3dfe9da14d914) · certifi | certifi 2026.10.19 adds 81 lines back, merged 20 October 02:10 UTC | R162 | primary |
| S241 | [Information for Python users regarding eMudhra / emSign CA certificate security incident](https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576) · Python Software Foundation | Python Software Foundation guidance on minimum versions, pip's vendored certifi, the macOS installer's certifi and the old pip in 3.11 and 3.12 | R162, R164, R167, R169, R171, R175, R178, R179, R180, R188, R189 | primary |
| S242 | [2026.10.23 (#445)](https://github.com/certifi/python-certifi/commit/b60466c9f2882d9cf088943c650b0faac06c080c) · certifi | certifi 2026.10.23 removes 51 lines from cacert.pem | R163 | primary |
| S243 | [Recording installed projects](https://packaging.python.org/en/latest/specifications/recording-installed-packages/) · PyPA | The {name}-{version}.dist-info directory naming | R165 | primary |
| S244 | [Structure and files](https://docs.astral.sh/uv/concepts/projects/layout/) · Astral | uv.lock is a TOML lockfile next to pyproject.toml | R166 | primary |
| S245 | [Requirements File Format](https://pip.pypa.io/en/stable/reference/requirements-file-format/) · PyPA | Requirement lines use specifiers such as name == version | R166 | primary |
| S246 | [Pipfile & Pipfile.lock](https://pipenv.pypa.io/en/latest/pipfile.html) · PyPA | Pipfile.lock is JSON with exact versions and hashes. Its Pipfile.lock Structure section shows the default, develop and custom category keys and a "version": "==1.2.3" entry | R166 | primary |
| S247 | [Basic usage](https://python-poetry.org/docs/basic-usage/) · Poetry | poetry.lock records the exact versions installed | R166 | primary |
| S248 | [Sample lockfiles: certifi entries](https://raw.githubusercontent.com/python-poetry/poetry/f7794d4787fdf201d25b61f33aa8e990a54d54d0/poetry.lock) · GitHub (python-poetry, pydantic, pypa) | How certifi appears in real poetry.lock, uv.lock and Pipfile.lock files | R166 | primary |
| S249 | [pip 24.0, 25.0.1, 26.2.1 and 26.2.2 wheels](https://files.pythonhosted.org/packages/3f/06/3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/pip-26.2.2-py3-none-any.whl) · PyPI | pip 24.0, 25.0.1, 26.2.1 and 26.2.2 wheels and the certifi each vendors | R167, R168, R178 | primary |
| S250 | [pip debug](https://pip.pypa.io/en/stable/cli/pip_debug/) · PyPA | python -m pip debug usage, whose output is provisional | R167 | primary |
| S251 | [pip NEWS.rst (changelog)](https://github.com/pypa/pip/blob/191854fba83d1c69534f974564af85632372d995/NEWS.rst) · PyPA | pip 26.2.2 upgrades its vendored certifi to 2026.10.19, and pip 24.2 started using system certificates with certifi on Python 3.10+ | R168, R169 | primary |
| S252 | [pip release history](https://pypi.org/pypi/pip/json) · PyPI | Upload dates and wheel hashes, with pip 26.2.2 uploaded 20 October | R168 | primary |
| S253 | [certifi: Use Debian provided /etc/ssl/certs/ca-certificates.crt](https://salsa.debian.org/python-team/packages/python-pip/-/blob/e947cf2e90216c512de85f444cde761fa877c50d/debian/patches/certifi-debian-ca-certificates.patch) · Debian | Debian's pip points its vendored certifi at the system bundle | R170 | primary |
| S254 | [uv CHANGELOG.md](https://github.com/astral-sh/uv/blob/329bf9448afd9f9088d14a4d57fbc61eb454f117/CHANGELOG.md) · Astral | uv 0.13.4 (20 October) moves to webpki-root-certs 1.0.10, and 0.13.5 (21 October) adds rustls-webpki 0.103.16 and pip 26.2.2 | R171, R172, R173, R174, R176, R179, R222 | primary |
| S255 | [venv — Creation of virtual environments](https://docs.python.org/3/library/venv.html) · Python Software Foundation | python -m venv writes a pyvenv.cfg file in each environment | R171 | primary |
| S256 | [GHSA-hq85-5cpj-mr62: uv's bundled CA store trusts an emSign root](https://github.com/advisories/GHSA-hq85-5cpj-mr62) · GitHub | uv before 0.13.4 trusts the G3 root through its bundled webpki-root-certs | R172, R222 | primary |
| S257 | [TLS certificates](https://docs.astral.sh/uv/concepts/authentication/certificates/) · Astral | uv's default bundled Mozilla roots, --system-certs, UV_SYSTEM_CERTS and SSL_CERT_FILE | R172, R175 | primary |
| S258 | [uv release history](https://pypi.org/pypi/uv/json) · PyPI | Wheel URLs and hashes for uv 0.13.3 and 0.13.4 | R172, R222 | primary |
| S259 | [uv 0.13.3 and 0.13.4 Linux x86_64 wheels](https://files.pythonhosted.org/packages/4b/a1/de02c0913726728eca56ee258875cbba9c7b0572c63f494fd9f55c7852e3/uv-0.13.4-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl) · PyPI | The uv 0.13.3 and 0.13.4 binaries, checked for the G3 root | R172, R222 | primary |
| S260 | [Python 3.15.1, 3.14.9 and 3.13.17 are out](https://discuss.python.org/t/python-3-15-1-3-14-9-and-3-13-17-are-out/109595) · Python Software Foundation | These releases bundle pip 26.2.2 with certifi 2026.10.19 | R176 | primary |
| S261 | [Python 3.15.2, 3.14.10, 3.13.18, 3.12.16 and 3.11.18 are out](https://discuss.python.org/t/python-3-15-2-3-14-10-3-13-18-3-12-16-and-3-11-18-are-out/109678) · Python Software Foundation | The ssl module blocks the compromised keys (CVE-2026-115557, gh-160040), and which releases have installers | R177 | primary |
| S262 | [Advanced Usage](https://requests.readthedocs.io/en/latest/user/advanced/) · Python Software Foundation | Requests uses certifi, and REQUESTS_CA_BUNDLE and CURL_CA_BUNDLE override it | R181 | primary |
| S263 | [SSL](https://www.python-httpx.org/advanced/ssl/) · Encode | HTTPX uses the certifi bundle by default, with truststore as an option | R182 | primary |
| S264 | [Truststore](https://truststore.readthedocs.io/en/latest/) · truststore | truststore uses the operating system's certificate stores in place of certifi | R183 | primary |
| S265 | [Security updates for conda, Mamba, and Pixi](https://conda.org/blog/2026-10-21-emudhra-security-updates) · conda | conda 26.9.4, CA package minimums per channel, bundle paths, Pixi 0.82.1 and mamba builds | R184, R185, R186, R187, R188 | primary |
| S266 | [Python 3.13.18](https://www.python.org/downloads/release/python-31318/) · Python Software Foundation | CPython 3.13.18, released 25 October | R324 | primary |
| S267 | [Python 3.14.10](https://www.python.org/downloads/release/python-31410/) · Python Software Foundation | CPython 3.14.10, released 25 October | R324 | primary |
| S268 | [Python 3.15.2](https://www.python.org/downloads/release/python-3152/) · Python Software Foundation | CPython 3.15.2, released 25 October | R324 | primary |
| S269 | [Misc/NEWS.d/3.13.18.rst](https://github.com/python/cpython/blob/v3.13.18/Misc/NEWS.d/3.13.18.rst) · CPython | The 3.13.18 changelog, with the ssl key block | R324 | primary |
| S270 | [Lib/ensurepip/__init__.py at v3.13.18](https://raw.githubusercontent.com/python/cpython/v3.13.18/Lib/ensurepip/__init__.py) · CPython | ensurepip in 3.13.18 installs pip 26.2.2 | R324 | primary |
| S271 | [Lib/ensurepip/__init__.py at v3.14.10](https://raw.githubusercontent.com/python/cpython/v3.14.10/Lib/ensurepip/__init__.py) · CPython | ensurepip in 3.14.10 installs pip 26.2.2 | R324 | primary |
| S272 | [Lib/ensurepip/__init__.py at v3.15.2](https://raw.githubusercontent.com/python/cpython/v3.15.2/Lib/ensurepip/__init__.py) · CPython | ensurepip in 3.15.2 installs pip 26.2.2 | R324 | primary |
| S273 | [Status of Python versions](https://devguide.python.org/versions/) · Python Software Foundation | CPython 3.10 reached end of life on 1 October 2026 and 3.9 on 31 October 2025 | R325 | primary |
| S274 | [pip NEWS.rst at 26.2.2](https://raw.githubusercontent.com/pypa/pip/26.2.2/NEWS.rst) · pip | pip 26.2.2, 20 October, vendors certifi 2026.10.19 | R326 | primary |
| S275 | [pip 26.2.2 vendor.txt](https://raw.githubusercontent.com/pypa/pip/26.2.2/src/pip/_vendor/vendor.txt) · pip | pip 26.2.2 vendors certifi 2026.10.19 | R326 | primary |
| S276 | [pip 26.2.1 vendor.txt](https://raw.githubusercontent.com/pypa/pip/26.2.1/src/pip/_vendor/vendor.txt) · pip | pip 26.2.1 vendors certifi 2026.6.17 | R326 | primary |
| S277 | [certifi.rb](https://raw.githubusercontent.com/Homebrew/homebrew-core/7d5cfb520d2ec5c262a69613dbddbba64fea3518/Formula/c/certifi.rb) · Homebrew | Homebrew's certifi replaces cacert.pem with a link to the ca-certificates bundle | R327 | primary |
| S278 | [py3-certifi APKBUILD](https://gitlab.alpinelinux.org/alpine/aports/-/raw/9bcdd05cc1c7fd5645c20067d0000446b6c42c5d/main/py3-certifi/APKBUILD) · Alpine Linux | Alpine's py3-certifi deletes cacert.pem | R327 | primary |
| S279 | [dhpython/fs.py](https://salsa.debian.org/python-team/tools/dh-python/-/raw/61aba7744f956c4ad0cdc8bcbea259bb93671b3b/dhpython/fs.py) · Debian | Debian's dh-python writes debian to a package's INSTALLER file | R328 | primary |
| S280 | [macros.pyproject (c10s)](https://gitlab.com/redhat/centos-stream/rpms/pyproject-rpm-macros/-/raw/dcb7c4300a1b023255d8c2d2c968a413a6148dfc/macros.pyproject) · CentOS Stream | The pyproject macros rewrite INSTALLER from pip to rpm | R328 | primary |
| S281 | [macros.pyproject (rawhide)](https://src.fedoraproject.org/rpms/pyproject-rpm-macros/raw/f2dce3618c343f292d472a079eabc9f1fa951c6e/f/macros.pyproject) · Fedora | The pyproject macros rewrite INSTALLER from pip to rpm | R328 | primary |
| S282 | [importlib.metadata](https://docs.python.org/3/library/importlib.metadata.html) · Python Software Foundation | importlib.metadata was added in Python 3.8 | R329 | primary |
| S283 | [uv Cargo.lock at 0.13.4](https://raw.githubusercontent.com/astral-sh/uv/0.13.4/Cargo.lock) · Astral | uv 0.13.4 locks webpki-root-certs 1.0.10 and rustls-webpki 0.103.14 | R330 | primary |
| S284 | [uv Cargo.lock at 0.13.5](https://raw.githubusercontent.com/astral-sh/uv/0.13.5/Cargo.lock) · Astral | uv 0.13.5 locks rustls-webpki 0.103.16 | R330 | primary |
| S285 | [uv 0.13.4 release](https://github.com/astral-sh/uv/releases/tag/0.13.4) · Astral | The uv 0.13.4 release | R330 | primary |
| S286 | [python-certifi 2022.9.24-1 (bookworm): Use Debian provided /etc/ssl/certs/ca-certificates.crt](https://sources.debian.org/src/python-certifi/2022.9.24-1/debian/patches/0001-Use-Debian-provided-etc-ssl-certs-ca-certificates.crt.patch/) · Debian | Debian's certifi where() returns the system bundle /etc/ssl/certs/ca-certificates.crt | R354 | primary |
| S287 | [python-certifi 2025.1.31+ds-1 (trixie): the same patch](https://sources.debian.org/src/python-certifi/2025.1.31+ds-1/debian/patches/0001-Use-Debian-provided-etc-ssl-certs-ca-certificates.crt.patch/) · Debian | The same certifi patch in trixie | R354 | primary |
| S288 | [python-pip 23.0.1+dfsg-1 (bookworm): certifi: Use Debian provided /etc/ssl/certs/ca-certificates.crt](https://sources.debian.org/src/python-pip/23.0.1+dfsg-1/debian/patches/certifi-debian-ca-certificates.patch/) · Debian | Debian's pip makes its vendored certifi return the system bundle | R354 | primary |
| S289 | [python-pip 25.1.1+dfsg-1 (trixie): the same patch](https://sources.debian.org/src/python-pip/25.1.1+dfsg-1/debian/patches/certifi-debian-ca-certificates.patch/) · Debian | The same pip patch in trixie | R354 | primary |
| S290 | [python-certifi 2023.11.17-1 (Ubuntu noble): the same patch](https://git.launchpad.net/ubuntu/+source/python-certifi/tree/debian/patches/0001-Use-Debian-provided-etc-ssl-certs-ca-certificates.crt.patch?h=ubuntu/noble) · Ubuntu | The same certifi patch in Ubuntu noble | R354 | primary |
| S291 | [Lib/ensurepip/__init__.py at v3.11.18](https://github.com/python/cpython/blob/v3.11.18/Lib/ensurepip/__init__.py) · CPython | ensurepip in 3.11.18 still installs pip 24.0 | R358 | primary |
| S292 | [Lib/ensurepip/__init__.py at v3.12.16](https://github.com/python/cpython/blob/v3.12.16/Lib/ensurepip/__init__.py) · CPython | ensurepip in 3.12.16 still installs pip 25.0.1 | R358 | primary |
| S293 | [pip 24.0 vendor.txt](https://github.com/pypa/pip/blob/24.0/src/pip/_vendor/vendor.txt) · pip | pip 24.0 vendors certifi 2023.7.22 | R358 | primary |
| S294 | [pip 25.0.1 vendor.txt](https://github.com/pypa/pip/blob/25.0.1/src/pip/_vendor/vendor.txt) · pip | pip 25.0.1 vendors certifi 2024.8.30 | R358 | primary |
| S295 | [gh-160040: Distrust compromised eMudhra intermediate CA keys (GH-160042)](https://github.com/python/cpython/commit/7dd8b4736a1419750b94a388e6d158be15836fe6) · CPython | The ssl key block reached CPython main on 24 October | R350 | primary |
| S296 | [Python 3.16.0a1](https://www.python.org/downloads/release/python-3160a1/) · Python Software Foundation | CPython 3.16.0a1, released 13 October, before the ssl key block | R350 | primary |
| S297 | [PEP 826: Python 3.16 release schedule](https://peps.python.org/pep-0826/) · Python Software Foundation | 3.16.0a2 is scheduled for 10 November 2026 | R350 | primary |
| S546 | [uv Cargo.lock at 0.10.10](https://raw.githubusercontent.com/astral-sh/uv/0.10.10/Cargo.lock) · Astral | uv 0.10.10 locks webpki-roots 1.0.2 and no webpki-root-certs | R172, R222 | primary |
| S547 | [uv Cargo.lock at 0.10.12](https://raw.githubusercontent.com/astral-sh/uv/0.10.12/Cargo.lock) · Astral | uv 0.10.12, the last 0.10 release, locks webpki-roots 1.0.6 and no webpki-root-certs | R172, R222 | primary |
| S548 | [uv Cargo.lock at 0.11.0](https://raw.githubusercontent.com/astral-sh/uv/0.11.0/Cargo.lock) · Astral | uv 0.11.0 locks webpki-root-certs 1.0.6 and no webpki-roots | R172, R222 | primary |
| S549 | [uv Cargo.lock at 0.13.3](https://raw.githubusercontent.com/astral-sh/uv/0.13.3/Cargo.lock) · Astral | uv 0.13.3 locks webpki-root-certs 1.0.9 | R172, R222 | primary |
| S550 | [webpki-roots 1.0.2 src/lib.rs](https://raw.githubusercontent.com/rustls/webpki-roots/v/1.0.2/webpki-roots/src/lib.rs) · rustls | webpki-roots 1.0.2 holds emSign ECC Root CA - G3 as a TrustAnchor of subject name and public key | R172 | primary |
| S551 | [webpki-roots 1.0.6 src/lib.rs](https://raw.githubusercontent.com/rustls/webpki-roots/v/1.0.6/webpki-roots/src/lib.rs) · rustls | webpki-roots 1.0.6 holds emSign ECC Root CA - G3 as a TrustAnchor of subject name and public key | R172 | primary |

## JavaScript runtimes

| # | Source | Backs | R-numbers | Kind |
|---|---|---|---|---|
| S298 | [TLS (SSL)](https://nodejs.org/api/tls.html) · Node.js | tls.rootCertificates is the bundled Mozilla store | R190 | primary |
| S299 | [crypto: update root certificates to NSS 3.131.1](https://github.com/nodejs/node/pull/66877) · Node.js | Node removes emSign ECC Root CA - G3, C1 and C3, merged 20 October | R191 | primary |
| S300 | [Node.js 22 ChangeLog](https://github.com/nodejs/node/blob/f145fa4692145ca23d40848d8eeda068863600cd/doc/changelogs/CHANGELOG_V22.md) · Node.js | 22.23.4 (21 October) carries NSS 3.131.1 and the blocked public key check | R192, R196 | primary |
| S301 | [Node.js 22.23.4 (LTS)](https://nodejs.org/en/blog/release/v22.23.4) · Node.js | Release post confirming NSS 3.131.1 in 22.23.4 | R192 | primary |
| S302 | [Node.js 20.20.2 to 26.12.1 Linux x64 tarballs](https://nodejs.org/dist/v22.23.4/node-v22.23.4-linux-x64.tar.xz) · Node.js | The node binaries from 20.20.2 to 26.12.1, checked for the G3 root | R192, R193, R194, R195, R275 | primary |
| S303 | [Node.js distribution index (index.json)](https://nodejs.org/dist/index.json) · Node.js | Release dates and security flags, with 20.20.2 the latest 20.x | R192, R193, R195 | primary |
| S304 | [Node.js 24 ChangeLog](https://github.com/nodejs/node/blob/b615ce858fd92c35e1a7111af16b78e9bcf29733/doc/changelogs/CHANGELOG_V24.md) · Node.js | 24.22.1 (21 October) carries NSS 3.131.1 and the blocked public key check | R193, R196, R276 | primary |
| S305 | [Node.js 26 ChangeLog](https://github.com/nodejs/node/blob/ee982dbf48397bad3be955feca339338ce73fe97/doc/changelogs/CHANGELOG_V26.md) · Node.js | 26.12.1 (21 October) carries NSS 3.131.1 and the blocked public key check | R194, R196 | primary |
| S306 | [Node.js 20 ChangeLog](https://github.com/nodejs/node/blob/ee982dbf48397bad3be955feca339338ce73fe97/doc/changelogs/CHANGELOG_V20.md) · Node.js | The last 20.x root store update is NSS 3.119, and no 20.x release came after 20.20.2 | R195 | primary |
| S307 | [Node.js Release Working Group README](https://github.com/nodejs/Release/blob/c3e8696312969c95643cb52f05f124c161db87b2/README.md) · Node.js | 20.x reached end of life on 30 April 2026, and the support status of 22.x, 24.x and 26.x | R195 | primary |
| S308 | [October 21, 2026 Security Releases](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) · Node.js | Lists the eMudhra CA update as a dependency update for 26.x, 24.x and 22.x, with no CVE | R197 | primary |
| S309 | [GitHub Advisory Database, npm, 2026-10-17 to 2026-10-31](https://api.github.com/advisories?ecosystem=npm&published=2026-10-17..2026-10-31) · GitHub | Of 218 reviewed npm advisories, the only one about this incident is Electron's | R200 | primary |
| S310 | [Bun releases bun-v1.4.3 and bun-v1.4.4](https://github.com/oven-sh/bun/releases/tag/bun-v1.4.4) · Oven | bun-v1.4.4 published 22 October and bun-v1.4.3 on 10 October | R201 | primary |
| S311 | [crypto: update root certificates](https://github.com/oven-sh/bun/pull/46159) · Oven | Bun's embedded roots are generated from certdata.txt and cut from 121 to 117, merged 20 October | R201 | primary |
| S312 | [tls: reject chains containing blocked public keys, update root certificates to NSS 3.131.1](https://github.com/oven-sh/bun/pull/46300) · Oven | NSS 3.131.1 roots and the blocked public key check ported from Node, merged 21 October | R201 | primary |
| S313 | [Bun v1.4.4](https://bun.com/blog/bun-v1.4.4) · Oven | Root certificates updated to NSS 3.131.1 | R201 | primary |
| S314 | [Bun 1.4.3 and 1.4.4 Linux x64 zips](https://github.com/oven-sh/bun/releases/download/bun-v1.4.4/bun-linux-x64.zip) · Oven | The bun 1.4.3 and 1.4.4 binaries, checked for the G3 root | R201 | primary |
| S315 | [Environment variables](https://docs.deno.com/runtime/reference/env_variables/) · Deno | DENO_TLS_CA_STORE takes system or mozilla, default mozilla, and NODE_EXTRA_CA_CERTS is supported | R202 | primary |
| S316 | [Deno releases v2.9.7 and v2.9.8](https://github.com/denoland/deno/releases/tag/v2.9.8) · Deno | v2.9.8 published 21 October 15:28 UTC with the eMudhra distrust fix, and v2.9.7 on 17 September | R203 | primary |
| S317 | [fix(tls): distrust compromised eMudhra certificate authorities](https://github.com/denoland/deno/pull/37046) · Deno | Requires webpki-roots and webpki-root-certs 1.0.10 and rustls-webpki 0.103.16, merged 20 October | R203 | primary |
| S318 | [v2.9.8 is tagged but has no release, v2.9.7 still trusts the distrusted eMudhra root](https://github.com/denoland/deno/issues/37056) · Deno | Filed an hour before v2.9.8 went out and closed as premature | R203 | primary |
| S319 | [Cargo.lock at v2.9.7](https://github.com/denoland/deno/blob/v2.9.7/Cargo.lock) · Deno | Deno 2.9.7 locks webpki-root-certs 0.26.6, webpki-roots 0.26.1 and rustls-webpki 0.103.13 | R203, R204 | primary |
| S320 | [Cargo.lock at v2.9.8](https://github.com/denoland/deno/blob/v2.9.8/Cargo.lock) · Deno | Deno 2.9.8 locks webpki-root-certs 1.0.10, webpki-roots 1.0.10 and 0.26.11, and rustls-webpki 0.103.16 | R203 | primary |
| S321 | [Deno 2.9.7 and 2.9.8 Linux x86_64 zips](https://github.com/denoland/deno/releases/download/v2.9.8/deno-x86_64-unknown-linux-gnu.zip) · Deno | The deno 2.9.7 and 2.9.8 binaries, checked for the G3 root | R203, R204 | primary |
| S322 | [src/node_root_certs.h at v22.23.3](https://raw.githubusercontent.com/nodejs/node/v22.23.3/src/node_root_certs.h) · Node.js | Node's root list at v22.23.3 holds emSign ECC Root CA - G3 | R331 | primary |
| S323 | [src/node_root_certs.h at v22.23.4](https://raw.githubusercontent.com/nodejs/node/v22.23.4/src/node_root_certs.h) · Node.js | Node's root list at v22.23.4 no longer holds emSign ECC Root CA - G3 | R331 | primary |
| S324 | [src/node_root_certs.h at v24.22.0](https://raw.githubusercontent.com/nodejs/node/v24.22.0/src/node_root_certs.h) · Node.js | Node's root list at v24.22.0 holds emSign ECC Root CA - G3 | R331 | primary |
| S325 | [src/node_root_certs.h at v24.22.1](https://raw.githubusercontent.com/nodejs/node/v24.22.1/src/node_root_certs.h) · Node.js | Node's root list at v24.22.1 no longer holds emSign ECC Root CA - G3 | R331 | primary |
| S326 | [src/node_root_certs.h at v26.12.0](https://raw.githubusercontent.com/nodejs/node/v26.12.0/src/node_root_certs.h) · Node.js | Node's root list at v26.12.0 holds emSign ECC Root CA - G3 | R331 | primary |
| S327 | [src/node_root_certs.h at v26.12.1](https://raw.githubusercontent.com/nodejs/node/v26.12.1/src/node_root_certs.h) · Node.js | Node's root list at v26.12.1 no longer holds emSign ECC Root CA - G3 | R331 | primary |
| S328 | [src/node_root_certs.h at v12.22.12](https://raw.githubusercontent.com/nodejs/node/v12.22.12/src/node_root_certs.h) · Node.js | Node's root list at the last 12.x tag holds emSign ECC Root CA - G3 | R331 | primary |
| S329 | [src/node_root_certs.h at v13.14.0](https://raw.githubusercontent.com/nodejs/node/v13.14.0/src/node_root_certs.h) · Node.js | Node's root list at the last 13.x tag holds emSign ECC Root CA - G3 | R331 | primary |
| S330 | [src/node_root_certs.h at v14.21.3](https://raw.githubusercontent.com/nodejs/node/v14.21.3/src/node_root_certs.h) · Node.js | Node's root list at the last 14.x tag holds emSign ECC Root CA - G3 | R331 | primary |
| S331 | [src/node_root_certs.h at v15.14.0](https://raw.githubusercontent.com/nodejs/node/v15.14.0/src/node_root_certs.h) · Node.js | Node's root list at the last 15.x tag holds emSign ECC Root CA - G3 | R331 | primary |
| S332 | [src/node_root_certs.h at v16.20.2](https://raw.githubusercontent.com/nodejs/node/v16.20.2/src/node_root_certs.h) · Node.js | Node's root list at the last 16.x tag holds emSign ECC Root CA - G3 | R331 | primary |
| S333 | [src/node_root_certs.h at v17.9.1](https://raw.githubusercontent.com/nodejs/node/v17.9.1/src/node_root_certs.h) · Node.js | Node's root list at the last 17.x tag holds emSign ECC Root CA - G3 | R331 | primary |
| S334 | [src/node_root_certs.h at v18.20.8](https://raw.githubusercontent.com/nodejs/node/v18.20.8/src/node_root_certs.h) · Node.js | Node's root list at the last 18.x tag holds emSign ECC Root CA - G3 | R331 | primary |
| S335 | [src/node_root_certs.h at v19.9.0](https://raw.githubusercontent.com/nodejs/node/v19.9.0/src/node_root_certs.h) · Node.js | Node's root list at the last 19.x tag holds emSign ECC Root CA - G3 | R331 | primary |
| S336 | [src/node_root_certs.h at v20.20.2](https://raw.githubusercontent.com/nodejs/node/v20.20.2/src/node_root_certs.h) · Node.js | Node's root list at the last 20.x tag holds emSign ECC Root CA - G3 | R331 | primary |
| S337 | [src/node_root_certs.h at v21.7.3](https://raw.githubusercontent.com/nodejs/node/v21.7.3/src/node_root_certs.h) · Node.js | Node's root list at the last 21.x tag holds emSign ECC Root CA - G3 | R331 | primary |
| S338 | [src/node_root_certs.h at v23.11.1](https://raw.githubusercontent.com/nodejs/node/v23.11.1/src/node_root_certs.h) · Node.js | Node's root list at the last 23.x tag holds emSign ECC Root CA - G3 | R331 | primary |
| S339 | [src/node_root_certs.h at v25.9.0](https://raw.githubusercontent.com/nodejs/node/v25.9.0/src/node_root_certs.h) · Node.js | Node's root list at the last 25.x tag holds emSign ECC Root CA - G3 | R331 | primary |
| S340 | [src/node_root_certs.h at v24.19.0](https://raw.githubusercontent.com/nodejs/node/v24.19.0/src/node_root_certs.h) · Node.js | Node's root list at v24.19.0, the version some fixed Electron releases bundle, holds emSign ECC Root CA - G3 | R331 | primary |
| S341 | [src/node_root_certs.h on main at ae22341](https://raw.githubusercontent.com/nodejs/node/ae223417d9646775f71da8b68b8e5b3204393194/src/node_root_certs.h) · Node.js | Node's root list on main at ae22341 no longer holds emSign ECC Root CA - G3 | R331 | primary |
| S342 | [Release schedule README](https://raw.githubusercontent.com/nodejs/Release/c3e8696312969c95643cb52f05f124c161db87b2/README.md) · Node.js | Which Node.js release lines are end of life, and the 27.x alpha | R332 | primary |
| S343 | [schedule.json](https://raw.githubusercontent.com/nodejs/Release/c3e8696312969c95643cb52f05f124c161db87b2/schedule.json) · Node.js | Start and end-of-life dates for each Node.js release line | R332 | primary |
| S344 | [process.release](https://nodejs.org/docs/v24.22.1/api/process.html) · Node.js | process.release in official builds, including the download URLs | R333 | primary |
| S345 | [src/node_metadata.h](https://raw.githubusercontent.com/nodejs/node/d0fa608c07963448c41a0cbec8af9aa5db5da438/src/node_metadata.h) · Node.js | Node's build metadata, where the release download URL is set | R333 | primary |
| S346 | [src/node_metadata.cc](https://raw.githubusercontent.com/nodejs/node/8be36fb49413e8bbc0d4202eeb52b93c62ec4887/src/node_metadata.cc) · Node.js | Node's build metadata, where the release download URL is set | R333 | primary |
| S347 | [isrgrootx1.pem](https://letsencrypt.org/certs/isrgrootx1.pem) · Let's Encrypt | The base64 of ISRG Root X1 starts with MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAw | R334 | primary |
| S348 | [crates/node_runtime/src/node_runtime.rs](https://raw.githubusercontent.com/zed-industries/zed/130f1e92a48ecdcc210419c5d9a52d605fa18fc0/crates/node_runtime/src/node_runtime.rs) · Zed Industries | Zed downloads its own Node.js under its data directory and runs bin/node from there | R335 | primary |
| S349 | [packages/bun-usockets/root_certs.txt at bun-v1.4.3](https://raw.githubusercontent.com/oven-sh/bun/bun-v1.4.3/packages/bun-usockets/root_certs.txt) · Bun | Bun's bundled root list at bun-v1.4.3 holds emSign ECC Root CA - G3 | R336 | primary |
| S350 | [packages/bun-usockets/root_certs.txt at bun-v1.4.4](https://raw.githubusercontent.com/oven-sh/bun/bun-v1.4.4/packages/bun-usockets/root_certs.txt) · Bun | Bun's bundled root list at bun-v1.4.4 no longer holds emSign ECC Root CA - G3 | R336 | primary |
| S351 | [Compare bun-v1.4.3...bun-v1.4.4](https://api.github.com/repos/oven-sh/bun/compare/bun-v1.4.3...bun-v1.4.4) · Bun | The changes between bun-v1.4.3 and bun-v1.4.4 | R336 | primary |
| S352 | [Pull request 46300](https://api.github.com/repos/oven-sh/bun/pulls/46300) · Bun | Bun's blocked-key check | R336 | primary |
| S353 | [Cargo.lock at v2.9.7](https://raw.githubusercontent.com/denoland/deno/v2.9.7/Cargo.lock) · Deno | Deno 2.9.7 locks webpki-roots 0.26.1 and rustls-webpki 0.103.13 | R337 | primary |
| S354 | [Cargo.lock at v2.9.8](https://raw.githubusercontent.com/denoland/deno/v2.9.8/Cargo.lock) · Deno | Deno 2.9.8 locks webpki-roots and webpki-root-certs 1.0.10 and rustls-webpki 0.103.16 | R337 | primary |
| S355 | [Releases.md at v2.9.8](https://raw.githubusercontent.com/denoland/deno/v2.9.8/Releases.md) · Deno | Deno 2.9.8 release notes | R337 | primary |
| S356 | [rustls-webpki 0.103.16 src/data/distrusted/](https://raw.githubusercontent.com/rustls/webpki/v/0.103.16/src/data/distrusted/EMDVTLSCAG3B.spki.der) · rustls | rustls-webpki 0.103.16 ships the eight compromised public keys as a blocklist | R337 | primary |
| S357 | [src/crypto/crypto_context.cc at v22.23.4](https://github.com/nodejs/node/blob/v22.23.4/src/crypto/crypto_context.cc) · Node.js | Node includes node_root_certs.h in crypto_context.cc unconditionally | R352 | primary |
| S358 | [configure.py at v22.23.4](https://github.com/nodejs/node/blob/v22.23.4/configure.py) · Node.js | The --openssl-use-def-ca-store option only changes the default store at run time | R352 | primary |
| S359 | [nvm.sh at v0.40.8, nvm_version_dir and nvm_version_path](https://github.com/nvm-sh/nvm/blob/v0.40.8/nvm.sh) · nvm | nvm installs Node at $NVM_DIR/versions/node/vX.Y.Z, and below 0.12.0 at $NVM_DIR/vX.Y.Z | R353 | primary |
| S360 | [src/directories.rs at v1.39.0](https://github.com/Schniz/fnm/blob/v1.39.0/src/directories.rs) · fnm | Where fnm keeps its base directory and installs Node versions | R353 | primary |
| S361 | [src/config.rs at v1.39.0](https://github.com/Schniz/fnm/blob/v1.39.0/src/config.rs) · fnm | Where fnm keeps its base directory and installs Node versions | R353 | primary |
| S362 | [docs/directories.md at v2026.10.25](https://github.com/jdx/mise/blob/v2026.10.25/docs/directories.md) · mise | mise installs under ~/.local/share/mise/installs, and mise install --system under /usr/local/share/mise/installs | R353 | primary |

## Other languages

| # | Source | Backs | R-numbers | Kind |
|---|---|---|---|---|
| S363 | [GO-2026-6809 OSV record](https://vuln.go.dev/ID/GO-2026-6809.json) · Go | Machine-readable affected ranges and the Certificate.Verify symbol | R205, R206, R209 | primary |
| S364 | [\[security\] Go 1.27.3 and Go 1.26.10 are released](https://groups.google.com/g/golang-announce/c/66pojueaQek) · Go | Verify filters out chains that contain the intermediates | R206 | primary |
| S365 | [Release History](https://go.dev/doc/devel/release) · Go | go1.27.3 and go1.26.10 released 19 October with crypto/x509 security fixes | R206 | primary |
| S366 | [src/crypto/x509/root_linux.go (go1.27.3)](https://raw.githubusercontent.com/golang/go/go1.27.3/src/crypto/x509/root_linux.go) · Go | The Linux bundle files Go reads at run time | R208 | primary |
| S367 | [x509 package - crypto/x509](https://pkg.go.dev/crypto/x509) · Go | SetFallbackRoots conditions, GODEBUG x509usefallbackroots, SSL_CERT_FILE and SSL_CERT_DIR | R208, R210 | primary |
| S368 | [govulncheck command](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) · Go | govulncheck -mode binary analyses a built binary | R209 | primary |
| S369 | [fallback package](https://pkg.go.dev/golang.org/x/crypto/x509roots/fallback) · Go | The package embeds fallback roots through SetFallbackRoots | R210 | primary |
| S370 | [Go module proxy version list for x509roots/fallback](https://proxy.golang.org/golang.org/x/crypto/x509roots/fallback/@v/list) · Go | The x509roots/fallback module has no tagged versions | R210 | primary |
| S371 | [Module proxy info for x509roots/fallback v0.0.0-20261020153306-9f2b28d4331a](https://proxy.golang.org/golang.org/x/crypto/x509roots/fallback/@v/v0.0.0-20261020153306-9f2b28d4331a.info) · Go | The fixed pseudo-version exists on the proxy and maps to commit 9f2b28d | R210 | primary |
| S372 | [x509roots/fallback v0.0.0-20260916154351-b853e4b620cd module zip](https://proxy.golang.org/golang.org/x/crypto/x509roots/fallback/@v/v0.0.0-20260916154351-b853e4b620cd.zip) · Go module proxy | The 2026-09-16 fallback bundle holds emSign ECC Root CA - G3, C1 and C3, and no AAA | R211, R214 | primary |
| S373 | [x509roots/fallback v0.0.0-20261020153306-9f2b28d4331a module zip](https://proxy.golang.org/golang.org/x/crypto/x509roots/fallback/@v/v0.0.0-20261020153306-9f2b28d4331a.zip) · Go module proxy | The 2026-10-20 fallback bundle holds 117 roots and no G3, C1, C3 or AAA | R211, R214 | primary |
| S374 | [x509roots/fallback: update bundle](https://github.com/golang/crypto/commit/9f2b28d4331a80cb1ffd8fd7f1cf6207b696281b) · Go | The 20 October commit removing G3, C1 and C3 from the fallback bundle | R211 | primary |
| S375 | [golang/crypto commits touching x509roots](https://api.github.com/repos/golang/crypto/commits?path=x509roots&per_page=15) · Go | The previous bundle update was on 16 September (b853e4b620cd) | R211 | primary |
| S376 | [x509roots/fallback v0.0.0-20250203165127-fa5273e46196 module zip](https://proxy.golang.org/golang.org/x/crypto/x509roots/fallback/@v/v0.0.0-20250203165127-fa5273e46196.zip) · Go module proxy | The February 2025 bundle holds 140 roots, including G3 and AAA | R212 | primary |
| S377 | [x509roots/fallback v0.0.0-20250512154111-9f6bf8449a9f module zip](https://proxy.golang.org/golang.org/x/crypto/x509roots/fallback/@v/v0.0.0-20250512154111-9f6bf8449a9f.zip) · Go module proxy | The May 2025 bundle holds 142 roots, including G3 and no AAA | R212 | primary |
| S378 | [Go vulnerability database modules index](https://vuln.go.dev/index/modules.json) · Go | No entry for golang.org/x/crypto/x509roots/fallback | R213 | primary |
| S379 | [go command](https://pkg.go.dev/cmd/go) · Go | go version -m prints the module versions embedded in a binary | R214 | primary |
| S380 | [rustls/webpki-roots README](https://github.com/rustls/webpki-roots) · rustls | The crates hold Mozilla's roots from CCADB, for apps that can be recompiled | R215 | primary |
| S381 | [RUSTSEC-2026-0381](https://rustsec.org/advisories/RUSTSEC-2026-0381.html) · RustSec | webpki-roots advisory, with the note on the 0.26.11 wrapper | R216, R218 | primary |
| S382 | [advisory-db source: RUSTSEC-2026-0381](https://raw.githubusercontent.com/rustsec/advisory-db/8c25400939ad3954d97553d4dc48664c0771e1a7/crates/webpki-roots/RUSTSEC-2026-0381.md) · RustSec | Patched in 1.0.10 and later, 0.26.11 unaffected, alias CVE-2026-111943 | R216, R218, R224 | primary |
| S383 | [webpki-roots versions](https://crates.io/api/v1/crates/webpki-roots/versions?per_page=8) · crates.io | Publish dates of 1.0.9, 1.0.10 and 1.0.11 | R216, R217 | primary |
| S384 | [webpki-roots 1.0.9 crate](https://static.crates.io/crates/webpki-roots/webpki-roots-1.0.9.crate) · crates.io | 121 roots including G3, and no AAA | R217 | primary |
| S385 | [webpki-roots 1.0.10 crate](https://static.crates.io/crates/webpki-roots/webpki-roots-1.0.10.crate) · crates.io | 120 roots, with no G3 and no AAA, and C1 and C3 still present | R217 | primary |
| S386 | [Release 1.0.10 · rustls/webpki-roots](https://github.com/rustls/webpki-roots/releases/tag/v%2F1.0.10) · rustls | Release note for the G3 removal | R217 | primary |
| S387 | [Release 1.0.11 · rustls/webpki-roots](https://github.com/rustls/webpki-roots/releases/tag/v%2F1.0.11) · rustls | 1.0.11 also removes C1 and C3 | R217 | primary |
| S388 | [webpki-roots 0.26.11 crate](https://static.crates.io/crates/webpki-roots/webpki-roots-0.26.11.crate) · crates.io | 0.26.11 depends on webpki-roots 1 and re-exports its roots | R218 | primary |
| S389 | [webpki-roots 0.26.10 crate](https://static.crates.io/crates/webpki-roots/webpki-roots-0.26.10.crate) · crates.io | 142 roots including G3, and no AAA | R218, R219 | primary |
| S390 | [webpki-roots versions (60)](https://crates.io/api/v1/crates/webpki-roots/versions?per_page=60) · crates.io | Publish dates of the 0.26.x line | R218 | primary |
| S391 | [webpki-roots 0.26.8 crate](https://static.crates.io/crates/webpki-roots/webpki-roots-0.26.8.crate) · crates.io | 149 roots including G3 and AAA | R219 | primary |
| S392 | [webpki-roots 0.26.9 crate](https://static.crates.io/crates/webpki-roots/webpki-roots-0.26.9.crate) · crates.io | 149 roots including G3 and AAA | R219 | primary |
| S393 | [webpki-roots 0.25.4 crate](https://static.crates.io/crates/webpki-roots/webpki-roots-0.25.4.crate) · crates.io | 147 roots including G3 and AAA | R219, R343 | primary |
| S394 | [RUSTSEC-2026-0383](https://rustsec.org/advisories/RUSTSEC-2026-0383.html) · RustSec | webpki-root-certs advisory, with the note on the 0.26.11 wrapper | R220 | primary |
| S395 | [advisory-db source: RUSTSEC-2026-0383](https://raw.githubusercontent.com/rustsec/advisory-db/4b587f00996ebe5c05a73eaef105ef241e876414/crates/webpki-root-certs/RUSTSEC-2026-0383.md) · RustSec | Patched in 1.0.10 and later, 0.26.11 unaffected | R220, R224 | primary |
| S396 | [webpki-root-certs 1.0.9 crate](https://static.crates.io/crates/webpki-root-certs/webpki-root-certs-1.0.9.crate) · crates.io | 121 roots, one of them G3, and no AAA | R220 | primary |
| S397 | [webpki-root-certs 1.0.10 crate](https://static.crates.io/crates/webpki-root-certs/webpki-root-certs-1.0.10.crate) · crates.io | 120 roots, with no G3 or AAA | R220 | primary |
| S398 | [webpki-root-certs versions](https://crates.io/api/v1/crates/webpki-root-certs/versions?per_page=8) · crates.io | Publish dates of 1.0.9, 1.0.10 and 1.0.11 | R220 | primary |
| S399 | [webpki-root-certs 0.26.8 crate](https://static.crates.io/crates/webpki-root-certs/webpki-root-certs-0.26.8.crate) · crates.io | 149 roots including G3 and AAA | R221 | primary |
| S400 | [webpki-root-certs 0.26.9 crate](https://static.crates.io/crates/webpki-root-certs/webpki-root-certs-0.26.9.crate) · crates.io | 149 roots including G3 and AAA | R221 | primary |
| S401 | [webpki-root-certs 0.26.10 crate](https://static.crates.io/crates/webpki-root-certs/webpki-root-certs-0.26.10.crate) · crates.io | 142 roots including G3, and no AAA | R221 | primary |
| S402 | [RUSTSEC-2026-0382](https://rustsec.org/advisories/RUSTSEC-2026-0382.html) · RustSec | rustls-webpki rejects paths that use the distrusted public keys | R223 | primary |
| S403 | [advisory-db source: RUSTSEC-2026-0382](https://raw.githubusercontent.com/rustsec/advisory-db/e6f94f3760d5e6c54c1b05f204002263bc025524/crates/rustls-webpki/RUSTSEC-2026-0382.md) · RustSec | Patched ranges and the alias CVE-2026-111943 | R223, R224 | primary |
| S404 | [Release 0.103.16 · rustls/webpki](https://github.com/rustls/webpki/releases/tag/v%2F0.103.16) · rustls | Release note for the public key distrust | R223 | primary |
| S405 | [rustls-webpki 0.103.15 crate](https://static.crates.io/crates/rustls-webpki/rustls-webpki-0.103.15.crate) · crates.io | 0.103.15 has no distrust data, only TODO comments for a distrust check | R223 | primary |
| S406 | [rustls-webpki versions](https://crates.io/api/v1/crates/rustls-webpki/versions?per_page=40) · crates.io | Publish dates of 0.103.15, 0.103.16 and 0.104.0-alpha.8 | R223 | primary |
| S407 | [rustls/rustls-native-certs README](https://github.com/rustls/rustls-native-certs) · rustls | Loads the platform store, reading SSL_CERT_FILE first | R225 | primary |
| S408 | [rustls/rustls-platform-verifier README](https://github.com/rustls/rustls-platform-verifier) · rustls | On Linux it uses the system CA bundle with webpki and no OS revocation check | R225 | primary |
| S409 | [cargo tree](https://doc.rust-lang.org/cargo/commands/cargo-tree.html) · Rust Project | cargo tree -i shows what pulls in a crate | R226 | primary |
| S410 | [composer/ca-bundle README](https://github.com/composer/ca-bundle) · Composer | Uses the system bundle path with a bundled Mozilla fallback | R227 | primary |
| S411 | [Release 1.6.0 · composer/ca-bundle](https://github.com/composer/ca-bundle/releases/tag/1.6.0) · Composer | Distrusts the intermediates, adds findDistrustedCertificate and ships the 2026-10-20 cacert.pem | R228, R229 | primary |
| S412 | [Release 1.4.16 · composer/ca-bundle](https://github.com/composer/ca-bundle/releases/tag/1.4.16) · Composer | The same changes on the 1.4 branch | R228 | primary |
| S413 | [composer/ca-bundle package metadata](https://repo.packagist.org/p2/composer/ca-bundle.json) · Packagist | Release times and download URLs for 1.4.x, 1.5.x and 1.6.x | R228, R230 | primary |
| S414 | [composer/ca-bundle 1.5.14 archive](https://api.github.com/repos/composer/ca-bundle/zipball/0c8abba0634f637bd78c4e451981da368d403463) · GitHub (Composer) | res/cacert.pem with 121 certificates from 2026-08-13 Mozilla data, including G3, and no AAA | R228 | primary |
| S415 | [composer/ca-bundle 1.6.0 archive](https://api.github.com/repos/composer/ca-bundle/zipball/2c99cf2e92516985dea4914812b93d9daf01cdd6) · GitHub (Composer) | 118 certificates from 2026-10-20 data with no G3, C1 or C3, and the 8 SPKI hashes in CaBundle.php | R228, R229 | primary |
| S416 | [composer/ca-bundle 1.4.15 archive](https://api.github.com/repos/composer/ca-bundle/zipball/aacd680daf532ff281f058976c5e299c1cf9e7f5) · GitHub (Composer) | 121 certificates from 2026-08-13 data, including G3, and no AAA | R228 | primary |
| S417 | [composer/ca-bundle 1.4.16 archive](https://api.github.com/repos/composer/ca-bundle/zipball/b51ae45d50330c67de665b252275c4021fe2d7ef) · GitHub (Composer) | 118 certificates from 2026-10-20 data with no G3, and the 8 SPKI hashes in CaBundle.php | R228, R229 | primary |
| S418 | [composer/ca-bundle 1.5.6 archive](https://api.github.com/repos/composer/ca-bundle/zipball/f65c239c970e7f072f067ab78646e9f0b2935175) · GitHub (Composer) | 150 certificates including G3 and AAA | R230 | primary |
| S419 | [composer/ca-bundle 1.5.7 archive](https://api.github.com/repos/composer/ca-bundle/zipball/d665d22c417056996c59019579f1967dfe5c1e82) · GitHub (Composer) | 143 certificates including G3, and no AAA | R230 | primary |
| S420 | [composer/ca-bundle 1.4.7 archive](https://api.github.com/repos/composer/ca-bundle/zipball/9b8b487385d1a5140ad6765b9e9131fc3de3b891) · GitHub (Composer) | 150 certificates including G3 and AAA | R230 | primary |
| S421 | [composer/ca-bundle 1.4.8 archive](https://api.github.com/repos/composer/ca-bundle/zipball/89abbf0c6faba79240f3a1f701bbca4c761f26fe) · GitHub (Composer) | 143 certificates including G3, and no AAA | R230 | primary |
| S422 | [Release 2.11.0 · composer/composer](https://github.com/composer/composer/releases/tag/2.11.0) · Composer | Composer rejects the distrusted intermediates even when the system store trusts their roots | R231 | primary |
| S423 | [Release 2.2.31 · composer/composer](https://github.com/composer/composer/releases/tag/2.2.31) · Composer | The LTS fix, which requires ca-bundle 1.4.16 or later | R231 | primary |
| S424 | [composer/composer release list](https://api.github.com/repos/composer/composer/releases?per_page=6) · Composer | 2.10.3 (27 August) is the last 2.10 release, followed by 2.11.0-RC1, 2.11.0, 2.2.31 and 2.11.1 | R231 | primary |
| S425 | [PHP: Runtime Configuration - Manual (OpenSSL)](https://www.php.net/manual/en/openssl.configuration.php) · PHP | openssl.cafile and openssl.capath default to empty | R232 | primary |
| S426 | [Config - Composer](https://getcomposer.org/doc/06-config.md) · Composer | The cafile and capath options and PHP system CA detection | R232 | primary |
| S427 | [lib/rubygems/ssl_certs directory listing](https://github.com/ruby/rubygems/tree/54f5278450d0b0178c7b24dea53f53719bf463ef/lib/rubygems/ssl_certs) · RubyGems | The directory holds one file, rubygems.org/GlobalSign.pem | R233 | primary |
| S428 | [lib/rubygems/ssl_certs/rubygems.org/GlobalSign.pem](https://raw.githubusercontent.com/ruby/rubygems/54f5278450d0b0178c7b24dea53f53719bf463ef/lib/rubygems/ssl_certs/rubygems.org/GlobalSign.pem) · RubyGems | GlobalSign Root CA - R3, with no emSign or AAA | R233 | primary |
| S429 | [lib/rubygems/request.rb](https://raw.githubusercontent.com/ruby/rubygems/f12d7a2004013bca37a1e57086214eba2e2025fa/lib/rubygems/request.rb) · RubyGems | The RubyGems store is the OpenSSL default paths plus ssl_certs/*/*.pem | R233 | primary |
| S430 | [lib/bundler/fetcher/connection_pools.rb](https://raw.githubusercontent.com/ruby/rubygems/1de5bfc11cd7b60b5d8dfd704d08b3fccdac167e/lib/bundler/fetcher/connection_pools.rb) · RubyGems | Bundler builds the same store unless ssl_ca_cert is set | R233 | primary |
| S431 | [excon 1.8.0 gem](https://rubygems.org/downloads/excon-1.8.0.gem) · RubyGems.org | data/cacert.pem with 118 certificates from 2026-10-20 data and no G3 | R234 | primary |
| S432 | [excon changelog.txt at v1.8.0](https://raw.githubusercontent.com/excon/excon/v1.8.0/changelog.txt) · excon | 1.8.0 (21 October) removes G3, C1 and C3 | R234 | primary |
| S433 | [excon versions](https://rubygems.org/api/v1/versions/excon.json) · RubyGems.org | Release dates of 1.2.5, 1.2.6, 1.7.3, 1.8.0 and later | R234, R235 | primary |
| S434 | [excon 1.7.3 gem](https://rubygems.org/downloads/excon-1.7.3.gem) · RubyGems.org | 121 certificates from 2026-09-25 data, including G3, and no AAA | R234 | primary |
| S435 | [excon 1.2.5 gem](https://rubygems.org/downloads/excon-1.2.5.gem) · RubyGems.org | 150 certificates including G3 and AAA | R235 | primary |
| S436 | [excon 1.2.6 gem](https://rubygems.org/downloads/excon-1.2.6.gem) · RubyGems.org | 143 certificates including G3, and no AAA | R235 | primary |
| S437 | [httpclient versions](https://rubygems.org/api/v1/versions/httpclient.json) · RubyGems.org | 2.9.0 (22 February 2025) is the latest release | R236 | primary |
| S438 | [httpclient 2.9.0 gem](https://rubygems.org/downloads/httpclient-2.9.0.gem) · RubyGems.org | The bundled cacert.pem, loaded by default, holds 153 certificates from 2015 data, including AAA and no G3 | R236 | primary |
| S439 | [Mozilla-CA-20261020](https://metacpan.org/release/LWP/Mozilla-CA-20261020) · MetaCPAN | The Changes file denylists G3 by SHA-256 | R239, R241 | primary |
| S440 | [Mozilla-CA release search](https://fastapi.metacpan.org/v1/release/_search) · MetaCPAN | Release dates and tarball URLs from 20250202 to 20261020 | R239 | primary |
| S441 | [Mozilla-CA 20260813 tarball](https://cpan.metacpan.org/authors/id/L/LW/LWP/Mozilla-CA-20260813.tar.gz) · CPAN | 121 certificates including G3, and no AAA | R240 | primary |
| S442 | [Mozilla-CA 20261020 tarball](https://cpan.metacpan.org/authors/id/L/LW/LWP/Mozilla-CA-20261020.tar.gz) · CPAN | 120 certificates, with C1 and C3 and no G3, and a denylist naming AAA, emSign Root TLS CA - G3 and G3 | R240, R241, R242 | primary |
| S443 | [Mozilla-CA 20250202 tarball](https://cpan.metacpan.org/authors/id/L/LW/LWP/Mozilla-CA-20250202.tar.gz) · CPAN | 149 certificates including G3 and AAA | R242 | primary |
| S444 | [Mozilla-CA 20250602 tarball](https://cpan.metacpan.org/authors/id/L/LW/LWP/Mozilla-CA-20250602.tar.gz) · CPAN | 143 certificates including G3, and no AAA | R242 | primary |
| S445 | [IO::Socket::SSL](https://metacpan.org/pod/IO::Socket::SSL) · MetaCPAN | Uses the OpenSSL default CA store first and Mozilla::CA only as a fallback | R243 | primary |
| S446 | [elixir-mint/castore README](https://github.com/elixir-mint/castore) · elixir-mint | Each store update is a patch release, and CAStore.file_path/0 returns the file | R244 | primary |
| S447 | [CAStore](https://hexdocs.pm/castore/CAStore.html) · Hex | The module's only purpose is the CA store file | R244 | primary |
| S448 | [castore package API](https://hex.pm/api/packages/castore) · Hex | Release dates of 1.0.12 to 1.0.22 | R244 | primary |
| S449 | [castore 1.0.21 tarball](https://repo.hex.pm/tarballs/castore-1.0.21.tar) · Hex | 121 certificates from 2026-08-13 data, including G3, and no AAA | R244 | primary |
| S450 | [castore 1.0.22 tarball](https://repo.hex.pm/tarballs/castore-1.0.22.tar) · Hex | 118 certificates from 2026-10-20 data, with no G3, C1 or C3 | R244 | primary |
| S451 | [castore 1.0.12 tarball](https://repo.hex.pm/tarballs/castore-1.0.12.tar) · Hex | 150 certificates from 2025-02-25 data, including G3 and AAA | R245 | primary |
| S452 | [castore 1.0.13 tarball](https://repo.hex.pm/tarballs/castore-1.0.13.tar) · Hex | 149 certificates from 2025-05-15 data, including G3 and AAA | R245 | primary |
| S453 | [castore 1.0.14 tarball](https://repo.hex.pm/tarballs/castore-1.0.14.tar) · Hex | 143 certificates from 2025-05-20 data, including G3, and no AAA | R245 | primary |
| S454 | [erlang-certifi CHANGELOG.md](https://raw.githubusercontent.com/certifi/erlang-certifi/2929f17ab4a4df3f2d877b2cf8eda854f41d8f42/CHANGELOG.md) · certifi | 2.18.0 released 23 October | R246 | primary |
| S455 | [Changelog](https://certifi.hexdocs.pm/2.18.0/changelog.html) · Hex | 2.18.0 removes C1, C3 and G3 | R246 | primary |
| S456 | [certifi 2.17.0 Hex tarball](https://repo.hex.pm/tarballs/certifi-2.17.0.tar) · Hex | 119 certificates including G3, and no AAA | R246 | primary |
| S457 | [certifi 2.18.0 Hex tarball](https://repo.hex.pm/tarballs/certifi-2.18.0.tar) · Hex | 118 certificates with no G3, C1 or C3, and a test that asserts the emSign roots are absent | R246 | primary |
| S458 | [certifi/erlang-certifi README](https://github.com/certifi/erlang-certifi) · certifi | Certificates are embedded into the module at compile time | R246 | primary |
| S459 | [certifi 2.14.0 Hex tarball](https://repo.hex.pm/tarballs/certifi-2.14.0.tar) · Hex | 150 certificates including G3 and AAA | R247 | primary |
| S460 | [certifi 2.15.0 Hex tarball](https://repo.hex.pm/tarballs/certifi-2.15.0.tar) · Hex | 143 certificates from 2025-05-19 data, including G3, and no AAA | R247 | primary |
| S461 | [certifi package API](https://hex.pm/api/packages/certifi) · Hex | Release dates of 2.14.0 to 2.18.0 | R247 | primary |
| S462 | [mix deps.tree](https://hexdocs.pm/mix/Mix.Tasks.Deps.Tree.html) · Elixir | Prints the dependency tree | R248 | primary |
| S463 | [public_key](https://www.erlang.org/doc/apps/public_key/public_key.html) · Erlang | cacerts_get/0 loads the CA certificates the OS supplies | R249 | primary |
| S464 | [Cross-platform cryptography in .NET](https://learn.microsoft.com/en-us/dotnet/standard/security/cross-platform-cryptography) · Microsoft | .NET root stores per OS, and the Linux Disallowed store is not used | R250, R251 | primary |
| S465 | [cacert-2025-08-12.pem](https://curl.se/ca/cacert-2025-08-12.pem) · curl | 146 certificates including G3, and no AAA | R253 | primary |
| S466 | [cacert-2026-03-19.pem](https://curl.se/ca/cacert-2026-03-19.pem) · curl | 145 certificates including G3, and no AAA | R253 | primary |
| S467 | [cacert-2026-05-14.pem](https://curl.se/ca/cacert-2026-05-14.pem) · curl | 121 certificates including G3, and no AAA | R253 | primary |
| S468 | [TLS Certificate Verification](https://curl.se/docs/sslcerts.html) · curl | The Schannel native store, the curl-ca-bundle.crt search order and CURL_CA_BUNDLE | R254 | primary |
| S469 | [GHSA-frr6-h895-5pxp advisory record](https://api.github.com/repos/dart-lang/sdk/security-advisories/GHSA-frr6-h895-5pxp) · Dart | Patched Dart 3.13.7 and 3.14.0-315.3.beta and Flutter 3.47.8 and 3.50.0-0.2.pre, through a BoringSSL distrust of the intermediates | R255, R256 | primary |
| S470 | [Commits touching x509roots/fallback](https://api.github.com/repos/golang/crypto/commits?path=x509roots/fallback&sha=9f2b28d4331a80cb1ffd8fd7f1cf6207b696281b) · Go | The commit history of the fallback module, with the previous update on 16 September | R338 | primary |
| S471 | [Commit 9f2b28d4331a](https://github.com/golang/crypto/commit/9f2b28d4331a) · Go | The 20 October commit that removes emSign ECC Root CA - G3 from the fallback bundle | R338 | primary |
| S472 | [Commit 9f2b28d4331a as a patch: bundle.go drops CN=emSign ECC Root CA - G3](https://github.com/golang/crypto/commit/9f2b28d4331a80cb1ffd8fd7f1cf6207b696281b.patch) · Go | bundle.go drops CN=emSign ECC Root CA - G3 | R338 | primary |
| S473 | [Go Toolchains](https://go.dev/doc/toolchain) · Go | The go.mod toolchain line is a suggestion, and GOTOOLCHAIN=local always runs the bundled toolchain | R339 | primary |
| S474 | [debug/buildinfo/buildinfo.go](https://github.com/golang/go/blob/4d6a40923b7b55d48e9e7abfc3514e607d58fe40/src/debug/buildinfo/buildinfo.go) · Go | Since Go 1.18 the build info header sets flag bit 0x2 and stores strings inline | R340 | primary |
| S475 | [cmd/link/internal/ld/data.go](https://raw.githubusercontent.com/golang/go/2fb15af7f0882fc848cf08a91d91361224878703/src/cmd/link/internal/ld/data.go) · Go | The linker code that writes the build info header | R340 | primary |
| S476 | [Remap source paths](https://doc.rust-lang.org/rustc/remap-source-paths.html) · Rust | rustc embeds source paths in panic messages | R341 | primary |
| S477 | [Cargo Home](https://doc.rust-lang.org/cargo/guide/cargo-home.html) · Rust | Cargo unpacks crates under registry/src and git dependencies under git/checkouts, a layout it does not stabilize | R341 | primary |
| S478 | [webpki-roots versions](https://crates.io/api/v1/crates/webpki-roots/versions?per_page=100) · crates.io | webpki-roots version list, with 0.26.11 the last 0.26 release | R342 | primary |
| S479 | [webpki-root-certs versions](https://crates.io/api/v1/crates/webpki-root-certs/versions?per_page=100) · crates.io | webpki-root-certs version list, with 0.26.4 the first release | R342 | primary |
| S480 | [rustls-webpki versions](https://crates.io/api/v1/crates/rustls-webpki/versions?per_page=100) · crates.io | rustls-webpki version list, with 0.102.8 the last 0.102 release and 0.103.16 and 0.104.0-alpha.8 on 20 October | R342 | primary |
| S481 | [webpki-roots 0.16.0](https://static.crates.io/crates/webpki-roots/webpki-roots-0.16.0.crate) · crates.io | webpki-roots 0.16.0 holds AAA Certificate Services and no G3 root | R343 | primary |
| S482 | [webpki-roots 0.17.0](https://static.crates.io/crates/webpki-roots/webpki-roots-0.17.0.crate) · crates.io | webpki-roots 0.17.0 is the first release with emSign ECC Root CA - G3 | R343 | primary |
| S483 | [webpki-root-certs 0.26.4](https://static.crates.io/crates/webpki-root-certs/webpki-root-certs-0.26.4.crate) · crates.io | webpki-root-certs 0.26.4 holds emSign ECC Root CA - G3 | R344 | primary |
| S484 | [webpki-root-certs 0.26.11](https://static.crates.io/crates/webpki-root-certs/webpki-root-certs-0.26.11.crate) · crates.io | webpki-root-certs 0.26.11 holds no roots and re-exports those of webpki-root-certs 1.x | R344 | primary |
| S485 | [rustls-webpki 0.104.0-alpha.7](https://static.crates.io/crates/rustls-webpki/rustls-webpki-0.104.0-alpha.7.crate) · crates.io | rustls-webpki 0.104.0-alpha.7 has no blocked keys | R344 | primary |
| S486 | [rustls-webpki 0.104.0-alpha.8](https://static.crates.io/crates/rustls-webpki/rustls-webpki-0.104.0-alpha.8.crate) · crates.io | rustls-webpki 0.104.0-alpha.8 ships the eight blocked keys | R344 | primary |
| S487 | [composer/ca-bundle releases](https://api.github.com/repos/composer/ca-bundle/releases?per_page=6) · Composer | 1.4.16 and 1.6.0 released 20 October, and 1.5.14 (August) is the last 1.5 release | R345 | primary |
| S488 | [res/cacert.pem at 1.5.14](https://raw.githubusercontent.com/composer/ca-bundle/0c8abba0634f637bd78c4e451981da368d403463/res/cacert.pem) · Composer | The 1.5.14 bundle still holds emSign ECC Root CA - G3 | R345 | primary |

## Browsers and apps

| # | Source | Backs | R-numbers | Kind |
|---|---|---|---|---|
| S489 | [Commits touching root_store.textproto (GitHub mirror)](https://api.github.com/repos/chromium/chromium/commits?path=net/data/ssl/chrome_root_store/root_store.textproto) · Chromium | Identifies 8793082 (20 October) as the commit after 5a6a4e7 | R258 | primary |
| S490 | [Security Vulnerabilities fixed in Firefox 158.0.1](https://www.mozilla.org/en-US/security/advisories/mfsa2026-111/) · Mozilla | MFSA 2026-111, with the CVE-2026-113470 entry | R261 | primary |
| S491 | [Security Vulnerabilities fixed in Firefox ESR 153.5.1](https://www.mozilla.org/en-US/security/advisories/mfsa2026-112/) · Mozilla | MFSA 2026-112, with the same entry | R261 | primary |
| S492 | [Security Vulnerabilities fixed in Firefox ESR 115.43.1](https://www.mozilla.org/en-US/security/advisories/mfsa2026-113/) · Mozilla | MFSA 2026-113, with the same entry | R261 | primary |
| S493 | [Firefox release tags: bundled NSS version, certdata trust and OneCRL dump](https://github.com/mozilla-firefox/firefox) · Mozilla | Bundled NSS version, certdata trust and OneCRL data at nine Firefox release tags | R261, R262 | primary |
| S494 | [Bug 2084379: Firefox ESR 153.5.1 source includes NSS 3.125](https://bugzilla.mozilla.org/show_bug.cgi?id=2084379) · Mozilla | ESR builds keep older NSS with the G3 root and rely on OneCRL, so forks without OneCRL stay exposed | R262, R265 | primary |
| S495 | [Security Vulnerabilities fixed in Thunderbird 158.0.1](https://www.mozilla.org/en-US/security/advisories/mfsa2026-114/) · Mozilla | MFSA 2026-114, with the same OneCRL entry for Thunderbird | R267 | primary |
| S496 | [Security Vulnerabilities fixed in Thunderbird 153.5.1](https://www.mozilla.org/en-US/security/advisories/mfsa2026-115/) · Mozilla | MFSA 2026-115, with the same entry | R267 | primary |
| S497 | [Mozilla product details: Thunderbird versions](https://product-details.mozilla.org/1.0/thunderbird_versions.json) · Mozilla | Current Thunderbird 159.0 and ESR 153.6.0 | R267 | primary |
| S498 | [GitHub Advisory Database: GHSA-jr5w-w6x2-84p9](https://api.github.com/advisories/GHSA-jr5w-w6x2-84p9) · GitHub | npm electron affected ranges and first patched versions | R270 | primary |
| S499 | [electron v44.9.1](https://github.com/electron/electron/releases/tag/v44.9.1) · Electron | Release note naming the advisory | R271 | primary |
| S500 | [Electron 44.9.1 macOS arm64 zip](https://github.com/electron/electron/releases/download/v44.9.1/electron-v44.9.1-darwin-arm64.zip) · Electron | Where the framework Info.plist sits, and the version string in the framework binary | R273, R274, R275 | primary |
| S501 | [Electron 44.9.1 Linux x64 zip](https://github.com/electron/electron/releases/download/v44.9.1/electron-v44.9.1-linux-x64.zip) · Electron | The version string in the Linux binary | R274 | primary |
| S502 | [VS Code .npmrc and remote/.npmrc by release tag](https://github.com/microsoft/vscode/blob/1.144.0/.npmrc) · Microsoft | VS Code 1.143.x targets Electron 43.7.7 and 1.144.0 targets 43.8.3, with remote Node 24.22.1 from 1.143.1 | R276, R277 | primary |
| S503 | [chore: bump remote node@24.22.1](https://github.com/microsoft/vscode/pull/343541) · Microsoft | The only pull request in the 1.143.1 milestone | R276 | primary |
| S504 | [VS Code releases](https://github.com/microsoft/vscode/releases) · Microsoft | Release dates of 1.143.0, 1.143.1 and 1.144.0 | R277 | primary |
| S505 | [Obsidian 1.14.5 Desktop (Public)](https://obsidian.md/changelog/2026-10-22-desktop-v1.14.5/) · Obsidian | Moves Electron from 43.7.5 to 43.8.3 and needs a reinstall | R278 | primary |
| S506 | [Git for Windows 2.56.0(3)](https://github.com/git-for-windows/git/releases/tag/v2.56.0.windows.3) · Git for Windows | Security release for eMudhra, with asset SHA-256 hashes | R279 | primary |
| S507 | [MinGit 2.56.0(2) and 2.56.0(3) zips](https://github.com/git-for-windows/git/releases/download/v2.56.0.windows.3/MinGit-2.56.0.3-64-bit.zip) · Git for Windows | The bundled ca-bundle.crt before and after the fix | R279 | primary |
| S508 | [Bump certifi to 2026.10.19 (removes emSign roots)](https://github.com/certbot/certbot/pull/10812) · Certbot | Bumps certifi to 2026.10.19, merged 21 October, and explains the exposure of the Certbot image | R280, R303 | primary |
| S509 | [Certbot v5.9.0](https://github.com/certbot/certbot/releases/tag/v5.9.0) · Certbot | Released 29 October, with notes that do not mention certifi or eMudhra | R280 | primary |
| S510 | [tools/requirements.txt certifi pin at v5.8.0 and v5.9.0](https://github.com/certbot/certbot/blob/v5.9.0/tools/requirements.txt) · Certbot | certifi pinned to 2026.7.22 in 5.8.0 and to 2026.10.19 in 5.9.0 | R280 | primary |
| S511 | [Update to go1.27.3](https://github.com/containerd/containerd/pull/14439) · containerd | Merged to main on 20 October | R281 | primary |
| S512 | [containerd releases and Go 1.27.3 pull requests](https://github.com/containerd/containerd/releases) · containerd | No release after 13 October, and the release/2.4 backport merged | R281 | primary |
| S513 | [Docker Engine version 29 release notes](https://docs.docker.com/engine/release-notes/29/) · Docker | 29.9.2 moves to Go 1.26.10 for CVE-2026-111943 | R282 | primary |
| S514 | [Docker 29.9.1 and 29.9.2 static binaries](https://download.docker.com/linux/static/stable/x86_64/docker-29.9.2.tgz) · Docker | The Go toolchain version in the 29.9.1 and 29.9.2 binaries | R282 | primary |
| S515 | [Docker Desktop release notes](https://docs.docker.com/desktop/release-notes/) · Docker | 4.96.1, 4.96.2 and 4.96.3 each remove trust, with a batch rollout note | R283 | primary |
| S516 | [GitHub CLI 2.102.1](https://github.com/cli/cli/releases/tag/v2.102.1) · GitHub | Moves the Go toolchain from 1.27.1 to 1.27.3 | R284 | primary |
| S517 | [gh 2.102.0 and 2.102.1 Linux binaries](https://github.com/cli/cli/releases/download/v2.102.1/gh_2.102.1_linux_amd64.tar.gz) · GitHub | The Go toolchain version in each gh binary | R284 | primary |
| S518 | [Podman releases](https://github.com/containers/podman/releases) · Podman | No stable release after 12 October | R285 | primary |
| S519 | [certs: Sync with Mozilla bundle as of Oct 20, 2026](https://github.com/godotengine/godot/pull/124724) · Godot Engine | Merged to master on 21 October, with a request for cherry-picks | R287 | primary |
| S520 | [Godot releases](https://github.com/godotengine/godot/releases) · Godot Engine | The newest stable releases predate the fix | R287 | primary |
| S521 | [Godot thirdparty/certs bundles at tags and branches](https://github.com/godotengine/godot/blob/b0761321a2dda60c310a7494e5cf60f58906ce7a/thirdparty/certs/ca-bundle.crt) · Godot Engine | The certificate bundle at master, the merge commit, 4.7.2-stable, 4.7, 4.6, 3.6.3-stable and 3.x | R288 | primary |
| S522 | [nss: upgrade to 3.132 (change 212892)](https://gerrit.libreoffice.org/c/core/+/212892) · The Document Foundation | Merged to libreoffice-26-2, changing only download.lst | R289 | primary |
| S523 | [Gerrit query: nss upgrade to 3.132](https://gerrit.libreoffice.org/q/project:core+%22nss:+upgrade+to+3.132%22) · The Document Foundation | The same change merged on master, 26-8, 26-8-2, 26-2 and 26-2-7 | R289 | primary |
| S524 | [download.lst NSS lines by release tag](https://github.com/LibreOffice/core/blob/libreoffice-26.8.2.2/download.lst) · The Document Foundation | The NSS version at each release candidate tag | R289, R290 | primary |
| S525 | [Index of /libreoffice/stable](https://download.documentfoundation.org/libreoffice/stable/) · The Document Foundation | 26.8.2 published 28 October, and 26.2.7 not yet on stable | R289, R290 | primary |
| S526 | [ReleasePlan/26.8](https://wiki.documentfoundation.org/ReleasePlan/26.8) · The Document Foundation | 26.8.2 RC2 in week 43 and release in week 44 | R289 | primary |
| S527 | [ReleasePlan/26.2](https://wiki.documentfoundation.org/ReleasePlan/26.2) · The Document Foundation | 26.2.7 RC3 in week 44 | R290 | primary |
| S528 | [del_sys_ca (pull request 722)](https://gitcode.com/openharmony/security_certificate_manager/pull/722) · OpenHarmony | Merged into master and linked to an issue titled Remove insecure system CA certificates | R291 | primary |
| S529 | [Block the compromised eMudhra intermediate CAs](https://github.com/JetBrains/JetBrainsRuntime/pull/651) · JetBrains | Merged to jbr25 on 21 October, adding entries to blocked.certs.pem | R292 | primary |
| S530 | [JBR 25.0.4.1 b635.78 and b635.79 Linux x64 tarballs](https://cache-redirector.jetbrains.com/intellij-jbr/jbr-25.0.4.1-linux-x64-b635.79.tar.gz) · JetBrains | blocked.certs, cacerts and release from builds b635.78 and b635.79 | R292, R293 | primary |
| S531 | [JetBrains Runtime releases](https://github.com/JetBrains/JetBrainsRuntime/releases) · JetBrains | Dates of b635.78 and b635.79 | R292, R293 | primary |
| S532 | [Pull request 55126](https://github.com/electron/electron/pull/55126) · Electron | Merged to main on 20 October, adding the blocked keys to Chromium and to Node's TLS | R346 | primary |
| S533 | [Commit 44fdb9fee44e](https://github.com/electron/electron/commit/44fdb9fee44e) · Electron | The commit of the blocked-key change on main | R346 | primary |
| S534 | [patches/chromium/.patches at v46.0.0-alpha.1](https://github.com/electron/electron/blob/v46.0.0-alpha.1/patches/chromium/.patches) · Electron | 46.0.0-alpha.1 carries the blocked-key patch | R346 | primary |
| S535 | [releases.json](https://releases.electronjs.org/releases.json) · Electron | Electron release dates and the Node and Chromium versions each release bundles | R346 | primary |
| S536 | [DEPS at v44.9.1](https://api.github.com/repos/electron/electron/contents/DEPS?ref=v44.9.1) · Electron | The Chromium and Node versions Electron 44.9.1 pins | R346 | primary |
| S537 | [SQRLShipItLauncher.m](https://github.com/Squirrel/Squirrel.Mac/blob/0f51b1344780f662b95ba50302945750599347e9/Squirrel/SQRLShipItLauncher.m) · Squirrel | ShipIt runs under the app's bundle identifier plus .ShipIt | R347 | primary |
| S538 | [SQRLDirectoryManager.m](https://github.com/Squirrel/Squirrel.Mac/blob/70a530a96efd4d071d1181eecf3d598366c805ac/Squirrel/SQRLDirectoryManager.m) · Squirrel | ShipIt keeps its files in the user's Caches directory under that name | R347 | primary |
| S539 | [package.json](https://docs.npmjs.com/cli/v11/configuring-npm/package-json) · npm | An exact version in package.json must match exactly | R348 | primary |
| S540 | [node-semver README](https://github.com/npm/node-semver/blob/0d0a0a2582fb1486bc6cd255ba18819c441ed149/README.md) · npm | Range syntax, and a range includes a pre-release only when a bound is a pre-release on the same version | R348 | primary |
| S541 | [electron_version.tmpl at v45.0.0-beta.6](https://github.com/electron/electron/blob/v45.0.0-beta.6/build/templates/electron_version.tmpl) · Electron | Electron's version string is major.minor.patch, plus a hyphen and the pre-release when there is one | R349 | primary |
| S542 | [application_info.cc at v44.9.1](https://github.com/electron/electron/blob/v44.9.1/shell/common/application_info.cc) · Electron | Where Electron puts that version string in the binary | R349 | primary |

## Container images

| # | Source | Backs | R-numbers | Kind |
|---|---|---|---|---|
| S543 | [Docker Hub tag listings for debian, ubuntu, alpine](https://hub.docker.com/v2/repositories/library/debian/tags) · Docker | Dated image tags before and after 20 October | R296, R297 | primary |
| S544 | [Distroless container images](https://github.com/GoogleContainerTools/distroless) · GoogleContainerTools | The images are based on Debian 13, and Debian 12 tags are still listed | R299 | primary |
| S545 | [certbot/certbot v5.8.0 and v5.9.0 images](https://hub.docker.com/r/certbot/certbot) · Certbot | certifi and the Alpine bundle inside the v5.8.0 and v5.9.0 images | R303 | primary |
