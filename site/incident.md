---
title: eMudhra G3 CA compromise: what happened
description: What happened in the eMudhra G3 intermediate CA key compromise: the cause, the downstream impact, which clients are exposed, the timeline, root program actions and CVE IDs.
output: incident.html
refs: none
---

<header class="band">
  <div class="wrap">
    <a class="back" href="index.html">← Back to the guide</a>
    <p class="tags"><span>eMudhra G3</span><span>CA key compromise</span><span>October 2026</span></p>
    <p class="ids"><a href="index.html">Guide</a> &nbsp;·&nbsp; Incident &nbsp;·&nbsp; <a href="checks.html">Affected software</a> &nbsp;·&nbsp; <a href="fixes.html">Fixes</a> &nbsp;·&nbsp; <a href="detections.html">Checker rules</a> &nbsp;·&nbsp; <a href="proof.html">Proof</a> &nbsp;·&nbsp; <a href="references.html">References</a></p>
    <h1><span class='hl'>eMudhra G3</span> CA compromise<br>What happened</h1>
    <p>How eight eMudhra G3 intermediate CAs came to have private keys anyone can compute, what that lets an attacker do, and which clients are still exposed. <a href="index.html#helper">Jump to the checker</a>.</p>
  </div>
</header>

::: {tag=main .wrap}

<nav class="toc read" aria-label="Contents"><h2>Contents</h2><ol>
  <li><a href="#what">What happened</a><span>The cause, the downstream impact and what eMudhra has done since</span></li>
  <li><a href="#exposed">Who is exposed</a><span>Which clients still trust the chains, and the AAA cross-sign path</span></li>
  <li><a href="#background">Timeline, root programs and CVEs</a><span>Dates from disclosure to root removal, what each root program did and the CVE IDs</span></li>
  <li><a href="#sources">Sources</a><span>Where each claim comes from</span></li>
</ol></nav>

## What happened {#what}

{: .key}
**On 17 October 2026 a researcher found that eight eMudhra G3 intermediate CAs had private keys anyone can compute. With them, anyone can issue a TLS certificate for any website, or sign malware that Windows treats as coming from a trusted publisher [R010, R001, R004].**

{: .intro}
Cause
: - **A rehearsal step in the key ceremony:** At the 30 April 2025 ceremony, eMudhra issued the CA certificates over re-imported key objects instead of the original keys [R008].
  - **Which keys:** Only the P-384 keys of series B and C, made on Utimaco HSMs, are affected [R001, R008].
  - **Two accounts:** eMudhra first blamed similar key labels, then said the ceremony script itself chose the re-imported keys [R009].

Downstream impact
: - **Forged websites:** Anyone can issue a TLS certificate for any website under the six TLS CAs, and every client that still trusts the chain accepts it [R004].
  - **Signed malware:** The two code-signing keys can make malware look like it comes from a trusted publisher on Windows [R004].
  - **Forged certificates already exist:** One commenter counted 107,107 certificates logged under six of the keys after disclosure, 106,050 of them proof-of-concept certificates for google[.]com. Nobody has confirmed the count [R013].

What eMudhra has done since
: - **Leaving TLS:** eMudhra decided on 22 October to leave the global TLS certificate market [R015].
  - **Certificates still valid:** 25,058 G3 certificates were still valid on 28 October, and eMudhra is moving their subscribers to other roots [R016].
  - **Report still owed:** eMudhra had not filed its promised root-cause report by 31 October [R018].
  - **KPMG review:** eMudhra says KPMG is reviewing it, a claim only its own status page makes [R017].

## Who is exposed {#exposed}

{: .key}
**Browsers on default settings are covered by pushed blocks and root store changes, and anything that carries its own trust store stays exposed until it gets its own update [R026, R027, R035, R033, R038].**

{: .muted .read}
Software with its own trust store includes OS bundles, language packages, JDK `cacerts`, runtimes, Electron apps and container images [R038, R039, R025].

### By client

{: .intro}
Browsers on default settings
: - Covered. Chrome's CRLSet reached users on 17 October [R026].
  - Mozilla says Firefox's OneCRL block did too, though its NSS 3.131.1 announcement says 19 October [R027].
  - Apple, Windows and Edge pushed their own blocks between 19 and 22 October [R035, R033].

New Firefox ESR 115 profile
: Can still trust the chains until OneCRL loads after 20 idle seconds [R030].

Apps with their own CA bundle
: - Need their own update, even on a patched Windows host [R038, R109].
  - Microsoft says software that doesn't reliably check revocation or its disallowed list can still accept the chains if it keeps or restores trust in the removed roots [R109].

macOS command-line tools
: Tools that read `/etc/ssl/cert.pem`, including curl, git, python3, ruby, perl and openssl, skip Apple's block and still accept the chains [R044].

Containers
: A container trusts the CA bundle inside its image, so a patched host does not protect it [R038].

Node.js
: Bundles a Mozilla snapshot fixed at release time, so only a Node.js upgrade changes it [R039].

JDKs
: - A JDK update fixes only its bundled `cacerts` [R039].
  - An app's own JKS or PKCS12 truststore needs the roots removed from that file [R039].

Electron apps
: - Electron's advisory gives 42.11.16, 43.8.1, 44.9.1 and 45.0.0-beta.6 as the first releases that block the intermediates in its Chromium networking and Node.js TLS [R025].
  - Each Electron app needs its own release on one of them [R272].
  - Fixed Electron builds still contain the G3 root, so check each app's Electron version to tell fixed from unfixed [R271].

### The AAA Certificate Services path

{: .notes}
- **A store with AAA Certificate Services and no G3 root can still trust a forged chain.** Sectigo cross-signed all eight compromised intermediates under its AAA Certificate Services root, and each cross-sign reuses the same weak key [R002]. A forged leaf can chain through those cross-signed copies to AAA, so removing emSign ECC Root CA - G3 alone does not block it [R040].
- **Before the incident Apple and Microsoft still trusted AAA.** Mozilla and Chrome had removed it [R007].
- **Fixes that block by public key also catch the cross-signs.** Go's `crypto/x509` denylist, `rustls-webpki` 0.103.16 and CPython's `ssl` block match the compromised keys [R043]. So do Chrome's CRLSet and the Windows Disallowed CTL [R026, R033]. A fix that only removes the G3 root leaves the AAA path open wherever AAA is still trusted [R040].

{: .read}
How each root program and Sectigo handle AAA and the cross-signs:

{: .intro}
Microsoft
: - Removed AAA. Windows dropped it on 26 October, and Edge and WebView2 on 27 October [R034].
  - The 20 October Disallowed CTL block matches the keys, so it covers the cross-signs too [R033].

Mozilla
: - Trusts AAA for email only. NSS and Firefox carry the root without TLS trust [R041].
  - Mozilla left the cross-signs out of OneCRL, saying the root is not in its root store [R041].

Apple
: - Blocks the six TLS cross-signs. They are among the 12 TLS certificates Apple blocks [R035].
  - In `/etc/ssl/cert.pem` they still verify through AAA, so Apple's interim steps offer removing AAA as well as G3 [R040].

Chrome
: - Its store holds no AAA root. Chrome Root Store v41, v42 and v43 do not contain it [R042].
  - Chrome's CRLSet blocks by public key, so it covers the cross-signs anyway [R026].

Sectigo
: - Revoked the cross-signs on 19 October [R011].
  - Its AAA Certificate Services CRL backdates the revocations to 14 May 2025 [R310].
  - Clients that skip revocation checks, such as the macOS tools that read `/etc/ssl/cert.pem`, still accept the chains [R044].

### Revocation and CT

{: .notes}
- **Common tools could not fetch eMudhra's revocation data until 26 October.** eMudhra's firewall refused HTTP CRL and OCSP requests from curl, Wget, Python-urllib and libwww-perl user agents from 28 September 2022 to 10:32 UTC on 26 October 2026. The blocked files include the two CRLs that carry the eight revocations. HTTPS was no fallback, because the certificates name HTTP CRL URLs [R045].
- **Clients that don't enforce CT are more exposed.** CT-enforcing clients reject a leaf that was never logged. Non-browser clients such as curl usually don't enforce CT [R046].
- **106,058 post-disclosure CT certificates chain through the AAA cross-signs, by one count.** Nobody has replicated the count [R013].

## Timeline, root programs and CVEs {#background}

{: .key}
**Chrome blocked the keys within hours of the 17 October disclosure, and Mozilla, Apple and Microsoft removed or blocked emSign ECC Root CA - G3 between 20 and 27 October [R026, R029, R035, R034].**

### Timeline

{: .list .tbl .when}
| Date and time (UTC) | Event | Refs |
|---|---|---|
| 17 Oct 16:27 | A researcher scanning certificates disclosed in CCADB found the weak keys. | R010 |
| 17 Oct 18:05 | The researcher reported them to Apple, Chrome, Microsoft, Mozilla and eMudhra. | R010 |
| 17 Oct 19:45 | Chrome's CRLSet blocked the keys. | R026 |
| 17 Oct about 21:28 | eMudhra acknowledged and said EM DV TLS CA - G3C had been live. | R010 |
| 17 Oct 21:48 | Mozilla recovered the keys on its own. | R010 |
| 17 Oct by 22:59 | Firefox's OneCRL block reached all Firefox users on standard settings. The day is disputed. | R027 |
| 18 Oct 09:24 to 09:38 | eMudhra revoked the eight with reason cACompromise. | R011 |
| 18 Oct 12:06 | Mozilla opened Bug 2083449. | R012 |
| 19 Oct | Sectigo revoked the cross-signs. Its CRL backdates the revocations to 14 May 2025. Sectigo also revoked its other eMudhra cross-signs and ended the relationship. | R011 |
| 19 Oct | Mozilla warned downstream trust store maintainers. | R012 |
| 19 Oct around 22:00 | Android got the Chrome block through Google Play services. | R026 |
| 20 Oct | Mozilla chose emergency removal of emSign ECC Root CA - G3, and Chrome committed to the same. | R028 |
| 20 Oct | Mozilla published its blog post on the incident. | R012 |
| 20 Oct | NSS 3.131.1 removed emSign ECC Root CA - G3. | R029 |
| 20 Oct | Firefox 158.0.1, ESR 153.5.1 and ESR 115.43.1 shipped with the block built in. | R030 |
| 20 Oct | The Windows Disallowed CTL blocked the eight keys, and Edge CRLSet 2026.10.20 blocked the TLS keys. | R033 |
| 20 Oct 16:27 | eMudhra confirmed it had stopped all G3 issuance. | R016 |
| 22 Oct | eMudhra decided to leave the global TLS certificate market. | R015 |
| 23 Oct | Apple's block of emSign ECC Root CA - G3 started. | R035 |
| 26 Oct | A Windows out-of-band update (KB5134133, KB5134137) removed six emSign G3 roots and AAA Certificate Services. | R034 |
| 26 Oct 10:32 | eMudhra's firewall stopped refusing HTTP CRL and OCSP requests from curl, Wget, Python-urllib and libwww-perl. | R045 |
| 27 Oct | Edge and WebView2 removed the same roots, in PKI Metadata 72.0.0.0. | R034 |
| 27 Oct | Google expected Chrome Root Store v43, which removes emSign ECC Root CA - G3, on all devices that morning (Pacific time). No source we read confirms it shipped. | R031 |

{: .notes}
- **The day of the OneCRL block is disputed.** Mozilla's blog and the bug say 17 October. The NSS 3.131.1 announcement relayed on oss-security says OneCRL went out on Saturday 19th [R027].

### Root programs

{: .intro}
Chrome
: - Removed emSign ECC Root CA - G3 in Chrome Root Store v43. Version 42 still has it [R031].
  - Google expected v43 on all devices on the morning of 27 October (Pacific time). No source we read confirms it shipped [R031].
  - The 17 October CRLSet blocks by public key, so it also covers the Sectigo cross-signs [R026].

Mozilla
: - Removed the root in NSS 3.131.1 on 20 October. The release also removes emSign Root CA - C1 and emSign ECC Root CA - C3 [R029].
  - Firefox 158.0.1, ESR 153.5.1 and ESR 115.43.1 shipped the same day with the block built in, for users whose settings keep OneCRL from updating [R030].
  - Whether ESR 115.43.1 is fixed is disputed [R030].

Microsoft
: - Removed six emSign G3 roots and AAA Certificate Services [R034].
  - Windows removed them in a 26 October out-of-band update (KB5134133, KB5134137) [R034].
  - Edge and WebView2 removed them on 27 October, in PKI Metadata 72.0.0.0 [R034].
  - On 20 October the Windows Disallowed CTL had already blocked the eight keys, and Edge CRLSet 2026.10.20 had blocked the TLS keys [R033].

Apple
: - Blocks the 12 TLS certificates and the G3 ECC root. The 12 are the six eMudhra TLS CAs and their six Sectigo cross-signs [R035].
  - The root block started on 23 October [R035].
  - Apple dates the first block to 19 October. The community tracker says 22 October [R035].
  - Command-line tools that read `/etc/ssl/cert.pem` skip Apple's block [R044].

{: .notes}
- **No root program has removed emSign Root CA - G1.** Chrome Root Store v43 and NSS master still carry it. Mozilla said on 20 October it was not removing it at that time. Microsoft is evaluating the remaining eMudhra roots [R032]. OpenJDK's interim fix deletes the G1 alias anyway [R037].

### CVE IDs

{: .read}
**The compromise has no CVE of its own.** Red Hat says it is not a software vulnerability, and the CVEs track downstream trust store updates [R019].

{: .list .tbl}
| CVE | Assigner | Covers | Refs |
|---|---|---|---|
| CVE-2026-114820 | Oracle CNA | Java SE and GraalVM updates that remove the eMudhra roots. | R022 |
| CVE-2026-91403 | Oracle CNA | Java updates that distrust the intermediates. | R023 |
| CVE-2026-111943 | Go CNA | Adds a `crypto/x509` denylist, fixed in Go 1.26.10 and 1.27.3. | R020 |
| CVE-2026-114406 | Red Hat | The RHEL `ca-certificates` package. | R021 |
| CVE-2026-113470 | Mozilla | The Firefox and Thunderbird block lists. | R030 |
| CVE-2026-115570 | GitHub (GHSA-jr5w-w6x2-84p9) | Electron before 42.11.16, 43.8.1, 44.9.1 and 45.0.0-beta.6. | R025 |
| CVE-2026-113812 | CPANSec | Perl `Mozilla::CA` before 20261020. | R024 |

{: .notes}
- OpenJDK's own advisory reuses CVE-2026-114820, with issue JDK-8395690 as its fix marker [R022].
- Every fixed Electron release checked still carries the G3 root, because the fix blocks the intermediates and leaves the root in place [R271].

{: .read}
CVE-2026-111944 has no CVE record [R019].

## Sources {#sources}

{: .read}
The [references page](references.html) lists the sources for every claim on this page, with each source’s publisher and date.

:::

<footer>
  <div class="wrap"><p>eMudhra G3 intermediate CA key compromise, October 2026. An independent guide, not affiliated with eMudhra or Sectigo.</p><p>Last updated 2026-11-05. <a href="https://github.com/fieldse/emudhra-ca-compromise-check">Source on GitHub</a>.</p></div>
</footer>
