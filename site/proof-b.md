---
title: eMudhra G3 CA compromise: Flow B, why a certificate is untrusted
description: Flow B of verifying an eMudhra G3 checker finding by hand: recompute the weak key, and confirm mozilla, chrome and apple removed or blocked the root above it.
output: proof-b.html
refs: inline
anchors: auto
---

<header class="band">
  <div class="wrap">
    <a class="back" href="proof.html">← Back to verifying a finding</a>
    <p class="tags"><span>eMudhra G3</span><span>CA key compromise</span><span>October 2026</span></p>
    <p class="ids"><a href="index.html">Guide</a> &nbsp;·&nbsp; <a href="incident.html">Incident</a> &nbsp;·&nbsp; <a href="checks.html">Affected software</a> &nbsp;·&nbsp; <a href="fixes.html">Fixes</a> &nbsp;·&nbsp; <a href="detections.html">Checker rules</a> &nbsp;·&nbsp; <a href="proof.html">Proof</a> &nbsp;·&nbsp; <a href="references.html">References</a></p>
    <h1><span class='hl'>Flow B</span><br>Why a certificate is untrusted</h1>
    <p>One of four flows for <a href="proof.html">verifying a finding</a> by hand, from the original sources. Recompute the weak key, and confirm Mozilla, Chrome and Apple removed or blocked the root above it.</p>
  </div>
</header>

::: {tag=main .wrap}

<nav class="toc read" aria-label="Contents"><h2>Contents</h2><ol>
  <li><a href="#about">About this flow</a><span>What it checks and why</span></li>
  <li><a href="#step-1-make-an-empty-work-directory">Step 1. Make an empty work directory</a></li>
  <li><a href="#step-2-download-the-projects-list">Step 2. Download the project's list</a></li>
  <li><a href="#step-3-download-the-two-certificates-from-crtsh">Step 3. Download the two certificates from crt.sh</a></li>
  <li><a href="#step-4-read-both-certificates">Step 4. Read both certificates</a></li>
  <li><a href="#step-5-compare-both-certificates-with-the-list">Step 5. Compare both certificates with the list</a></li>
  <li><a href="#step-6-compare-the-public-keys">Step 6. Compare the public keys</a></li>
  <li><a href="#step-7-find-both-certificates-in-mozillas-notice">Step 7. Find both certificates in Mozilla's notice</a></li>
  <li><a href="#step-8-read-mozillas-finding-on-the-keys">Step 8. Read Mozilla's finding on the keys</a></li>
  <li><a href="#step-9-recompute-the-weak-key">Step 9. Recompute the weak key</a></li>
  <li><a href="#step-10-find-the-roots-removal-from-mozillas-list">Step 10. Find the root's removal from Mozilla's list</a></li>
  <li><a href="#step-11-find-the-roots-removal-from-the-chrome-root-store">Step 11. Find the root's removal from the Chrome Root Store</a></li>
  <li><a href="#step-12-find-apples-block">Step 12. Find Apple's block</a></li>
  <li><a href="#result">Result</a></li>
</ol></nav>

## About this flow {#about}

{: .key}
**Flow B checks why the rules list a certificate. It matches lines 2 and 3 of `rules/iocs.csv` to the published certificates and to the Mozilla bug that reports their weak keys. It then confirms that Mozilla and Chrome removed the root above them and Apple blocked it.**

{: .read}
The check reaches its verdict from rules in this repository. These steps rebuild the evidence for one finding from primary artifacts, so you can confirm it without trusting the checker. [Setup](proof.html#setup) lists the tools this flow needs.

The removed root, `emSign ECC Root CA - G3`:

- **Mozilla:** removed it in NSS 3.131.1, a release of Mozilla's security library.
- **Chrome:** removed it in Chrome Root Store version 43.
- **Apple:** has blocked it since 23 October 2026.

The weak intermediate, `EM DV TLS CA - G3B`:

- An intermediate CA is a certificate authority (CA) whose certificate is signed by a root.
- `EM DV TLS CA - G3B` is one of the eight intermediates that Mozilla Bug 2083449 reports have P-384 private keys below 256.
  - P-384 is a standard elliptic curve.
- The flow matches its serial number and SHA-256, and those of its Sectigo cross-sign, a second certificate for the same CA that reuses its key.

### The lines being checked

Lines 2 and 3 of `rules/iocs.csv` at release `v2.0.0`:

```text
EM DV TLS CA - G3B,compromised TLS intermediate,emSign Root TLS CA - G3,A4AEE678F23362B4C0E460B772F214,42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493,A99B289464F3B44343270A7A1E910F02370483FE,E21E2FE71C19390E554B62C120245735248A2514
EM DV TLS CA - G3B,compromised TLS intermediate,AAA Certificate Services,A024FDF4BA665C785CE4A020483858B7,45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE,1396BE1372BC93DFA2A433CA964DBA91548A6E57,E21E2FE71C19390E554B62C120245735248A2514
```

- Both lines are for one CA, `EM DV TLS CA - G3B`. The columns after the name and role are the issuer, serial number, SHA-256, SHA-1 and subject key identifier.
- Line 2 is the certificate eMudhra's root `emSign Root TLS CA - G3` issued. That root chains to `emSign ECC Root CA - G3`, the root Flow A finds.
- Line 3 is a cross-sign: a second certificate for the same CA, issued by Sectigo's root `AAA Certificate Services`. Software that trusts either root accepts certificates the CA signs.

### What the steps do

- **Steps 1 to 3:** download the project's list and the two certificates from crt.sh.
- **Steps 4 to 6:** read both certificates, compare them with lines 2 and 3, and compare their public keys.
- **Steps 7 and 8:** find both certificates in Mozilla's notice to trust store operators, the vendors that keep lists of trusted roots, and read Mozilla's finding on the keys.
- **Step 9:** recompute the weak-key finding with `openssl`, as an optional check.
- **Steps 10 to 12:** confirm that Mozilla and Chrome removed `emSign ECC Root CA - G3` and Apple blocked it.

The steps were run on 4 November 2026 with OpenSSL 3.6 and again with LibreSSL 3.3, the version macOS ships. Both gave the same values in different formats. LibreSSL's output differs in three ways:

- It prints names as `/C=NL/O=eMudhra BV/...` where OpenSSL prints `C=NL, O=eMudhra BV, ...`.
- It puts a space after `subject=`.
- It writes `SHA256 Fingerprint=` in capitals.

## Step 1. Make an empty work directory

`mktemp -d` makes a new empty directory with a random name. Every later step writes its files there.

```bash
cd "$(mktemp -d)"
ls -A | wc -l
```

```text
       0
```

## Step 2. Download the project's list

The list is the copy published with release `v2.0.0`, as in Flow A.

```bash
curl -fsS -o iocs.csv https://raw.githubusercontent.com/fieldse/emudhra-ca-compromise-check/v2.0.0/rules/iocs.csv
sed -n '1,3p' iocs.csv
```

```text
name,role,issuer,serial_hex,sha256,sha1,subject_key_identifier
EM DV TLS CA - G3B,compromised TLS intermediate,emSign Root TLS CA - G3,A4AEE678F23362B4C0E460B772F214,42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493,A99B289464F3B44343270A7A1E910F02370483FE,E21E2FE71C19390E554B62C120245735248A2514
EM DV TLS CA - G3B,compromised TLS intermediate,AAA Certificate Services,A024FDF4BA665C785CE4A020483858B7,45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE,1396BE1372BC93DFA2A433CA964DBA91548A6E57,E21E2FE71C19390E554B62C120245735248A2514
```

## Step 3. Download the two certificates from crt.sh

crt.sh is the certificate transparency search used in Flow A step 7. Each certificate has a page with a crt.sh ID:

| Line | crt.sh page |
|---|---|
| 2 | `https://crt.sh/?id=18286207191` |
| 3 | `https://crt.sh/?id=18519019583` |

A search on the SHA-256 from each line, `https://crt.sh/?sha256=<hash>`, leads to the same two pages. Adding `?d=` with the ID downloads the certificate in PEM form.

```bash
curl -fsS --retry 5 -o g3b-emudhra.pem 'https://crt.sh/?d=18286207191'
curl -fsS --retry 5 -o g3b-sectigo.pem 'https://crt.sh/?d=18519019583'
grep -c 'BEGIN CERTIFICATE' g3b-emudhra.pem g3b-sectigo.pem
```

```text
g3b-emudhra.pem:1
g3b-sectigo.pem:1
```

- crt.sh is often busy and answers with a `502` or `404` error. `-f` makes `curl` stop with an error message and save nothing.
- `--retry 5` tries again after a server error. If a command still fails, run it again.
- A count of 1 for each file shows it holds one certificate and no error page.

## Step 4. Read both certificates

```bash
openssl x509 -in g3b-emudhra.pem -noout -subject -issuer -serial -dates -fingerprint -sha256
openssl x509 -in g3b-sectigo.pem -noout -subject -issuer -serial -dates -fingerprint -sha256
```

```text
subject=C=NL, O=eMudhra BV, CN=EM DV TLS CA - G3B
issuer=C=IN, O=eMudhra Technologies Limited, CN=emSign Root TLS CA - G3
serial=A4AEE678F23362B4C0E460B772F214
notBefore=Apr 30 15:54:08 2025 GMT
notAfter=Apr 28 18:30:00 2040 GMT
sha256 Fingerprint=42:C4:AC:CD:12:C4:F5:95:97:92:5E:1A:08:A7:A9:01:02:60:85:43:80:93:08:D5:0E:C4:27:E1:18:BA:14:93
subject=C=NL, O=eMudhra BV, CN=EM DV TLS CA - G3B
issuer=C=GB, ST=Greater Manchester, L=Salford, O=Comodo CA Limited, CN=AAA Certificate Services
serial=A024FDF4BA665C785CE4A020483858B7
notBefore=May 14 00:00:00 2025 GMT
notAfter=Dec 31 23:59:59 2028 GMT
sha256 Fingerprint=45:A8:83:F3:49:AE:DF:D5:F3:A6:49:B5:49:8F:FB:12:17:12:BA:8B:44:8F:3F:2A:91:DB:C5:A7:66:FC:DD:BE
```

- Both certificates have the same subject, `EM DV TLS CA - G3B` of eMudhra BV.
- The first is issued by eMudhra's `emSign Root TLS CA - G3`, on 30 April 2025.
- The second is issued by `AAA Certificate Services`, on 14 May 2025. Sectigo runs this root, which still carries the name Comodo CA Limited.

## Step 5. Compare both certificates with the list

The function below reads a certificate's serial number and SHA-256 fingerprint, puts the fingerprint in the list's form as Flow A step 5 does, and compares both with columns 4 and 5 of one line. It prints `match` only when all digits of both are equal.

```bash
check() {
  serial=$(openssl x509 -in "$2" -noout -serial | cut -d= -f2)
  sha=$(openssl x509 -in "$2" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'a-f' 'A-F')
  [ "$serial,$sha" = "$(sed -n "$1p" iocs.csv | cut -d, -f4,5)" ] && echo "line $1: match" || echo "line $1: differ"
}
check 2 g3b-emudhra.pem
check 3 g3b-sectigo.pem
```

```text
line 2: match
line 3: match
```

## Step 6. Compare the public keys

A certificate binds a name to a public key. The field that holds the key and its algorithm is the subject public key info, or SPKI.

The SHA-256 of the SPKI identifies the key, as the fingerprint identifies the certificate. Mozilla's notice in step 7 lists keys by this hash.

```bash
spki() { openssl x509 -in "$1" -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256 | sed 's/.*= //'; }
spki g3b-emudhra.pem
spki g3b-sectigo.pem
openssl x509 -in g3b-emudhra.pem -noout -text | grep -E 'Public-Key|NIST CURVE'
```

```text
ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105
ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105
                Public-Key: (384 bit)
                NIST CURVE: P-384
```

- The two hashes are equal, so the two certificates carry the same public key.
- One private key belongs to that public key. Whoever holds it can sign certificates that chain through either certificate, to either root.
- The key is on the P-384 curve.

## Step 7. Find both certificates in Mozilla's notice

Mozilla Bug 2083449 is Mozilla's incident report for the eMudhra key compromise. In [comment 15](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449#c15) Mozilla attached, as plain text, the notice it sent to trust store operators. The attachment is `https://bugzilla.mozilla.org/attachment.cgi?id=9664786`.

```bash
curl -fsSL -o disclosure.txt 'https://bugzilla.mozilla.org/attachment.cgi?id=9664786'
tr -d '\r' < disclosure.txt | grep -v '^$' > notice.txt
grep -B3 "serial $(sed -n 2p iocs.csv | cut -d, -f4 | tr 'A-F' 'a-f')" notice.txt
grep 'SPKIs identical' notice.txt
grep -B2 "serial $(sed -n 3p iocs.csv | cut -d, -f4 | tr 'A-F' 'a-f')" notice.txt
grep -A3 'three different chains' notice.txt | sed 1d
```

```text
EM DV TLS CA - G3B (eMudhra BV), CCADB A012302
SHA-256 42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493
SHA256 SPKI ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105
serial a4aee678f23362b4c0e460b772f214, issuer emSign Root TLS CA - G3
These keys have also been cross-signed by Sectigo (SPKIs identical to the originals): 
EM DV TLS CA - G3B, CCADB A012347
SHA-256 45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE
serial a024fdf4ba665c785ce4a020483858b7
    AAA Certificate Services (SPKI SHA-256: bd153ed7b0434f6886b17bce8bbe84ed340c7132d702a8f4fa318f756ecbd6f3)
    emSign Root TLS CA - G3 (SPKI SHA-256: c619e4780ed8e0abeda24ad732567de4383a7ea941338f6d1a7d1b49ac792fe9)
    emSign ECC Root CA - G3 (SPKI SHA-256: 8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782)
```

The commands take the serial numbers from lines 2 and 3 of the list, in lower case, and print the notice's entries for them.

- The file has Windows line endings and blank lines between entries. `tr -d '\r'` and `grep -v '^$'` remove them.
- The first entry has line 2's serial number, line 2's SHA-256 and the SPKI hash from step 6.
- The second entry has line 3's serial number and SHA-256. It sits under the notice's heading for the Sectigo cross-signs, which says their SPKIs are identical to the originals.
- The last lines list the TLS chains that may be in use. `emSign ECC Root CA - G3` is one of the roots they name. The two code-signing intermediates chain to `emSign Root CS CA - G3`, which that list leaves out.

## Step 8. Read Mozilla's finding on the keys

Mozilla describes the flaw in [comment 5](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449#c5) of the bug. Bugzilla's REST API returns a single comment as JSON, and `18423372` is that comment's internal ID.

```bash
curl -fsS -o c5.json 'https://bugzilla.mozilla.org/rest/bug/comment/18423372'
grep -o -e '"bug_id":[0-9]*' -e '"count":[0-9]*' c5.json
grep -o -e 'The impacted keys are all the P384 keys[^.]*\.' -e 'The 8 impacted keys all used integers less than 256\.' c5.json | head -2
```

```text
"bug_id":2083449
"count":5
The impacted keys are all the P384 keys for the B and C series.
The 8 impacted keys all used integers less than 256.
```

- `bug_id` and `count` show this is comment 5 of Bug 2083449.
- The JSON holds the comment's text twice, so `head -2` keeps one copy of each sentence.
- A P-384 private key is a random whole number between 1 and a number about 384 bits long. A key below 256 fits in one byte, so anyone can find it by trying all 255 values.

## Step 9. Recompute the weak key

This optional step tries every private key from 1 to 255 and checks whether one of them belongs to the public key from step 6.

```bash
curl -fsS --retry 5 -o root-g3.pem 'https://crt.sh/?d=713604941'
grep -c 'BEGIN CERTIFICATE' root-g3.pem
openssl x509 -in root-g3.pem -noout -subject -fingerprint -sha256
openssl x509 -in root-g3.pem -noout -text | grep -E 'Public-Key|NIST CURVE'
search() {
  want=$(spki "$1")
  d=1
  while [ "$d" -le 255 ]; do
    printf 'asn1=SEQUENCE:k\n[k]\nv=INTEGER:1\nd=FORMAT:HEX,OCTETSTRING:%094d%02x\nc=EXPLICIT:0,OID:secp384r1\n' 0 "$d" > k.cnf
    openssl asn1parse -genconf k.cnf -noout -out k.der
    got=$(openssl ec -inform DER -in k.der -pubout -outform DER 2>/dev/null | openssl dgst -sha256 | sed 's/.*= //')
    [ "$got" = "$want" ] && echo "$1: private key is below 256"
    d=$((d+1))
  done
  rm -f k.cnf k.der
  echo "$1: searched 1 to 255"
}
search g3b-emudhra.pem
search root-g3.pem
```

```text
1
subject=C=IN, OU=emSign PKI, O=eMudhra Technologies Limited, CN=emSign ECC Root CA - G3
sha256 Fingerprint=86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04:3C:F9:E8:A8:62:CD:5C:57:A3:6B:BE:6B
                Public-Key: (384 bit)
                NIST CURVE: P-384
g3b-emudhra.pem: private key is below 256
g3b-emudhra.pem: searched 1 to 255
root-g3.pem: searched 1 to 255
```

- For each number `d`, `printf` writes a description of a P-384 private key whose value is `d`, padded with zeros to 48 bytes. `openssl asn1parse -genconf` turns the description into a key file.
- `openssl ec -pubout` works out the public key that belongs to that private key. The loop hashes it as step 6 does and compares the result with the certificate's.
- The `spki` function comes from step 6.
- `root-g3.pem` is `emSign ECC Root CA - G3`, downloaded by the crt.sh ID from Flow A step 7. Its fingerprint is the one in Flow A.
- The root also has a P-384 key and is the control. The search finds no key below 256 for it.
- The loop prints the name of the file that matched and leaves out the value of `d`.
- It deletes its key files when it ends, and takes a few seconds.

## Step 10. Find the root's removal from Mozilla's list

NSS is Mozilla's security library, and its source file `certdata.txt` is Mozilla's root list that Flow A step 8 reads. The commands download the file at two release tags, NSS 3.131 and NSS 3.131.1.

```bash
curl -fsS -o certdata-3.131.txt https://raw.githubusercontent.com/nss-dev/nss/NSS_3_131_RTM/lib/ckfw/builtins/certdata.txt
curl -fsS -o certdata-3.131.1.txt https://raw.githubusercontent.com/nss-dev/nss/NSS_3_131_1_RTM/lib/ckfw/builtins/certdata.txt
grep -c '86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04:3C:F9:E8:A8:62:CD:5C:57:A3:6B:BE:6B' certdata-3.131.txt certdata-3.131.1.txt
grep '^# Certificate "emSign' certdata-3.131.txt certdata-3.131.1.txt
```

```text
certdata-3.131.txt:2
certdata-3.131.1.txt:0
certdata-3.131.txt:# Certificate "emSign Root CA - G1"
certdata-3.131.txt:# Certificate "emSign ECC Root CA - G3"
certdata-3.131.txt:# Certificate "emSign Root CA - C1"
certdata-3.131.txt:# Certificate "emSign ECC Root CA - C3"
certdata-3.131.1.txt:# Certificate "emSign Root CA - G1"
```

- The fingerprint is the root's SHA-256 from Flow A. NSS 3.131 has it twice, in the certificate record and the trust record. NSS 3.131.1 does not have it.
- NSS 3.131.1 also drops `emSign Root CA - C1` and `emSign ECC Root CA - C3`, and keeps `emSign Root CA - G1`.

The decision is in [comment 18](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449#c18) of the bug:

```bash
curl -fsS -o c18.json 'https://bugzilla.mozilla.org/rest/bug/comment/18429106'
grep -o -e '"bug_id":[0-9]*' -e '"count":[0-9]*' c18.json
grep -o 'we have decided[^.]*\.' c18.json | head -1
```

```text
"bug_id":2083449
"count":18
we have decided that the circumstances warrant the emergency removal of trust in emSign ECC Root CA - G3.
```

The [NSS 3.131.1 release notes](https://firefox-source-docs.mozilla.org/security/nss/releases/nss_3_131_1.html) give the release date as 20 October 2026 and list the change as "Bug 2084101 - Remove eMudhra emSign Root CA - G3 from NSS." The note leaves "ECC" out of the root's name. The `certdata.txt` comparison above shows which root went.

## Step 11. Find the root's removal from the Chrome Root Store

Chrome's root list is the file `root_store.textproto` in the Chromium source. It names each root by the SHA-256 of the certificate, in lower case, on a `sha256_hex` line. Its `version_major` line is the Chrome Root Store version.

Chromium commit `8793082f793c2533dccf28e83e33f0e700c52d28`, the automatic update for 20 October 2026, changed the file to version 43. Its parent commit, `47a3823334a4d0632a4eabb003a0677553b447e6`, holds version 42. The Chromium source server returns a file in base64 when the URL ends in `?format=TEXT`, and `openssl base64 -d -A` decodes it.

```bash
crs='net/data/ssl/chrome_root_store/root_store.textproto?format=TEXT'
curl -fsS --retry 5 "https://chromium.googlesource.com/chromium/src/+/47a3823334a4d0632a4eabb003a0677553b447e6/$crs" | openssl base64 -d -A > crs-v42.txt
curl -fsS --retry 5 "https://chromium.googlesource.com/chromium/src/+/8793082f793c2533dccf28e83e33f0e700c52d28/$crs" | openssl base64 -d -A > crs-v43.txt
grep -e 'version_major' -e '86a1ecba' crs-v42.txt crs-v43.txt
```

```text
crs-v42.txt:version_major: 42
crs-v42.txt:  sha256_hex: "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b"
crs-v43.txt:version_major: 43
```

Version 42 lists the root's SHA-256. Version 43 does not. The same files open in a browser without `?format=TEXT`:

```text
https://chromium.googlesource.com/chromium/src/+/47a3823334a4d0632a4eabb003a0677553b447e6/net/data/ssl/chrome_root_store/root_store.textproto
https://chromium.googlesource.com/chromium/src/+/8793082f793c2533dccf28e83e33f0e700c52d28/net/data/ssl/chrome_root_store/root_store.textproto
```

## Step 12. Find Apple's block

Apple describes its block in the support article "About the compromised eMudhra intermediate CAs", `https://support.apple.com/en-us/149555`. Apple updates the article in place, so the commands also print its published date.

```bash
curl -fsSL -o apple.html 'https://support.apple.com/en-us/149555'
grep -o "datePublished'>[^<]*" apple.html
grep -o '[^>.]*began blocking[^.<]*\.' apple.html
grep -o '[^>.]*which chains to[^.<]*' apple.html
grep -o '[^>.]*check Apple[^.<]*\.' apple.html
awk '{gsub(/<\/tr>/, "\n"); print}' apple.html | sed 's/<[^>]*>/ /g' | tr -s ' ' | grep -e "$(sed -n 2p iocs.csv | cut -d, -f5)" -e "$(sed -n 3p iocs.csv | cut -d, -f5)"
```

```text
datePublished'>October 29, 2026
On 19 October 2026, Apple began blocking these 12 certificates on Apple devices.
 On 23 October 2026, Apple also began blocking the emSign ECC Root CA - G3.
A certificate issued by emSign Root TLS CA - G3, which chains to emSign ECC Root CA - G3
A certificate cross-signed by Sectigo, which chains to AAA Certificate Services
 For certificates that chain to a root CA certificate in this file, these tools don't check Apple's block or whether the certificate has been revoked.
 EM DV TLS CA - G3B emSign Root TLS CA - G3 42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493 
 EM DV TLS CA - G3B AAA Certificate Services 45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE 
```

- Apple blocked the 12 certificates of the six TLS intermediates from 19 October 2026, and the root from 23 October 2026.
- The two "chains to" lines describe the two certificates each intermediate has. The first is the chain from line 2 up to `emSign ECC Root CA - G3`.
- "This file" in the next line is `/etc/ssl/cert.pem`, the bundle Flow A reads. Command-line tools that use it do not check Apple's block.
- The last command splits the article's table of blocked certificates into rows and keeps the rows with the SHA-256 values from lines 2 and 3. Both certificates are in the table.

## Result

- **Certificates:** lines 2 and 3 of `rules/iocs.csv` are the two published certificates for `EM DV TLS CA - G3B`, crt.sh IDs 18286207191 and 18519019583.
  - Their serial numbers and SHA-256 values match.
- **Key:** both certificates carry the public key with SPKI hash `ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105`.
- **Weak key:** Mozilla's notice in Bug 2083449 lists both certificates and that key.
  - Comment 5 reports that the eight intermediates have P-384 private keys below 256.
  - Step 9 tries every private key from 1 to 255 and finds one whose public key matches the certificate's.
  - The Sectigo cross-sign of `EM DV TLS CA - G3B` carries the same public key, so the result covers it too.
  - The same search on `emSign ECC Root CA - G3`, the control, finds no match.
  - Step 9 prints only which file matched. This page does not publish the private key.
- **Other intermediates:** the other seven were not recomputed. Their weak keys rest on the Mozilla bug report and the published certificates.
- **The check:** it matches certificates by content and public key. It does not recompute any private key.
- **Root:** `emSign ECC Root CA - G3` is missing from NSS 3.131.1 and from Chrome Root Store version 43.
  - Apple has blocked it since 23 October 2026.

Each claim in Flow B rests on one of these original sources:

| Claim | Step | Source and what to look for |
|---|---|---|
| The project's list names both `EM DV TLS CA - G3B` certificates | Step 2 | [`rules/iocs.csv` at release `v2.0.0`](https://raw.githubusercontent.com/fieldse/emudhra-ca-compromise-check/v2.0.0/rules/iocs.csv). Lines 2 and 3, `serial_hex` column: `A4AEE678F23362B4C0E460B772F214` and `A024FDF4BA665C785CE4A020483858B7` |
| Line 2 of the list is eMudhra's certificate for `EM DV TLS CA - G3B` | Steps 3 to 5 | [crt.sh search for line 2's SHA-256](https://crt.sh/?sha256=42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493). crt.sh ID `18286207191`, issuer `emSign Root TLS CA - G3` |
| Line 3 of the list is Sectigo's cross-sign of the same CA | Steps 3 to 5 | [crt.sh search for line 3's SHA-256](https://crt.sh/?sha256=45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE). crt.sh ID `18519019583`, issuer `AAA Certificate Services`. [Archived copy](https://web.archive.org/web/20251218045629/https://crt.sh/?sha256=45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE) |
| Mozilla's notice lists both certificates and the key they share | Steps 6 and 7 | [Mozilla's notice, attached in comment 15 of Bug 2083449](https://bugzilla.mozilla.org/attachment.cgi?id=9664786). `SHA256 SPKI ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105`, `serial a4aee678f23362b4c0e460b772f214`, `serial a024fdf4ba665c785ce4a020483858b7` and "SPKIs identical to the originals" |
| The eight keys are below 256 | Step 8 | [Bug 2083449, comment 5](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449#c5). "The 8 impacted keys all used integers less than 256." [Archived copy](https://web.archive.org/web/20261103143306/https://bugzilla.mozilla.org/show_bug.cgi?id=2083449#c5) |
| Mozilla decided on the emergency removal of the G3 root | Step 10 | [Bug 2083449, comment 18](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449#c18). "we have decided that the circumstances warrant the emergency removal of trust in emSign ECC Root CA - G3." [Archived copy](https://web.archive.org/web/20261103143306/https://bugzilla.mozilla.org/show_bug.cgi?id=2083449#c18) |
| NSS 3.131 holds the G3 root | Step 10 | [`certdata.txt` at tag `NSS_3_131_RTM`](https://raw.githubusercontent.com/nss-dev/nss/NSS_3_131_RTM/lib/ckfw/builtins/certdata.txt). `# Certificate "emSign ECC Root CA - G3"`, and the root's SHA-256 fingerprint twice |
| NSS 3.131.1 drops the G3 root | Step 10 | [`certdata.txt` at tag `NSS_3_131_1_RTM`](https://raw.githubusercontent.com/nss-dev/nss/NSS_3_131_1_RTM/lib/ckfw/builtins/certdata.txt). No `emSign ECC Root CA - G3`. `# Certificate "emSign Root CA - G1"` is still there |
| NSS 3.131.1 came out on 20 October 2026 with the removal | Step 10 | [NSS 3.131.1 release notes](https://firefox-source-docs.mozilla.org/security/nss/releases/nss_3_131_1.html). "Network Security Services (NSS) 3.131.1 was released on 20 October 2026." and "Bug 2084101 - Remove eMudhra emSign Root CA - G3 from NSS." |
| Chrome Root Store version 42 lists the G3 root | Step 11 | [`root_store.textproto` at commit `47a3823`](https://chromium.googlesource.com/chromium/src/+/47a3823334a4d0632a4eabb003a0677553b447e6/net/data/ssl/chrome_root_store/root_store.textproto). `version_major: 42` and `sha256_hex: "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b"` |
| Chrome Root Store version 43 drops the G3 root | Step 11 | [`root_store.textproto` at commit `8793082`](https://chromium.googlesource.com/chromium/src/+/8793082f793c2533dccf28e83e33f0e700c52d28/net/data/ssl/chrome_root_store/root_store.textproto). `version_major: 43`, and no `86a1ecba` |
| Apple blocks the `EM DV TLS CA - G3B` certificates and the G3 root | Step 12 | [Apple support article 149555](https://support.apple.com/en-us/149555). "On 19 October 2026, Apple began blocking these 12 certificates on Apple devices.", "On 23 October 2026, Apple also began blocking the emSign ECC Root CA - G3." and table rows with the SHA-256 values from lines 2 and 3 of the list |
| Tools that read `/etc/ssl/cert.pem` on macOS do not check Apple's block | Step 12 | [Apple support article 149555](https://support.apple.com/en-us/149555). "these tools don't check Apple's block or whether the certificate has been revoked" |

:::

<footer>
  <div class="wrap"><p>eMudhra G3 intermediate CA key compromise, October 2026. An independent guide, not affiliated with eMudhra or Sectigo.</p><p>Last updated 2026-11-05. <a href="https://github.com/fieldse/emudhra-ca-compromise-check">Source on GitHub</a>.</p></div>
</footer>
