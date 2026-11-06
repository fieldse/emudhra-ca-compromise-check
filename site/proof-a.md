---
title: eMudhra G3 CA compromise: Flow A, a certificate in a bundle
description: Flow A of verifying an eMudhra G3 checker finding by hand: find a certificate in a ca bundle or java keystore, and confirm it is the one on the project’s list.
output: proof-a.html
refs: inline
anchors: auto
---

<header class="band">
  <div class="wrap">
    <a class="back" href="proof.html">← Back to verifying a finding</a>
    <p class="tags"><span>eMudhra G3</span><span>CA key compromise</span><span>October 2026</span></p>
    <p class="ids"><a href="index.html">Guide</a> &nbsp;·&nbsp; <a href="incident.html">Incident</a> &nbsp;·&nbsp; <a href="checks.html">Affected software</a> &nbsp;·&nbsp; <a href="fixes.html">Fixes</a> &nbsp;·&nbsp; <a href="detections.html">Checker rules</a> &nbsp;·&nbsp; <a href="proof.html">Proof</a> &nbsp;·&nbsp; <a href="references.html">References</a></p>
    <h1><span class='hl'>Flow A</span><br>A certificate in a bundle</h1>
    <p>One of four flows for <a href="proof.html">verifying a finding</a> by hand, from the original sources. Find a certificate in a CA bundle or Java keystore, and confirm it is the one on the project’s list.</p>
  </div>
</header>

::: {tag=main .wrap}

<nav class="toc read" aria-label="Contents"><h2>Contents</h2><ol>
  <li><a href="#about">About this flow</a><span>What it checks and why</span></li>
  <li><a href="#step-1-make-an-empty-work-directory">Step 1. Make an empty work directory</a></li>
  <li><a href="#step-2-count-the-certificates-in-the-bundle">Step 2. Count the certificates in the bundle</a></li>
  <li><a href="#step-3-split-the-bundle-into-one-file-per-certificate">Step 3. Split the bundle into one file per certificate</a></li>
  <li><a href="#step-4-find-the-certificate-by-its-sha-256-fingerprint">Step 4. Find the certificate by its SHA-256 fingerprint</a></li>
  <li><a href="#step-5-compare-the-full-hash-with-the-projects-list">Step 5. Compare the full hash with the project's list</a></li>
  <li><a href="#step-6-read-the-certificate">Step 6. Read the certificate</a></li>
  <li><a href="#step-7-look-the-hash-up-at-crtsh">Step 7. Look the hash up at crt.sh</a></li>
  <li><a href="#step-8-find-the-root-in-mozillas-root-list">Step 8. Find the root in Mozilla's root list</a></li>
  <li><a href="#the-same-check-in-a-java-keystore">The same check in a Java keystore</a></li>
  <li><a href="#result">Result</a></li>
</ol></nav>

## About this flow {#about}

{: .key}
**Flow A checks one `FAIL` line by hand, without running the check. It confirms that the bundle holds the exact certificate on the project's list, and that the hash on the list belongs to a real eMudhra root that Mozilla trusted.**

{: .read}
The check reaches its verdict from rules in this repository. These steps rebuild the evidence for one finding from primary artifacts, so you can confirm it without trusting the checker. [Setup](proof.html#setup) lists the tools this flow needs.

### The line being checked

On a Mac the check can print this line:

```text
FAIL  os trust store [/etc/ssl/cert.pem] contains emSign ECC Root CA - G3 (removed root)
```

- It means the file `/etc/ssl/cert.pem` still holds the root certificate `emSign ECC Root CA - G3`.
- A root certificate is a trust anchor. Software trusts a trust anchor without checking any certificate above it, and trusts every certificate issued under it.
- Any program that reads `/etc/ssl/cert.pem` as its list of trusted roots still trusts this one.

### What the steps do

- **Steps 1 to 3:** split the bundle into one file per certificate.
- **Steps 4 to 6:** find the certificate by its SHA-256 fingerprint, compare that fingerprint with the project's list and read the certificate.
- **Steps 7 and 8:** look the same fingerprint up in two primary artifacts, crt.sh and Mozilla's list of trusted roots as Debian ships it.
- **Java keystore:** find the same fingerprint in a Java runtime's trusted roots, as an optional last check.

[Flow B](proof-b.html) shows why that root is no longer trusted.

The certificate count and the file numbers in the output depend on the machine.

## Step 1. Make an empty work directory

`mktemp -d` makes a new empty directory with a random name. Step 3 writes more than a hundred files, and an empty directory keeps them apart from everything else.

```bash
cd "$(mktemp -d)"
ls -A | wc -l
```

```text
       0
```

## Step 2. Count the certificates in the bundle

The count sets how many times step 3 cuts the file. The bundle stores each certificate in PEM form, a block of text that opens with a `-----BEGIN CERTIFICATE-----` line, so counting those lines counts the certificates.

```bash
grep -c 'BEGIN CERTIFICATE' /etc/ssl/cert.pem
```

```text
128
```

## Step 3. Split the bundle into one file per certificate

`openssl x509` reads only the first certificate in a file, so each certificate needs a file of its own.

```bash
n=$(grep -c 'BEGIN CERTIFICATE' /etc/ssl/cert.pem)
csplit -s -k -n 3 -f c- /etc/ssl/cert.pem '/-----BEGIN CERTIFICATE-----/' "{$((n-1))}"
ls c-* | wc -l
ls c-* | sed -n '1p;2p;$p'
```

```text
     129
c-000
c-001
c-128
```

`csplit` cuts the file at the first `BEGIN` line and then repeats the cut `n-1` times, 127 here, once for each remaining certificate.

- `-f c-` names the pieces `c-000`, `c-001` and so on.
- `-n 3` gives the names three digits. The macOS `csplit` uses two by default and stops at 100 files.
- `-k` keeps the pieces already written if `csplit` stops early.
- `-s` turns off the byte counts `csplit` prints for each piece.

The macOS `csplit` has no `{*}` for "repeat to the end of the file", so the command passes in the count from step 2.

There are 129 pieces for 128 certificates. `c-000` holds the comment text at the top of the bundle, before the first certificate, and no certificate.

```bash
grep -c 'BEGIN CERTIFICATE' c-000
```

```text
0
```

Every other piece starts at a `BEGIN` line. In this bundle every piece but the last also carries, after its `END` line, a text description of the next certificate. `openssl` reads the block from `BEGIN` to `END` and ignores the text around it.

## Step 4. Find the certificate by its SHA-256 fingerprint

A SHA-256 fingerprint is the SHA-256 hash of a certificate's bytes, 64 hexadecimal digits that `openssl` prints in pairs separated by colons. Any change to the certificate changes the fingerprint, so a matching fingerprint identifies one certificate exactly. A name does not, because anyone can put any name in a certificate.

The loop prints the fingerprint of every piece and keeps the line that starts with `86:A1:EC:BA`.

```bash
for f in c-*; do echo "$f $(openssl x509 -in "$f" -noout -fingerprint -sha256 2>/dev/null)"; done | grep '86:A1:EC:BA'
```

```text
c-044 sha256 Fingerprint=86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04:3C:F9:E8:A8:62:CD:5C:57:A3:6B:BE:6B
```

The prefix `86:A1:EC:BA` is the first eight digits of the hash on the project's list. A prefix taken from the list being tested only points at a candidate, and step 5 compares all 64 digits.

`2>/dev/null` hides the error `openssl` gives for `c-000`, which holds no certificate. The steps below use `c-044`. On another machine the piece number differs.

## Step 5. Compare the full hash with the project's list

Only a match on all 64 digits shows that the bundle holds the certificate the project lists.

The project's list of certificates is `rules/iocs.csv`. The command below downloads the copy published with release `v2.0.0`. A clone of the repo at that tag holds the same file.

```bash
curl -sS -o iocs.csv https://raw.githubusercontent.com/fieldse/emudhra-ca-compromise-check/v2.0.0/rules/iocs.csv
sed -n '1p;18p' iocs.csv
```

```text
name,role,issuer,serial_hex,sha256,sha1,subject_key_identifier
emSign ECC Root CA - G3,G3 root,emSign ECC Root CA - G3,3CF607A968700EDA8B84,86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B,3043FA4FF257DCA0C380EE2E58EA78B23FE6BBC1,7C5D028413D4CC8A9B81CE171C2E291E9C486342
```

The fifth column, `sha256`, holds the hash as 64 digits with no colons. The first command below puts the bundle's fingerprint in the same form by cutting the text before `=`, removing the colons and changing any lower-case letters to upper case. The second prints the fifth column of line 18.

```bash
openssl x509 -in c-044 -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'a-f' 'A-F'
sed -n 18p iocs.csv | cut -d, -f5
```

```text
86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B
86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B
```

The shell test below compares the two strings character by character. It prints `match` only when all 64 digits are equal.

```bash
a=$(openssl x509 -in c-044 -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'a-f' 'A-F')
b=$(sed -n 18p iocs.csv | cut -d, -f5)
[ "$a" = "$b" ] && echo match || echo differ
```

```text
match
```

## Step 6. Read the certificate

The subject, issuer, serial number and dates show which certificate `c-044` is.

```bash
openssl x509 -in c-044 -noout -subject -issuer -serial -dates
openssl verify -check_ss_sig -CAfile c-044 c-044
```

```text
subject=C=IN, OU=emSign PKI, O=eMudhra Technologies Limited, CN=emSign ECC Root CA - G3
issuer=C=IN, OU=emSign PKI, O=eMudhra Technologies Limited, CN=emSign ECC Root CA - G3
serial=3CF607A968700EDA8B84
notBefore=Feb 18 18:30:00 2018 GMT
notAfter=Feb 18 18:30:00 2043 GMT
c-044: OK
```

- The subject is the name the certificate is for. The issuer is the name of whoever signed it. Both are `emSign ECC Root CA - G3` of eMudhra Technologies Limited.
- `openssl verify` treats `c-044` as its own trusted root, and `-check_ss_sig` makes it check the certificate's signature against the certificate's own public key. `OK` means the certificate signed itself, which makes it self-signed, as every root certificate is.
- The serial number, `3CF607A968700EDA8B84`, is the same as the `serial_hex` column on line 18 of `rules/iocs.csv`.
- The certificate is valid from 18 February 2018 to 18 February 2043.

Browser and operating system vendors stop trusting a root by dropping it from their lists of trusted roots. The certificate itself does not change, and nothing in it marks it as compromised or withdrawn.

## Step 7. Look the hash up at crt.sh

crt.sh is a public search of certificate transparency logs, the public, append-only records of certificates kept by Google, Sectigo, DigiCert and others. The project does not run it.

The page for this fingerprint is:

```text
https://crt.sh/?sha256=86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B
```

On 3 November 2026 the page showed these values:

| Field on the page | Value |
|---|---|
| crt.sh ID | `713604941` |
| Summary | Root certificate |
| Certificate Fingerprints, SHA-256 | `86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B` |
| Serial Number | `3c:f6:07:a9:68:70:0e:da:8b:84` |
| Issuer | `commonName = emSign ECC Root CA - G3`, `organizationName = eMudhra Technologies Limited` |
| Subject | Same as the issuer |
| Validity | Feb 18 18:30:00 2018 GMT to Feb 18 18:30:00 2043 GMT |
| Certificate Transparency | First entry 2019-09-05, in a Sectigo log |

The "Download Certificate: PEM" link on that page gives crt.sh's own copy of the certificate. Its fingerprint, worked out locally, is the same as the one from `c-044`.

```bash
curl -sS -o crtsh.pem 'https://crt.sh/?d=713604941'
openssl x509 -in crtsh.pem -noout -fingerprint -sha256
```

```text
sha256 Fingerprint=86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04:3C:F9:E8:A8:62:CD:5C:57:A3:6B:BE:6B
```

The page's Revocation table reads "Not Revoked" for every source it checks. Root removals do not appear in that table.

## Step 8. Find the root in Mozilla's root list

Mozilla publishes the roots it trusts in a file called `certdata.txt`. Debian's `ca-certificates` package carries a copy, and the project cites the one in Debian 12's package version `20230311+deb12u1`, from before the removal. An entry there shows the hash belongs to a root that Mozilla checked and trusted.

The page to read in a browser is:

```text
https://sources.debian.org/src/ca-certificates/20230311%2Bdeb12u1/mozilla/certdata.txt/
```

A search on that page for `emSign ECC Root CA - G3` finds the entry at line 16688. The same file can be downloaded as plain text:

```bash
curl -sS -o certdata.txt 'https://sources.debian.org/data/main/c/ca-certificates/20230311%2Bdeb12u1/mozilla/certdata.txt'
grep -n -A7 '^# Certificate "emSign ECC Root CA - G3"' certdata.txt
```

```text
16688:# Certificate "emSign ECC Root CA - G3"
16689-#
16690-# Issuer: CN=emSign ECC Root CA - G3,O=eMudhra Technologies Limited,OU=emSign PKI,C=IN
16691-# Serial Number:3c:f6:07:a9:68:70:0e:da:8b:84
16692-# Subject: CN=emSign ECC Root CA - G3,O=eMudhra Technologies Limited,OU=emSign PKI,C=IN
16693-# Not Valid Before: Sun Feb 18 18:30:00 2018
16694-# Not Valid After : Wed Feb 18 18:30:00 2043
16695-# Fingerprint (SHA-256): 86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04:3C:F9:E8:A8:62:CD:5C:57:A3:6B:BE:6B
```

The label, serial number and SHA-256 fingerprint are the same as in steps 5 and 6. A second record further down the file sets what Mozilla trusted the root to do:

```bash
awk '/^# Trust for "emSign ECC Root CA - G3"/,/TRUST_SERVER_AUTH/' certdata.txt | grep -E '^# Trust for|^# Fingerprint \(SHA-256\)|SERVER_AUTH'
```

```text
# Trust for "emSign ECC Root CA - G3"
# Fingerprint (SHA-256): 86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04:3C:F9:E8:A8:62:CD:5C:57:A3:6B:BE:6B
CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_TRUSTED_DELEGATOR
```

`CKT_NSS_TRUSTED_DELEGATOR` on the `CKA_TRUST_SERVER_AUTH` line means Mozilla trusted the root to issue certificates for websites.

## The same check in a Java keystore

Java keeps its trusted roots in a keystore file, `cacerts`, and `keytool -list` prints the SHA-256 fingerprint of each entry. `changeit` is the default password of that keystore. This output is from the `eclipse-temurin:21.0.8_9-jre` image, a Java runtime released before the fix, run in a container:

```bash
keytool -list -cacerts -storepass changeit | grep -i -A1 'emsign_ecc_root_ca__g3'
```

```text
cn_emsign_ecc_root_ca__g3,o_emudhra_technologies_limited,ou_emsign_pki,c_in [jdk], Nov 3, 2026, trustedCertEntry, 
Certificate fingerprint (SHA-256): 86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04:3C:F9:E8:A8:62:CD:5C:57:A3:6B:BE:6B
```

Step 5's comparison applies to this fingerprint unchanged.

## Result

- **Finding:** the hash on the project's list is the fingerprint of a real eMudhra root that Mozilla trusted.
- **Bundle:** `/etc/ssl/cert.pem` holds a self-signed certificate named `emSign ECC Root CA - G3`.
  - Its SHA-256 fingerprint is `86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B`.
- **List:** all 64 digits of the fingerprint match line 18 of `rules/iocs.csv`.
- **crt.sh:** crt.sh holds the same certificate under ID 713604941.
- **Mozilla:** Mozilla's root list in Debian's 2023 package names the same fingerprint as a root trusted for websites.

Each claim in Flow A rests on one of these original sources:

| Claim | Step | Source and what to look for |
|---|---|---|
| The project's list names the G3 root | Step 5 | [`rules/iocs.csv` at release `v2.0.0`](https://raw.githubusercontent.com/fieldse/emudhra-ca-compromise-check/v2.0.0/rules/iocs.csv). Line 18, `sha256` column: `86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B` |
| crt.sh holds the G3 root | Step 7 | [crt.sh search for the root's SHA-256](https://crt.sh/?sha256=86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B). crt.sh ID `713604941` and Serial Number `3c:f6:07:a9:68:70:0e:da:8b:84` |
| Mozilla trusted the G3 root for websites, in Debian 12's copy of its root list | Step 8 | [`certdata.txt` in Debian's `ca-certificates` 20230311+deb12u1](https://sources.debian.org/src/ca-certificates/20230311%2Bdeb12u1/mozilla/certdata.txt/). `# Certificate "emSign ECC Root CA - G3"` at line 16688, and `CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_TRUSTED_DELEGATOR` in the root's trust record |

[Flow B](proof-b.html) shows why that root is no longer trusted.

:::

<footer>
  <div class="wrap"><p>eMudhra G3 intermediate CA key compromise, October 2026. An independent guide, not affiliated with eMudhra or Sectigo.</p><p>Last updated 2026-11-05. <a href="https://github.com/fieldse/emudhra-ca-compromise-check">Source on GitHub</a>.</p></div>
</footer>
