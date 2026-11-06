---
title: eMudhra G3 CA compromise: Flow D, a certificate inside a binary
description: Flow D of verifying an eMudhra G3 checker finding by hand: find the removed root compiled into a uv binary, and show bun 1.4.4 holds neither its key nor its name.
output: proof-d.html
refs: inline
anchors: auto
---

<header class="band">
  <div class="wrap">
    <a class="back" href="proof.html">← Back to verifying a finding</a>
    <p class="tags"><span>eMudhra G3</span><span>CA key compromise</span><span>October 2026</span></p>
    <p class="ids"><a href="index.html">Guide</a> &nbsp;·&nbsp; <a href="incident.html">Incident</a> &nbsp;·&nbsp; <a href="checks.html">Affected software</a> &nbsp;·&nbsp; <a href="fixes.html">Fixes</a> &nbsp;·&nbsp; <a href="detections.html">Checker rules</a> &nbsp;·&nbsp; <a href="proof.html">Proof</a> &nbsp;·&nbsp; <a href="references.html">References</a></p>
    <h1><span class='hl'>Flow D</span><br>A certificate inside a binary</h1>
    <p>One of four flows for <a href="proof.html">verifying a finding</a> by hand, from the original sources. Find the removed root compiled into a uv binary, and show Bun 1.4.4 holds neither its key nor its name.</p>
  </div>
</header>

::: {tag=main .wrap}

<nav class="toc read" aria-label="Contents"><h2>Contents</h2><ol>
  <li><a href="#about">About this flow</a><span>What it checks and why</span></li>
  <li><a href="#step-1-make-an-empty-work-directory">Step 1. Make an empty work directory</a></li>
  <li><a href="#step-2-get-the-root-certificate">Step 2. Get the root certificate</a></li>
  <li><a href="#step-3-write-each-binary-out-as-hex">Step 3. Write each binary out as hex</a></li>
  <li><a href="#step-4-search-for-the-full-certificate">Step 4. Search for the full certificate</a></li>
  <li><a href="#step-5-search-for-the-roots-public-key">Step 5. Search for the root's public key</a></li>
  <li><a href="#step-6-cut-the-key-out-of-uv-and-compare-it">Step 6. Cut the key out of uv and compare it</a></li>
  <li><a href="#step-7-read-the-name-stored-before-the-key">Step 7. Read the name stored before the key</a></li>
  <li><a href="#step-8-cut-a-full-certificate-out-of-a-test-file">Step 8. Cut a full certificate out of a test file</a></li>
  <li><a href="#step-9-check-the-uv-version-against-its-advisory">Step 9. Check the uv version against its advisory</a></li>
  <li><a href="#step-10-check-the-bun-version-against-its-release">Step 10. Check the Bun version against its release</a></li>
  <li><a href="#result">Result</a></li>
</ol></nav>

## About this flow {#about}

{: .key}
**Flow D checks one `FAIL` line for a binary by reading the binary as data. It finds the removed root's public key and name inside `uv` 0.10.10, matches them to the certificate `rules/iocs.csv` names, and shows that Bun 1.4.4 holds neither. The only commands that run either binary are `uv --version` and `bun --version`.**

{: .read}
The check reaches its verdict from rules in this repository. These steps rebuild the evidence for one finding from primary artifacts, so you can confirm it without trusting the checker. [Setup](proof.html#setup) lists the tools this flow needs.

- A binary is an application's program file.
- `uv`, a Python package manager, and `bun`, a JavaScript runtime, each carry their own list of trusted roots inside the binary.
- Neither binary on this machine holds the full certificate. Step 8 runs the full-certificate search on a test file that does.

### The line being checked

On a Mac with uv 0.10.10 and Bun 1.4.4 the check printed these lines:

```text
PASS  bun [host] found 1.4.4, fixed 1.4.4
PASS  bun [/opt/homebrew/Cellar/bun/1.4.4/bin/bun] contains no compromised eMudhra certificate
FAIL  uv [host uv] found 0.10.10, fixed 0.13.4 (vendors its own CA bundle)
FAIL  uv [~/.local/bin/uv] contains the public key of emSign ECC Root CA - G3 (removed root) as a trust anchor
```

The flow checks the last line.

- It means the `uv` binary holds the public key of `emSign ECC Root CA - G3`, the root from [Flow A](proof-a.html).
- A trust anchor is a key software trusts without checking any certificate above it. uv stores each root this way, as its name and public key without the rest of the certificate.
- uv trusts any certificate that chains to this one.
- The check looks for a bare key only when no full certificate matched. [How it works](https://github.com/fieldse/emudhra-ca-compromise-check/blob/main/docs/how-it-works.md) lists the four ways it matches.

### What the steps do

- **Steps 1 and 2:** make a work directory, get the root certificate and compare its SHA-256 fingerprint with the project's list.
- **Steps 3 and 4:** search both binaries for the full certificate, the two ways the check does.
- **Step 5:** search both binaries for the root's public key.
- **Steps 6 and 7:** cut the key and the name out of uv and compare them with the certificate and the list.
- **Step 8:** append the certificate to a copy of a harmless file, then find it, cut it out and fingerprint it.
- **Steps 9 and 10:** compare each version with the first fixed release named by uv's advisory and Bun's release notes.

Byte offsets depend on the build of each binary. The test file's offset depends on the size of the file it copies.

## Step 1. Make an empty work directory

`mktemp -d` makes a new empty directory. Step 3 writes a hex copy of each binary into it, about twice the binary's size.

```bash
cd "$(mktemp -d)"
ls -A | wc -l
```

```text
       0
```

## Step 2. Get the root certificate

This is the same certificate and the same comparison as Flow A steps 5 and 7. crt.sh gives the certificate, and line 18 of `rules/iocs.csv` gives its hash.

```bash
curl -sS -o iocs.csv https://raw.githubusercontent.com/fieldse/emudhra-ca-compromise-check/v2.0.0/rules/iocs.csv
curl -sS -o root.pem 'https://crt.sh/?d=713604941'
a=$(openssl x509 -in root.pem -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'a-f' 'A-F')
b=$(sed -n 18p iocs.csv | cut -d, -f5)
echo "$b"
[ "$a" = "$b" ] && echo match || echo differ
```

```text
86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B
match
```

The check searches a binary for two forms of the certificate:

- **DER bytes:** the certificate's raw binary form, which `root.der` holds.
- **First base64 line:** the first 64 characters of the PEM text, line 2 of `root.pem`, for a binary that stores the PEM text.

`root.hex` holds the DER bytes as hex digits, for the search in step 4.

```bash
openssl x509 -in root.pem -outform der -out root.der
xxd -p root.der | tr -d '\n' > root.hex
sed -n 2p root.pem > line.txt
wc -c < root.der
cat line.txt
```

```text
     594
MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG
```

## Step 3. Write each binary out as hex

`grep` searches text, and the macOS `grep` cannot search for raw bytes. `xxd -p` writes each byte as two hex digits, and `tr -d '\n'` joins the result into one line that `grep` can search for a hex string.

```bash
xxd -p "$(command -v uv)" | tr -d '\n' > uv.hex
xxd -p "$(command -v bun)" | tr -d '\n' > bun.hex
```

Both commands read the binaries as files and print nothing.

## Step 4. Search for the full certificate

The loop counts matches of the DER bytes in each hex copy and of the first base64 line in each binary.

```bash
for t in uv bun; do
  echo "$t DER: $(grep -c -F "$(cat root.hex)" $t.hex)  base64 line: $(grep -c -F "$(cat line.txt)" "$(command -v $t)")"
done
```

```text
uv DER: 0  base64 line: 0
bun DER: 0  base64 line: 0
```

Neither binary holds the full certificate in either form.

## Step 5. Search for the root's public key

The public key is stored in a certificate as its subject public key info (SPKI), a DER structure that names the key type and holds the key. `openssl pkey` writes it out on its own.

```bash
openssl x509 -in root.pem -noout -pubkey | openssl pkey -pubin -outform der -out key.der
wc -c < key.der
xxd -l 2 key.der
```

```text
     120
00000000: 3076                                     0v
```

The first two bytes are its DER header:

- `30` marks a SEQUENCE.
- `76` is the length of what follows, 118 bytes.

uv's root list stores the 118 bytes without the header, and the check searches for the same 118 bytes. `tail -c +3` drops the header.

```bash
tail -c +3 key.der | xxd -p | tr -d '\n' > key.hex
grep -c -F "$(cat key.hex)" bun.hex
grep -o -b -F "$(cat key.hex)" uv.hex | cut -d: -f1
```

```text
0
72766028
```

- Bun 1.4.4 does not hold the key.
- In uv the match starts at hex digit 72766028. Two digits make one byte, so the key starts at byte 36383014.
- A match at an odd digit would straddle two bytes and would not count.

## Step 6. Cut the key out of uv and compare it

`dd` copies the 118 bytes at that offset. `printf '\060\166'` writes the two header bytes `30 76` in front, which makes a standard key file.

```bash
off=$((72766028 / 2))
echo $off
dd if="$(command -v uv)" of=carved-key.bin bs=1 skip=$off count=118 2>/dev/null
{ printf '\060\166'; cat carved-key.bin; } > carved-key.der
cmp carved-key.der key.der && echo same
openssl pkey -pubin -inform der -in carved-key.der -noout -text | sed -n '1p;$p'
```

```text
36383014
same
Public-Key: (384 bit)
NIST CURVE: P-384
```

- `cmp` finds no difference between the key cut from uv and the key in the certificate from crt.sh.
- `openssl` reads the cut bytes as a P-384 public key.
- `2>/dev/null` hides the record counts `dd` prints.

The project's list also identifies the key directly. Its seventh column, `subject_key_identifier`, is the SHA-1 hash of the key's last 97 bytes. Those bytes are the key value, without the fields that name the key type.

```bash
tail -c 97 carved-key.bin | openssl dgst -sha1 -r | cut -c1-40 | tr 'a-f' 'A-F'
sed -n 18p iocs.csv | cut -d, -f7
```

```text
7C5D028413D4CC8A9B81CE171C2E291E9C486342
7C5D028413D4CC8A9B81CE171C2E291E9C486342
```

## Step 7. Read the name stored before the key

A trust anchor pairs the key with the root's name. In uv the name sits in the 107 bytes just before the key.

`openssl asn1parse` shows the certificate's subject name at byte 178, with a 2-byte header and 107 bytes of content. The commands cut the 107 bytes from the certificate and from uv and compare them.

```bash
openssl asn1parse -in root.pem | grep '^ *178:'
dd if=root.der of=name-cert.bin bs=1 skip=180 count=107 2>/dev/null
dd if="$(command -v uv)" of=name-uv.bin bs=1 skip=$((off - 107)) count=107 2>/dev/null
cmp name-cert.bin name-uv.bin && echo same
tr -c '[:print:]' '.' < name-uv.bin; echo
```

```text
  178:d=2  hl=2 l= 107 cons: SEQUENCE          
same
1.0...U....IN1.0...U....emSign PKI1%0#..U....eMudhra Technologies Limited1 0...U....emSign ECC Root CA - G3
```

The last command prints the name with each non-text byte shown as a dot. uv holds the name and key of `emSign ECC Root CA - G3` next to each other.

## Step 8. Cut a full certificate out of a test file

Neither binary holds the full certificate, so this step builds a test file that does. It appends the certificate's DER bytes to a copy of `/bin/ls`, then runs the search from step 4 on it.

```bash
cp /bin/ls control.bin
wc -c < control.bin
cat root.der >> control.bin
xxd -p control.bin | tr -d '\n' > control.hex
grep -o -b -F "$(cat root.hex)" control.hex | cut -d: -f1
```

```text
  154208
308416
```

The match starts at hex digit 308416, which is byte 154208. That is the size of the copy before the append. The certificate's first four bytes give its length.

```bash
coff=$((308416 / 2))
echo $coff
xxd -s $coff -l 4 control.bin
```

```text
154208
00025a60: 3082 024e                                0..N
```

- `30` marks a SEQUENCE.
- `82` means the length is in the next two bytes.
- `02 4e` is 590.

The certificate is the 4 header bytes plus 590, 594 bytes in all. `dd` cuts them out, and `openssl` fingerprints the cut bytes.

```bash
len=$((4 + 0x024e))
echo $len
dd if=control.bin of=carved.der bs=1 skip=$coff count=$len 2>/dev/null
a=$(openssl x509 -inform der -in carved.der -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'a-f' 'A-F')
echo "$a"
[ "$a" = "$(sed -n 18p iocs.csv | cut -d, -f5)" ] && echo match || echo differ
```

```text
594
86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B
match
```

The search from step 4 finds the certificate when a file holds it, and `dd` cuts it out. The same search found nothing in uv or Bun.

## Step 9. Check the uv version against its advisory

uv's advisory on GitHub, GHSA-hq85-5cpj-mr62, gives the affected range and the first fixed release.

```bash
uv --version
curl -sS https://api.github.com/advisories/GHSA-hq85-5cpj-mr62 | grep -E '"(summary|vulnerable_version_range|first_patched_version)"'
```

```text
uv 0.10.10 (8c730aaad 2026-03-13)
  "summary": "uv's bundled CA store trusts an emSign root whose intermediate CA keys are compromised",
      "vulnerable_version_range": "< 0.13.4",
      "first_patched_version": "0.13.4",
```

uv 0.10.10 is below 0.13.4, so the root found in steps 5 to 7 is the one the advisory describes.

The advisory says uv checks TLS against `webpki-root-certs`, a Rust crate of full certificates. uv 0.10.10 locks `webpki-roots` 1.0.2 instead, a crate that stores each root as a `TrustAnchor` of name and key, so steps 4 and 5 found the key without the full certificate.

```bash
curl -sS https://raw.githubusercontent.com/astral-sh/uv/0.10.10/Cargo.lock | grep -A1 '^name = "webpki-roots"'
curl -sS https://raw.githubusercontent.com/rustls/webpki-roots/v/1.0.2/webpki-roots/src/lib.rs | grep -A24 'Label: "emSign ECC Root CA - G3"' | grep -o -E '^ *(TrustAnchor|subject|subject_public_key_info|name_constraints)\b[^(]*'
```

```text
name = "webpki-roots"
version = "1.0.2"
  TrustAnchor {
    subject: Der::from_slice
    subject_public_key_info: Der::from_slice
    name_constraints: None
```

## Step 10. Check the Bun version against its release

Bun's release notes for 1.4.4 say it updates its root certificates to NSS 3.131.1, the Mozilla release that removed the root ([Flow B](proof-b.html)). Bun's own root list holds the root at `bun-v1.4.3` and not at `bun-v1.4.4`.

```bash
bun --version
curl -sS https://bun.com/blog/bun-v1.4.4 | grep -o 'root certificates are[^<"]*' | sort -u
for t in bun-v1.4.3 bun-v1.4.4; do
  echo "$t $(curl -sS https://raw.githubusercontent.com/oven-sh/bun/$t/packages/bun-usockets/root_certs.txt | grep -c 'emSign ECC Root CA - G3')"
done
```

```text
1.4.4
root certificates are updated to NSS 3.131.1.
bun-v1.4.3 1
bun-v1.4.4 0
```

Bun 1.4.4 is the first release without the root, which matches the zero counts in steps 4 and 5.

## Result

- **uv key:** the uv 0.10.10 binary holds the public key of `emSign ECC Root CA - G3` at byte 36383014.
  - The root's name is in the 107 bytes before it.
  - The key is identical to the one in crt.sh's copy of the certificate.
  - Its SHA-1 matches the `subject_key_identifier` on line 18 of `rules/iocs.csv`.
- **Full certificate:** the uv binary does not hold it, because uv 0.10.10 stores its roots as name and key.
- **Control:** the same search finds the full certificate in a test file that holds it, and `dd` cuts it out.
- **uv version:** 0.10.10 is below 0.13.4, the first fixed release in uv's advisory.
- **Bun:** Bun 1.4.4 holds neither the certificate nor the key.
  - It is Bun's first release without the root.

Each claim in Flow D rests on one of these original sources:

| Claim | Step | Source and what to look for |
|---|---|---|
| The project's list names the G3 root | Step 2 | [`rules/iocs.csv` at release `v2.0.0`](https://raw.githubusercontent.com/fieldse/emudhra-ca-compromise-check/v2.0.0/rules/iocs.csv). Line 18, `sha256` column: `86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B` |
| uv below 0.13.4 trusts the G3 root | Step 9 | [GHSA-hq85-5cpj-mr62](https://github.com/advisories/GHSA-hq85-5cpj-mr62). Affected versions `< 0.13.4`, patched version `0.13.4` |
| uv 0.10.10 locks `webpki-roots` 1.0.2 | Step 9 | [uv's `Cargo.lock` at tag `0.10.10`](https://raw.githubusercontent.com/astral-sh/uv/0.10.10/Cargo.lock). `name = "webpki-roots"` followed by `version = "1.0.2"` |
| `webpki-roots` 1.0.2 stores the G3 root as a name and a key | Step 9 | [`webpki-roots/src/lib.rs` at tag `v/1.0.2`](https://raw.githubusercontent.com/rustls/webpki-roots/v/1.0.2/webpki-roots/src/lib.rs). `Label: "emSign ECC Root CA - G3"`, followed by `TrustAnchor {` with `subject` and `subject_public_key_info` |
| Bun 1.4.4 updates its roots to NSS 3.131.1 | Step 10 | [Bun v1.4.4 release post](https://bun.com/blog/bun-v1.4.4). "root certificates are updated to NSS 3.131.1." [Archived copy](https://web.archive.org/web/20261027045112/https://bun.com/blog/bun-v1.4.4) |
| Bun's root list holds the G3 root at `bun-v1.4.3` | Step 10 | [`root_certs.txt` at tag `bun-v1.4.3`](https://raw.githubusercontent.com/oven-sh/bun/bun-v1.4.3/packages/bun-usockets/root_certs.txt). `emSign ECC Root CA - G3` |
| Bun's root list drops the G3 root at `bun-v1.4.4` | Step 10 | [`root_certs.txt` at tag `bun-v1.4.4`](https://raw.githubusercontent.com/oven-sh/bun/bun-v1.4.4/packages/bun-usockets/root_certs.txt). No `emSign ECC Root CA - G3` |

:::

<footer>
  <div class="wrap"><p>eMudhra G3 intermediate CA key compromise, October 2026. An independent guide, not affiliated with eMudhra or Sectigo.</p><p>Last updated 2026-11-05. <a href="https://github.com/fieldse/emudhra-ca-compromise-check">Source on GitHub</a>.</p></div>
</footer>
