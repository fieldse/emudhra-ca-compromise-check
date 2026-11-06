---
title: eMudhra G3 CA compromise: verify a finding
description: How to verify a finding from the eMudhra G3 CA compromise checker yourself, from the original sources, with a shell, openssl, curl and a browser.
output: proof.html
refs: inline
anchors: auto
---

<header class="band">
  <div class="wrap">
    <a class="back" href="index.html">← Back to the guide</a>
    <p class="tags"><span>eMudhra G3</span><span>CA key compromise</span><span>October 2026</span></p>
    <p class="ids"><a href="index.html">Guide</a> &nbsp;·&nbsp; <a href="incident.html">Incident</a> &nbsp;·&nbsp; <a href="checks.html">Affected software</a> &nbsp;·&nbsp; <a href="fixes.html">Fixes</a> &nbsp;·&nbsp; <a href="detections.html">Checker rules</a> &nbsp;·&nbsp; Proof &nbsp;·&nbsp; <a href="references.html">References</a></p>
    <h1><span class='hl'>eMudhra G3</span> CA compromise<br>Verify a finding</h1>
    <p>How to check the checker’s findings yourself, from the original sources. Find your output line in the table below, then follow its steps with a shell, <code>openssl</code>, <code>curl</code> and a browser.</p>
  </div>
</header>

::: {tag=main .wrap}

<nav class="toc read" aria-label="Contents"><h2>Contents</h2><ol>
  <li><a href="#about">About this page</a><span>What it is, when to use it and how</span></li>
  <li><a href="#find-your-finding">Find your finding</a><span>Which flow verifies your output line</span></li>
  <li><a href="#flows">Verification flows</a><span>What a flow is, and one page for each</span></li>
  <li><a href="#setup">Setup</a><span>The tools every flow needs</span></li>
  <li><a href="#method">How the rules were checked</a><span>Two reviews per rule, and the test that checks the register against the code</span></li>
  <li><a href="#limitations">Limitations</a><span>The rules no source fully backs</span></li>
  <li><a href="#reporting">Reporting mistakes</a><span>How to report a wrong rule</span></li>
</ol></nav>

## About this page {#about}

{: .key}
**This page shows how to confirm a checker finding yourself, by hand, from its original sources.**

The checker reports a `FAIL` or `WARN` from rules in this repository. Each flow on this page takes one kind of output line and rebuilds the evidence behind it from primary artifacts, such as published certificates, root program lists, security advisories and release notes.

Use it when:

{: .notes}
- **You are about to act on a finding.** Confirm it before you upgrade, remove a root or open a ticket.
- **You doubt a result.** A flow shows whether the rule behind it matches its source.
- **You want to audit the checker.** The flows show which sources the rules rest on and how to read them.

To use it:

1. Find your output line in [Find your finding](#find-your-finding).
2. Check [Setup](#setup) for the tools the flow needs.
3. Follow the flow’s page step by step. Each ends with a Result and a table of the sources it used.

## Find your finding

{: .key}
**Find the row that matches your output line, then follow the steps it names.**

Match on the words before the brackets and the words after them. For example, `FAIL  os trust store [/etc/ssl/cert.pem] contains emSign ECC Root CA - G3 (removed root)` matches the first row.

| Subject | Detail | Verify with |
|---|---|---|
| `os trust store` or `ca-bundle` | `contains emSign ECC Root CA - G3 (removed root)` | [Flow A](proof-a.html), then [Flow B steps 10 to 12](proof-b.html#step-10-find-the-roots-removal-from-mozillas-list) for why the root is untrusted |
| `os trust store` or `ca-bundle` | `contains EM DV TLS CA - G3B (compromised key)` or `contains EM DV TLS CA - G3B, Sectigo cross-sign (compromised key)` | [Flow B](proof-b.html). Flow A steps 1 to 6 find the certificate in the bundle, with line 2 or 3 of `rules/iocs.csv` in place of line 18 |
| `os trust store` or `ca-bundle` | `contains` another certificate | Flow A steps 1 to 6, with that certificate's line of `rules/iocs.csv` in place of line 18 |
| `java keystore` | `contains emSign ECC Root CA - G3 (removed root)` | [The same check in a Java keystore](proof-a.html#the-same-check-in-a-java-keystore), at the end of Flow A |
| `go` | `found <version>, fixed <version> (CVE-2026-111943, rebuild binaries after upgrading)` | [Flow C](proof-c.html), steps 1 to 8 |
| `webpki-roots`, with a `Cargo.lock` path | `found <version>, fixed 1.0.10` | [The same trace for a version in Cargo.lock](proof-c.html#the-same-trace-for-a-version-in-cargolock), at the end of Flow C |
| `uv`, with a binary path | `contains the public key of emSign ECC Root CA - G3 (removed root) as a trust anchor` | [Flow D](proof-d.html), steps 1 to 7 |
| `uv`, with `host uv` | `found <version>, fixed 0.13.4 (vendors its own CA bundle)` | [Flow D step 9](proof-d.html#step-9-check-the-uv-version-against-its-advisory) |
| `bun`, with `host` | `found <version>, fixed 1.4.4` | [Flow D step 10](proof-d.html#step-10-check-the-bun-version-against-its-release) |
| `bun` or `uv`, with a binary path | `contains no compromised eMudhra certificate` | [Flow D steps 4](proof-d.html#step-4-search-for-the-full-certificate) and 5 |
| `bun` or `uv`, with a binary path | `contains` a certificate name | Flow D steps 3 and 4, then [step 8](proof-d.html#step-8-cut-a-full-certificate-out-of-a-test-file) on the binary in place of `control.bin` to cut the certificate out and fingerprint it |
| Anything else, such as Node, pip, certifi, Electron, an rpm package or a JDK | Any detail | The item's card on the [Affected software page](checks.html). Its Sources line gives R-numbers, and each R-number is a source on the [references page](references.html) |

## Verification flows {#flows}

{: .key}
**A flow is a step-by-step check of one kind of finding, done by hand.**

{: .read}
Pick the flow that [Find your finding](#find-your-finding) names for your line.

<ul class="resources">
  <li><a href="proof-a.html">Flow A: a certificate in a bundle</a><span>Find a certificate in a CA bundle or Java keystore, and confirm it is the one on the project’s list.</span></li>
  <li><a href="proof-b.html">Flow B: why a certificate is untrusted</a><span>Recompute the weak key, and confirm Mozilla, Chrome and Apple removed or blocked the root above it.</span></li>
  <li><a href="proof-c.html">Flow C: a version below a fix</a><span>Trace a Go or Rust version from its security advisory to the fix in the source.</span></li>
  <li><a href="proof-d.html">Flow D: a certificate inside a binary</a><span>Find the removed root compiled into a uv binary, and show Bun 1.4.4 holds neither its key nor its name.</span></li>
</ul>

## Setup {#setup}

{: .key}
**You need a shell, `openssl`, `curl` and a browser. Flow C also needs `go`, Flow D needs `xxd`, `uv` and `bun`, and the Java keystore check in Flow A needs Java or a container.**

Run each flow in a new empty directory. Its output blocks are pasted from a real run. Each source in a Result table also links an archived copy on the Wayback Machine, where one exists.

## How the rules were checked {#method}

{: .key}
**LLM agents reviewed every rule twice against its sources on 2 November 2026. A rule counts as verified only when both reviews agree.**

Every rule the checker applies is a row in `rules/detection-rules.csv`, with its code line and its sources. The [Checker rules page](detections.html) shows them all. The two reviews ran separately:

- One opened the rule's own sources and quoted the line that backs it.
- The other treated the rule as wrong and tried to disprove it from sources it found itself.

When the reviews disagree, the rule takes the worse result. The reviews found 16 rules that a source contradicted. All 16 were fixed in the code, and the register now marks none as wrong. `tests/unit/test_register.py` fails if a rule's value, level or code line stops matching the code.

## Limitations {#limitations}

{: .key}
**70 of the checker's 186 rules rest partly or wholly on the project's own judgement. If your finding comes from one of them, check it by hand before you act on it.**

Each rule has one of four statuses:

- **Verified (116):** a primary source backs the whole rule.
- **Weak decision (58):** a choice the project made that no outside source can settle. For example, a version the checker can't compare gets `WARN` and a manual check.
- **Weak fact (10):** a source backs most of the rule, but not all of it. For example, Arch publishes no advisory, so its fixed version rests on the NSS release note.
- **Unverifiable (2):** a design rule with no primary source at all.
  - `PY-CPY-08`: the checker never runs the macOS `/usr/bin/python3` stub, and Apple doesn't document how the stub behaves.
  - `LK-POD-04`: the checker judges a container image's `ca-certificates` package by the distro its `os-release` file names.

[weak-rules.md](https://github.com/fieldse/emudhra-ca-compromise-check/blob/main/docs/weak-rules.md) lists every weak and unverifiable rule, with the reason for each. The [Checker rules page](detections.html) tags each weak and unverifiable rule in its table.

## Reporting mistakes {#reporting}

{: .key}
**[Open an issue](https://github.com/fieldse/emudhra-ca-compromise-check/issues/new) for any rule a source contradicts. Give the rule ID, the source's URL and the line that disagrees.**

Rule IDs, such as `RT-GO-06`, are on the [Checker rules page](detections.html) and in the `id` column of `rules/detection-rules.csv`.

:::


<footer>
  <div class="wrap"><p>eMudhra G3 intermediate CA key compromise, October 2026. An independent guide, not affiliated with eMudhra or Sectigo.</p><p>Last updated 2026-11-05. <a href="https://github.com/fieldse/emudhra-ca-compromise-check">Source on GitHub</a>.</p></div>
</footer>
