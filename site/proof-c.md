---
title: eMudhra G3 CA compromise: Flow C, a version below a fix
description: Flow C of verifying an eMudhra G3 checker finding by hand: trace a go or rust version from its security advisory to the fix in the source.
output: proof-c.html
refs: inline
anchors: auto
---

<header class="band">
  <div class="wrap">
    <a class="back" href="proof.html">← Back to verifying a finding</a>
    <p class="tags"><span>eMudhra G3</span><span>CA key compromise</span><span>October 2026</span></p>
    <p class="ids"><a href="index.html">Guide</a> &nbsp;·&nbsp; <a href="incident.html">Incident</a> &nbsp;·&nbsp; <a href="checks.html">Affected software</a> &nbsp;·&nbsp; <a href="fixes.html">Fixes</a> &nbsp;·&nbsp; <a href="detections.html">Checker rules</a> &nbsp;·&nbsp; <a href="proof.html">Proof</a> &nbsp;·&nbsp; <a href="references.html">References</a></p>
    <h1><span class='hl'>Flow C</span><br>A version below a fix</h1>
    <p>One of four flows for <a href="proof.html">verifying a finding</a> by hand, from the original sources. Trace a Go or Rust version from its security advisory to the fix in the source.</p>
  </div>
</header>

::: {tag=main .wrap}

<nav class="toc read" aria-label="Contents"><h2>Contents</h2><ol>
  <li><a href="#about">About this flow</a><span>What it checks and why</span></li>
  <li><a href="#step-1-make-an-empty-work-directory">Step 1. Make an empty work directory</a></li>
  <li><a href="#step-2-read-the-installed-go-version">Step 2. Read the installed Go version</a></li>
  <li><a href="#step-3-read-the-version-recorded-in-a-go-binary">Step 3. Read the version recorded in a Go binary</a></li>
  <li><a href="#step-4-read-gos-vulnerability-entry">Step 4. Read Go's vulnerability entry</a></li>
  <li><a href="#step-5-read-the-cve-record">Step 5. Read the CVE record</a></li>
  <li><a href="#step-6-read-gos-release-history">Step 6. Read Go's release history</a></li>
  <li><a href="#step-7-find-the-fix-in-gos-source-code">Step 7. Find the fix in Go's source code</a></li>
  <li><a href="#step-8-compare-the-versions">Step 8. Compare the versions</a></li>
  <li><a href="#the-same-trace-for-a-version-in-cargolock">The same trace for a version in Cargo.lock</a></li>
  <li><a href="#result">Result</a></li>
</ol></nav>

## About this flow {#about}

{: .key}
**Flow C checks a version rule by tracing the fixed version from its security advisory to the version recorded in the software. It does not run the check.** A version rule states the first release that carries a fix.

{: .read}
The check reaches its verdict from rules in this repository. These steps rebuild the evidence for one finding from primary artifacts, so you can confirm it without trusting the checker. [Setup](proof.html#setup) lists the tools this flow needs.

- **Example:** the Go toolchain on a Mac, Go 1.27.1, below the fix in Go 1.27.3.
- **Trace:** from Go's vulnerability entry, its CVE record, its release history and its source code to the fixed release, and from the `go` binary to the toolchain version recorded in it.
- **Lockfiles:** a dependency pinned in a lockfile, such as `webpki-roots` in `Cargo.lock`, is checked the same way, from its advisory to the version the lockfile names.

### The line being checked

On a Mac with Go 1.27.1 installed from Homebrew, the check printed this line:

```text
FAIL  go [host] found 1.27.1, fixed 1.27.3 (CVE-2026-111943, rebuild binaries after upgrading)
```

- `go [host]` is the `go` command on `PATH`.
- `found 1.27.1` is the version `go version` prints.
- `fixed 1.27.3` is the first 1.27 release with Go's fix for CVE-2026-111943.
- A Go program carries the standard library it was built with. A program built with Go 1.27.1 keeps the unfixed code after the toolchain is upgraded, so the note asks for a rebuild.

### What the steps do

- **Steps 1 to 3:** read the Go version on the machine, from the `go` command and from the build record inside the `go` binary.
- **Steps 4 to 7:** trace the fix through four primary artifacts: Go's vulnerability entry, the CVE record, Go's release history and Go's source code.
- **Step 8:** compare the machine's version with the fix, and with the value in `emudhra_check/fixes.py`.
- **Cargo.lock:** run the same trace for `webpki-roots`, from its advisory to a version pinned in a hand-written lockfile.

The versions in steps 2 and 3 depend on the machine.

## Step 1. Make an empty work directory

`mktemp -d` makes a new empty directory. `GOTOOLCHAIN=local` makes `go` use the installed toolchain and never download another one.

```bash
cd "$(mktemp -d)"
export GOTOOLCHAIN=local
ls -A | wc -l
```

```text
       0
```

## Step 2. Read the installed Go version

```bash
go version
```

```text
go version go1.27.1 darwin/arm64
```

`go1.27.1` is the toolchain version. `darwin/arm64` is the operating system and processor.

## Step 3. Read the version recorded in a Go binary

Go writes a build record into every program it builds, and the first line names the toolchain that built it. `go version -m` reads the record from the file without running the program. The `go` command is itself a Go program, so its own file is the example.

```bash
go version -m "$(go env GOROOT)/bin/go" | head -n 4
```

```text
/opt/homebrew/Cellar/go/1.27.1/libexec/bin/go: go1.27.1
	path	cmd/go
	build	-buildmode=exe
	build	-compiler=gc
```

`go env GOROOT` prints where the toolchain is installed. The record names Go 1.27.1, the same version as step 2.

`go list -deps` lists every package a program is built from. `crypto/x509`, the package the fix changes, is one of the packages in the `go` command:

```bash
go list -deps cmd/go | grep -x crypto/x509
```

```text
crypto/x509
```

A program whose list has no `crypto/x509` does not contain the code the fix changes.

## Step 4. Read Go's vulnerability entry

Go publishes its vulnerabilities in its own database. The entry for this fix is GO-2026-6809, shown in a browser at [pkg.go.dev/vuln/GO-2026-6809](https://pkg.go.dev/vuln/GO-2026-6809). The machine-readable record is one long line of JSON, so `grep -o` prints only the three fields used below.

```bash
curl -sS https://vuln.go.dev/ID/GO-2026-6809.json | grep -o -E '"(aliases|events|symbols)":\[[^]]*\]'
```

```text
"aliases":["CVE-2026-111943"]
"events":[{"introduced":"0"},{"fixed":"1.26.10"},{"introduced":"1.27.0-0"},{"fixed":"1.27.3"}]
"symbols":["Certificate.Verify"]
```

- `aliases` ties the entry to CVE-2026-111943.
- `events` lists the affected ranges, and a `fixed` version is the first one not affected:
  - every version from `0` up to `1.26.10`
  - every version from `1.27.0-0` up to `1.27.3`
- `1.27.0-0` is the lowest possible 1.27.0 pre-release, so the 1.27 release candidates are in the range too.
- `symbols` names the affected function, `Certificate.Verify`.

## Step 5. Read the CVE record

Go assigns CVE IDs for its own vulnerabilities, so Go also wrote the CVE record. The CVE Program serves it as JSON.

```bash
curl -sS https://cveawg.mitre.org/api/cve/CVE-2026-111943 | grep -o -E '"(assignerShortName|packageName)":"[^"]*"|"versions":\[[^]]*\]'
```

```text
"assignerShortName":"Go"
"packageName":"crypto/x509"
"versions":[{"version":"0","lessThan":"1.26.10","status":"affected","versionType":"semver"},{"version":"1.27.0-0","lessThan":"1.27.3","status":"affected","versionType":"semver"}]
```

- `assignerShortName` shows that Go assigned the CVE.
- `packageName` is `crypto/x509`.
- `versions` gives the same two ranges as step 4, with `lessThan` in place of `fixed`.

## Step 6. Read Go's release history

Go lists every release with its date and a one-line summary at [go.dev/doc/devel/release](https://go.dev/doc/devel/release). The command prints the entries for the two fixed releases, without blank lines.

```bash
curl -sS https://go.dev/doc/devel/release | grep -A10 -E 'id="go1\.(27\.3|26\.10)"' | grep -v -E '^[[:space:]]*$'
```

```text
		<p id="go1.27.3">
		go1.27.3
		(released 2026-10-19)
			includes
				security
				fixes to the <code>crypto/x509</code> package.
--
		<p id="go1.26.10">
		go1.26.10
		(released 2026-10-19)
			includes
				security
				fixes to the <code>crypto/x509</code> package.
```

Both releases came out on 19 October 2026 with security fixes to `crypto/x509`. On the same page, the entries for 1.27.1 and 1.27.2 name no `crypto/x509` fix.

## Step 7. Find the fix in Go's source code

The vulnerability entry links the change that made the fix, [CL 851047](https://go.dev/cl/851047), and the Go issue, [82345](https://go.dev/issue/82345). Gerrit, Go's code review site, serves the change as JSON. Its times are in UTC.

```bash
curl -sS "https://go-review.googlesource.com/changes/851047?o=CURRENT_COMMIT&o=CURRENT_REVISION" | grep -o -E '"(status|submitted)":"[^"]*"|crypto/x509: distrust a handful of intermediates|Fixes CVE-[0-9-]+|For golang/go#[0-9]+' | sort -u
```

```text
"status":"MERGED"
"submitted":"2026-10-20 02:40:26.000000000"
crypto/x509: distrust a handful of intermediates
Fixes CVE-2026-111943
For golang/go#82345
```

That change went into Go's main branch. Go tracks the copy for each older release line as a backport issue, and the issue's milestone is the release that shipped it.

```bash
for n in 82348 82349; do curl -sS https://api.github.com/repos/golang/go/issues/$n | grep -E '^  "title"|^    "title"'; done
```

```text
  "title": "security: fix CVE-2026-111943 [1.26 backport]",
    "title": "Go1.26.10",
  "title": "security: fix CVE-2026-111943 [1.27 backport]",
    "title": "Go1.27.3",
```

The first title of each pair is the issue and the second is its milestone.

The change adds a denylist called `distrustedSPKIHashes` to `src/crypto/x509/verify.go`. It holds the SHA-256 hashes of the public keys of the distrusted intermediates. Counting the name in that file at each release tag shows which releases carry the denylist:

```bash
for t in go1.26.9 go1.26.10 go1.27.2 go1.27.3; do printf '%s %s\n' "$t" "$(curl -sS https://raw.githubusercontent.com/golang/go/$t/src/crypto/x509/verify.go | grep -c distrustedSPKIHashes)"; done
```

```text
go1.26.9 0
go1.26.10 4
go1.27.2 0
go1.27.3 4
```

The source of the installed toolchain has no denylist:

```bash
grep -c distrustedSPKIHashes "$(go env GOROOT)/src/crypto/x509/verify.go"
```

```text
0
```

`grep -c` prints `0` for a file with no match, and an error for a file that does not exist.

## Step 8. Compare the versions

The check keeps its fixed versions in `emudhra_check/fixes.py`. The command reads the copy published with release `v2.0.0`.

```bash
curl -sS https://raw.githubusercontent.com/fieldse/emudhra-ca-compromise-check/v2.0.0/emudhra_check/fixes.py | grep -n -A6 '^GO_FIXED'
```

```text
23:GO_FIXED: Final = FixRule(  # PKG-002 (R206)
24-    (("1.26", "1.26.10"), ("1.27", "1.27.3")),
25-    2,
26-    Level.FAIL,
27-    Level.FAIL,
28-    "CVE-2026-111943, rebuild binaries after upgrading",
29-)
```

- Line 24 holds one fix per release line, 1.26.10 for 1.26 and 1.27.3 for 1.27. These are the two `fixed` values from step 4.
- The `2` on line 25 makes the check pick the release line by the first two numbers of the version, so 1.27.1 is judged against 1.27.3.
- Line 26 sets `FAIL` for a version below its line's fix.
- Line 27 sets `FAIL` for a release line with no listed fix, such as 1.25.
- Line 28 is the note at the end of the printed line.
- `R206` is the entry on the [references page](references.html#r206) that cites the sources in steps 4 to 6.

`sort -V` sorts version numbers, so the lower of the two prints first.

```bash
printf '%s\n' 1.27.3 1.27.1 | sort -V | head -n 1
```

```text
1.27.1
```

## The same trace for a version in Cargo.lock

A Rust project's `Cargo.lock` records the exact version of every crate, or Rust package, it builds with. The crate `webpki-roots` carries its own copy of Mozilla's trusted roots, and the check judges its version against `WEBPKI_ROOTS_FIXED` in `fixes.py`.

The lockfile below is written by hand. It pins `webpki-roots` 1.0.9.

```bash
mkdir demo
cat > demo/Cargo.lock <<'EOF'
version = 4

[[package]]
name = "demo"
version = "0.1.0"
dependencies = ["webpki-roots"]

[[package]]
name = "webpki-roots"
version = "1.0.9"
source = "registry+https://github.com/rust-lang/crates.io-index"
EOF
grep -A1 '^name = "webpki-roots"' demo/Cargo.lock
```

```text
name = "webpki-roots"
version = "1.0.9"
```

Run on this directory, the check printed the line below. `<work dir>` stands for the directory from step 1.

```text
FAIL  webpki-roots [<work dir>/demo/Cargo.lock] found 1.0.9, fixed 1.0.10
```

RustSec, the Rust security advisory database, lists the fix as RUSTSEC-2026-0381. The command reads the advisory's source file at a fixed commit of the database and prints the lines that name the fix.

```bash
curl -sS https://raw.githubusercontent.com/rustsec/advisory-db/8c25400939ad3954d97553d4dc48664c0771e1a7/crates/webpki-roots/RUSTSEC-2026-0381.md | sed -n '3,4p;13,17p;29,34p'
```

```text
id = "RUSTSEC-2026-0381"
package = "webpki-roots"
aliases = ["CVE-2026-111943"]

[versions]
patched = [">= 1.0.10"]
unaffected = ["= 0.26.11"]
Version 1.0.10+ removes this root.

The `webpki-roots` 0.26.11 compatibility package contains no independent trust
store and re-exports the roots from its separately resolved 1.x dependency.
That parent dependency must resolve to 1.0.10 or newer; an older parent remains
affected by this advisory.
```

- `patched` makes 1.0.10 the first fixed release.
- The root it removes is `emSign ECC Root CA - G3`, named earlier in the same file.
- 0.26.11 has no roots of its own. It is safe only when the lockfile resolves its 1.x dependency to 1.0.10 or later.
- `aliases` reuses Go's CVE ID.

The `webpki-roots` release note for 1.0.10 names the removed root:

```bash
curl -sS "https://api.github.com/repos/rustls/webpki-roots/releases/tags/v%2F1.0.10" | grep -E -o '"(tag_name|published_at)": *"[^"]*"|Removed \\"[^\\]*\\"'
```

```text
"tag_name": "v/1.0.10"
"published_at": "2026-10-19T20:12:29Z"
Removed \"emSign ECC Root CA - G3\"
```

The check's value is on line 66 of `fixes.py`, and line 67 holds the 0.26.11 version from the advisory:

```bash
curl -sS https://raw.githubusercontent.com/fieldse/emudhra-ca-compromise-check/v2.0.0/emudhra_check/fixes.py | grep -n -B1 '^WEBPKI'
```

```text
65-# PKG-020 (R216), PKG-027 (R220)
66:WEBPKI_ROOTS_FIXED: Final = FixRule.single("1.0.10", Level.FAIL)
67:WEBPKI_WRAPPER: Final = "0.26.11"  # PKG-024 (R218)
```

`FixRule.single` is one fixed version with no release lines. A plain `sort` puts `1.0.10` before `1.0.9`, so the comparison needs `sort -V`.

```bash
printf '%s\n' 1.0.10 1.0.9 | sort -V | head -n 1
```

```text
1.0.9
```

## Result

- **Go:** the `go` command on this Mac is Go 1.27.1, and the build record in the `go` binary names the same toolchain.
- **Fix:** Go's entry GO-2026-6809 and the CVE record for CVE-2026-111943 give 1.27.3 as the first fixed 1.27 release and 1.26.10 as the first fixed 1.26 release.
- **Release:** Go released both on 19 October 2026 with `crypto/x509` security fixes.
- **Source:** the denylist from CL 851047 is in `verify.go` at `go1.26.10` and `go1.27.3`.
  - It is missing at `go1.26.9`, at `go1.27.2` and in the installed 1.27.1.
- **Check:** `fixes.py` holds the same two versions.
  - 1.27.1 is below 1.27.3, so the `FAIL` line is correct for this machine.
- **Cargo.lock:** RUSTSEC-2026-0381 and the 1.0.10 release note make 1.0.10 the first `webpki-roots` release without the G3 root.
  - `fixes.py` holds 1.0.10, and a lockfile that pins 1.0.9 is below it.

Each claim in Flow C rests on one of these original sources:

| Claim | Step | Source and what to look for |
|---|---|---|
| Go's fix is in 1.27.3 and 1.26.10 | Step 4 | [GO-2026-6809 on pkg.go.dev](https://pkg.go.dev/vuln/GO-2026-6809). Alias `CVE-2026-111943`, fixed versions `1.27.3` and `1.26.10`, symbol `Certificate.Verify`. [Archived copy](https://web.archive.org/web/20261024213223/https://pkg.go.dev/vuln/GO-2026-6809) |
| Go assigned the CVE, for `crypto/x509` | Step 5 | [CVE record for CVE-2026-111943](https://cveawg.mitre.org/api/cve/CVE-2026-111943). `"assignerShortName":"Go"`, `"packageName":"crypto/x509"` and `"lessThan":"1.27.3"`. [Archived copy](https://web.archive.org/web/20261025025616/https://cveawg.mitre.org/api/cve/CVE-2026-111943) |
| Go 1.27.3 and 1.26.10 came out on 19 October 2026 with `crypto/x509` security fixes | Step 6 | [Go release history](https://go.dev/doc/devel/release). "go1.27.3 (released 2026-10-19) includes security fixes to the crypto/x509 package." [Archived copy](https://web.archive.org/web/20261027021802/https://go.dev/doc/devel/release) |
| CL 851047 is Go's fix | Step 7 | [CL 851047](https://go.dev/cl/851047). "crypto/x509: distrust a handful of intermediates", "Fixes CVE-2026-111943", merged 2026-10-20 |
| The 1.27 backport shipped in Go 1.27.3 | Step 7 | [Go issue 82349 in the GitHub API](https://api.github.com/repos/golang/go/issues/82349). `"title": "security: fix CVE-2026-111943 [1.27 backport]"` and the milestone's `"title": "Go1.27.3"` |
| `go1.27.3` carries the denylist and `go1.27.2` does not | Step 7 | [`verify.go` at tag `go1.27.3`](https://raw.githubusercontent.com/golang/go/go1.27.3/src/crypto/x509/verify.go). `distrustedSPKIHashes`, 4 times. The same file at tag `go1.27.2` has none |
| The check's fixed versions for Go and `webpki-roots` | Step 8 and the Cargo.lock trace | [`emudhra_check/fixes.py` at release `v2.0.0`](https://raw.githubusercontent.com/fieldse/emudhra-ca-compromise-check/v2.0.0/emudhra_check/fixes.py). Line 24 `(("1.26", "1.26.10"), ("1.27", "1.27.3"))` and line 66 `FixRule.single("1.0.10", Level.FAIL)` |
| `webpki-roots` 1.0.10 is the first fixed release | Cargo.lock trace | [RUSTSEC-2026-0381 at advisory-db commit `8c25400`](https://raw.githubusercontent.com/rustsec/advisory-db/8c25400939ad3954d97553d4dc48664c0771e1a7/crates/webpki-roots/RUSTSEC-2026-0381.md). `patched = [">= 1.0.10"]`, `unaffected = ["= 0.26.11"]` and `aliases = ["CVE-2026-111943"]` |
| `webpki-roots` 1.0.10 removes the G3 root | Cargo.lock trace | [`webpki-roots` v/1.0.10 release note](https://github.com/rustls/webpki-roots/releases/tag/v%2F1.0.10). `Removed "emSign ECC Root CA - G3"`. [Archived copy](https://web.archive.org/web/20261025230830/https://github.com/rustls/webpki-roots/releases/tag/v%2F1.0.10) |

:::

<footer>
  <div class="wrap"><p>eMudhra G3 intermediate CA key compromise, October 2026. An independent guide, not affiliated with eMudhra or Sectigo.</p><p>Last updated 2026-11-05. <a href="https://github.com/fieldse/emudhra-ca-compromise-check">Source on GitHub</a>.</p></div>
</footer>
