# chain-of-creation-verify

Reference implementation for independently verifying a **chain-of-creation** record: the
provenance chain the Human Intelligence Institute (HII) attaches to a certified work. It
implements the algorithms specified in [`docs/verification-spec.md`](docs/verification-spec.md)
— leaf parsing, Ed25519 signature checks, content matching (exact hash + fuzzy digest),
Merkle log-inclusion proofs, identity resolution, and revocation status — and compiles both
to a Go CLI and to WebAssembly for the hosted browser verifier.

## What a result from this tool means

An **exact match** means the file you supplied is byte-identical to the one HII certified.
That is strong evidence.

A **fuzzy match** means the content is *consistent with* the certified work within a published
distance threshold. It is advisory. It is not proof that this file is that work.

Neither result is proof that a human created the work. This tool verifies what HII attested
and when — not how the work was made.

Verification of log inclusion, identity binding and revocation status requires network access
to the transparency log. A verdict produced without it covers content matching only.

## What's in this repo

- `pkg/cocverify` — the stable public verification API (offline leaf/signature/content
  checks; wraps `internal/verify`).
- `pkg/attest`, `pkg/fuzzy`, `pkg/identity`, `pkg/leaf`, `pkg/status` — supporting packages
  (leaf construction, fuzzy digest algorithms, identity resolution, leaf encoding, revocation
  status) exported for HII's own cross-repo use.
- `internal/provenance`, `internal/verify` — the underlying provenance-chain reconstruction
  and inclusion/identity verification logic.
- `cmd/hiiverify` — a CLI reference verifier: given a work's leaf files, reconstructs the
  provenance chain, verifies signatures, resolves identity, and reports exact/fuzzy content
  match as JSON.
- `cmd/wasmverify` — the same verification logic compiled with `GOOS=js GOARCH=wasm`,
  exposing `cocVerifyLeaf`, `cocVerifyInclusion`, `cocVerifyIdentity`, and
  `cocResolveStatus` to the browser.
- `web/` — the static HTML/JS front end for the hosted verifier (fetches its own
  `config.json` at load time — see note below).
- `docs/verification-spec.md` — the public, self-contained specification. It is written to
  be implementable without reading this code; auditing this code is an alternative to
  porting the spec, never a prerequisite.

## Install and usage

Requires Go 1.26+.

Build and run the CLI directly:

```sh
go run ./cmd/hiiverify -dir /path/to/leaf-files -media /path/to/candidate-file
```

Or install it:

```sh
go install github.com/human-intelligence-institute/chain-of-creation-verify/cmd/hiiverify@latest
hiiverify -dir /path/to/leaf-files -media /path/to/candidate-file
```

Pass `-trusted-root <hex Ed25519 pubkey>` to also verify identity bindings against a
specific trust root. `hiiverify` prints a JSON verification report to stdout.

To build the WebAssembly verifier used by the hosted browser tool:

```sh
sh web/build.sh
```

This produces `web/cocverify.wasm` and stages `wasm_exec.js` next to it; serve `web/` over
HTTP (not `file://`) to load it.

### A note on `web/config.json`

The browser verifier fetches `config.json` at load time for its pinned trust anchors
(transparency-log origin, checkpoint verification key, identity root). **This repository
does not commit a production `config.json`.** Any values you see referenced in `web/` code
or comments are development placeholders, not production anchors — real values are injected
at deploy time from HII's own configuration store. Do not treat anything in this repo as a
live trust anchor; obtain current anchors from HII directly.

## Reproducing the golden vectors

`pkg/fuzzy/golden_test.go` and `pkg/status/golden_test.go` freeze the exact wire output of
the published algorithms (`simhash-text-v1`, `phash-dct-64`, and related digests). They are
the machine-checkable half of the spec: a third-party reimplementation should reproduce
these digests byte-for-byte. Run them with:

```sh
go test ./pkg/fuzzy/... ./pkg/status/... -run Golden -v
```

A full test run (`go test ./...`) exercises all eight packages, including the WebAssembly
build's parity test against the same golden vectors (`wasm_parity_test.go`).

## The frozen leaf corpus

The golden vectors freeze the **digest function**. They do not freeze a **certificate** —
and a certificate is what somebody is holding in 2036 when they ask whether it still
verifies.

`pkg/cocverify/testdata/corpus/` holds complete, signed leaves — one directory per case,
covering every algorithm id this build resolves, both leaf kinds, and the failure paths
(unrelated content, an unknown algorithm id, a tampered signature). Each `case.json`
records the **entire expected verification result**, including the leaf hash. Run it with:

```sh
go test ./pkg/cocverify/ -run Golden -v
```

These are bytes on disk that no test regenerates, and that distinction is the whole point.
Every other test here builds its input with the same code it is testing, so a *consistent*
refactor — reordering two fields in both the encoder and the decoder, say — leaves the
entire rest of the suite green while invalidating every leaf ever written to a log. We
checked: that mutation reddens `TestGoldenLeafCorpus` and nothing else, `pkg/leaf`'s own
round-trip tests included. Quietly loosening a fuzzy-match threshold is likewise caught
here and nowhere else.

> ⚠️ **A red test here is not a fixture to refresh.** It means a published contract moved,
> which requires a new algorithm id or schema version — never an in-place edit.
> `cmd/gencorpus`, which produced these files, refuses to overwrite an existing case for
> that reason.

### A caveat on `phash-dct-64` and synthetic images

Building this corpus surfaced a real limitation worth stating plainly. pHash thresholds each
low-frequency DCT coefficient against the block median with a bare `c > median` and no tie
tolerance. For an image whose low-frequency spectrum is *degenerate* — a flat fill, a linear
gradient, perfectly repeating bands — almost every coefficient lands on the median at
numerical zero, and each of those bits is then decided by floating-point rounding. One such
test image produced `6d696d216d006d6f` natively and `796979097900797b` under js/wasm: 6
differing bits for the same input.

Photographs never look like this; synthetic graphics can, and `digital-art` is an accepted
media type. So for such images, "a third party reproduces the digest byte-for-byte" is not
unconditionally true of `phash-dct-64` the way it is of `simhash64-v1` (pure integer
arithmetic over SHA-256). The match threshold absorbs the difference in practice — 6 bits is
well inside it — but an implementer comparing digests exactly should know this exists. It is
tracked as a spec issue; `docs/verification-spec.md` does not yet say so.

## Verifying the hosted verifier

The WebAssembly verifier HII serves in the browser is built from this module — there is no
separate source for it. You can rebuild it yourself and compare bytes:

```sh
mkdir /tmp/verify-check && cd /tmp/verify-check
go mod init check
go get github.com/human-intelligence-institute/chain-of-creation-verify/cmd/wasmverify@v1.0.0
GOOS=js GOARCH=wasm go build -trimpath -o mine.wasm \
  github.com/human-intelligence-institute/chain-of-creation-verify/cmd/wasmverify
curl -sO https://<verifier-host>/cocverify.wasm
shasum -a 256 mine.wasm cocverify.wasm   # must match
```

> ⚠️ The build must treat this repository as a **dependency**, exactly as above. Cloning the
> repo and running `go build ./cmd/wasmverify` produces **different bytes even with
> `-trimpath`**, because Go embeds `debug.BuildInfo` recording which module is the main
> module. That difference is **not** evidence of tampering.

Three other things will change the bytes, so get them right before concluding anything:

- `go get` must name the **package** path (`.../cmd/wasmverify@vX.Y.Z`), not just the module
  path. Fetching the module alone does not record the `go.sum` entries the build needs, and
  the build fails rather than silently differing.
- Use the tag the host is actually serving, not `@latest`. See the warning below — this one
  is easy to get wrong and looks alarming when you do.
- Build with the Go toolchain this module's `go.mod` requires. A different Go version
  produces a different binary.

> ⚠️ **The hash is version-specific, not source-specific.** Go records the module version in
> `debug.BuildInfo`, so **two tags with byte-identical source still produce different
> binaries**. `v1.0.0` and `v1.0.1` of this module contain no code difference whatsoever —
> `git diff v1.0.0 v1.0.1 -- pkg internal cmd web spec go.mod go.sum` is empty — and their
> wasm builds differ regardless.
>
> So comparing the **newest** release asset against a host still pinned to an older tag
> yields a mismatch that means nothing at all. Compare like for like: build the tag the host
> serves, or download that tag's release asset.

### Which tag is the host serving?

Honest answer: the served bundle does not currently advertise its version, so you cannot read
it off the wire. Until that changes, either ask HII, or download release assets newest-first
until one matches — a match identifies the tag. We regard this as a gap in our own
verifiability story rather than a property we are content with.

Substitute `<verifier-host>` with the host you are checking. HII's verifier is currently
served from a CloudFront distribution and has no permanent custom domain yet, so rather than
freeze a hostname here: take it from the URL of the verifier page you are auditing, or ask
HII directly.

From the next tagged release onward, each tag publishes `cocverify.wasm` and
`cocverify.wasm.sha256` as GitHub Release assets, built by `.github/workflows/release.yml` in
exactly the dependency-module way shown above; that published sha256 is the value both your
own build and the served file should have. `v1.0.0` predates that workflow — it exists as a
tag only, with no release assets, so for `v1.0.0` the comparison above is the check.

## Known gap

Inclusion proofs, identity resolution and revocation status **are** covered by tests.
`pkg/cocverify/inclusion_test.go`, `pkg/cocverify/identity_test.go` and
`pkg/cocverify/status_test.go` run against a frozen log fixture committed under
`pkg/cocverify/testdata/`: a recorded checkpoint, tiles, entry bundles and a manifest. (An
earlier version of this README said those tests were parked during extraction and that
fixture coverage was follow-up work. That is no longer true — this paragraph replaces it.)

The fixture is deliberately the material a third party actually has: static log artifacts,
not a live node. You can run the suite offline and get the same result we do.

Whole-certificate coverage is handled separately by the frozen leaf corpus described above.

What remains genuinely weaker is this: the fixtures exercise the verifier against a
**recorded** log, so they cannot catch a regression that only appears against a live, growing
one — tile boundaries that move as the tree grows, a checkpoint that advances between
requests, a log node that answers differently from the recording. HII covers that separately
with an end-to-end smoke against its running transparency log. **An outside auditor cannot
run that**, and nothing in this repository substitutes for it. If you are auditing this code,
that is the honest boundary of what you can independently reproduce.

## Why a verdict is INDETERMINATE

Revocation status fails closed: if a status anchor exists and its artifact cannot be
obtained and hash-matched, the verdict is `INDETERMINATE`, never `VERIFIED`. That is the
property separating this from OCSP soft-fail, where blocking one request buys a clean pass.

But the verdict alone is not actionable, and that matters for anyone building on this.
`INDETERMINATE` spans a log that is equivocating and a laptop that is offline. So
`status.Resolve` returns a typed reason alongside it, surfaced as `indeterminate_reason` on
`cocverify.StatusResult` and in the WASM bridge's JSON:

| reason | what it means | retrying helps |
|---|---|---|
| `anchor_scan_failed` | an entry bundle could not be read, so a newer withdrawal may be unseen | usually |
| `anchor_untrusted` | anchors exist but none is signed by a pinned identity root — possibly a root rotation this verifier has not picked up | no |
| `artifact_unreachable` | a trusted anchor names a withdrawal list that could not be fetched | usually |
| `artifact_parse_error` | the list was fetched but is malformed | no |
| `artifact_hash_mismatch` | **the list served does not match what the log committed to** — corruption, or equivocation | no |

`indeterminate_detail` carries the underlying error for display. It is diagnostic only and
carries no verdict weight — a caller that treats it as a failure throws away a perfectly
good fail-closed answer.

The last row is the only one that is *evidence* rather than an inability to check, and the
hosted verifier colours it differently for that reason. If you port this spec, we would
encourage reporting the reason too: a verifier that can only print the word "indeterminate"
teaches users to read it as noise, and fail-closed then quietly degrades into fail-ignored.

## API stability

`pkg/cocverify` is the **supported public API** of this repository. It is the small,
stable surface intended for external integration, and breaking changes to it will follow
semantic versioning.

`pkg/attest`, `pkg/fuzzy`, `pkg/identity`, `pkg/leaf`, and `pkg/status` are exported
because HII uses them directly from other repositories, not because they are committed to
as a stable external contract. They **may change between minor versions** without the same
compatibility guarantee `pkg/cocverify` gets. If you depend on them directly, pin a
specific commit or module version and expect to review diffs on upgrade.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE) for
third-party components vendored under `web/vendor/` (PDF.js, Apache-2.0; Mammoth,
BSD-2-Clause).

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability, including verifier
correctness bugs.
