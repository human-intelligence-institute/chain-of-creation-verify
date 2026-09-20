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

## Known gap

Two tests — covering Merkle log-inclusion proofs and identity resolution end-to-end — were
parked during extraction from HII's internal monorepo because they depended on a live
transparency log that stays private and could not be included here. The underlying code
paths (`internal/verify`, `pkg/identity`) are present and used by `cmd/hiiverify` and
`cmd/wasmverify`; what's missing is test coverage against a public fixture. Rewriting these
against committed static fixtures (a recorded checkpoint + tile set, rather than a live
node) is follow-up work. If you're auditing this code, treat inclusion-proof and
identity-resolution verification as **less independently test-covered** than the rest of
the codebase until that follow-up lands — an auditor should hear this from us, not
discover it.

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
