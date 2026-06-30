# chain-of-creation — Verification Specification (v1)

This document is the **public contract** for independently verifying a
chain-of-creation record. It describes the byte-exact formats and algorithms a
third party needs to check a leaf on their own — by reading our open reference
implementation (`pkg/cocverify`, compiled to WebAssembly in `web/`), porting it,
or auditing it.

> **Scope of this version.** This spec covers what the offline reference verifier
> checks today: **leaf parsing, Ed25519 signatures, and content matching** (exact
> hash + fuzzy digest). It does **not** yet cover **log-inclusion proofs** or
> **identity resolution** (mapping a signing key to a creator) — those are Phase 2
> and will extend this spec. A passing content+signature check means "this leaf is
> well-formed, correctly signed, and your file matches it." It does **not** by
> itself prove the leaf is published in the transparency log.

## 1. Trust model — what each check is worth

| Check | Primitive | Reproducible by a third party? | Strength |
|-------|-----------|--------------------------------|----------|
| Exact content match | BLAKE3-256 | **Yes, universally** (BLAKE3 has many independent implementations) | **Strong** — a match proves byte-identical media |
| Signature | Ed25519 | **Yes, universally** | **Strong** — proves the leaf was signed by the holder of `SignerPubKey` |
| Fuzzy content match | `simhash-text-v1` / `phash-dct-64` (bespoke) | **Only by running our reference** (or a faithful port) | **Advisory** — see below |
| Log inclusion | RFC6962 Merkle proof | Phase 2 | n/a yet |
| Identity (key → creator) | Ed25519-signed `IdentityBinding` | Phase 2 | n/a yet |

**The fuzzy digest is a similarity index, not a cryptographic commitment.** Because
the algorithm and its parameters are public, a fuzzy match is *steerable* and must be
read as **"consistent with the certified work,"** never as **"proven identical."**
Exact integrity comes from the BLAKE3 `ExactHash`; the fuzzy digest only answers
"does a re-encoded / reformatted copy plausibly correspond to the same work." A
non-match likewise does not prove "different work." Treat fuzzy results as evidence to
corroborate, not as an authoritative decision.

## 2. Encoding primitives

All multi-byte integers are **big-endian**. The canonical encoding uses four field
shapes:

- `u8` — one byte.
- `u32` / `u64` — 4 / 8 bytes, big-endian.
- `fixed(n)` — exactly `n` raw bytes, **no length prefix** (width known from context).
- `var` — a `u32` big-endian length prefix followed by that many raw bytes. A UTF-8
  string is encoded as `var` over its UTF-8 bytes.

A decoder reads fields in order and must reject trailing bytes (strict round-trip).
Reference: `internal/leaf/codec.go`.

## 3. Leaf formats

A leaf begins with a `u8` **kind tag**: `1` = Attestation, `2` = IdentityBinding.

### 3.1 Attestation (kind = 1)

Provenance event for a work. Marshaled field order (`internal/leaf/attestation.go`):

| # | Field | Shape | Notes |
|---|-------|-------|-------|
| 1 | kind | `u8` | `1` |
| 2 | SchemaVersion | `u32` | |
| 3 | WorkID | `fixed(16)` | stable work identifier |
| 4 | EventSeq | `u64` | 0,1,2… within the work |
| 5 | PrevEventHash | `u8` present-flag + `fixed(32)` if present | flag `1` ⇒ 32-byte hash follows; flag `0` ⇒ nothing. The hash is the **LeafHash** of the prior event |
| 6 | EventType | `var` (UTF-8) | e.g. `draft`/`edit`/`finalize`/`publish` |
| 7 | MediaType | `var` (UTF-8) | e.g. `text`/`photo`/`digital-art` |
| 8 | AlgorithmID | `var` (UTF-8) | fuzzy algorithm id (= version handle) |
| 9 | FuzzyDigest | `var` | opaque, algorithm-specific |
| 10 | ExactHash | `fixed(32)` | BLAKE3-256 of the exact media bytes |
| 11 | SignerPubKey | `fixed(32)` | Ed25519 public key |
| 12 | Signature | `fixed(64)` | Ed25519, over the signing payload (§4) |
| 13 | SubmittedAt | `u64` | unix milliseconds |
| 14 | ToolTrace | `var` | optional appendix |

**LeafHash** = BLAKE3-256 over the full marshaled leaf (all 14 fields). A later
event references this value in field 5.

### 3.2 IdentityBinding (kind = 2)

HII-signed mapping from a signing key to a creator (`internal/leaf/binding.go`):

| # | Field | Shape |
|---|-------|-------|
| 1 | kind | `u8` (`2`) |
| 2 | CreatorID | `var` (UTF-8) |
| 3 | AuthorizedKey | `fixed(32)` |
| 4 | KeyType | `u8` (`1`=HII-custodial, `2`=self-managed) |
| 5 | ValidFrom | `u64` (unix ms) |
| 6 | IssuerPubKey | `fixed(32)` (HII identity-root key) |
| 7 | IssuerSignature | `fixed(64)` |

## 4. Signatures (Ed25519)

Signatures are **domain-separated**: the payload begins with a `var` domain string so
a signature over one message type can never be replayed as another. The payload is
distinct from the marshaled leaf — it omits the signature itself and commits to
`ToolTrace` only via its hash.

**Attestation signing payload** (domain `coc-attestation-v1`), in order:
`domain (var)`, `SchemaVersion (u32)`, `WorkID (fixed16)`, `EventSeq (u64)`,
`PrevEventHash (u8 flag + fixed32?)`, `EventType (var)`, `MediaType (var)`,
`AlgorithmID (var)`, `FuzzyDigest (var)`, `ExactHash (fixed32)`,
`SignerPubKey (fixed32)`, `SubmittedAt (u64)`, `toolTraceHash (fixed32)`.

`toolTraceHash` = BLAKE3-256 of `ToolTrace`, or 32 zero bytes when `ToolTrace` is
empty. Verify with `Ed25519.Verify(SignerPubKey, payload, Signature)`.

**IdentityBinding signing payload** (domain `coc-identity-binding-v1`), in order:
`domain (var)`, `CreatorID (var)`, `AuthorizedKey (fixed32)`, `KeyType (u8)`,
`ValidFrom (u64)`, `IssuerPubKey (fixed32)`. Verify against `IssuerSignature`.

## 5. Content hashing

**ExactHash** = `BLAKE3-256(media_bytes)`, 32 bytes. A verifier recomputes this over a
candidate file; equality proves byte-identical content. BLAKE3 is a published standard
with independent implementations, so this check needs no HII code.

## 6. Fuzzy algorithms

The `AlgorithmID` field selects the algorithm **and its version**. A verifier MUST use
the algorithm matching the stored id; mismatched versions are not comparable. Two
algorithms ship in v1. Both emit an **8-byte (64-bit) big-endian** digest, and both
define distance as `popcount(a XOR b) / 64` (normalized Hamming, range `[0,1]`, `0` =
identical). A pair is a *candidate match* when `distance ≤ threshold`.

### 6.1 `simhash-text-v1` (text)

64-bit SimHash over frequency-weighted word tokens. Steps:

1. Interpret the media bytes as **UTF-8** text.
2. **Tokenize:** split on every rune that is **not** a Unicode letter and **not** a
   Unicode digit (Go `unicode.IsLetter`/`unicode.IsDigit`). Lowercase each token (Go
   `strings.ToLower`). Count occurrences → `weight(token)`.
3. For each distinct token, compute `h = FNV-1a-64(token_utf8_bytes)` (the lowercased
   token's UTF-8 bytes; standard FNV-1a, offset basis `0xcbf29ce484222325`, prime
   `0x100000001b3`).
4. Maintain a signed accumulator `acc[0..63] = 0`. For each token and each bit
   `i ∈ [0,64)`: if bit `i` of `h` is set, `acc[i] += weight`; else `acc[i] -= weight`.
5. Fingerprint bit `i` = `1` **iff** `acc[i] > 0` (an accumulator of exactly `0` ⇒ bit
   `0`). Bit `i` occupies value `1 << i`.
6. Serialize the 64-bit fingerprint **big-endian** into 8 bytes.

**Threshold:** `0.15` (≤ 9 differing bits). Reference: `internal/fuzzy/simhash.go`.

### 6.2 `phash-dct-64` (photo, digital-art)

64-bit perceptual hash (DCT-II over a 32×32 luminance image). Steps:

1. Decode the image (PNG, JPEG, or GIF).
2. **Resize to 32×32 luminance** by bilinear-style point sampling: for target pixel
   `(x,y)` in a 32×32 grid, source coordinate `sx = floor((x+0.5)·W/32)`,
   `sy = floor((y+0.5)·H/32)`, clamped to `W-1`/`H-1`. Luminance from the source
   pixel's 16-bit RGBA: `lum = (0.299·R + 0.587·G + 0.114·B) / 257.0`.
3. **DCT-II**, separable (rows then columns), **unnormalized**, with
   `cos(π/32 · (x+0.5) · u)`.
4. Take the low-frequency **8×8 block** in row-major order:
   `block[v·8 + u] = coeffs[v][u]` for `u,v ∈ [0,8)`.
5. Compute the **median of the block excluding index 0** (the DC term, which would
   otherwise dominate): sort the 63 remaining values, take element `63/2 = 31`.
6. Fingerprint bit `i` = `1` iff `block[i] > median`. Serialize **big-endian**.

**Threshold:** `0.1875` (≤ 12 differing bits). Reference: `internal/fuzzy/phash.go`.

> **Known limitation (re-implementers).** This hash uses floating-point DCT and
> median comparison. An *independent* implementation may differ by one or two bits
> from ours for coefficients that sit very close to the median, because of
> floating-point rounding differences. **Running our reference implementation is
> bit-exact** (our native and WebAssembly builds compile the same Go math and agree —
> CI runs the golden vectors under `GOOS=js GOARCH=wasm` to prove it). If you
> re-implement, allow a small tolerance, or run our reference for an authoritative
> digest.

## 7. Golden vectors

Any conforming implementation MUST reproduce these digests exactly. They are also
asserted in `internal/fuzzy/golden_test.go`; the image inputs are the committed files
under `internal/fuzzy/testdata/`.

### `simhash-text-v1`

| Input (exact UTF-8) | Digest (hex, big-endian) |
|---------------------|--------------------------|
| `The quick brown fox jumps over the lazy dog.` | `cab7991c5475edee` |
| `the   QUICK brown fox\tjumps over the lazy dog` (reformat of the above) | `cab7991c5475edee` |
| `Provenance you can verify.` | `3540200101864944` |
| `café déjà vu 🎨 naïve façade` | `0c8d8f26ac712ca0` |
| `` (empty) | `0000000000000000` |

The first two rows differ only in case, whitespace, and trailing punctuation, yet hash
identically — that reformatting-invariance is the point of the fuzzy digest.

### `phash-dct-64`

| Input file (`internal/fuzzy/testdata/`) | Digest (hex, big-endian) |
|-----------------------------------------|--------------------------|
| `gradient-a.png` | `f8f8f8f8f8070605` |
| `gradient-a.jpg` (same image, JPEG q40) | `f8f8f8f8f8070605` |
| `gradient-b.png` (different image) | `2d126d926d2d936d` |

The PNG and JPEG of the same image hash identically (distance 0) despite lossy
recompression; the different image is far away (`distance(a,b) = popcount(f8f8f8f8f8070605 ⊕ 2d126d926d2d936d)/64`).

## 8. Versioning

This spec is **v1**, matching `AlgorithmID` values `simhash-text-v1` and
`phash-dct-64`. Any change to tokenization, hashing, bit ordering, thresholds, or the
leaf wire format is a **breaking change** to this contract: it requires a new
`AlgorithmID` (and a new spec revision), never an in-place edit. Stored leaves keep
verifying against the version named in their `AlgorithmID`.
