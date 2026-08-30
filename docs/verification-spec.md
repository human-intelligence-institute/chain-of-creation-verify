# chain-of-creation — Verification Specification (v1.1)

This document is the **public contract** for independently verifying a
chain-of-creation record. It describes the byte-exact formats and algorithms a
third party needs to check a leaf on their own, and it is **self-contained**: every
algorithm is specified here in enough detail to implement without reading HII code.
HII's reference implementation (`pkg/cocverify`, compiled to WebAssembly for the hosted
verifier) is not currently published — it is available on request, and auditing it is an
alternative to porting, never a prerequisite. The pinned trust anchors needed for §8 and
§9 **are** published; see **§11**.

> **Scope of this version.** This spec covers **leaf parsing, Ed25519 signatures,
> content matching** (exact hash + fuzzy digest), **log-inclusion proofs** (§8),
> **identity resolution** (mapping a signing key to a creator, §9), and
> **revocation status** (§12). A passing content+signature check means "this leaf is
> well-formed, correctly signed, and your file matches it"; the §8 inclusion check
> proves the leaf is **committed in the published log**; the §9 identity check proves
> **which creator HII vouched the signing key for** at submission time; the §12 status
> check reports whether **HII has since withdrawn** the certification. A verifier must
> perform §12 before presenting a record as verified.

## 1. Trust model — what each check is worth

| Check | Primitive | Reproducible by a third party? | Strength |
|-------|-----------|--------------------------------|----------|
| Exact content match | BLAKE3-256 or SHA-256 (named by `ExactAlg`) | **Yes, universally** (both have many independent implementations) | **Strong** — a match proves byte-identical media |
| Signature | Ed25519 | **Yes, universally** | **Strong** — proves the leaf was signed by the holder of `SignerPubKey` |
| Fuzzy content match | `simhash64-v1` (SHA-256 features) / `phash-dct-64` | **Yes** for `simhash64-v1` — SHA-256 has one definition in every language; pHash only by running our reference | **Advisory** — see below |
| Log inclusion | RFC6962 Merkle proof under a pinned-key checkpoint (§8) | **Yes** — fetch checkpoint + tiles, reconstruct the proof | **Strong** — proves the leaf is committed in the published log |
| Identity (key → creator) | Ed25519-signed `IdentityBinding`, proven included (§9) | **Yes** — verify the binding named by the receipt | **Strong** (for HII's vouch) — proves HII bound the key to the creator and logged it |

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

## 3. Leaf formats

A leaf begins with a `u8` **kind tag**: `1` = Attestation, `2` = IdentityBinding,
`3` = StatusAnchor. Kinds are **additive**: a reader that does not recognise a tag
skips the leaf, and leaves written before a kind existed keep decoding unchanged.

### 3.1 Attestation (kind = 1)

Provenance event for a work. Marshaled field order:

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
| 10 | ExactHash | `fixed(32)` | exact hash of the media bytes; the algorithm is named by `ExactAlg` (§5) |
| 11 | ExactAlg | `var` (UTF-8) | exact-hash algorithm id: `blake3` (default) or `sha256`; empty ⇒ `blake3` |
| 12 | SignerPubKey | `fixed(32)` | Ed25519 public key |
| 13 | Signature | `fixed(64)` | Ed25519, over the signing payload (§4) |
| 14 | SubmittedAt | `u64` | unix milliseconds |
| 15 | ToolTrace | `var` | optional appendix |

**LeafHash** = BLAKE3-256 over the full marshaled leaf (all 15 fields). A later
event references this value in field 5.

### 3.2 IdentityBinding (kind = 2)

HII-signed mapping from a signing key to a creator:

| # | Field | Shape |
|---|-------|-------|
| 1 | kind | `u8` (`2`) |
| 2 | CreatorID | `var` (UTF-8) |
| 3 | AuthorizedKey | `fixed(32)` |
| 4 | KeyType | `u8` (`1`=HII-custodial, `2`=self-managed) |
| 5 | ValidFrom | `u64` (unix ms) |
| 6 | IssuerPubKey | `fixed(32)` (HII identity-root key) |
| 7 | IssuerSignature | `fixed(64)` |

### 3.3 StatusAnchor (kind = 3)

HII-signed commitment to the hash of a published **revocation status artifact**
(§12). The artifact lists attestation leaves HII has withdrawn.

| # | Field | Shape | Notes |
|---|-------|-------|-------|
| 1 | kind | `u8` | `3` |
| 2 | SchemaVersion | `u32` | |
| 3 | ArtifactVersion | `u64` | strictly monotonic across publications |
| 4 | ArtifactHash | `fixed(32)` | BLAKE3-256 over the artifact bytes **as published** |
| 5 | IssuedAt | `u64` | unix milliseconds |
| 6 | IssuerPubKey | `fixed(32)` | HII identity-root key — the anchor already pinned for §3.2 |
| 7 | IssuerSignature | `fixed(64)` | Ed25519 over the signing payload (§4) |

`ArtifactVersion` is inside the signed payload deliberately: without it, an old
artifact's signature could be replayed under a higher version number and the
status rolled back undetectably.

The artifact itself carries **no signature of its own**. Its authenticity is
transitive from this leaf, which is both signed and committed to the append-only
log — one signature, in one place, covered by the log's tamper-evidence.

## 4. Signatures (Ed25519)

Signatures are **domain-separated**: the payload begins with a `var` domain string so
a signature over one message type can never be replayed as another. The payload is
distinct from the marshaled leaf — it omits the signature itself and commits to
`ToolTrace` only via its hash.

**Attestation signing payload** (domain `coc-attestation-v1`), in order:
`domain (var)`, `SchemaVersion (u32)`, `WorkID (fixed16)`, `EventSeq (u64)`,
`PrevEventHash (u8 flag + fixed32?)`, `EventType (var)`, `MediaType (var)`,
`AlgorithmID (var)`, `FuzzyDigest (var)`, `ExactHash (fixed32)`, `ExactAlg (var)`,
`SignerPubKey (fixed32)`, `SubmittedAt (u64)`, `toolTraceHash (fixed32)`.

`toolTraceHash` = BLAKE3-256 of `ToolTrace`, or 32 zero bytes when `ToolTrace` is
empty. Verify with `Ed25519.Verify(SignerPubKey, payload, Signature)`.

**IdentityBinding signing payload** (domain `coc-identity-binding-v1`), in order:
`domain (var)`, `CreatorID (var)`, `AuthorizedKey (fixed32)`, `KeyType (u8)`,
`ValidFrom (u64)`, `IssuerPubKey (fixed32)`. Verify against `IssuerSignature`.

**StatusAnchor signing payload** (domain `coc-status-v1`), in order:
`domain (var)`, `SchemaVersion (u32)`, `ArtifactVersion (u64)`,
`ArtifactHash (fixed32)`, `IssuedAt (u64)`, `IssuerPubKey (fixed32)`. Verify
against `IssuerSignature`. The distinct domain is what stops a status signature
being replayed as an IdentityBinding, given both are made with the identity-root key.

## 5. Content hashing

**ExactHash** (32 bytes) is a one-way digest of the exact media, and the field **`ExactAlg`
names the algorithm** used:

- **`blake3`** (or empty ⇒ blake3): `BLAKE3-256(media_bytes)`. Used by the server-side
  media-digest path.
- **`sha256`**: `SHA-256(...)` over one of **two different subjects**, depending on which
  certifier issued the leaf. `ExactAlg` alone does not tell them apart — see the warning
  below.
  - **Raw file bytes.** File-based certifiers (the Word add-in) hash the **exact certified
    file** (the `.docx`), because that is the artifact the creator holds. A match proves
    the candidate is the byte-identical certified **file** — not merely the same text; a
    re-export or reformat changes the bytes and will not match.
  - **Canonical normalized text.** Text-based certifiers (the Google Docs extension) hash
    the **normalized token stream** defined by §6.3 steps 1–5, joined with single spaces —
    i.e. `SHA-256(canonical_text)`, *not* the raw extracted text. This is deliberately
    reproducible by anyone holding the document: they need the normalization, not HII's
    extraction. Case, whitespace, quote style and punctuation do not affect it.

> **Warning — the subject is not carried in the leaf.** Two leaves can both say
> `ExactAlg: sha256` and commit to different things. Hashing raw text against a
> file-bytes leaf, or raw text against a normalized-text leaf, produces a mismatch that
> looks exactly like tampering. A verifier that cannot determine the subject MUST report
> "cannot check" rather than "does not match". HII's verification API exposes the subject
> explicitly as `exact_hash_subject`.

A verifier recomputes the hash named by `ExactAlg` over the candidate bytes and compares.
Both BLAKE3 and SHA-256 are published standards with independent implementations, so this
check needs no HII code. An `ExactAlg` the verifier does not recognize is treated as
"not a match" (it cannot be checked), never a silent pass.

## 6. Fuzzy algorithms

The `AlgorithmID` field selects the algorithm **and its version**. A verifier MUST use
the algorithm matching the stored id; mismatched versions are not comparable. Each
algorithm emits an **8-byte (64-bit) big-endian** digest and defines distance as
`popcount(a XOR b) / 64` (normalized Hamming, range `[0,1]`, `0` = identical). A pair is a
*candidate match* when `distance ≤ threshold`. The canonical text algorithm is
**`simhash64-v1`** (§6.3); `simhash-text-v1` (§6.1) is a legacy text algorithm kept
resolvable for older leaves; `phash-dct-64` (§6.2) covers images.

### 6.1 `simhash-text-v1` (text, legacy)

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

**Threshold:** `0.15` (≤ 9 differing bits).

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

**Threshold:** `0.1875` (≤ 12 differing bits).

> **Known limitation (re-implementers).** This hash uses floating-point DCT and
> median comparison. An *independent* implementation may differ by one or two bits
> from ours for coefficients that sit very close to the median, because of
> floating-point rounding differences. **Running our reference implementation is
> bit-exact** (our native and WebAssembly builds compile the same Go math and agree —
> CI runs the golden vectors under `GOOS=js GOARCH=wasm` to prove it). If you
> re-implement, allow a small tolerance, or run our reference for an authoritative
> digest.

### 6.3 `simhash64-v1` (text) — canonical

The content fingerprint HII certifiers compute client-side and record on the ledger.
64-bit SimHash over normalized word 3-shingles with a **SHA-256 feature hash**. Steps:

1. Interpret the media as **UTF-8** text.
2. **Normalize** (the step that makes different file formats agree), in order:
   1. Unicode **NFKC**.
   2. Lowercase.
   3. Fold curly single/double quotes → `'` / `"` and en/em/horizontal dashes → `-`.
   4. Replace every run of characters that is **neither a Unicode letter nor a Unicode
      digit** (`[^\p{L}\p{N}]+`) with a single space.
   5. Trim leading/trailing spaces.
3. **Tokenize:** split the normalized string on single spaces (drop empties).
4. **Shingle:** join every **3** consecutive tokens with a single space. Fewer than 3
   tokens ⇒ one shingle of all tokens (none when there are no tokens).
5. For each shingle `s`: `feature = big-endian uint64 of SHA-256(utf8(s))[0:8]`.
6. Signed accumulator `acc[0..63] = 0`. For each shingle and bit `i ∈ [0,64)`: if bit `i`
   of `feature` is set, `acc[i] += 1`, else `acc[i] -= 1`. Bit `i` occupies value `1 << i`.
7. Fingerprint bit `i` = `1` iff `acc[i] > 0`. Serialize the 64-bit fingerprint
   **big-endian** into 8 bytes (equivalently, 16 lowercase hex chars, high 32 bits first).

**Why SHA-256 features.** MurmurHash3 (the usual SimHash feature hash) has several
mutually-incompatible variants (x86_32 vs x64_128, seed/sign handling); SHA-256 has
exactly one definition in every language, so a third party reproduces this digest with
only their standard library — no HII code, no variant ambiguity.

**Threshold:** `0.15` (≤ 9 differing bits). Golden vectors: §7.

> **Extraction note (re-implementers).** The fingerprint is defined over **text**. When
> the certified work is a binary document (`.docx`, `.pdf`, `.epub`), the ledger digest was
> computed over text the certifier extracted client-side; an independent verifier must
> extract text and can differ slightly (tables, footnotes, word boundaries), shifting a few
> bits. Where a certifier exists for the format, the hosted verifier reuses the same
> extraction libraries to minimize this; for a format no certifier emits — `.epub` today —
> the candidate is being compared against a leaf certified from some other format, so
> extraction drift is unavoidable and only the fuzzy result is meaningful (the exact hash
> commits to bytes that an `.epub` will never reproduce). Treat a fuzzy result as advisory
> (§1), never as proof.
>
> **Word boundaries are the trap.** Step 2.4 collapses every non-alphanumeric run to a
> single space, so *any* separator between two words is equivalent — but *no* separator is
> not. Extractors that concatenate block elements without one (a DOM `textContent` over
> `<h1>Hours</h1><p>Marguerite…`, joining PDF text spans) fuse two words into a single
> token, and each fused token corrupts three shingles. Measured on a two-paragraph EPUB:
> **5 of 64 bits** — over half the 0.15 budget, still "within threshold", and it compounds
> with every block junction. Emit a separator at every block boundary.

## 7. Golden vectors

Any conforming implementation MUST reproduce these digests exactly. They are also asserted by HII's own test
suites; the image inputs are fixed files, available on request.

### `simhash64-v1`

The vectors below are the single source of truth that the coc verifier **and** every HII
certifier (customer-app, Word add-in, gdoc extension) reproduce byte-for-byte in their own
test suites. A machine-readable copy is available on request.

| Input (exact UTF-8) | Digest (hex, big-endian) |
|---------------------|--------------------------|
| `The quick brown fox jumps over the lazy dog.` | `e7e097a95960e95f` |
| `the   QUICK brown fox\tjumps over the lazy dog` (reformat of the above) | `e7e097a95960e95f` |
| `Provenance you can verify.` | `f560282f20b80090` |
| `café déjà vu 🎨 naïve façade` | `b1ea06b8a80badd3` |
| `two words` (fewer than 3 tokens ⇒ one shingle) | `a03f1d611645eb53` |
| `` (empty) | `0000000000000000` |

The first two rows differ only in case, whitespace, and trailing punctuation, yet hash
identically — that reformatting-invariance is the point of the fuzzy digest.

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

| Input file | Digest (hex, big-endian) |
|-----------------------------------------|--------------------------|
| `gradient-a.png` | `f8f8f8f8f8070605` |
| `gradient-a.jpg` (same image, JPEG q40) | `f8f8f8f8f8070605` |
| `gradient-b.png` (different image) | `2d126d926d2d936d` |

The PNG and JPEG of the same image hash identically (distance 0) despite lossy
recompression; the different image is far away (`distance(a,b) = popcount(f8f8f8f8f8070605 ⊕ 2d126d926d2d936d)/64`).

### Revocation (§12)

Derived from the Ed25519 seed
`0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20`, giving the
identity root
`79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664`.

Status artifact (exact bytes — these are what get hashed):

```
{"issued_at":1786000000000,"log_size_at_issue":9,"schema":1,"version":1,"withdrawn":[{"leaf_hash":"oKGio6SlpqeoqaqrrK2ur6ChoqOkpaanqKmqq6ytrq8=","reason":"certification_rejected","withdrawn_at":1786000000001}]}
```

| Value | Expected |
|-------|----------|
| `ArtifactHash` (BLAKE3-256 of the bytes above) | `b6cd453b16d99761862fa3f1ed7c8d50f121135596fef2595ff7015fb4a30f36` |
| `StatusAnchor` leaf, base64 | `AwAAAAEAAAAAAAAAAbbNRTsW2Zdhhi+j8e18jVDxIRNVlv7yWV/3AV+0ow82AAABn9XlRAB5tVYuj+ZU+UB4sRLoqYunkB+FOuaVvtfg45ELrQSWZMmdoBLEMzgo8+2iCMuu8X34SCrHV9RC4Fpwa9zYefMovoYx07ehBgTi+wScWOcqi2LBtQtzTEDo7uvssGxaPQ4=` |
| Verdict for leaf hash `oKGio6SlpqeoqaqrrK2ur6ChoqOkpaanqKmqq6ytrq8=` | **`WITHDRAWN`** |
| Verdict for any other leaf hash | `VERIFIED` |
| Verdict when the artifact is unreachable or its hash differs | **`INDETERMINATE`** |

An implementation that omits status resolution returns `VERIFIED` for the third
row and fails this vector. That is deliberate: conformance to §12 has to be
demonstrable, not merely claimed.

## 8. Log inclusion

The checks above prove a leaf is well-formed, signed, and matches a file. Inclusion
proves the leaf is **committed in the published log** — that the operator actually
logged it and cannot later disavow or alter it. The log exposes the c2sp tlog-tiles
read path; it does **not** serve ready-made proofs, so a verifier reconstructs the
proof itself from tiles. This keeps verification independent of the operator.

### 8.1 Read path

- `GET /checkpoint` — the signed checkpoint (a C2SP signed note).
- `GET /tile/{level}/{index}[.p/{w}]` — a Merkle tile (binary).
- `GET /tile/entries/{index}[.p/{w}]` — an entry bundle (binary).

Responses carry `Access-Control-Allow-Origin: *` so a browser verifier on another
origin can fetch them.

### 8.2 Checkpoint — pinned-key verification

The checkpoint is a [note](https://pkg.go.dev/golang.org/x/mod/sumdb/note):

```
<origin>
<tree size>
<root hash, base64>

— <origin> <base64 signature>
[additional log/witness cosignature lines]
```

A verifier MUST verify the checkpoint signature against a **pinned** `(origin, vkey)`
that ships with the verifier (**§11**, or baked into the distribution) — **never**
a key taken from the response. The pinned vkey is the trust anchor; an unverifiable
checkpoint is a hard failure, never a silent pass. Witness cosignatures, when a witness
quorum is live, are verified against the published witness policy; until then the log
is **not yet witnessed** and split-view/equivocation protection is pending — a verifier
should say so rather than imply it.

### 8.3 Inclusion proof

Given the record's `{leaf, index}` (the index is returned in the submit receipt):

1. Fetch + verify the checkpoint → tree `size` and `root`.
2. If `index ≥ size`, the leaf is not in this checkpoint — not included.
3. Compute the RFC6962 inclusion proof node set for `(index, size)` and fetch those
   nodes from the tiles (the right-edge nodes may be ephemeral and synthesized from
   partial tiles — standard tlog-tiles proof reconstruction).
4. The leaf hash is `RFC6962-LeafHash(rawLeaf)` (Tessera's hasher — distinct from the
   BLAKE3 content/`LeafHash` used to chain provenance events). Verify the proof against
   `root`.

A verifier reproduces this with the Tessera client (`client.FetchCheckpoint`,
`client.NewProofBuilder(...).InclusionProof`) over any fetcher, or an equivalent port.
The hosted verifier exposes this as
`cocVerifyInclusion(leafB64, index, readBaseURL, origin, vkey)`.

### 8.4 What inclusion does and does not prove

A successful check proves the leaf is committed at `index` in a log of `size` entries
under a checkpoint signed by the pinned key, **as of the checkpoint you fetched**. It
does **not** prove the log never forked or rewound over time — that needs consistency
proofs between checkpoints over time (a later revision) and live witnessing.

## 9. Identity resolution

Inclusion proves a leaf is in the log; identity answers "whose key signed it." HII
issues an `IdentityBinding` (§3.2) mapping a signing key to a creator, signed by its
**identity-root key** and stored in the same log. Identity resolution does **not**
search the log: at any scale, the verifier is handed the binding's location and
verifies exactly that one binding.

### 9.1 The receipt

A record's portable **receipt** is verification metadata (off-leaf, not signed):

```json
{ "leaf": "<base64 attestation leaf>", "index": <attestation log index>,
  "binding_index": <binding log index> }
```

`binding_index` is the log index of the creator's `IdentityBinding`. It is returned by
the custodial submit response (`binding_index`) at certification time. The receipt is
self-authenticating: a wrong `binding_index` cannot forge anything — the verifier reads
that exact leaf and checks it is signed by the pinned identity root **and** authorizes
the attestation's `SignerPubKey`, so a bad pointer simply fails to resolve.

### 9.2 Second pinned anchor — the identity root

The verifier pins the HII **identity-root public key(s)** (hex Ed25519, published in
**§11**), separately from the checkpoint key, and accepts a *set* for rotation (bindings
issued by a rotated-out root stay verifiable, optionally up to a cutoff).

### 9.3 Procedure

Given the attestation and `binding_index`:

1. Fetch + verify the checkpoint (§8.2) → tree `size`, `root`.
2. If `binding_index ≥ size`, the binding is not committed — unresolved.
3. Read the binding leaf at `binding_index` from the entry bundle that holds it
   (bundle `binding_index / 256`, offset `binding_index % 256`).
4. **Prove the binding leaf is included** (§8.3) — a binding that is not committed in
   the log is not trusted, even if validly signed.
5. Decode it as an `IdentityBinding`; verify `IssuerSignature` against a pinned
   identity root.
6. Accept only if it **authorizes the attestation's `SignerPubKey`** and its
   `ValidFrom ≤ Attestation.SubmittedAt`. When a key has several bindings, the one with
   the greatest `ValidFrom` not after `SubmittedAt` wins.

The result reports the `CreatorID`, the `KeyType` (HII-custodial vs self-managed), and
that the binding was proven included. The hosted verifier exposes this as
`cocVerifyIdentity(leafB64, bindingIndex, readBaseURL, origin, checkpointVkey, identityRootsHex)`.

### 9.4 Semantics and scope

Resolution is **effective-at-submission**: provenance verifies a historical event, so
the binding in force at the attestation's `SubmittedAt` is the authoritative one. "Is
this key valid *now* / has it been revoked" is a different, current-status question and
is **out of scope**. Likewise, resolving a **bare signing key with no receipt**, or
proving **no binding exists** for a key (non-membership), is not covered here — that
needs a verifiable key→binding map (key-transparency), a **future** capability,
deliberately not built while records carry their own binding.

The same framing governs **certification status**. A leaf attests that HII made a
statement at time T; it does not assert that HII still stands behind it. An entry
whose certification was later rejected therefore remains a correct historical
record, and the log is not wrong to contain it. What must not happen is a verifier
reporting such an entry as plainly verified — that is a presentation error, not a
log error, and §12 specifies how to avoid it.

## 10. Versioning

This spec is **v1.1**. Revision 1.1 adds the `StatusAnchor` leaf (§3.3) and
revocation status (§12).

Leaf kinds are **additive** and not a breaking change: every leaf written under v1
decodes unchanged, and a v1 reader skips unrecognised kinds. The **verifier verdict
is** a breaking change — results now carry `VERIFIED` / `WITHDRAWN` / `INDETERMINATE`
rather than a bare pass, and a consumer reading only a boolean will over-claim on a
withdrawn record. That was the point of the change, so it is deliberate rather than
incidental.

The v1 content rules below are unchanged, matching `AlgorithmID` values `simhash64-v1` (canonical text),
`simhash-text-v1` (legacy text), and `phash-dct-64` (image). Any change to normalization,
tokenization, hashing, bit ordering, thresholds, or the leaf wire format is a **breaking
change** to this contract: it requires a new `AlgorithmID` (and a new spec revision),
never an in-place edit. Stored leaves keep verifying against the version named in their
`AlgorithmID`. `ExactHash` is accompanied by `ExactAlg` (`blake3` default, or `sha256`);
adding a new exact-hash algorithm is likewise a versioned change.

## 11. Trust anchors

Sections 8 and 9 require anchors that a verifier **pins** rather than reads from a
response. They are published as `config.json` on each environment's verifier
distribution, which is also the log's read base URL:

```
GET <read base URL>/config.json
{"origin": "...", "vkey": "...", "idRoot": "...", "baseUrl": ""}
```

`baseUrl` is empty by convention: the hosted verifier is served from the same
distribution as the read path, so it defaults to its own origin. A third-party verifier
substitutes the read base URL below.

### 11.1 Production

| | |
|---|---|
| read base URL | `https://d3kztzkiozolaa.cloudfront.net` |
| `origin` | `chain.humancreator.com` |
| `vkey` | `chain.humancreator.com+5a6e428e+AW3IP9XX0NZXoNfAeTY7Q4t4skSULvhfFAIJBzaEtv9y` |
| `idRoot` | `bc0035e0c7f441a5673fae1c4d5b02dfef460b61eeda535a3c8ac3ed624ff0df` |

### 11.2 Development

| | |
|---|---|
| read base URL | `https://d2nocngkolfsh0.cloudfront.net` |
| `origin` | `chain-of-creation` |
| `vkey` | `chain-of-creation+5a24a178+AVdcdlg+PJyuS+QRkxACp1+Osfgq29yoZO5jHJvRxwY7` |
| `idRoot` | `48b0ef7bcfd7af6811518397c562382c4841cf7a0c4f86124bc1a46a1e3355a1` |

### 11.3 The origin is a name, not a URL

**`origin` is the checkpoint's note name and is NOT the read endpoint.** In production it
*looks* like a hostname — `chain.humancreator.com` — but that host serves the submit API,
not the tlog-tiles read path, and a verifier that derives a URL from it will fail to
connect. Always fetch `/checkpoint` and `/tile/...` from the read base URL above.

### 11.4 Fetching the anchors is a bootstrap, not a verification

Reading `config.json` over TLS establishes the anchors on first use; from then on they
must be **pinned**. A verifier that re-fetches them per verification has replaced
cryptographic pinning with trust in whoever serves that file, and gains nothing over
trusting HII's API directly. Pin the values; treat a change as an event to investigate.

### 11.5 Witnessing status

At the time of writing both logs report **zero witness cosignatures**. Checkpoint
signature verification against the pinned key therefore proves the log's own commitment,
but split-view/equivocation protection is **not** yet in force (§8.2, §8.4). A verifier
should report this rather than imply otherwise.

## 12. Revocation and status

A transparency log is append-only, so HII cannot withdraw a record by deleting it.
Withdrawal is expressed as an **additional statement about** a leaf, never a
mutation of it.

### 12.1 The status artifact

HII publishes a JSON document listing withdrawn attestation leaves, addressed by
version at `<read base URL>/status/v<N>.json`. Being version-addressed, each is
immutable and may be cached indefinitely.

```json
{"issued_at":<u64 ms>,"log_size_at_issue":<u64>,"schema":1,"version":<u64>,
 "withdrawn":[{"leaf_hash":"<base64 32B>","reason":"<enum>","withdrawn_at":<u64 ms>}]}
```

`leaf_hash` is the **BLAKE3 `LeafHash`** — the content hash over the marshaled leaf
that §3.1 field 5 uses for chaining. It is **not** the RFC6962 tree leaf hash of
§8.3; the two are deliberately distinct and must not be interchanged.

`reason` is a coarse enum (`certification_rejected`, `certification_withdrawn`,
`work_deleted`) and carries no case detail.

A verifier **MUST** hash the artifact bytes **exactly as received** and **MUST NOT**
re-serialise the JSON before hashing.

### 12.2 Discovery

The newest `StatusAnchor` (§3.3) in the log is authoritative. A hint at
`<read base URL>/status/latest.json` (`{"version":N,"anchor_index":I}`) may be used
as a **starting point only**; it is untrusted.

A verifier:

1. Fetches and verifies the checkpoint (§8.2) → tree `size`.
2. Scans entry bundles from the hinted index to `size` for `kind = 3` leaves,
   taking the one with the greatest `ArtifactVersion` whose `IssuerSignature`
   verifies against a **pinned** identity root (§11). Scanning to the tip — rather
   than trusting the hint — is what prevents a stale or dishonest hint from
   concealing a newer anchor.
3. If the hint is missing, unparseable, out of range, or names a leaf that is not a
   `StatusAnchor`, it **MUST** fall back to scanning from index 0. It **MUST NOT**
   treat a bad hint as evidence that no status exists.

Cost is one bundle fetch per 256 leaves scanned.

### 12.3 Verdicts — normative

A verifier reports one of `VERIFIED`, `WITHDRAWN`, `INDETERMINATE`.

- A verifier **MUST** perform status resolution before reporting `VERIFIED`.
- If no `StatusAnchor` exists anywhere in the log, no status has been published and
  `VERIFIED` is permitted.
- If an anchor exists but its artifact cannot be fetched, cannot be parsed, or its
  BLAKE3 hash does not equal the anchor's `ArtifactHash`, the verifier **MUST**
  report `INDETERMINATE` and **MUST NOT** report `VERIFIED`.
- If an anchor exists but none verifies against a pinned identity root, the verifier
  **MUST** report `INDETERMINATE`. "Cannot check" is not "nothing to check".
- If the leaf appears in the withdrawn set, the verifier **MUST** report `WITHDRAWN`.

Structural findings — signature validity and proven inclusion — remain true and
**SHOULD** still be reported for a withdrawn entry. They are facts about what was
logged; only the verdict speaks to whether HII still stands behind it.

Failing closed here is deliberate. A verifier that downgraded an unreachable
artifact to `VERIFIED` would let anyone who can block one request suppress every
revocation, which is the failure mode that made OCSP soft-fail ineffective.

### 12.4 What this does and does not guarantee

Publishing revocation **in the log** means a withdrawal is as tamper-evident as the
entries it qualifies: HII cannot retract or backdate one without equivocating about
something the log commits to. Consequently a third party can **disprove** a false
`VERIFIED` claim by exhibiting the anchor and artifact.

It does **not** compel anyone. No protocol can force a verifier to perform a check,
and an implementation that skips §12.2 is indistinguishable from one that ran it and
found nothing. This specification therefore reserves the term: an implementation that
does not perform status resolution is **not a conforming verifier** and its output
must not be described as verification under this spec. The §7 revocation vector makes
that testable.

Readers should also note that the most likely route to a stale claim in practice is
not a non-conforming verifier at all, but a **frozen artefact** — a screenshot, badge
image, or PDF asserting a past verification to someone who never runs a verifier.
Nothing in this specification addresses that; it is a property of how a result is
presented, not of how it is computed.

## Appendix A. Implementation index (internal)

The sections above deliberately contain no source-tree paths: this document is published
externally, and a reader outside HII cannot open them. The mapping is preserved here for
HII engineers.

| Spec section | Implementation |
|---|---|
| §2 Encoding primitives | `internal/leaf/codec.go` |
| §3.1 Attestation | `internal/leaf/attestation.go` |
| §3.2 IdentityBinding | `internal/leaf/binding.go` |
| §6.1 `simhash-text-v1` | `internal/fuzzy/simhash.go` |
| §6.2 `phash-dct-64` | `internal/fuzzy/phash.go` |
| §6.3 `simhash64-v1` | `internal/fuzzy/simhash64.go` |
| §7 Golden vectors | `spec/simhash64-vectors.json`, `internal/fuzzy/golden_test.go`, `internal/fuzzy/testdata/`, `internal/status/golden_test.go` |
| §8 Log inclusion | `pkg/cocverify/inclusion.go` |
| §9 Identity resolution | `pkg/cocverify/identity.go` |
| §12 Revocation and status | `internal/leaf/status.go`, `internal/status/`, `pkg/cocverify/status.go` |
| §11 Trust anchors | `cmd/hiipub` derives them; served as `config.json` |

**When editing this document, keep it publication-ready:** put source paths here, not in
the body. The published HTML is generated verbatim from this file
(`customer-app/scripts/build-verification-spec-html.py`), so anything added to the body
ships to the public page.
