// Command gencorpus writes the frozen leaf corpus under
// pkg/cocverify/testdata/corpus — complete, signed leaves with their expected
// verification results, one directory per case.
//
// The corpus exists because every other test in this repository builds its own
// input with the same code it is testing. Reorder a field in the encoder, change
// a signing domain string, or drop a legacy algorithm from the registry, and
// those tests stay green while every leaf already written to a transparency log
// stops verifying. Only bytes that no test regenerates can catch that.
//
// So this generator is deliberately awkward to re-run: it REFUSES to overwrite a
// case directory that already exists. Adding an eleventh case must not be able to
// silently rewrite the first ten. If a case's expectations no longer hold, that is
// the signal the corpus was built to raise — a breaking change needing a new
// algorithm id or schema version, never a regeneration.
//
// All keys here are throwaway values derived from fixed seeds committed in this
// file. Nothing in the corpus touches HII's production key material, and the
// identity root below vouches for nothing.
//
// Usage (from the repository root):
//
//	go run ./cmd/gencorpus
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"log"
	"os"
	"path/filepath"

	"github.com/human-intelligence-institute/chain-of-creation-verify/pkg/cocverify"
	"github.com/human-intelligence-institute/chain-of-creation-verify/pkg/fuzzy"
	"github.com/human-intelligence-institute/chain-of-creation-verify/pkg/leaf"
)

// Fixed seeds. Deterministic so a reader can re-derive every public key in the
// corpus from this file alone, and confirm no production key was involved.
var (
	signerSeed = []byte("coc-corpus-signer-seed-000000001")
	issuerSeed = []byte("coc-corpus-issuer-seed-000000001")
)

// Fixed timestamp: 2026-09-20T00:00:00Z in unix milliseconds. A wall clock here
// would make the corpus unreproducible for no benefit.
const submittedAt = 1789603200000

// caseFile is the on-disk description of one frozen case. It is written once,
// beside the leaf bytes it describes, and read back verbatim by corpus_test.go.
type caseFile struct {
	Name string `json:"name"`
	// Why records what breaking change this case is positioned to catch. It is
	// for the human reading a red test, not for the test itself.
	Why    string               `json:"why"`
	Leaf   string               `json:"leaf"`
	Media  string               `json:"media,omitempty"`
	Text   string               `json:"text,omitempty"`
	Expect cocverify.LeafResult `json:"expect"`
}

// blob is one media file written alongside a case.
type blob struct {
	name  string
	bytes []byte
}

func main() {
	dir := flag.String("dir", filepath.Join("pkg", "cocverify", "testdata", "corpus"), "corpus directory")
	flag.Parse()

	signer := ed25519.NewKeyFromSeed(signerSeed)
	issuer := ed25519.NewKeyFromSeed(issuerSeed)

	article := []byte("The chain of creation records who made a work and when, " +
		"not how it was made. An exact match proves the file is the one certified. " +
		"A fuzzy match says only that the content is consistent with it.\n")
	edited := []byte("The chain of creation records who made a work and when, " +
		"not how it was produced. An exact match proves the file is the one certified. " +
		"A fuzzy match says only that the content is consistent with it.\n")
	unrelated := []byte("Tessera stores entry bundles under tile paths, and a checkpoint " +
		"names the tree size and root hash that the inclusion proof is checked against.\n")
	// A stand-in for a container format (.docx and friends) whose raw bytes are
	// not the text a digest is computed over. Exact matching must fail here while
	// fuzzy matching on the extracted text succeeds — the real-world case that
	// produced the 93.8% comparison in HII's own smoke tests.
	container := append([]byte("PK\x03\x04container-wrapper\x00"), article...)

	photo := structuredPNG()
	reencoded := reencodeJPEG(photo)
	brightened := brightenPNG(photo, 18)
	nudged := structuredPNGAt(83, 50, 28)
	different := differentPNG()

	cases := []struct {
		name  string
		why   string
		build func() (rawLeaf []byte, media, text []byte, blobs []blob)
	}{
		{
			name: "simhash64-text-exact",
			why:  "the current default text algorithm, exact and fuzzy agreeing on the certified file",
			build: func() ([]byte, []byte, []byte, []blob) {
				a := attestation(signer, "simhash64-v1", leaf.MediaText, article, 0)
				return a.Marshal(), article, nil, []blob{{"media.txt", article}}
			},
		},
		{
			name: "simhash64-extracted-text",
			why:  "a container format: raw bytes are not the digested text, so exact must fail while fuzzy holds at distance 0",
			build: func() ([]byte, []byte, []byte, []blob) {
				a := attestation(signer, "simhash64-v1", leaf.MediaText, article, 1)
				return a.Marshal(), container, article,
					[]blob{{"media.bin", container}, {"text.txt", article}}
			},
		},
		{
			name: "simhash64-edited",
			why:  "a lightly edited candidate: the frozen distance is what a change to normalization or shingling would move",
			build: func() ([]byte, []byte, []byte, []blob) {
				a := attestation(signer, "simhash64-v1", leaf.MediaText, article, 2)
				return a.Marshal(), edited, nil, []blob{{"media.txt", edited}}
			},
		},
		{
			name: "simhash64-unrelated",
			why:  "an unrelated candidate must fail both checks — a corpus of only passing cases proves nothing",
			build: func() ([]byte, []byte, []byte, []blob) {
				a := attestation(signer, "simhash64-v1", leaf.MediaText, article, 3)
				return a.Marshal(), unrelated, nil, []blob{{"media.txt", unrelated}}
			},
		},
		{
			name: "simhash-text-v1-legacy",
			why:  "the deprecated text algorithm id must stay resolvable: this is the 2036 promise, and the one case that catches quietly dropping an old format",
			build: func() ([]byte, []byte, []byte, []blob) {
				a := attestation(signer, "simhash-text-v1", leaf.MediaText, article, 0)
				return a.Marshal(), article, nil, []blob{{"media.txt", article}}
			},
		},
		{
			name: "phash-dct-64-exact",
			why:  "the image algorithm on the certified file; also pins the floating-point DCT, which could drift between native and wasm",
			build: func() ([]byte, []byte, []byte, []blob) {
				a := attestation(signer, "phash-dct-64", leaf.MediaPhoto, photo, 0)
				return a.Marshal(), photo, nil, []blob{{"media.png", photo}}
			},
		},
		{
			name: "phash-dct-64-reencoded",
			why:  "a JPEG re-encode: exact fails, perceptual match survives — the property pHash is chosen for",
			build: func() ([]byte, []byte, []byte, []blob) {
				a := attestation(signer, "phash-dct-64", leaf.MediaPhoto, photo, 1)
				return a.Marshal(), reencoded, nil, []blob{{"media.jpg", reencoded}}
			},
		},
		{
			name: "phash-dct-64-brightened",
			why:  "a global exposure change must come out at distance EXACTLY 0: the DC term is excluded from the median, so pHash is brightness-invariant by construction, and that invariance is a published property worth freezing",
			build: func() ([]byte, []byte, []byte, []blob) {
				a := attestation(signer, "phash-dct-64", leaf.MediaPhoto, photo, 2)
				return a.Marshal(), brightened, nil, []blob{{"media.png", brightened}}
			},
		},
		{
			name: "phash-dct-64-nudged",
			why:  "a small compositional edit: a NONZERO distance still under threshold — without it every passing phash case sits at 0 and a distance metric stuck at 0 would satisfy the whole corpus",
			build: func() ([]byte, []byte, []byte, []blob) {
				a := attestation(signer, "phash-dct-64", leaf.MediaPhoto, photo, 4)
				return a.Marshal(), nudged, nil, []blob{{"media.png", nudged}}
			},
		},
		{
			name: "phash-dct-64-different",
			why:  "a structurally different image must exceed the perceptual threshold — the image-side negative",
			build: func() ([]byte, []byte, []byte, []blob) {
				a := attestation(signer, "phash-dct-64", leaf.MediaPhoto, photo, 3)
				return a.Marshal(), different, nil, []blob{{"media.png", different}}
			},
		},
		{
			name: "unknown-algorithm",
			why:  "a leaf naming an algorithm this build does not know must degrade to a note, not a crash or a silent pass",
			build: func() ([]byte, []byte, []byte, []blob) {
				a := attestation(signer, "simhash64-v99", leaf.MediaText, article, 0)
				return a.Marshal(), article, nil, []blob{{"media.txt", article}}
			},
		},
		{
			name: "identity-binding",
			why:  "the second leaf kind's encoding and issuer-signature domain separation",
			build: func() ([]byte, []byte, []byte, []blob) {
				b := &leaf.IdentityBinding{
					CreatorID: "creator-corpus-1",
					KeyType:   leaf.KeyHIICustodial,
					ValidFrom: submittedAt,
				}
				copy(b.AuthorizedKey[:], signer.Public().(ed25519.PublicKey))
				b.Sign(issuer)
				return b.Marshal(), nil, nil, nil
			},
		},
		{
			name: "tampered-attestation",
			why:  "one flipped byte in the signed region must read as an invalid signature — the negative that gives the positives meaning",
			build: func() ([]byte, []byte, []byte, []blob) {
				a := attestation(signer, "simhash64-v1", leaf.MediaText, article, 0)
				raw := a.Marshal()
				// Flip the low bit of EventSeq, which signingPayload covers.
				// The leaf still decodes cleanly and reads as event 1 — the
				// renumbering an attacker would want — and only the signature
				// check gives it away.
				raw[28] ^= 0x01
				return raw, article, nil, []blob{{"media.txt", article}}
			},
		},
	}

	for _, c := range cases {
		caseDir := filepath.Join(*dir, c.name)
		if _, err := os.Stat(caseDir); err == nil {
			fmt.Printf("kept frozen: %s\n", c.name)
			continue
		} else if !os.IsNotExist(err) {
			log.Fatalf("%s: %v", c.name, err)
		}
		rawLeaf, media, text, blobs := c.build()
		got, err := cocverify.VerifyLeaf(rawLeaf, media, text)
		if err != nil {
			log.Fatalf("%s: verify: %v", c.name, err)
		}
		cf := caseFile{Name: c.name, Why: c.why, Leaf: "leaf.bin", Expect: got}
		for _, b := range blobs {
			switch {
			case bytes.Equal(b.bytes, text) && cf.Text == "":
				cf.Text = b.name
			case cf.Media == "":
				cf.Media = b.name
			}
		}
		if err := os.MkdirAll(caseDir, 0o755); err != nil {
			log.Fatalf("%s: %v", c.name, err)
		}
		write(filepath.Join(caseDir, "leaf.bin"), rawLeaf)
		for _, b := range blobs {
			write(filepath.Join(caseDir, b.name), b.bytes)
		}
		enc, err := json.MarshalIndent(cf, "", "  ")
		if err != nil {
			log.Fatalf("%s: %v", c.name, err)
		}
		write(filepath.Join(caseDir, "case.json"), append(enc, '\n'))
		fmt.Printf("wrote: %s (leaf_hash %s)\n", c.name, got.LeafHash)
	}
}

// attestation builds a signed attestation over media with the named algorithm.
// The fuzzy digest is computed by the algorithm itself, so the leaf is exactly
// what an HII certifier would have produced — except for an unknown id, where
// no digester exists and a fixed placeholder stands in.
func attestation(signer ed25519.PrivateKey, algID string, mt leaf.MediaType, media []byte, seq uint64) *leaf.Attestation {
	a := &leaf.Attestation{
		SchemaVersion: 1,
		EventSeq:      seq,
		EventType:     leaf.EventPublish,
		MediaType:     mt,
		AlgorithmID:   algID,
		ExactHash:     leaf.HashContent(media),
		ExactAlg:      "blake3",
		SubmittedAt:   submittedAt,
	}
	// A fixed, obviously synthetic work id.
	copy(a.WorkID[:], []byte{0xc0, 0x12, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(seq)})

	if v, err := fuzzy.Default().Verifier(algID); err == nil {
		d, err := v.Digest(media)
		if err != nil {
			log.Fatalf("digest %s: %v", algID, err)
		}
		a.FuzzyDigest = d
	} else {
		a.FuzzyDigest = []byte{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef}
	}
	a.Sign(signer)
	return a
}

// structuredPNG renders a deterministic 128x128 image with real low-frequency
// structure: four quadrants of distinct luminance plus an off-centre disc.
//
// ⚠️ A smooth gradient will NOT do here, though it is the obvious choice. pHash
// thresholds the low-frequency 8x8 DCT block against its own median with the DC
// term excluded — and a gradient puts nearly all its energy in DC, leaving the
// other coefficients in numerical noise where every bit is a coin flip that
// recompression re-flips. A 64x64 gradient measured 26 differing bits across a
// mere JPEG round-trip. Structure is what makes the digest mean anything.
//
// Generated rather than committed as an opaque binary so a reader can regenerate
// it and confirm the corpus contains no unexplained bytes.
func structuredPNG() []byte { return structuredPNGAt(80, 48, 28) }

// structuredPNGAt renders that scene with the disc at an arbitrary centre and
// radius, so a case can make a small compositional edit without changing
// anything else.
func structuredPNGAt(cx, cy, r int) []byte {
	const n = 128
	img := image.NewRGBA(image.Rect(0, 0, n, n))
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			var lum uint8
			switch {
			case x < n/2 && y < n/2:
				lum = 30
			case x >= n/2 && y < n/2:
				lum = 200
			case x < n/2 && y >= n/2:
				lum = 140
			default:
				lum = 70
			}
			dx, dy := float64(x-cx), float64(y-cy)
			if dx*dx+dy*dy < float64(r*r) {
				lum = 245
			}
			img.Set(x, y, color.RGBA{R: lum, G: lum, B: lum, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		log.Fatalf("png: %v", err)
	}
	return buf.Bytes()
}

// brightenPNG lifts every channel by delta, clamped. A global exposure change is
// the mildest real-world edit a perceptual hash is expected to absorb.
func brightenPNG(pngBytes []byte, delta int) []byte {
	src, err := png.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		log.Fatalf("decode png: %v", err)
	}
	b := src.Bounds()
	out := image.NewRGBA(b)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r, g, bl, a := src.At(x, y).RGBA()
			out.Set(x, y, color.RGBA{
				R: clamp8(int(r>>8) + delta),
				G: clamp8(int(g>>8) + delta),
				B: clamp8(int(bl>>8) + delta),
				A: uint8(a >> 8),
			})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, out); err != nil {
		log.Fatalf("png: %v", err)
	}
	return buf.Bytes()
}

func clamp8(v int) uint8 {
	if v < 0 {
		return 0
	}
	if v > 255 {
		return 255
	}
	return uint8(v)
}

// differentPNG renders an image with unrelated — but still ASYMMETRIC —
// low-frequency structure: a diagonal split with a bright rectangle off to one
// side.
//
// ⚠️ Perfectly repeating bands will NOT do, though they are the obvious "clearly
// a different picture". Horizontal bands have no horizontal frequency content at
// all, so 59 of the 63 non-DC coefficients land within 1e-6 of a median that is
// itself 3e-28 — numerically zero. pHash thresholds with a bare `c > med` and no
// tie tolerance, so each of those bits is decided by floating-point rounding, and
// the digest measurably DIFFERS between native Go and js/wasm (6d696d216d006d6f
// vs 796979097900797b). Real photographs never look like this; synthetic graphics
// can. See the note in the README.
func differentPNG() []byte {
	const n = 128
	img := image.NewRGBA(image.Rect(0, 0, n, n))
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			lum := uint8(40)
			if x+y/2 > 110 {
				lum = 175
			}
			if x > 14 && x < 54 && y > 82 && y < 116 {
				lum = 250
			}
			img.Set(x, y, color.RGBA{R: lum, G: lum, B: lum, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		log.Fatalf("png: %v", err)
	}
	return buf.Bytes()
}

// reencodeJPEG round-trips the PNG through lossy JPEG, producing a file with
// different bytes and near-identical low-frequency structure.
func reencodeJPEG(pngBytes []byte) []byte {
	img, err := png.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		log.Fatalf("decode png: %v", err)
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 75}); err != nil {
		log.Fatalf("jpeg: %v", err)
	}
	return buf.Bytes()
}

func write(path string, b []byte) {
	if err := os.WriteFile(path, b, 0o644); err != nil {
		log.Fatalf("write %s: %v", path, err)
	}
}
