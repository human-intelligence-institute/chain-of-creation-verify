package fuzzy

// Golden vectors freeze the exact wire output of the published fuzzy algorithms.
// They are the machine-checkable half of docs/verification-spec.md: a third
// party re-implementing simhash-text-v1 or phash-dct-64 must reproduce these
// digests byte-for-byte (the spec lists the same values in a table). Changing a
// digest here is a breaking change to a public contract — it requires a new
// AlgorithmID/version, never an in-place edit.
//
// Image vectors hash committed files in testdata/ so they are portable: anyone
// can fetch the file and confirm the digest without running our generator.

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func mustDigest(t *testing.T, v Verifier, b []byte) string {
	t.Helper()
	d, err := v.Digest(b)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	return hex.EncodeToString(d)
}

func TestGoldenSimHashText(t *testing.T) {
	v := NewSimHashText()
	cases := []struct {
		name, text, want string
	}{
		{"pangram", "The quick brown fox jumps over the lazy dog.", "cab7991c5475edee"},
		// Reformatting (case, runs of whitespace, tabs, trailing punctuation)
		// does not change the digest — same tokens, same fingerprint.
		{"reformat", "the   QUICK brown fox\tjumps over the lazy dog", "cab7991c5475edee"},
		{"tagline", "Provenance you can verify.", "3540200101864944"},
		// Combining marks + an astral emoji: pins UTF-8 tokenization (the emoji
		// is a non-letter rune and splits tokens; it contributes no token).
		{"unicode", "café déjà vu 🎨 naïve façade", "0c8d8f26ac712ca0"},
		// No tokens → all bit-weights are zero → all-zero fingerprint.
		{"empty", "", "0000000000000000"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := mustDigest(t, v, []byte(c.text)); got != c.want {
				t.Fatalf("simhash-text-v1(%q) = %s, want %s", c.text, got, c.want)
			}
		})
	}
}

// TestGoldenSimHash64 pins simhash64-v1 to the shared vector file that every
// client repo (customer-app, word-certifier, gdoc-certifier) also reproduces.
// Reading the same spec/simhash64-vectors.json — rather than hardcoding a second
// copy here — makes drift between the spec and this implementation impossible.
func TestGoldenSimHash64(t *testing.T) {
	raw, err := os.ReadFile("../../spec/simhash64-vectors.json")
	if err != nil {
		t.Fatalf("read shared vectors: %v", err)
	}
	var spec struct {
		AlgorithmID string `json:"algorithm_id"`
		Vectors     []struct {
			Name   string `json:"name"`
			Input  string `json:"input"`
			Digest string `json:"digest"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("parse shared vectors: %v", err)
	}
	v := NewSimHash64()
	if v.ID() != spec.AlgorithmID {
		t.Fatalf("registry id %q != shared vectors algorithm_id %q", v.ID(), spec.AlgorithmID)
	}
	if len(spec.Vectors) == 0 {
		t.Fatal("no vectors in spec/simhash64-vectors.json")
	}
	for _, c := range spec.Vectors {
		t.Run(c.Name, func(t *testing.T) {
			if got := mustDigest(t, v, []byte(c.Input)); got != c.Digest {
				t.Fatalf("simhash64-v1(%q) = %s, want %s", c.Input, got, c.Digest)
			}
		})
	}
}

func TestGoldenPHashImage(t *testing.T) {
	v := NewPHashImage()
	cases := []struct {
		name, file, want string
	}{
		{"gradient-a-png", "gradient-a.png", "f8f8f8f8f8070605"},
		// Same source image, lossy JPEG (q40): the perceptual hash is unchanged,
		// so the digest matches gradient-a.png exactly (distance 0).
		{"gradient-a-jpg", "gradient-a.jpg", "f8f8f8f8f8070605"},
		{"gradient-b-png", "gradient-b.png", "2d126d926d2d936d"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, err := os.ReadFile("testdata/" + c.file)
			if err != nil {
				t.Fatal(err)
			}
			if got := mustDigest(t, v, b); got != c.want {
				t.Fatalf("phash-dct-64(%s) = %s, want %s", c.file, got, c.want)
			}
		})
	}
}
