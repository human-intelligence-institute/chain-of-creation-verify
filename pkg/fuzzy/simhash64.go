package fuzzy

import (
	"crypto/sha256"
	"encoding/binary"
	"math/bits"
	"regexp"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// simHash64 is the canonical content fingerprint HII certifiers compute
// client-side and record on the ledger as "simhash64-v1": a 64-bit Charikar
// SimHash over normalized word 3-shingles, with a SHA-256 feature hash.
//
// This algorithm is a PUBLISHED CONTRACT specified in docs/verification-spec.md
// (§6.3) and frozen by golden vectors shared with the TS clients
// (spec/simhash64-vectors.json, asserted here and in each client's test suite).
// The feature hash is SHA-256 — chosen over MurmurHash3 precisely because
// MurmurHash3 has multiple incompatible variants (x86_32 vs x64_128, seed/sign
// handling) while SHA-256 has exactly one definition in every language, so a
// third party reproduces the digest with only their standard library. Any change
// to normalization, shingling, the feature hash, bit order, or threshold is a
// breaking change: bump the id, do not edit in place.
type simHash64 struct{}

// NewSimHash64 returns the canonical text fuzzy hasher (id "simhash64-v1").
func NewSimHash64() Verifier { return simHash64{} }

func (simHash64) ID() string { return "simhash64-v1" }

// simhash64Shingle is the word k-shingle size (§6.3). A change here is a breaking
// change to the published contract.
const simhash64Shingle = 3

// punctNorm maps the curly quotes and long dashes to their ASCII forms before
// the non-alphanumeric strip, matching the TS clients' normalize() byte-for-byte.
var punctNorm = strings.NewReplacer(
	"‘", "'", "’", "'", "‚", "'", "‛", "'", // ‘ ’ ‚ ‛
	"“", "\"", "”", "\"", "„", "\"", "‟", "\"", // “ ” „ ‟
	"–", "-", "—", "-", "―", "-", // – — ―
)

// nonAlnumRun matches any run of characters that are neither a Unicode letter
// nor a Unicode digit — collapsed to a single space during normalization.
var nonAlnumRun = regexp.MustCompile(`[^\p{L}\p{N}]+`)

// normalize strips cross-format noise so that the same text extracted from
// different file formats produces the same tokens. It MUST match the TS clients'
// normalize() exactly (NFKC → lowercase → punctuation folding → non-alnum runs to
// a single space → trim).
func simhash64Normalize(text string) string {
	s := norm.NFKC.String(text)
	s = strings.ToLower(s)
	s = punctNorm.Replace(s)
	s = nonAlnumRun.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

// simhash64Tokens returns the normalized whitespace-separated tokens.
func simhash64Tokens(text string) []string {
	s := simhash64Normalize(text)
	if s == "" {
		return nil
	}
	return strings.Split(s, " ")
}

// simhash64Shingles joins every simhash64Shingle consecutive tokens with a single
// space. Fewer than that many tokens yields one shingle of all tokens (or none
// when there are no tokens), matching the TS clients.
func simhash64Shingles(tokens []string) []string {
	if len(tokens) < simhash64Shingle {
		if len(tokens) == 0 {
			return nil
		}
		return []string{strings.Join(tokens, " ")}
	}
	out := make([]string, 0, len(tokens)-simhash64Shingle+1)
	for i := 0; i+simhash64Shingle <= len(tokens); i++ {
		out = append(out, strings.Join(tokens[i:i+simhash64Shingle], " "))
	}
	return out
}

func (simHash64) Digest(media []byte) ([]byte, error) {
	feats := simhash64Shingles(simhash64Tokens(string(media)))
	var acc [64]int64
	for _, f := range feats {
		sum := sha256.Sum256([]byte(f))
		feature := binary.BigEndian.Uint64(sum[:8])
		for i := 0; i < 64; i++ {
			if feature&(1<<uint(i)) != 0 {
				acc[i]++
			} else {
				acc[i]--
			}
		}
	}
	var fp uint64
	for i := 0; i < 64; i++ {
		if acc[i] > 0 {
			fp |= 1 << uint(i)
		}
	}
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, fp)
	return out, nil
}

func (simHash64) Distance(a, b []byte) (float64, error) {
	if len(a) != 8 || len(b) != 8 {
		return 0, ErrDigestLength
	}
	d := bits.OnesCount64(binary.BigEndian.Uint64(a) ^ binary.BigEndian.Uint64(b))
	return float64(d) / 64.0, nil
}

// DefaultThreshold allows up to ~9 differing bits. NOTE: the client-vs-verifier
// extraction-drift budget (Office.js vs mammoth/pdfjs) is measured by the
// calibration corpus in the client test suites; if that drift is material this
// threshold should be re-derived as drift_headroom + edit_tolerance.
func (simHash64) DefaultThreshold() float64 { return 0.15 }
