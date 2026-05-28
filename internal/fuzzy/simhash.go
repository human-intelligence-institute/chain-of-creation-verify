package fuzzy

import (
	"encoding/binary"
	"hash/fnv"
	"math/bits"
	"strings"
	"unicode"
)

// simHashText is a 64-bit SimHash over frequency-weighted word tokens. It is
// robust to whitespace, casing, and small edits: changing a few tokens flips
// only a few fingerprint bits, so similar documents stay close in Hamming space.
type simHashText struct{}

// NewSimHashText returns the text fuzzy hasher (algorithm id "simhash-text-v1").
func NewSimHashText() Verifier { return simHashText{} }

func (simHashText) ID() string { return "simhash-text-v1" }

func (simHashText) Digest(media []byte) ([]byte, error) {
	weights := [64]int64{}
	for tok, count := range tokenize(media) {
		h := fnv.New64a()
		_, _ = h.Write([]byte(tok))
		sum := h.Sum64()
		for i := 0; i < 64; i++ {
			if sum&(1<<uint(i)) != 0 {
				weights[i] += int64(count)
			} else {
				weights[i] -= int64(count)
			}
		}
	}
	var fp uint64
	for i := 0; i < 64; i++ {
		if weights[i] > 0 {
			fp |= 1 << uint(i)
		}
	}
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, fp)
	return out, nil
}

func (simHashText) Distance(a, b []byte) (float64, error) {
	if len(a) != 8 || len(b) != 8 {
		return 0, ErrDigestLength
	}
	d := bits.OnesCount64(binary.BigEndian.Uint64(a) ^ binary.BigEndian.Uint64(b))
	return float64(d) / 64.0, nil
}

// DefaultThreshold allows up to ~9 differing bits — comfortably absorbs
// reformatting and minor edits while rejecting unrelated text.
func (simHashText) DefaultThreshold() float64 { return 0.15 }

// tokenize lowercases and splits on non-alphanumeric runes, returning token
// counts. Frequency weighting makes the fingerprint reflect dominant terms.
func tokenize(media []byte) map[string]int {
	counts := map[string]int{}
	fields := strings.FieldsFunc(string(media), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	for _, f := range fields {
		counts[strings.ToLower(f)]++
	}
	return counts
}
