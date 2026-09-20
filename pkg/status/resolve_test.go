package status

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/human-intelligence-institute/chain-of-creation-verify/pkg/leaf"
	"github.com/zeebo/blake3"
)

var (
	withdrawnLeaf = [32]byte{0x11, 0x22, 0x33}
	onlyInV2      = [32]byte{0x44, 0x55, 0x66}
)

// fakeFetcher serves canned bundles and artifacts.
type fakeFetcher struct {
	hint      *Hint
	hintErr   error
	bundles   map[uint64][][]byte // bundle index -> raw leaves
	artifacts map[uint64][]byte   // artifact version -> raw bytes
	roots     [][32]byte
}

func (f *fakeFetcher) FetchHint() (*Hint, error) { return f.hint, f.hintErr }

func (f *fakeFetcher) FetchBundle(i uint64) ([][]byte, error) {
	b, ok := f.bundles[i]
	if !ok {
		return nil, errNotFound
	}
	return b, nil
}

func (f *fakeFetcher) FetchArtifact(v uint64) ([]byte, error) {
	raw, ok := f.artifacts[v]
	if !ok {
		return nil, errNotFound
	}
	return raw, nil
}

// artifactJSON builds canonical artifact bytes (sorted keys, compact) listing
// the given leaves as withdrawn. Built as a literal string so the test controls
// the exact bytes that get hashed.
func artifactJSON(version uint64, leaves ...[32]byte) []byte {
	entries := ""
	for i, lh := range leaves {
		if i > 0 {
			entries += ","
		}
		entries += fmt.Sprintf(
			`{"leaf_hash":"%s","reason":"certification_rejected","withdrawn_at":1786000000001}`,
			base64.StdEncoding.EncodeToString(lh[:]),
		)
	}
	return []byte(fmt.Sprintf(
		`{"issued_at":1786000000000,"log_size_at_issue":9,"schema":1,"version":%d,"withdrawn":[%s]}`,
		version, entries,
	))
}

// signedAnchor returns the marshaled StatusAnchor leaf committing to raw.
func signedAnchor(priv ed25519.PrivateKey, version uint64, raw []byte) []byte {
	a := &leaf.StatusAnchor{
		SchemaVersion:   1,
		ArtifactVersion: version,
		ArtifactHash:    leaf.Hash(blake3.Sum256(raw)),
		IssuedAt:        1786000000000,
	}
	a.Sign(priv)
	return a.Marshal()
}

// newFetcherWithAnchor builds a fetcher whose bundle 0 holds one signed anchor
// for `version`, with a matching artifact withdrawing `lh`.
func newFetcherWithAnchor(t *testing.T, version uint64, lh [32]byte) *fakeFetcher {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	raw := artifactJSON(version, lh)
	return &fakeFetcher{
		hint:      &Hint{Version: version, AnchorIndex: 0},
		bundles:   map[uint64][][]byte{0: {signedAnchor(priv, version, raw)}},
		artifacts: map[uint64][]byte{version: raw},
		roots:     [][32]byte{[32]byte(pub)},
	}
}

// newFetcherWithTwoAnchors places anchor v1 at index 0 and v2 at index 1, where
// only v2 withdraws onlyInV2.
func newFetcherWithTwoAnchors(t *testing.T) *fakeFetcher {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	raw1 := artifactJSON(1, withdrawnLeaf)
	raw2 := artifactJSON(2, withdrawnLeaf, onlyInV2)
	return &fakeFetcher{
		hint: &Hint{Version: 2, AnchorIndex: 1},
		bundles: map[uint64][][]byte{0: {
			signedAnchor(priv, 1, raw1),
			signedAnchor(priv, 2, raw2),
		}},
		artifacts: map[uint64][]byte{1: raw1, 2: raw2},
		roots:     [][32]byte{[32]byte(pub)},
	}
}

func TestNoAnchorAnywhereIsVerified(t *testing.T) {
	f := &fakeFetcher{bundles: map[uint64][][]byte{0: {}}}
	v, _, err := Resolve(f, [32]byte{0x01}, 0, nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v != VerdictVerified {
		t.Fatalf("verdict = %v, want VERIFIED when no anchor has ever been published", v)
	}
}

func TestWithdrawnLeafIsWithdrawn(t *testing.T) {
	f := newFetcherWithAnchor(t, 1, withdrawnLeaf)
	v, e, err := Resolve(f, withdrawnLeaf, 1, f.roots)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v != VerdictWithdrawn {
		t.Fatalf("verdict = %v, want WITHDRAWN", v)
	}
	if e == nil || e.Reason != "certification_rejected" {
		t.Fatalf("entry = %+v", e)
	}
}

func TestNotWithdrawnLeafIsVerified(t *testing.T) {
	f := newFetcherWithAnchor(t, 1, withdrawnLeaf)
	v, _, err := Resolve(f, [32]byte{0xab}, 1, f.roots)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v != VerdictVerified {
		t.Fatalf("verdict = %v, want VERIFIED for a leaf absent from the withdrawn set", v)
	}
}

func TestUnreachableArtifactIsIndeterminate(t *testing.T) {
	f := newFetcherWithAnchor(t, 1, withdrawnLeaf)
	delete(f.artifacts, 1) // anchor exists, artifact does not
	v, _, err := Resolve(f, withdrawnLeaf, 1, f.roots)
	if err != nil {
		t.Fatalf("Resolve returned a hard error; want a verdict: %v", err)
	}
	if v != VerdictIndeterminate {
		t.Fatalf("verdict = %v, want INDETERMINATE", v)
	}
}

func TestArtifactHashMismatchIsIndeterminate(t *testing.T) {
	f := newFetcherWithAnchor(t, 1, withdrawnLeaf)
	f.artifacts[1] = append(f.artifacts[1], ' ') // byte-level change breaks the hash
	v, _, err := Resolve(f, withdrawnLeaf, 1, f.roots)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v != VerdictIndeterminate {
		t.Fatalf("verdict = %v, want INDETERMINATE on hash mismatch", v)
	}
}

// The security-critical case: a hint naming an OLD anchor must not hide a newer
// one appended after it.
func TestStaleHintDoesNotHideNewerAnchor(t *testing.T) {
	f := newFetcherWithTwoAnchors(t)
	f.hint = &Hint{Version: 1, AnchorIndex: 0} // stale: v2 also lives in the log
	v, _, err := Resolve(f, onlyInV2, 2, f.roots)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v != VerdictWithdrawn {
		t.Fatalf("verdict = %v, want WITHDRAWN — the stale hint suppressed a newer anchor", v)
	}
}

func TestMissingHintFallsBackToFullScan(t *testing.T) {
	f := newFetcherWithAnchor(t, 1, withdrawnLeaf)
	f.hint, f.hintErr = nil, errNotFound
	v, _, err := Resolve(f, withdrawnLeaf, 1, f.roots)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v != VerdictWithdrawn {
		t.Fatalf("verdict = %v, want WITHDRAWN — a missing hint must fall back to a full scan", v)
	}
}

func TestAnchorWithUnpinnedIssuerIsIgnored(t *testing.T) {
	f := newFetcherWithAnchor(t, 1, withdrawnLeaf)
	// An anchor signed by a key the verifier does not pin must not be trusted.
	// With no trusted anchor remaining, there is nothing to check.
	v, _, err := Resolve(f, withdrawnLeaf, 1, [][32]byte{{0xde, 0xad}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v == VerdictWithdrawn {
		t.Fatal("verdict = WITHDRAWN from an anchor signed by an unpinned key")
	}
}

func TestTamperedAnchorIsIgnored(t *testing.T) {
	f := newFetcherWithAnchor(t, 1, withdrawnLeaf)
	raw := f.bundles[0][0]
	raw[len(raw)-1] ^= 0xff // corrupt the signature
	v, _, err := Resolve(f, withdrawnLeaf, 1, f.roots)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v == VerdictWithdrawn {
		t.Fatal("a signature-invalid anchor was trusted")
	}
}
