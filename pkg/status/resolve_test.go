package status

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
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
	v, _, reason, cause := Resolve(f, [32]byte{0x01}, 0, nil)
	if cause != nil {
		t.Fatalf("Resolve cause: %v", cause)
	}
	if reason != ReasonNone {
		t.Fatalf("reason = %q, want empty on a definite verdict", reason)
	}
	if v != VerdictVerified {
		t.Fatalf("verdict = %v, want VERIFIED when no anchor has ever been published", v)
	}
}

func TestWithdrawnLeafIsWithdrawn(t *testing.T) {
	f := newFetcherWithAnchor(t, 1, withdrawnLeaf)
	v, e, reason, cause := Resolve(f, withdrawnLeaf, 1, f.roots)
	if cause != nil {
		t.Fatalf("Resolve cause: %v", cause)
	}
	if reason != ReasonNone {
		t.Fatalf("reason = %q, want empty on a definite verdict", reason)
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
	v, _, reason, cause := Resolve(f, [32]byte{0xab}, 1, f.roots)
	if cause != nil {
		t.Fatalf("Resolve cause: %v", cause)
	}
	if reason != ReasonNone {
		t.Fatalf("reason = %q, want empty on a definite verdict", reason)
	}
	if v != VerdictVerified {
		t.Fatalf("verdict = %v, want VERIFIED for a leaf absent from the withdrawn set", v)
	}
}

func TestUnreachableArtifactIsIndeterminate(t *testing.T) {
	f := newFetcherWithAnchor(t, 1, withdrawnLeaf)
	delete(f.artifacts, 1) // anchor exists, artifact does not
	v, _, reason, cause := Resolve(f, withdrawnLeaf, 1, f.roots)
	if v != VerdictIndeterminate {
		t.Fatalf("verdict = %v, want INDETERMINATE", v)
	}
	if reason != ReasonArtifactUnreachable {
		t.Fatalf("reason = %q, want %q", reason, ReasonArtifactUnreachable)
	}
	// The cause rides ALONGSIDE the verdict. A caller that treated it as a
	// failure would throw away a perfectly good fail-closed answer.
	if cause == nil {
		t.Fatal("cause = nil; a fetch failure must carry its underlying error for display")
	}
}

func TestArtifactHashMismatchIsIndeterminate(t *testing.T) {
	f := newFetcherWithAnchor(t, 1, withdrawnLeaf)
	f.artifacts[1] = append(f.artifacts[1], ' ') // byte-level change breaks the hash
	v, _, reason, _ := Resolve(f, withdrawnLeaf, 1, f.roots)
	if v != VerdictIndeterminate {
		t.Fatalf("verdict = %v, want INDETERMINATE on hash mismatch", v)
	}
	// The most serious reason in the set: corruption or equivocation, never a
	// local network problem. A UI must not soften this into "try again".
	if reason != ReasonArtifactHashMismatch {
		t.Fatalf("reason = %q, want %q", reason, ReasonArtifactHashMismatch)
	}
}

// The security-critical case: a hint naming an OLD anchor must not hide a newer
// one appended after it.
func TestStaleHintDoesNotHideNewerAnchor(t *testing.T) {
	f := newFetcherWithTwoAnchors(t)
	f.hint = &Hint{Version: 1, AnchorIndex: 0} // stale: v2 also lives in the log
	v, _, _, cause := Resolve(f, onlyInV2, 2, f.roots)
	if cause != nil {
		t.Fatalf("Resolve cause: %v", cause)
	}
	if v != VerdictWithdrawn {
		t.Fatalf("verdict = %v, want WITHDRAWN — the stale hint suppressed a newer anchor", v)
	}
}

func TestMissingHintFallsBackToFullScan(t *testing.T) {
	f := newFetcherWithAnchor(t, 1, withdrawnLeaf)
	f.hint, f.hintErr = nil, errNotFound
	v, _, _, cause := Resolve(f, withdrawnLeaf, 1, f.roots)
	if cause != nil {
		t.Fatalf("Resolve cause: %v", cause)
	}
	if v != VerdictWithdrawn {
		t.Fatalf("verdict = %v, want WITHDRAWN — a missing hint must fall back to a full scan", v)
	}
}

func TestAnchorWithUnpinnedIssuerIsIgnored(t *testing.T) {
	f := newFetcherWithAnchor(t, 1, withdrawnLeaf)
	// An anchor signed by a key the verifier does not pin must not be trusted.
	// With no trusted anchor remaining, there is nothing to check.
	v, _, reason, _ := Resolve(f, withdrawnLeaf, 1, [][32]byte{{0xde, 0xad}})
	if v == VerdictWithdrawn {
		t.Fatal("verdict = WITHDRAWN from an anchor signed by an unpinned key")
	}
	// Distinguishable from "no status was ever published", which is VERIFIED.
	// Confusing the two is the fail-open bug this whole package exists to avoid.
	if v != VerdictIndeterminate || reason != ReasonAnchorUntrusted {
		t.Fatalf("verdict/reason = %v/%q, want INDETERMINATE/%q", v, reason, ReasonAnchorUntrusted)
	}
}

func TestTamperedAnchorIsIgnored(t *testing.T) {
	f := newFetcherWithAnchor(t, 1, withdrawnLeaf)
	raw := f.bundles[0][0]
	raw[len(raw)-1] ^= 0xff // corrupt the signature
	v, _, reason, _ := Resolve(f, withdrawnLeaf, 1, f.roots)
	if v == VerdictWithdrawn {
		t.Fatal("a signature-invalid anchor was trusted")
	}
	if v != VerdictIndeterminate || reason != ReasonAnchorUntrusted {
		t.Fatalf("verdict/reason = %v/%q, want INDETERMINATE/%q", v, reason, ReasonAnchorUntrusted)
	}
}

// errBundleFetcher fails every bundle read, standing in for a log node that is
// unreachable rather than one that is misbehaving.
type errBundleFetcher struct{ fakeFetcher }

func (f *errBundleFetcher) FetchBundle(uint64) ([][]byte, error) {
	return nil, fmt.Errorf("dial tcp: connection refused")
}

func TestUnreadableBundleIsIndeterminateWithScanReason(t *testing.T) {
	f := &errBundleFetcher{}
	v, _, reason, cause := Resolve(f, withdrawnLeaf, 1, nil)
	if v != VerdictIndeterminate {
		t.Fatalf("verdict = %v, want INDETERMINATE — an unreadable bundle may hide a newer anchor", v)
	}
	if reason != ReasonAnchorScanFailed {
		t.Fatalf("reason = %q, want %q", reason, ReasonAnchorScanFailed)
	}
	// The whole point of carrying the cause: "connection refused" is local and
	// retryable, and nothing in the Reason alone could tell a user that.
	if cause == nil || !strings.Contains(cause.Error(), "connection refused") {
		t.Fatalf("cause = %v, want the underlying transport error preserved", cause)
	}
}

// TestIndeterminateAlwaysCarriesAReason is the invariant, not a case list: an
// INDETERMINATE with no reason is exactly the opaque verdict this change
// removed, and a definite verdict carrying one would make the field untrustworthy.
func TestIndeterminateAlwaysCarriesAReason(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T) (Fetcher, [32]byte, uint64, [][32]byte)
		want  Reason
	}{
		{"no anchor at all", func(t *testing.T) (Fetcher, [32]byte, uint64, [][32]byte) {
			return &fakeFetcher{bundles: map[uint64][][]byte{0: {}}}, [32]byte{0x01}, 0, nil
		}, ReasonNone},
		{"withdrawn", func(t *testing.T) (Fetcher, [32]byte, uint64, [][32]byte) {
			f := newFetcherWithAnchor(t, 1, withdrawnLeaf)
			return f, withdrawnLeaf, 1, f.roots
		}, ReasonNone},
		{"bundle unreadable", func(t *testing.T) (Fetcher, [32]byte, uint64, [][32]byte) {
			return &errBundleFetcher{}, withdrawnLeaf, 1, nil
		}, ReasonAnchorScanFailed},
		{"no anchor chains to a pinned root", func(t *testing.T) (Fetcher, [32]byte, uint64, [][32]byte) {
			f := newFetcherWithAnchor(t, 1, withdrawnLeaf)
			return f, withdrawnLeaf, 1, [][32]byte{{0xde, 0xad}}
		}, ReasonAnchorUntrusted},
		{"artifact missing", func(t *testing.T) (Fetcher, [32]byte, uint64, [][32]byte) {
			f := newFetcherWithAnchor(t, 1, withdrawnLeaf)
			delete(f.artifacts, 1)
			return f, withdrawnLeaf, 1, f.roots
		}, ReasonArtifactUnreachable},
		{"artifact unparseable", func(t *testing.T) (Fetcher, [32]byte, uint64, [][32]byte) {
			f := newFetcherWithAnchor(t, 1, withdrawnLeaf)
			f.artifacts[1] = []byte("{not json")
			return f, withdrawnLeaf, 1, f.roots
		}, ReasonArtifactParseError},
		{"artifact does not match the log", func(t *testing.T) (Fetcher, [32]byte, uint64, [][32]byte) {
			f := newFetcherWithAnchor(t, 1, withdrawnLeaf)
			f.artifacts[1] = append(f.artifacts[1], ' ')
			return f, withdrawnLeaf, 1, f.roots
		}, ReasonArtifactHashMismatch},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, lh, size, roots := c.build(t)
			v, _, reason, _ := Resolve(f, lh, size, roots)
			if reason != c.want {
				t.Errorf("reason = %q, want %q", reason, c.want)
			}
			switch v {
			case VerdictIndeterminate:
				if reason == ReasonNone {
					t.Error("INDETERMINATE with no reason — the caller can say nothing useful")
				}
			default:
				if reason != ReasonNone {
					t.Errorf("definite verdict %v carried reason %q", v, reason)
				}
			}
		})
	}
}
