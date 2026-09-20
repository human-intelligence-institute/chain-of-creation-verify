package status

import (
	"errors"

	"github.com/human-intelligence-institute/chain-of-creation-verify/pkg/leaf"
)

// BundleSize is the tlog-tiles entry bundle width. Scanning happens a bundle at
// a time, so cost is measured in bundle fetches, not leaves.
//
// It is exported so callers wiring a real log can assert it still matches
// Tessera's layout.EntryBundleWidth; pkg/cocverify does this at compile time.
const BundleSize = 256

var errNotFound = errors.New("status: not found")

// Verdict is the top-level result of status resolution.
type Verdict string

const (
	VerdictVerified      Verdict = "VERIFIED"
	VerdictWithdrawn     Verdict = "WITHDRAWN"
	VerdictIndeterminate Verdict = "INDETERMINATE"
)

// Hint is the UNTRUSTED discovery aid published at status/latest.json. It only
// ever supplies a starting index; correctness never depends on it.
type Hint struct {
	Version     uint64 `json:"version"`
	AnchorIndex uint64 `json:"anchor_index"`
}

// Fetcher abstracts the read paths resolution needs.
type Fetcher interface {
	FetchHint() (*Hint, error)
	FetchBundle(index uint64) ([][]byte, error) // raw leaves of bundle `index`
	FetchArtifact(version uint64) ([]byte, error)
}

// Resolve determines whether leafHash has been withdrawn.
//
// It fails CLOSED. Whenever a status anchor exists but its artifact cannot be
// obtained and hash-matched, the verdict is INDETERMINATE rather than VERIFIED.
// Only the total absence of any trusted anchor permits VERIFIED, because then no
// status has ever been published and there is nothing to check.
//
// This is the property that separates the design from OCSP soft-fail, where
// blocking a single request buys a clean pass.
func Resolve(f Fetcher, leafHash [32]byte, logSize uint64, identityRoots [][32]byte) (Verdict, *Entry, error) {
	start := uint64(0)
	if h, err := f.FetchHint(); err == nil && h != nil && h.AnchorIndex < logSize {
		start = h.AnchorIndex
	}

	newest, sawUntrusted, err := scanForNewestAnchor(f, start, logSize, identityRoots)
	if err != nil {
		return VerdictIndeterminate, nil, nil
	}
	// A hint that yielded nothing may simply have been stale or wrong. Retry
	// honestly from the beginning rather than concluding "no status exists".
	if newest == nil && start > 0 {
		newest, sawUntrusted, err = scanForNewestAnchor(f, 0, logSize, identityRoots)
		if err != nil {
			return VerdictIndeterminate, nil, nil
		}
	}
	if newest == nil {
		if sawUntrusted {
			// Status HAS been published, but nothing chains to a pinned root —
			// possibly an identity-root rotation this verifier has not picked
			// up. "Cannot check" is not "nothing to check".
			return VerdictIndeterminate, nil, nil
		}
		return VerdictVerified, nil, nil
	}

	raw, err := f.FetchArtifact(newest.ArtifactVersion)
	if err != nil {
		return VerdictIndeterminate, nil, nil
	}
	art, gotHash, err := ParseArtifact(raw)
	if err != nil {
		return VerdictIndeterminate, nil, nil
	}
	if gotHash != [32]byte(newest.ArtifactHash) {
		// The artifact served does not match what the log committed to:
		// corruption, or equivocation.
		return VerdictIndeterminate, nil, nil
	}
	if e, ok := art.Find(leafHash); ok {
		return VerdictWithdrawn, e, nil
	}
	return VerdictVerified, nil, nil
}

// scanForNewestAnchor walks entry bundles from `from` to the tip and returns the
// validly-signed, pinned-issuer StatusAnchor with the greatest ArtifactVersion.
//
// Scanning to the tip — rather than trusting the hint's index — is what stops a
// stale or dishonest hint from suppressing a newer anchor.
//
// The second return reports whether any kind=3 leaf was seen that did NOT chain
// to a pinned root, so the caller can distinguish "no status published" from
// "status published but unverifiable".
func scanForNewestAnchor(f Fetcher, from, logSize uint64, roots [][32]byte) (*leaf.StatusAnchor, bool, error) {
	var newest *leaf.StatusAnchor
	sawUntrusted := false

	for b := from / BundleSize; b*BundleSize < logSize; b++ {
		leaves, err := f.FetchBundle(b)
		if err != nil {
			// A bundle we cannot read might hold a newer anchor, so this must
			// not be treated as "nothing found".
			return nil, sawUntrusted, err
		}
		for _, raw := range leaves {
			k, err := leaf.PeekKind(raw)
			if err != nil || k != leaf.KindStatusAnchor {
				continue
			}
			a, err := leaf.UnmarshalStatusAnchor(raw)
			if err != nil {
				continue
			}
			if !a.Verify() || !isPinned(a.IssuerPubKey, roots) {
				sawUntrusted = true
				continue
			}
			if newest == nil || a.ArtifactVersion > newest.ArtifactVersion {
				newest = a
			}
		}
	}
	return newest, sawUntrusted, nil
}

func isPinned(key [32]byte, roots [][32]byte) bool {
	for _, r := range roots {
		if key == r {
			return true
		}
	}
	return false
}
