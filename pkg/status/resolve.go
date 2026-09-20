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

// Reason names WHY resolution could not reach a definite answer. It is empty
// for VERIFIED and WITHDRAWN, and always set when the verdict is INDETERMINATE.
//
// The verdict alone is not actionable. "Indeterminate" spans a log that is
// misbehaving and a laptop that is offline, and a user deciding whether to trust
// a certificate needs to know which: the first three reasons below say something
// is wrong with the log or the publisher, the fetch failures are usually local
// and retryable. Without this distinction a UI can only ever print the word
// "indeterminate", users learn to read it as noise, and fail-closed quietly
// degrades into fail-ignored.
type Reason string

const (
	// ReasonNone is the empty reason carried by a definite verdict.
	ReasonNone Reason = ""
	// ReasonAnchorScanFailed: an entry bundle could not be read, so a newer
	// anchor may exist and go unseen. Fetch-level; usually local.
	ReasonAnchorScanFailed Reason = "anchor_scan_failed"
	// ReasonAnchorUntrusted: status anchors exist in the log, but none verifies
	// against a pinned identity root — possibly a root rotation this verifier
	// has not picked up. Cannot check is not nothing to check.
	ReasonAnchorUntrusted Reason = "anchor_untrusted"
	// ReasonArtifactUnreachable: a trusted anchor names a status artifact that
	// could not be fetched. Fetch-level; usually local.
	ReasonArtifactUnreachable Reason = "artifact_unreachable"
	// ReasonArtifactParseError: the artifact was fetched but is not well-formed.
	ReasonArtifactParseError Reason = "artifact_parse_error"
	// ReasonArtifactHashMismatch: the artifact served does not hash to what the
	// log committed to — corruption, or equivocation. The most serious of these.
	ReasonArtifactHashMismatch Reason = "artifact_hash_mismatch"
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
//
// The third return names WHY an INDETERMINATE verdict was reached; it is
// ReasonNone for VERIFIED and WITHDRAWN.
//
// The fourth return is the underlying CAUSE, for diagnostics only. It is
// non-nil only alongside a fetch- or parse-level reason, it never affects the
// verdict, and a caller MUST NOT treat it as failure — doing so would turn a
// fail-closed INDETERMINATE into a hard error and lose the verdict entirely.
// It exists because the distinction a user most often needs, "the network is
// down" versus "the server returned 404", lives below the Fetcher interface and
// cannot be recovered from the Reason alone.
func Resolve(f Fetcher, leafHash [32]byte, logSize uint64, identityRoots [][32]byte) (Verdict, *Entry, Reason, error) {
	start := uint64(0)
	if h, err := f.FetchHint(); err == nil && h != nil && h.AnchorIndex < logSize {
		start = h.AnchorIndex
	}

	newest, sawUntrusted, err := scanForNewestAnchor(f, start, logSize, identityRoots)
	if err != nil {
		return VerdictIndeterminate, nil, ReasonAnchorScanFailed, err
	}
	// A hint that yielded nothing may simply have been stale or wrong. Retry
	// honestly from the beginning rather than concluding "no status exists".
	if newest == nil && start > 0 {
		newest, sawUntrusted, err = scanForNewestAnchor(f, 0, logSize, identityRoots)
		if err != nil {
			return VerdictIndeterminate, nil, ReasonAnchorScanFailed, err
		}
	}
	if newest == nil {
		if sawUntrusted {
			// Status HAS been published, but nothing chains to a pinned root —
			// possibly an identity-root rotation this verifier has not picked
			// up. "Cannot check" is not "nothing to check".
			return VerdictIndeterminate, nil, ReasonAnchorUntrusted, nil
		}
		return VerdictVerified, nil, ReasonNone, nil
	}

	raw, err := f.FetchArtifact(newest.ArtifactVersion)
	if err != nil {
		return VerdictIndeterminate, nil, ReasonArtifactUnreachable, err
	}
	art, gotHash, err := ParseArtifact(raw)
	if err != nil {
		return VerdictIndeterminate, nil, ReasonArtifactParseError, err
	}
	if gotHash != [32]byte(newest.ArtifactHash) {
		// The artifact served does not match what the log committed to:
		// corruption, or equivocation.
		return VerdictIndeterminate, nil, ReasonArtifactHashMismatch, nil
	}
	if e, ok := art.Find(leafHash); ok {
		return VerdictWithdrawn, e, ReasonNone, nil
	}
	return VerdictVerified, nil, ReasonNone, nil
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
