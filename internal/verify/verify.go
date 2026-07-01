// Package verify assembles a verification report for a claim about a work: it
// checks each event's signature, resolves the signer to a creator identity,
// analyzes the provenance chain's integrity, and — when a media file is supplied
// — reports exact and fuzzy content matches with their distances. The output is
// a structured report, not a boolean: that is what makes a claim defendable.
package verify

import (
	"crypto/sha256"
	"errors"
	"time"

	"github.com/human-intelligence-institute/chain-of-creation/internal/fuzzy"
	"github.com/human-intelligence-institute/chain-of-creation/internal/identity"
	"github.com/human-intelligence-institute/chain-of-creation/internal/leaf"
	"github.com/human-intelligence-institute/chain-of-creation/internal/provenance"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

// SignatureResult reports whether an event's signature verifies.
type SignatureResult struct {
	Valid bool `json:"valid"`
}

// IdentityResult reports the resolved creator identity for an event's signer.
type IdentityResult struct {
	Resolved  bool   `json:"resolved"`
	CreatorID string `json:"creator_id,omitempty"`
	Custodial bool   `json:"custodial"` // true when HII holds the signing key
}

// ContentMatch reports how a candidate media file compares to an attestation.
type ContentMatch struct {
	ExactMatch     bool    `json:"exact_match"`
	AlgorithmID    string  `json:"algorithm_id"`
	FuzzyChecked   bool    `json:"fuzzy_checked"`
	FuzzyMatch     bool    `json:"fuzzy_match"`
	FuzzyDistance  float64 `json:"fuzzy_distance"`
	FuzzyThreshold float64 `json:"fuzzy_threshold"`
	Note           string  `json:"note,omitempty"` // e.g. why fuzzy was not checked
}

// EventReport is the per-event slice of a work report.
type EventReport struct {
	LeafHashHex string          `json:"leaf_hash"`
	EventSeq    uint64          `json:"event_seq"`
	EventType   string          `json:"event_type"`
	Signature   SignatureResult `json:"signature"`
	Identity    IdentityResult  `json:"identity"`
}

// ChainReport summarizes structural integrity.
type ChainReport struct {
	Linear        bool `json:"linear"`
	RootCount     int  `json:"root_count"`
	ForkCount     int  `json:"fork_count"`
	DanglingCount int  `json:"dangling_count"`
}

// VerifyEvent checks one attestation's signature and resolves its signer to a
// creator identity effective at the event's submission time.
func VerifyEvent(att *leaf.Attestation, res *identity.Resolver) (SignatureResult, IdentityResult) {
	sig := SignatureResult{Valid: att.Verify()}
	id := IdentityResult{}
	if res != nil {
		at := time.UnixMilli(int64(att.SubmittedAt))
		if r, ok := res.Resolve(att.SignerPubKey, at); ok {
			id.Resolved = true
			id.CreatorID = r.CreatorID
			id.Custodial = r.Custodial()
		}
	}
	return sig, id
}

// exactMatch recomputes the exact hash of media under the algorithm named by
// att.ExactAlg and compares it to att.ExactHash. HII leaves record "sha256" over
// the raw certified file bytes; older/other leaves use BLAKE3 (named "blake3" or
// left empty). An unknown exact algorithm cannot be verified, so it is not a
// match. For file-based media (e.g. a .docx) `media` must be the RAW file bytes;
// the fuzzy path takes extracted text separately (see the callers).
func exactMatch(media []byte, att *leaf.Attestation) bool {
	switch att.ExactAlg {
	case "sha256":
		return leaf.Hash(sha256.Sum256(media)) == att.ExactHash
	case "blake3", "":
		return leaf.HashContent(media) == att.ExactHash
	default:
		return false
	}
}

// MatchMedia recomputes the exact hash and (when the algorithm supports it) the
// fuzzy distance of media against an attestation.
func MatchMedia(media []byte, att *leaf.Attestation, reg *fuzzy.Registry) ContentMatch {
	cm := ContentMatch{
		ExactMatch:  exactMatch(media, att),
		AlgorithmID: att.AlgorithmID,
	}
	v, err := reg.Verifier(att.AlgorithmID)
	if err != nil {
		cm.Note = err.Error()
		return cm
	}
	digest, err := v.Digest(media)
	if err != nil {
		cm.Note = "digest failed: " + err.Error()
		return cm
	}
	dist, err := v.Distance(digest, att.FuzzyDigest)
	if err != nil {
		cm.Note = "distance failed: " + err.Error()
		return cm
	}
	cm.FuzzyChecked = true
	cm.FuzzyDistance = dist
	cm.FuzzyThreshold = v.DefaultThreshold()
	cm.FuzzyMatch = dist <= v.DefaultThreshold()
	return cm
}

// VerifyInclusion checks that rawLeaf is included in a tree of the given size
// with the given root, using the supplied RFC6962 inclusion proof. The leaf hash
// is derived with the RFC6962 hasher (matching Tessera), which is distinct from
// the BLAKE3 content hash used to chain provenance events.
func VerifyInclusion(rawLeaf []byte, index, size uint64, inclusionProof [][]byte, root []byte) error {
	if size == 0 {
		return errors.New("verify: tree size is zero")
	}
	leafHash := rfc6962.DefaultHasher.HashLeaf(rawLeaf)
	return proof.VerifyInclusion(rfc6962.DefaultHasher, index, size, leafHash, inclusionProof, root)
}

func chainReport(in provenance.Integrity) ChainReport {
	return ChainReport{
		Linear:        in.Linear,
		RootCount:     len(in.Roots),
		ForkCount:     len(in.Forks),
		DanglingCount: len(in.Dangling),
	}
}
