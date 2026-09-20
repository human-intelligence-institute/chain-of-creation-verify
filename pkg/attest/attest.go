// Package attest builds attestation leaves from media: it computes the fuzzy
// digest (via the shared registry) and the exact content hash, then assembles an
// unsigned Attestation. The caller signs it — with a local key (hiisign) or a
// custodial key (the server). Keeping digest computation here guarantees the
// self-signed and custodial paths produce identical digests.
package attest

import (
	"errors"
	"fmt"
	"time"

	"github.com/human-intelligence-institute/chain-of-creation-verify/pkg/fuzzy"
	"github.com/human-intelligence-institute/chain-of-creation-verify/pkg/leaf"
)

// Params describes the event being attested. AlgorithmID is optional: when
// empty, the registry's default algorithm for MediaType is used.
type Params struct {
	WorkID      [16]byte
	EventSeq    uint64
	Prev        *leaf.Hash
	EventType   leaf.EventType
	MediaType   leaf.MediaType
	AlgorithmID string
	// ExactAlg names the algorithm used to compute the precomputed exact hash
	// (e.g. "sha256"). Empty when unspecified. Only the precomputed path uses it;
	// the media path always hashes with BLAKE3.
	ExactAlg  string
	ToolTrace []byte
	// Now overrides the submission timestamp (for tests); zero means time.Now.
	Now time.Time
}

// ErrNoDigester is returned when no algorithm is available for the media type
// and none was named explicitly.
var ErrNoDigester = errors.New("attest: no fuzzy digester for media type")

// Build computes the digest and exact hash for media and returns an unsigned
// Attestation. The returned attestation still needs a call to Sign.
func Build(media []byte, p Params, reg *fuzzy.Registry) (*leaf.Attestation, error) {
	var d fuzzy.Digester
	var ok bool
	if p.AlgorithmID != "" {
		d, ok = reg.Get(p.AlgorithmID)
		if !ok {
			return nil, fmt.Errorf("%w: %q", fuzzy.ErrUnknownAlgorithm, p.AlgorithmID)
		}
	} else {
		d, ok = reg.DigesterForMedia(p.MediaType)
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrNoDigester, p.MediaType)
		}
	}

	digest, err := d.Digest(media)
	if err != nil {
		return nil, err
	}

	now := p.Now
	if now.IsZero() {
		now = time.Now()
	}

	return &leaf.Attestation{
		SchemaVersion: 1,
		WorkID:        p.WorkID,
		EventSeq:      p.EventSeq,
		PrevEventHash: p.Prev,
		EventType:     p.EventType,
		MediaType:     p.MediaType,
		AlgorithmID:   d.ID(),
		FuzzyDigest:   digest,
		ExactHash:     leaf.HashContent(media),
		SubmittedAt:   uint64(now.UnixMilli()),
		ToolTrace:     p.ToolTrace,
	}, nil
}

// BuildPrecomputed assembles an unsigned Attestation from digests the caller
// already computed — coc does not hash media here. It is the path for callers
// (e.g. HII certifiers) that hold only the normalized provenance triple and may
// never have the original media. AlgorithmID is stored verbatim; no registry
// lookup happens, so any algorithm id (including one whose Go digester is not
// registered) is accepted. The returned attestation still needs a call to Sign.
func BuildPrecomputed(exactHash leaf.Hash, fuzzyDigest []byte, p Params) (*leaf.Attestation, error) {
	now := p.Now
	if now.IsZero() {
		now = time.Now()
	}
	return &leaf.Attestation{
		SchemaVersion: 1,
		WorkID:        p.WorkID,
		EventSeq:      p.EventSeq,
		PrevEventHash: p.Prev,
		EventType:     p.EventType,
		MediaType:     p.MediaType,
		AlgorithmID:   p.AlgorithmID,
		FuzzyDigest:   fuzzyDigest,
		ExactHash:     exactHash,
		ExactAlg:      p.ExactAlg,
		SubmittedAt:   uint64(now.UnixMilli()),
		ToolTrace:     p.ToolTrace,
	}, nil
}
