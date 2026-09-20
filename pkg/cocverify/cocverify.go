// Package cocverify is the stable, public verification API for chain-of-creation
// leaves. It wraps the internal verification logic behind a small surface that
// external consumers — including the WebAssembly browser verifier — can call.
//
// VerifyLeaf is offline: it checks a single leaf's signature and, for an
// attestation with media, the exact and fuzzy content match. Verifying log
// inclusion against a live node builds on the verify package separately.
package cocverify

import (
	"encoding/hex"
	"errors"

	"github.com/human-intelligence-institute/chain-of-creation-verify/pkg/fuzzy"
	"github.com/human-intelligence-institute/chain-of-creation-verify/pkg/leaf"
	"github.com/human-intelligence-institute/chain-of-creation-verify/internal/verify"
)

// LeafResult is the JSON-serializable outcome of verifying one leaf.
type LeafResult struct {
	Kind           string               `json:"kind"`
	SignatureValid bool                 `json:"signature_valid"`
	LeafHash       string               `json:"leaf_hash"`
	WorkID         string               `json:"work_id,omitempty"`
	EventSeq       uint64               `json:"event_seq,omitempty"`
	EventType      string               `json:"event_type,omitempty"`
	CreatorID      string               `json:"creator_id,omitempty"` // bindings only
	Content        *verify.ContentMatch `json:"content,omitempty"`
}

// VerifyLeaf decodes a raw leaf, verifies its signature, and — for an
// attestation when rawBytes is non-nil — reports the content match. rawBytes are
// the raw candidate file bytes (checked against the exact hash); text is the
// extracted text (checked against the fuzzy digest). Pass text=nil when the media
// is already plain text: the raw bytes are then used for both, preserving the
// single-input .txt behaviour.
func VerifyLeaf(rawLeaf, rawBytes, text []byte) (LeafResult, error) {
	kind, err := leaf.PeekKind(rawLeaf)
	if err != nil {
		return LeafResult{}, err
	}
	switch kind {
	case leaf.KindAttestation:
		att, err := leaf.UnmarshalAttestation(rawLeaf)
		if err != nil {
			return LeafResult{}, err
		}
		lh := att.LeafHash()
		res := LeafResult{
			Kind:           "attestation",
			SignatureValid: att.Verify(),
			LeafHash:       hex.EncodeToString(lh[:]),
			WorkID:         hex.EncodeToString(att.WorkID[:]),
			EventSeq:       att.EventSeq,
			EventType:      string(att.EventType),
		}
		if rawBytes != nil {
			ft := text
			if ft == nil {
				ft = rawBytes
			}
			cm := verify.MatchMedia(rawBytes, ft, att, fuzzy.Default())
			res.Content = &cm
		}
		return res, nil

	case leaf.KindIdentityBinding:
		b, err := leaf.UnmarshalIdentityBinding(rawLeaf)
		if err != nil {
			return LeafResult{}, err
		}
		lh := b.LeafHash()
		return LeafResult{
			Kind:           "identity_binding",
			SignatureValid: b.Verify(),
			LeafHash:       hex.EncodeToString(lh[:]),
			CreatorID:      b.CreatorID,
		}, nil

	default:
		return LeafResult{}, errors.New("cocverify: unknown leaf kind")
	}
}
