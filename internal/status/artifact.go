// Package status parses and resolves the coc revocation status artifact — the
// published document naming the attestation leaves HII has withdrawn.
//
// The log itself stays append-only: a withdrawal is never a mutation of the
// original leaf, only an additional statement about it. See docs/verification-spec.md
// §12.
package status

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/zeebo/blake3"
)

// Entry is one withdrawn attestation leaf.
type Entry struct {
	// LeafHash is base64-std over the 32-byte BLAKE3 LeafHash — the content
	// hash used to chain provenance events, NOT the RFC6962 tree leaf hash
	// used for inclusion proofs. Spec §8.3 keeps these deliberately distinct.
	LeafHash    string `json:"leaf_hash"`
	Reason      string `json:"reason"`
	WithdrawnAt uint64 `json:"withdrawn_at"`
}

// Artifact is the published status document.
//
// Field order here is irrelevant to correctness because this struct is never
// re-serialised — see ParseArtifact.
type Artifact struct {
	IssuedAt       uint64  `json:"issued_at"`
	LogSizeAtIssue uint64  `json:"log_size_at_issue"`
	Schema         int     `json:"schema"`
	Version        uint64  `json:"version"`
	Withdrawn      []Entry `json:"withdrawn"`
}

// ParseArtifact decodes the artifact and returns it alongside the BLAKE3-256
// hash of the RAW bytes supplied.
//
// Hashing the bytes as received — never a re-serialisation — is deliberate and
// load-bearing. The producer is Python and this verifier is Go; if the hash
// were taken over a Go re-encoding, any difference in key ordering, spacing or
// HTML escaping between the two languages would break the comparison against
// the anchor and yield a permanent, spurious INDETERMINATE verdict.
func ParseArtifact(raw []byte) (*Artifact, [32]byte, error) {
	h := [32]byte(blake3.Sum256(raw))

	var a Artifact
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, h, fmt.Errorf("status: parse artifact: %w", err)
	}
	return &a, h, nil
}

// Find reports whether the given BLAKE3 LeafHash appears in the withdrawn set.
func (a *Artifact) Find(leafHash [32]byte) (*Entry, bool) {
	want := base64.StdEncoding.EncodeToString(leafHash[:])
	for i := range a.Withdrawn {
		if a.Withdrawn[i].LeafHash == want {
			return &a.Withdrawn[i], true
		}
	}
	return nil, false
}

// marshalCanonical encodes the artifact deterministically.
//
// encoding/json escapes <, > and & by default, which would make the bytes depend
// on content and diverge from the producer's expectation. Encoder also appends a
// newline, which must be trimmed — the hash is over the document, not the
// document plus a separator.
func marshalCanonical(a Artifact) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(a); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
