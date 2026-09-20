package leaf

import (
	"crypto/ed25519"
	"errors"
)

// domainAttestation separates attestation signatures from any other use of the
// same key, so a signature over one message type can never be replayed as another.
const domainAttestation = "coc-attestation-v1"

// Attestation is a single signed provenance event for a work. Many events with
// the same WorkID, linked by PrevEventHash, form the work's history. The log
// stores the canonical Marshal() bytes; the graph over events is reconstructed
// off-log by indexing on WorkID.
type Attestation struct {
	SchemaVersion uint32
	WorkID        [16]byte // stable UUID tying all events of one work together
	EventSeq      uint64   // author-asserted ordering within the work (0,1,2…)
	PrevEventHash *Hash    // LeafHash of the prior event; nil at EventSeq 0

	EventType   EventType
	MediaType   MediaType
	AlgorithmID string // fuzzy-hash algorithm id, e.g. "tlsh-v1"
	FuzzyDigest []byte // opaque, algorithm-specific
	ExactHash   Hash   // exact hash of the media bytes (algorithm named by ExactAlg)
	ExactAlg    string // exact-hash algorithm id, e.g. "blake3" or "sha256"; "" when unspecified

	SignerPubKey [32]byte // ed25519 public key
	Signature    [64]byte // over signingPayload()
	SubmittedAt  uint64   // unix milliseconds

	ToolTrace []byte // optional signed appendix; hashed into the signature
}

// toolTraceHash is the BLAKE3 of ToolTrace, or the zero hash when absent. The
// signature commits to this hash rather than the raw trace, so the trace stays
// tamper-evident even if stored off-leaf.
func (a *Attestation) toolTraceHash() Hash {
	if len(a.ToolTrace) == 0 {
		return Hash{}
	}
	return hashBytes(a.ToolTrace)
}

// signingPayload is the deterministic byte string covered by Signature. It
// omits SignerPubKey-independent framing and the signature itself, and commits
// to ToolTrace only via its hash.
func (a *Attestation) signingPayload() []byte {
	e := &encoder{}
	e.str(domainAttestation)
	e.u32(a.SchemaVersion)
	e.fixed(a.WorkID[:])
	e.u64(a.EventSeq)
	if a.PrevEventHash != nil {
		e.u8(1)
		e.fixed(a.PrevEventHash[:])
	} else {
		e.u8(0)
	}
	e.str(string(a.EventType))
	e.str(string(a.MediaType))
	e.str(a.AlgorithmID)
	e.bytes(a.FuzzyDigest)
	e.fixed(a.ExactHash[:])
	e.str(a.ExactAlg)
	e.fixed(a.SignerPubKey[:])
	e.u64(a.SubmittedAt)
	tth := a.toolTraceHash()
	e.fixed(tth[:])
	return e.buf
}

// Sign sets SignerPubKey and Signature from priv.
func (a *Attestation) Sign(priv ed25519.PrivateKey) {
	copy(a.SignerPubKey[:], priv.Public().(ed25519.PublicKey))
	sig := ed25519.Sign(priv, a.signingPayload())
	copy(a.Signature[:], sig)
}

// Verify reports whether Signature is a valid signature by SignerPubKey over
// the current contents.
func (a *Attestation) Verify() bool {
	return ed25519.Verify(a.SignerPubKey[:], a.signingPayload(), a.Signature[:])
}

// Marshal returns the canonical, kind-tagged leaf bytes stored in the log.
func (a *Attestation) Marshal() []byte {
	e := &encoder{}
	e.u8(uint8(KindAttestation))
	e.u32(a.SchemaVersion)
	e.fixed(a.WorkID[:])
	e.u64(a.EventSeq)
	if a.PrevEventHash != nil {
		e.u8(1)
		e.fixed(a.PrevEventHash[:])
	} else {
		e.u8(0)
	}
	e.str(string(a.EventType))
	e.str(string(a.MediaType))
	e.str(a.AlgorithmID)
	e.bytes(a.FuzzyDigest)
	e.fixed(a.ExactHash[:])
	e.str(a.ExactAlg)
	e.fixed(a.SignerPubKey[:])
	e.fixed(a.Signature[:])
	e.u64(a.SubmittedAt)
	e.bytes(a.ToolTrace)
	return e.buf
}

// LeafHash is the BLAKE3 of the marshaled leaf — a stable content identifier
// independent of the leaf's position in the log. A later event references this
// value in its PrevEventHash.
func (a *Attestation) LeafHash() Hash {
	return hashBytes(a.Marshal())
}

var errWrongKind = errors.New("leaf: wrong kind tag")

// UnmarshalAttestation decodes leaf bytes produced by Attestation.Marshal.
func UnmarshalAttestation(b []byte) (*Attestation, error) {
	d := &decoder{buf: b}
	kind, err := d.u8()
	if err != nil {
		return nil, err
	}
	if LeafKind(kind) != KindAttestation {
		return nil, errWrongKind
	}
	a := &Attestation{}
	if a.SchemaVersion, err = d.u32(); err != nil {
		return nil, err
	}
	wid, err := d.fixed(16)
	if err != nil {
		return nil, err
	}
	copy(a.WorkID[:], wid)
	if a.EventSeq, err = d.u64(); err != nil {
		return nil, err
	}
	hasPrev, err := d.u8()
	if err != nil {
		return nil, err
	}
	if hasPrev == 1 {
		ph, err := d.fixed(32)
		if err != nil {
			return nil, err
		}
		var h Hash
		copy(h[:], ph)
		a.PrevEventHash = &h
	}
	et, err := d.str()
	if err != nil {
		return nil, err
	}
	a.EventType = EventType(et)
	mt, err := d.str()
	if err != nil {
		return nil, err
	}
	a.MediaType = MediaType(mt)
	if a.AlgorithmID, err = d.str(); err != nil {
		return nil, err
	}
	if a.FuzzyDigest, err = d.bytes(); err != nil {
		return nil, err
	}
	eh, err := d.fixed(32)
	if err != nil {
		return nil, err
	}
	copy(a.ExactHash[:], eh)
	if a.ExactAlg, err = d.str(); err != nil {
		return nil, err
	}
	pk, err := d.fixed(32)
	if err != nil {
		return nil, err
	}
	copy(a.SignerPubKey[:], pk)
	sig, err := d.fixed(64)
	if err != nil {
		return nil, err
	}
	copy(a.Signature[:], sig)
	if a.SubmittedAt, err = d.u64(); err != nil {
		return nil, err
	}
	if a.ToolTrace, err = d.bytes(); err != nil {
		return nil, err
	}
	if err := d.finish(); err != nil {
		return nil, err
	}
	return a, nil
}
