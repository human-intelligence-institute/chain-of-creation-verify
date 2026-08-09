package leaf

import "crypto/ed25519"

// domainStatusAnchor separates status signatures from every other use of the
// identity-root key, so a signature over one message type can never be replayed
// as another.
const domainStatusAnchor = "coc-status-v1"

// StatusAnchor commits the log to the hash of a published revocation status
// artifact — the document naming the attestation leaves HII has withdrawn.
//
// HII signs it with the identity-root key, the same anchor verifiers already
// pin for IdentityBinding, so this introduces no new trust anchor.
//
// The artifact itself carries no signature. Its authenticity is transitive from
// this leaf, which is both signed and committed to the append-only log: one
// signature, in one place, covered by the log's own tamper-evidence.
type StatusAnchor struct {
	SchemaVersion   uint32
	ArtifactVersion uint64   // strictly monotonic across publications
	ArtifactHash    Hash     // BLAKE3-256 over the artifact bytes as published
	IssuedAt        uint64   // unix milliseconds
	IssuerPubKey    [32]byte // HII identity-root public key
	IssuerSignature [64]byte
}

// signingPayload is the deterministic byte string covered by IssuerSignature.
// ArtifactVersion is inside it deliberately: without that, an attacker could
// replay an old artifact's signature under a higher version number and roll the
// status back undetectably.
func (s *StatusAnchor) signingPayload() []byte {
	e := &encoder{}
	e.str(domainStatusAnchor)
	e.u32(s.SchemaVersion)
	e.u64(s.ArtifactVersion)
	e.fixed(s.ArtifactHash[:])
	e.u64(s.IssuedAt)
	e.fixed(s.IssuerPubKey[:])
	return e.buf
}

// Sign sets IssuerPubKey and IssuerSignature from the HII identity-root key.
func (s *StatusAnchor) Sign(issuer ed25519.PrivateKey) {
	copy(s.IssuerPubKey[:], issuer.Public().(ed25519.PublicKey))
	sig := ed25519.Sign(issuer, s.signingPayload())
	copy(s.IssuerSignature[:], sig)
}

// Verify reports whether IssuerSignature is valid by IssuerPubKey.
func (s *StatusAnchor) Verify() bool {
	return ed25519.Verify(s.IssuerPubKey[:], s.signingPayload(), s.IssuerSignature[:])
}

func (s *StatusAnchor) Marshal() []byte {
	e := &encoder{}
	e.u8(uint8(KindStatusAnchor))
	e.u32(s.SchemaVersion)
	e.u64(s.ArtifactVersion)
	e.fixed(s.ArtifactHash[:])
	e.u64(s.IssuedAt)
	e.fixed(s.IssuerPubKey[:])
	e.fixed(s.IssuerSignature[:])
	return e.buf
}

func (s *StatusAnchor) LeafHash() Hash { return hashBytes(s.Marshal()) }

// UnmarshalStatusAnchor decodes leaf bytes produced by StatusAnchor.Marshal.
func UnmarshalStatusAnchor(buf []byte) (*StatusAnchor, error) {
	d := &decoder{buf: buf}
	kind, err := d.u8()
	if err != nil {
		return nil, err
	}
	if LeafKind(kind) != KindStatusAnchor {
		return nil, errWrongKind
	}
	s := &StatusAnchor{}
	if s.SchemaVersion, err = d.u32(); err != nil {
		return nil, err
	}
	if s.ArtifactVersion, err = d.u64(); err != nil {
		return nil, err
	}
	ah, err := d.fixed(32)
	if err != nil {
		return nil, err
	}
	copy(s.ArtifactHash[:], ah)
	if s.IssuedAt, err = d.u64(); err != nil {
		return nil, err
	}
	ip, err := d.fixed(32)
	if err != nil {
		return nil, err
	}
	copy(s.IssuerPubKey[:], ip)
	is, err := d.fixed(64)
	if err != nil {
		return nil, err
	}
	copy(s.IssuerSignature[:], is)
	if err := d.finish(); err != nil {
		return nil, err
	}
	return s, nil
}
