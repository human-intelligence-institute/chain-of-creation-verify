package leaf

import "crypto/ed25519"

const domainIdentityBinding = "coc-identity-binding-v1"

// IdentityBinding maps a signing public key to a creator identity. HII issues
// and signs these (with the identity-root key); a verifier resolves an
// attestation's SignerPubKey to a CreatorID — and to whether HII vouches for it
// — by finding the matching binding in the log.
type IdentityBinding struct {
	CreatorID       string
	AuthorizedKey   [32]byte // the signing key this binding authorizes
	KeyType         KeyType
	ValidFrom       uint64   // unix milliseconds
	IssuerPubKey    [32]byte // HII identity-root public key
	IssuerSignature [64]byte
}

func (b *IdentityBinding) signingPayload() []byte {
	e := &encoder{}
	e.str(domainIdentityBinding)
	e.str(b.CreatorID)
	e.fixed(b.AuthorizedKey[:])
	e.u8(uint8(b.KeyType))
	e.u64(b.ValidFrom)
	e.fixed(b.IssuerPubKey[:])
	return e.buf
}

// Sign sets IssuerPubKey and IssuerSignature from the HII identity-root key.
func (b *IdentityBinding) Sign(issuer ed25519.PrivateKey) {
	copy(b.IssuerPubKey[:], issuer.Public().(ed25519.PublicKey))
	sig := ed25519.Sign(issuer, b.signingPayload())
	copy(b.IssuerSignature[:], sig)
}

// Verify reports whether IssuerSignature is valid by IssuerPubKey.
func (b *IdentityBinding) Verify() bool {
	return ed25519.Verify(b.IssuerPubKey[:], b.signingPayload(), b.IssuerSignature[:])
}

func (b *IdentityBinding) Marshal() []byte {
	e := &encoder{}
	e.u8(uint8(KindIdentityBinding))
	e.str(b.CreatorID)
	e.fixed(b.AuthorizedKey[:])
	e.u8(uint8(b.KeyType))
	e.u64(b.ValidFrom)
	e.fixed(b.IssuerPubKey[:])
	e.fixed(b.IssuerSignature[:])
	return e.buf
}

func (b *IdentityBinding) LeafHash() Hash { return hashBytes(b.Marshal()) }

// UnmarshalIdentityBinding decodes leaf bytes produced by IdentityBinding.Marshal.
func UnmarshalIdentityBinding(buf []byte) (*IdentityBinding, error) {
	d := &decoder{buf: buf}
	kind, err := d.u8()
	if err != nil {
		return nil, err
	}
	if LeafKind(kind) != KindIdentityBinding {
		return nil, errWrongKind
	}
	b := &IdentityBinding{}
	if b.CreatorID, err = d.str(); err != nil {
		return nil, err
	}
	ak, err := d.fixed(32)
	if err != nil {
		return nil, err
	}
	copy(b.AuthorizedKey[:], ak)
	kt, err := d.u8()
	if err != nil {
		return nil, err
	}
	b.KeyType = KeyType(kt)
	if b.ValidFrom, err = d.u64(); err != nil {
		return nil, err
	}
	ip, err := d.fixed(32)
	if err != nil {
		return nil, err
	}
	copy(b.IssuerPubKey[:], ip)
	is, err := d.fixed(64)
	if err != nil {
		return nil, err
	}
	copy(b.IssuerSignature[:], is)
	if err := d.finish(); err != nil {
		return nil, err
	}
	return b, nil
}

// PeekKind returns the LeafKind tag of marshaled leaf bytes without fully
// decoding, so a reader can dispatch to the right Unmarshal function.
func PeekKind(b []byte) (LeafKind, error) {
	d := &decoder{buf: b}
	k, err := d.u8()
	return LeafKind(k), err
}
