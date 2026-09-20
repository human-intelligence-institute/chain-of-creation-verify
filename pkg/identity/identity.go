// Package identity issues and resolves IdentityBinding leaves. HII signs every
// binding with its identity-root key; a verifier uses the bindings published in
// the log to map an attestation's signing key to a creator — and to whether the
// signing key is HII-custodied or the creator's own.
package identity

import (
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/human-intelligence-institute/chain-of-creation-verify/pkg/leaf"
)

// Issuer holds the HII identity-root key and mints signed IdentityBindings.
type Issuer struct {
	root ed25519.PrivateKey
}

// NewIssuer wraps the HII identity-root private key.
func NewIssuer(root ed25519.PrivateKey) *Issuer { return &Issuer{root: root} }

// RootPublicKey returns the issuer's public key, which verifiers configure as
// their trusted root.
func (i *Issuer) RootPublicKey() [32]byte {
	var pk [32]byte
	copy(pk[:], i.root.Public().(ed25519.PublicKey))
	return pk
}

// Issue creates and signs a binding from a signing key to a creator. Use
// leaf.KeyHIICustodial when HII holds the signing key, or leaf.KeySelfManaged
// when the creator controls it.
// SignerKey returns the identity-root private key.
//
// Exposed so the status publisher can sign a StatusAnchor with the same root
// that signs IdentityBindings — a StatusAnchor is an HII statement about the
// log, not a per-creator attestation, so it belongs to this key rather than a
// fourth pinned anchor verifiers would have to obtain and rotate.
func (i *Issuer) SignerKey() ed25519.PrivateKey { return i.root }

func (i *Issuer) Issue(creatorID string, authorizedKey [32]byte, kt leaf.KeyType, validFrom time.Time) *leaf.IdentityBinding {
	b := &leaf.IdentityBinding{
		CreatorID:     creatorID,
		AuthorizedKey: authorizedKey,
		KeyType:       kt,
		ValidFrom:     uint64(validFrom.UnixMilli()),
	}
	b.Sign(i.root)
	return b
}

// Resolution is what a verifier learns about an attestation's signing key.
type Resolution struct {
	CreatorID string
	KeyType   leaf.KeyType
	ValidFrom time.Time
}

// Custodial reports whether HII holds the signing key (and therefore produced
// the attestation signature itself) versus merely registering a key the creator
// controls.
func (r Resolution) Custodial() bool { return r.KeyType == leaf.KeyHIICustodial }

// trustedRoot is an accepted issuer key with an optional cutoff. When notAfter
// is non-zero, bindings from this root whose ValidFrom is after it are rejected.
type trustedRoot struct {
	key      [32]byte
	notAfter uint64 // ms; 0 = no cutoff
}

// Resolver indexes accepted bindings by their authorized signing key. It accepts
// bindings signed by any of its trusted roots — supporting identity-root key
// rotation, where bindings from the previous root must stay verifiable.
type Resolver struct {
	roots []trustedRoot
	byKey map[[32]byte][]*leaf.IdentityBinding
}

// NewResolver creates a resolver that trusts bindings issued by root. Add
// further roots (e.g. a rotated-out predecessor) with TrustRoot.
func NewResolver(root [32]byte) *Resolver {
	return &Resolver{
		roots: []trustedRoot{{key: root}},
		byKey: map[[32]byte][]*leaf.IdentityBinding{},
	}
}

// TrustRoot adds an additional accepted issuer root. When notAfter is non-zero,
// bindings from this root with a ValidFrom after notAfter are rejected: use it
// to keep a rotated-out root's earlier bindings verifiable while refusing to
// honor anything it "issued" past the rotation/compromise time.
func (r *Resolver) TrustRoot(key [32]byte, notAfter time.Time) {
	var na uint64
	if !notAfter.IsZero() {
		na = uint64(notAfter.UnixMilli())
	}
	r.roots = append(r.roots, trustedRoot{key: key, notAfter: na})
}

var (
	// ErrUntrustedIssuer is returned when a binding's issuer is not a trusted root.
	ErrUntrustedIssuer = errors.New("identity: binding issuer is not a trusted root")
	// ErrBadSignature is returned when a binding's issuer signature does not verify.
	ErrBadSignature = errors.New("identity: binding signature invalid")
	// ErrRootExpired is returned when a binding is signed by a trusted root but its
	// ValidFrom is after that root's notAfter cutoff.
	ErrRootExpired = errors.New("identity: binding is past its issuer root's cutoff")
)

// Add validates and indexes a binding. A binding is accepted only when its
// IssuerPubKey matches a trusted root, it is within that root's cutoff, and its
// signature verifies.
func (r *Resolver) Add(b *leaf.IdentityBinding) error {
	root, ok := r.matchRoot(b.IssuerPubKey)
	if !ok {
		return ErrUntrustedIssuer
	}
	if root.notAfter != 0 && b.ValidFrom > root.notAfter {
		return ErrRootExpired
	}
	if !b.Verify() {
		return ErrBadSignature
	}
	r.byKey[b.AuthorizedKey] = append(r.byKey[b.AuthorizedKey], b)
	return nil
}

func (r *Resolver) matchRoot(k [32]byte) (trustedRoot, bool) {
	for _, rt := range r.roots {
		if rt.key == k {
			return rt, true
		}
	}
	return trustedRoot{}, false
}

// Resolve returns the identity bound to signerKey effective at time at. When a
// key has several bindings (e.g. re-registration), it returns the one with the
// greatest ValidFrom not after at. The bool is false when no binding is in
// effect for the key at that time.
func (r *Resolver) Resolve(signerKey [32]byte, at time.Time) (Resolution, bool) {
	bindings := r.byKey[signerKey]
	atMs := uint64(at.UnixMilli())
	var best *leaf.IdentityBinding
	for _, b := range bindings {
		if b.ValidFrom > atMs {
			continue
		}
		if best == nil || b.ValidFrom > best.ValidFrom {
			best = b
		}
	}
	if best == nil {
		return Resolution{}, false
	}
	return Resolution{
		CreatorID: best.CreatorID,
		KeyType:   best.KeyType,
		ValidFrom: time.UnixMilli(int64(best.ValidFrom)),
	}, true
}
