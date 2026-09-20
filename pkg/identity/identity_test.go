package identity

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/human-intelligence-institute/chain-of-creation-verify/pkg/leaf"
)

func key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func pubArray(p ed25519.PublicKey) (a [32]byte) { copy(a[:], p); return }

func TestIssueAndResolve(t *testing.T) {
	_, root := key(t)
	issuer := NewIssuer(root)
	signerPub, _ := key(t)
	sk := pubArray(signerPub)

	t0 := time.UnixMilli(1_700_000_000_000)
	b := issuer.Issue("creator-1", sk, leaf.KeySelfManaged, t0)

	r := NewResolver(issuer.RootPublicKey())
	if err := r.Add(b); err != nil {
		t.Fatalf("Add: %v", err)
	}

	res, ok := r.Resolve(sk, t0.Add(time.Hour))
	if !ok {
		t.Fatal("expected resolution")
	}
	if res.CreatorID != "creator-1" {
		t.Fatalf("CreatorID = %q", res.CreatorID)
	}
	if res.Custodial() {
		t.Fatal("self-managed key should not report Custodial")
	}
}

func TestResolveBeforeValidFrom(t *testing.T) {
	_, root := key(t)
	issuer := NewIssuer(root)
	signerPub, _ := key(t)
	sk := pubArray(signerPub)

	t0 := time.UnixMilli(1_700_000_000_000)
	b := issuer.Issue("creator-1", sk, leaf.KeyHIICustodial, t0)

	r := NewResolver(issuer.RootPublicKey())
	_ = r.Add(b)

	if _, ok := r.Resolve(sk, t0.Add(-time.Second)); ok {
		t.Fatal("binding should not resolve before ValidFrom")
	}
}

func TestResolvePicksLatestEffectiveBinding(t *testing.T) {
	_, root := key(t)
	issuer := NewIssuer(root)
	signerPub, _ := key(t)
	sk := pubArray(signerPub)

	t0 := time.UnixMilli(1_700_000_000_000)
	t1 := t0.Add(24 * time.Hour)
	r := NewResolver(issuer.RootPublicKey())
	_ = r.Add(issuer.Issue("old-name", sk, leaf.KeySelfManaged, t0))
	_ = r.Add(issuer.Issue("new-name", sk, leaf.KeySelfManaged, t1))

	res, ok := r.Resolve(sk, t1.Add(time.Hour))
	if !ok || res.CreatorID != "new-name" {
		t.Fatalf("expected new-name, got %q ok=%v", res.CreatorID, ok)
	}
	res0, ok := r.Resolve(sk, t0.Add(time.Hour))
	if !ok || res0.CreatorID != "old-name" {
		t.Fatalf("expected old-name at t0, got %q ok=%v", res0.CreatorID, ok)
	}
}

func TestAddRejectsUntrustedIssuer(t *testing.T) {
	_, root := key(t)
	_, attacker := key(t)
	issuer := NewIssuer(root)
	signerPub, _ := key(t)

	// Binding signed by an attacker, not the trusted root.
	rogue := NewIssuer(attacker).Issue("victim", pubArray(signerPub), leaf.KeyHIICustodial, time.Now())

	r := NewResolver(issuer.RootPublicKey())
	if err := r.Add(rogue); err != ErrUntrustedIssuer {
		t.Fatalf("expected ErrUntrustedIssuer, got %v", err)
	}
}

func TestAddRejectsTamperedBinding(t *testing.T) {
	_, root := key(t)
	issuer := NewIssuer(root)
	signerPub, _ := key(t)
	b := issuer.Issue("creator-1", pubArray(signerPub), leaf.KeyHIICustodial, time.Now())
	b.CreatorID = "attacker" // invalidates the issuer signature

	r := NewResolver(issuer.RootPublicKey())
	if err := r.Add(b); err != ErrBadSignature {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

func TestResolverTrustsMultipleRootsAcrossRotation(t *testing.T) {
	_, oldRoot := key(t)
	_, newRoot := key(t)
	oldIssuer, newIssuer := NewIssuer(oldRoot), NewIssuer(newRoot)
	signerPub, _ := key(t)
	sk := pubArray(signerPub)

	// A binding issued under the old root, before rotation, must stay verifiable.
	t0 := time.UnixMilli(1_700_000_000_000)
	oldBinding := oldIssuer.Issue("creator-1", sk, leaf.KeyHIICustodial, t0)
	// A new binding under the new root after rotation.
	signer2, _ := key(t)
	sk2 := pubArray(signer2)
	newBinding := newIssuer.Issue("creator-2", sk2, leaf.KeyHIICustodial, t0.Add(48*time.Hour))

	// Verifier configured with the new root as primary and the old root retained.
	r := NewResolver(newIssuer.RootPublicKey())
	r.TrustRoot(oldIssuer.RootPublicKey(), time.Time{}) // no cutoff: trust old bindings forever
	if err := r.Add(oldBinding); err != nil {
		t.Fatalf("old-root binding should remain verifiable: %v", err)
	}
	if err := r.Add(newBinding); err != nil {
		t.Fatalf("new-root binding should verify: %v", err)
	}
	if res, ok := r.Resolve(sk, t0.Add(time.Hour)); !ok || res.CreatorID != "creator-1" {
		t.Fatalf("old binding did not resolve: %q ok=%v", res.CreatorID, ok)
	}
}

func TestResolverRootNotAfterCutoff(t *testing.T) {
	_, oldRoot := key(t)
	_, newRoot := key(t)
	oldIssuer := NewIssuer(oldRoot)
	signerPub, _ := key(t)
	sk := pubArray(signerPub)

	cutoff := time.UnixMilli(1_700_000_000_000)
	// Old root retained but only up to the rotation/compromise time.
	r := NewResolver(NewIssuer(newRoot).RootPublicKey())
	r.TrustRoot(oldIssuer.RootPublicKey(), cutoff)

	// A binding from the old root dated AFTER the cutoff (e.g. minted by an
	// attacker who stole the rotated-out key) must be rejected.
	forged := oldIssuer.Issue("victim", sk, leaf.KeyHIICustodial, cutoff.Add(time.Hour))
	if err := r.Add(forged); err != ErrRootExpired {
		t.Fatalf("expected ErrRootExpired for post-cutoff binding, got %v", err)
	}
	// A binding dated before the cutoff is still fine.
	legit := oldIssuer.Issue("creator", sk, leaf.KeyHIICustodial, cutoff.Add(-time.Hour))
	if err := r.Add(legit); err != nil {
		t.Fatalf("pre-cutoff binding should verify: %v", err)
	}
}

func TestResolveUnknownKey(t *testing.T) {
	_, root := key(t)
	r := NewResolver(NewIssuer(root).RootPublicKey())
	var unknown [32]byte
	if _, ok := r.Resolve(unknown, time.Now()); ok {
		t.Fatal("unknown key should not resolve")
	}
}
