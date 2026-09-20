package cocverify_test

// Identity resolution against the frozen log in testdata/.
//
// Every case below feeds the same fetcher and the same frozen checkpoint; the
// negative cases differ from TestVerifyIdentity_Resolved by exactly ONE input
// (the pinned root, or the binding index). That is what keeps them genuinely
// negative: since the positive combination resolves through this fetcher, a
// Resolved=false verdict can only come from the input that changed, never from
// a fetcher that fails on everything.

import (
	"context"
	"testing"

	"github.com/human-intelligence-institute/chain-of-creation-verify/pkg/cocverify"
)

func TestVerifyIdentity_Resolved(t *testing.T) {
	ctx := context.Background()
	m := loadManifest(t)
	root := m.root(t, m.IDRoot)

	rawAtt := m.raw(t, "identity-attestation")
	bindingIndex := m.index(t, "identity-binding")

	res, err := cocverify.VerifyIdentity(ctx, fixtureFetcher(t), rawAtt, bindingIndex, m.Origin, m.VKey, [][32]byte{root})
	if err != nil {
		t.Fatalf("VerifyIdentity: %v", err)
	}
	if !res.Resolved || res.CreatorID != "creator-7" || !res.Custodial || !res.BindingIncluded {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestVerifyIdentity_UntrustedRoot(t *testing.T) {
	ctx := context.Background()
	m := loadManifest(t)
	otherRoot := m.root(t, m.OtherRoot) // a different, not-pinned root

	rawAtt := m.raw(t, "identity-attestation")
	bindingIndex := m.index(t, "identity-binding")

	res, err := cocverify.VerifyIdentity(ctx, fixtureFetcher(t), rawAtt, bindingIndex, m.Origin, m.VKey, [][32]byte{otherRoot})
	if err != nil {
		t.Fatalf("VerifyIdentity: %v", err)
	}
	if res.Resolved {
		t.Fatal("binding signed by a non-pinned root must not resolve")
	}
	if !res.BindingIncluded {
		t.Fatal("binding is in the log; BindingIncluded should be true even when untrusted")
	}
}

func TestVerifyIdentity_WrongBindingIndex(t *testing.T) {
	ctx := context.Background()
	m := loadManifest(t)
	root := m.root(t, m.IDRoot)

	rawAtt := m.raw(t, "identity-attestation")
	attIndex := m.index(t, "identity-attestation")

	// Point binding_index at the attestation leaf — it is included, but it is not
	// a binding, so identity must not resolve.
	res, err := cocverify.VerifyIdentity(ctx, fixtureFetcher(t), rawAtt, attIndex, m.Origin, m.VKey, [][32]byte{root})
	if err != nil {
		t.Fatalf("VerifyIdentity: %v", err)
	}
	if res.Resolved {
		t.Fatal("a binding_index pointing at a non-binding leaf must not resolve")
	}
	// The leaf at that index IS committed — the rejection is because it is not a
	// binding, not because the log could not be read.
	if !res.BindingIncluded {
		t.Fatal("the attestation leaf is in the log; BindingIncluded should be true")
	}
}

func TestVerifyIdentity_BindingForDifferentKey(t *testing.T) {
	ctx := context.Background()
	m := loadManifest(t)
	root := m.root(t, m.IDRoot)

	rawAtt := m.raw(t, "identity-attestation")
	// A valid, trusted binding — but for a different signing key than the one that
	// signed the attestation.
	bindingIndex := m.index(t, "identity-binding-other-key")

	res, err := cocverify.VerifyIdentity(ctx, fixtureFetcher(t), rawAtt, bindingIndex, m.Origin, m.VKey, [][32]byte{root})
	if err != nil {
		t.Fatalf("VerifyIdentity: %v", err)
	}
	if res.Resolved {
		t.Fatal("a binding that authorizes a different key must not resolve this signer")
	}
	// That binding is itself a genuine, committed, trusted binding — the only
	// reason it does not resolve is the key it authorizes.
	if !res.BindingIncluded {
		t.Fatal("the other-key binding is in the log; BindingIncluded should be true")
	}
}
