package cocverify_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/human-intelligence-institute/chain-of-creation/internal/custodial"
	"github.com/human-intelligence-institute/chain-of-creation/internal/fuzzy"
	"github.com/human-intelligence-institute/chain-of-creation/internal/identity"
	"github.com/human-intelligence-institute/chain-of-creation/internal/leaf"
	"github.com/human-intelligence-institute/chain-of-creation/internal/lognode"
	"github.com/human-intelligence-institute/chain-of-creation/pkg/cocverify"
	"github.com/transparency-dev/tessera/client"
)

func fetcherWithEntries(n *lognode.Node) cocverify.Fetcher {
	r := n.Reader()
	return cocverify.Fetcher{Checkpoint: r.ReadCheckpoint, Tile: r.ReadTile, Entries: r.ReadEntryBundle}
}

func newIssuer(t *testing.T) (*identity.Issuer, [32]byte) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	iss := identity.NewIssuer(priv)
	return iss, iss.RootPublicKey()
}

func attestationBy(t *testing.T, priv ed25519.PrivateKey, at time.Time) []byte {
	t.Helper()
	a := &leaf.Attestation{
		SchemaVersion: 1,
		WorkID:        [16]byte{7, 7, 7},
		EventType:     leaf.EventPublish,
		MediaType:     leaf.MediaText,
		AlgorithmID:   "simhash-text-v1",
		FuzzyDigest:   []byte{1, 2, 3, 4, 5, 6, 7, 8},
		SubmittedAt:   uint64(at.UnixMilli()),
	}
	a.Sign(priv)
	return a.Marshal()
}

// appendAwait appends and blocks until the leaf is in a published checkpoint.
func appendAwait(t *testing.T, n *lognode.Node, b []byte) uint64 {
	t.Helper()
	idx, _, err := n.AppendAwait(context.Background(), b)
	if err != nil {
		t.Fatalf("AppendAwait: %v", err)
	}
	return idx.Index
}

func TestVerifyIdentity_Resolved(t *testing.T) {
	ctx := context.Background()
	n, vkey := nodeWithKnownKey(t)
	iss, root := newIssuer(t)

	_, signPriv, _ := ed25519.GenerateKey(rand.Reader)
	var signPub [32]byte
	copy(signPub[:], signPriv.Public().(ed25519.PublicKey))

	binding := iss.Issue("creator-7", signPub, leaf.KeyHIICustodial, time.Now().Add(-time.Minute))
	bindingIndex := appendAwait(t, n, binding.Marshal())
	rawAtt := attestationBy(t, signPriv, time.Now())
	appendAwait(t, n, rawAtt)

	res, err := cocverify.VerifyIdentity(ctx, fetcherWithEntries(n), rawAtt, bindingIndex, inclOrigin, vkey, [][32]byte{root})
	if err != nil {
		t.Fatalf("VerifyIdentity: %v", err)
	}
	if !res.Resolved || res.CreatorID != "creator-7" || !res.Custodial || !res.BindingIncluded {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestVerifyIdentity_UntrustedRoot(t *testing.T) {
	ctx := context.Background()
	n, vkey := nodeWithKnownKey(t)
	iss, _ := newIssuer(t)
	_, otherRoot := newIssuer(t) // a different, not-pinned root

	_, signPriv, _ := ed25519.GenerateKey(rand.Reader)
	var signPub [32]byte
	copy(signPub[:], signPriv.Public().(ed25519.PublicKey))

	binding := iss.Issue("creator-7", signPub, leaf.KeyHIICustodial, time.Now().Add(-time.Minute))
	bindingIndex := appendAwait(t, n, binding.Marshal())
	rawAtt := attestationBy(t, signPriv, time.Now())
	appendAwait(t, n, rawAtt)

	res, err := cocverify.VerifyIdentity(ctx, fetcherWithEntries(n), rawAtt, bindingIndex, inclOrigin, vkey, [][32]byte{otherRoot})
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
	n, vkey := nodeWithKnownKey(t)
	iss, root := newIssuer(t)

	_, signPriv, _ := ed25519.GenerateKey(rand.Reader)
	var signPub [32]byte
	copy(signPub[:], signPriv.Public().(ed25519.PublicKey))

	binding := iss.Issue("creator-7", signPub, leaf.KeyHIICustodial, time.Now().Add(-time.Minute))
	appendAwait(t, n, binding.Marshal())
	rawAtt := attestationBy(t, signPriv, time.Now())
	attIndex := appendAwait(t, n, rawAtt)

	// Point binding_index at the attestation leaf — it is included, but it is not
	// a binding, so identity must not resolve.
	res, err := cocverify.VerifyIdentity(ctx, fetcherWithEntries(n), rawAtt, attIndex, inclOrigin, vkey, [][32]byte{root})
	if err != nil {
		t.Fatalf("VerifyIdentity: %v", err)
	}
	if res.Resolved {
		t.Fatal("a binding_index pointing at a non-binding leaf must not resolve")
	}
}

func TestVerifyIdentity_BindingForDifferentKey(t *testing.T) {
	ctx := context.Background()
	n, vkey := nodeWithKnownKey(t)
	iss, root := newIssuer(t)

	_, signPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	var otherPub [32]byte
	copy(otherPub[:], otherPriv.Public().(ed25519.PublicKey))

	// A valid, trusted binding — but for a different signing key than the one that
	// signed the attestation.
	binding := iss.Issue("creator-7", otherPub, leaf.KeyHIICustodial, time.Now().Add(-time.Minute))
	bindingIndex := appendAwait(t, n, binding.Marshal())
	rawAtt := attestationBy(t, signPriv, time.Now())
	appendAwait(t, n, rawAtt)

	res, err := cocverify.VerifyIdentity(ctx, fetcherWithEntries(n), rawAtt, bindingIndex, inclOrigin, vkey, [][32]byte{root})
	if err != nil {
		t.Fatalf("VerifyIdentity: %v", err)
	}
	if res.Resolved {
		t.Fatal("a binding that authorizes a different key must not resolve this signer")
	}
}

// Exercises the receipt-producing server path: a custodial submission issues the
// binding, returns its index, and the verifier resolves identity from that index.
func TestCustodialEmitsBindingIndexAndResolves(t *testing.T) {
	ctx := context.Background()
	n, vkey := nodeWithKnownKey(t)
	iss, root := newIssuer(t)

	svc := custodial.NewService(custodial.NewMemoryKeyStore(), iss, fuzzy.Default(), n)
	res, err := svc.Submit(ctx, custodial.Request{
		CreatorID: "creator-c1",
		Media:     []byte("a short certified work"),
		EventType: leaf.EventPublish,
		MediaType: leaf.MediaText,
		Await:     true,
	})
	if err != nil {
		t.Fatalf("custodial Submit: %v", err)
	}
	if !res.BindingIssued {
		t.Fatal("first submission should issue a binding")
	}

	// Fetch the attestation leaf the service signed, from its index in the log.
	r := n.Reader()
	size, err := r.IntegratedSize(ctx)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := client.GetEntryBundle(ctx, r.ReadEntryBundle, res.Index.Index/256, size)
	if err != nil {
		t.Fatalf("GetEntryBundle: %v", err)
	}
	rawAtt := bundle.Entries[res.Index.Index%256]

	got, err := cocverify.VerifyIdentity(ctx, fetcherWithEntries(n), rawAtt, res.BindingIndex, inclOrigin, vkey, [][32]byte{root})
	if err != nil {
		t.Fatalf("VerifyIdentity: %v", err)
	}
	if !got.Resolved || got.CreatorID != "creator-c1" || !got.Custodial {
		t.Fatalf("custodial record did not resolve: %+v", got)
	}
}
