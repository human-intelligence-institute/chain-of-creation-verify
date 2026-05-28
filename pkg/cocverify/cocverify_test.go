package cocverify

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/human-intelligence-institute/chain-of-creation/internal/attest"
	"github.com/human-intelligence-institute/chain-of-creation/internal/fuzzy"
	"github.com/human-intelligence-institute/chain-of-creation/internal/identity"
	"github.com/human-intelligence-institute/chain-of-creation/internal/leaf"
)

func TestVerifyLeafAttestationWithMedia(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	media := []byte("the registered work text for cocverify")
	att, err := attest.Build(media, attest.Params{
		WorkID: [16]byte{3}, EventType: leaf.EventPublish, MediaType: leaf.MediaText,
	}, fuzzy.Default())
	if err != nil {
		t.Fatal(err)
	}
	att.Sign(priv)

	res, err := VerifyLeaf(att.Marshal(), media)
	if err != nil {
		t.Fatalf("VerifyLeaf: %v", err)
	}
	if res.Kind != "attestation" || !res.SignatureValid {
		t.Fatalf("unexpected: %+v", res)
	}
	if res.Content == nil || !res.Content.ExactMatch || !res.Content.FuzzyMatch {
		t.Fatalf("content match failed: %+v", res.Content)
	}
}

func TestVerifyLeafAttestationNoMedia(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	att, _ := attest.Build([]byte("x"), attest.Params{
		MediaType: leaf.MediaText, EventType: leaf.EventDraft,
	}, fuzzy.Default())
	att.Sign(priv)

	res, err := VerifyLeaf(att.Marshal(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.SignatureValid || res.Content != nil {
		t.Fatalf("expected valid sig and no content section: %+v", res)
	}
}

func TestVerifyLeafTamperedSignature(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	att, _ := attest.Build([]byte("x"), attest.Params{
		MediaType: leaf.MediaText, EventType: leaf.EventDraft,
	}, fuzzy.Default())
	att.Sign(priv)
	att.FuzzyDigest = []byte("tampered")

	res, err := VerifyLeaf(att.Marshal(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.SignatureValid {
		t.Fatal("tampered leaf should not verify")
	}
}

func TestVerifyLeafIdentityBinding(t *testing.T) {
	_, root, _ := ed25519.GenerateKey(rand.Reader)
	signerPub, _, _ := ed25519.GenerateKey(rand.Reader)
	var sk [32]byte
	copy(sk[:], signerPub)
	b := identity.NewIssuer(root).Issue("creator-x", sk, leaf.KeySelfManaged, time.Now())

	res, err := VerifyLeaf(b.Marshal(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Kind != "identity_binding" || !res.SignatureValid || res.CreatorID != "creator-x" {
		t.Fatalf("unexpected binding result: %+v", res)
	}
}
