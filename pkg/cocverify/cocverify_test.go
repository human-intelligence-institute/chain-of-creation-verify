package cocverify

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
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

	res, err := VerifyLeaf(att.Marshal(), media, nil)
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

// TestVerifyLeafTwoInputHII exercises the HII split: the exact hash is SHA-256
// over the raw file bytes (e.g. a .docx container) while the fuzzy digest is over
// the separately-extracted text. The two inputs differ, so this only passes if
// VerifyLeaf threads them to the right checks.
func TestVerifyLeafTwoInputHII(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	text := []byte("the extracted document text that the certifier fingerprinted")
	raw := append([]byte("PK\x03\x04 fake docx container \x00\x01\x02 "), text...) // distinct raw bytes

	// Build over the text to get the canonical fuzzy digest, then override the
	// exact hash to SHA-256 over the raw file bytes (what an HII leaf records).
	att, err := attest.Build(text, attest.Params{
		WorkID: [16]byte{9}, EventType: leaf.EventPublish, MediaType: leaf.MediaText,
	}, fuzzy.Default())
	if err != nil {
		t.Fatal(err)
	}
	att.ExactAlg = "sha256"
	att.ExactHash = leaf.Hash(sha256.Sum256(raw))
	att.Sign(priv)

	res, err := VerifyLeaf(att.Marshal(), raw, text)
	if err != nil {
		t.Fatalf("VerifyLeaf: %v", err)
	}
	if res.Content == nil || !res.Content.ExactMatch || !res.Content.FuzzyMatch {
		t.Fatalf("two-input match failed: %+v", res.Content)
	}

	// Passing the raw bytes as the fuzzy input (the single-input mistake) must NOT
	// exact-match against text and must fail fuzzy — proves the inputs are distinct.
	res2, err := VerifyLeaf(att.Marshal(), text, text)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Content.ExactMatch {
		t.Fatalf("exact should not match when raw bytes are wrong: %+v", res2.Content)
	}
}

func TestVerifyLeafAttestationNoMedia(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	att, _ := attest.Build([]byte("x"), attest.Params{
		MediaType: leaf.MediaText, EventType: leaf.EventDraft,
	}, fuzzy.Default())
	att.Sign(priv)

	res, err := VerifyLeaf(att.Marshal(), nil, nil)
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

	res, err := VerifyLeaf(att.Marshal(), nil, nil)
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

	res, err := VerifyLeaf(b.Marshal(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Kind != "identity_binding" || !res.SignatureValid || res.CreatorID != "creator-x" {
		t.Fatalf("unexpected binding result: %+v", res)
	}
}
