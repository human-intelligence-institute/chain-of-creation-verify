package verify

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/human-intelligence-institute/chain-of-creation/internal/fuzzy"
	"github.com/human-intelligence-institute/chain-of-creation/internal/identity"
	"github.com/human-intelligence-institute/chain-of-creation/internal/leaf"
	"github.com/human-intelligence-institute/chain-of-creation/internal/provenance"
	"github.com/transparency-dev/merkle/rfc6962"
)

// textAttestation builds a signed attestation describing the given media using
// the default text hasher, with ExactHash and FuzzyDigest populated.
func textAttestation(t *testing.T, media []byte, priv ed25519.PrivateKey) *leaf.Attestation {
	t.Helper()
	d, err := fuzzy.NewSimHashText().Digest(media)
	if err != nil {
		t.Fatal(err)
	}
	a := &leaf.Attestation{
		SchemaVersion: 1,
		WorkID:        [16]byte{7},
		EventType:     leaf.EventPublish,
		MediaType:     leaf.MediaText,
		AlgorithmID:   "simhash-text-v1",
		FuzzyDigest:   d,
		ExactHash:     leaf.HashContent(media),
		SubmittedAt:   uint64(time.Now().UnixMilli()),
	}
	a.Sign(priv)
	return a
}

func TestVerifyEventSignatureAndIdentity(t *testing.T) {
	_, root, _ := ed25519.GenerateKey(rand.Reader)
	issuer := identity.NewIssuer(root)
	res := identity.NewResolver(issuer.RootPublicKey())

	signerPub, signerPriv, _ := ed25519.GenerateKey(rand.Reader)
	var sk [32]byte
	copy(sk[:], signerPub)
	_ = res.Add(issuer.Issue("creator-7", sk, leaf.KeyHIICustodial, time.UnixMilli(1)))

	att := textAttestation(t, []byte("hello provenance world"), signerPriv)
	sig, id := VerifyEvent(att, res)
	if !sig.Valid {
		t.Fatal("signature should be valid")
	}
	if !id.Resolved || id.CreatorID != "creator-7" || !id.Custodial {
		t.Fatalf("identity not resolved as expected: %+v", id)
	}
}

func TestVerifyEventBadSignature(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	att := textAttestation(t, []byte("hello"), priv)
	att.FuzzyDigest = []byte("tampered")
	sig, _ := VerifyEvent(att, nil)
	if sig.Valid {
		t.Fatal("tampered attestation should fail signature verification")
	}
}

func TestMatchMediaExact(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	media := []byte("the original work text that was registered")
	att := textAttestation(t, media, priv)

	cm := MatchMedia(media, att, fuzzy.Default())
	if !cm.ExactMatch {
		t.Fatal("identical media should match exactly")
	}
	if !cm.FuzzyChecked || !cm.FuzzyMatch || cm.FuzzyDistance != 0 {
		t.Fatalf("identical media fuzzy mismatch: %+v", cm)
	}
}

func TestMatchMediaFuzzyOnly(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	original := []byte("The Original Work Text, that was registered, with punctuation.")
	att := textAttestation(t, original, priv)

	reformatted := []byte("the original work text that was registered with punctuation")
	cm := MatchMedia(reformatted, att, fuzzy.Default())
	if cm.ExactMatch {
		t.Fatal("reformatted media should not match exactly")
	}
	if !cm.FuzzyChecked || !cm.FuzzyMatch {
		t.Fatalf("reformatted media should fuzzy-match: %+v", cm)
	}
}

func TestMatchMediaUnsupportedAlgorithm(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	att := textAttestation(t, []byte("x"), priv)
	att.AlgorithmID = "chromaprint-v2" // not registered for verification

	cm := MatchMedia([]byte("x"), att, fuzzy.Default())
	if cm.FuzzyChecked {
		t.Fatal("unsupported algorithm should not be fuzzy-checked")
	}
	if cm.Note == "" {
		t.Fatal("expected an explanatory note")
	}
}

func TestBuildWorkReport(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	ix := provenance.NewIndex()
	var prev *leaf.Hash
	for i := 0; i < 3; i++ {
		a := &leaf.Attestation{
			WorkID: [16]byte{7}, EventSeq: uint64(i), PrevEventHash: prev,
			EventType: leaf.EventEdit, MediaType: leaf.MediaText, AlgorithmID: "simhash-text-v1",
		}
		a.Sign(priv)
		h := a.LeafHash()
		prev = &h
		ix.Add(a, uint64(i))
	}
	chain, _ := ix.Work([16]byte{7})
	rep := BuildWorkReport(chain, nil)

	if len(rep.Events) != 3 || !rep.Chain.Linear {
		t.Fatalf("unexpected report: %+v", rep)
	}
	if !rep.AllSignaturesValid() {
		t.Fatal("all signatures should be valid")
	}
	for i, e := range rep.Events {
		if e.EventSeq != uint64(i) {
			t.Fatalf("events not sorted by seq: %+v", rep.Events)
		}
	}
}

func TestVerifyInclusionSizeOne(t *testing.T) {
	raw := []byte("leaf-zero")
	root := rfc6962.DefaultHasher.HashLeaf(raw)
	if err := VerifyInclusion(raw, 0, 1, nil, root); err != nil {
		t.Fatalf("size-1 inclusion should verify: %v", err)
	}
}

func TestVerifyInclusionSizeTwo(t *testing.T) {
	l0 := []byte("leaf-zero")
	l1 := []byte("leaf-one")
	h := rfc6962.DefaultHasher
	root := h.HashChildren(h.HashLeaf(l0), h.HashLeaf(l1))

	if err := VerifyInclusion(l0, 0, 2, [][]byte{h.HashLeaf(l1)}, root); err != nil {
		t.Fatalf("index-0 inclusion should verify: %v", err)
	}
	if err := VerifyInclusion(l1, 1, 2, [][]byte{h.HashLeaf(l0)}, root); err != nil {
		t.Fatalf("index-1 inclusion should verify: %v", err)
	}
}

func TestVerifyInclusionRejectsWrongRoot(t *testing.T) {
	raw := []byte("leaf-zero")
	bad := make([]byte, 32)
	if err := VerifyInclusion(raw, 0, 1, nil, bad); err == nil {
		t.Fatal("inclusion against a wrong root must fail")
	}
}
