package verify

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/human-intelligence-institute/chain-of-creation/internal/fuzzy"
	"github.com/human-intelligence-institute/chain-of-creation/internal/identity"
	"github.com/human-intelligence-institute/chain-of-creation/internal/leaf"
	"github.com/human-intelligence-institute/chain-of-creation/internal/provenance"
	"github.com/transparency-dev/merkle/rfc6962"
)

// hiiAttestation builds an HII-style leaf: the canonical simhash64-v1 fuzzy digest
// over extracted text, and an exact hash that is SHA-256 over the raw file bytes
// (ExactAlg "sha256"). For a plain-text work rawBytes == text.
func hiiAttestation(t *testing.T, rawBytes, text []byte, priv ed25519.PrivateKey) *leaf.Attestation {
	t.Helper()
	fd, err := fuzzy.NewSimHash64().Digest(text)
	if err != nil {
		t.Fatal(err)
	}
	a := &leaf.Attestation{
		SchemaVersion: 1,
		WorkID:        [16]byte{9},
		EventType:     leaf.EventPublish,
		MediaType:     leaf.MediaText,
		AlgorithmID:   "simhash64-v1",
		FuzzyDigest:   fd,
		ExactHash:     leaf.Hash(sha256.Sum256(rawBytes)),
		ExactAlg:      "sha256",
		SubmittedAt:   uint64(time.Now().UnixMilli()),
	}
	a.Sign(priv)
	return a
}

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

	cm := MatchMedia(media, media, att, fuzzy.Default())
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
	cm := MatchMedia(reformatted, reformatted, att, fuzzy.Default())
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

	cm := MatchMedia([]byte("x"), []byte("x"), att, fuzzy.Default())
	if cm.FuzzyChecked {
		t.Fatal("unsupported algorithm should not be fuzzy-checked")
	}
	if cm.Note == "" {
		t.Fatal("expected an explanatory note")
	}
}

// TestMatchMediaHIILeaf is the headline case: an HII leaf (sha256 exact +
// simhash64-v1 fuzzy) verifies against the identical plain-text bytes. Before the
// exact-dispatch fix this was structurally impossible (BLAKE3 vs sha256) and the
// fuzzy path returned "unknown algorithm: simhash64-v1".
func TestMatchMediaHIILeaf(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	media := []byte("the certified written work, in plain text")
	att := hiiAttestation(t, media, media, priv)

	cm := MatchMedia(media, media, att, fuzzy.Default())
	if !cm.ExactMatch {
		t.Fatal("sha256 exact hash should match the identical raw bytes")
	}
	if !cm.FuzzyChecked || !cm.FuzzyMatch || cm.FuzzyDistance != 0 {
		t.Fatalf("simhash64-v1 fuzzy should match at distance 0: %+v", cm)
	}
	if cm.Note != "" {
		t.Fatalf("no note expected on a clean match, got %q", cm.Note)
	}
}

// TestMatchMediaHIIEditedCopy: a lightly edited copy no longer matches exactly,
// but simhash64-v1 still runs and reports a small nonzero distance (graded, not
// a silent skip).
func TestMatchMediaHIIEditedCopy(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	original := []byte("the certified written work has a distinctive opening sentence and several more clauses to fingerprint")
	att := hiiAttestation(t, original, original, priv)

	edited := append(append([]byte{}, original...), []byte(" plus one more clause")...)
	cm := MatchMedia(edited, edited, att, fuzzy.Default())
	if cm.ExactMatch {
		t.Fatal("an edited copy must not exact-match")
	}
	if !cm.FuzzyChecked {
		t.Fatalf("simhash64-v1 must be fuzzy-checked, got note %q", cm.Note)
	}
	if cm.FuzzyDistance <= 0 {
		t.Fatalf("edited copy should have a nonzero fuzzy distance: %+v", cm)
	}
}

// TestExactMatchBlake3Explicit is the regression guard: changing MatchMedia to
// dispatch on ExactAlg must not break existing non-HII leaves that use BLAKE3
// (whether ExactAlg is "blake3" or empty).
func TestExactMatchBlake3Explicit(t *testing.T) {
	media := []byte("a blake3 exact-alg leaf")
	for _, alg := range []string{"blake3", ""} {
		a := &leaf.Attestation{ExactHash: leaf.HashContent(media), ExactAlg: alg}
		if !exactMatch(media, a) {
			t.Fatalf("ExactAlg=%q: identical bytes must match", alg)
		}
		if exactMatch([]byte("different bytes"), a) {
			t.Fatalf("ExactAlg=%q: different bytes must not match", alg)
		}
	}
}

// TestExactMatchUnknownAlg: an exact-hash algorithm the verifier doesn't know is
// not a match, even if some hash of the bytes happens to be stored.
func TestExactMatchUnknownAlg(t *testing.T) {
	media := []byte("x")
	a := &leaf.Attestation{ExactHash: leaf.HashContent(media), ExactAlg: "md5"}
	if exactMatch(media, a) {
		t.Fatal("unknown exact-alg must not verify as a match")
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
