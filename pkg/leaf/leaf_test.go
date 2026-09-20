package leaf

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func mustKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func sampleAttestation() *Attestation {
	prev := Hash{0xaa, 0xbb}
	return &Attestation{
		SchemaVersion: 1,
		WorkID:        [16]byte{1, 2, 3, 4},
		EventSeq:      7,
		PrevEventHash: &prev,
		EventType:     EventEdit,
		MediaType:     MediaText,
		AlgorithmID:   "tlsh-v1",
		FuzzyDigest:   []byte("digest-bytes"),
		ExactHash:     Hash{0xde, 0xad, 0xbe, 0xef},
		ExactAlg:      "blake3",
		SubmittedAt:   1_700_000_000_000,
		ToolTrace:     []byte(`{"editor":"vim"}`),
	}
}

func TestAttestationRoundTrip(t *testing.T) {
	_, priv := mustKey(t)
	a := sampleAttestation()
	a.Sign(priv)

	got, err := UnmarshalAttestation(a.Marshal())
	if err != nil {
		t.Fatalf("UnmarshalAttestation: %v", err)
	}
	if !bytes.Equal(got.Marshal(), a.Marshal()) {
		t.Fatal("round-trip marshal mismatch")
	}
	if !got.Verify() {
		t.Fatal("decoded attestation fails verification")
	}
}

func TestAttestationRoundTripNoPrevNoTrace(t *testing.T) {
	_, priv := mustKey(t)
	a := sampleAttestation()
	a.EventSeq = 0
	a.PrevEventHash = nil
	a.ToolTrace = nil
	a.Sign(priv)

	got, err := UnmarshalAttestation(a.Marshal())
	if err != nil {
		t.Fatalf("UnmarshalAttestation: %v", err)
	}
	if got.PrevEventHash != nil {
		t.Fatal("expected nil PrevEventHash")
	}
	if len(got.ToolTrace) != 0 {
		t.Fatalf("expected empty ToolTrace, got %q", got.ToolTrace)
	}
	if !got.Verify() {
		t.Fatal("verification failed")
	}
}

func TestMarshalIsDeterministic(t *testing.T) {
	_, priv := mustKey(t)
	a := sampleAttestation()
	a.Sign(priv)
	if !bytes.Equal(a.Marshal(), a.Marshal()) {
		t.Fatal("Marshal not deterministic")
	}
}

func TestTamperBreaksVerification(t *testing.T) {
	_, priv := mustKey(t)
	a := sampleAttestation()
	a.Sign(priv)

	a.FuzzyDigest = []byte("tampered")
	if a.Verify() {
		t.Fatal("verification passed after tampering with FuzzyDigest")
	}
}

func TestToolTraceTamperBreaksVerification(t *testing.T) {
	_, priv := mustKey(t)
	a := sampleAttestation()
	a.Sign(priv)

	a.ToolTrace = []byte(`{"editor":"emacs"}`)
	if a.Verify() {
		t.Fatal("verification passed after tampering with ToolTrace")
	}
}

func TestExactAlgRoundTripAndTamper(t *testing.T) {
	_, priv := mustKey(t)
	a := sampleAttestation()
	a.ExactAlg = "sha256"
	a.Sign(priv)

	got, err := UnmarshalAttestation(a.Marshal())
	if err != nil {
		t.Fatalf("UnmarshalAttestation: %v", err)
	}
	if got.ExactAlg != "sha256" {
		t.Fatalf("ExactAlg did not round-trip: got %q", got.ExactAlg)
	}
	if !got.Verify() {
		t.Fatal("decoded attestation fails verification")
	}

	a.ExactAlg = "blake3"
	if a.Verify() {
		t.Fatal("verification passed after tampering with ExactAlg")
	}
}

func TestWrongSignerFailsVerification(t *testing.T) {
	_, priv := mustKey(t)
	a := sampleAttestation()
	a.Sign(priv)

	other, _ := mustKey(t)
	copy(a.SignerPubKey[:], other) // claim a different signer
	if a.Verify() {
		t.Fatal("verification passed with mismatched signer key")
	}
}

func TestUnmarshalRejectsWrongKind(t *testing.T) {
	b := (&IdentityBinding{CreatorID: "c1"}).Marshal()
	if _, err := UnmarshalAttestation(b); err == nil {
		t.Fatal("expected error decoding a binding as an attestation")
	}
}

func TestUnmarshalRejectsTrailingBytes(t *testing.T) {
	_, priv := mustKey(t)
	a := sampleAttestation()
	a.Sign(priv)
	corrupted := append(a.Marshal(), 0x00)
	if _, err := UnmarshalAttestation(corrupted); err == nil {
		t.Fatal("expected error on trailing bytes")
	}
}

func TestIdentityBindingRoundTrip(t *testing.T) {
	_, issuer := mustKey(t)
	authPub, _ := mustKey(t)
	b := &IdentityBinding{
		CreatorID: "creator-123",
		KeyType:   KeySelfManaged,
		ValidFrom: 1_700_000_000_000,
	}
	copy(b.AuthorizedKey[:], authPub)
	b.Sign(issuer)

	got, err := UnmarshalIdentityBinding(b.Marshal())
	if err != nil {
		t.Fatalf("UnmarshalIdentityBinding: %v", err)
	}
	if !bytes.Equal(got.Marshal(), b.Marshal()) {
		t.Fatal("round-trip mismatch")
	}
	if !got.Verify() {
		t.Fatal("decoded binding fails verification")
	}
	if got.CreatorID != "creator-123" || got.KeyType != KeySelfManaged {
		t.Fatalf("field mismatch: %+v", got)
	}
}

func TestIdentityBindingTamperBreaksVerification(t *testing.T) {
	_, issuer := mustKey(t)
	authPub, _ := mustKey(t)
	b := &IdentityBinding{CreatorID: "c1", KeyType: KeyHIICustodial}
	copy(b.AuthorizedKey[:], authPub)
	b.Sign(issuer)

	b.CreatorID = "attacker"
	if b.Verify() {
		t.Fatal("verification passed after tampering with CreatorID")
	}
}

func TestPeekKind(t *testing.T) {
	_, priv := mustKey(t)
	a := sampleAttestation()
	a.Sign(priv)
	if k, err := PeekKind(a.Marshal()); err != nil || k != KindAttestation {
		t.Fatalf("PeekKind attestation = %v, %v", k, err)
	}
	b := (&IdentityBinding{CreatorID: "c"}).Marshal()
	if k, err := PeekKind(b); err != nil || k != KindIdentityBinding {
		t.Fatalf("PeekKind binding = %v, %v", k, err)
	}
}

func TestLeafHashChangesWithContent(t *testing.T) {
	_, priv := mustKey(t)
	a := sampleAttestation()
	a.Sign(priv)
	h1 := a.LeafHash()

	a2 := sampleAttestation()
	a2.EventSeq = 8
	a2.Sign(priv)
	if a.LeafHash() == a2.LeafHash() {
		t.Fatal("LeafHash collision across distinct events")
	}
	if a.LeafHash() != h1 {
		t.Fatal("LeafHash not stable")
	}
}

func sampleStatusAnchor() *StatusAnchor {
	return &StatusAnchor{
		SchemaVersion:   1,
		ArtifactVersion: 3,
		ArtifactHash:    Hash{0x11, 0x22, 0x33},
		IssuedAt:        1786000000000,
	}
}

func TestStatusAnchorRoundTrip(t *testing.T) {
	_, priv := mustKey(t)
	a := sampleStatusAnchor()
	a.Sign(priv)
	if !a.Verify() {
		t.Fatal("Verify() = false on freshly signed anchor")
	}
	got, err := UnmarshalStatusAnchor(a.Marshal())
	if err != nil {
		t.Fatalf("UnmarshalStatusAnchor: %v", err)
	}
	if got.ArtifactVersion != a.ArtifactVersion || got.IssuedAt != a.IssuedAt {
		t.Fatalf("round-trip mismatch: got %+v want %+v", got, a)
	}
	if !bytes.Equal(got.ArtifactHash[:], a.ArtifactHash[:]) {
		t.Fatal("ArtifactHash did not round-trip")
	}
	if !got.Verify() {
		t.Fatal("decoded anchor failed Verify()")
	}
}

func TestStatusAnchorTamperBreaksVerification(t *testing.T) {
	_, priv := mustKey(t)
	a := sampleStatusAnchor()
	a.Sign(priv)
	a.ArtifactHash[0] ^= 0xff
	if a.Verify() {
		t.Fatal("Verify() = true after tampering with ArtifactHash")
	}
}

func TestStatusAnchorVersionIsSigned(t *testing.T) {
	_, priv := mustKey(t)
	a := sampleStatusAnchor()
	a.Sign(priv)
	a.ArtifactVersion = 99
	if a.Verify() {
		t.Fatal("Verify() = true after tampering with ArtifactVersion — rollback would be undetectable")
	}
}

func TestStatusAnchorRejectsWrongKind(t *testing.T) {
	_, priv := mustKey(t)
	b := sampleAttestation()
	b.Sign(priv)
	if _, err := UnmarshalStatusAnchor(b.Marshal()); err == nil {
		t.Fatal("UnmarshalStatusAnchor accepted an Attestation")
	}
}

func TestStatusAnchorRejectsTrailingBytes(t *testing.T) {
	_, priv := mustKey(t)
	a := sampleStatusAnchor()
	a.Sign(priv)
	if _, err := UnmarshalStatusAnchor(append(a.Marshal(), 0x00)); err == nil {
		t.Fatal("UnmarshalStatusAnchor accepted trailing bytes")
	}
}

// TestStatusAnchorSigningPayloadCommitsToDomain asserts the domain tag is
// actually inside the signed bytes.
//
// Comparing a StatusAnchor signature against an IdentityBinding is NOT a valid
// test of this: their field layouts differ, so verification fails for that
// reason alone and the assertion passes even with domain separation deleted
// (verified by mutation). Only inspecting the payload catches its removal.
func TestStatusAnchorSigningPayloadCommitsToDomain(t *testing.T) {
	p := sampleStatusAnchor().signingPayload()
	if !bytes.Contains(p, []byte(domainStatusAnchor)) {
		t.Fatalf("signing payload does not commit to %q — signatures are replayable across message types", domainStatusAnchor)
	}
	if bytes.Contains(p, []byte(domainIdentityBinding)) {
		t.Fatal("status payload carries the identity-binding domain")
	}
}

func TestPeekKindStatusAnchor(t *testing.T) {
	_, priv := mustKey(t)
	a := sampleStatusAnchor()
	a.Sign(priv)
	k, err := PeekKind(a.Marshal())
	if err != nil {
		t.Fatalf("PeekKind: %v", err)
	}
	if k != KindStatusAnchor {
		t.Fatalf("PeekKind = %d, want %d", k, KindStatusAnchor)
	}
}
