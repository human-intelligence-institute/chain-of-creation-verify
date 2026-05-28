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
