package status

import (
	"encoding/base64"
	"testing"
)

const sampleLeafB64 = "ESIzAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

const sampleRaw = `{"issued_at":1786000000000,"log_size_at_issue":42,"schema":1,"version":3,` +
	`"withdrawn":[{"leaf_hash":"` + sampleLeafB64 + `",` +
	`"reason":"certification_rejected","withdrawn_at":1786000000001}]}`

func TestParseArtifact(t *testing.T) {
	a, h, err := ParseArtifact([]byte(sampleRaw))
	if err != nil {
		t.Fatalf("ParseArtifact: %v", err)
	}
	if a.Version != 3 || a.Schema != 1 {
		t.Fatalf("got version=%d schema=%d", a.Version, a.Schema)
	}
	if a.IssuedAt != 1786000000000 || a.LogSizeAtIssue != 42 {
		t.Fatalf("got issued_at=%d log_size=%d", a.IssuedAt, a.LogSizeAtIssue)
	}
	if len(a.Withdrawn) != 1 {
		t.Fatalf("got %d withdrawn entries, want 1", len(a.Withdrawn))
	}
	if h == ([32]byte{}) {
		t.Fatal("hash is zero")
	}
}

// The verifier must hash the bytes it received, never a re-serialisation. The
// producer is Python and the verifier is Go; any canonicalisation mismatch
// would otherwise surface as a spurious INDETERMINATE verdict.
func TestHashIsOverRawBytesNotReserialised(t *testing.T) {
	spaced := `{"issued_at": 1786000000000, "log_size_at_issue": 42, "schema": 1, ` +
		`"version": 3, "withdrawn": []}`
	compact := `{"issued_at":1786000000000,"log_size_at_issue":42,"schema":1,` +
		`"version":3,"withdrawn":[]}`
	_, h1, err := ParseArtifact([]byte(spaced))
	if err != nil {
		t.Fatalf("ParseArtifact(spaced): %v", err)
	}
	_, h2, err := ParseArtifact([]byte(compact))
	if err != nil {
		t.Fatalf("ParseArtifact(compact): %v", err)
	}
	if h1 == h2 {
		t.Fatal("hashes matched — implementation is re-serialising instead of hashing raw bytes")
	}
}

func TestFindHit(t *testing.T) {
	a, _, err := ParseArtifact([]byte(sampleRaw))
	if err != nil {
		t.Fatalf("ParseArtifact: %v", err)
	}
	e, ok := a.Find(mustLeafHash(t, sampleLeafB64))
	if !ok {
		t.Fatal("Find() = false for a withdrawn leaf")
	}
	if e.Reason != "certification_rejected" {
		t.Fatalf("reason = %q", e.Reason)
	}
	if e.WithdrawnAt != 1786000000001 {
		t.Fatalf("withdrawn_at = %d", e.WithdrawnAt)
	}
}

func TestFindMiss(t *testing.T) {
	a, _, err := ParseArtifact([]byte(sampleRaw))
	if err != nil {
		t.Fatalf("ParseArtifact: %v", err)
	}
	if _, ok := a.Find([32]byte{0xff}); ok {
		t.Fatal("Find() = true for a leaf that is not withdrawn")
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	if _, _, err := ParseArtifact([]byte("{not json")); err == nil {
		t.Fatal("ParseArtifact accepted malformed JSON")
	}
}

func mustLeafHash(t *testing.T, b64 string) [32]byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode %q: %v", b64, err)
	}
	if len(raw) != 32 {
		t.Fatalf("leaf hash is %d bytes, want 32", len(raw))
	}
	var out [32]byte
	copy(out[:], raw)
	return out
}
