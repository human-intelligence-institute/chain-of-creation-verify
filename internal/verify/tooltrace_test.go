package verify

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/human-intelligence-institute/chain-of-creation-verify/pkg/leaf"
)

// canonicalTrace builds a ToolTrace exactly as HII does: sorted keys, no
// whitespace. Go's encoding/json already sorts map keys and emits no spaces, so
// this is the same byte sequence Python's
// json.dumps(..., sort_keys=True, separators=(",",":")) produces.
func canonicalTrace(t *testing.T, fields map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func attWithTrace(exact leaf.Hash, trace []byte) *leaf.Attestation {
	return &leaf.Attestation{ExactHash: exact, ToolTrace: trace}
}

func sampleHash(b byte) leaf.Hash {
	var h leaf.Hash
	for i := range h {
		h[i] = b
	}
	return h
}

func TestInspectToolTraceAbsentIsNotAnError(t *testing.T) {
	// A non-HII leaf carries no trace. That must read as "absent", NOT as a
	// failed check — conflating the two would make every third-party leaf look
	// suspicious.
	rep := InspectToolTrace(&leaf.Attestation{})
	if rep.Present || rep.Parsed {
		t.Fatalf("empty trace should be absent, got %+v", rep)
	}
	if rep.Note != "" {
		t.Fatalf("absent trace should not carry a note, got %q", rep.Note)
	}
}

func TestInspectToolTraceNilAttestation(t *testing.T) {
	if rep := InspectToolTrace(nil); rep.Present {
		t.Fatalf("nil attestation should report absent, got %+v", rep)
	}
}

func TestInspectToolTraceHappyPath(t *testing.T) {
	exact := sampleHash(0xab)
	trace := canonicalTrace(t, map[string]any{
		"certification_id":   "cc14b56d-0047-4b43-a083-2f11ca15b99b",
		"exact_hash":         hex.EncodeToString(exact[:]),
		"kms_cert_signature": "c2ln",
		"metadata_hash":      "de1e7e",
	})

	rep := InspectToolTrace(attWithTrace(exact, trace))

	if !rep.Present || !rep.Parsed {
		t.Fatalf("expected present+parsed, got %+v", rep)
	}
	if !rep.Canonical {
		t.Error("canonical trace should be reported canonical")
	}
	if !rep.ExactHashChecked || !rep.ExactHashMatches {
		t.Error("exact_hash should be checked and match the leaf")
	}
	if !rep.HasKMSSignature || !rep.HasMetadataHash {
		t.Error("presence flags should be set")
	}
	if rep.CertificationID != "cc14b56d-0047-4b43-a083-2f11ca15b99b" {
		t.Errorf("certification_id = %q", rep.CertificationID)
	}
}

// The point of the whole file: a trace that is intact and well-formed but
// describes a DIFFERENT leaf's media must not pass. Signature tamper-evidence
// cannot catch this — the producer signs whatever trace it is given.
func TestInspectToolTraceDetectsBindingToTheWrongLeaf(t *testing.T) {
	leafHash := sampleHash(0x11)
	otherHash := sampleHash(0x22)
	trace := canonicalTrace(t, map[string]any{
		"certification_id":   "some-cert",
		"exact_hash":         hex.EncodeToString(otherHash[:]), // not this leaf
		"kms_cert_signature": "c2ln",
		"metadata_hash":      "de1e7e",
	})

	rep := InspectToolTrace(attWithTrace(leafHash, trace))

	if !rep.Parsed {
		t.Fatalf("trace should parse, got %+v", rep)
	}
	if !rep.ExactHashChecked {
		t.Fatal("exact_hash should have been checked")
	}
	if rep.ExactHashMatches {
		t.Fatal("a trace bound to another leaf's media must NOT match")
	}
}

func TestInspectToolTraceNonCanonicalEncoding(t *testing.T) {
	// Same content, pretty-printed. It is not forged — it is unreproducible,
	// which defeats third-party verification just as thoroughly, so the report
	// must distinguish it from the canonical form while still parsing.
	exact := sampleHash(0x33)
	pretty, err := json.MarshalIndent(map[string]any{
		"certification_id":   "c",
		"exact_hash":         hex.EncodeToString(exact[:]),
		"kms_cert_signature": "c2ln",
		"metadata_hash":      "de1e7e",
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	rep := InspectToolTrace(attWithTrace(exact, pretty))

	if !rep.Parsed {
		t.Fatal("pretty-printed JSON should still parse")
	}
	if rep.Canonical {
		t.Fatal("indented JSON must not be reported canonical")
	}
	// The binding itself is still checkable.
	if !rep.ExactHashMatches {
		t.Error("exact_hash should still match despite the encoding")
	}
}

func TestInspectToolTraceMalformedJSON(t *testing.T) {
	rep := InspectToolTrace(attWithTrace(sampleHash(1), []byte("{not json")))
	if !rep.Present {
		t.Fatal("a malformed trace is still present")
	}
	if rep.Parsed {
		t.Fatal("malformed JSON must not report parsed")
	}
	if rep.Note == "" {
		t.Fatal("a parse failure must explain itself")
	}
}

func TestInspectToolTraceTrailingContent(t *testing.T) {
	// Two concatenated objects: the first parses, so a naive decoder would
	// accept it and silently ignore the rest.
	rep := InspectToolTrace(attWithTrace(sampleHash(1), []byte(`{"certification_id":"a"}{"certification_id":"b"}`)))
	if rep.Parsed {
		t.Fatal("trailing content after the object must not report parsed")
	}
	if rep.Note == "" {
		t.Fatal("expected a note explaining the trailing content")
	}
}

func TestInspectToolTraceBadHexExactHash(t *testing.T) {
	trace := canonicalTrace(t, map[string]any{
		"certification_id":   "c",
		"exact_hash":         "zzzz", // not hex
		"kms_cert_signature": nil,
		"metadata_hash":      nil,
	})
	rep := InspectToolTrace(attWithTrace(sampleHash(1), trace))

	if !rep.Parsed {
		t.Fatal("schema still parses; only the hash value is bad")
	}
	if rep.ExactHashMatches {
		t.Fatal("unparseable hex must never be reported as a match")
	}
	if rep.ExactHashChecked {
		t.Fatal("a hash that could not be decoded was not actually checked")
	}
	if rep.Note == "" {
		t.Fatal("expected a note about the bad hex")
	}
}

func TestInspectToolTraceNullOptionalFields(t *testing.T) {
	// HII emits absent fields as JSON null, not by omitting the key.
	exact := sampleHash(0x44)
	trace := canonicalTrace(t, map[string]any{
		"certification_id":   "c",
		"exact_hash":         hex.EncodeToString(exact[:]),
		"kms_cert_signature": nil,
		"metadata_hash":      nil,
	})

	rep := InspectToolTrace(attWithTrace(exact, trace))

	if !rep.Parsed {
		t.Fatalf("nulls must not break parsing: %+v", rep)
	}
	if rep.HasKMSSignature || rep.HasMetadataHash {
		t.Error("null fields should report as absent, not present")
	}
	if !rep.ExactHashMatches {
		t.Error("exact_hash should still match")
	}
	if !rep.Canonical {
		t.Error("nulls are part of the canonical form and should stay canonical")
	}
}

// An empty exact_hash means the producer supplied no binding to check. That must
// leave ExactHashMatches false AND ExactHashChecked false — reporting an
// unchecked field as "matching" is the failure mode this guards.
func TestInspectToolTraceMissingExactHashIsUnchecked(t *testing.T) {
	trace := canonicalTrace(t, map[string]any{
		"certification_id":   "c",
		"exact_hash":         "",
		"kms_cert_signature": nil,
		"metadata_hash":      nil,
	})
	rep := InspectToolTrace(attWithTrace(sampleHash(1), trace))

	if rep.ExactHashChecked || rep.ExactHashMatches {
		t.Fatalf("absent exact_hash must be unchecked and unmatched, got %+v", rep)
	}
}
