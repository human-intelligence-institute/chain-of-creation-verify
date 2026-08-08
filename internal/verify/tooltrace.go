package verify

import (
	"bytes"
	"encoding/hex"
	"encoding/json"

	"github.com/human-intelligence-institute/chain-of-creation/internal/leaf"
)

// HII writes a ToolTrace appendix into each custodial Attestation binding the
// leaf to the certification that produced it. The trace is already
// TAMPER-EVIDENT without any of the code below: Attestation.toolTraceHash is
// folded into the signing payload, so altering a byte invalidates the signature
// (see TestToolTraceTamperBreaksVerification).
//
// What this file adds is SEMANTIC validation — the trace being intact says
// nothing about whether it refers to the certificate a verifier was handed.
// Those are different claims and the report keeps them separate.
//
// Canonical form, as produced by HII:
//
//	json.dumps({certification_id, exact_hash, kms_cert_signature, metadata_hash},
//	           sort_keys=True, separators=(",", ":")).encode("utf-8")
//
// i.e. keys sorted, no whitespace, absent fields present as JSON null. Go's
// encoding/json sorts map keys and omits spaces, so marshalling a
// map[string]any reproduces that byte-for-byte — which is what Canonical
// checks. (86bapjeft)
//
// SCOPE: everything here is offline and self-contained. Verifying
// kms_cert_signature against HII's KMS public key, and checking metadata_hash
// against the fetched off-log metadata, both need inputs a third party must
// first be able to OBTAIN — an unsolved distribution question, tracked
// separately on 86bapjeft.

// ToolTrace is the HII certification binding carried in an Attestation.
type ToolTrace struct {
	CertificationID  string `json:"certification_id"`
	ExactHash        string `json:"exact_hash"`         // hex, lowercase
	KMSCertSignature string `json:"kms_cert_signature"` // base64 KMS signature over the cert payload
	MetadataHash     string `json:"metadata_hash"`      // hex sha256 of the off-log metadata JSON
}

// ToolTraceReport records what could be established about the binding. Like the
// rest of this package it reports findings rather than a verdict: a caller
// deciding what "verified" means needs to see WHICH checks ran.
type ToolTraceReport struct {
	Present bool `json:"present"`
	Parsed  bool `json:"parsed"`

	CertificationID string `json:"certification_id,omitempty"`

	// Canonical is true when the trace bytes exactly reproduce the canonical
	// encoding of their own contents. A false here does not mean forgery — it
	// means the producer's serialization is not reproducible, which defeats
	// third-party verification just as effectively.
	Canonical bool `json:"canonical"`

	// ExactHashChecked/Matches compare the binding's exact_hash to the leaf's
	// ExactHash. This is the one substantive cross-check available offline: it
	// proves the trace describes THIS leaf's media rather than another's.
	ExactHashChecked bool `json:"exact_hash_checked"`
	ExactHashMatches bool `json:"exact_hash_matches"`

	// Populated but NOT verified here — see SCOPE above.
	HasKMSSignature bool `json:"has_kms_signature"`
	HasMetadataHash bool `json:"has_metadata_hash"`

	Note string `json:"note,omitempty"`
}

// InspectToolTrace parses and cross-checks the ToolTrace on an attestation.
//
// A missing trace is not an error: ToolTrace is optional and non-HII leaves
// carry none. The caller distinguishes "absent" from "present but unparseable"
// via Present/Parsed, because those mean very different things — the second is
// a red flag, the first is routine.
func InspectToolTrace(att *leaf.Attestation) ToolTraceReport {
	var rep ToolTraceReport
	if att == nil || len(att.ToolTrace) == 0 {
		return rep
	}
	rep.Present = true

	// Decode into a map first so canonicality can be judged against exactly the
	// keys present, without a struct silently inventing or dropping fields.
	var raw map[string]any
	dec := json.NewDecoder(bytes.NewReader(att.ToolTrace))
	if err := dec.Decode(&raw); err != nil {
		rep.Note = "tool_trace is not valid JSON: " + err.Error()
		return rep
	}
	// Trailing bytes after the object mean this is not a single canonical value.
	if dec.More() {
		rep.Note = "tool_trace has trailing content after the JSON object"
		return rep
	}

	var tt ToolTrace
	if err := json.Unmarshal(att.ToolTrace, &tt); err != nil {
		rep.Note = "tool_trace does not match the HII schema: " + err.Error()
		return rep
	}
	rep.Parsed = true
	rep.CertificationID = tt.CertificationID
	rep.HasKMSSignature = tt.KMSCertSignature != ""
	rep.HasMetadataHash = tt.MetadataHash != ""

	// Re-marshal the decoded map: encoding/json sorts keys and emits no spaces,
	// matching Python's sort_keys=True + separators=(",",":").
	if canon, err := json.Marshal(raw); err == nil {
		rep.Canonical = bytes.Equal(canon, att.ToolTrace)
	}

	// Does this binding describe the leaf it rides on?
	if tt.ExactHash != "" {
		rep.ExactHashChecked = true
		want := make([]byte, len(att.ExactHash))
		copy(want, att.ExactHash[:])
		got, err := hex.DecodeString(tt.ExactHash)
		if err != nil {
			rep.Note = "tool_trace exact_hash is not valid hex"
			rep.ExactHashChecked = false
		} else {
			rep.ExactHashMatches = bytes.Equal(got, want)
		}
	}

	return rep
}
