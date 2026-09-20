package cocverify_test

// The reason a verdict is INDETERMINATE only helps a user if it survives the
// whole way out: Go struct -> JSON -> the wasm bridge -> web/index.html's
// lookup table. Every hop is a place a name can drift, and the failure is
// silent — an unrecognised key falls through to the generic "could not be
// determined" copy, which is precisely the opaque message this was meant to
// remove. Nothing else in the suite would go red.

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/human-intelligence-institute/chain-of-creation-verify/pkg/cocverify"
	"github.com/human-intelligence-institute/chain-of-creation-verify/pkg/status"
)

// allReasons is every non-empty status.Reason. Adding a reason without adding
// it here, and to the page, is the drift this file exists to catch.
var allReasons = []status.Reason{
	status.ReasonAnchorScanFailed,
	status.ReasonAnchorUntrusted,
	status.ReasonArtifactUnreachable,
	status.ReasonArtifactParseError,
	status.ReasonArtifactHashMismatch,
}

func TestStatusResultJSONCarriesTheReason(t *testing.T) {
	res := cocverify.StatusResult{
		Verdict:             string(status.VerdictIndeterminate),
		TreeSize:            7,
		IndeterminateReason: string(status.ReasonArtifactHashMismatch),
		IndeterminateDetail: "dial tcp: connection refused",
	}
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]any{
		"indeterminate_reason": "artifact_hash_mismatch",
		"indeterminate_detail": "dial tcp: connection refused",
	} {
		if got[k] != want {
			t.Errorf("%s = %v, want %v — web/index.html reads this exact key", k, got[k], want)
		}
	}
}

// A definite verdict must serialize exactly as it did before these fields
// existed. Both are omitempty precisely so adding them is not a wire change.
func TestDefiniteVerdictJSONIsUnchanged(t *testing.T) {
	raw, err := json.Marshal(cocverify.StatusResult{Verdict: "VERIFIED", TreeSize: 7})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"indeterminate_reason", "indeterminate_detail"} {
		if strings.Contains(string(raw), k) {
			t.Errorf("%s present on a definite verdict: %s", k, raw)
		}
	}
}

// TestWebPageHandlesEveryReason reads the shipped page and asserts its lookup
// table has an arm for each reason. This is a string check on purpose: the page
// is the artifact users actually run, and there is no other test in this
// repository that reads it at all.
func TestWebPageHandlesEveryReason(t *testing.T) {
	page, err := os.ReadFile("../../web/index.html")
	if err != nil {
		t.Skipf("web/index.html not readable from here: %v", err)
	}
	for _, r := range allReasons {
		if !strings.Contains(string(page), string(r)+":") {
			t.Errorf("web/index.html has no arm for reason %q — it would fall through to the generic copy", r)
		}
	}
	// And the field names the page reads must be the ones Go emits.
	for _, k := range []string{"indeterminate_reason", "indeterminate_detail"} {
		if !strings.Contains(string(page), k) {
			t.Errorf("web/index.html never reads %q", k)
		}
	}
}
