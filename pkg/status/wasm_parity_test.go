package status

import "testing"

// TestGoldenStatusParity pins the WASM build to the same verdicts as native Go.
//
// It is named "Golden" so the CI wasm-parity job's `-run Golden` filter picks it
// up; renaming it silently removes WASM coverage. It deliberately covers all
// three verdicts, because a divergence in the fail-closed path is the one that
// would turn into a false VERIFIED in the browser while native Go stayed correct.
func TestGoldenStatusParity(t *testing.T) {
	t.Run("withdrawn", func(t *testing.T) {
		f := newFetcherWithAnchor(t, 1, withdrawnLeaf)
		v, e, reason, cause := Resolve(f, withdrawnLeaf, 1, f.roots)
		if cause != nil {
			t.Fatalf("Resolve cause: %v", cause)
		}
		if reason != ReasonNone {
			t.Fatalf("reason = %q, want empty on a definite verdict", reason)
		}
		if v != VerdictWithdrawn {
			t.Fatalf("verdict = %v, want WITHDRAWN", v)
		}
		if e == nil || e.Reason != "certification_rejected" {
			t.Fatalf("entry = %+v", e)
		}
	})

	t.Run("verified", func(t *testing.T) {
		f := newFetcherWithAnchor(t, 1, withdrawnLeaf)
		v, _, reason, cause := Resolve(f, [32]byte{0xab}, 1, f.roots)
		if cause != nil {
			t.Fatalf("Resolve cause: %v", cause)
		}
		if reason != ReasonNone {
			t.Fatalf("reason = %q, want empty on a definite verdict", reason)
		}
		if v != VerdictVerified {
			t.Fatalf("verdict = %v, want VERIFIED", v)
		}
	})

	t.Run("indeterminate", func(t *testing.T) {
		f := newFetcherWithAnchor(t, 1, withdrawnLeaf)
		delete(f.artifacts, 1)
		v, _, reason, _ := Resolve(f, withdrawnLeaf, 1, f.roots)
		if v != VerdictIndeterminate {
			t.Fatalf("verdict = %v, want INDETERMINATE", v)
		}
		// The REASON must cross the native/wasm boundary intact too. A browser
		// that reached the same verdict by a different route, or lost the
		// reason string, would show the user something the CLI never would.
		if reason != ReasonArtifactUnreachable {
			t.Fatalf("reason = %q, want %q", reason, ReasonArtifactUnreachable)
		}
	})
}
