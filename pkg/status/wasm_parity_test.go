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
		v, e, err := Resolve(f, withdrawnLeaf, 1, f.roots)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
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
		v, _, err := Resolve(f, [32]byte{0xab}, 1, f.roots)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if v != VerdictVerified {
			t.Fatalf("verdict = %v, want VERIFIED", v)
		}
	})

	t.Run("indeterminate", func(t *testing.T) {
		f := newFetcherWithAnchor(t, 1, withdrawnLeaf)
		delete(f.artifacts, 1)
		v, _, err := Resolve(f, withdrawnLeaf, 1, f.roots)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if v != VerdictIndeterminate {
			t.Fatalf("verdict = %v, want INDETERMINATE", v)
		}
	})
}
