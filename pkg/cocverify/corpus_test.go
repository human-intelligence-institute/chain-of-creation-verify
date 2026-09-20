package cocverify_test

// The frozen leaf corpus.
//
// Every other test in this package builds its input with the same code it is
// testing: construct an Attestation, sign it, marshal it, verify it. That
// round-trip stays green through a reordered encoder, a changed signing domain
// string, or a legacy algorithm quietly dropped from the registry — while every
// leaf already written to a transparency log stops verifying. The golden vectors
// in spec/simhash64-vectors.json close the same gap one level down, for the
// digest function alone; nothing until now covered a whole certificate.
//
// These cases are bytes on disk that no test regenerates. They were produced
// once by cmd/gencorpus and are never rewritten — the generator refuses to
// overwrite an existing case directory. Each case.json carries the complete
// expected LeafResult, so a change anywhere in leaf encoding, signature
// coverage, hashing, algorithm resolution, distance metrics, or thresholds
// surfaces here as a diff against a value frozen at the time the format was
// published.
//
// ⚠️ A red test here is not a fixture to refresh. It means a published contract
// moved, which the spec says requires a new algorithm id or schema version —
// never an in-place edit. Regenerating the corpus to make it pass destroys the
// only evidence that anything changed.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/human-intelligence-institute/chain-of-creation-verify/pkg/cocverify"
	"github.com/human-intelligence-institute/chain-of-creation-verify/pkg/fuzzy"
)

const corpusDir = "testdata/corpus"

type corpusCase struct {
	Name   string               `json:"name"`
	Why    string               `json:"why"`
	Leaf   string               `json:"leaf"`
	Media  string               `json:"media"`
	Text   string               `json:"text"`
	Expect cocverify.LeafResult `json:"expect"`
}

func loadCorpus(t *testing.T) []corpusCase {
	t.Helper()
	entries, err := os.ReadDir(corpusDir)
	if err != nil {
		t.Fatalf("read corpus dir: %v", err)
	}
	var cases []corpusCase
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(corpusDir, e.Name(), "case.json"))
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		var c corpusCase
		// DisallowUnknownFields: a field added to the case format without
		// updating the frozen cases would otherwise be silently ignored.
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&c); err != nil {
			t.Fatalf("%s/case.json: %v", e.Name(), err)
		}
		if c.Name != e.Name() {
			t.Fatalf("%s/case.json: name is %q", e.Name(), c.Name)
		}
		cases = append(cases, c)
	}
	if len(cases) == 0 {
		t.Fatal("corpus is empty — testdata/corpus must not be pruned")
	}
	return cases
}

// TestGoldenLeafCorpus verifies each frozen leaf and compares the full result
// against the expectation committed beside it.
//
// The name starts with "Golden" so CI's wasm-parity job reaches it under
// `-run Golden`: phash-dct-64 thresholds a floating-point DCT, and native Go and
// js/wasm agreeing on those bits is not something to assume.
func TestGoldenLeafCorpus(t *testing.T) {
	for _, c := range loadCorpus(t) {
		t.Run(c.Name, func(t *testing.T) {
			dir := filepath.Join(corpusDir, c.Name)
			read := func(name string) []byte {
				if name == "" {
					return nil
				}
				b, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil {
					t.Fatalf("read %s: %v", name, err)
				}
				return b
			}

			got, err := cocverify.VerifyLeaf(read(c.Leaf), read(c.Media), read(c.Text))
			if err != nil {
				t.Fatalf("VerifyLeaf: %v", err)
			}
			if !reflect.DeepEqual(got, c.Expect) {
				gotJSON, _ := json.MarshalIndent(got, "", "  ")
				wantJSON, _ := json.MarshalIndent(c.Expect, "", "  ")
				t.Errorf("frozen case %q no longer verifies as published.\nwhy this case exists: %s\n\ngot:\n%s\n\nwant:\n%s\n\n"+
					"Do NOT regenerate the corpus to make this pass. A moved published contract "+
					"needs a new algorithm id or schema version (docs/verification-spec.md).",
					c.Name, c.Why, gotJSON, wantJSON)
			}
		})
	}
}

// TestGoldenLeafCorpusCoversEveryAlgorithm asserts the corpus holds at least one
// case per algorithm the default registry resolves. Registering a new algorithm
// without freezing a leaf for it is how the corpus would quietly stop being a
// complete record — the retired ids are the ones nobody remembers to test.
func TestGoldenLeafCorpusCoversEveryAlgorithm(t *testing.T) {
	covered := map[string]bool{}
	for _, c := range loadCorpus(t) {
		if c.Expect.Content != nil {
			covered[c.Expect.Content.AlgorithmID] = true
		}
	}
	for _, id := range fuzzy.Default().IDs() {
		if !covered[id] {
			t.Errorf("algorithm %q has no frozen leaf: add a case with `go run ./cmd/gencorpus`", id)
		}
	}
}
