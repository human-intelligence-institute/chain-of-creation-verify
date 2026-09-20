package provenance

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/human-intelligence-institute/chain-of-creation-verify/pkg/leaf"
)

var testWork = [16]byte{1, 1, 1}

// mkEvent builds a signed attestation for testWork at seq, linked to prev.
func mkEvent(t *testing.T, seq uint64, prev *leaf.Hash) *leaf.Attestation {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	a := &leaf.Attestation{
		SchemaVersion: 1,
		WorkID:        testWork,
		EventSeq:      seq,
		PrevEventHash: prev,
		EventType:     leaf.EventEdit,
		MediaType:     leaf.MediaText,
		AlgorithmID:   "simhash-text-v1",
		FuzzyDigest:   []byte{byte(seq)},
		SubmittedAt:   uint64(1_700_000_000_000 + seq),
	}
	a.Sign(priv)
	return a
}

// linkedChain returns n attestations forming a linear history.
func linkedChain(t *testing.T, n int) []*leaf.Attestation {
	t.Helper()
	out := make([]*leaf.Attestation, 0, n)
	var prev *leaf.Hash
	for i := 0; i < n; i++ {
		a := mkEvent(t, uint64(i), prev)
		h := a.LeafHash()
		prev = &h
		out = append(out, a)
	}
	return out
}

func TestLinearChain(t *testing.T) {
	ix := NewIndex()
	for i, a := range linkedChain(t, 4) {
		ix.Add(a, uint64(i))
	}
	chain, ok := ix.Work(testWork)
	if !ok {
		t.Fatal("work not found")
	}
	in := chain.Analyze()
	if !in.Linear || len(in.Roots) != 1 || len(in.Forks) != 0 || len(in.Dangling) != 0 {
		t.Fatalf("expected linear chain, got %+v", in)
	}
	ordered, err := chain.Linearize()
	if err != nil {
		t.Fatalf("Linearize: %v", err)
	}
	for i, e := range ordered {
		if e.Att.EventSeq != uint64(i) {
			t.Fatalf("event %d out of order: seq %d", i, e.Att.EventSeq)
		}
	}
}

func TestForkExposed(t *testing.T) {
	chain := linkedChain(t, 2) // seq0 -> seq1
	// A competing seq1 event sharing the same parent (the root).
	rootHash := chain[0].LeafHash()
	competing := mkEvent(t, 1, &rootHash)

	ix := NewIndex()
	ix.Add(chain[0], 0)
	ix.Add(chain[1], 1)
	ix.Add(competing, 2)

	c, _ := ix.Work(testWork)
	in := c.Analyze()
	if in.Linear {
		t.Fatal("chain with a fork must not be linear")
	}
	if len(in.Forks) != 1 || len(in.Forks[0].Children) != 2 {
		t.Fatalf("expected one fork with two children, got %+v", in.Forks)
	}
	if _, err := c.Linearize(); err != ErrNotLinear {
		t.Fatalf("Linearize should fail with ErrNotLinear, got %v", err)
	}
}

func TestMultipleRoots(t *testing.T) {
	ix := NewIndex()
	ix.Add(mkEvent(t, 0, nil), 0)
	ix.Add(mkEvent(t, 0, nil), 1)

	c, _ := ix.Work(testWork)
	in := c.Analyze()
	if in.Linear || len(in.Roots) != 2 {
		t.Fatalf("expected two roots, non-linear; got %+v", in)
	}
	foundRootFork := false
	for _, f := range in.Forks {
		if f.Root {
			foundRootFork = true
		}
	}
	if !foundRootFork {
		t.Fatal("expected a root fork")
	}
}

func TestDanglingLink(t *testing.T) {
	bogus := leaf.Hash{0xff, 0xee}
	ix := NewIndex()
	ix.Add(mkEvent(t, 0, nil), 0)
	ix.Add(mkEvent(t, 1, &bogus), 1) // prev references an absent event

	c, _ := ix.Work(testWork)
	in := c.Analyze()
	if in.Linear || len(in.Dangling) != 1 {
		t.Fatalf("expected one dangling event, non-linear; got %+v", in)
	}
}

func TestMultipleWorks(t *testing.T) {
	ix := NewIndex()
	a := &leaf.Attestation{WorkID: [16]byte{1}, MediaType: leaf.MediaText}
	b := &leaf.Attestation{WorkID: [16]byte{2}, MediaType: leaf.MediaText}
	ix.Add(a, 0)
	ix.Add(b, 1)

	works := ix.Works()
	if len(works) != 2 {
		t.Fatalf("expected 2 works, got %d", len(works))
	}
	if works[0][0] != 1 || works[1][0] != 2 {
		t.Fatalf("works not sorted: %v", works)
	}
	if _, ok := ix.Work([16]byte{3}); ok {
		t.Fatal("unknown work should not resolve")
	}
}
