package cocverify_test

// Inclusion verification against the frozen log in testdata/. These are the
// tests that were parked during extraction because they drove a live log node;
// the assertions are unchanged — only the source of the log artifacts is.

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/human-intelligence-institute/chain-of-creation-verify/pkg/cocverify"
	"golang.org/x/mod/sumdb/note"
)

func TestVerifyInclusion_Included(t *testing.T) {
	ctx := context.Background()
	m := loadManifest(t)
	raw := m.raw(t, "inclusion-attestation")
	idx := m.index(t, "inclusion-attestation")

	res, err := cocverify.VerifyInclusion(ctx, fixtureFetcher(t), raw, idx, m.Origin, m.VKey)
	if err != nil {
		t.Fatalf("VerifyInclusion: %v", err)
	}
	if !res.Included {
		t.Fatalf("want Included=true, got %+v", res)
	}
	if !res.CheckpointSigValid || res.TreeSize < 1 {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestVerifyInclusion_TamperedLeaf(t *testing.T) {
	ctx := context.Background()
	m := loadManifest(t)
	raw := m.raw(t, "inclusion-attestation")
	idx := m.index(t, "inclusion-attestation")

	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-1] ^= 0xff // flip a byte → different leaf hash
	res, err := cocverify.VerifyInclusion(ctx, fixtureFetcher(t), tampered, idx, m.Origin, m.VKey)
	if err != nil {
		t.Fatalf("VerifyInclusion: %v", err)
	}
	if res.Included {
		t.Fatal("tampered leaf must not verify as included")
	}
	// The verdict must come from the proof, not from a broken fetcher: the
	// checkpoint was still read and verified.
	if !res.CheckpointSigValid || res.TreeSize == 0 {
		t.Fatalf("negative verdict did not come from a verified checkpoint: %+v", res)
	}
}

func TestVerifyInclusion_IndexBeyondTree(t *testing.T) {
	ctx := context.Background()
	m := loadManifest(t)
	raw := m.raw(t, "inclusion-attestation")

	res, err := cocverify.VerifyInclusion(ctx, fixtureFetcher(t), raw, 9999, m.Origin, m.VKey)
	if err != nil {
		t.Fatalf("VerifyInclusion: %v", err)
	}
	if res.Included {
		t.Fatal("index beyond tree size must not be included")
	}
	if !res.CheckpointSigValid || res.TreeSize == 0 {
		t.Fatalf("negative verdict did not come from a verified checkpoint: %+v", res)
	}
}

func TestVerifyInclusion_WrongPinnedKey(t *testing.T) {
	ctx := context.Background()
	m := loadManifest(t)
	raw := m.raw(t, "inclusion-attestation")
	idx := m.index(t, "inclusion-attestation")

	// A different key with the same origin name — the checkpoint signature must
	// fail to verify, which is a hard error (never a silent pass).
	_, wrongVkey, err := note.GenerateKey(rand.Reader, m.Origin)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := cocverify.VerifyInclusion(ctx, fixtureFetcher(t), raw, idx, m.Origin, wrongVkey); err == nil {
		t.Fatal("expected error when the checkpoint is not signed by the pinned key")
	}
}
