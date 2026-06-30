package cocverify_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/human-intelligence-institute/chain-of-creation/internal/leaf"
	"github.com/human-intelligence-institute/chain-of-creation/internal/lognode"
	"github.com/human-intelligence-institute/chain-of-creation/pkg/cocverify"
	"golang.org/x/mod/sumdb/note"
)

const inclOrigin = "coc-incl-test"

// nodeWithKnownKey spins a local POSIX log and returns it plus the note vkey a
// verifier would pin. AppendAwait is enabled so a submission blocks until it is
// covered by a published checkpoint.
func nodeWithKnownKey(t *testing.T) (*lognode.Node, string) {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, inclOrigin)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	n, err := lognode.New(context.Background(), lognode.Config{
		StoragePath:              t.TempDir(),
		CheckpointSigner:         signer,
		BatchMaxAge:              20 * time.Millisecond,
		CheckpointInterval:       100 * time.Millisecond,
		EnablePublicationAwaiter: true,
		AwaiterPollInterval:      20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("lognode.New: %v", err)
	}
	t.Cleanup(func() { _ = n.Close(context.Background()) })
	return n, vkey
}

func signedLeaf(t *testing.T) []byte {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	a := &leaf.Attestation{
		SchemaVersion: 1,
		WorkID:        [16]byte{1, 2, 3},
		EventType:     leaf.EventPublish,
		MediaType:     leaf.MediaText,
		AlgorithmID:   "simhash-text-v1",
		FuzzyDigest:   []byte{0xca, 0xb7, 0x99, 0x1c, 0x54, 0x75, 0xed, 0xee},
		SubmittedAt:   uint64(time.Now().UnixMilli()),
	}
	a.Sign(priv)
	return a.Marshal()
}

func fetcherFor(n *lognode.Node) cocverify.Fetcher {
	r := n.Reader()
	return cocverify.Fetcher{Checkpoint: r.ReadCheckpoint, Tile: r.ReadTile}
}

func TestVerifyInclusion_Included(t *testing.T) {
	ctx := context.Background()
	n, vkey := nodeWithKnownKey(t)
	raw := signedLeaf(t)
	idx, _, err := n.AppendAwait(ctx, raw)
	if err != nil {
		t.Fatalf("AppendAwait: %v", err)
	}
	res, err := cocverify.VerifyInclusion(ctx, fetcherFor(n), raw, idx.Index, inclOrigin, vkey)
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
	n, vkey := nodeWithKnownKey(t)
	raw := signedLeaf(t)
	idx, _, err := n.AppendAwait(ctx, raw)
	if err != nil {
		t.Fatalf("AppendAwait: %v", err)
	}
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-1] ^= 0xff // flip a byte → different leaf hash
	res, err := cocverify.VerifyInclusion(ctx, fetcherFor(n), tampered, idx.Index, inclOrigin, vkey)
	if err != nil {
		t.Fatalf("VerifyInclusion: %v", err)
	}
	if res.Included {
		t.Fatal("tampered leaf must not verify as included")
	}
}

func TestVerifyInclusion_IndexBeyondTree(t *testing.T) {
	ctx := context.Background()
	n, vkey := nodeWithKnownKey(t)
	raw := signedLeaf(t)
	if _, _, err := n.AppendAwait(ctx, raw); err != nil {
		t.Fatalf("AppendAwait: %v", err)
	}
	res, err := cocverify.VerifyInclusion(ctx, fetcherFor(n), raw, 9999, inclOrigin, vkey)
	if err != nil {
		t.Fatalf("VerifyInclusion: %v", err)
	}
	if res.Included {
		t.Fatal("index beyond tree size must not be included")
	}
}

func TestVerifyInclusion_WrongPinnedKey(t *testing.T) {
	ctx := context.Background()
	n, _ := nodeWithKnownKey(t)
	raw := signedLeaf(t)
	idx, _, err := n.AppendAwait(ctx, raw)
	if err != nil {
		t.Fatalf("AppendAwait: %v", err)
	}
	// A different key with the same origin name — the checkpoint signature must
	// fail to verify, which is a hard error (never a silent pass).
	_, wrongVkey, _ := note.GenerateKey(rand.Reader, inclOrigin)
	if _, err := cocverify.VerifyInclusion(ctx, fetcherFor(n), raw, idx.Index, inclOrigin, wrongVkey); err == nil {
		t.Fatal("expected error when the checkpoint is not signed by the pinned key")
	}
}
