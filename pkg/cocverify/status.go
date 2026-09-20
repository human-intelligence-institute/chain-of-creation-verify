package cocverify

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/human-intelligence-institute/chain-of-creation-verify/pkg/status"
	"github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/tessera/api/layout"
	"github.com/transparency-dev/tessera/client"
	"github.com/zeebo/blake3"
)

// These two declarations fail the build if the pure-logic bundle width in
// internal/status ever drifts from Tessera's actual entry-bundle width. The
// scanner computes bundle indices from that constant, so a mismatch would make
// it read the wrong bundles and silently miss anchors.
//
// Both directions are needed: uint(a-b) only rejects a < b, so a single
// declaration would let the constant drift upward unnoticed.
const (
	_ = uint(layout.EntryBundleWidth - status.BundleSize)
	_ = uint(status.BundleSize - layout.EntryBundleWidth)
)

// WithdrawnInfo describes a withdrawal, for the JSON bridge.
type WithdrawnInfo struct {
	At              uint64 `json:"at"`
	Reason          string `json:"reason"`
	ArtifactVersion uint64 `json:"artifact_version"`
}

// StatusResult is the outcome of revocation-status resolution for one leaf.
type StatusResult struct {
	// Verdict is VERIFIED, WITHDRAWN, or INDETERMINATE. It is never VERIFIED
	// unless status was actually resolved — see docs/verification-spec.md §12.
	Verdict   string         `json:"verdict"`
	Withdrawn *WithdrawnInfo `json:"withdrawn"`
	TreeSize  uint64         `json:"tree_size"`
}

// ResolveStatus reports whether the given raw leaf has been withdrawn by HII.
//
// The checkpoint is verified against the pinned (origin, vkey) — an
// unverifiable checkpoint is a hard error, never a silent pass — and the tree
// size it reports bounds the anchor scan.
func ResolveStatus(ctx context.Context, f Fetcher, rawLeaf []byte, origin, vkey string, roots [][32]byte) (StatusResult, error) {
	v, err := note.NewVerifier(vkey)
	if err != nil {
		return StatusResult{}, fmt.Errorf("pinned checkpoint key: %w", err)
	}
	cp, _, _, err := client.FetchCheckpoint(ctx, f.Checkpoint, v, origin)
	if err != nil {
		return StatusResult{}, fmt.Errorf("checkpoint: %w", err)
	}

	// The withdrawn set is keyed by the BLAKE3 LeafHash — the content hash over
	// the marshaled leaf, which is exactly these bytes. This is deliberately NOT
	// the RFC6962 tree leaf hash used for inclusion proofs (spec §8.3).
	leafHash := [32]byte(blake3.Sum256(rawLeaf))

	verdict, entry, err := status.Resolve(
		&bundleStatusFetcher{ctx: ctx, f: f, size: cp.Size}, leafHash, cp.Size, roots,
	)
	if err != nil {
		return StatusResult{}, err
	}
	res := StatusResult{Verdict: string(verdict), TreeSize: cp.Size}
	if entry != nil {
		res.Withdrawn = &WithdrawnInfo{At: entry.WithdrawnAt, Reason: entry.Reason}
	}
	return res, nil
}

// bundleStatusFetcher adapts the Tessera read paths to status.Fetcher.
type bundleStatusFetcher struct {
	ctx  context.Context
	f    Fetcher
	size uint64
}

func (b *bundleStatusFetcher) FetchHint() (*status.Hint, error) {
	if b.f.Blob == nil {
		return nil, fmt.Errorf("cocverify: no blob fetcher configured")
	}
	raw, err := b.f.Blob(b.ctx, "status/latest.json")
	if err != nil {
		return nil, err
	}
	var h status.Hint
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, err
	}
	return &h, nil
}

func (b *bundleStatusFetcher) FetchBundle(index uint64) ([][]byte, error) {
	bundle, err := client.GetEntryBundle(b.ctx, b.f.Entries, index, b.size)
	if err != nil {
		return nil, err
	}
	return bundle.Entries, nil
}

func (b *bundleStatusFetcher) FetchArtifact(version uint64) ([]byte, error) {
	if b.f.Blob == nil {
		return nil, fmt.Errorf("cocverify: no blob fetcher configured")
	}
	// Version-addressed and immutable, so it is safe to cache indefinitely.
	return b.f.Blob(b.ctx, fmt.Sprintf("status/v%d.json", version))
}
