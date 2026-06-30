package cocverify

// Inclusion verification proves that a leaf is committed in the published log,
// not merely well-formed and signed. Given a record's {leaf, index}, it fetches
// the current signed checkpoint and the tiles on that index's proof path,
// reconstructs the RFC6962 inclusion proof, and checks the leaf against the
// checkpoint root.
//
// Trust model: the checkpoint is verified against a PINNED (origin, vkey) — the
// key the server presents is never trusted. The heavy lifting (proof
// reconstruction from tiles, checkpoint parse+verify) is the Tessera client
// library; this is the glue that ties it to our leaf + verify.VerifyInclusion.

import (
	"context"
	"fmt"

	"github.com/human-intelligence-institute/chain-of-creation/internal/verify"
	"github.com/transparency-dev/tessera/client"
	"golang.org/x/mod/sumdb/note"
)

// Fetcher supplies the log artifacts an inclusion check needs. It mirrors the
// Tessera client fetch funcs so a caller can back it with net/http (native) or
// the browser fetch() (WASM) without the core knowing which.
type Fetcher struct {
	Checkpoint client.CheckpointFetcherFunc
	Tile       client.TileFetcherFunc
}

// InclusionResult reports whether a leaf is committed in the log and the
// checkpoint it was proven against. It is JSON-serializable for the WASM bridge.
type InclusionResult struct {
	Included bool   `json:"included"`
	Index    uint64 `json:"index"`
	TreeSize uint64 `json:"tree_size"`
	Origin   string `json:"origin"`
	// CheckpointSigValid is true once the checkpoint's note signature verifies
	// against the pinned log key. (If it does not, VerifyInclusion returns an
	// error rather than a result — a record can never be "verified" against an
	// unverifiable checkpoint.)
	CheckpointSigValid bool `json:"checkpoint_sig_valid"`
	// Cosignatures counts note signatures beyond the log's own that this build
	// did NOT verify (witness verification is not wired yet). 0 today, because
	// witnessing is inactive. Surfaced so the UI can say "not yet witnessed"
	// honestly rather than implying split-view protection that isn't there.
	Cosignatures int `json:"cosignatures"`
}

// VerifyInclusion fetches the current signed checkpoint and proves rawLeaf is
// committed at index. The checkpoint is parsed and signature-verified against the
// pinned (origin, vkey); on signature failure it returns an error. A
// well-formed-but-not-included leaf is not an error — it returns Included=false.
func VerifyInclusion(ctx context.Context, f Fetcher, rawLeaf []byte, index uint64, origin, vkey string) (InclusionResult, error) {
	v, err := note.NewVerifier(vkey)
	if err != nil {
		return InclusionResult{}, fmt.Errorf("pinned checkpoint key: %w", err)
	}
	cp, _, n, err := client.FetchCheckpoint(ctx, f.Checkpoint, v, origin)
	if err != nil {
		return InclusionResult{}, fmt.Errorf("checkpoint: %w", err)
	}
	res := InclusionResult{
		Index:              index,
		TreeSize:           cp.Size,
		Origin:             cp.Origin,
		CheckpointSigValid: true,
		Cosignatures:       len(n.UnverifiedSigs),
	}
	// An index at or beyond the tree size cannot be included in this checkpoint.
	if index >= cp.Size {
		return res, nil
	}
	pb, err := client.NewProofBuilder(ctx, cp.Size, f.Tile)
	if err != nil {
		return res, fmt.Errorf("proof builder: %w", err)
	}
	pf, err := pb.InclusionProof(ctx, index)
	if err != nil {
		return res, fmt.Errorf("inclusion proof: %w", err)
	}
	// A failed proof means "not included under this checkpoint" — a legitimate
	// negative verdict, not an operational error.
	if err := verify.VerifyInclusion(rawLeaf, index, cp.Size, pf, cp.Hash); err == nil {
		res.Included = true
	}
	return res, nil
}
