package cocverify

// Identity resolution maps an attestation's signing key to a creator. It does
// not search the log: the verification receipt carries the binding's index
// (`binding_index`), so the verifier reads exactly that one leaf, proves it is
// committed, and checks it authorizes the signing key. This is O(log N) per
// verification regardless of log size — no key index to build or trust.
//
// Two trust anchors are pinned by the caller: the checkpoint key (as in
// inclusion) and the HII identity-root key(s) that sign bindings. A binding is
// honored only if it is both (a) proven included in the log and (b) signed by a
// pinned identity root and authorizes the signer at the attestation's time.
//
// Semantics are effective-at-submission: provenance verifies a historical event,
// so the binding in force at the attestation's SubmittedAt is the right one.
// "Is the key valid now / has it been revoked" is a different question, out of
// scope here.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/human-intelligence-institute/chain-of-creation-verify/pkg/identity"
	"github.com/human-intelligence-institute/chain-of-creation-verify/pkg/leaf"
	"github.com/human-intelligence-institute/chain-of-creation-verify/internal/verify"
	"github.com/transparency-dev/tessera/api/layout"
	"github.com/transparency-dev/tessera/client"
	"golang.org/x/mod/sumdb/note"
)

// IdentityResult reports the creator an attestation's signing key resolves to.
type IdentityResult struct {
	Resolved        bool   `json:"resolved"`
	CreatorID       string `json:"creator_id,omitempty"`
	Custodial       bool   `json:"custodial"`          // true when HII holds the signing key
	KeyType         uint8  `json:"key_type,omitempty"` // 1=HII-custodial, 2=self-managed
	BindingIndex    uint64 `json:"binding_index"`
	BindingIncluded bool   `json:"binding_included"` // the binding leaf is committed in the log
}

// VerifyIdentity resolves the signer of rawAttLeaf to a creator using the binding
// at bindingIndex (from the record's receipt). It verifies the checkpoint against
// the pinned (origin, vkey), proves the binding leaf is included, and resolves it
// against the pinned identity roots. A checkpoint that does not verify is a hard
// error; every other negative (binding not included, wrong key, untrusted issuer)
// returns Resolved=false rather than an error.
func VerifyIdentity(ctx context.Context, f Fetcher, rawAttLeaf []byte, bindingIndex uint64, origin, vkey string, roots [][32]byte) (IdentityResult, error) {
	att, err := leaf.UnmarshalAttestation(rawAttLeaf)
	if err != nil {
		return IdentityResult{}, fmt.Errorf("attestation: %w", err)
	}
	if len(roots) == 0 {
		return IdentityResult{}, errors.New("no pinned identity root configured")
	}
	v, err := note.NewVerifier(vkey)
	if err != nil {
		return IdentityResult{}, fmt.Errorf("pinned checkpoint key: %w", err)
	}
	cp, _, _, err := client.FetchCheckpoint(ctx, f.Checkpoint, v, origin)
	if err != nil {
		return IdentityResult{}, fmt.Errorf("checkpoint: %w", err)
	}

	res := IdentityResult{BindingIndex: bindingIndex}
	if bindingIndex >= cp.Size {
		return res, nil // binding index beyond the tree → not committed
	}

	// Read the binding leaf at its index from the entry bundle that holds it.
	bundle, err := client.GetEntryBundle(ctx, f.Entries, bindingIndex/layout.EntryBundleWidth, cp.Size)
	if err != nil {
		return res, fmt.Errorf("entry bundle: %w", err)
	}
	offset := int(bindingIndex % layout.EntryBundleWidth)
	if offset >= len(bundle.Entries) {
		return res, nil
	}
	bindingBytes := bundle.Entries[offset]

	// Prove the binding leaf is committed in the log (else it could be fabricated).
	pb, err := client.NewProofBuilder(ctx, cp.Size, f.Tile)
	if err != nil {
		return res, fmt.Errorf("proof builder: %w", err)
	}
	pf, err := pb.InclusionProof(ctx, bindingIndex)
	if err != nil {
		return res, fmt.Errorf("inclusion proof: %w", err)
	}
	if err := verify.VerifyInclusion(bindingBytes, bindingIndex, cp.Size, pf, cp.Hash); err != nil {
		return res, nil // the bytes at that index are not committed → do not trust
	}
	res.BindingIncluded = true

	b, err := leaf.UnmarshalIdentityBinding(bindingBytes)
	if err != nil {
		return res, nil // the committed leaf at that index is not a binding
	}

	// Resolve against the pinned roots. Resolver.Add verifies the issuer
	// signature; Resolve only matches when the binding authorizes this exact
	// signer key with ValidFrom <= the attestation's time.
	resolver := identity.NewResolver(roots[0])
	for _, rt := range roots[1:] {
		resolver.TrustRoot(rt, time.Time{})
	}
	if err := resolver.Add(b); err != nil {
		return res, nil // untrusted issuer or bad signature
	}
	r, ok := resolver.Resolve(att.SignerPubKey, time.UnixMilli(int64(att.SubmittedAt)))
	if !ok {
		return res, nil // binding does not authorize this signer at this time
	}
	res.Resolved = true
	res.CreatorID = r.CreatorID
	res.Custodial = r.Custodial()
	res.KeyType = uint8(r.KeyType)
	return res, nil
}
