package status

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/human-intelligence-institute/chain-of-creation-verify/pkg/leaf"
	"github.com/zeebo/blake3"
)

// The published §7 revocation vector. These exact strings appear in
// docs/verification-spec.md; changing either side without the other is a spec
// break. An implementation that skipped status resolution fails this outright,
// which is the point — conformance cannot be asserted, only demonstrated.
const (
	vecSeedHex      = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	vecIdentityRoot = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"
	vecWithdrawnB64 = "oKGio6SlpqeoqaqrrK2ur6ChoqOkpaanqKmqq6ytrq8="
	vecArtifact     = `{"issued_at":1786000000000,"log_size_at_issue":9,"schema":1,"version":1,` +
		`"withdrawn":[{"leaf_hash":"oKGio6SlpqeoqaqrrK2ur6ChoqOkpaanqKmqq6ytrq8=",` +
		`"reason":"certification_rejected","withdrawn_at":1786000000001}]}`
	vecArtifactHashHex = "b6cd453b16d99761862fa3f1ed7c8d50f121135596fef2595ff7015fb4a30f36"
	vecAnchorLeafB64   = "AwAAAAEAAAAAAAAAAbbNRTsW2Zdhhi+j8e18jVDxIRNVlv7yWV/3AV+0ow82AAABn9XlRAB5" +
		"tVYuj+ZU+UB4sRLoqYunkB+FOuaVvtfg45ELrQSWZMmdoBLEMzgo8+2iCMuu8X34SCrHV9RC" +
		"4Fpwa9zYefMovoYx07ehBgTi+wScWOcqi2LBtQtzTEDo7uvssGxaPQ4="
)

func TestGoldenRevocationVectorIsStable(t *testing.T) {
	seed, err := hex.DecodeString(vecSeedHex)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)

	if got := hex.EncodeToString(priv.Public().(ed25519.PublicKey)); got != vecIdentityRoot {
		t.Fatalf("identity root = %s, spec says %s", got, vecIdentityRoot)
	}

	ah := blake3.Sum256([]byte(vecArtifact))
	if got := hex.EncodeToString(ah[:]); got != vecArtifactHashHex {
		t.Fatalf("artifact hash = %s, spec says %s", got, vecArtifactHashHex)
	}

	a := &leaf.StatusAnchor{
		SchemaVersion:   1,
		ArtifactVersion: 1,
		ArtifactHash:    leaf.Hash(ah),
		IssuedAt:        1786000000000,
	}
	a.Sign(priv)
	if got := base64.StdEncoding.EncodeToString(a.Marshal()); got != vecAnchorLeafB64 {
		t.Fatalf("anchor leaf = %s\nspec says   = %s", got, vecAnchorLeafB64)
	}
}

// TestGoldenRevocationVectorResolvesWithdrawn is the conformance case: fed the
// published anchor and artifact, a verifier MUST return WITHDRAWN.
func TestGoldenRevocationVectorResolvesWithdrawn(t *testing.T) {
	root, err := hex.DecodeString(vecIdentityRoot)
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	anchor, err := base64.StdEncoding.DecodeString(vecAnchorLeafB64)
	if err != nil {
		t.Fatalf("anchor: %v", err)
	}
	lh, err := base64.StdEncoding.DecodeString(vecWithdrawnB64)
	if err != nil {
		t.Fatalf("leaf hash: %v", err)
	}

	f := &fakeFetcher{
		hint:      &Hint{Version: 1, AnchorIndex: 0},
		bundles:   map[uint64][][]byte{0: {anchor}},
		artifacts: map[uint64][]byte{1: []byte(vecArtifact)},
	}
	v, e, reason, cause := Resolve(f, [32]byte(lh), 1, [][32]byte{[32]byte(root)})
	if cause != nil {
		t.Fatalf("Resolve cause: %v", cause)
	}
	if reason != ReasonNone {
		t.Fatalf("reason = %q, want empty on a definite verdict", reason)
	}
	if v != VerdictWithdrawn {
		t.Fatalf("verdict = %v, want WITHDRAWN for the published vector", v)
	}
	if e == nil || e.Reason != "certification_rejected" {
		t.Fatalf("entry = %+v", e)
	}
}
