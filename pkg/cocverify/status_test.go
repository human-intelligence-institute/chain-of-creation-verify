package cocverify_test

// Revocation-status resolution against the frozen fixtures in testdata/.
//
// These tests cover the ADAPTER — bundleStatusFetcher, and the leaf-hash scheme
// ResolveStatus picks — not pkg/status's resolution logic, which has its own
// unit tests over an in-memory fetcher.
//
// ⚠️ The hazard this file is written around: status.Resolve fails CLOSED, so a
// fetcher that errors on everything yields INDETERMINATE, which is
// indistinguishable at a glance from a correct fail-closed result. A suite that
// only ever asserts INDETERMINATE proves nothing at all.
//
// Two structural rules keep that from happening here:
//
//  1. Every INDETERMINATE test first runs the POSITIVE control through the same
//     log, the same checkpoint and the same fetcher construction, asserts
//     WITHDRAWN, and only then changes ONE thing — the blob directory, or the
//     pinned root. A verdict that flips can only have flipped because of the
//     single input that changed.
//  2. The positive assertions are exact: WITHDRAWN must carry the reason string
//     and timestamp from the published artifact. Those bytes are only reachable
//     if the anchor's BLAKE3 commitment matched AND the leaf was found under the
//     BLAKE3 content hash — so a wrong leaf-hash scheme (RFC6962 tree hashing,
//     say) cannot pass, it collapses to INDETERMINATE or VERIFIED.

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/human-intelligence-institute/chain-of-creation-verify/pkg/cocverify"
	"github.com/human-intelligence-institute/chain-of-creation-verify/pkg/status"
	"github.com/zeebo/blake3"
)

// statusArtifact parses the published artifact out of the named blob directory.
func statusArtifact(t *testing.T, dir string, version uint64) (*status.Artifact, [32]byte) {
	t.Helper()
	name := filepath.Base(status.ArtifactPath(version))
	raw, err := os.ReadFile(filepath.Join(fixtureDir, dir, name))
	if err != nil {
		t.Fatalf("read %s/%s: %v", dir, name, err)
	}
	art, h, err := status.ParseArtifact(raw)
	if err != nil {
		t.Fatalf("parse %s/%s: %v", dir, name, err)
	}
	return art, h
}

func leafHash(t *testing.T, raw []byte) [32]byte {
	t.Helper()
	return [32]byte(blake3.Sum256(raw))
}

// TestStatusFixturesAreWellFormed guards the status fixtures the way
// TestFixtureTreeIsWellFormed guards the tree. Without it, a fixture tree
// missing its artifact would make every INDETERMINATE case below "pass".
func TestStatusFixturesAreWellFormed(t *testing.T) {
	m := loadManifest(t)
	st := m.status(t)

	if st.AnchorIndex >= m.TreeSize {
		t.Fatalf("anchor index %d is outside the frozen tree (size %d)", st.AnchorIndex, m.TreeSize)
	}
	if st.NoAnchorTreeSize == 0 || st.NoAnchorLog == "" {
		t.Fatalf("no-anchor log fixture is missing: %+v", st)
	}

	// The manifest's leaf hashes must be the BLAKE3 content hash over the raw
	// leaf bytes — the same scheme ResolveStatus uses, and deliberately NOT the
	// RFC6962 tree leaf hash (spec §8.3).
	wh := leafHash(t, m.raw(t, st.WithdrawnLeaf))
	lh := leafHash(t, m.raw(t, st.LiveLeaf))
	if got := hex.EncodeToString(wh[:]); got != st.WithdrawnLeafHash {
		t.Fatalf("withdrawn leaf hash %s, manifest says %s", got, st.WithdrawnLeafHash)
	}
	if got := hex.EncodeToString(lh[:]); got != st.LiveLeafHash {
		t.Fatalf("live leaf hash %s, manifest says %s", got, st.LiveLeafHash)
	}
	if wh == lh {
		t.Fatal("the withdrawn and live fixture leaves hash identically")
	}

	// The published artifact must actually distinguish the two leaves,
	// otherwise WITHDRAWN and VERIFIED could not differ.
	good, goodHash := statusArtifact(t, st.GoodDir, st.ArtifactVersion)
	if _, ok := good.Find(wh); !ok {
		t.Fatal("the published artifact does not list the withdrawn fixture leaf")
	}
	if _, ok := good.Find(lh); ok {
		t.Fatal("the published artifact lists the leaf that is supposed to be live")
	}

	// The corrupted variant must parse (so the INDETERMINATE it causes comes
	// from the hash comparison, not from a JSON error) and must hash
	// differently (so it causes one at all).
	bad, badHash := statusArtifact(t, st.BadDir, st.ArtifactVersion)
	if bad.Version != good.Version {
		t.Fatalf("corrupted artifact is version %d, want %d", bad.Version, good.Version)
	}
	if badHash == goodHash {
		t.Fatal("the corrupted artifact hashes identically to the published one")
	}

	// The missing-artifact variant must serve the hint but not the artifact.
	if _, err := os.ReadFile(filepath.Join(fixtureDir, st.GoneDir, "latest.json")); err != nil {
		t.Fatalf("%s must serve the hint: %v", st.GoneDir, err)
	}
	gone := filepath.Join(fixtureDir, st.GoneDir, filepath.Base(status.ArtifactPath(st.ArtifactVersion)))
	if _, err := os.Stat(gone); !os.IsNotExist(err) {
		t.Fatalf("%s must NOT contain the artifact (stat err = %v)", st.GoneDir, err)
	}
}

// resolve is the one call every scenario makes; only logDir, blobDir and roots
// differ between them. logDir picks not just the tree but the (origin, vkey)
// it was signed under: the main log and the no-anchor log are two distinct
// logs, each under its own identity (see fixtureManifest.NoAnchorOrigin).
func resolve(t *testing.T, logDir, blobDir string, roots [][32]byte, rawLeaf []byte) cocverify.StatusResult {
	t.Helper()
	m := loadManifest(t)
	st := m.status(t)
	origin, vkey := m.Origin, m.VKey
	if logDir == st.NoAnchorLog {
		origin, vkey = m.NoAnchorOrigin, m.NoAnchorVKey
	}
	res, err := cocverify.ResolveStatus(
		context.Background(), fixtureFetcherFrom(t, logDir, blobDir), rawLeaf, origin, vkey, roots,
	)
	if err != nil {
		t.Fatalf("ResolveStatus: %v", err)
	}
	return res
}

// --- scenario 1: no trusted anchor anywhere → VERIFIED ---

func TestResolveStatus_NoAnchorInLog_Verified(t *testing.T) {
	m := loadManifest(t)
	st := m.status(t)
	root := m.root(t, m.IDRoot)

	// testdata/log-noanchor holds the same leaves at the same indices but no
	// status anchor. The artifact and hint ARE served — resolution simply never
	// has a reason to consult them.
	for _, name := range []string{st.LiveLeaf, st.WithdrawnLeaf} {
		res := resolve(t, st.NoAnchorLog, st.GoodDir, [][32]byte{root}, m.raw(t, name))
		if res.Verdict != "VERIFIED" {
			t.Fatalf("%s: verdict = %s, want VERIFIED when no anchor has ever been published", name, res.Verdict)
		}
		if res.Withdrawn != nil {
			t.Fatalf("%s: withdrawal reported with no anchor: %+v", name, res.Withdrawn)
		}
		if res.TreeSize != st.NoAnchorTreeSize {
			t.Fatalf("%s: tree size %d, want %d — the verdict did not come from the no-anchor checkpoint",
				name, res.TreeSize, st.NoAnchorTreeSize)
		}
	}
}

// --- scenario 2: anchor + valid artifact, leaf not listed → VERIFIED ---

func TestResolveStatus_AnchoredAndNotListed_Verified(t *testing.T) {
	m := loadManifest(t)
	st := m.status(t)
	root := m.root(t, m.IDRoot)

	res := resolve(t, "log", st.GoodDir, [][32]byte{root}, m.raw(t, st.LiveLeaf))
	if res.Verdict != "VERIFIED" {
		t.Fatalf("verdict = %s, want VERIFIED", res.Verdict)
	}
	if res.Withdrawn != nil {
		t.Fatalf("a leaf absent from the artifact was reported withdrawn: %+v", res.Withdrawn)
	}
	// This verdict must have come from the anchored artifact, not from an
	// unreachable one: the withdrawn sibling resolves to WITHDRAWN through the
	// very same inputs.
	if sib := resolve(t, "log", st.GoodDir, [][32]byte{root}, m.raw(t, st.WithdrawnLeaf)); sib.Verdict != "WITHDRAWN" {
		t.Fatalf("control: the withdrawn sibling resolved %s, so this VERIFIED proves nothing", sib.Verdict)
	}
	if res.TreeSize != m.TreeSize {
		t.Fatalf("tree size %d, want %d", res.TreeSize, m.TreeSize)
	}
}

// --- scenario 3: anchor + valid artifact, leaf listed → WITHDRAWN ---

func TestResolveStatus_AnchoredAndListed_Withdrawn(t *testing.T) {
	m := loadManifest(t)
	st := m.status(t)
	root := m.root(t, m.IDRoot)

	res := resolve(t, "log", st.GoodDir, [][32]byte{root}, m.raw(t, st.WithdrawnLeaf))
	if res.Verdict != "WITHDRAWN" {
		t.Fatalf("verdict = %s, want WITHDRAWN", res.Verdict)
	}
	if res.Withdrawn == nil {
		t.Fatal("WITHDRAWN with no withdrawal detail")
	}

	// Exact-match the detail against the published artifact. Reaching these
	// bytes requires the anchor's BLAKE3 commitment to have matched the served
	// artifact AND the leaf to have been found under the BLAKE3 content hash of
	// its raw bytes. A wrong leaf-hash scheme cannot satisfy both.
	art, _ := statusArtifact(t, st.GoodDir, st.ArtifactVersion)
	want, ok := art.Find(leafHash(t, m.raw(t, st.WithdrawnLeaf)))
	if !ok {
		t.Fatal("fixture artifact does not list the withdrawn leaf")
	}
	if res.Withdrawn.Reason != want.Reason {
		t.Fatalf("reason = %q, want %q", res.Withdrawn.Reason, want.Reason)
	}
	if res.Withdrawn.At != want.WithdrawnAt {
		t.Fatalf("withdrawn_at = %d, want %d", res.Withdrawn.At, want.WithdrawnAt)
	}
	if res.TreeSize != m.TreeSize {
		t.Fatalf("tree size %d, want %d", res.TreeSize, m.TreeSize)
	}
}

// --- scenario 4: anchor present, artifact missing → INDETERMINATE ---

func TestResolveStatus_ArtifactMissing_Indeterminate(t *testing.T) {
	m := loadManifest(t)
	st := m.status(t)
	root := m.root(t, m.IDRoot)
	raw := m.raw(t, st.WithdrawnLeaf)

	// Control first: with the artifact present, these exact inputs resolve.
	if ctl := resolve(t, "log", st.GoodDir, [][32]byte{root}, raw); ctl.Verdict != "WITHDRAWN" {
		t.Fatalf("control resolved %s, not WITHDRAWN — the INDETERMINATE below would prove nothing", ctl.Verdict)
	}

	// Change exactly one thing: the blob directory, which serves the hint but
	// not status/vN.json.
	res := resolve(t, "log", st.GoneDir, [][32]byte{root}, raw)
	if res.Verdict != "INDETERMINATE" {
		t.Fatalf("verdict = %s, want INDETERMINATE when the anchored artifact cannot be fetched", res.Verdict)
	}
	if res.Withdrawn != nil {
		t.Fatalf("withdrawal detail from an unfetchable artifact: %+v", res.Withdrawn)
	}
	// The log itself was still read: the checkpoint is present and verified.
	if res.TreeSize != m.TreeSize {
		t.Fatalf("tree size %d, want %d — INDETERMINATE must come from the artifact, not a dead log fetcher",
			res.TreeSize, m.TreeSize)
	}
}

// --- scenario 5: anchor present, artifact hash mismatch → INDETERMINATE ---

func TestResolveStatus_ArtifactHashMismatch_Indeterminate(t *testing.T) {
	m := loadManifest(t)
	st := m.status(t)
	root := m.root(t, m.IDRoot)

	for name, want := range map[string]string{st.WithdrawnLeaf: "WITHDRAWN", st.LiveLeaf: "VERIFIED"} {
		raw := m.raw(t, name)
		// Control: the same leaf through the same log with the artifact the
		// anchor actually commits to. Demanding the EXACT verdict, not merely
		// "not INDETERMINATE", is what keeps this case sensitive to the
		// leaf-hash scheme as well as to the artifact bytes.
		ctl := resolve(t, "log", st.GoodDir, [][32]byte{root}, raw)
		if ctl.Verdict != want {
			t.Fatalf("%s: control resolved %s, want %s; the mismatch case below would prove nothing", name, ctl.Verdict, want)
		}

		res := resolve(t, "log", st.BadDir, [][32]byte{root}, raw)
		if res.Verdict != "INDETERMINATE" {
			t.Fatalf("%s: verdict = %s, want INDETERMINATE — a served artifact the anchor does not commit to must not be trusted",
				name, res.Verdict)
		}
		if res.Withdrawn != nil {
			t.Fatalf("%s: withdrawal detail from a hash-mismatched artifact: %+v", name, res.Withdrawn)
		}
		if res.TreeSize != m.TreeSize {
			t.Fatalf("%s: tree size %d, want %d", name, res.TreeSize, m.TreeSize)
		}
	}
}

// --- scenario 6: anchor signed by a non-pinned root ---
//
// The brief expected VERIFIED here, by analogy with "no trusted anchor". The
// implementation is stricter, and deliberately so: scanForNewestAnchor reports
// that it SAW a status anchor it could not trust, and Resolve turns that into
// INDETERMINATE — "cannot check" is not "nothing to check" (see its comment on
// the sawUntrusted branch, and pkg/status's own
// TestAnchorWithUnpinnedIssuerIsIgnored, which asserts only "not WITHDRAWN").
//
// Asserting the implemented behaviour rather than the brief's is the safe
// direction: INDETERMINATE fails closed, VERIFIED would fail open.
func TestResolveStatus_UnpinnedIssuer_Indeterminate(t *testing.T) {
	m := loadManifest(t)
	st := m.status(t)
	other := m.root(t, m.OtherRoot) // a real root that signed nothing here
	raw := m.raw(t, st.WithdrawnLeaf)

	// Control: with the correct root pinned, these inputs resolve to WITHDRAWN.
	if ctl := resolve(t, "log", st.GoodDir, [][32]byte{m.root(t, m.IDRoot)}, raw); ctl.Verdict != "WITHDRAWN" {
		t.Fatalf("control resolved %s, not WITHDRAWN", ctl.Verdict)
	}

	// Change exactly one thing: the pinned root.
	res := resolve(t, "log", st.GoodDir, [][32]byte{other}, raw)
	if res.Verdict == "WITHDRAWN" {
		t.Fatal("an anchor signed by a non-pinned root was trusted")
	}
	if res.Verdict != "INDETERMINATE" {
		t.Fatalf("verdict = %s, want INDETERMINATE: an unverifiable published status must not read as clean", res.Verdict)
	}
}

// --- the adapter's own nil-Blob guard ---
//
// A caller that wires Checkpoint/Tile/Entries but forgets Blob must not get a
// clean verdict. This is the adapter's failure mode specifically, not
// pkg/status's.
func TestResolveStatus_NoBlobFetcher_Indeterminate(t *testing.T) {
	m := loadManifest(t)
	st := m.status(t)
	root := m.root(t, m.IDRoot)
	raw := m.raw(t, st.WithdrawnLeaf)

	if ctl := resolve(t, "log", st.GoodDir, [][32]byte{root}, raw); ctl.Verdict != "WITHDRAWN" {
		t.Fatalf("control resolved %s, not WITHDRAWN", ctl.Verdict)
	}

	res := resolve(t, "log", "", [][32]byte{root}, raw) // blobDir "" → Blob is nil
	if res.Verdict != "INDETERMINATE" {
		t.Fatalf("verdict = %s, want INDETERMINATE with no blob fetcher configured", res.Verdict)
	}
}
