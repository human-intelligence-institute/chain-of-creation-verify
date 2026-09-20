package cocverify_test

// The log-dependent verifier tests run against a frozen transparency log
// committed under testdata/. This is deliberately closer to reality than the
// live node the tests originally spun up: a third-party verifier only ever has
// static, already-published log artifacts, which is exactly what these are.
//
// The tree was produced by chain-of-creation's cmd/genverifierfixtures using
// throwaway keys; testdata/manifest.json records the pinned origin and
// checkpoint vkey, the identity roots, and each fixture leaf's index and raw
// bytes.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/human-intelligence-institute/chain-of-creation-verify/pkg/cocverify"
	"github.com/transparency-dev/tessera/api/layout"
)

const fixtureDir = "testdata"

// fixtureLeaf is one frozen leaf from the manifest.
type fixtureLeaf struct {
	Name  string `json:"name"`
	Index uint64 `json:"index"`
	Bytes string `json:"bytes"`
}

// fixtureStatus describes the revocation-status fixtures: the anchor committed
// to the main log, the artifact version it names, the two leaves the status
// tests resolve, and the blob roots the broken scenarios select.
type fixtureStatus struct {
	AnchorLeaf        string `json:"anchor_leaf"`
	AnchorIndex       uint64 `json:"anchor_index"`
	ArtifactVersion   uint64 `json:"artifact_version"`
	WithdrawnLeaf     string `json:"withdrawn_leaf"`
	WithdrawnLeafHash string `json:"withdrawn_leaf_hash"`
	LiveLeaf          string `json:"live_leaf"`
	LiveLeafHash      string `json:"live_leaf_hash"`
	GoodDir           string `json:"good_dir"`
	BadDir            string `json:"bad_dir"`
	GoneDir           string `json:"gone_dir"`
	NoAnchorLog       string `json:"no_anchor_log"`
	NoAnchorTreeSize  uint64 `json:"no_anchor_tree_size"`
}

type fixtureManifest struct {
	GeneratedAt string        `json:"generated_at"`
	Origin      string        `json:"origin"`
	VKey        string        `json:"vkey"`
	IDRoot      string        `json:"id_root"`
	OtherRoot   string        `json:"other_root"`
	TreeSize    uint64        `json:"tree_size"`
	// NoAnchorOrigin and NoAnchorVKey pin the SEPARATE (origin, key) the
	// no-anchor log in testdata/log-noanchor is signed under. It is a
	// distinct log from the main one, not another checkpoint for it, so it
	// carries its own identity rather than reusing Origin/VKey.
	NoAnchorOrigin string         `json:"no_anchor_origin"`
	NoAnchorVKey   string         `json:"no_anchor_vkey"`
	Leaves         []fixtureLeaf  `json:"leaves"`
	Status         *fixtureStatus `json:"status"`
}

// status returns the status fixture block, failing the test if the manifest
// predates it. An absent block must never read as a passing scenario.
func (m *fixtureManifest) status(t *testing.T) *fixtureStatus {
	t.Helper()
	if m.Status == nil {
		t.Fatal("manifest has no status block; regenerate the fixtures")
	}
	return m.Status
}

// raw returns the raw bytes of the named leaf, failing the test if it is absent
// — a missing fixture is a broken test, never a silent negative result.
func (m *fixtureManifest) raw(t *testing.T, name string) []byte {
	t.Helper()
	b, err := hex.DecodeString(m.leaf(t, name).Bytes)
	if err != nil {
		t.Fatalf("fixture %q: decode bytes: %v", name, err)
	}
	return b
}

func (m *fixtureManifest) index(t *testing.T, name string) uint64 {
	t.Helper()
	return m.leaf(t, name).Index
}

func (m *fixtureManifest) leaf(t *testing.T, name string) fixtureLeaf {
	t.Helper()
	for _, l := range m.Leaves {
		if l.Name == name {
			return l
		}
	}
	t.Fatalf("fixture leaf %q not in manifest", name)
	return fixtureLeaf{}
}

// root decodes one of the manifest's 32-byte identity root keys.
func (m *fixtureManifest) root(t *testing.T, hexKey string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(hexKey)
	if err != nil {
		t.Fatalf("decode root: %v", err)
	}
	if len(b) != 32 {
		t.Fatalf("root key is %d bytes, want 32", len(b))
	}
	var k [32]byte
	copy(k[:], b)
	return k
}

// loadManifest reads testdata/manifest.json.
func loadManifest(t *testing.T) *fixtureManifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixtureDir, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var m fixtureManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	if len(m.Leaves) == 0 || m.VKey == "" || m.Origin == "" || m.NoAnchorOrigin == "" || m.NoAnchorVKey == "" {
		t.Fatalf("manifest is incomplete: %+v", m)
	}
	if m.NoAnchorOrigin == m.Origin || m.NoAnchorVKey == m.VKey {
		t.Fatalf("the no-anchor log must be signed under its own origin/key, not the main log's: %+v", m)
	}
	return &m
}

// fixtureFetcher serves the frozen log out of testdata/log. The tlog-tiles path
// layout the POSIX log wrote is the same layout the Tessera client asks for, so
// the whole fetcher is layout.*Path + os.ReadFile. os.ReadFile already returns
// os.ErrNotExist, which is the client's documented not-found contract.
func fixtureFetcher(t *testing.T) cocverify.Fetcher {
	t.Helper()
	return fixtureFetcherFrom(t, "log", "")
}

// fixtureFetcherFrom is fixtureFetcher over a chosen log tree, optionally with a
// Blob function serving the "status/..." objects out of blobDir.
//
// Only the directories change between scenarios: the reading code is the same
// in every case, so a scenario's verdict can only come from the fixture bytes it
// selected, never from a fetcher wired differently.
//
// blobDir == "" leaves Blob nil, which is what the non-status tests want.
func fixtureFetcherFrom(t *testing.T, logDir, blobDir string) cocverify.Fetcher {
	t.Helper()
	root := filepath.Join(fixtureDir, logDir)
	read := func(rel string) ([]byte, error) {
		return os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	}
	f := cocverify.Fetcher{
		Checkpoint: func(context.Context) ([]byte, error) {
			return read(layout.CheckpointPath)
		},
		Tile: func(_ context.Context, level, index uint64, p uint8) ([]byte, error) {
			return read(layout.TilePath(level, index, p))
		},
		Entries: func(_ context.Context, bundleIndex uint64, p uint8) ([]byte, error) {
			return read(layout.EntriesPath(bundleIndex, p))
		},
	}
	if blobDir != "" {
		f.Blob = func(_ context.Context, path string) ([]byte, error) {
			// The adapter only ever asks for "status/<object>"; the scenario
			// picks which directory that prefix resolves to.
			return os.ReadFile(filepath.Join(fixtureDir, blobDir, filepath.Base(path)))
		}
	}
	return f
}

// TestFixtureTreeIsWellFormed guards the fixture itself. If the frozen tree were
// truncated or the manifest drifted from it, every negative test below would
// still "pass" — for entirely the wrong reason. This asserts the positive
// preconditions they all rely on before any of them run.
func TestFixtureTreeIsWellFormed(t *testing.T) {
	m := loadManifest(t)
	if m.TreeSize < uint64(len(m.Leaves)) {
		t.Fatalf("frozen checkpoint covers %d entries, manifest names %d leaves", m.TreeSize, len(m.Leaves))
	}
	for _, name := range []string{
		"inclusion-attestation", "identity-binding",
		"identity-attestation", "identity-binding-other-key",
		"status-live-attestation", "status-withdrawn-attestation", "status-anchor",
	} {
		l := m.leaf(t, name)
		if l.Index >= m.TreeSize {
			t.Fatalf("fixture %q index %d is outside the frozen tree (size %d)", name, l.Index, m.TreeSize)
		}
	}
	// The fetcher must actually serve the checkpoint; a fetcher that errors on
	// everything is the failure mode these tests exist to rule out.
	f := fixtureFetcher(t)
	if _, err := f.Checkpoint(context.Background()); err != nil {
		t.Fatalf("fixture fetcher cannot read the checkpoint: %v", err)
	}
}
