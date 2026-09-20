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

type fixtureManifest struct {
	GeneratedAt string        `json:"generated_at"`
	Origin      string        `json:"origin"`
	VKey        string        `json:"vkey"`
	IDRoot      string        `json:"id_root"`
	OtherRoot   string        `json:"other_root"`
	TreeSize    uint64        `json:"tree_size"`
	Leaves      []fixtureLeaf `json:"leaves"`
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
	if len(m.Leaves) == 0 || m.VKey == "" || m.Origin == "" {
		t.Fatalf("manifest is incomplete: %+v", m)
	}
	return &m
}

// fixtureFetcher serves the frozen log out of testdata/log. The tlog-tiles path
// layout the POSIX log wrote is the same layout the Tessera client asks for, so
// the whole fetcher is layout.*Path + os.ReadFile. os.ReadFile already returns
// os.ErrNotExist, which is the client's documented not-found contract.
func fixtureFetcher(t *testing.T) cocverify.Fetcher {
	t.Helper()
	root := filepath.Join(fixtureDir, "log")
	read := func(rel string) ([]byte, error) {
		return os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	}
	return cocverify.Fetcher{
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
