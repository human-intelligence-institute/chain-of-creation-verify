package status

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/human-intelligence-institute/chain-of-creation/internal/leaf"
)

type put struct {
	path         string
	body         []byte
	cacheControl string
}

type fakeWriter struct {
	puts    []put
	failOn  string
	objects map[string][]byte
}

func (f *fakeWriter) Put(_ context.Context, path string, body []byte, _ string, cc string) error {
	if f.failOn == path {
		return errors.New("boom")
	}
	if f.objects == nil {
		f.objects = map[string][]byte{}
	}
	f.objects[path] = body
	f.puts = append(f.puts, put{path: path, body: body, cacheControl: cc})
	return nil
}

type fakeAppender struct {
	leaves [][]byte
	fail   bool
}

func (a *fakeAppender) Append(_ context.Context, b []byte) (uint64, error) {
	if a.fail {
		return 0, errors.New("append failed")
	}
	a.leaves = append(a.leaves, append([]byte(nil), b...))
	return uint64(len(a.leaves) - 1), nil
}

func newPublisher(t *testing.T) (*Publisher, *fakeWriter, *fakeAppender, ed25519.PublicKey) {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	w, a := &fakeWriter{}, &fakeAppender{}
	p := &Publisher{
		Writer: w, Appender: a, Issuer: priv,
		Now: func() time.Time { return time.UnixMilli(1786000000000) },
	}
	return p, w, a, priv.Public().(ed25519.PublicKey)
}

var sampleWithdrawal = Withdrawal{
	LeafHashB64: "oKGio6SlpqeoqaqrrK2ur6ChoqOkpaanqKmqq6ytrq8=",
	Reason:      "certification_rejected",
	WithdrawnAt: 1786000000001,
}

// The write order is the whole safety argument: artifact, then anchor, then hint.
func TestPublishWritesArtifactThenAnchorThenHint(t *testing.T) {
	p, w, a, _ := newPublisher(t)
	res, err := p.Publish(context.Background(), nil, 0, []Withdrawal{sampleWithdrawal}, 9)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if !res.Changed || res.Version != 1 {
		t.Fatalf("res = %+v", res)
	}
	if len(w.puts) != 2 {
		t.Fatalf("expected 2 puts, got %d", len(w.puts))
	}
	if w.puts[0].path != ArtifactPath(1) {
		t.Fatalf("first put = %q, want the artifact — an anchor must never name an unfetchable object", w.puts[0].path)
	}
	if w.puts[1].path != HintPath {
		t.Fatalf("second put = %q, want the hint last", w.puts[1].path)
	}
	if len(a.leaves) != 1 {
		t.Fatalf("expected exactly 1 anchor leaf, got %d", len(a.leaves))
	}
}

func TestPublishIsANoOpWhenTheSetIsUnchanged(t *testing.T) {
	p, w, a, _ := newPublisher(t)
	first, err := p.Publish(context.Background(), nil, 0, []Withdrawal{sampleWithdrawal}, 9)
	if err != nil {
		t.Fatalf("first Publish: %v", err)
	}
	prev, _, err := ParseArtifact(w.objects[ArtifactPath(first.Version)])
	if err != nil {
		t.Fatalf("ParseArtifact: %v", err)
	}

	res, err := p.Publish(context.Background(), prev, first.Version, []Withdrawal{sampleWithdrawal}, 12)
	if err != nil {
		t.Fatalf("second Publish: %v", err)
	}
	if res.Changed {
		t.Fatal("an unchanged set published a new version — the log would fill with identical anchors")
	}
	if len(a.leaves) != 1 {
		t.Fatalf("a no-op appended an anchor: %d leaves", len(a.leaves))
	}
}

// Input order must not look like a change.
func TestPublishIgnoresInputOrdering(t *testing.T) {
	p, w, a, _ := newPublisher(t)
	other := Withdrawal{LeafHashB64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Reason: "certification_rejected", WithdrawnAt: 5}
	first, _ := p.Publish(context.Background(), nil, 0, []Withdrawal{sampleWithdrawal, other}, 9)
	prev, _, _ := ParseArtifact(w.objects[ArtifactPath(first.Version)])

	res, err := p.Publish(context.Background(), prev, first.Version, []Withdrawal{other, sampleWithdrawal}, 9)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if res.Changed {
		t.Fatal("reordered input was treated as a change")
	}
	if len(a.leaves) != 1 {
		t.Fatalf("appended %d anchors, want 1", len(a.leaves))
	}
}

// A failed append must not leave a hint pointing at an unanchored artifact.
func TestPublishDoesNotWriteTheHintWhenTheAppendFails(t *testing.T) {
	p, w, a, _ := newPublisher(t)
	a.fail = true
	if _, err := p.Publish(context.Background(), nil, 0, []Withdrawal{sampleWithdrawal}, 9); err == nil {
		t.Fatal("expected an error when the anchor append fails")
	}
	if _, ok := w.objects[HintPath]; ok {
		t.Fatal("the hint was published despite the anchor never committing")
	}
}

func TestPublishedAnchorVerifiesAndCommitsToTheArtifact(t *testing.T) {
	p, w, a, pub := newPublisher(t)
	res, err := p.Publish(context.Background(), nil, 0, []Withdrawal{sampleWithdrawal}, 9)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	anchor, err := leaf.UnmarshalStatusAnchor(a.leaves[0])
	if err != nil {
		t.Fatalf("UnmarshalStatusAnchor: %v", err)
	}
	if !anchor.Verify() {
		t.Fatal("published anchor does not verify")
	}
	if hex.EncodeToString(anchor.IssuerPubKey[:]) != hex.EncodeToString(pub) {
		t.Fatal("anchor signed by an unexpected key")
	}
	// End to end: resolving against exactly what was published must say WITHDRAWN.
	f := &publishedFetcher{w: w, anchorIdx: res.AnchorIndex, leaves: a.leaves}
	lh := mustLeafHash(t, sampleWithdrawal.LeafHashB64)
	v, e, err := Resolve(f, lh, 1, [][32]byte{[32]byte(pub)})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v != VerdictWithdrawn {
		t.Fatalf("verdict = %v, want WITHDRAWN against freshly published state", v)
	}
	if e.Reason != "certification_rejected" {
		t.Fatalf("entry = %+v", e)
	}
}

// publishedFetcher reads back exactly what the Publisher wrote.
type publishedFetcher struct {
	w         *fakeWriter
	anchorIdx uint64
	leaves    [][]byte
}

func (p *publishedFetcher) FetchHint() (*Hint, error) {
	raw, ok := p.w.objects[HintPath]
	if !ok {
		return nil, errNotFound
	}
	var h Hint
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, err
	}
	return &h, nil
}

func (p *publishedFetcher) FetchBundle(uint64) ([][]byte, error) { return p.leaves, nil }

func (p *publishedFetcher) FetchArtifact(v uint64) ([]byte, error) {
	raw, ok := p.w.objects[ArtifactPath(v)]
	if !ok {
		return nil, errNotFound
	}
	return raw, nil
}

// The artifact is immutable and the hint is not; caching them alike would either
// serve a stale hint for a year or defeat caching on the artifact.
func TestCacheControlDistinguishesImmutableFromMutable(t *testing.T) {
	p, w, _, _ := newPublisher(t)
	if _, err := p.Publish(context.Background(), nil, 0, []Withdrawal{sampleWithdrawal}, 9); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if w.puts[0].cacheControl != artifactCacheCtl {
		t.Fatalf("artifact cache-control = %q", w.puts[0].cacheControl)
	}
	if w.puts[1].cacheControl != hintCacheCtl {
		t.Fatalf("hint cache-control = %q", w.puts[1].cacheControl)
	}
}

// Cross-language contract: these bytes must match what the Python reconciler
// produced before construction moved here, and the §7 spec vector.
func TestBuildArtifactMatchesTheSpecVector(t *testing.T) {
	raw, err := BuildArtifact([]Entry{{
		LeafHash:    "oKGio6SlpqeoqaqrrK2ur6ChoqOkpaanqKmqq6ytrq8=",
		Reason:      "certification_rejected",
		WithdrawnAt: 1786000000001,
	}}, 1, 9, 1786000000000)
	if err != nil {
		t.Fatalf("BuildArtifact: %v", err)
	}
	if string(raw) != vecArtifact {
		t.Fatalf("artifact bytes drifted from the published §7 vector:\n got %s\nwant %s", raw, vecArtifact)
	}
}

func TestBuildArtifactEmitsAnEmptyArrayNotNull(t *testing.T) {
	raw, err := BuildArtifact(nil, 1, 0, 0)
	if err != nil {
		t.Fatalf("BuildArtifact: %v", err)
	}
	want := `{"issued_at":0,"log_size_at_issue":0,"schema":1,"version":1,"withdrawn":[]}`
	if string(raw) != want {
		t.Fatalf("got %s want %s", raw, want)
	}
}

func TestValidateLeafHashB64(t *testing.T) {
	if err := ValidateLeafHashB64(sampleWithdrawal.LeafHashB64); err != nil {
		t.Fatalf("valid hash rejected: %v", err)
	}
	if err := ValidateLeafHashB64("not-base64!!"); err == nil {
		t.Fatal("accepted non-base64")
	}
	if err := ValidateLeafHashB64("QUJD"); err == nil {
		t.Fatal("accepted a hash that is not 32 bytes — it could never match, so it would withdraw nothing")
	}
}

func (f *fakeWriter) Get(_ context.Context, path string) ([]byte, bool, error) {
	b, ok := f.objects[path]
	return b, ok, nil
}

// Reconcile must read the currently published state, so a repeat call with the
// same set is a no-op even across process restarts (nothing is held in memory).
func TestReconcileIsIdempotentAcrossCalls(t *testing.T) {
	p, w, a, _ := newPublisher(t)
	p.Reader = w
	p.LogSize = func(context.Context) (uint64, error) { return 9, nil }

	first, err := p.Reconcile(context.Background(), []Withdrawal{sampleWithdrawal})
	if err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	if !first.Changed || first.Version != 1 {
		t.Fatalf("first = %+v", first)
	}

	second, err := p.Reconcile(context.Background(), []Withdrawal{sampleWithdrawal})
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if second.Changed {
		t.Fatal("an unchanged set republished — every scheduled run would append an anchor")
	}
	if len(a.leaves) != 1 {
		t.Fatalf("appended %d anchors across two reconciles, want 1", len(a.leaves))
	}
}

func TestReconcilePublishesWhenTheSetGrows(t *testing.T) {
	p, w, a, _ := newPublisher(t)
	p.Reader = w
	p.LogSize = func(context.Context) (uint64, error) { return 9, nil }

	if _, err := p.Reconcile(context.Background(), []Withdrawal{sampleWithdrawal}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	more := Withdrawal{LeafHashB64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Reason: "certification_rejected", WithdrawnAt: 5}
	res, err := p.Reconcile(context.Background(), []Withdrawal{sampleWithdrawal, more})
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if !res.Changed || res.Version != 2 {
		t.Fatalf("res = %+v, want a new version 2", res)
	}
	if len(a.leaves) != 2 {
		t.Fatalf("appended %d anchors, want 2", len(a.leaves))
	}
}

// A withdrawal being REMOVED (a rejection reversed) must also republish —
// otherwise the log would keep asserting a withdrawal that no longer holds.
func TestReconcilePublishesWhenTheSetShrinks(t *testing.T) {
	p, w, a, _ := newPublisher(t)
	p.Reader = w
	p.LogSize = func(context.Context) (uint64, error) { return 9, nil }

	if _, err := p.Reconcile(context.Background(), []Withdrawal{sampleWithdrawal}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	res, err := p.Reconcile(context.Background(), nil)
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if !res.Changed {
		t.Fatal("removing a withdrawal did not republish")
	}
	if len(a.leaves) != 2 {
		t.Fatalf("appended %d anchors, want 2", len(a.leaves))
	}
}

// An unreadable hint must not block withdrawals.
func TestReconcileTreatsAMissingHintAsNothingPublished(t *testing.T) {
	p, w, _, _ := newPublisher(t)
	p.Reader = w
	p.LogSize = func(context.Context) (uint64, error) { return 0, nil }
	res, err := p.Reconcile(context.Background(), []Withdrawal{sampleWithdrawal})
	if err != nil {
		t.Fatalf("Reconcile with no prior state: %v", err)
	}
	if !res.Changed || res.Version != 1 {
		t.Fatalf("res = %+v", res)
	}
}
