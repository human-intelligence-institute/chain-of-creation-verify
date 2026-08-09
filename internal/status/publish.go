package status

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/human-intelligence-institute/chain-of-creation/internal/leaf"
	"github.com/zeebo/blake3"
)

// Paths under the log read base. Version-addressed artifacts are immutable, so
// they cache forever; the hint changes on every publication and must not.
const (
	HintPath          = "status/latest.json"
	artifactPathFmt   = "status/v%d.json"
	artifactCacheCtl  = "public, max-age=31536000, immutable"
	hintCacheCtl      = "public, max-age=15"
	artifactCType     = "application/json"
	publisherSchemaV1 = 1
)

// ArtifactPath is the object key for a given artifact version.
func ArtifactPath(version uint64) string { return fmt.Sprintf(artifactPathFmt, version) }

// ObjectWriter publishes an object to the log read base. Implemented over S3 in
// cmd/hiinode; a fake in tests keeps this package free of AWS.
type ObjectWriter interface {
	Put(ctx context.Context, path string, body []byte, contentType, cacheControl string) error
}

// ObjectReader reads an object from the log read base. found is false when the
// object does not exist, which is the normal state before the first publication.
type ObjectReader interface {
	Get(ctx context.Context, path string) (body []byte, found bool, err error)
}

// Appender appends a canonical leaf and returns its assigned index.
type Appender interface {
	Append(ctx context.Context, leafBytes []byte) (uint64, error)
}

// Withdrawal is one entry supplied by the reconciler.
type Withdrawal struct {
	LeafHashB64 string `json:"leaf_hash"`
	Reason      string `json:"reason"`
	WithdrawnAt uint64 `json:"withdrawn_at"`
}

// Publisher builds, signs, anchors and publishes the revocation status artifact.
//
// It lives here rather than in the reconciler because everything it needs is
// here and nowhere else: the identity-root key (a coc secret), BLAKE3, the log
// appender, and write access to the log bucket. Keeping construction in one
// language also means the canonical bytes have exactly one definition, so there
// is no cross-language canonicalisation to keep in step.
type Publisher struct {
	Writer   ObjectWriter
	Reader   ObjectReader
	Appender Appender
	Issuer   ed25519.PrivateKey // HII identity root
	Now      func() time.Time
	// LogSize reports the current tree size, recorded in the artifact so an
	// auditor can spot a reconciler that has stalled while the log grew.
	LogSize func(ctx context.Context) (uint64, error)
}

// Reconcile loads the currently published status and republishes only if the
// supplied set differs. It is the entry point the HTTP handler calls.
//
// A missing or unreadable hint is treated as "nothing published yet" rather than
// an error: the worst case is republishing an identical set as a new version,
// which costs one anchor and is self-correcting. Failing instead would let a
// transient read error block withdrawals indefinitely.
func (p *Publisher) Reconcile(ctx context.Context, withdrawn []Withdrawal) (PublishResult, error) {
	prev, prevVersion := p.currentlyPublished(ctx)

	size := uint64(0)
	if p.LogSize != nil {
		n, err := p.LogSize(ctx)
		if err != nil {
			return PublishResult{}, fmt.Errorf("status: log size: %w", err)
		}
		size = n
	}
	return p.Publish(ctx, prev, prevVersion, withdrawn, size)
}

// currentlyPublished resolves the hint to the artifact it names. Any failure
// yields (nil, 0) — see Reconcile for why that is safe.
func (p *Publisher) currentlyPublished(ctx context.Context) (*Artifact, uint64) {
	if p.Reader == nil {
		return nil, 0
	}
	raw, found, err := p.Reader.Get(ctx, HintPath)
	if err != nil || !found {
		return nil, 0
	}
	var h Hint
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, 0
	}
	body, found, err := p.Reader.Get(ctx, ArtifactPath(h.Version))
	if err != nil || !found {
		return nil, h.Version
	}
	art, _, err := ParseArtifact(body)
	if err != nil {
		return nil, h.Version
	}
	return art, h.Version
}

// PublishResult reports what a Publish call did.
type PublishResult struct {
	Changed     bool   `json:"changed"`
	Version     uint64 `json:"version"`
	AnchorIndex uint64 `json:"anchor_index"`
}

// Publish reconciles the published status against the supplied withdrawn set.
//
// It is a no-op when the set is unchanged — otherwise every run would append a
// redundant anchor and the log would fill with identical commitments.
//
// The write order is load-bearing:
//
//  1. the version-addressed artifact, so an anchor never names an object that
//     cannot be fetched;
//  2. the StatusAnchor leaf, which is the authoritative commitment;
//  3. the discovery hint, only once the anchor is committed, so it never points
//     at an unanchored artifact.
//
// A failure part-way leaves the log correct: a published artifact nobody
// references is inert, and an anchor with a stale hint is still found by the
// verifier's scan.
func (p *Publisher) Publish(ctx context.Context, prev *Artifact, prevVersion uint64, withdrawn []Withdrawal, logSize uint64) (PublishResult, error) {
	entries := normalise(withdrawn)
	if prev != nil && sameSet(prev.Withdrawn, entries) {
		return PublishResult{Changed: false, Version: prevVersion}, nil
	}

	version := prevVersion + 1
	now := p.Now()
	raw, err := BuildArtifact(entries, version, logSize, uint64(now.UnixMilli()))
	if err != nil {
		return PublishResult{}, err
	}

	if err := p.Writer.Put(ctx, ArtifactPath(version), raw, artifactCType, artifactCacheCtl); err != nil {
		return PublishResult{}, fmt.Errorf("status: publish artifact: %w", err)
	}

	anchor := &leaf.StatusAnchor{
		SchemaVersion:   publisherSchemaV1,
		ArtifactVersion: version,
		ArtifactHash:    leaf.Hash(blake3.Sum256(raw)),
		IssuedAt:        uint64(now.UnixMilli()),
	}
	anchor.Sign(p.Issuer)

	idx, err := p.Appender.Append(ctx, anchor.Marshal())
	if err != nil {
		return PublishResult{}, fmt.Errorf("status: append anchor: %w", err)
	}

	hint, err := json.Marshal(Hint{Version: version, AnchorIndex: idx})
	if err != nil {
		return PublishResult{}, err
	}
	if err := p.Writer.Put(ctx, HintPath, hint, artifactCType, hintCacheCtl); err != nil {
		return PublishResult{}, fmt.Errorf("status: publish hint: %w", err)
	}

	return PublishResult{Changed: true, Version: version, AnchorIndex: idx}, nil
}

// BuildArtifact returns the canonical artifact bytes.
//
// These exact bytes are what the anchor commits to and what a verifier hashes on
// receipt — it never re-serialises. Treat this as a wire format: any change to
// the encoding changes every hash.
//
// encoding/json emits struct fields in declaration order, and Artifact's fields
// are declared alphabetically to match, with HTML escaping disabled so the
// output is byte-identical regardless of content.
func BuildArtifact(entries []Entry, version, logSize, issuedAt uint64) ([]byte, error) {
	if entries == nil {
		entries = []Entry{}
	}
	a := Artifact{
		IssuedAt:       issuedAt,
		LogSizeAtIssue: logSize,
		Schema:         publisherSchemaV1,
		Version:        version,
		Withdrawn:      entries,
	}
	return marshalCanonical(a)
}

// normalise converts the reconciler's input to sorted artifact entries. Sorting
// is what makes an unchanged set produce identical bytes run after run.
func normalise(in []Withdrawal) []Entry {
	out := make([]Entry, 0, len(in))
	for _, w := range in {
		out = append(out, Entry{
			LeafHash:    w.LeafHashB64,
			Reason:      w.Reason,
			WithdrawnAt: w.WithdrawnAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LeafHash < out[j].LeafHash })
	return out
}

func sameSet(a, b []Entry) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ValidateLeafHashB64 rejects an entry whose leaf hash is not 32 base64 bytes.
// A malformed hash can never match, so it would silently withdraw nothing.
func ValidateLeafHashB64(s string) error {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("status: leaf_hash is not base64: %w", err)
	}
	if len(raw) != 32 {
		return fmt.Errorf("status: leaf_hash must be 32 bytes, got %d", len(raw))
	}
	return nil
}
