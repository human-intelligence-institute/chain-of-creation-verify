// Package fuzzy is the plugin registry of fuzzy-hash algorithms. Each algorithm
// has a stable ID and can compute a digest from media bytes; verification-capable
// algorithms also provide a distance metric and a recommended match threshold.
//
// The same code runs at registration and at verification — that identity is the
// safeguard against the two sides silently diverging. Registration of any media
// type works regardless of what is registered here (the log stores opaque digest
// bytes); this registry governs server-side digesting and verification, which
// land per media type over time (text + image first).
package fuzzy

import (
	"errors"
	"fmt"

	"github.com/human-intelligence-institute/chain-of-creation-verify/pkg/leaf"
)

// Digester computes a fuzzy digest from raw media bytes.
type Digester interface {
	ID() string
	Digest(media []byte) ([]byte, error)
}

// Verifier is a Digester that can also compare two digests. Distance returns a
// normalized dissimilarity in [0,1] (0 == identical); a pair is considered a
// match when Distance <= DefaultThreshold (or a stricter verifier-chosen value).
type Verifier interface {
	Digester
	Distance(a, b []byte) (float64, error)
	DefaultThreshold() float64
}

var (
	// ErrUnknownAlgorithm is returned for an algorithm ID not in the registry.
	ErrUnknownAlgorithm = errors.New("fuzzy: unknown algorithm")
	// ErrVerifyUnsupported is returned when an algorithm can digest but cannot
	// yet verify (no distance metric implemented).
	ErrVerifyUnsupported = errors.New("fuzzy: verification not supported for algorithm")
	// ErrDigestLength is returned when a digest is not the size the algorithm expects.
	ErrDigestLength = errors.New("fuzzy: digest has unexpected length")
)

// Registry maps algorithm IDs to their implementations and records a default
// algorithm per media type (used by the custodial path to pick a digester).
type Registry struct {
	byID           map[string]Digester
	defaultByMedia map[leaf.MediaType]string
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		byID:           map[string]Digester{},
		defaultByMedia: map[leaf.MediaType]string{},
	}
}

// Register adds a digester and marks it as the default algorithm for each given
// media type. It panics on a duplicate algorithm ID — registration happens once
// at startup, so a clash is a programming error.
func (r *Registry) Register(d Digester, media ...leaf.MediaType) {
	if _, dup := r.byID[d.ID()]; dup {
		panic(fmt.Sprintf("fuzzy: algorithm %q already registered", d.ID()))
	}
	r.byID[d.ID()] = d
	for _, m := range media {
		r.defaultByMedia[m] = d.ID()
	}
}

// Get returns the digester for an algorithm ID.
func (r *Registry) Get(id string) (Digester, bool) {
	d, ok := r.byID[id]
	return d, ok
}

// Verifier returns the verification-capable implementation for an algorithm ID,
// or ErrUnknownAlgorithm / ErrVerifyUnsupported.
func (r *Registry) Verifier(id string) (Verifier, error) {
	d, ok := r.byID[id]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownAlgorithm, id)
	}
	v, ok := d.(Verifier)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrVerifyUnsupported, id)
	}
	return v, nil
}

// DigesterForMedia returns the default digester for a media type.
func (r *Registry) DigesterForMedia(mt leaf.MediaType) (Digester, bool) {
	id, ok := r.defaultByMedia[mt]
	if !ok {
		return nil, false
	}
	return r.byID[id], true
}

// Default returns a registry with the algorithms shipped today: the canonical
// simhash64-v1 (the id HII certifiers record) as the text default, plus the
// legacy simhash-text-v1 kept resolvable for any older text leaves, and
// pHash-DCT for photo and digital art.
func Default() *Registry {
	r := NewRegistry()
	r.Register(NewSimHash64(), leaf.MediaText)
	r.Register(NewSimHashText())
	r.Register(NewPHashImage(), leaf.MediaPhoto, leaf.MediaDigitalArt)
	return r
}
