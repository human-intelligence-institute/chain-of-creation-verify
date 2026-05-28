// Package provenance reconstructs the history graph of a work from its
// attestation events. The transparency log is flat; this package rebuilds the
// per-work graph by grouping events on WorkID and linking them by
// PrevEventHash. Forks (two events claiming the same parent, or multiple roots)
// are exposed rather than rejected — an append-only log cannot refuse them, so
// the verifier surfaces them and lets the consumer decide.
package provenance

import (
	"errors"
	"sort"

	"github.com/human-intelligence-institute/chain-of-creation/internal/leaf"
)

// Event is one attestation positioned in the log.
type Event struct {
	Att      *leaf.Attestation
	Hash     leaf.Hash // BLAKE3 content hash (the value a child references)
	LogIndex uint64
}

// Index groups attestation events by work.
type Index struct {
	byWork map[[16]byte][]*Event
}

// NewIndex returns an empty index.
func NewIndex() *Index { return &Index{byWork: map[[16]byte][]*Event{}} }

// Add records an attestation at its log index and returns the created Event.
func (ix *Index) Add(att *leaf.Attestation, logIndex uint64) *Event {
	e := &Event{Att: att, Hash: att.LeafHash(), LogIndex: logIndex}
	ix.byWork[att.WorkID] = append(ix.byWork[att.WorkID], e)
	return e
}

// Works returns the work ids present in the index, sorted for deterministic output.
func (ix *Index) Works() [][16]byte {
	works := make([][16]byte, 0, len(ix.byWork))
	for id := range ix.byWork {
		works = append(works, id)
	}
	sort.Slice(works, func(i, j int) bool {
		for k := range works[i] {
			if works[i][k] != works[j][k] {
				return works[i][k] < works[j][k]
			}
		}
		return false
	})
	return works
}

// Work returns the reconstructed chain for a work id.
func (ix *Index) Work(workID [16]byte) (*Chain, bool) {
	evs, ok := ix.byWork[workID]
	if !ok {
		return nil, false
	}
	return &Chain{WorkID: workID, Events: evs}, true
}

// Chain is the set of events belonging to a single work.
type Chain struct {
	WorkID [16]byte
	Events []*Event
}

// Fork is a divergence point. For a shared parent, ParentHash is set and
// Children holds the competing events. For multiple seq-0 roots, Root is true.
type Fork struct {
	Root       bool
	ParentHash leaf.Hash
	Children   []*Event
}

// Integrity is the structural analysis of a chain.
type Integrity struct {
	// Linear is true for the well-formed case: exactly one root, no forks, and
	// every PrevEventHash resolves to a present event.
	Linear   bool
	Roots    []*Event
	Forks    []Fork
	Dangling []*Event // events whose PrevEventHash references an event not in the chain
}

func (c *Chain) byHash() map[leaf.Hash]*Event {
	m := make(map[leaf.Hash]*Event, len(c.Events))
	for _, e := range c.Events {
		m[e.Hash] = e
	}
	return m
}

// links partitions the chain into roots, parent→children adjacency, and
// dangling events (broken back-references).
func (c *Chain) links() (roots []*Event, childrenOf map[leaf.Hash][]*Event, dangling []*Event) {
	present := c.byHash()
	childrenOf = map[leaf.Hash][]*Event{}
	for _, e := range c.Events {
		if e.Att.PrevEventHash == nil {
			roots = append(roots, e)
			continue
		}
		prev := *e.Att.PrevEventHash
		if _, ok := present[prev]; !ok {
			dangling = append(dangling, e)
			continue
		}
		childrenOf[prev] = append(childrenOf[prev], e)
	}
	return roots, childrenOf, dangling
}

// Analyze computes the chain's structural integrity. Output is deterministic:
// forks are sorted by parent hash and children by (EventSeq, Hash).
func (c *Chain) Analyze() Integrity {
	roots, childrenOf, dangling := c.links()

	var forks []Fork
	for ph, kids := range childrenOf {
		if len(kids) > 1 {
			sortEvents(kids)
			forks = append(forks, Fork{ParentHash: ph, Children: kids})
		}
	}
	sort.Slice(forks, func(i, j int) bool {
		return bytesLess(forks[i].ParentHash, forks[j].ParentHash)
	})
	if len(roots) > 1 {
		sortEvents(roots)
		forks = append(forks, Fork{Root: true, Children: roots})
	}

	return Integrity{
		Linear:   len(roots) == 1 && len(forks) == 0 && len(dangling) == 0,
		Roots:    roots,
		Forks:    forks,
		Dangling: dangling,
	}
}

// ErrNotLinear is returned by Linearize when the chain has zero/multiple roots,
// a fork, or a dangling link.
var ErrNotLinear = errors.New("provenance: chain is not linear")

// Linearize returns the events ordered from the single root following
// single-child links. It errors unless the chain is Linear.
func (c *Chain) Linearize() ([]*Event, error) {
	roots, childrenOf, dangling := c.links()
	if len(roots) != 1 || len(dangling) != 0 {
		return nil, ErrNotLinear
	}
	ordered := make([]*Event, 0, len(c.Events))
	cur := roots[0]
	for {
		ordered = append(ordered, cur)
		kids := childrenOf[cur.Hash]
		if len(kids) == 0 {
			break
		}
		if len(kids) > 1 {
			return nil, ErrNotLinear
		}
		cur = kids[0]
	}
	if len(ordered) != len(c.Events) {
		// Some events were unreachable from the root (e.g. a detached cycle).
		return nil, ErrNotLinear
	}
	return ordered, nil
}

func sortEvents(evs []*Event) {
	sort.Slice(evs, func(i, j int) bool {
		if evs[i].Att.EventSeq != evs[j].Att.EventSeq {
			return evs[i].Att.EventSeq < evs[j].Att.EventSeq
		}
		return bytesLess(evs[i].Hash, evs[j].Hash)
	})
}

func bytesLess(a, b leaf.Hash) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}
