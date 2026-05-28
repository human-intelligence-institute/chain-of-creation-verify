package verify

import (
	"encoding/hex"
	"sort"

	"github.com/human-intelligence-institute/chain-of-creation/internal/identity"
	"github.com/human-intelligence-institute/chain-of-creation/internal/provenance"
)

// Report is the full verification result for a work.
type Report struct {
	WorkIDHex string        `json:"work_id"`
	Events    []EventReport `json:"events"`
	Chain     ChainReport   `json:"chain"`
	Content   *MediaReport  `json:"content,omitempty"`
}

// MediaReport is the content-match section, present when a media file was
// verified against a specific event.
type MediaReport struct {
	TargetLeafHashHex string       `json:"target_leaf_hash"`
	Match             ContentMatch `json:"match"`
}

// BuildWorkReport verifies every event's signature and identity, analyzes chain
// integrity, and returns a deterministic report (events sorted by sequence then
// leaf hash). Content matching is attached separately via WithMedia.
func BuildWorkReport(chain *provenance.Chain, res *identity.Resolver) Report {
	events := make([]EventReport, 0, len(chain.Events))
	for _, e := range chain.Events {
		sig, id := VerifyEvent(e.Att, res)
		events = append(events, EventReport{
			LeafHashHex: hex.EncodeToString(e.Hash[:]),
			EventSeq:    e.Att.EventSeq,
			EventType:   string(e.Att.EventType),
			Signature:   sig,
			Identity:    id,
		})
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].EventSeq != events[j].EventSeq {
			return events[i].EventSeq < events[j].EventSeq
		}
		return events[i].LeafHashHex < events[j].LeafHashHex
	})

	return Report{
		WorkIDHex: hex.EncodeToString(chain.WorkID[:]),
		Events:    events,
		Chain:     chainReport(chain.Analyze()),
	}
}

// AllSignaturesValid reports whether every event in the report has a valid
// signature — a convenient top-line gate.
func (r Report) AllSignaturesValid() bool {
	for _, e := range r.Events {
		if !e.Signature.Valid {
			return false
		}
	}
	return true
}
