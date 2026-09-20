package verify

import (
	"encoding/hex"
	"sort"

	"github.com/human-intelligence-institute/chain-of-creation-verify/pkg/identity"
	"github.com/human-intelligence-institute/chain-of-creation-verify/internal/provenance"
	"github.com/human-intelligence-institute/chain-of-creation-verify/pkg/status"
)

// Report is the full verification result for a work.
//
// Verdict is the top line and rolls up every event's status. It starts as
// INDETERMINATE and only becomes VERIFIED once status resolution has actually
// run and cleared every event — a report that was never resolved must not read
// as verified.
type Report struct {
	WorkIDHex string        `json:"work_id"`
	Verdict   string        `json:"verdict"`
	Events    []EventReport `json:"events"`
	Chain     ChainReport   `json:"chain"`
	Content   *MediaReport  `json:"content,omitempty"`
}

// SetEventStatus applies a status-resolution outcome to one event, identified by
// its hex leaf hash, then recomputes the work-level verdict. It reports whether
// an event matched.
//
// Withdrawal targets a single attestation leaf, so a work with several events
// can have exactly one withdrawn while the rest stand.
func (r *Report) SetEventStatus(leafHashHex string, v status.Verdict, e *status.Entry, artifactVersion uint64) bool {
	matched := false
	for i := range r.Events {
		if r.Events[i].LeafHashHex != leafHashHex {
			continue
		}
		matched = true
		r.Events[i].Verdict = string(v)
		if e == nil {
			r.Events[i].Withdrawn = nil
			break
		}
		r.Events[i].Withdrawn = &WithdrawnDetail{
			At:              e.WithdrawnAt,
			Reason:          e.Reason,
			ArtifactVersion: artifactVersion,
		}
		break
	}
	r.rollUpVerdict()
	return matched
}

// rollUpVerdict sets the work-level verdict from its events.
//
// Precedence is INDETERMINATE > WITHDRAWN > VERIFIED: an event whose status
// could not be resolved might be concealing a withdrawal, so it dominates a
// known one. In practice the distinction rarely arises — every event in a report
// resolves against the same artifact fetch, so an unreachable artifact makes the
// whole report indeterminate at once.
//
// An event with no verdict yet counts as unresolved, which is why a report that
// has never had status applied reports INDETERMINATE rather than VERIFIED.
func (r *Report) rollUpVerdict() {
	worst := status.VerdictVerified
	for _, e := range r.Events {
		switch status.Verdict(e.Verdict) {
		case status.VerdictVerified:
			// no change
		case status.VerdictWithdrawn:
			if worst == status.VerdictVerified {
				worst = status.VerdictWithdrawn
			}
		default: // INDETERMINATE, or empty (never resolved)
			r.Verdict = string(status.VerdictIndeterminate)
			return
		}
	}
	r.Verdict = string(worst)
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

	r := Report{
		WorkIDHex: hex.EncodeToString(chain.WorkID[:]),
		Events:    events,
		Chain:     chainReport(chain.Analyze()),
	}
	// Status has not been resolved yet, so this lands on INDETERMINATE. A caller
	// must run resolution and apply it before the report can read as VERIFIED.
	r.rollUpVerdict()
	return r
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
