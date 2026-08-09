package verify

import (
	"encoding/json"
	"testing"

	"github.com/human-intelligence-institute/chain-of-creation/internal/status"
)

func twoEventReport() *Report {
	return &Report{
		WorkIDHex: "aabb",
		Events: []EventReport{
			{LeafHashHex: "1111", EventSeq: 0},
			{LeafHashHex: "2222", EventSeq: 1},
		},
	}
}

func TestSetEventStatusMarksOnlyTheTargetedLeaf(t *testing.T) {
	r := twoEventReport()
	ok := r.SetEventStatus("2222", status.VerdictWithdrawn, &status.Entry{
		Reason: "certification_rejected", WithdrawnAt: 1786000000001,
	}, 3)
	if !ok {
		t.Fatal("SetEventStatus did not match leaf 2222")
	}
	if r.Events[0].Verdict == string(status.VerdictWithdrawn) {
		t.Fatal("event 0 was marked withdrawn; withdrawal must target one leaf")
	}
	if r.Events[1].Verdict != string(status.VerdictWithdrawn) {
		t.Fatalf("event 1 verdict = %q", r.Events[1].Verdict)
	}
	if r.Events[1].Withdrawn == nil || r.Events[1].Withdrawn.ArtifactVersion != 3 {
		t.Fatalf("event 1 withdrawn = %+v", r.Events[1].Withdrawn)
	}
}

func TestSetEventStatusReportsUnknownLeaf(t *testing.T) {
	r := twoEventReport()
	if r.SetEventStatus("dead", status.VerdictWithdrawn, nil, 1) {
		t.Fatal("SetEventStatus returned true for a leaf not in the report")
	}
}

// One withdrawn event must taint the work's top-line verdict, or a caller that
// reads only the top line renders a clean checkmark.
func TestOneWithdrawnEventTaintsTheWorkVerdict(t *testing.T) {
	r := twoEventReport()
	r.SetEventStatus("1111", status.VerdictVerified, nil, 3)
	r.SetEventStatus("2222", status.VerdictWithdrawn, &status.Entry{Reason: "certification_rejected"}, 3)
	if r.Verdict != string(status.VerdictWithdrawn) {
		t.Fatalf("work verdict = %q, want WITHDRAWN", r.Verdict)
	}
}

func TestAllVerifiedEventsGiveVerifiedWork(t *testing.T) {
	r := twoEventReport()
	r.SetEventStatus("1111", status.VerdictVerified, nil, 3)
	r.SetEventStatus("2222", status.VerdictVerified, nil, 3)
	if r.Verdict != string(status.VerdictVerified) {
		t.Fatalf("work verdict = %q, want VERIFIED", r.Verdict)
	}
}

func TestIndeterminateDominates(t *testing.T) {
	r := twoEventReport()
	r.SetEventStatus("1111", status.VerdictWithdrawn, &status.Entry{Reason: "x"}, 3)
	r.SetEventStatus("2222", status.VerdictIndeterminate, nil, 3)
	if r.Verdict != string(status.VerdictIndeterminate) {
		t.Fatalf("work verdict = %q, want INDETERMINATE", r.Verdict)
	}
}

// An unresolved report must never serialise as VERIFIED just because status
// resolution was never run.
func TestVerdictIsIndeterminateBeforeResolution(t *testing.T) {
	r := twoEventReport()
	if r.Verdict == string(status.VerdictVerified) {
		t.Fatal("a report that has not had status resolved reads as VERIFIED")
	}
}

func TestReportSerialisesVerdict(t *testing.T) {
	r := twoEventReport()
	r.SetEventStatus("1111", status.VerdictVerified, nil, 3)
	r.SetEventStatus("2222", status.VerdictWithdrawn, &status.Entry{
		Reason: "certification_rejected", WithdrawnAt: 1786000000001,
	}, 3)
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got["verdict"] != "WITHDRAWN" {
		t.Fatalf("serialised verdict = %v", got["verdict"])
	}
}
