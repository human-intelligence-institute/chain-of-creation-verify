package attest

import (
	"testing"
	"time"

	"github.com/human-intelligence-institute/chain-of-creation/internal/fuzzy"
	"github.com/human-intelligence-institute/chain-of-creation/internal/leaf"
)

func TestBuildText(t *testing.T) {
	media := []byte("a short passage of text to attest")
	att, err := Build(media, Params{
		WorkID:    [16]byte{1},
		EventType: leaf.EventDraft,
		MediaType: leaf.MediaText,
		Now:       time.UnixMilli(1_700_000_000_000),
	}, fuzzy.Default())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if att.AlgorithmID != "simhash64-v1" {
		t.Fatalf("AlgorithmID = %q", att.AlgorithmID)
	}
	if att.ExactHash != leaf.HashContent(media) {
		t.Fatal("ExactHash mismatch")
	}
	if len(att.FuzzyDigest) == 0 {
		t.Fatal("FuzzyDigest not populated")
	}
	if att.SubmittedAt != 1_700_000_000_000 {
		t.Fatalf("SubmittedAt = %d", att.SubmittedAt)
	}
}

func TestBuildUnsupportedMediaType(t *testing.T) {
	_, err := Build([]byte("x"), Params{
		EventType: leaf.EventDraft,
		MediaType: leaf.MediaAudio, // no registered digester
	}, fuzzy.Default())
	if err == nil {
		t.Fatal("expected ErrNoDigester for audio")
	}
}

func TestBuildExplicitAlgorithm(t *testing.T) {
	att, err := Build([]byte("x"), Params{
		EventType:   leaf.EventDraft,
		MediaType:   leaf.MediaText,
		AlgorithmID: "simhash-text-v1",
	}, fuzzy.Default())
	if err != nil {
		t.Fatal(err)
	}
	if att.AlgorithmID != "simhash-text-v1" {
		t.Fatalf("AlgorithmID = %q", att.AlgorithmID)
	}
}

func TestBuildUnknownAlgorithm(t *testing.T) {
	_, err := Build([]byte("x"), Params{
		MediaType:   leaf.MediaText,
		AlgorithmID: "nope-v9",
	}, fuzzy.Default())
	if err == nil {
		t.Fatal("expected error for unknown algorithm id")
	}
}
