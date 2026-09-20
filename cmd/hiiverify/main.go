// Command hiiverify is the reference verifier. Given a work's leaf files
// (attestations and, optionally, identity bindings), it reconstructs the
// provenance chain, verifies each event's signature, resolves signer identities
// against a trusted root, and — when given a media file — reports the exact and
// fuzzy content match. It prints a JSON verification report.
//
// This offline mode operates on leaf bytes the caller already holds; verifying
// log inclusion against a live node (tile fetching) builds on verify.VerifyInclusion.
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/human-intelligence-institute/chain-of-creation-verify/pkg/fuzzy"
	"github.com/human-intelligence-institute/chain-of-creation-verify/pkg/identity"
	"github.com/human-intelligence-institute/chain-of-creation-verify/pkg/leaf"
	"github.com/human-intelligence-institute/chain-of-creation-verify/internal/provenance"
	"github.com/human-intelligence-institute/chain-of-creation-verify/internal/verify"
)

type stringList []string

func (s *stringList) String() string     { return fmt.Sprint(*s) }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "hiiverify:", err)
		os.Exit(1)
	}
}

func run() error {
	var leafFiles stringList
	flag.Var(&leafFiles, "leaf", "path to a raw leaf file (repeatable)")
	dir := flag.String("dir", "", "directory of leaf files to load")
	trustedRootHex := flag.String("trusted-root", "", "hex Ed25519 identity-root public key")
	mediaFile := flag.String("media", "", "media file to content-match")
	workHex := flag.String("work", "", "hex work id (16 bytes); optional if exactly one work is present")
	targetHex := flag.String("target", "", "leaf hash to match media against; default is the highest-sequence event")
	flag.Parse()

	paths, err := collectPaths(leafFiles, *dir)
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return errors.New("no leaf files given (use -leaf or -dir)")
	}

	var resolver *identity.Resolver
	if *trustedRootHex != "" {
		root, err := parseKey32(*trustedRootHex)
		if err != nil {
			return fmt.Errorf("trusted-root: %w", err)
		}
		resolver = identity.NewResolver(root)
	}

	index := provenance.NewIndex()
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if err := ingest(raw, index, resolver); err != nil {
			return fmt.Errorf("%s: %w", filepath.Base(p), err)
		}
	}

	chain, err := selectWork(index, *workHex)
	if err != nil {
		return err
	}

	report := verify.BuildWorkReport(chain, resolver)

	if *mediaFile != "" {
		media, err := os.ReadFile(*mediaFile)
		if err != nil {
			return err
		}
		target, err := selectTarget(chain, *targetHex)
		if err != nil {
			return err
		}
		match := verify.MatchMedia(media, media, target.Att, fuzzy.Default())
		report.Content = &verify.MediaReport{
			TargetLeafHashHex: hex.EncodeToString(target.Hash[:]),
			Match:             match,
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// ingest decodes a leaf and routes it: attestations populate the provenance
// index; identity bindings are added to the resolver (when one is configured).
func ingest(raw []byte, index *provenance.Index, resolver *identity.Resolver) error {
	kind, err := leaf.PeekKind(raw)
	if err != nil {
		return err
	}
	switch kind {
	case leaf.KindAttestation:
		att, err := leaf.UnmarshalAttestation(raw)
		if err != nil {
			return err
		}
		index.Add(att, 0)
	case leaf.KindIdentityBinding:
		b, err := leaf.UnmarshalIdentityBinding(raw)
		if err != nil {
			return err
		}
		if resolver != nil {
			if err := resolver.Add(b); err != nil {
				return err
			}
		}
	default:
		return errors.New("unknown leaf kind")
	}
	return nil
}

func collectPaths(files stringList, dir string) ([]string, error) {
	paths := append([]string{}, files...)
	if dir != "" {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if !e.IsDir() {
				paths = append(paths, filepath.Join(dir, e.Name()))
			}
		}
	}
	return paths, nil
}

func selectWork(index *provenance.Index, workHex string) (*provenance.Chain, error) {
	if workHex != "" {
		b, err := hex.DecodeString(workHex)
		if err != nil || len(b) != 16 {
			return nil, errors.New("work must be 16 bytes (32 hex chars)")
		}
		var id [16]byte
		copy(id[:], b)
		chain, ok := index.Work(id)
		if !ok {
			return nil, errors.New("no events for the given work id")
		}
		return chain, nil
	}
	works := index.Works()
	switch len(works) {
	case 0:
		return nil, errors.New("no attestations loaded")
	case 1:
		chain, _ := index.Work(works[0])
		return chain, nil
	default:
		return nil, errors.New("multiple works present; specify -work")
	}
}

// selectTarget picks the event to match media against: the one named by
// targetHex, or (by default) the highest-sequence event.
func selectTarget(chain *provenance.Chain, targetHex string) (*provenance.Event, error) {
	if targetHex != "" {
		want, err := hex.DecodeString(targetHex)
		if err != nil {
			return nil, errors.New("target must be hex")
		}
		for _, e := range chain.Events {
			if string(e.Hash[:]) == string(want) {
				return e, nil
			}
		}
		return nil, errors.New("target leaf hash not found in work")
	}
	var best *provenance.Event
	for _, e := range chain.Events {
		if best == nil || e.Att.EventSeq > best.Att.EventSeq {
			best = e
		}
	}
	if best == nil {
		return nil, errors.New("work has no events")
	}
	return best, nil
}

func parseKey32(h string) ([32]byte, error) {
	var k [32]byte
	b, err := hex.DecodeString(h)
	if err != nil {
		return k, err
	}
	if len(b) != 32 {
		return k, errors.New("must be 32 bytes (64 hex chars)")
	}
	copy(k[:], b)
	return k, nil
}
