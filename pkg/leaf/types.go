package leaf

import "github.com/zeebo/blake3"

// MediaType enumerates the work types the system accepts. Registration accepts
// all of them; verification support lands progressively (text + photo first).
type MediaType string

const (
	MediaText       MediaType = "text"
	MediaAudio      MediaType = "audio"
	MediaVideo      MediaType = "video"
	MediaDigitalArt MediaType = "digital-art"
	MediaPhoto      MediaType = "photo"
)

// EventType is the kind of provenance event an Attestation records. The set is
// intentionally open-ended; verifiers must tolerate unknown values.
type EventType string

const (
	EventDraft    EventType = "draft"
	EventEdit     EventType = "edit"
	EventFinalize EventType = "finalize"
	EventPublish  EventType = "publish"
)

// KeyType distinguishes an HII-custodied signing key from a creator's
// self-managed one. A verifier uses this to decide whether HII vouches for the
// identity or merely witnessed a self-asserted one.
type KeyType uint8

const (
	KeyHIICustodial KeyType = 1
	KeySelfManaged  KeyType = 2
)

// Hash is a 32-byte BLAKE3 digest.
type Hash [32]byte

// hashBytes returns the BLAKE3-256 digest of b.
func hashBytes(b []byte) Hash {
	return Hash(blake3.Sum256(b))
}

// HashContent returns the BLAKE3-256 digest of media bytes — the same function
// used to populate an Attestation's ExactHash. Verifiers recompute it over a
// candidate file to test for a byte-identical match.
func HashContent(b []byte) Hash { return hashBytes(b) }
