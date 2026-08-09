// Package leaf defines the two opaque leaf types stored in the transparency
// log — Attestation (a signed provenance event) and IdentityBinding — together
// with their deterministic, canonical wire encoding.
//
// Tessera treats these bytes as opaque and computes its own RFC6962 Merkle leaf
// hash over them. The canonical encoding here exists for two independent
// purposes: producing a stable byte string to sign/verify, and producing a
// stable content hash (LeafHash) used to chain provenance events together.
package leaf

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// LeafKind tags the concrete type carried in a marshaled leaf so a reader can
// dispatch without out-of-band context.
type LeafKind uint8

const (
	KindAttestation     LeafKind = 1
	KindIdentityBinding LeafKind = 2
	KindStatusAnchor    LeafKind = 3
)

// encoder builds a canonical byte string. Integers are big-endian; variable
// length fields are length-prefixed with a uint32. The encoding is fully
// deterministic: identical inputs always produce identical bytes.
type encoder struct{ buf []byte }

func (e *encoder) u8(v uint8) { e.buf = append(e.buf, v) }
func (e *encoder) u32(v uint32) {
	e.buf = binary.BigEndian.AppendUint32(e.buf, v)
}
func (e *encoder) u64(v uint64) {
	e.buf = binary.BigEndian.AppendUint64(e.buf, v)
}

// fixed appends a fixed-width field with no length prefix (caller guarantees width).
func (e *encoder) fixed(b []byte) { e.buf = append(e.buf, b...) }

// bytes appends a length-prefixed variable-width field.
func (e *encoder) bytes(b []byte) {
	e.u32(uint32(len(b)))
	e.buf = append(e.buf, b...)
}

func (e *encoder) str(s string) { e.bytes([]byte(s)) }

// decoder mirrors encoder with bounds-checked reads.
type decoder struct {
	buf []byte
	pos int
}

var errTruncated = errors.New("leaf: truncated input")

func (d *decoder) u8() (uint8, error) {
	if d.pos+1 > len(d.buf) {
		return 0, errTruncated
	}
	v := d.buf[d.pos]
	d.pos++
	return v, nil
}

func (d *decoder) u32() (uint32, error) {
	if d.pos+4 > len(d.buf) {
		return 0, errTruncated
	}
	v := binary.BigEndian.Uint32(d.buf[d.pos:])
	d.pos += 4
	return v, nil
}

func (d *decoder) u64() (uint64, error) {
	if d.pos+8 > len(d.buf) {
		return 0, errTruncated
	}
	v := binary.BigEndian.Uint64(d.buf[d.pos:])
	d.pos += 8
	return v, nil
}

// fixed reads exactly n bytes (a copy).
func (d *decoder) fixed(n int) ([]byte, error) {
	if d.pos+n > len(d.buf) {
		return nil, errTruncated
	}
	out := make([]byte, n)
	copy(out, d.buf[d.pos:d.pos+n])
	d.pos += n
	return out, nil
}

// bytes reads a length-prefixed variable-width field (a copy).
func (d *decoder) bytes() ([]byte, error) {
	n, err := d.u32()
	if err != nil {
		return nil, err
	}
	return d.fixed(int(n))
}

func (d *decoder) str() (string, error) {
	b, err := d.bytes()
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// finish errors if any unconsumed bytes remain — a strict round-trip guard.
func (d *decoder) finish() error {
	if d.pos != len(d.buf) {
		return fmt.Errorf("leaf: %d trailing bytes after decode", len(d.buf)-d.pos)
	}
	return nil
}
