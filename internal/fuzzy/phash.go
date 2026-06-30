package fuzzy

import (
	"bytes"
	"encoding/binary"
	"image"
	"math"
	"math/bits"
	"sort"

	// Register the decoders we support for registration/verification.
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
)

// phashImage is a 64-bit perceptual hash (DCT-II over a 32x32 luminance image,
// thresholded against the median of the low-frequency 8x8 block). It is robust
// to recompression, rescaling, and mild adjustments because those preserve the
// low-frequency structure the hash captures.
//
// This algorithm is a PUBLISHED CONTRACT: its byte-exact behavior is specified in
// docs/verification-spec.md (id "phash-dct-64") and frozen by golden vectors in
// golden_test.go. Any change to resizing, the DCT, the median rule, bit order, or
// threshold is a breaking change — bump the algorithm id, do not edit in place.
type phashImage struct{}

// NewPHashImage returns the image fuzzy hasher (algorithm id "phash-dct-64").
func NewPHashImage() Verifier { return phashImage{} }

func (phashImage) ID() string { return "phash-dct-64" }

const phashN = 32 // working resolution before DCT

func (phashImage) Digest(media []byte) ([]byte, error) {
	img, _, err := image.Decode(bytes.NewReader(media))
	if err != nil {
		return nil, err
	}
	gray := resizeLuma(img, phashN)
	coeffs := dct2d(gray)

	// Collect the low-frequency 8x8 block; compute the median excluding the
	// DC term (coeffs[0][0]), which otherwise dominates.
	block := make([]float64, 0, 64)
	for v := 0; v < 8; v++ {
		for u := 0; u < 8; u++ {
			block = append(block, coeffs[v][u])
		}
	}
	med := medianExcludingFirst(block)

	var fp uint64
	for i, c := range block {
		if c > med {
			fp |= 1 << uint(i)
		}
	}
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, fp)
	return out, nil
}

func (phashImage) Distance(a, b []byte) (float64, error) {
	if len(a) != 8 || len(b) != 8 {
		return 0, ErrDigestLength
	}
	d := bits.OnesCount64(binary.BigEndian.Uint64(a) ^ binary.BigEndian.Uint64(b))
	return float64(d) / 64.0, nil
}

// DefaultThreshold allows up to ~12 differing bits, the usual perceptual-match
// cutoff for a 64-bit pHash.
func (phashImage) DefaultThreshold() float64 { return 0.1875 }

// resizeLuma samples img down to an n×n grayscale (luminance) matrix using
// bilinear interpolation, independent of the source dimensions.
func resizeLuma(img image.Image, n int) [][]float64 {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	out := make([][]float64, n)
	for y := 0; y < n; y++ {
		out[y] = make([]float64, n)
		// Map target row center to source space.
		fy := (float64(y) + 0.5) * float64(h) / float64(n)
		sy := int(fy)
		if sy >= h {
			sy = h - 1
		}
		for x := 0; x < n; x++ {
			fx := (float64(x) + 0.5) * float64(w) / float64(n)
			sx := int(fx)
			if sx >= w {
				sx = w - 1
			}
			r, g, bl, _ := img.At(b.Min.X+sx, b.Min.Y+sy).RGBA()
			// RGBA returns 16-bit values; weight to luminance and scale to 0..255.
			lum := (0.299*float64(r) + 0.587*float64(g) + 0.114*float64(bl)) / 257.0
			out[y][x] = lum
		}
	}
	return out
}

// dctCos[u][x] = cos(pi/N * (x+0.5) * u), precomputed once.
var dctCos = func() [phashN][phashN]float64 {
	var t [phashN][phashN]float64
	for u := 0; u < phashN; u++ {
		for x := 0; x < phashN; x++ {
			t[u][x] = math.Cos(math.Pi / float64(phashN) * (float64(x) + 0.5) * float64(u))
		}
	}
	return t
}()

// dct2d applies a separable 2D DCT-II to an N×N matrix (rows then columns).
// Normalization is omitted because only the relative ordering against the median
// matters for the hash.
func dct2d(in [][]float64) [][]float64 {
	n := phashN
	rows := make([][]float64, n)
	for y := 0; y < n; y++ {
		rows[y] = dct1d(in[y])
	}
	out := make([][]float64, n)
	for v := 0; v < n; v++ {
		out[v] = make([]float64, n)
	}
	col := make([]float64, n)
	for u := 0; u < n; u++ {
		for y := 0; y < n; y++ {
			col[y] = rows[y][u]
		}
		c := dct1d(col)
		for v := 0; v < n; v++ {
			out[v][u] = c[v]
		}
	}
	return out
}

func dct1d(in []float64) []float64 {
	n := phashN
	out := make([]float64, n)
	for u := 0; u < n; u++ {
		var s float64
		for x := 0; x < n; x++ {
			s += in[x] * dctCos[u][x]
		}
		out[u] = s
	}
	return out
}

func medianExcludingFirst(block []float64) float64 {
	rest := make([]float64, len(block)-1)
	copy(rest, block[1:])
	sort.Float64s(rest)
	return rest[len(rest)/2]
}
