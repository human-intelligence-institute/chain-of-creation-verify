package fuzzy

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"testing"

	"github.com/human-intelligence-institute/chain-of-creation/internal/leaf"
)

// --- registry ---

type digesterOnly struct{}

func (digesterOnly) ID() string                      { return "digest-only-v1" }
func (digesterOnly) Digest(b []byte) ([]byte, error) { return []byte{0}, nil }

func TestDefaultRegistry(t *testing.T) {
	r := Default()
	if _, ok := r.Get("simhash-text-v1"); !ok {
		t.Fatal("simhash-text-v1 not registered")
	}
	if _, ok := r.Get("phash-dct-64"); !ok {
		t.Fatal("phash-dct-64 not registered")
	}
	if d, ok := r.DigesterForMedia(leaf.MediaText); !ok || d.ID() != "simhash-text-v1" {
		t.Fatal("text default not wired")
	}
	if d, ok := r.DigesterForMedia(leaf.MediaDigitalArt); !ok || d.ID() != "phash-dct-64" {
		t.Fatal("digital-art should map to pHash")
	}
	if _, ok := r.DigesterForMedia(leaf.MediaAudio); ok {
		t.Fatal("audio should have no default digester yet")
	}
}

func TestVerifierErrors(t *testing.T) {
	r := NewRegistry()
	r.Register(digesterOnly{}, leaf.MediaVideo)

	if _, err := r.Verifier("nope"); err == nil {
		t.Fatal("expected ErrUnknownAlgorithm")
	}
	if _, err := r.Verifier("digest-only-v1"); err == nil {
		t.Fatal("expected ErrVerifyUnsupported for digester-only algorithm")
	}
}

func TestRegisterDuplicatePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on duplicate registration")
		}
	}()
	r := NewRegistry()
	r.Register(NewSimHashText())
	r.Register(NewSimHashText())
}

// --- SimHash text ---

func digest(t *testing.T, v Verifier, b []byte) []byte {
	t.Helper()
	d, err := v.Digest(b)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	return d
}

func distance(t *testing.T, v Verifier, a, b []byte) float64 {
	t.Helper()
	d, err := v.Distance(a, b)
	if err != nil {
		t.Fatalf("Distance: %v", err)
	}
	return d
}

func TestSimHashIdentical(t *testing.T) {
	v := NewSimHashText()
	text := []byte("the quick brown fox jumps over the lazy dog and runs away quickly")
	if distance(t, v, digest(t, v, text), digest(t, v, text)) != 0 {
		t.Fatal("identical text should have distance 0")
	}
}

func TestSimHashMatchesReformatted(t *testing.T) {
	v := NewSimHashText()
	original := []byte("The Quick Brown Fox jumps over the lazy dog, and then it runs away very quickly indeed.")
	reformatted := []byte("the   quick brown fox JUMPS over the\n\tlazy dog and then it runs away very quickly indeed")

	d := distance(t, v, digest(t, v, original), digest(t, v, reformatted))
	if d > v.DefaultThreshold() {
		t.Fatalf("reformatted text distance %.3f exceeds threshold %.3f", d, v.DefaultThreshold())
	}
}

func TestSimHashRejectsUnrelated(t *testing.T) {
	v := NewSimHashText()
	a := []byte("a treatise on the migratory patterns of arctic terns across hemispheres")
	b := []byte("quarterly financial projections for the semiconductor manufacturing sector")

	d := distance(t, v, digest(t, v, a), digest(t, v, b))
	if d <= v.DefaultThreshold() {
		t.Fatalf("unrelated text distance %.3f within threshold %.3f (false match)", d, v.DefaultThreshold())
	}
}

// --- pHash image ---

// pattern draws a deterministic 128x128 image with low-frequency structure so
// the perceptual hash is meaningful. variant changes the gradient orientation
// and a bright block's position.
func pattern(variant int) image.Image {
	const n = 128
	img := image.NewRGBA(image.Rect(0, 0, n, n))
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			var lum int
			if variant == 0 {
				lum = (x + y) % 256
			} else {
				lum = (x + (n - y)) % 256
			}
			// A bright block whose corner depends on the variant.
			bx, by := 8, 8
			if variant != 0 {
				bx, by = 80, 80
			}
			if x >= bx && x < bx+40 && y >= by && y < by+40 {
				lum = 250
			}
			img.Set(x, y, color.RGBA{uint8(lum), uint8(lum), uint8(lum), 255})
		}
	}
	return img
}

func pngBytes(t *testing.T, img image.Image) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func jpegBytes(t *testing.T, img image.Image, quality int) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: quality}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestPHashIdentical(t *testing.T) {
	v := NewPHashImage()
	img := pngBytes(t, pattern(0))
	if distance(t, v, digest(t, v, img), digest(t, v, img)) != 0 {
		t.Fatal("identical image should have distance 0")
	}
}

func TestPHashMatchesRecompressed(t *testing.T) {
	v := NewPHashImage()
	base := digest(t, v, pngBytes(t, pattern(0)))
	// Same image, lossy JPEG recompression at low quality.
	recompressed := digest(t, v, jpegBytes(t, pattern(0), 40))

	d := distance(t, v, base, recompressed)
	if d > v.DefaultThreshold() {
		t.Fatalf("recompressed image distance %.3f exceeds threshold %.3f", d, v.DefaultThreshold())
	}
}

func TestPHashRejectsDifferentImage(t *testing.T) {
	v := NewPHashImage()
	a := digest(t, v, pngBytes(t, pattern(0)))
	b := digest(t, v, pngBytes(t, pattern(1)))

	d := distance(t, v, a, b)
	if d <= v.DefaultThreshold() {
		t.Fatalf("different images distance %.3f within threshold %.3f (false match)", d, v.DefaultThreshold())
	}
}

func TestDistanceRejectsWrongLength(t *testing.T) {
	for _, v := range []Verifier{NewSimHashText(), NewPHashImage()} {
		if _, err := v.Distance([]byte{1, 2}, []byte{3, 4}); err != ErrDigestLength {
			t.Fatalf("%s: expected ErrDigestLength, got %v", v.ID(), err)
		}
	}
}
