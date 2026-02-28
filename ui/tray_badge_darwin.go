//go:build darwin

package main

import (
	"bytes"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
)

type trayStatus int

const (
	trayStatusGray   trayStatus = iota // all disconnected
	trayStatusGreen                    // connected, no issues
	trayStatusYellow                   // connecting
	trayStatusRed                      // errors
)

var statusColors = [4]color.RGBA{
	{R: 142, G: 142, B: 147, A: 255}, // gray   — iOS system gray
	{R: 52, G: 199, B: 89, A: 255},   // green  — iOS system green
	{R: 255, G: 204, B: 0, A: 255},   // yellow — iOS system yellow
	{R: 255, G: 59, B: 48, A: 255},   // red    — iOS system red
}

var cachedIcons [4][]byte

func initTrayIcons() {
	for s := trayStatusGray; s <= trayStatusRed; s++ {
		cachedIcons[s] = generateBadgedIcon(trayIconPNG, s)
	}
}

func trayIconForStatus(s trayStatus) []byte {
	if int(s) < len(cachedIcons) && cachedIcons[s] != nil {
		return cachedIcons[s]
	}
	return trayIconPNG
}

func generateBadgedIcon(base []byte, status trayStatus) []byte {
	src, err := png.Decode(bytes.NewReader(base))
	if err != nil {
		return base
	}

	bounds := src.Bounds()
	dst := image.NewRGBA(bounds)
	draw.Draw(dst, bounds, src, bounds.Min, draw.Src)

	w := bounds.Dx()
	h := bounds.Dy()

	// Badge: ~20% of icon size, positioned at bottom-right with slight padding.
	radius := float64(w) * 0.20
	border := math.Max(1.0, radius*0.22)
	pad := radius * 0.15

	cx := float64(w) - radius - pad
	cy := float64(h) - radius - pad

	// White border ring for contrast on any background.
	fillCircleAA(dst, cx, cy, radius+border, color.RGBA{R: 255, G: 255, B: 255, A: 255})
	// Colored status dot.
	fillCircleAA(dst, cx, cy, radius, statusColors[status])

	var buf bytes.Buffer
	if err := png.Encode(&buf, dst); err != nil {
		return base
	}
	return buf.Bytes()
}

// fillCircleAA draws a filled circle with 1-pixel anti-aliased edges.
func fillCircleAA(img *image.RGBA, cx, cy, r float64, c color.RGBA) {
	minX := int(math.Floor(cx - r - 1))
	maxX := int(math.Ceil(cx + r + 1))
	minY := int(math.Floor(cy - r - 1))
	maxY := int(math.Ceil(cy + r + 1))

	bounds := img.Bounds()
	if minX < bounds.Min.X {
		minX = bounds.Min.X
	}
	if minY < bounds.Min.Y {
		minY = bounds.Min.Y
	}
	if maxX > bounds.Max.X {
		maxX = bounds.Max.X
	}
	if maxY > bounds.Max.Y {
		maxY = bounds.Max.Y
	}

	for y := minY; y < maxY; y++ {
		for x := minX; x < maxX; x++ {
			dx := float64(x) + 0.5 - cx
			dy := float64(y) + 0.5 - cy
			dist := math.Sqrt(dx*dx + dy*dy)

			if dist <= r-0.5 {
				// Fully inside — opaque fill.
				img.SetRGBA(x, y, c)
			} else if dist < r+0.5 {
				// Edge pixel — blend for anti-aliasing.
				alpha := r + 0.5 - dist
				bg := img.RGBAAt(x, y)
				img.SetRGBA(x, y, blendOver(bg, c, alpha))
			}
		}
	}
}

func blendOver(bg, fg color.RGBA, fgAlpha float64) color.RGBA {
	a := float64(fg.A) / 255.0 * fgAlpha
	inv := 1.0 - a
	return color.RGBA{
		R: clamp8(float64(fg.R)*a + float64(bg.R)*inv),
		G: clamp8(float64(fg.G)*a + float64(bg.G)*inv),
		B: clamp8(float64(fg.B)*a + float64(bg.B)*inv),
		A: clamp8(float64(fg.A)*fgAlpha + float64(bg.A)*inv),
	}
}

func clamp8(v float64) uint8 {
	if v < 0 {
		return 0
	}
	if v > 255 {
		return 255
	}
	return uint8(v)
}
