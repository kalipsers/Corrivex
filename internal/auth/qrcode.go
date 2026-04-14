package auth

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"

	"rsc.io/qr"
)

// QRDataURL renders text into a QR code PNG and returns it as a
// `data:image/png;base64,…` URL ready to drop into an <img src=…>.
//
// scale = number of pixels per QR module (8 → ~200px for typical otpauth
// URLs); border is the white quiet zone in modules around the code (4 is the
// minimum recommended by the QR spec).
func QRDataURL(text string, scale, border int) (string, error) {
	if scale < 1 {
		scale = 8
	}
	if border < 0 {
		border = 4
	}
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	n := code.Size
	side := (n + border*2) * scale
	img := image.NewGray(image.Rect(0, 0, side, side))
	// White background.
	for i := range img.Pix {
		img.Pix[i] = 0xff
	}
	black := color.Gray{Y: 0}
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			if !code.Black(x, y) {
				continue
			}
			px := (x + border) * scale
			py := (y + border) * scale
			for dy := 0; dy < scale; dy++ {
				for dx := 0; dx < scale; dx++ {
					img.SetGray(px+dx, py+dy, black)
				}
			}
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}
