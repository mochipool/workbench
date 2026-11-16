// Package qrcode draws QR codes with rsc.io/qr, the one place that library is
// imported (internal/archtest). It implements ports.QRCodeRenderer for the
// Catalyst voting-key QR code (spec: SPO-09a-EXT-005, SPO-09a-OUT-007).
//
// The error-correction level is H, as the Catalyst toolbox's (catalyst-toolbox
// src/kedqr/img.rs, `EcLevel::H`). rsc.io/qr copies the text into a string
// that cannot be wiped; the payload is the key encrypted under a four-digit
// PIN, which is why the command treats the image as secret.
package qrcode

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io/fs"
	"os"
	"strings"

	rsqr "rsc.io/qr"

	"github.com/mochipool/workbench/spo/internal/ports"
)

const (
	moduleSize = 8 // pixels per QR module
	quietZone  = 4 // modules of white around the code
)

// Renderer implements ports.QRCodeRenderer.
type Renderer struct{}

var _ ports.QRCodeRenderer = Renderer{}

func encode(payload []byte) (*rsqr.Code, error) {
	if len(payload) == 0 {
		return nil, errors.New("qrcode: nothing to encode")
	}
	c, err := rsqr.Encode(string(payload), rsqr.H)
	if err != nil {
		return nil, fmt.Errorf("qrcode: %w", err)
	}
	return c, nil
}

// PNG renders the image bytes: black modules on white, a four-module quiet zone.
func (Renderer) PNG(payload []byte) ([]byte, error) {
	c, err := encode(payload)
	if err != nil {
		return nil, err
	}
	side := (c.Size + 2*quietZone) * moduleSize
	img := image.NewGray(image.Rect(0, 0, side, side))
	for i := range img.Pix {
		img.Pix[i] = 0xff
	}
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if !c.Black(x, y) {
				continue
			}
			for dy := 0; dy < moduleSize; dy++ {
				for dx := 0; dx < moduleSize; dx++ {
					img.SetGray((x+quietZone)*moduleSize+dx, (y+quietZone)*moduleSize+dy, color.Gray{Y: 0})
				}
			}
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// WritePNG implements ports.QRCodeRenderer. The file is created with
// O_EXCL, which also refuses a symbolic link at the path, and mode 0600.
func (r Renderer) WritePNG(path string, payload []byte) error {
	data, err := r.PNG(payload)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%w: %s", ports.ErrQRFileExists, path)
		}
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

// Terminal implements ports.QRCodeRenderer: two rows of modules per line with
// the half-block characters, dark modules as the terminal's foreground on a
// white-on-black-safe palette (light modules are drawn as blocks, so the code
// reads correctly on a dark terminal as the toolbox's inverted rendering does).
func (Renderer) Terminal(payload []byte) (string, error) {
	c, err := encode(payload)
	if err != nil {
		return "", err
	}
	const q = 2
	dark := func(x, y int) bool {
		if x < 0 || y < 0 || x >= c.Size || y >= c.Size {
			return false
		}
		return c.Black(x, y)
	}
	var sb strings.Builder
	for y := -q; y < c.Size+q; y += 2 {
		for x := -q; x < c.Size+q; x++ {
			top, bottom := !dark(x, y), !dark(x, y+1) // light module -> filled
			switch {
			case top && bottom:
				sb.WriteString("█")
			case top:
				sb.WriteString("▀")
			case bottom:
				sb.WriteString("▄")
			default:
				sb.WriteString(" ")
			}
		}
		sb.WriteString("\n")
	}
	return sb.String(), nil
}
