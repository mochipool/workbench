// Package qrcode draws QR codes with rsc.io/qr, the one place that library is
// imported (internal/archtest). It implements ports.QRCodeRenderer for the
// Catalyst voting-key QR code (spec: SPO-09a-EXT-005, SPO-09a-OUT-007).
//
// The error-correction level is H, as the Catalyst toolbox's (catalyst-toolbox
// src/kedqr/img.rs, `EcLevel::H`). rsc.io/qr copies the text into a string
// that cannot be wiped; the payload is the key encrypted under a four-digit
// PIN, which is why the command treats the drawing as secret. The package has
// no image writer: the release binary shows the code on a terminal and writes
// it to no file (SPO-Xcustody-INV-001).
package qrcode

import (
	"errors"
	"fmt"
	"strings"

	rsqr "rsc.io/qr"

	"github.com/mochipool/workbench/spo/internal/ports"
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
