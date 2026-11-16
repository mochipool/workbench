package catalyst

import (
	"context"
	"errors"
	"fmt"

	domcat "github.com/mochipool/workbench/spo/internal/domain/catalyst"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ErrHardwareVotingKey: a voting key on a hardware wallet has no signing key
// the QR code could carry (SPO-09a-PRE-008, SPO-09a-OUT-009).
var ErrHardwareVotingKey = errors.New("this voting key is on a hardware wallet: it has no signing key to export, so it has no QR code for the mobile app")

// ExportVotingKeyQR writes the PIN-protected QR code of a voting key (upstream
// 09a `qrcode`). The key never reaches the use case: Source builds the
// encrypted payload from the vault, and only the payload, which is as
// sensitive as the key (SPO-09a-SEC-002), is handed to Renderer.
type ExportVotingKeyQR struct {
	Store    ports.Store
	Source   ports.VotingKeyQRSource
	Renderer ports.QRCodeRenderer
}

// QRRequest names the key, the PIN and where the PNG goes.
type QRRequest struct {
	Name string // a leading `./` is dropped
	// PIN is four ASCII digits; the use case does not keep it.
	PIN []byte
	// Path is the PNG file, which must not exist (SPO-09a-PRE-010).
	Path string
}

// QRExported is the result. Terminal is the second output of SPO-09a-OUT-007
// and is as secret as the image.
type QRExported struct {
	Name     string
	Path     string
	Terminal string
}

// Run checks the preconditions in the order of the spec, builds the payload
// and writes the image. The payload is wiped when done.
//
// spec: SPO-09a-PRE-008, SPO-09a-PRE-009, SPO-09a-PRE-010, SPO-09a-EXT-005, SPO-09a-OUT-007
func (uc ExportVotingKeyQR) Run(ctx context.Context, req QRRequest) (res QRExported, err error) {
	if uc.Store == nil || uc.Source == nil || uc.Renderer == nil {
		return res, ErrNotConfigured
	}
	nm, err := plainName(req.Name)
	if err != nil {
		return res, err
	}
	var haveKey, haveHws bool
	if err := uc.Store.View(ctx, func(r ports.Reader) error {
		var err error
		if haveKey, err = r.Exists(ports.Ref{Name: nm, Kind: ports.VotingSKey}); err != nil {
			return err
		}
		haveHws, err = r.Exists(ports.Ref{Name: nm, Kind: ports.VotingHwsFile})
		return err
	}); err != nil {
		return res, err
	}
	if !haveKey { // SPO-09a-PRE-008
		if haveHws {
			return res, ErrHardwareVotingKey
		}
		return res, fmt.Errorf("%w: %s", ErrMissingFile, ports.Ref{Name: nm, Kind: ports.VotingSKey})
	}
	pin, err := domcat.ParsePIN(req.PIN) // SPO-09a-PRE-009
	if err != nil {
		return res, err
	}
	defer pin.Wipe()
	if req.Path == "" {
		return res, errors.New("no file to write the QR code to")
	}
	payload, err := uc.Source.VotingKeyQRPayload(ctx, nm, pin)
	if err != nil {
		return res, fmt.Errorf("build the QR payload: %w", err)
	}
	defer func() {
		for i := range payload {
			payload[i] = 0
		}
	}()
	if err := uc.Renderer.WritePNG(req.Path, payload); err != nil { // SPO-09a-PRE-010
		return res, err
	}
	term, err := uc.Renderer.Terminal(payload)
	if err != nil {
		return res, err
	}
	return QRExported{Name: nm, Path: req.Path, Terminal: term}, nil
}
