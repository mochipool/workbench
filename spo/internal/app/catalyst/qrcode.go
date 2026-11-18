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

// QRDisplayOperation is the audit record's operation for showing the QR code.
const QRDisplayOperation = "catalyst-qr-display"

// ExportVotingKeyQR builds the PIN-protected QR code of a voting key (upstream
// 09a `qrcode`) for display on a terminal. The release binary writes it to no
// file (SPO-Xcustody-INV-001): the terminal drawing is its one output, and the
// use case records the display in the audit log before the payload is built
// (ADR 0004: a Secret leaves only through an audited path). The key never
// reaches the use case: Source builds the encrypted payload from the vault, and
// only the payload, which is as sensitive as the key (SPO-09a-SEC-002), is
// handed to Renderer.
type ExportVotingKeyQR struct {
	Store    ports.NamedStore
	Source   ports.VotingKeyQRSource
	Renderer ports.QRCodeRenderer
	Auditor  ports.WorkspaceAuditor
}

// QRRequest names the key and the PIN.
type QRRequest struct {
	Name string // a leading `./` is dropped
	// PIN is four ASCII digits; the use case does not keep it.
	PIN []byte
}

// QRExported is the result. Terminal is the drawing of SPO-09a-OUT-007 and is
// as secret as the key.
type QRExported struct {
	Name     string
	Terminal string
}

// Run checks the preconditions in the order of the spec, records the display in
// the audit log, builds the payload and draws it. The payload is wiped when
// done.
//
// spec: SPO-09a-PRE-008, SPO-09a-PRE-009, SPO-09a-EXT-005, SPO-09a-OUT-007, SPO-Xcustody-INV-001
func (uc ExportVotingKeyQR) Run(ctx context.Context, req QRRequest) (res QRExported, err error) {
	if uc.Store == nil || uc.Source == nil || uc.Renderer == nil || uc.Auditor == nil {
		return res, ErrNotConfigured
	}
	nm, err := plainName(req.Name)
	if err != nil {
		return res, err
	}
	var haveKey, haveHws bool
	if err := uc.Store.View(ctx, func(r ports.NamedReader) error {
		var err error
		if haveKey, err = r.Exists(ports.NamedRef{Name: nm, Kind: ports.VotingSKey}); err != nil {
			return err
		}
		haveHws, err = r.Exists(ports.NamedRef{Name: nm, Kind: ports.VotingHwsFile})
		return err
	}); err != nil {
		return res, err
	}
	if !haveKey { // SPO-09a-PRE-008
		if haveHws {
			return res, ErrHardwareVotingKey
		}
		return res, fmt.Errorf("%w: %s", ErrMissingFile, ports.NamedRef{Name: nm, Kind: ports.VotingSKey})
	}
	pin, err := domcat.ParsePIN(req.PIN) // SPO-09a-PRE-009
	if err != nil {
		return res, err
	}
	defer pin.Wipe()
	if err := uc.Auditor.Record(ctx, ports.AuditEvent{
		Operation: QRDisplayOperation, Owners: []string{nm},
		Command: "spo catalyst key qrcode", Read: "voting key QR code drawn on a terminal, protected by a four-digit PIN only",
	}); err != nil {
		return res, fmt.Errorf("the display of the QR code could not be recorded, so it is not made: %w", err)
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
	term, err := uc.Renderer.Terminal(payload)
	if err != nil {
		return res, err
	}
	return QRExported{Name: nm, Terminal: term}, nil
}
