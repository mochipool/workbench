package ports

import (
	"context"
	"errors"

	"github.com/mochipool/workbench/spo/internal/domain/catalyst"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
)

// ErrQRFileExists means the PNG of the QR code is already there; it is never
// overwritten (SPO-09a-PRE-010).
var ErrQRFileExists = errors.New("the QR code file already exists; it is not overwritten")

// VotingKeyQRSource builds the payload of the Catalyst mobile app's QR code
// for a voting key held in the vault: the extended secret key encrypted with
// the PIN (domain/catalyst). It is a capability of the adapter that may read
// signing keys (ports.Vault); use cases never read the key. The payload is as
// sensitive as the key, because four digits do not resist an offline guess
// (SPO-09a-SEC-002). The caller wipes it.
type VotingKeyQRSource interface {
	VotingKeyQRPayload(ctx context.Context, name string, pin catalyst.PIN) ([]byte, error)
}

// QRCodeRenderer draws a payload as a QR code, as the PNG file the mobile app
// scans and as text for the terminal (SPO-09a-EXT-005, SPO-09a-OUT-007).
type QRCodeRenderer interface {
	// WritePNG creates the file with mode 0600 and writes the image. It never
	// replaces an existing file or follows a symbolic link (ErrQRFileExists).
	WritePNG(path string, payload []byte) error
	// Terminal returns the QR code as lines of block characters.
	Terminal(payload []byte) (string, error)
}

// TextSignature is a plain Ed25519 signature over a text and the public key
// that made it (SPO-15-OUT-006).
type TextSignature struct {
	PublicKey [32]byte
	Signature [64]byte
}

// TextSigner signs a text with a Calidus key: the signature is over the bytes
// of the text itself, not a CIP-8 message (SPO-15-OUT-006). A device does not
// claim it: the specs have no hardware Calidus key (SPO-15-IF-006).
type TextSigner interface {
	Signer
	SignText(ctx context.Context, key custody.Key[custody.Calidus], text []byte) (TextSignature, error)
}
