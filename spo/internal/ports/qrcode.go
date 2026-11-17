package ports

import (
	"context"

	"github.com/mochipool/workbench/spo/internal/domain/catalyst"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
)

// VotingKeyQRSource builds the payload of the Catalyst mobile app's QR code
// for a voting key held in the vault: the extended secret key encrypted with
// the PIN (domain/catalyst). It is a capability of the adapter that may read
// signing keys (ports.Vault); use cases never read the key. The payload is as
// sensitive as the key, because four digits do not resist an offline guess
// (SPO-09a-SEC-002). The caller wipes it.
type VotingKeyQRSource interface {
	VotingKeyQRPayload(ctx context.Context, name string, pin catalyst.PIN) ([]byte, error)
}

// QRCodeRenderer draws a payload as a QR code as text for a terminal
// (SPO-09a-OUT-007). It has no method that writes a file: the release binary
// shows the code on a terminal only (SPO-Xcustody-INV-001).
type QRCodeRenderer interface {
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
