package ports

import (
	"context"
	"errors"
	"unicode/utf8"

	"github.com/mochipool/workbench/spo/internal/domain/catalyst"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
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

// ErrNotText means the data given to the Calidus `sign` is not valid UTF-8. The
// command signs a text (upstream passes it to `cardano-signer sign --data-text`,
// SPO-15-EXT-006); the bytes that would make a COSE Sig_structure (which starts
// 0x84 or 0x85, never a UTF-8 lead byte) are therefore not a text
// (SPO-Xidentity-SEC-008).
var ErrNotText = errors.New("the data is not valid UTF-8 text: the Calidus `sign` signs a text only")

// CheckSignableText is the guard of every route that signs caller-chosen bytes
// raw with a Calidus key, which is also the payment key 0/0 of its mnemonic: the
// data must be valid UTF-8 (ErrNotText), and, as defence in depth, must not be or
// start like the signing input of a relay statement
// (relaybind.LooksLikeSignedStatementInput; relaybind.ErrRawStatementInput). The
// adapter, the use case and the command all call it, so that a route added
// without one of the layers is still closed by the others.
//
// spec: SPO-Xidentity-SEC-008, SPO-Xrelaybind-SEC-018
func CheckSignableText(text []byte) error {
	if !utf8.Valid(text) {
		return ErrNotText
	}
	if relaybind.LooksLikeSignedStatementInput(text) {
		return relaybind.ErrRawStatementInput
	}
	return nil
}

// TextSigner signs a text with a Calidus key: the signature is over the bytes
// of the text itself, not a CIP-8 message (SPO-15-OUT-006). A device does not
// claim it: the specs have no hardware Calidus key (SPO-15-IF-006). An
// implementation refuses what CheckSignableText refuses, before it opens a key.
type TextSigner interface {
	Signer
	SignText(ctx context.Context, key custody.Key[custody.Calidus], text []byte) (TextSignature, error)
}
