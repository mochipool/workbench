package poolkey

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/mochipool/workbench/spo/internal/app/keyring"

	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ErrHardwareCalidusSuspended is the refusal of every hardware Calidus key:
// upstream suspends deriving one on a device until a dedicated derivation path
// exists (SPO-15-PRE-002), and `sign` takes no hardware Calidus key
// (SPO-15-IF-006).
var ErrHardwareCalidusSuspended = errors.New("a Calidus key cannot be held on a hardware wallet: upstream suspends it until CIP-151 has a dedicated derivation path (SPO-15-PRE-002), so the Calidus key stays in the workspace; the pool cold key on a hardware wallet can still sign its registration")

// SignWithCalidusKey signs a text with the Calidus key (upstream 15 `sign`).
// The signature is a plain Ed25519 signature over the text, not a CIP-8
// message (SPO-15-OUT-006). A failed signature is an error here, not exit 0.
type SignWithCalidusKey struct {
	Store   ports.NamedStore
	Signers ports.SignerDirectory
}

// CalidusSignature is the result; all of it is public.
type CalidusSignature struct {
	CalidusID    string
	PublicKey    [32]byte
	SignatureHex string
}

// Run signs text with the Calidus key named by calidus (a `.vkey` or
// `.calidus` suffix and a leading `./` are dropped, SPO-15-IF-003).
//
// spec: SPO-15-IF-006, SPO-15-EXT-006, SPO-15-OUT-006
func (uc SignWithCalidusKey) Run(ctx context.Context, calidus string, text []byte) (res CalidusSignature, err error) {
	if uc.Store == nil || uc.Signers == nil {
		return res, ErrNotConfigured
	}
	// Raw signing over caller-chosen bytes: text only, never a statement's
	// signing input (SPO-Xidentity-SEC-008). Checked before the store is read.
	if err := ports.CheckSignableText(text); err != nil {
		return res, err
	}
	cal, err := calidusName(calidus)
	if err != nil {
		return res, err
	}
	var ref custody.KeyRef
	if err := uc.Store.View(ctx, func(r ports.NamedReader) error {
		have, err := r.Exists(ports.NamedRef{Name: cal, Kind: ports.CalidusSKey})
		if err != nil {
			return err
		}
		if !have {
			// A Calidus key cannot be made on a device (SPO-15-PRE-002): a hardware
			// signing file alone is no signing key.
			return fmt.Errorf("%w: %s", ErrMissingFile, ports.NamedRef{Name: cal, Kind: ports.CalidusSKey})
		}
		ref, err = keyring.Resolve(r, custody.RoleCalidus, cal)
		return err
	}); err != nil {
		return res, err
	}
	if _, err := ports.PlanSignatures(uc.Signers, []custody.Slot{{
		Label: "sign a text with the Calidus key", Key: ref,
		Demand: custody.Demand{Role: custody.RoleCalidus, Operation: custody.OpSignText},
	}}); err != nil {
		return res, err
	}
	sg, err := uc.Signers.SignerFor(ref)
	if err != nil {
		return res, err
	}
	signer, ok := sg.(ports.TextSigner)
	if !ok {
		return res, ErrNoSigner
	}
	key, err := custody.As[custody.Calidus](ref)
	if err != nil {
		return res, err
	}
	sig, err := signer.SignText(ctx, key, text)
	if err != nil {
		return res, fmt.Errorf("sign the text: %w", err)
	}
	if sig == (ports.TextSignature{}) {
		return res, errors.New("the signer returned no signature") // SPO-15-OUT-006
	}
	// The answer is verified against the demanded Calidus key before anything is returned.
	if err := custody.VerifyText(text, sig.PublicKey, sig.Signature, ref.Identity); err != nil {
		return res, fmt.Errorf("the signer's answer does not verify: %w", err)
	}
	id, err := cose.CalidusID(sig.PublicKey[:])
	if err != nil {
		return res, err
	}
	return CalidusSignature{CalidusID: id, PublicKey: sig.PublicKey, SignatureHex: hex.EncodeToString(sig.Signature[:])}, nil
}
