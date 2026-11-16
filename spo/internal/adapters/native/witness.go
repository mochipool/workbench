package native

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/bip32"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Signing key envelope types the vault signer uses for a transaction
// witness, per role. Both the normal and the extended (BIP32) form are
// accepted; an `enc` file (SPO-Pfiles-OUT-003) is a different shape and is
// refused with its own message.
var witnessKeyTypes = map[custody.Role]struct{ normal, extended string }{
	custody.RolePayment: {"PaymentSigningKeyShelley_ed25519", "PaymentExtendedSigningKeyShelley_ed25519_bip32"},
	custody.RoleStake:   {"StakeSigningKeyShelley_ed25519", "StakeExtendedSigningKeyShelley_ed25519_bip32"},
	// The pool cold key witnesses a pool registration or retirement
	// (SPO-05c-EXT-004, SPO-07b-EXT-002); the owner is the pool's name.
	custody.RolePoolCold: {"StakePoolSigningKey_ed25519", "StakePoolExtendedSigningKey_ed25519_bip32"},
}

// witnessRef maps a key reference to the secret artefact. For a payment key
// the owner is the address name as upstream's scripts take it (`w` or
// `w.payment`); for a stake key it is the wallet name.
func witnessRef(key custody.KeyRef) (ports.Ref, error) {
	switch key.Role {
	case custody.RolePayment:
		return ports.Ref{Name: key.Owner, Kind: ports.AddrSKey}, nil
	case custody.RoleStake:
		return ports.Ref{Name: key.Owner, Kind: ports.StakingSKey}, nil
	case custody.RolePoolCold:
		return ports.Ref{Name: key.Owner, Kind: ports.NodeSKey}, nil
	}
	return ports.Ref{}, fmt.Errorf("the vault signer cannot witness a transaction with a %s key", key.Role)
}

// loadSigningKey reads a payment or stake signing key envelope held in
// guarded memory into the form bursa signs with. The cborHex is decoded
// into slices that are wiped, never into a string; the returned key's SKey
// is the caller's to wipe.
//
// A normal key is the 32-byte seed, expanded to Go's 64-byte private key. An
// extended key is 128 bytes (key 64, public 32, chain code 32) and becomes
// the 96-byte extended private key bursa signs with after the embedded
// public key is checked against the one derived from the private half.
func loadSigningKey(role custody.Role, env *secret.Buffer) (*bursa.LoadedKey, error) {
	types, ok := witnessKeyTypes[role]
	if !ok {
		return nil, fmt.Errorf("no signing key type is defined for the %s role", role)
	}
	var lk *bursa.LoadedKey
	err := env.Use(func(b []byte) error {
		var e struct {
			Type    string          `json:"type"`
			CborHex json.RawMessage `json:"cborHex"`
			Encr    json.RawMessage `json:"encrHex"`
		}
		if err := json.Unmarshal(b, &e); err != nil {
			return errors.New("the signing key is not a text envelope")
		}
		defer wipe(e.CborHex)
		defer wipe(e.Encr)
		if len(e.Encr) > 0 {
			return errors.New("the signing key is gpg-encrypted (key type enc); decrypt it first, the vault signer does not read that form")
		}
		if e.Type != types.normal && e.Type != types.extended {
			return fmt.Errorf("unsupported signing key type %q for a %s key", e.Type, role)
		}
		h := e.CborHex
		if len(h) < 2 || h[0] != '"' || h[len(h)-1] != '"' {
			return errors.New("the signing key envelope has no cborHex")
		}
		h = h[1 : len(h)-1]
		raw := make([]byte, hex.DecodedLen(len(h)))
		defer wipe(raw)
		n, err := hex.Decode(raw, h)
		if err != nil {
			return errors.New("the signing key cborHex is not hex")
		}
		raw = raw[:n]
		switch {
		case e.Type == types.normal && n == 34 && raw[0] == 0x58 && raw[1] == 0x20:
			priv := ed25519.NewKeyFromSeed(raw[2:34])
			lk = &bursa.LoadedKey{Type: e.Type, SKey: []byte(priv), VKey: append([]byte(nil), priv[32:]...)}
		case e.Type == types.extended && n == 130 && raw[0] == 0x58 && raw[1] == 0x80:
			key := raw[2:]
			xprv := make([]byte, 96)
			copy(xprv[:64], key[:64])
			copy(xprv[64:], key[96:128])
			derived := bip32.XPrv(xprv).PublicKey()
			if subtle.ConstantTimeCompare(derived, key[64:96]) != 1 {
				wipe(xprv)
				return errors.New("the extended signing key's public half does not match its private half")
			}
			lk = &bursa.LoadedKey{Type: e.Type, SKey: xprv, VKey: derived}
		default:
			if e.Type == types.normal {
				return errors.New("the signing key is not a 32-byte Ed25519 key")
			}
			return errors.New("the extended signing key is not a 128-byte BIP32-Ed25519 key")
		}
		return nil
	})
	return lk, err
}

// Witness implements ports.TxWitnesser: it signs the transaction id with a
// payment or stake key from the vault. The key is opened for the call and
// destroyed after it. A software signer signs a hash, so it has no limit on
// the features of the body.
//
// spec: SPO-Ptx-EXT-006, SPO-Ptx-SEC-001, SPO-Pfiles-INV-002
func (v VaultSigner) Witness(ctx context.Context, key custody.KeyRef, body txbuild.TxBody) (txbuild.Witness, error) {
	ref, err := witnessRef(key)
	if err != nil {
		return txbuild.Witness{}, err
	}
	env, err := v.Vault.Open(ctx, ref)
	if err != nil {
		return txbuild.Witness{}, fmt.Errorf("open the %s signing key: %w", key.Role, err)
	}
	defer env.Destroy()
	lk, err := loadSigningKey(key.Role, env)
	if err != nil {
		return txbuild.Witness{}, err
	}
	defer wipe(lk.SKey)
	w, err := bursa.CreateWitness(body.ID[:], lk)
	if err != nil {
		return txbuild.Witness{}, err
	}
	if len(w.Vkey) != 32 || len(w.Signature) != 64 {
		return txbuild.Witness{}, errors.New("the witness has unexpected sizes")
	}
	var out txbuild.Witness
	copy(out.VKey[:], w.Vkey)
	copy(out.Signature[:], w.Signature)
	return out, nil
}

var _ ports.TxWitnesser = VaultSigner{}
