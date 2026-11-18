package native

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/blinklabs-io/bursa/bip32"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// VKeyDeriver derives the verification key of an Ed25519 signing key
// envelope (ports.VerificationKeyDeriver). A normal key is the 32-byte seed;
// an extended key is 128 bytes (key 64, public 32, chain code 32) and carries
// its public key, which is checked against the private half.
//
// It also renders the verification key envelope the generator of the same key
// type writes (DeriveVKeyEnvelope), for an import that must rebuild a missing
// `.vkey`.
//
// Where key bytes are in ordinary memory: the cborHex member is decoded into
// slices that are wiped; the Go ed25519 implementation expands the seed into
// a 64-byte private key on the heap, wiped here after use, which the runtime
// may have copied first.
type VKeyDeriver struct{}

type vkeyForm struct {
	vType, vDesc string
	extended     bool
}

// vkeyForms maps a signing key envelope type to the verification key the
// generators of this package write for it: cardano-cli's descriptions and
// four-space indent for random (normal) keys, cardano-signer's and bursa's
// descriptions and two-space indent for keys derived from a mnemonic
// (extended). Types bursa accepts under another spelling are included.
var vkeyForms = func() map[string]vkeyForm {
	m := map[string]vkeyForm{
		"StakePoolSigningKey_ed25519":                      {coldVType, coldVDesc, false},
		"StakePoolSigningKeyShelley_ed25519":               {coldVType, coldVDesc, false},
		"StakePoolExtendedSigningKeyShelley_ed25519_bip32": {coldVType, "Stake Pool Cold Verification Key", true},
		"StakePoolExtendedSigningKey_ed25519_bip32":        {coldVType, "Stake Pool Cold Verification Key", true},
		"PaymentSigningKeyShelley_ed25519":                 {payVType, payVDesc, false},
		"PaymentExtendedSigningKeyShelley_ed25519_bip32":   {payVType, payVDesc, true},
		"StakeSigningKeyShelley_ed25519":                   {stkVType, stkVDesc, false},
		"StakeExtendedSigningKeyShelley_ed25519_bip32":     {stkVType, stkVDesc, true},
		"PolicySigningKeyShelley_ed25519":                  {payVType, "Policy Verification Key", false},
		"PolicyExtendedSigningKeyShelley_ed25519_bip32":    {payVType, "Policy Verification Key", true},
		"CalidusSigningKeyShelley_ed25519":                 {"CalidusVerificationKeyShelley_ed25519", "Calidus Verification Key", false},
		"CalidusExtendedSigningKeyShelley_ed25519_bip32":   {"CalidusVerificationKeyShelley_ed25519", "Calidus Verification Key", true},
	}
	for _, t := range []string{"DRepSigningKey_ed25519", "DRepSigningKeyShelley_ed25519"} {
		m[t] = vkeyForm{drepVType, drepVDesc, false}
	}
	for _, t := range []string{"DRepExtendedSigningKey_ed25519_bip32", "DRepExtendedSigningKeyShelley_ed25519_bip32"} {
		m[t] = vkeyForm{drepVType, signerDRepVDesc, true}
	}
	for _, t := range []string{"ConstitutionalCommitteeColdSigningKey_ed25519", "CommitteeColdSigningKeyShelley_ed25519"} {
		m[t] = vkeyForm{ccColdVType, ccColdVDesc, false}
	}
	for _, t := range []string{"ConstitutionalCommitteeColdExtendedSigningKey_ed25519_bip32", "CommitteeColdExtendedSigningKeyShelley_ed25519_bip32"} {
		m[t] = vkeyForm{ccColdVType, signerCCColdVDesc, true}
	}
	for _, t := range []string{"ConstitutionalCommitteeHotSigningKey_ed25519", "CommitteeHotSigningKeyShelley_ed25519"} {
		m[t] = vkeyForm{ccHotVType, ccHotVDesc, false}
	}
	for _, t := range []string{"ConstitutionalCommitteeHotExtendedSigningKey_ed25519_bip32", "CommitteeHotExtendedSigningKeyShelley_ed25519_bip32"} {
		m[t] = vkeyForm{ccHotVType, signerCCHotVDesc, true}
	}
	return m
}()

// ErrBadSigningKey is returned for a signing key envelope that cannot be read
// as the Ed25519 key its type says. It carries no key material.
var ErrBadSigningKey = errors.New("the signing key envelope is malformed")

// derive returns the 32-byte public key and the form of its envelope.
func (VKeyDeriver) derive(env *secret.Buffer) (pub []byte, form vkeyForm, err error) {
	err = env.Use(func(b []byte) error {
		var e struct {
			Type        string          `json:"type"`
			Description string          `json:"description"`
			CborHex     json.RawMessage `json:"cborHex"`
			Encr        json.RawMessage `json:"encrHex"`
		}
		if jerr := json.Unmarshal(b, &e); jerr != nil {
			return ErrBadSigningKey
		}
		defer wipe(e.CborHex)
		defer wipe(e.Encr)
		if len(e.Encr) > 0 {
			return ErrBadSigningKey
		}
		f, ok := vkeyForms[e.Type]
		if !ok {
			// KES, VRF, BLS and anything else this adapter does not know.
			return ports.ErrKeyTypeUnsupported
		}
		// A policy key made by cardano-cli is a payment key; bursa's derived
		// policy key keeps the payment type and says "Policy" in the description.
		if f.vType == payVType && strings.Contains(e.Description, "Policy") {
			f.vDesc = "Policy Verification Key"
		}
		h := e.CborHex
		if len(h) < 2 || h[0] != '"' || h[len(h)-1] != '"' {
			return ErrBadSigningKey
		}
		h = h[1 : len(h)-1]
		raw := make([]byte, hex.DecodedLen(len(h)))
		defer wipe(raw)
		n, herr := hex.Decode(raw, h)
		if herr != nil {
			return ErrBadSigningKey
		}
		raw = raw[:n]
		switch {
		case !f.extended && n == 34 && raw[0] == 0x58 && raw[1] == 0x20:
			priv := ed25519.NewKeyFromSeed(raw[2:34])
			defer wipe(priv)
			pub = append([]byte(nil), priv[32:]...)
		case f.extended && n == 130 && raw[0] == 0x58 && raw[1] == 0x80:
			key := raw[2:]
			xprv := make([]byte, 96)
			defer wipe(xprv)
			copy(xprv[:64], key[:64])
			copy(xprv[64:], key[96:128])
			derived := bip32.XPrv(xprv).PublicKey()
			defer wipe(derived)
			if subtle.ConstantTimeCompare(derived, key[64:96]) != 1 {
				return ErrBadSigningKey
			}
			pub = append([]byte(nil), derived...)
		default:
			return ErrBadSigningKey
		}
		form = f
		return nil
	})
	return pub, form, err
}

// DeriveVerificationKey implements ports.VerificationKeyDeriver: the raw
// 32-byte verification key.
//
// A KES signing key (the Sum6 root key) and a VRF signing key (the public half)
// are derived by HotKeyDeriver, in the exact forms of pool.ValidateHot: an
// import by stem therefore refuses a file that has the envelope type of such a
// key and other material, and one whose key does not pair with its stored
// verification key.
func (d VKeyDeriver) DeriveVerificationKey(ctx context.Context, skeyEnvelope *secret.Buffer) ([]byte, error) {
	var typ string
	_ = skeyEnvelope.Use(func(b []byte) error {
		var e struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(b, &e) == nil {
			typ = e.Type
		}
		return nil
	})
	switch typ {
	case "KesSigningKey_ed25519_kes_2^6":
		return HotKeyDeriver{}.DeriveKES(ctx, skeyEnvelope)
	case "VrfSigningKey_PraosVRF":
		return HotKeyDeriver{}.DeriveVRF(ctx, skeyEnvelope)
	}
	pub, _, err := d.derive(skeyEnvelope)
	return pub, err
}

// DeriveVKeyEnvelope returns the verification key text envelope exactly as the
// generator of the signing key's type writes it.
func (d VKeyDeriver) DeriveVKeyEnvelope(_ context.Context, skeyEnvelope *secret.Buffer) ([]byte, error) {
	pub, f, err := d.derive(skeyEnvelope)
	if err != nil {
		return nil, err
	}
	kf := struct{ t, d, c string }{f.vType, f.vDesc, "5820" + hex.EncodeToString(pub)}
	indent := "    "
	if f.extended {
		indent = "  "
	}
	return renderEnvelope(kf.t, kf.d, kf.c, indent)
}

func renderEnvelope(typ, desc, cborHex, indent string) ([]byte, error) {
	b, err := json.MarshalIndent(struct {
		Type        string `json:"type"`
		Description string `json:"description"`
		CborHex     string `json:"cborHex"`
	}{typ, desc, cborHex}, "", indent)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

var _ ports.VerificationKeyDeriver = VKeyDeriver{}
