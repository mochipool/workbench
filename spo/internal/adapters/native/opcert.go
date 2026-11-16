package native

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/blinklabs-io/bursa"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// VaultSigner signs with keys that sit in the vault. Today it issues
// operational certificates with a pool cold key; the key is opened for the
// call and destroyed after it.
type VaultSigner struct {
	Vault ports.Vault
}

// Profile implements ports.Signer.
func (VaultSigner) Profile() custody.Profile {
	return custody.NewProfile("vault").Allow(custody.RolePoolCold, custody.OpIssueOpCert)
}

// coldSeed extracts the 32-byte seed from a cardano-cli StakePoolSigningKey_ed25519
// envelope held in guarded memory. The seed is returned in guarded memory;
// the temporaries on the way are wiped. (The envelope parser copies the cborHex
// into a byte slice, not a string, so it can be wiped.)
func coldSeed(env *secret.Buffer) (*secret.Buffer, error) {
	var seed *secret.Buffer
	err := env.Use(func(b []byte) error {
		var e struct {
			Type    string          `json:"type"`
			CborHex json.RawMessage `json:"cborHex"`
		}
		if err := json.Unmarshal(b, &e); err != nil {
			return errors.New("the cold signing key is not a text envelope")
		}
		defer wipe(e.CborHex)
		if e.Type != "StakePoolSigningKey_ed25519" {
			return fmt.Errorf("unsupported cold signing key type %q: only StakePoolSigningKey_ed25519 can be used in process", e.Type)
		}
		h := e.CborHex
		if len(h) < 2 || h[0] != '"' || h[len(h)-1] != '"' {
			return errors.New("the cold signing key envelope has no cborHex")
		}
		h = h[1 : len(h)-1]
		raw := make([]byte, hex.DecodedLen(len(h)))
		defer wipe(raw)
		n, err := hex.Decode(raw, h)
		if err != nil || n != 34 || raw[0] != 0x58 || raw[1] != 0x20 {
			return errors.New("the cold signing key is not a 32-byte Ed25519 key")
		}
		seed = secret.Take(append([]byte(nil), raw[2:n]...))
		return nil
	})
	return seed, err
}

// IssueOpCert implements ports.OpCertIssuer.
//
// spec: SPO-04d-EXT-003, SPO-04d-INV-005
func (v VaultSigner) IssueOpCert(ctx context.Context, cold custody.Key[custody.PoolCold], req ports.OpCertRequest) ([]byte, error) {
	env, err := v.Vault.Open(ctx, ports.Ref{Name: cold.Ref().Owner, Kind: ports.NodeSKey})
	if err != nil {
		return nil, fmt.Errorf("open the cold signing key: %w", err)
	}
	defer env.Destroy()
	seed, err := coldSeed(env)
	if err != nil {
		return nil, err
	}
	defer seed.Destroy()

	var oc *bursa.OperationalCertificate
	if err := seed.Use(func(s []byte) error {
		var err error
		oc, err = bursa.CreateOperationalCertificate(req.KesVKey, req.Counter, req.KesPeriod, s)
		return err
	}); err != nil {
		return nil, err
	}
	if len(oc.ColdSignature) != ed25519.SignatureSize || len(oc.ColdVkey) != ed25519.PublicKeySize {
		return nil, errors.New("operational certificate has unexpected sizes")
	}
	return envelope(bursa.KeyFile{
		Type:    pool.TypeOpCert,
		CborHex: hex.EncodeToString(opCertCBOR(oc)),
	})
}

// opCertCBOR encodes [[kes_vkey, counter, period, cold_signature], cold_vkey],
// the shape cardano-cli writes.
func opCertCBOR(oc *bursa.OperationalCertificate) []byte {
	b := []byte{0x82, 0x84}
	b = cborBytes(b, oc.KesVkey)
	b = cborUint(b, oc.IssueNumber)
	b = cborUint(b, oc.KesPeriod)
	b = cborBytes(b, oc.ColdSignature)
	return cborBytes(b, oc.ColdVkey)
}

func cborUint(b []byte, n uint64) []byte { return cborHead(b, 0, n) }

func cborBytes(b []byte, p []byte) []byte { return append(cborHead(b, 2, uint64(len(p))), p...) }

func cborHead(b []byte, major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return append(b, m|byte(n))
	case n < 1<<8:
		return append(b, m|24, byte(n))
	case n < 1<<16:
		return append(b, m|25, byte(n>>8), byte(n))
	case n < 1<<32:
		return append(b, m|26, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	default:
		return append(b, m|27, byte(n>>56), byte(n>>48), byte(n>>40), byte(n>>32),
			byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
}

// Signers is the directory of the signers this build has. Only the vault
// signer exists in process; devices and remote parties are other adapters.
type Signers struct {
	Vault ports.Vault
}

// SignerFor implements ports.SignerDirectory.
func (s Signers) SignerFor(key custody.KeyRef) (ports.Signer, error) {
	switch key.Holder {
	case custody.HolderVault:
		return VaultSigner{Vault: s.Vault}, nil
	case custody.HolderHardware:
		return nil, errors.New("no hardware signer is configured")
	case custody.HolderRemote:
		return nil, errors.New("no remote signer is configured")
	}
	return nil, fmt.Errorf("no signer is configured for holder %q", key.Holder)
}

var (
	_ ports.OpCertIssuer    = VaultSigner{}
	_ ports.SignerDirectory = Signers{}
)
