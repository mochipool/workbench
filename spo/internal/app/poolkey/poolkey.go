// Package poolkey holds the use cases of the Calidus pool key (CIP-151,
// upstream 15_calidusPoolKey): generate the key, build and sign its CIP-88
// version 2 registration with the pool cold key, and query the registered
// keys.
//
// The registration is not submitted here. Like upstream, the use case writes
// the metadata and the operator attaches it to an ordinary send transaction
// (`01_sendLovelaces <wallet> <wallet> min <file>.json`, SPO-15-OUT-004), which
// the existing send use case does with the file reference of its extras.
//
// A hardware or remote holder is refused up front by the signing plan (ADR
// 0008), and the hardware ids of the spec are waived until the hardware signer
// adapter exists. A failure is an error: where upstream exits 0 after a failed
// signature or write, the use case returns an error.
package poolkey

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals.
var (
	ErrExists          = errors.New("artefacts of this name already exist")
	ErrMissingFile     = errors.New("a file the workflow needs does not exist")
	ErrNotConfigured   = errors.New("the use case is not configured")
	ErrDerivationRange = errors.New("account and index numbers must be 0 to 2147483647")
	ErrBadName         = errors.New("the name must be a plain name without a directory part")
	ErrNoColdSigner    = errors.New("the pool has no cold signing key (.node.skey) or hardware signing file (.node.hwsfile)")
	ErrNoPoolID        = errors.New("the pool id is unknown: the pool has none of <pool>.pool.id-bech, <pool>.pool.id, <pool>.node.vkey")
	ErrNoSigner        = errors.New("the signer for the pool cold key cannot sign a Calidus registration")
	ErrBadSubject      = errors.New("the subject is not a Calidus id, public key, pool id or stored name, nor the word all")
	ErrNoReader        = errors.New("no chain provider is available to read Calidus keys (offline mode has none)")
)

// MaxDerivationIndex is the largest account or index number.
const MaxDerivationIndex = 1<<31 - 1

func trimDir(s string) string { return strings.TrimPrefix(s, "./") }

func plainName(s string) (string, error) {
	s = trimDir(s)
	if err := (ports.Ref{Name: s, Kind: ports.CalidusVKey}).Validate(); err != nil {
		return "", fmt.Errorf("%w: %q", ErrBadName, s)
	}
	return s, nil
}

// ---- new ---------------------------------------------------------------------------

// GenerateCalidusKey creates a Calidus key pair from a mnemonic (upstream 15
// `new cli`): `<name>.calidus.vkey`, `.skey`, `.mnemonics` and `.id`, written
// together or not at all. The mnemonic is stored as a secret and never
// returned. There is no random-seed path: cardano-signer always derives, from a
// given or a fresh phrase.
type GenerateCalidusKey struct {
	Store     ports.Store
	Deriver   ports.CalidusKeyDeriver
	Mnemonics ports.MnemonicGenerator // when no phrase is given
}

// GenerateCalidusKeyRequest names the key.
type GenerateCalidusKeyRequest struct {
	// Name has a leading `./` dropped (SPO-15-IF-002).
	Name   string
	Holder custody.Holder // empty means the vault
	// Account and Index select 1852H/1815H/<Account>H/0/<Index>; the upstream
	// script has no such option and uses 0 and 0.
	Account, Index uint32
	// Mnemonic is the phrase to derive from; nil generates a fresh one. The
	// buffer stays the caller's.
	Mnemonic *ports.Secret
}

// CalidusKeyGenerated is the result. It carries no signing key and no mnemonic.
type CalidusKeyGenerated struct {
	Name           string
	VKey           []byte
	PublicKey      [32]byte
	ID             string // bech32 Calidus id
	MnemonicStored bool
}

// Run creates the key.
func (uc GenerateCalidusKey) Run(ctx context.Context, req GenerateCalidusKeyRequest) (res CalidusKeyGenerated, err error) {
	if uc.Store == nil || uc.Deriver == nil || (req.Mnemonic == nil && uc.Mnemonics == nil) {
		return res, ErrNotConfigured
	}
	nm, err := plainName(req.Name)
	if err != nil {
		return res, err
	}
	if req.Account > MaxDerivationIndex || req.Index > MaxDerivationIndex {
		return res, ErrDerivationRange
	}
	// A hardware or remote holder is refused before anything else
	// (SPO-15-PRE-002: upstream suspends the hardware path).
	if req.Holder == custody.HolderHardware {
		return res, ErrHardwareCalidusSuspended
	}
	if _, err := custody.PlanGeneration(custody.KeyRef{Role: custody.RoleCalidus, Holder: req.Holder, Owner: nm}); err != nil {
		return res, err
	}
	refs := []ports.Ref{
		{Name: nm, Kind: ports.CalidusVKey}, {Name: nm, Kind: ports.CalidusSKey}, {Name: nm, Kind: ports.CalidusHwsFile},
		{Name: nm, Kind: ports.CalidusMnemonics}, {Name: nm, Kind: ports.CalidusID},
	}
	if err := uc.Store.View(ctx, func(r ports.Reader) error { return refuseExisting(r, refs...) }); err != nil {
		return res, err
	}
	var words *ports.Secret
	defer func() { words.Destroy() }()
	if req.Mnemonic == nil {
		words, err = uc.Mnemonics.GenerateMnemonic(ctx)
	} else {
		words, err = ports.NormalizeMnemonic(req.Mnemonic)
	}
	if err != nil {
		return res, err
	}
	pair, err := uc.Deriver.DeriveCalidus(ctx, words, req.Account, req.Index)
	if err != nil {
		return res, fmt.Errorf("derive the Calidus key: %w", err)
	}
	defer pair.SKey.Destroy()
	pub, err := cose.VKeyFromEnvelope(pair.VKey)
	if err != nil {
		return res, err
	}
	id, err := cose.CalidusID(pub[:])
	if err != nil {
		return res, err
	}
	file, err := ports.MnemonicFile(words)
	if err != nil {
		return res, err
	}
	defer file.Destroy()
	err = uc.Store.Update(ctx, func(w ports.Writer) error {
		if err := refuseExisting(w, refs...); err != nil {
			return err
		}
		if err := w.PutSecret(refs[3], file); err != nil {
			return err
		}
		if err := w.Put(refs[0], pair.VKey); err != nil {
			return err
		}
		if err := w.PutSecret(refs[1], pair.SKey); err != nil {
			return err
		}
		return w.Put(refs[4], []byte(id+"\n"))
	})
	if err != nil {
		return res, err
	}
	return CalidusKeyGenerated{Name: nm, VKey: pair.VKey, PublicKey: pub, ID: id, MnemonicStored: true}, nil
}

func refuseExisting(r ports.Reader, refs ...ports.Ref) error {
	for _, ref := range refs {
		ok, err := r.Exists(ref)
		if err != nil {
			return err
		}
		if ok {
			return fmt.Errorf("%w: %s", ErrExists, ref)
		}
	}
	return nil
}

// ---- genmeta -----------------------------------------------------------------------

// GenerateCalidusRegistration builds and signs the CIP-88 version 2
// registration of a Calidus key with the pool cold key (upstream 15
// `genmeta`) and writes `<pool>_<yymmddHHMMSS>.calidus-registration.json`.
// The pool cold key is demanded through a signing plan before anything is
// built: a hardware or remote cold key is refused up front.
type GenerateCalidusRegistration struct {
	Store   ports.Store
	Signers ports.SignerDirectory
	// Clock names the file and, when no nonce is given and Tip is nil, gives
	// the nonce.
	Clock ports.Clock
	// Tip, when set, gives the nonce its default: the current slot of the
	// active work mode (SPO-15-MODE-001). When nil the default is the mainnet
	// slot of the clock, which is what cardano-signer chooses.
	Tip ports.TipReader
	// BeforeDevice, when set, is called before a hardware cold key is asked to
	// sign (SPO-15-PR-001): it shows what the device will display and asks the
	// operator to continue. An error stops the registration before the device is
	// contacted; nothing is written.
	BeforeDevice func(ctx context.Context, d DeviceSigning) error
}

// DeviceSigning is what a device is about to be asked to sign, as the operator
// should see it before the device asks.
type DeviceSigning struct {
	PoolBech  string
	CalidusID string
	Nonce     uint64
	// DeviceHash is the blake2b-224 of the message, the hash a Ledger displays
	// for a `message sign` request (SPO-15-INV-006), in hex.
	DeviceHash string
}

// CalidusRegistrationRequest names the key and the pool.
type CalidusRegistrationRequest struct {
	// Calidus loses `.vkey` and then `.calidus` and a leading `./`; Pool
	// loses `.skey` or `.hwsfile`, then `.node`, and a leading `./`
	// (SPO-15-IF-003).
	Calidus, Pool string
	// Holder of the cold key; empty infers it as upstream does: a
	// `.node.hwsfile` wins over a `.node.skey` (SPO-15-INV-002).
	Holder custody.Holder
	// Nonce is the registration nonce; 0 chooses the default. Upstream
	// accepts a given nonce only above zero (SPO-15-IF-004).
	Nonce uint64
}

// CalidusRegistrationGenerated is the result. All of it is public.
type CalidusRegistrationGenerated struct {
	Ref        ports.Ref // the registration file
	PoolID     chain.PoolID
	PoolBech   string
	CalidusPub [32]byte
	CalidusID  string
	Nonce      uint64
	// JSON is the stored file's content; CBOR is the same metadata as a
	// binary `.cbor` metadata file, for the send transaction (not stored).
	JSON []byte
	CBOR []byte
}

func calidusName(s string) (string, error) {
	return plainName(strings.TrimSuffix(strings.TrimSuffix(trimDir(s), ".vkey"), ".calidus"))
}

func poolName(s string) (string, error) {
	s = trimDir(s)
	s = strings.TrimSuffix(strings.TrimSuffix(s, ".skey"), ".hwsfile")
	return plainName(strings.TrimSuffix(s, ".node"))
}

// Run builds, signs and stores the registration.
func (uc GenerateCalidusRegistration) Run(ctx context.Context, req CalidusRegistrationRequest) (res CalidusRegistrationGenerated, err error) {
	if uc.Store == nil || uc.Signers == nil || uc.Clock == nil {
		return res, ErrNotConfigured
	}
	cal, err := calidusName(req.Calidus)
	if err != nil {
		return res, err
	}
	pl, err := poolName(req.Pool)
	if err != nil {
		return res, err
	}
	var calVKey, nodeVKey, idBech, idHex []byte
	var haveSKey, haveHws bool
	err = uc.Store.View(ctx, func(r ports.Reader) error {
		var err error
		if calVKey, err = r.Get(ports.Ref{Name: cal, Kind: ports.CalidusVKey}); err != nil {
			if errors.Is(err, ports.ErrNotFound) {
				return fmt.Errorf("%w: %s", ErrMissingFile, ports.Ref{Name: cal, Kind: ports.CalidusVKey})
			}
			return err
		}
		if haveSKey, err = r.Exists(ports.Ref{Name: pl, Kind: ports.NodeSKey}); err != nil {
			return err
		}
		if haveHws, err = r.Exists(ports.Ref{Name: pl, Kind: ports.NodeHwsFile}); err != nil {
			return err
		}
		optional := func(k ports.Kind) []byte {
			b, err := r.Get(ports.Ref{Name: pl, Kind: k})
			if err != nil {
				return nil
			}
			return b
		}
		idBech, idHex, nodeVKey = optional(ports.PoolIDBechFile), optional(ports.PoolIDFile), optional(ports.NodeVKey)
		return nil
	})
	if err != nil {
		return res, err
	}
	if !haveSKey && !haveHws {
		return res, ErrNoColdSigner
	}
	holder := req.Holder
	if holder == "" {
		holder = custody.HolderVault
		if haveHws {
			holder = custody.HolderHardware // upstream's order: the hardware flow wins (SPO-15-INV-002)
		}
	}
	calPub, err := cose.VKeyFromEnvelope(calVKey)
	if err != nil {
		return res, fmt.Errorf("the Calidus verification key: %w", err)
	}
	pid, err := poolIDOf(idBech, idHex, nodeVKey)
	if err != nil {
		return res, err
	}

	// The signing plan: the cold key must be able to sign a Calidus registration.
	cold := custody.KeyRef{Role: custody.RolePoolCold, Holder: holder, Owner: pl}
	if _, err := ports.PlanSignatures(uc.Signers, []custody.Slot{{
		Label: "sign the Calidus registration", Key: cold,
		Demand: custody.Demand{Role: custody.RolePoolCold, Operation: custody.OpSignCip88},
	}}); err != nil {
		return res, err
	}
	sg, err := uc.Signers.SignerFor(cold)
	if err != nil {
		return res, err
	}
	signer, ok := sg.(ports.Cip88Signer)
	if !ok {
		return res, ErrNoSigner
	}
	key, err := custody.As[custody.PoolCold](cold)
	if err != nil {
		return res, err
	}

	now := uc.Clock.Now()
	nonce := req.Nonce
	if nonce == 0 {
		if uc.Tip != nil {
			tip, err := uc.Tip.Tip(ctx)
			if err != nil {
				return res, fmt.Errorf("current slot for the nonce: %w", err)
			}
			nonce = tip.Slot
		} else {
			nonce = cose.MainnetSlotAt(now)
		}
	}
	reg := cose.Cip88{PoolID: pid, CalidusPub: calPub, Nonce: nonce}
	if holder == custody.HolderHardware && uc.BeforeDevice != nil {
		ph := reg.PayloadHash()
		dh := cose.Blake2b224(ph[:])
		pb, err := chain.Bech32Encode("pool", pid[:])
		if err != nil {
			return res, err
		}
		cid, err := cose.CalidusID(calPub[:])
		if err != nil {
			return res, err
		}
		if err := uc.BeforeDevice(ctx, DeviceSigning{PoolBech: pb, CalidusID: cid, Nonce: nonce, DeviceHash: hexString(dh[:])}); err != nil {
			return res, err
		}
	}
	signed, err := signer.SignCip88(ctx, key, reg)
	if err != nil {
		return res, fmt.Errorf("sign the registration: %w", err)
	}
	// The signer's answer is checked before it is stored: a signer that
	// returns something that does not verify is a failure, not a file.
	if _, err := cose.VerifyCip88(signed.CBOR); err != nil {
		return res, fmt.Errorf("the signer's registration does not verify: %w", err)
	}
	file, err := cose.RegistrationFile(signed.JSON)
	if err != nil {
		return res, err
	}
	id, err := cose.CalidusID(calPub[:])
	if err != nil {
		return res, err
	}
	ref := ports.Ref{Name: pl + "_" + now.Format("060102150405"), Kind: ports.CalidusRegistration}
	if err := uc.Store.Update(ctx, func(w ports.Writer) error {
		if err := refuseExisting(w, ref); err != nil { // SPO-15-PRE-005
			return err
		}
		return w.Put(ref, file)
	}); err != nil {
		return res, err
	}
	pb, err := chain.Bech32Encode("pool", pid[:])
	if err != nil {
		return res, err
	}
	return CalidusRegistrationGenerated{Ref: ref, PoolID: chain.PoolID(pid), PoolBech: pb, CalidusPub: calPub,
		CalidusID: id, Nonce: nonce, JSON: file, CBOR: signed.CBOR}, nil
}

// poolIDOf resolves the pool id, first match wins (SPO-15-INV-003): the
// bech32 id file, the hex id file, the cold verification key.
func poolIDOf(idBech, idHex, nodeVKey []byte) ([28]byte, error) {
	var out [28]byte
	if s := strings.TrimSpace(string(idBech)); len(s) == 56 && strings.HasPrefix(s, "pool1") {
		if p, err := chain.ParsePoolBech32(s); err == nil {
			return p, nil
		}
	}
	if s := strings.TrimSpace(string(idHex)); len(s) == 56 {
		if b, err := hexDecode(s); err == nil {
			copy(out[:], b)
			return out, nil
		}
	}
	if len(nodeVKey) > 0 {
		pub, err := cose.VKeyFromEnvelope(nodeVKey)
		if err != nil {
			return out, fmt.Errorf("the pool's cold verification key: %w", err)
		}
		return cose.Blake2b224(pub[:]), nil
	}
	return out, ErrNoPoolID
}
