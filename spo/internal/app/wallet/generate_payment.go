package wallet

import (
	"context"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/app/hwkeys"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals of the key generation use cases.
var (
	// ErrAccountExists means an artefact of the account is already stored
	// (SPO-02-PRE-001, SPO-03a-PRE-001).
	ErrAccountExists = errors.New("artefacts of this account already exist")
	// ErrMnemonicsExist means <name>.payment.mnemonics is already stored
	// (SPO-03a-PRE-002).
	ErrMnemonicsExist = errors.New("a mnemonics file for this wallet already exists")
	// ErrNotConfigured means the use case has no generator for what was asked.
	ErrNotConfigured = errors.New("the use case is not configured for this key source")
)

// GeneratePaymentAccount creates a payment key pair and the enterprise
// address built from it (upstream 02_genPaymentAddrOnly, software keys).
//
// Upstream's key type argument becomes explicit: the signing key is held in
// the store (`cli`); `enc` is not ported at generation (same decision as
// 04c). A hardware holder (`hw`, `hwmulti`) is planned against the device
// profile and exported through Hardware; with no Hardware wired it is refused
// by the generation plan before any effect (ADR 0008).
type GeneratePaymentAccount struct {
	Store     ports.Store
	KeyGen    ports.PaymentKeyGenerator
	Addresses ports.AddressBuilder
	NetworkID uint8 // the workspace's network (ports.NetworkMainnet or NetworkTestnet)
	// Hardware exports the key of a hardware holder; nil keeps the upfront refusal.
	Hardware ports.HardwareKeyExporter
}

// GeneratePaymentRequest names the account. Name takes the forms of
// SPO-Pfiles-IN-001 (`w`, `w.addr`, `./w.addr`).
type GeneratePaymentRequest struct {
	Name   string
	Holder custody.Holder // empty means the vault
	// Account and Index are the hardware account and address index of
	// 1852H|1854H/1815H/<Account>H/0/<Index> (SPO-02-IF-003); Multisig selects
	// 1854H (`hwmulti`). They apply to a hardware holder only.
	Account, Index uint32
	Multisig       bool
}

// PaymentAccountGenerated is the result. It carries no signing key.
type PaymentAccountGenerated struct {
	Name    string
	Address chain.Address
	VKey    []byte
}

// Run generates the keys and the address. All three artefacts are written
// together or not at all.
//
// spec: SPO-02-IF-002, SPO-02-IF-003, SPO-02-EXT-003, SPO-02-OUT-002, SPO-Pfiles-OUT-004
func (uc GeneratePaymentAccount) Run(ctx context.Context, req GeneratePaymentRequest) (PaymentAccountGenerated, error) {
	name, err := normalizeName(req.Name)
	if err != nil {
		return PaymentAccountGenerated{}, err
	}
	if req.Account > MaxDerivationIndex || req.Index > MaxDerivationIndex {
		return PaymentAccountGenerated{}, ErrDerivationRange
	}
	key := custody.KeyRef{Role: custody.RolePayment, Holder: req.Holder, Owner: name}
	onDevice := hwkeys.Hardware(key)
	if !onDevice && (req.Account != 0 || req.Index != 0 || req.Multisig) {
		return PaymentAccountGenerated{}, fmt.Errorf("%w: account, index and multisig are for hardware keys", ErrOptionNotUsed)
	}
	if _, err := hwkeys.Plan(uc.Hardware, key); err != nil {
		return PaymentAccountGenerated{}, err
	}
	check := func(r ports.Reader) error {
		return refuseExisting(r, ErrAccountExists, ports.Ref{Name: name, Kind: ports.AddrVKey}, ports.AddrSKey, ports.AddrHwsFile, ports.AddrFile)
	}
	if err := uc.Store.View(ctx, check); err != nil {
		return PaymentAccountGenerated{}, err
	}
	var pair ports.KeyPair
	var hwsfile []byte
	if onDevice {
		hk, err := hwkeys.Export(ctx, uc.Hardware, key, hwkeys.Options{Account: req.Account, Index: req.Index, Multisig: req.Multisig})
		if err != nil {
			return PaymentAccountGenerated{}, err
		}
		pair.VKey, hwsfile = hk.VKey, hk.SigningFile
	} else {
		if pair, err = uc.KeyGen.GeneratePayment(ctx); err != nil {
			return PaymentAccountGenerated{}, fmt.Errorf("generate payment key: %w", err)
		}
		defer pair.SKey.Destroy()
	}

	hash, err := vkeyHash(pair.VKey)
	if err != nil {
		return PaymentAccountGenerated{}, err
	}
	addr, err := uc.Addresses.BuildAddress(uc.NetworkID, hash, nil)
	if err != nil {
		return PaymentAccountGenerated{}, fmt.Errorf("build address: %w", err)
	}
	err = uc.Store.Update(ctx, func(w ports.Writer) error {
		if err := check(w); err != nil {
			return err
		}
		if err := w.Put(ports.Ref{Name: name, Kind: ports.AddrVKey}, pair.VKey); err != nil {
			return err
		}
		if onDevice {
			// A hardware key leaves no secret: the signing file names the device path.
			if err := w.Put(ports.Ref{Name: name, Kind: ports.AddrHwsFile}, hwsfile); err != nil {
				return err
			}
		} else if err := w.PutSecret(ports.Ref{Name: name, Kind: ports.AddrSKey}, pair.SKey); err != nil {
			return err
		}
		// Decision (spec correction): cardano-cli 11.2.3.0's `address build`
		// writes the address with no trailing newline, so the file has none
		// (SPO-Pfiles-OUT-001 said it had one).
		return w.Put(ports.Ref{Name: name, Kind: ports.AddrFile}, []byte(addr))
	})
	if err != nil {
		return PaymentAccountGenerated{}, err
	}
	return PaymentAccountGenerated{Name: name, Address: addr, VKey: pair.VKey}, nil
}

// refuseExisting returns sentinel (wrapped with the reference) when the
// first reference or any of the further kinds of the same name exists.
func refuseExisting(r ports.Reader, sentinel error, first ports.Ref, more ...ports.Kind) error {
	refs := []ports.Ref{first}
	for _, k := range more {
		refs = append(refs, ports.Ref{Name: first.Name, Kind: k})
	}
	return refuseRefs(r, sentinel, refs...)
}

func refuseRefs(r ports.Reader, sentinel error, refs ...ports.Ref) error {
	for _, ref := range refs {
		exists, err := r.Exists(ref)
		if err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("%w: %s", sentinel, ref)
		}
	}
	return nil
}

// vkeyHash is the credential of a verification key envelope.
func vkeyHash(vkeyEnvelope []byte) (txbuild.KeyHash, error) {
	env, err := pool.ParseEnvelope(vkeyEnvelope)
	if err != nil {
		return txbuild.KeyHash{}, err
	}
	raw, err := env.Key32()
	if err != nil {
		return txbuild.KeyHash{}, err
	}
	return txbuild.HashKey(raw), nil
}
