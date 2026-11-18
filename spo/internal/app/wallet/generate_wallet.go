package wallet

import (
	"context"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/app/hwkeys"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// WalletKeySource says where a wallet's keys come from. It replaces the key
// type word of upstream's 03a for the software paths: `cli` is
// WalletKeysRandom, `mnemonics` is WalletKeysMnemonic. `enc` is not ported at
// generation (same decision as 04c); the hardware and hybrid types are Holder
// and StakeHolder, planned against the device profile (hwkeys.Plan).
type WalletKeySource string

// Key sources.
const (
	WalletKeysRandom   WalletKeySource = "random"
	WalletKeysMnemonic WalletKeySource = "mnemonic"
)

// MaxDerivationIndex is the largest account or index number upstream accepts
// (SPO-03a-IF-004; 2^31-1, the hardened range's limit).
const MaxDerivationIndex = 1<<31 - 1

// ErrDerivationRange means an account or index number is out of range.
var ErrDerivationRange = errors.New("account and index numbers must be 0 to 2147483647")

// ErrOptionNotUsed means an option does not apply to the key source: upstream
// silently ignores them, this port refuses.
var ErrOptionNotUsed = errors.New("option does not apply to this key source")

// GenerateWalletAccount creates one wallet account: payment and stake key
// pairs, the base address and the stake address (upstream 03a, software key
// types). The mnemonic of a derived wallet is stored as a secret and never
// returned.
type GenerateWalletAccount struct {
	Store     ports.NamedStore
	Payment   ports.PaymentKeyGenerator // WalletKeysRandom
	Stake     ports.StakeKeyGenerator   // WalletKeysRandom
	Mnemonics ports.MnemonicGenerator   // WalletKeysMnemonic without given words
	Deriver   ports.WalletDeriver       // WalletKeysMnemonic
	Addresses ports.AddressBuilder
	NetworkID uint8
	// Hardware exports the keys of a hardware holder (`hw`, `hwmulti`,
	// `hybrid`, `hybridmulti`); nil keeps the upfront refusal.
	Hardware ports.HardwareKeyExporter
}

// GenerateWalletRequest is the wallet to create.
type GenerateWalletRequest struct {
	// Name is the wallet name: a trailing `.addr` and a leading `./` are
	// dropped, nothing else (SPO-03a-IF-003).
	Name  string
	Place custody.Placement // empty means the vault
	// StakePlace is where the stake key is made; empty means Place. Hardware
	// payment key with StakePlace vault is the `hybrid` type of 03a; the
	// stake key is then a software key. A software payment key with a
	// hardware stake key is not a type of 03a and is refused.
	StakePlace custody.Placement
	// Multisig selects the 1854H root of `hwmulti` and `hybridmulti` for the
	// hardware payment key (SPO-03a-INV-001).
	Multisig bool
	Source   WalletKeySource
	// Account and Index select the CIP-1852 path of a mnemonic wallet or the
	// hardware payment path <root>H/1815H/<Account>H/0/<Index> (the hardware
	// stake path is <root>H/1815H/<Account>H/2/0, SPO-03a-INV-001):
	// payment 1852H/1815H/<Account>H/0/<Index>, stake
	// 1852H/1815H/<Account>H/2/<Index>. They must be 0 for random keys.
	Account, Index uint32
	// Mnemonic is the phrase to derive from; nil generates a fresh one. The
	// buffer stays the caller's. Mnemonic source only.
	Mnemonic *ports.Secret
}

// WalletGenerated is the result. It carries no signing key and no mnemonic:
// the mnemonic is shown only by the audited export use case.
type WalletGenerated struct {
	Name           string
	PaymentAddress chain.Address
	StakeAddress   chain.StakeAddress
	PaymentVKey    []byte
	StakeVKey      []byte
	MnemonicStored bool
}

// Run creates the wallet. All artefacts are written together or not at all.
func (uc GenerateWalletAccount) Run(ctx context.Context, req GenerateWalletRequest) (res WalletGenerated, err error) {
	// spec: SPO-03a-IF-003
	name, err := normalizeName(req.Name)
	if err != nil {
		return res, err
	}
	if req.Account > MaxDerivationIndex || req.Index > MaxDerivationIndex {
		return res, ErrDerivationRange
	}
	payPlace, stakePlace := req.Place, req.StakePlace
	if stakePlace == "" {
		stakePlace = payPlace
	}
	payHW, stakeHW := payPlace == custody.PlaceHardware, stakePlace == custody.PlaceHardware
	if stakeHW && !payHW {
		return res, fmt.Errorf("%w: a hardware stake key with a software payment key is not a wallet type of 03a", ErrOptionNotUsed)
	}
	if !payHW && req.Multisig {
		return res, fmt.Errorf("%w: multisig is for a hardware payment key", ErrOptionNotUsed)
	}
	switch {
	case payHW:
		// spec: SPO-03a-IF-001 (hw, hwmulti, hybrid, hybridmulti)
		if req.Source != WalletKeysRandom && req.Source != "" || req.Mnemonic != nil {
			return res, fmt.Errorf("%w: a hardware wallet has no mnemonic or derived source", ErrOptionNotUsed)
		}
		req.Source = WalletKeysRandom
		if !stakeHW && uc.Stake == nil {
			return res, ErrNotConfigured
		}
	case req.Source == WalletKeysRandom:
		if req.Account != 0 || req.Index != 0 || req.Mnemonic != nil {
			return res, fmt.Errorf("%w: account, index and mnemonic are for derived wallets", ErrOptionNotUsed)
		}
		if uc.Payment == nil || uc.Stake == nil {
			return res, ErrNotConfigured
		}
	case req.Source == WalletKeysMnemonic:
		if uc.Deriver == nil || (req.Mnemonic == nil && uc.Mnemonics == nil) {
			return res, ErrNotConfigured
		}
	default:
		return res, fmt.Errorf("unknown key source %q", req.Source)
	}

	if _, err := hwkeys.Plan(uc.Hardware, payPlace, custody.RolePayment); err != nil {
		return res, err
	}
	if _, err := hwkeys.Plan(uc.Hardware, stakePlace, custody.RoleStake); err != nil {
		return res, err
	}

	payName := name + ".payment"
	check := func(r ports.NamedReader) error {
		if err := refuseRefs(r, ErrAccountExists,
			ports.NamedRef{Name: payName, Kind: ports.AddrVKey}, ports.NamedRef{Name: payName, Kind: ports.AddrSKey},
			ports.NamedRef{Name: payName, Kind: ports.AddrHwsFile}, ports.NamedRef{Name: payName, Kind: ports.AddrFile},
			ports.NamedRef{Name: name, Kind: ports.StakingVKey}, ports.NamedRef{Name: name, Kind: ports.StakingSKey},
			ports.NamedRef{Name: name, Kind: ports.StakingHwsFile}, ports.NamedRef{Name: name, Kind: ports.StakingAddr},
			ports.NamedRef{Name: name, Kind: ports.StakingCert}); err != nil {
			return err
		}
		if req.Source == WalletKeysMnemonic {
			return refuseRefs(r, ErrMnemonicsExist, ports.NamedRef{Name: name, Kind: ports.PaymentMnemonics})
		}
		return nil
	}
	if err := uc.Store.View(ctx, check); err != nil {
		return res, err
	}

	var pay, stake ports.KeyPair
	var words *ports.Secret // the normalised phrase, mnemonic source only
	defer func() {
		pay.SKey.Destroy()
		stake.SKey.Destroy()
		words.Destroy()
	}()
	var payHws, stakeHws []byte
	switch {
	case payHW:
		hk, err := hwkeys.Export(ctx, uc.Hardware, custody.RolePayment, hwkeys.Options{Account: req.Account, Index: req.Index, Multisig: req.Multisig})
		if err != nil {
			return res, err
		}
		pay.VKey, payHws = hk.VKey, hk.SigningFile
		if stakeHW {
			sk, err := hwkeys.Export(ctx, uc.Hardware, custody.RoleStake, hwkeys.Options{Account: req.Account, Multisig: req.Multisig})
			if err != nil {
				return res, err
			}
			stake.VKey, stakeHws = sk.VKey, sk.SigningFile
		} else if stake, err = uc.Stake.GenerateStake(ctx); err != nil {
			return res, fmt.Errorf("generate stake key: %w", err)
		}
	case req.Source == WalletKeysRandom:
		if pay, err = uc.Payment.GeneratePayment(ctx); err != nil {
			return res, fmt.Errorf("generate payment key: %w", err)
		}
		if stake, err = uc.Stake.GenerateStake(ctx); err != nil {
			return res, fmt.Errorf("generate stake key: %w", err)
		}
	case req.Source == WalletKeysMnemonic:
		if words, err = uc.phrase(ctx, req.Mnemonic); err != nil {
			return res, err
		}
		keys, err := uc.Deriver.DeriveWallet(ctx, words, req.Account, req.Index)
		if err != nil {
			return res, fmt.Errorf("derive wallet: %w", err)
		}
		pay, stake = keys.Payment, keys.Stake
	}

	payHash, err := vkeyHash(pay.VKey)
	if err != nil {
		return res, err
	}
	stakeHash, err := vkeyHash(stake.VKey)
	if err != nil {
		return res, err
	}
	base, err := uc.Addresses.BuildAddress(uc.NetworkID, payHash, &stakeHash)
	if err != nil {
		return res, fmt.Errorf("build base address: %w", err)
	}
	reward, err := uc.Addresses.BuildStakeAddress(uc.NetworkID, stakeHash)
	if err != nil {
		return res, fmt.Errorf("build stake address: %w", err)
	}

	var file *ports.Secret // the phrase and a newline, as upstream's echo writes it
	if words != nil {
		if file, err = ports.MnemonicFile(words); err != nil {
			return res, err
		}
		defer file.Destroy()
	}

	err = uc.Store.Update(ctx, func(w ports.NamedWriter) error {
		if err := check(w); err != nil {
			return err
		}
		if file != nil {
			if err := w.PutSecret(ports.NamedRef{Name: name, Kind: ports.PaymentMnemonics}, file); err != nil {
				return err
			}
		}
		if err := w.Put(ports.NamedRef{Name: payName, Kind: ports.AddrVKey}, pay.VKey); err != nil {
			return err
		}
		if payHW {
			// spec: SPO-03a-EXT-002, SPO-03a-OUT-001, SPO-Pfiles-OUT-004
			if err := w.Put(ports.NamedRef{Name: payName, Kind: ports.AddrHwsFile}, payHws); err != nil {
				return err
			}
		} else if err := w.PutSecret(ports.NamedRef{Name: payName, Kind: ports.AddrSKey}, pay.SKey); err != nil {
			return err
		}
		if err := w.Put(ports.NamedRef{Name: name, Kind: ports.StakingVKey}, stake.VKey); err != nil {
			return err
		}
		if stakeHW {
			if err := w.Put(ports.NamedRef{Name: name, Kind: ports.StakingHwsFile}, stakeHws); err != nil {
				return err
			}
		} else if err := w.PutSecret(ports.NamedRef{Name: name, Kind: ports.StakingSKey}, stake.SKey); err != nil {
			return err
		}
		// The base address file has no trailing newline, the stake address
		// file has one: that is what cardano-cli 11.2.3.0's `address build`
		// and `stake-address build` write (SPO-Pfiles-OUT-001 correction).
		if err := w.Put(ports.NamedRef{Name: payName, Kind: ports.AddrFile}, []byte(base)); err != nil {
			return err
		}
		return w.Put(ports.NamedRef{Name: name, Kind: ports.StakingAddr}, []byte(reward+"\n"))
	})
	if err != nil {
		return res, err
	}
	return WalletGenerated{Name: name, PaymentAddress: base, StakeAddress: reward,
		PaymentVKey: pay.VKey, StakeVKey: stake.VKey, MnemonicStored: file != nil}, nil
}

// phrase returns the normalised phrase: the given one, or a fresh one.
// Normalising lowercases and squeezes spaces as upstream does, then requires
// 24 words (SPO-03a-IF-004).
func (uc GenerateWalletAccount) phrase(ctx context.Context, given *ports.Secret) (*ports.Secret, error) {
	if given == nil {
		return uc.Mnemonics.GenerateMnemonic(ctx)
	}
	return ports.NormalizeMnemonic(given)
}
