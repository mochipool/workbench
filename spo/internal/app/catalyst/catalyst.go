// Package catalyst holds the use cases of Project Catalyst voting keys and
// CIP-36 registration (upstream 09a_catalystVote): generate a voting key from
// a mnemonic, and build and sign the registration metadata that delegates a
// stake key's voting power to voting keys.
//
// The registration is not a transaction: the operator attaches the `.cbor`
// file to an ordinary send (`01_sendLovelaces <wallet> <wallet> min <file>.cbor`,
// SPO-09a-OUT-006). The QR code of the mobile app and the Catalyst API query
// are not ported (see the waivers of the spec in spo/spec-coverage.toml).
//
// A hardware or remote holder is refused up front by the signing plan (ADR
// 0008) and the hardware ids are waived until the hardware signer adapter
// exists. Where upstream exits 0 after a failed signature, the use case
// returns an error.
package catalyst

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/mochipool/workbench/spo/internal/app/hwkeys"
	"github.com/mochipool/workbench/spo/internal/app/keyring"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals.
var (
	ErrExists          = errors.New("artefacts of this name already exist")
	ErrMissingFile     = errors.New("a file the workflow needs does not exist")
	ErrNotConfigured   = errors.New("the use case is not configured")
	ErrDerivationRange = errors.New("account and index numbers must be 0 to 2147483647")
	ErrBadName         = errors.New("the name must be a plain name without a directory part")
	ErrNoStakeSigner   = errors.New("the stake account has no signing key (.staking.skey) or hardware signing file (.staking.hwsfile)")
	ErrNoSigner        = errors.New("the signer for the stake key cannot sign a Catalyst registration")
	ErrBadDelegation   = errors.New("invalid delegation")
	ErrBadVotingKey    = errors.New("the voting key reference names no voting key")
	ErrBadRewards      = errors.New("the rewards address is not a payment address of this network")
	ErrAdaHandle       = errors.New("ADA Handle rewards addresses are not supported yet; give the address or the name of a stored address")
	ErrNoNonce         = errors.New("no nonce: give one or wire a current-slot reader")
)

// MaxDerivationIndex is the largest account or index number.
const MaxDerivationIndex = 1<<31 - 1

func trimDir(s string) string { return strings.TrimPrefix(s, "./") }

func plainName(s string) (string, error) {
	s = trimDir(s)
	if err := (ports.NamedRef{Name: s, Kind: ports.VotingVKey}).Validate(); err != nil {
		return "", fmt.Errorf("%w: %q", ErrBadName, s)
	}
	return s, nil
}

func refuseExisting(r ports.NamedReader, refs ...ports.NamedRef) error {
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

// ---- new ---------------------------------------------------------------------------

// GenerateVotingKey creates a voting key pair from a mnemonic (upstream 09a
// `new cli`): `<name>.voting.vkey`, `.skey`, `.pkey` (the bech32 `cvote_vk`
// public key) and `.mnemonics`, written together or not at all. The mnemonic is
// stored as a secret and never returned. The key is never encrypted
// (SPO-09a-INV-001) here: the store seals it.
type GenerateVotingKey struct {
	Store     ports.NamedStore
	Deriver   ports.VotingKeyDeriver
	Mnemonics ports.MnemonicGenerator // when no phrase is given
	// Hardware makes the key on a device (upstream 09a `new hw`,
	// SPO-09a-EXT-002): nil refuses a hardware holder up front. Only the
	// verification key and the hardware signing file are stored
	// (SPO-09a-OUT-004, SPO-09a-OUT-009): no .pkey, no mnemonic.
	Hardware ports.HardwareKeyExporter
}

// GenerateVotingKeyRequest names the key.
type GenerateVotingKeyRequest struct {
	Name  string
	Place custody.Placement // empty means the vault
	// Account and Index select 1694H/1815H/<Account>H/0/<Index>; upstream
	// fixes both at 0 (its port note asks for parameters).
	Account, Index uint32
	// Mnemonic is the phrase to derive from; nil generates a fresh one. The
	// buffer stays the caller's.
	Mnemonic *ports.Secret
}

// VotingKeyGenerated is the result. It carries no signing key and no mnemonic.
type VotingKeyGenerated struct {
	Name      string
	VKey      []byte
	PublicKey [32]byte
	PKey      string // bech32 cvote_vk
}

// Run creates the key.
func (uc GenerateVotingKey) Run(ctx context.Context, req GenerateVotingKeyRequest) (res VotingKeyGenerated, err error) {
	nm, err := plainName(req.Name)
	if err != nil {
		return res, err
	}
	onDevice := req.Place == custody.PlaceHardware
	if uc.Store == nil || (!onDevice && (uc.Deriver == nil || (req.Mnemonic == nil && uc.Mnemonics == nil))) {
		return res, ErrNotConfigured
	}
	if req.Account > MaxDerivationIndex || req.Index > MaxDerivationIndex {
		return res, ErrDerivationRange
	}
	// A device that cannot hold the key (a Trezor, a Keystone), a missing
	// hardware signer and every other holder are refused before any tool or
	// file is touched (ADR 0008).
	if _, err := hwkeys.Plan(uc.Hardware, req.Place, custody.RoleCatalystVote); err != nil {
		return res, err
	}
	refs := []ports.NamedRef{
		{Name: nm, Kind: ports.VotingVKey}, {Name: nm, Kind: ports.VotingSKey}, {Name: nm, Kind: ports.VotingHwsFile},
		{Name: nm, Kind: ports.VotingPKey}, {Name: nm, Kind: ports.VotingMnemonics},
	}
	if err := uc.Store.View(ctx, func(r ports.NamedReader) error { return refuseExisting(r, refs...) }); err != nil {
		return res, err
	}
	if onDevice {
		return uc.runOnDevice(ctx, nm, req, refs)
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
	pair, pkey, err := uc.Deriver.DeriveVoting(ctx, words, req.Account, req.Index)
	if err != nil {
		return res, fmt.Errorf("derive the voting key: %w", err)
	}
	defer pair.SKey.Destroy()
	pub, err := cose.VKeyFromEnvelope(pair.VKey)
	if err != nil {
		return res, err
	}
	file, err := ports.MnemonicFile(words)
	if err != nil {
		return res, err
	}
	defer file.Destroy()
	err = uc.Store.Update(ctx, func(w ports.NamedWriter) error {
		if err := refuseExisting(w, refs...); err != nil {
			return err
		}
		if err := w.PutSecret(refs[4], file); err != nil {
			return err
		}
		if err := w.Put(refs[0], pair.VKey); err != nil {
			return err
		}
		if err := w.PutSecret(refs[1], pair.SKey); err != nil {
			return err
		}
		return w.Put(refs[3], []byte(pkey+"\n"))
	})
	if err != nil {
		return res, err
	}
	return VotingKeyGenerated{Name: nm, VKey: pair.VKey, PublicKey: pub, PKey: pkey}, nil
}

// runOnDevice is `new hw`: the key is made on the device at
// 1694H/1815H/<account>H/0/<index>, and the verification key and the hardware
// signing file are stored (SPO-09a-EXT-002, SPO-09a-OUT-004). Nothing of the
// device's reaches the workspace but those two files.
func (uc GenerateVotingKey) runOnDevice(ctx context.Context, nm string, req GenerateVotingKeyRequest, refs []ports.NamedRef) (res VotingKeyGenerated, err error) {
	if req.Mnemonic != nil {
		return res, errors.New("a hardware voting key has no mnemonic: it is made on the device")
	}
	hk, err := hwkeys.Export(ctx, uc.Hardware, custody.RoleCatalystVote, hwkeys.Options{Account: req.Account, Index: req.Index})
	if err != nil {
		return res, err
	}
	pub, err := cose.VKeyFromEnvelope(hk.VKey)
	if err != nil {
		return res, fmt.Errorf("the device's verification key: %w", err)
	}
	pkey, err := chain.Bech32Encode("cvote_vk", pub[:])
	if err != nil {
		return res, err
	}
	err = uc.Store.Update(ctx, func(w ports.NamedWriter) error {
		if err := refuseExisting(w, refs...); err != nil {
			return err
		}
		if err := w.Put(refs[0], hk.VKey); err != nil {
			return err
		}
		return w.Put(refs[2], hk.SigningFile)
	})
	if err != nil {
		return res, err
	}
	return VotingKeyGenerated{Name: nm, VKey: hk.VKey, PublicKey: pub, PKey: pkey}, nil
}

// ---- genmeta -----------------------------------------------------------------------

// DelegationWord is one voting key reference with its weight, before the key is
// resolved.
type DelegationWord struct {
	Ref    string
	Weight uint64
}

// ParseDelegation splits the delegation argument of `genmeta`
// (SPO-09a-IF-003): one voting key or several joined with `|`, each optionally
// followed by a space and a weight (`"myvote 3|other 1"`). A missing weight
// is 1; a weight is digits only (SPO-09a-PRE-004). Zero is accepted here as
// upstream does, the total is checked by the registration.
func ParseDelegation(s string) ([]DelegationWord, error) {
	var out []DelegationWord
	for _, part := range strings.Split(s, "|") {
		f := strings.Fields(part)
		switch len(f) {
		case 1:
			out = append(out, DelegationWord{Ref: f[0], Weight: 1})
		case 2:
			w, err := strconv.ParseUint(f[1], 10, 64)
			if err != nil || strings.TrimLeft(f[1], "0123456789") != "" {
				return nil, fmt.Errorf("%w: the weight %q is not a number", ErrBadDelegation, f[1])
			}
			out = append(out, DelegationWord{Ref: f[0], Weight: w})
		default:
			return nil, fmt.Errorf("%w: %q", ErrBadDelegation, part)
		}
	}
	if len(out) == 0 {
		return nil, ErrBadDelegation
	}
	return out, nil
}

// GenerateRegistration builds and signs a CIP-36 registration with the stake
// key (upstream 09a `genmeta`) and writes
// `<stake>_<yymmddHHMMSS>.vote-registration.cbor`. The stake key is demanded
// through a signing plan before anything is built.
type GenerateRegistration struct {
	Store   ports.NamedStore
	Signers ports.SignerDirectory
	Clock   ports.Clock
	// Tip gives the nonce: the current slot of the active work mode
	// (SPO-09a-INV-003). Optional when every request gives a nonce.
	Tip ports.TipReader
	// NetworkID is the network the rewards address must belong to.
	NetworkID uint8
}

// RegistrationRequest is one registration.
type RegistrationRequest struct {
	// Delegation is the parsed delegation; each Ref is resolved as SPO-09a-IF-006.
	Delegation []DelegationWord
	// Stake is the stake account: a trailing `.addr` and `.staking` and a
	// leading `./` are dropped (SPO-09a-IN-002).
	Stake string
	// Rewards is an address name, or a payment address (SPO-09a-IN-004).
	Rewards string
	// Nonce overrides the default (the current slot); 0 uses the default.
	Nonce uint64
	// Purpose is the voting purpose; 0 is Catalyst.
	Purpose uint64
}

// RegistrationGenerated is the result. All of it is public.
type RegistrationGenerated struct {
	Ref     ports.NamedRef // the registration file
	Nonce   uint64
	Keys    []ResolvedKey
	Rewards chain.Address
	JSON    string
	CBOR    []byte
}

// ResolvedKey is a voting key as resolved, with its source and weight
// (SPO-09a-PRE-005 displays them).
type ResolvedKey struct {
	Ref       string
	Source    string // pkey file, vkey file, hex or bech32
	PublicKey [32]byte
	Weight    uint64
}

func stakeName(s string) (string, error) {
	s = strings.TrimSuffix(strings.TrimSuffix(trimDir(s), ".addr"), ".staking")
	return plainName(s)
}

// Run builds, signs and stores the registration.
func (uc GenerateRegistration) Run(ctx context.Context, req RegistrationRequest) (res RegistrationGenerated, err error) {
	if uc.Store == nil || uc.Signers == nil || uc.Clock == nil {
		return res, ErrNotConfigured
	}
	if len(req.Delegation) == 0 {
		return res, ErrBadDelegation
	}
	sn, err := stakeName(req.Stake)
	if err != nil {
		return res, err
	}
	var haveSKey, haveHws, haveRewardsHws bool
	var rewardsKeyName string
	var stakeVKey []byte
	var rewards chain.Address
	var keys []ResolvedKey
	var stake, rewardsKey custody.KeyRef
	err = uc.Store.View(ctx, func(r ports.NamedReader) error {
		var err error
		if haveSKey, err = r.Exists(ports.NamedRef{Name: sn, Kind: ports.StakingSKey}); err != nil {
			return err
		}
		if haveHws, err = r.Exists(ports.NamedRef{Name: sn, Kind: ports.StakingHwsFile}); err != nil {
			return err
		}
		if !haveSKey && !haveHws {
			return nil
		}
		if stakeVKey, err = r.Get(ports.NamedRef{Name: sn, Kind: ports.StakingVKey}); err != nil {
			if errors.Is(err, ports.ErrNotFound) {
				return fmt.Errorf("%w: %s", ErrMissingFile, ports.NamedRef{Name: sn, Kind: ports.StakingVKey})
			}
			return err
		}
		if stake, err = keyring.Resolve(r, custody.RoleStake, sn); err != nil {
			return err
		}
		if rewards, err = uc.rewardsAddress(r, req.Rewards); err != nil {
			return err
		}
		// SPO-09a-INV-004: the rewards account's hardware signing file counts only
		// when the rewards account is the staking account.
		rewardsKeyName = rewardsName(req.Rewards)
		if strings.TrimSuffix(rewardsKeyName, ".payment") == sn && (ports.NamedRef{Name: rewardsKeyName, Kind: ports.AddrHwsFile}).Validate() == nil {
			if haveRewardsHws, err = r.Exists(ports.NamedRef{Name: rewardsKeyName, Kind: ports.AddrHwsFile}); err != nil {
				return err
			}
			if haveRewardsHws {
				if rewardsKey, err = keyring.Resolve(r, custody.RolePayment, rewardsKeyName); err != nil {
					return err
				}
			}
		}
		for _, d := range req.Delegation {
			k, err := resolveVotingKey(r, d)
			if err != nil {
				return err
			}
			keys = append(keys, k)
		}
		return nil
	})
	if err != nil {
		return res, err
	}
	if !haveSKey && !haveHws { // SPO-09a-PRE-003
		return res, ErrNoStakeSigner
	}
	stakePub, err := cose.VKeyFromEnvelope(stakeVKey)
	if err != nil {
		return res, fmt.Errorf("the stake verification key: %w", err)
	}
	_, addrBytes, err := chain.Bech32Decode(string(rewards))
	if err != nil {
		return res, ErrBadRewards
	}
	reg := cose.Cip36{StakePub: stakePub, Address: addrBytes, Purpose: req.Purpose}
	for _, k := range keys {
		reg.Delegations = append(reg.Delegations, cose.Delegation{VotePub: k.PublicKey, Weight: k.Weight})
	}
	if err := reg.Validate(); err != nil {
		return res, err
	}

	if _, err := ports.PlanSignatures(uc.Signers, []custody.Slot{{
		Label: "sign the Catalyst registration", Key: stake,
		Demand: custody.Demand{Role: custody.RoleStake, Operation: custody.OpSignCip36},
	}}); err != nil {
		return res, err
	}
	sg, err := uc.Signers.SignerFor(stake)
	if err != nil {
		return res, err
	}
	signer, ok := sg.(ports.Cip36Signer)
	if !ok {
		return res, ErrNoSigner
	}
	key, err := custody.As[custody.Stake](stake)
	if err != nil {
		return res, err
	}

	// The nonce is the current slot (SPO-09a-INV-003).
	reg.Nonce = req.Nonce
	if reg.Nonce == 0 {
		if uc.Tip == nil {
			return res, ErrNoNonce
		}
		tip, err := uc.Tip.Tip(ctx)
		if err != nil {
			return res, fmt.Errorf("current slot for the nonce: %w", err)
		}
		reg.Nonce = tip.Slot
	}
	var signed ports.Registration
	if hs, ok := signer.(ports.HardwareCip36Signer); ok && haveRewardsHws {
		signed, err = hs.SignCip36With(ctx, key, reg, ports.Cip36HardwareOptions{RewardsKey: &rewardsKey})
	} else {
		signed, err = signer.SignCip36(ctx, key, reg)
	}
	if err != nil {
		return res, fmt.Errorf("sign the registration: %w", err)
	}
	// The registration must verify under the stake key that was demanded: a
	// signer that answers with a valid registration of another key is refused.
	demanded, err := identity.KeyHashOf(reg.StakePub[:])
	if err != nil {
		return res, err
	}
	if _, err := custody.VerifyCip36(signed.CBOR, demanded); err != nil {
		return res, fmt.Errorf("the signer's registration does not verify: %w", err)
	}
	ref := ports.NamedRef{Name: sn + "_" + uc.Clock.Now().Format("060102150405"), Kind: ports.VoteRegistration}
	if err := uc.Store.Update(ctx, func(w ports.NamedWriter) error {
		if err := refuseExisting(w, ref); err != nil { // SPO-09a-OUT-005
			return err
		}
		return w.Put(ref, signed.CBOR)
	}); err != nil {
		return res, err
	}
	return RegistrationGenerated{Ref: ref, Nonce: reg.Nonce, Keys: keys, Rewards: rewards, JSON: signed.JSON, CBOR: signed.CBOR}, nil
}

// rewardsName is the name of the rewards argument as a stored payment key,
// `<wallet>.payment` for a wallet, with a `.addr` suffix removed; its account
// is that without `.payment` (SPO-09a-INV-004).
func rewardsName(s string) string {
	return strings.TrimSuffix(trimDir(strings.TrimSpace(s)), ".addr")
}

// rewardsAddress resolves the rewards argument (SPO-09a-IN-004): a stored
// `<rewards>.addr`, else the argument as a payment address. An ADA Handle is
// refused as in the send use case.
func (uc GenerateRegistration) rewardsAddress(r ports.NamedReader, s string) (chain.Address, error) {
	name := strings.TrimSuffix(trimDir(s), ".addr")
	var text string
	if (ports.NamedRef{Name: name, Kind: ports.AddrFile}).Validate() == nil {
		if b, err := r.Get(ports.NamedRef{Name: name, Kind: ports.AddrFile}); err == nil {
			text = strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0])
		}
	}
	if text == "" {
		text = strings.TrimSpace(s)
	}
	if strings.HasPrefix(text, "$") {
		return "", ErrAdaHandle
	}
	hrp, raw, err := chain.Bech32Decode(text)
	if err != nil || len(raw) == 0 || raw[0]>>4 > 7 || (hrp != "addr" && hrp != "addr_test") {
		return "", fmt.Errorf("%w: %q", ErrBadRewards, text)
	}
	// The network nibble must match (cardano-signer: --testnet or mainnet).
	if raw[0]&0x0f != uc.NetworkID {
		return "", fmt.Errorf("%w: it belongs to another network", ErrBadRewards)
	}
	return chain.Address(text), nil
}

// resolveVotingKey is SPO-09a-IF-006: a stored `.voting.pkey`, a stored
// `.voting.vkey`, 64 or 128 hex digits, a bech32 key; the first match wins.
func resolveVotingKey(r ports.NamedReader, d DelegationWord) (ResolvedKey, error) {
	k := ResolvedKey{Ref: d.Ref, Weight: d.Weight}
	ref := trimDir(d.Ref)
	name := strings.TrimSuffix(strings.TrimSuffix(ref, ".pkey"), ".voting")
	bech := func(s string) bool {
		_, raw, err := chain.Bech32Decode(s)
		if err != nil || len(raw) != 32 {
			return false
		}
		copy(k.PublicKey[:], raw)
		return true
	}
	if (ports.NamedRef{Name: name, Kind: ports.VotingPKey}).Validate() == nil {
		if b, err := r.Get(ports.NamedRef{Name: name, Kind: ports.VotingPKey}); err == nil && bech(strings.TrimSpace(string(b))) {
			k.Source = ports.NamedRef{Name: name, Kind: ports.VotingPKey}.String()
			return k, nil
		}
		if b, err := r.Get(ports.NamedRef{Name: name, Kind: ports.VotingVKey}); err == nil {
			pub, err := cose.VKeyFromEnvelope(b)
			if err != nil {
				return k, fmt.Errorf("%w: %s: %v", ErrBadVotingKey, d.Ref, err)
			}
			k.PublicKey, k.Source = pub, ports.NamedRef{Name: name, Kind: ports.VotingVKey}.String()
			return k, nil
		}
	}
	if n := len(ref); n == 64 || n == 128 {
		if raw, err := hex.DecodeString(ref); err == nil {
			copy(k.PublicKey[:], raw[:32])
			k.Source = "hex"
			return k, nil
		}
	}
	if bech(ref) {
		k.Source = "bech32"
		return k, nil
	}
	return k, fmt.Errorf("%w: %q", ErrBadVotingKey, d.Ref)
}
