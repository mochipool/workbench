package governance

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// KeySource says where a governance key comes from. It replaces the key type
// word of upstream's 21a, 23a and 23b for the software paths: `cli` is
// KeysRandom, `mnemonics` is KeysMnemonic. `enc` is not ported at generation
// (the decision of 04c and 03a); hardware holders are refused up front through
// the holder, and their ids are waived until the hardware signer adapter exists.
type KeySource string

// Key sources.
const (
	KeysRandom   KeySource = "random"
	KeysMnemonic KeySource = "mnemonic"
)

// MaxDerivationIndex is the largest account or index number (SPO-21a-PRE-001).
const MaxDerivationIndex = 1<<31 - 1

// GenerateKeysRequest names the key and where it comes from.
type GenerateKeysRequest struct {
	// Name is the DRep or committee member name as upstream takes it.
	Name   string
	Holder custody.Holder // empty means the vault
	Source KeySource
	// Account and Index select the derivation path of a mnemonic key:
	// 1852H/1815H/<Account>H/<role>/<Index>. They must be 0 for random keys.
	Account, Index uint32
	// Mnemonic is the phrase to derive from; nil generates a fresh one. The
	// buffer stays the caller's. Mnemonic source only.
	Mnemonic *ports.Secret
	// Replace (the hot key only, SPO-23b-PR-001) deletes an existing hot key
	// and its files first. It is the explicit answer to upstream's prompt
	// (default No); without it an existing hot key is refused.
	Replace bool
}

// keyKit says which artefacts and generators one kind of key uses.
type keyKit struct {
	role                         custody.Role
	vkey, skey, hws, aux, mnemos ports.Kind
	// gen makes a random pair; derive a mnemonic one.
	gen    func(context.Context) (ports.KeyPair, error)
	derive func(context.Context, *ports.Secret, uint32, uint32) (ports.KeyPair, error)
	// auxFile makes the content of the id or hash file; ids of the pair.
	auxFile func(hash [28]byte) ([]byte, error)
	// existing are the artefacts whose presence refuses the generation.
	existing []ports.Kind
	// replaceable: the hot key may be replaced on request.
	replaceable bool
	// mnemoOnlyCheck: the mnemonics file is checked only for the mnemonic source.
}

type keysGenerated struct {
	Name           string
	VKey           []byte
	Credential     governance.Credential
	MnemonicStored bool
	auxContent     []byte
}

func (kit keyKit) run(ctx context.Context, st ports.Store, mn ports.MnemonicGenerator, params ports.ProtocolParametersReader, req GenerateKeysRequest, nm string) (keysGenerated, error) {
	var res keysGenerated
	if req.Account > MaxDerivationIndex || req.Index > MaxDerivationIndex {
		return res, ErrDerivationRange
	}
	switch req.Source {
	case KeysRandom:
		if req.Account != 0 || req.Index != 0 || req.Mnemonic != nil {
			return res, fmt.Errorf("%w: account, index and mnemonic are for derived keys", ErrOptionNotUsed)
		}
		if kit.gen == nil {
			return res, ErrNotConfigured
		}
	case KeysMnemonic:
		if kit.derive == nil || (req.Mnemonic == nil && mn == nil) {
			return res, ErrNotConfigured
		}
	default:
		return res, fmt.Errorf("unknown key source %q", req.Source)
	}
	if req.Replace && !kit.replaceable {
		return res, fmt.Errorf("%w: only a hot key can be replaced", ErrOptionNotUsed)
	}
	// The hardware holder is refused before anything else.
	if _, err := custody.PlanGeneration(custody.KeyRef{Role: kit.role, Holder: req.Holder, Owner: nm}); err != nil {
		return res, err
	}
	if params != nil {
		p, err := params.ProtocolParameters(ctx)
		if err != nil {
			return res, fmt.Errorf("protocol parameters: %w", err)
		}
		if p.ProtocolMajor < MinConwayMajor {
			return res, ErrProtocolTooOld
		}
	}
	existing := func(r ports.Reader) []ports.Ref {
		var out []ports.Ref
		for _, k := range kit.existing {
			if ok, err := r.Exists(ports.Ref{Name: nm, Kind: k}); err == nil && ok {
				out = append(out, ports.Ref{Name: nm, Kind: k})
			}
		}
		return out
	}
	check := func(r ports.Reader) error {
		for _, k := range kit.existing {
			ref := ports.Ref{Name: nm, Kind: k}
			ok, err := r.Exists(ref)
			if err != nil {
				return err
			}
			if ok && !req.Replace {
				return fmt.Errorf("%w: %s", ErrExists, ref)
			}
		}
		if req.Source == KeysMnemonic {
			return refuseExisting(r, ports.Ref{Name: nm, Kind: kit.mnemos})
		}
		return nil
	}
	if err := st.View(ctx, check); err != nil {
		return res, err
	}

	var pair ports.KeyPair
	var words *ports.Secret
	defer func() {
		pair.SKey.Destroy()
		words.Destroy()
	}()
	var err error
	switch req.Source {
	case KeysRandom:
		if pair, err = kit.gen(ctx); err != nil {
			return res, fmt.Errorf("generate %s key: %w", kit.role, err)
		}
	case KeysMnemonic:
		if req.Mnemonic == nil {
			words, err = mn.GenerateMnemonic(ctx)
		} else {
			words, err = ports.NormalizeMnemonic(req.Mnemonic)
		}
		if err != nil {
			return res, err
		}
		if pair, err = kit.derive(ctx, words, req.Account, req.Index); err != nil {
			return res, fmt.Errorf("derive %s key: %w", kit.role, err)
		}
	}
	h, err := vkeyHash(pair.VKey)
	if err != nil {
		return res, err
	}
	aux, err := kit.auxFile(h)
	if err != nil {
		return res, err
	}
	var file *ports.Secret
	if words != nil {
		if file, err = ports.MnemonicFile(words); err != nil {
			return res, err
		}
		defer file.Destroy()
	}
	err = st.Update(ctx, func(w ports.Writer) error {
		if err := check2(w, kit, nm, req.Replace, existing); err != nil {
			return err
		}
		if req.Replace {
			// Upstream's replace branch removes the verification key twice and
			// never the signing key (SPO-23b-PR-001 quirk): all of them go here.
			for _, ref := range existing(w) {
				if err := w.Delete(ref); err != nil {
					return err
				}
			}
		}
		if file != nil {
			if err := w.PutSecret(ports.Ref{Name: nm, Kind: kit.mnemos}, file); err != nil {
				return err
			}
		}
		if err := w.Put(ports.Ref{Name: nm, Kind: kit.vkey}, pair.VKey); err != nil {
			return err
		}
		if err := w.PutSecret(ports.Ref{Name: nm, Kind: kit.skey}, pair.SKey); err != nil {
			return err
		}
		return w.Put(ports.Ref{Name: nm, Kind: kit.aux}, aux)
	})
	if err != nil {
		return res, err
	}
	res = keysGenerated{Name: nm, VKey: pair.VKey, Credential: governance.Credential{Hash: h}, MnemonicStored: file != nil, auxContent: aux}
	return res, nil
}

// check2 repeats the refusal inside the update, so a concurrent change cannot slip in.
func check2(w ports.Writer, kit keyKit, nm string, replace bool, _ func(ports.Reader) []ports.Ref) error {
	if replace {
		return nil
	}
	return refuseExisting(w, func() []ports.Ref {
		var out []ports.Ref
		for _, k := range kit.existing {
			out = append(out, ports.Ref{Name: nm, Kind: k})
		}
		return out
	}()...)
}

// ---- 21a --------------------------------------------------------------------------------

// GenerateDRepKeys creates the key material of a DRep and its id file (upstream
// 21a, software key types): `<drep>.drep.vkey`, `.skey`, `.id` and, for a
// mnemonic key, `.mnemonics`. All artefacts are written together or not at all
// (upstream leaves orphans after a failure, SPO-21a-PRE-004 port note). The
// mnemonic is stored as a secret and never returned.
type GenerateDRepKeys struct {
	Store     ports.Store
	Keys      ports.DRepKeyGenerator  // KeysRandom
	Deriver   ports.GovernanceDeriver // KeysMnemonic
	Mnemonics ports.MnemonicGenerator // KeysMnemonic without given words
	// Params gives the era gate (SPO-21a-PRE-003); nil skips it. A pre-Conway
	// era is an error here, where upstream exits 0 and creates nothing.
	Params ports.ProtocolParametersReader
}

// DRepKeysGenerated is the result. It carries no signing key and no mnemonic.
type DRepKeysGenerated struct {
	Name       string
	VKey       []byte
	Credential governance.Credential
	// IDs are the three spellings of the DRep id; the stored `.drep.id` holds
	// the legacy one, as `cardano-cli governance drep id` prints it.
	IDs            governance.DRepIDs
	MnemonicStored bool
}

// Run generates the DRep keys and the id.
//
// spec: SPO-21a-IF-001, SPO-21a-IF-003, SPO-21a-IF-004, SPO-21a-PRE-001, SPO-21a-PRE-002, SPO-21a-PRE-003, SPO-21a-PRE-004,
// spec: SPO-21a-PRE-005, SPO-21a-PRE-006, SPO-21a-PRE-007, SPO-21a-IN-001, SPO-21a-EXT-001, SPO-21a-EXT-003, SPO-21a-EXT-005,
// spec: SPO-21a-INV-002, SPO-21a-INV-003, SPO-21a-OUT-002, SPO-21a-OUT-003, SPO-Pfiles-OUT-024
func (uc GenerateDRepKeys) Run(ctx context.Context, req GenerateKeysRequest) (DRepKeysGenerated, error) {
	nm, err := name(strings.TrimSuffix(trimDir(req.Name), ".id"))
	if err != nil {
		return DRepKeysGenerated{}, err
	}
	kit := keyKit{role: custody.RoleDRep, vkey: ports.DRepVKey, skey: ports.DRepSKey, hws: ports.DRepHwsFile, aux: ports.DRepID, mnemos: ports.DRepMnemonics,
		existing: []ports.Kind{ports.DRepVKey, ports.DRepSKey, ports.DRepHwsFile, ports.DRepID},
		auxFile: func(h [28]byte) ([]byte, error) {
			ids, err := governance.DRepIDsOf(governance.Credential{Hash: h})
			return []byte(ids.Legacy), err
		}}
	if uc.Keys != nil {
		kit.gen = uc.Keys.GenerateDRep
	}
	if uc.Deriver != nil {
		kit.derive = uc.Deriver.DeriveDRep
	}
	g, err := kit.run(ctx, uc.Store, uc.Mnemonics, uc.Params, req, nm)
	if err != nil {
		return DRepKeysGenerated{}, err
	}
	ids, err := governance.DRepIDsOf(g.Credential)
	if err != nil {
		return DRepKeysGenerated{}, err
	}
	return DRepKeysGenerated{Name: nm, VKey: g.VKey, Credential: g.Credential, IDs: ids, MnemonicStored: g.MnemonicStored}, nil
}

// ---- 23a and 23b -----------------------------------------------------------------------

// CommitteeKeysGenerated is the result of 23a and 23b. The `.hash` file holds
// the 56-digit hash and a newline, as `governance committee key-hash` prints it.
type CommitteeKeysGenerated struct {
	Name           string
	VKey           []byte
	Credential     governance.Credential
	IDs            governance.CommitteeIDs
	MnemonicStored bool
}

func hashFile(h [28]byte) ([]byte, error) { return []byte(hex.EncodeToString(h[:]) + "\n"), nil }

// GenerateCommitteeColdKeys creates a committee member's cold key and its hash
// (upstream 23a, software key types): `<com>.cc-cold.vkey`, `.skey`, `.hash`
// and, for a mnemonic key, `.mnemonics` (path role 4).
type GenerateCommitteeColdKeys struct {
	Store     ports.Store
	Keys      ports.CommitteeColdKeyGenerator
	Deriver   ports.GovernanceDeriver
	Mnemonics ports.MnemonicGenerator
	Params    ports.ProtocolParametersReader
}

// Run generates the cold key.
//
// spec: SPO-23a-IF-001, SPO-23a-IF-003, SPO-23a-PRE-001, SPO-23a-PRE-002, SPO-23a-PRE-003, SPO-23a-PRE-004, SPO-23a-EXT-001,
// spec: SPO-23a-EXT-003, SPO-23a-EXT-005, SPO-23a-INV-002, SPO-23a-INV-003, SPO-23a-OUT-002, SPO-Pfiles-OUT-026, SPO-Pfiles-OUT-027
func (uc GenerateCommitteeColdKeys) Run(ctx context.Context, req GenerateKeysRequest) (CommitteeKeysGenerated, error) {
	nm, err := name(strings.TrimSuffix(trimDir(req.Name), ".hash"))
	if err != nil {
		return CommitteeKeysGenerated{}, err
	}
	kit := keyKit{role: custody.RoleCommitteeCold, vkey: ports.CCColdVKey, skey: ports.CCColdSKey, hws: ports.CCColdHwsFile, aux: ports.CCColdHash, mnemos: ports.CCColdMnemonics,
		existing: []ports.Kind{ports.CCColdVKey, ports.CCColdSKey, ports.CCColdHwsFile, ports.CCColdHash}, auxFile: hashFile}
	if uc.Keys != nil {
		kit.gen = uc.Keys.GenerateCommitteeCold
	}
	if uc.Deriver != nil {
		kit.derive = uc.Deriver.DeriveCommitteeCold
	}
	g, err := kit.run(ctx, uc.Store, uc.Mnemonics, uc.Params, req, nm)
	if err != nil {
		return CommitteeKeysGenerated{}, err
	}
	ids, err := governance.CommitteeIDsOf(g.Credential, false)
	return CommitteeKeysGenerated{Name: nm, VKey: g.VKey, Credential: g.Credential, IDs: ids, MnemonicStored: g.MnemonicStored}, err
}

// GenerateCommitteeHotKeys creates a committee member's hot key and its hash
// (upstream 23b, software key types; path role 5). An existing hot key is
// replaced only on Replace (the answer to upstream's prompt, default No), and
// the replacement removes the signing key too.
type GenerateCommitteeHotKeys struct {
	Store     ports.Store
	Keys      ports.CommitteeHotKeyGenerator
	Deriver   ports.GovernanceDeriver
	Mnemonics ports.MnemonicGenerator
	Params    ports.ProtocolParametersReader
}

// Run generates the hot key.
//
// spec: SPO-23b-IF-001, SPO-23b-IF-003, SPO-23b-PRE-001, SPO-23b-PRE-002, SPO-23b-PRE-003, SPO-23b-PR-001, SPO-23b-EXT-001,
// spec: SPO-23b-EXT-003, SPO-23b-EXT-005, SPO-23b-INV-002, SPO-23b-INV-003, SPO-23b-OUT-002, SPO-Pfiles-OUT-026, SPO-Pfiles-OUT-027
func (uc GenerateCommitteeHotKeys) Run(ctx context.Context, req GenerateKeysRequest) (CommitteeKeysGenerated, error) {
	nm, err := name(strings.TrimSuffix(trimDir(req.Name), ".hash"))
	if err != nil {
		return CommitteeKeysGenerated{}, err
	}
	kit := keyKit{role: custody.RoleCommitteeHot, vkey: ports.CCHotVKey, skey: ports.CCHotSKey, hws: ports.CCHotHwsFile, aux: ports.CCHotHash, mnemos: ports.CCHotMnemonics,
		existing: []ports.Kind{ports.CCHotVKey, ports.CCHotSKey, ports.CCHotHwsFile, ports.CCHotHash}, auxFile: hashFile, replaceable: true}
	if uc.Keys != nil {
		kit.gen = uc.Keys.GenerateCommitteeHot
	}
	if uc.Deriver != nil {
		kit.derive = uc.Deriver.DeriveCommitteeHot
	}
	g, err := kit.run(ctx, uc.Store, uc.Mnemonics, uc.Params, req, nm)
	if err != nil {
		return CommitteeKeysGenerated{}, err
	}
	ids, err := governance.CommitteeIDsOf(g.Credential, true)
	return CommitteeKeysGenerated{Name: nm, VKey: g.VKey, Credential: g.Credential, IDs: ids, MnemonicStored: g.MnemonicStored}, err
}

var _ = errors.New
