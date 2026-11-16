package workspace

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/keyfile"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals of the import of a pool (upstream 0x_importHelper).
var (
	// ErrEmptyPoolName: the import name has no letter or digit left after the
	// sanitising of SPO-0x-IF-002 (upstream does not check).
	ErrEmptyPoolName = errors.New("the pool name has no letter or digit")
	// ErrPoolExists: the pool's descriptor exists (SPO-0x-PRE-004).
	ErrPoolExists = errors.New("the pool already has a descriptor in this workspace")
	// ErrPoolPartExists: other artefacts of the pool exist and the operator did
	// not agree to go on (SPO-0x-PR-002).
	ErrPoolPartExists = errors.New("artefacts of this pool already exist; go on only to add to them")
	// ErrInfoMember: a member of the info is missing or empty (SPO-0x-PRE-005).
	ErrInfoMember = errors.New("the pool info lacks a required member")
	// ErrRelay: a relay with no usable entry, more than one, or too long
	// (SPO-0x-OUT-005).
	ErrRelay = errors.New("a relay of the pool is not usable")
	// ErrKeyRefused: a key source that SPO-0x-PRE-006, SPO-0x-PRE-007 and
	// SPO-0x-PRE-008 refuse; upstream asks again, a request refuses.
	ErrKeyRefused = errors.New("a key was refused")
	// ErrKeyNotPool: the cold key is not the pool's (a check upstream lacks,
	// SPO-0x-INV-004).
	ErrKeyNotPool = errors.New("the cold key does not belong to this pool")
	// ErrCounterUnknown: the chain's operational certificate counter is not known
	// (an info file without it), so the counter file cannot be made.
	ErrCounterUnknown = errors.New("the chain's operational certificate counter is not known")
	// ErrAccountName: an account name that is not a plain name (SPO-0x-SEC-002).
	ErrAccountName = errors.New("the account name must be a plain name: letters, digits, '-', '_' and single dots")
	// ErrNoDeposit: the stake address deposit is not known.
	ErrNoDeposit = errors.New("the stake address deposit is not known")
	// ErrImportMisconfigured: the composition lacks a port.
	ErrImportMisconfigured = errors.New("the pool import is not wired correctly")
)

// ImportPoolFromChain brings a pool that was set up with other tools into the
// workspace: from its registration data (the chain, or an info file) and the
// operator's key files it builds the descriptor, the cold and VRF keys and, per
// account, the payment and stake keys, addresses and certificates (upstream
// 0x_importHelper). It differs from ImportWorkspace, which copies an upstream
// directory.
//
// Everything is planned first and written in one store transaction, so a
// refusal leaves nothing behind (the port note of SPO-0x-PRE-004 and
// SPO-0x-PRE-006); the prompts of the script are fields of the request. The
// secrets are read from the buffers the request holds, sealed by the store,
// and never copied elsewhere: the sources stay the caller's to destroy.
type ImportPoolFromChain struct {
	PoolInfoAcquirer
	Store     ports.Store
	VKeys     ports.VKeyEnvelopeDeriver
	VRF       ports.VrfVKeyDeriver
	Addresses ports.AddressBuilder
	Certs     ports.CertificateBuilder
	// Params gives the stake address deposit; needed only when an account has
	// both its keys. Offline mode wires the transfer file's parameters.
	Params ports.ProtocolParametersReader
	// Cross is an optional second, independent reader of the pool's
	// registration. When the info comes from the chain, the fields both
	// providers state must agree; without it (or when it does not answer) the
	// request must acknowledge a single source (ADR 0006, F3).
	Cross ports.PoolInfoReader
	// OnSingle records an acknowledged single source before anything is
	// written; required when the data rests on one provider (ADR 0006). A dry
	// run writes nothing and records nothing.
	OnSingle  ports.SingleSourceHook
	NetworkID uint8
	// Zone is the zone of regSubmitted; nil is UTC (upstream's `date -R` uses the
	// machine's zone).
	Zone *time.Location
}

// AccountKeys are the key sources of one owner or reward account. A nil
// Payment gives the account up; a nil Stake imports the payment key only
// (SPO-0x-PR-006).
type AccountKeys struct {
	// Name is the account name, the prefix of its files; it is validated, not
	// cleaned (SPO-0x-SEC-002).
	Name           string
	Payment, Stake *ports.Secret
}

// ImportPoolRequest is one import.
type ImportPoolRequest struct {
	// Name is the first argument of the script: the pool name before the
	// sanitising of SPO-0x-IF-002.
	Name   string
	Source PoolInfoSource
	// ContinueExisting answers the question of SPO-0x-PR-002 (default no).
	ContinueExisting bool
	// Cold and VRF are the signing key envelopes to import; nil skips
	// (SPO-0x-PR-003, SPO-0x-PR-004).
	Cold, VRF *ports.Secret
	Accounts  []AccountKeys
	// DryRun plans and checks everything and writes nothing.
	DryRun bool
	// SingleSource acknowledges registration data that rests on one provider.
	SingleSource bool
	// Fetched, when set, is the registration data an earlier Fetch read (and
	// cross-checked); Run uses it and reads nothing from the chain, so what is
	// written is what the operator was shown. Source and SingleSource are then
	// not consulted.
	Fetched *FetchedPool
}

// FetchedPool is the registration data of one read of the chain (or an info
// file) together with the result of its cross-check. A caller that shows the
// data before it is written passes the same value to every Run.
type FetchedPool struct {
	Info chain.PoolInfo
	// Sources are the providers the data rests on (empty for an info file) and
	// Single is true when it rests on one by acknowledgement.
	Sources []chain.Source
	Single  bool
	// Mismatch is set when the published metadata does not hash to the
	// registered hash; Run refuses unless the request accepts it.
	Mismatch *MetadataMismatch
}

// Fetch reads the registration data once: the info file or the chain, the
// metadata check (a mismatch is recorded, not refused), and the cross-check
// with the second provider. It writes nothing.
func (u ImportPoolFromChain) Fetch(ctx context.Context, src PoolInfoSource, single bool) (*FetchedPool, error) {
	info, mm, err := u.acquire(ctx, src)
	if err != nil {
		return nil, err
	}
	f := &FetchedPool{Info: info, Mismatch: mm}
	if len(src.InfoFile) == 0 {
		word, err := stake.ParsePoolWord(src.PoolID)
		if err != nil || !word.IsID {
			return nil, ErrBadPoolID
		}
		f.Sources, f.Single, err = corroborate(ctx, u.Pools, u.Cross, word.Pool, info, single)
		if err != nil {
			return nil, err
		}
	}
	return f, nil
}

// AccountImported says what became of an account.
type AccountImported struct {
	Name string
	// Complete: both keys were imported, so the addresses and the registration
	// certificate exist; Delegation: the delegation certificate too.
	Complete   bool
	Delegation bool
	// Owner and Reward: the staking address is among the pool's owners, or is
	// its reward account (SPO-0x-OUT-014, SPO-0x-OUT-015). An account that is
	// neither is imported all the same (SPO-0x-INV-005).
	Owner, Reward bool
	StakeAddress  string
}

// PoolImported is the result. Nothing in it is secret.
type PoolImported struct {
	Pool       string
	Info       chain.PoolInfo
	Descriptor []byte
	Written    []ports.Ref // empty after a dry run
	Accounts   []AccountImported
	// CounterNext is the number in the counter file (chain counter + 1); valid
	// when the cold key was imported.
	CounterNext uint64
	// Sources are the providers the registration data was read from (empty
	// for an info file); SingleSource is true when it rests on one of them by
	// the operator's acknowledgement.
	Sources      []chain.Source
	SingleSource bool
	// RewardsMissing: no account is the pool's rewards account; the script asks
	// whether to go back and add one (SPO-0x-PR-007, default yes).
	RewardsMissing bool
	DryRun         bool
}

var nonAlnum = regexp.MustCompile(`[^A-Za-z0-9]`)

// PoolImportName is the pool name of SPO-0x-IF-002: a trailing `.json`, then a
// trailing `.pool` removed, then every character that is not a letter or a
// digit. An empty result is refused (SPO-0x-IF-002 notes upstream does not).
//
// spec: SPO-0x-IF-002
func PoolImportName(arg string) (string, error) {
	s := strings.TrimSuffix(strings.TrimSuffix(arg, ".json"), ".pool")
	s = nonAlnum.ReplaceAllString(s, "")
	if s == "" {
		return "", ErrEmptyPoolName
	}
	return s, nil
}

func metaString(doc map[string]any, k string) string {
	s, _ := doc[k].(string)
	return s
}

type put struct {
	ref  ports.Ref
	data []byte
	sec  *ports.Secret
}

func (u ImportPoolFromChain) keyEnvelope(s *ports.Secret, what string) error {
	info, err := classifyBuf(s)
	switch {
	case err == nil && info.Form == keyfile.FormPlain && strings.Contains(info.Type, "SigningKey"):
		return nil
	case err == nil && info.Form == keyfile.FormEncrypted:
		// SPO-0x-SEC-001: an encrypted key cannot be imported here; decrypt it
		// first (ImportWorkspace decrypts and seals).
		return fmt.Errorf("%w: the %s key is encrypted; decrypt it first", ErrKeyRefused, what)
	}
	return fmt.Errorf("%w: the %s source is not a signing key envelope", ErrKeyRefused, what)
}

func vkeyRaw(env []byte) ([]byte, error) {
	e, err := pool.ParseEnvelope(env)
	if err != nil {
		return nil, err
	}
	return e.Key32()
}

// Run imports.
//
// spec: SPO-0x-IF-002, SPO-0x-IN-003, SPO-0x-PR-002, SPO-0x-OUT-002, SPO-0x-PRE-004, SPO-0x-PRE-005
// spec: SPO-0x-OUT-003, SPO-0x-OUT-004, SPO-0x-OUT-005, SPO-0x-OUT-006, SPO-0x-INV-003, SPO-0x-PRE-006, SPO-0x-OUT-007, SPO-0x-INV-004
// spec: SPO-0x-PRE-007, SPO-0x-OUT-008, SPO-0x-PR-006, SPO-0x-PRE-008, SPO-0x-OUT-009, SPO-0x-OUT-010
// spec: SPO-0x-OUT-011, SPO-0x-OUT-012, SPO-0x-OUT-014, SPO-0x-OUT-015, SPO-0x-INV-005, SPO-0x-PR-007, SPO-0x-OUT-016
// spec: SPO-0x-SEC-001, SPO-0x-SEC-002, SPO-0x-SEC-003, SPO-0x-MODE-001
func (u ImportPoolFromChain) Run(ctx context.Context, req ImportPoolRequest) (PoolImported, error) {
	if u.Store == nil {
		return PoolImported{}, fmt.Errorf("%w: a store is needed", ErrImportMisconfigured)
	}
	name, err := PoolImportName(req.Name)
	if err != nil {
		return PoolImported{}, err
	}
	// The info first: nothing of the workspace is looked at before it is in
	// hand. It is read once; a caller that confirms the data passes it back in
	// req.Fetched. The second provider corroborates it (F3): the reward
	// address, owners and counter would otherwise rest on one answer.
	fetched := req.Fetched
	if fetched == nil {
		f, err := u.Fetch(ctx, req.Source, req.SingleSource)
		if err != nil {
			return PoolImported{}, err
		}
		fetched = f
	}
	if fetched.Mismatch != nil && !req.Source.AcceptMetadataMismatch {
		return PoolImported{}, ErrMetadataHash
	}
	info, sources, singleUsed := fetched.Info, fetched.Sources, fetched.Single

	// Existing artefacts of the pool (SPO-0x-PR-002, SPO-0x-PRE-004).
	poolKinds := []ports.Kind{ports.PoolDescriptor, ports.NodeSKey, ports.NodeVKey, ports.NodeCounter, ports.VrfSKey, ports.VrfVKey}
	var nodeVKey []byte
	if err := u.Store.View(ctx, func(r ports.Reader) error {
		for _, k := range poolKinds {
			ok, err := r.Exists(ports.Ref{Name: name, Kind: k})
			if err != nil {
				return err
			}
			if ok && !req.ContinueExisting {
				return fmt.Errorf("%w: %s", ErrPoolPartExists, ports.Ref{Name: name, Kind: k})
			}
			if ok && k == ports.PoolDescriptor {
				return fmt.Errorf("%w: %s", ErrPoolExists, name)
			}
		}
		if b, err := r.Get(ports.Ref{Name: name, Kind: ports.NodeVKey}); err == nil {
			nodeVKey = b
		}
		return nil
	}); err != nil {
		return PoolImported{}, err
	}

	// Required members (SPO-0x-PRE-005).
	var meta map[string]any
	if len(info.Metadata) > 0 {
		_ = json.Unmarshal(info.Metadata, &meta)
	}
	for _, m := range []struct{ n, v string }{
		{"pledge", info.Pledge}, {"fixed_cost", info.FixedCost}, {"margin", info.Margin},
		{"metadata.name", metaString(meta, "name")}, {"metadata.description", metaString(meta, "description")},
		{"metadata.ticker", metaString(meta, "ticker")}, {"metadata.homepage", metaString(meta, "homepage")},
		{"pool_status", info.Status}, {"pool_id_hex", info.IDHex}, {"pool_id_bech32", info.IDBech},
	} {
		if m.v == "" {
			return PoolImported{}, fmt.Errorf("%w: %s", ErrInfoMember, m.n)
		}
	}
	if !info.HasLastUpdate {
		return PoolImported{}, fmt.Errorf("%w: lastupdate_time and lastupdate_epoch", ErrInfoMember)
	}
	// The identity the keys are checked against must be consistent (SPO-0x-SEC-003).
	idRaw, err := hex.DecodeString(info.IDHex)
	if err != nil || len(idRaw) != 28 {
		return PoolImported{}, fmt.Errorf("%w: pool_id_hex is not 56 hex digits", ErrBadInfo)
	}
	if pid, err := chain.ParsePoolBech32(info.IDBech); err != nil || hex.EncodeToString(pid[:]) != strings.ToLower(info.IDHex) {
		return PoolImported{}, fmt.Errorf("%w: pool_id_bech32 is not pool_id_hex", ErrBadInfo)
	}

	// Relays (SPO-0x-OUT-005).
	var relays []pool.DescriptorRelay
	for _, r := range info.Relays {
		if len(r.Members) != 1 {
			return PoolImported{}, fmt.Errorf("%w: it has %d address members, expected one", ErrRelay, len(r.Members))
		}
		for k, v := range r.Members {
			if v == "" || len(v) > 64 || (k != "ipv4" && k != "ipv6" && k != "dns" && k != "srv") {
				return PoolImported{}, fmt.Errorf("%w: %s entry is empty, too long or of an unknown type", ErrRelay, k)
			}
			relays = append(relays, pool.DescriptorRelay{Type: k, Entry: v, Port: r.Port})
		}
	}

	zone := u.Zone
	if zone == nil {
		zone = time.UTC
	}
	desc := pool.NewImportedDescriptor(pool.ImportedDescriptor{
		Name: name, Pledge: info.Pledge, Cost: info.FixedCost, Margin: info.Margin, Relays: relays,
		MetaName: metaString(meta, "name"), MetaDescription: metaString(meta, "description"),
		MetaTicker: metaString(meta, "ticker"), MetaHomepage: metaString(meta, "homepage"),
		MetaURL: info.MetaURL, ExtendedMetaURL: metaString(meta, "extended"),
		PoolIDHex: info.IDHex, PoolIDBech: info.IDBech,
		Registered: info.Status == "registered", RegEpoch: info.LastUpdateEpoch,
		RegSubmitted: time.Unix(int64(info.LastUpdateTime), 0).In(zone),
	})

	var plan []put
	res := PoolImported{Pool: name, Info: info, DryRun: req.DryRun, Sources: sources, SingleSource: singleUsed}
	taken := map[ports.Ref]bool{}
	// refuse catches a name used twice in this request; what the store already
	// holds is checked against the whole plan below (SPO-0x-PRE-006, SPO-0x-PRE-008).
	refuse := func(r ports.Ref) error {
		if taken[r] {
			return fmt.Errorf("%w: %s is used twice", ErrKeyRefused, r)
		}
		taken[r] = true
		return nil
	}

	// Cold key (SPO-0x-PR-003, SPO-0x-PRE-006, SPO-0x-OUT-007).
	var coldRaw []byte
	if req.Cold != nil {
		if u.VKeys == nil {
			return PoolImported{}, fmt.Errorf("%w: a verification key deriver is needed", ErrImportMisconfigured)
		}
		if err := u.keyEnvelope(req.Cold, "cold"); err != nil {
			return PoolImported{}, err
		}
		sk, vk, cnt := ports.Ref{Name: name, Kind: ports.NodeSKey}, ports.Ref{Name: name, Kind: ports.NodeVKey}, ports.Ref{Name: name, Kind: ports.NodeCounter}
		for _, r := range []ports.Ref{sk, vk, cnt} {
			if err := refuse(r); err != nil {
				return PoolImported{}, err
			}
		}
		vkEnv, err := u.VKeys.DeriveVKeyEnvelope(ctx, req.Cold)
		if err != nil {
			return PoolImported{}, fmt.Errorf("%w: the cold verification key cannot be derived: %v", ErrKeyRefused, err)
		}
		if coldRaw, err = vkeyRaw(vkEnv); err != nil {
			return PoolImported{}, fmt.Errorf("%w: %v", ErrKeyRefused, err)
		}
		if id, _ := chain.PoolIDOf(coldRaw); hex.EncodeToString(id[:]) != strings.ToLower(info.IDHex) {
			return PoolImported{}, ErrKeyNotPool // SPO-0x-INV-004: upstream accepts any signing key
		}
		// The counter: chain + 1, or 0 when no block was minted (SPO-0x-OUT-003);
		// an unknown chain counter is not guessed (hazard H1).
		var next uint64
		switch n, ok := info.OpCertCounter.Get(); {
		case ok:
			if n == ^uint64(0) {
				return PoolImported{}, ErrCounterUnknown
			}
			next = n + 1
		case info.OpCertCounter.IsNone():
			next = 0
		default:
			return PoolImported{}, fmt.Errorf("%w: %s", ErrCounterUnknown, info.OpCertCounter.Why())
		}
		ic := pool.IssueCounter{Next: next}
		copy(ic.ColdVKey[:], coldRaw)
		res.CounterNext = next
		plan = append(plan, put{ref: sk, sec: req.Cold}, put{ref: vk, data: vkEnv}, put{ref: cnt, data: ic.Envelope()})
	}
	if len(coldRaw) == 0 && len(nodeVKey) > 0 {
		if raw, err := vkeyRaw(nodeVKey); err == nil {
			coldRaw = raw // an earlier import of the cold key (SPO-0x-OUT-012)
		}
	}

	// VRF key (SPO-0x-PR-004, SPO-0x-PRE-007, SPO-0x-OUT-008).
	if req.VRF != nil {
		if u.VRF == nil {
			return PoolImported{}, fmt.Errorf("%w: a VRF key deriver is needed", ErrImportMisconfigured)
		}
		if err := u.keyEnvelope(req.VRF, "VRF"); err != nil {
			return PoolImported{}, err
		}
		sk, vk := ports.Ref{Name: name, Kind: ports.VrfSKey}, ports.Ref{Name: name, Kind: ports.VrfVKey}
		for _, r := range []ports.Ref{sk, vk} {
			if err := refuse(r); err != nil {
				return PoolImported{}, err
			}
		}
		vkEnv, err := u.VRF.DeriveVrfVKey(ctx, req.VRF)
		if err != nil {
			return PoolImported{}, fmt.Errorf("%w: the VRF verification key cannot be derived: %v", ErrKeyRefused, err)
		}
		raw, err := vkeyRaw(vkEnv)
		if err != nil {
			return PoolImported{}, fmt.Errorf("%w: %v", ErrKeyRefused, err)
		}
		if h := pool.VrfHash(raw); hex.EncodeToString(h[:]) != strings.ToLower(info.VRFKeyHash) {
			return PoolImported{}, fmt.Errorf("%w: the VRF key's hash is not the pool's vrf_key_hash", ErrKeyRefused)
		}
		plan = append(plan, put{ref: sk, sec: req.VRF}, put{ref: vk, data: vkEnv})
	}

	// Accounts (SPO-0x-PR-005, SPO-0x-PR-006).
	seen := map[string]bool{}
	for _, a := range req.Accounts {
		if a.Name == "" {
			continue // a blank name ends the loop
		}
		if (ports.Ref{Name: a.Name, Kind: ports.StakingSKey}).Validate() != nil || seen[a.Name] {
			return PoolImported{}, fmt.Errorf("%w: %q", ErrAccountName, a.Name)
		}
		seen[a.Name] = true
		if a.Payment == nil {
			continue
		}
		ai := AccountImported{Name: a.Name}
		payBase := a.Name + ".payment"
		pSk, pVk := ports.Ref{Name: payBase, Kind: ports.AddrSKey}, ports.Ref{Name: payBase, Kind: ports.AddrVKey}
		if u.VKeys == nil {
			return PoolImported{}, fmt.Errorf("%w: a verification key deriver is needed", ErrImportMisconfigured)
		}
		if err := u.keyEnvelope(a.Payment, "payment"); err != nil {
			return PoolImported{}, err
		}
		for _, r := range []ports.Ref{pSk, pVk} {
			if err := refuse(r); err != nil {
				return PoolImported{}, err
			}
		}
		pEnv, err := u.VKeys.DeriveVKeyEnvelope(ctx, a.Payment)
		if err != nil {
			return PoolImported{}, fmt.Errorf("%w: the payment verification key cannot be derived: %v", ErrKeyRefused, err)
		}
		pRaw, err := vkeyRaw(pEnv)
		if err != nil {
			return PoolImported{}, fmt.Errorf("%w: %v", ErrKeyRefused, err)
		}
		plan = append(plan, put{ref: pSk, sec: a.Payment}, put{ref: pVk, data: pEnv})
		if a.Stake != nil {
			sSk, sVk := ports.Ref{Name: a.Name, Kind: ports.StakingSKey}, ports.Ref{Name: a.Name, Kind: ports.StakingVKey}
			if err := u.keyEnvelope(a.Stake, "stake"); err != nil {
				return PoolImported{}, err
			}
			for _, r := range []ports.Ref{sSk, sVk} {
				if err := refuse(r); err != nil {
					return PoolImported{}, err
				}
			}
			sEnv, err := u.VKeys.DeriveVKeyEnvelope(ctx, a.Stake)
			if err != nil {
				return PoolImported{}, fmt.Errorf("%w: the stake verification key cannot be derived: %v", ErrKeyRefused, err)
			}
			sRaw, err := vkeyRaw(sEnv)
			if err != nil {
				return PoolImported{}, fmt.Errorf("%w: %v", ErrKeyRefused, err)
			}
			plan = append(plan, put{ref: sSk, sec: a.Stake}, put{ref: sVk, data: sEnv})
			if u.Addresses == nil || u.Certs == nil || u.Params == nil {
				return PoolImported{}, fmt.Errorf("%w: address, certificate and parameter ports are needed for an account with both keys", ErrImportMisconfigured)
			}
			payHash, stkHash := txbuild.HashKey(pRaw), txbuild.HashKey(sRaw)
			addr, err := u.Addresses.BuildAddress(u.NetworkID, payHash, &stkHash)
			if err != nil {
				return PoolImported{}, err
			}
			stkAddr, err := u.Addresses.BuildStakeAddress(u.NetworkID, stkHash)
			if err != nil {
				return PoolImported{}, err
			}
			refs := []ports.Ref{{Name: payBase, Kind: ports.AddrFile}, {Name: a.Name, Kind: ports.StakingAddr}, {Name: a.Name, Kind: ports.StakingCert}}
			for _, r := range refs {
				if err := refuse(r); err != nil {
					return PoolImported{}, err
				}
			}
			pp, err := u.Params.ProtocolParameters(ctx)
			if err != nil {
				return PoolImported{}, fmt.Errorf("protocol parameters (the stake address deposit): %w", err)
			}
			if pp.StakeAddressDeposit == 0 {
				return PoolImported{}, ErrNoDeposit
			}
			reg, err := u.Certs.BuildCertificate(stake.Spec{Kind: stake.CertRegistration, Stake: stake.KeyHash(stkHash), Deposit: pp.StakeAddressDeposit})
			if err != nil {
				return PoolImported{}, fmt.Errorf("the registration certificate: %w", err)
			}
			plan = append(plan, put{ref: refs[0], data: []byte(string(addr) + "\n")}, put{ref: refs[1], data: []byte(string(stkAddr) + "\n")}, put{ref: refs[2], data: reg.Envelope})
			ai.Complete, ai.StakeAddress = true, string(stkAddr)
			if len(coldRaw) == 32 { // SPO-0x-OUT-012: only when the cold key is there
				pid, _ := chain.PoolIDOf(coldRaw)
				dref := ports.Ref{Name: a.Name, Kind: ports.DelegCert}
				if err := refuse(dref); err != nil {
					return PoolImported{}, err
				}
				dc, err := u.Certs.BuildCertificate(stake.Spec{Kind: stake.CertPoolDelegation, Stake: stake.KeyHash(stkHash), Pool: pid})
				if err != nil {
					return PoolImported{}, fmt.Errorf("the delegation certificate: %w", err)
				}
				plan = append(plan, put{ref: dref, data: dc.Envelope})
				ai.Delegation = true
			}
			for _, o := range info.Owners { // SPO-0x-OUT-014
				if o == string(stkAddr) {
					ai.Owner = true
					desc.AddImportedOwner(a.Name)
					break
				}
			}
			if info.RewardAddr != "" && info.RewardAddr == string(stkAddr) { // SPO-0x-OUT-015
				ai.Reward = true
				desc.SetImportedRewards(a.Name)
			}
		}
		res.Accounts = append(res.Accounts, ai)
	}
	res.RewardsMissing = desc.Text(pool.FieldRewards) == ""

	dref := ports.Ref{Name: name, Kind: ports.PoolDescriptor}
	res.Descriptor = desc.Render()
	plan = append(plan, put{ref: dref, data: res.Descriptor})
	if req.DryRun {
		err := u.Store.View(ctx, func(r ports.Reader) error {
			for _, p := range plan {
				ok, err := r.Exists(p.ref)
				if err != nil {
					return err
				}
				if ok {
					return fmt.Errorf("%w: %s already exists", ErrKeyRefused, p.ref)
				}
			}
			return nil
		})
		return res, err
	}
	// The audit record of an acknowledged single source comes before the first
	// write (ADR 0006); a failure leaves the workspace as it was.
	if singleUsed {
		if err := u.OnSingle.Accept(ctx, "the pool's reward address, owners and operational certificate counter", sources[0]); err != nil {
			return PoolImported{}, err
		}
	}
	err = u.Store.Update(ctx, func(w ports.Writer) error {
		// The same checks inside the transaction: the workspace may have moved.
		for _, p := range plan {
			ok, err := w.Exists(p.ref)
			if err != nil {
				return err
			}
			if ok {
				return fmt.Errorf("%w: %s already exists", ErrKeyRefused, p.ref)
			}
		}
		for _, p := range plan {
			var err error
			if p.sec != nil {
				err = w.PutSecret(p.ref, p.sec)
			} else {
				err = w.Put(p.ref, p.data)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return PoolImported{}, err
	}
	for _, p := range plan {
		res.Written = append(res.Written, p.ref)
	}
	sort.Slice(res.Written, func(i, j int) bool { return res.Written[i].String() < res.Written[j].String() })
	return res, nil
}
