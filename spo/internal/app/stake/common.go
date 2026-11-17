// Package stake holds the use cases of stake accounts: the certificates
// that register, delegate and retire them (05b, 08a, 22a), the transactions
// that put those certificates on chain (03b, 06, 08b, 22b) and the status
// read (03c). Transactions run the shared pipeline of app/txflow; the
// state rules are those of domain/stake.
//
// Every use case is one workflow. Which signer holds a key and whether the
// signed transaction is submitted or queued are decided by the composition:
// a hardware holder is decided up front by the signing plan against the
// device's profile (ADR 0008), the body is brought to hardware form before it
// is shown, and a hardware key mixed with a key-file key is refused
// (SPO-Ptx-PRE-006).
package stake

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/mochipool/workbench/spo/internal/app/keyring"
	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	stk "github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals of the stake use cases, beyond those of domain/stake and
// app/txflow. Every failure is a returned error: where upstream exits 0
// after a failed query or a refused minimum value (hazard H3), the use case
// returns an error.
var (
	// ErrMissingFile: an artefact the workflow reads does not exist.
	ErrMissingFile = errors.New("a file the workflow needs does not exist")
	// ErrNotStakeAddress: the stored or given address is not a stake address
	// whose credential is a key (SPO-03b-PRE-001, SPO-08b-PRE-001, SPO-03c-IF-003).
	ErrNotStakeAddress = errors.New("the address is not a stake address with a key credential")
	// ErrNetworkMismatch: an address belongs to another network.
	ErrNetworkMismatch = errors.New("the address belongs to a different network")
	// ErrNoSigningKey: neither a signing key nor a hardware signing file exists.
	ErrNoSigningKey = errors.New("no signing key (.skey) or hardware signing file (.hwsfile)")
	// ErrSourceNotKey: the paying address cannot be spent with a key witness.
	ErrSourceNotKey = errors.New("the paying address does not use a payment key (a script or Byron address cannot be signed with a key file)")
	// ErrProtocolTooOld: the Conway certificates need protocol version 9.
	ErrProtocolTooOld = errors.New("the protocol version is older than 9: the Conway certificates and deposits are not available")
	// ErrWrongCertificate: the certificate file is of another kind than the workflow's.
	ErrWrongCertificate = errors.New("the certificate is not of the kind this workflow registers")
	// ErrNoDeposit: the protocol parameters carry no stake address deposit.
	ErrNoDeposit = errors.New("the protocol parameters carry no stakeAddressDeposit")
	// ErrDepositMismatch: the deposit in the certificate is not the deposit the chain holds.
	ErrDepositMismatch = errors.New("the deposit in the certificate is not the deposit the chain holds for the stake address")
	// ErrNoChainReader: a check the workflow requires has no chain reader.
	ErrNoChainReader = errors.New("this workflow needs a chain reader the composition does not provide")
	// ErrSingleSource: a read of the "harmful if false" class rests on one
	// source and the policy does not acknowledge that (ADR 0006).
	ErrSingleSource = errors.New("this read rests on a single chain source: give a second independent source, or acknowledge the single source explicitly")
	// ErrSourcesDisagree: two independent sources gave different answers.
	ErrSourcesDisagree = errors.New("the chain sources disagree about the stake address")
	// ErrPoolNotRegistered: the pool a delegation names is not registered.
	ErrPoolNotRegistered = errors.New("the pool is not registered on the chain")
	// ErrDRepNotRegistered: the DRep a vote delegation names is not registered.
	ErrDRepNotRegistered = errors.New("the DRep is not registered on the chain")
	// ErrUnverified: a check could not be made and the policy does not allow going on.
	ErrUnverified = errors.New("a chain check could not be made")
	// ErrBadWord: an argument word names nothing.
	ErrBadWord = errors.New("the word names neither a stored artefact nor a valid id")

	// Aliases of the pipeline's refusals.
	ErrDeclined      = txflow.ErrDeclined
	ErrNoConfirmer   = txflow.ErrNoConfirmer
	ErrNoSigner      = txflow.ErrNoSigner
	ErrMisconfigured = txflow.ErrMisconfigured
)

// ApprovalPolicy and its values are those of txflow (and wallet): skipping
// the confirmation is explicit and recorded.
type ApprovalPolicy = txflow.ApprovalPolicy

// Approval values.
const (
	ApprovalAsk  = txflow.ApprovalAsk
	ApprovalSkip = txflow.ApprovalSkip
)

// SourcePolicy says what the use case does with a read of the "harmful if
// false" class (ADR 0006): the reward balance before a deregistration, the
// deposit a refund rests on, the registration state of a pool.
type SourcePolicy int

const (
	// RequireCorroboration is the zero value: such a read needs a second,
	// independent source that agrees; one source is refused.
	RequireCorroboration SourcePolicy = iota
	// SingleSourceAcknowledged goes on with one source. The result and the
	// operator's summary name it; it is the explicit confirmation that
	// the ADR requires and is the caller's to audit-log.
	SingleSourceAcknowledged
)

// Base is what the transaction use cases share. The embedded Pipeline holds
// the signing and ledger ports and exactly one of Submitter and Queue.
type Base struct {
	Store     ports.Store
	Addresses ports.AddressInspector
	Params    ports.ProtocolParametersReader
	Tip       ports.TipReader
	Utxos     ports.UtxoReader
	Pipeline  txflow.Pipeline

	// NetworkID is the network the addresses must belong to.
	NetworkID uint8
	// DefTTL is the number of slots of validity; zero means the default.
	DefTTL uint64
	// Selection chooses the inputs; empty means SelectAll.
	Selection txbuild.SelectionStrategy
	// Files and Encrypter are needed only by a request with Extras that name
	// metadata files or ask for message encryption.
	Files     ports.MetadataFileReader
	Encrypter ports.MessageEncrypter
}

// Result is what a transaction use case did. Nothing in it is secret.
type Result struct {
	txflow.Result
	Certificate stk.Certificate
	// Deposit is the key deposit paid and Refund the key deposit refunded.
	Deposit chain.Lovelace
	Refund  chain.Lovelace
	// Sources names the chain sources the checks and amounts came from.
	Sources []chain.Source
	// SingleSource is true when a read of the harmful class rested on one
	// source, acknowledged by the policy.
	SingleSource bool
	// Unchecked lists the chain checks that were not made, with the reason.
	Unchecked []string
}

// ---- store ---------------------------------------------------------------

// walletName applies upstream's stake-name rule: `.staking` is appended when
// absent, so `owner` and `owner.staking` are the same account. The result is
// the wallet name the artefacts are kept under (`owner`); a directory part
// cannot name an artefact (hazard H7).
//
// spec: SPO-03b-IF-001, SPO-08b-IF-001, SPO-06-IF-001, SPO-22b-IF-001, SPO-08a-IF-001, SPO-05b-IF-002, SPO-22a-IF-001
func walletName(s string) (string, error) {
	s = strings.TrimSuffix(strings.TrimPrefix(s, "./"), ".addr")
	s = strings.TrimSuffix(s, ".staking")
	if s == "" || strings.ContainsAny(s, "/\\") {
		return "", fmt.Errorf("%w: %q", ErrBadWord, s)
	}
	return s, nil
}

// payerName drops `.addr` and a leading `./` (SPO-Pfiles-IN-001).
func payerName(s string) (string, error) {
	s = strings.TrimSuffix(strings.TrimPrefix(s, "./"), ".addr")
	if s == "" || strings.ContainsAny(s, "/\\") {
		return "", fmt.Errorf("%w: %q", ErrBadWord, s)
	}
	return s, nil
}

// firstLine is the content of an address file (SPO-Pfiles-OUT-001).
func firstLine(b []byte) string {
	line, _, _ := strings.Cut(string(b), "\n")
	return strings.TrimSpace(line)
}

func get(r ports.Reader, ref ports.Ref) ([]byte, error) {
	b, err := r.Get(ref)
	if errors.Is(err, ports.ErrNotFound) {
		return nil, fmt.Errorf("%w: %s", ErrMissingFile, ref)
	}
	return b, err
}

// vkeyHash reads the key hash of a verification key envelope.
func vkeyHash(env []byte) (txbuild.KeyHash, error) {
	e, err := pool.ParseEnvelope(env)
	if err != nil {
		return txbuild.KeyHash{}, err
	}
	raw, err := e.Key32()
	if err != nil {
		return txbuild.KeyHash{}, err
	}
	return txbuild.HashKey(raw), nil
}

// payer is the paying address of a transaction with its payment key.
type payer struct {
	name string
	addr chain.Address
	hash txbuild.KeyHash
	key  custody.KeyRef
}

// readPayer reads and checks the paying address (SPO-Ptx-IN-001, SPO-Ptx-IN-002).
func (b Base) readPayer(r ports.Reader, name string) (payer, error) {
	ab, err := get(r, ports.Ref{Name: name, Kind: ports.AddrFile})
	if err != nil {
		return payer{}, err
	}
	key, err := keyring.Held(r, custody.RolePayment, name, ErrNoSigningKey)
	if err != nil {
		return payer{}, err
	}
	p := payer{name: name, addr: chain.Address(firstLine(ab)), key: key}
	info, err := b.Addresses.InspectAddress(p.addr)
	if err != nil {
		return payer{}, fmt.Errorf("paying address: %w", err)
	}
	if !info.Kind.IsPayment() || info.PaymentKeyHash == nil {
		return payer{}, fmt.Errorf("%w: %s", ErrSourceNotKey, name)
	}
	if info.NetworkID != b.NetworkID {
		return payer{}, fmt.Errorf("%w: the paying address %s", ErrNetworkMismatch, name)
	}
	p.hash = *info.PaymentKeyHash
	return p, nil
}

// checkStakeAddress verifies that the address is a stake address of this
// network with a key credential, and returns its key hash.
//
// spec: SPO-03b-PRE-001, SPO-08b-PRE-001, SPO-08a-IN-001, SPO-03c-IF-003
func (b Base) checkStakeAddress(addr chain.StakeAddress) (stk.KeyHash, error) {
	info, err := b.Addresses.InspectAddress(chain.Address(addr))
	if err != nil {
		return stk.KeyHash{}, fmt.Errorf("%w: %v", ErrNotStakeAddress, err)
	}
	if info.Kind != ports.AddrReward || info.StakeKeyHash == nil {
		return stk.KeyHash{}, fmt.Errorf("%w: %s", ErrNotStakeAddress, addr)
	}
	if info.NetworkID != b.NetworkID {
		return stk.KeyHash{}, fmt.Errorf("%w: the stake address", ErrNetworkMismatch)
	}
	return stk.KeyHash(*info.StakeKeyHash), nil
}

// ---- chain reads -----------------------------------------------------------

// Reads of the stake account. Primary is the source the answer comes from;
// CrossCheck is an optional second, independent source. A read of the
// harmful class (ADR 0006) needs them to agree, or the policy to
// acknowledge the single source.
type accountReads struct {
	Primary    ports.RewardAccountReader
	CrossCheck ports.RewardAccountReader
	Policy     SourcePolicy
	// OnSingle records an acknowledged single source before the use case goes
	// on (ADR 0006). Nil with Policy SingleSourceAcknowledged refuses.
	OnSingle ports.SingleSourceHook
}

type accountAnswer struct {
	Account stk.Account
	Known   stk.Known
	Sources []chain.Source
	Single  bool
	// Notes say what the answer rests on one source for although two agreed:
	// a figure the second source does not state (the deposit of a Blockfrost
	// account), which the summary must show.
	Notes []string
}

// read answers what the chain says about a stake address. Unknown is an
// error and never becomes "not registered". When harmful is true the
// ADR 0006 rule applies. A failed reader is an error, not exit 0 (hazard H3).
//
// spec: SPO-03b-PRE-003, SPO-08a-PRE-001, SPO-08b-EXT-001, SPO-01claimRewards-MODE-002
func (a accountReads) read(ctx context.Context, addr chain.StakeAddress, harmful bool) (accountAnswer, error) {
	if a.Primary == nil {
		return accountAnswer{}, ErrNoChainReader
	}
	r, err := a.Primary.RewardAccount(ctx, addr)
	if err != nil {
		return accountAnswer{}, fmt.Errorf("the stake address state from %s: %w", a.Primary.Source(), err)
	}
	acc, known, err := stk.FromReading(r)
	if err != nil {
		return accountAnswer{}, fmt.Errorf("%s: %w", a.Primary.Source(), err)
	}
	out := accountAnswer{Account: acc, Known: known, Sources: []chain.Source{a.Primary.Source()}}
	if !harmful {
		return out, nil
	}
	corroborated := false
	if a.CrossCheck != nil {
		r2, err := a.CrossCheck.RewardAccount(ctx, addr)
		if err != nil {
			return accountAnswer{}, fmt.Errorf("the stake address state from %s: %w", a.CrossCheck.Source(), err)
		}
		if !r2.IsUnknown() {
			if diff := compareAccounts(r, r2); diff != "" {
				return accountAnswer{}, fmt.Errorf("%w: %s says %s, %s says %s (%s)", ErrSourcesDisagree,
					a.Primary.Source(), describeAccount(r), a.CrossCheck.Source(), describeAccount(r2), diff)
			}
			corroborated = true
			out.Sources = append(out.Sources, a.CrossCheck.Source())
			out.Notes = append(out.Notes, depositNote(r, r2, a.Primary.Source(), a.CrossCheck.Source())...)
		} else if a.Policy != SingleSourceAcknowledged {
			return accountAnswer{}, fmt.Errorf("%w: %s says %s, but %s did not answer: %s", ErrSingleSource,
				a.Primary.Source(), describeAccount(r), a.CrossCheck.Source(), r2.Why())
		}
	}
	if !corroborated {
		if a.Policy != SingleSourceAcknowledged {
			return accountAnswer{}, fmt.Errorf("%w: %s", ErrSingleSource, a.Primary.Source())
		}
		if err := a.OnSingle.Accept(ctx, "the reward balance and stake deposit", a.Primary.Source()); err != nil {
			return accountAnswer{}, err
		}
		out.Single = true
	}
	return out, nil
}

// depositNote is the statement that a deposit amount rests on the first
// provider although both agreed on the rest: the second does not state
// deposits, so nothing corroborated the figure the refund is computed from. A
// wrong amount is refused by the ledger, which the note says.
func depositNote(first, second chain.Reading[chain.RewardAccount], firstSrc, secondSrc chain.Source) []string {
	a, ok := first.Get()
	if !ok {
		return nil
	}
	d, stated := a.Deposit.Get()
	if !stated {
		return nil
	}
	if b, ok := second.Get(); ok && !b.Deposit.IsUnknown() {
		return nil
	}
	return []string{fmt.Sprintf("deposit %d lovelace from %s only; %s does not state deposits; the ledger refuses a wrong amount", d, firstSrc, secondSrc)}
}
