package poolops

import (
	"context"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/app/keyring"
	"github.com/mochipool/workbench/spo/internal/app/opcounter"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals of IssueOperationalCertificate.
var (
	// ErrNoColdKey: neither a cold signing key nor a hardware signing file.
	ErrNoColdKey = errors.New("the pool has no cold signing key (.node.skey) or hardware signing file (.node.hwsfile)")
	// ErrNoColdVKey: the cold verification key is missing.
	ErrNoColdVKey = errors.New("the pool's cold verification key (.node.vkey) is missing")
	// ErrNoKesVKey: the waiting KES verification key is missing.
	ErrNoKesVKey = errors.New("the waiting KES verification key is missing")
	// ErrNoIssueCounter: the cold issue counter does not exist. Create it
	// with CreateIssueCounter, or pass a counter override.
	ErrNoIssueCounter = errors.New("the pool's operational certificate issue counter (.node.counter) does not exist")
	// ErrCounterKeyMismatch: the stored counter belongs to another cold key.
	ErrCounterKeyMismatch = errors.New("the issue counter belongs to a different cold verification key")
	// ErrChainUnverified: the chain could not be consulted and the caller
	// did not ask for an unverified issue.
	ErrChainUnverified = errors.New("the operational certificate counter on the chain could not be determined")
	// ErrOpCertSingleSource: the counter would rest on one provider and the
	// caller did not acknowledge that (--single-source). A certificate
	// issued from a wrong counter gets the pool's blocks rejected, so one
	// unchecked answer is not enough (ADR 0006, N7).
	ErrOpCertSingleSource = errors.New("the operational certificate counter rests on a single provider: configure a second independent provider, or acknowledge the single source with --single-source")
	// ErrNoSigner: the signer for the cold key cannot issue certificates.
	ErrNoSigner = errors.New("the signer for the cold key cannot issue operational certificates")
)

// CounterMismatchError means the certificate was issued with a counter the
// chain does not accept. Nothing was written. Run again with
// IssueOptions.CounterOverride set to Required.
type CounterMismatchError struct {
	Issued   uint64
	Required uint64
}

func (e *CounterMismatchError) Error() string {
	return fmt.Sprintf("the chain requires operational certificate counter %d, not %d; nothing was written; run again with counter %d",
		e.Required, e.Issued, e.Required)
}

// IssueOperationalCertificate signs the waiting KES key with the pool's cold
// key (upstream 04d_genNodeOpCert). There is one workflow: whether the cold
// key is in the vault or on a device is the signer's business (ADR 0008).
type IssueOperationalCertificate struct {
	Store   ports.NamedStore
	Signers ports.SignerDirectory
	Tip     ports.TipReader
	Genesis ports.GenesisReader
	// Counters reads the counter the chain has seen for the pool.
	Counters ports.OpCertCounterReader
	// Cross is an optional second, independent source of the counter (ADR
	// 0006). When set, the counter is used only if it agrees with Counters
	// (opcounter.Corroborate); SingleSource acknowledges a second source that
	// does not answer.
	Cross        ports.OpCertCounterReader
	SingleSource bool
	// OnSingle records an accepted single source before the certificate is
	// signed or any file written; required when SingleSource is true.
	OnSingle ports.SingleSourceHook
	Clock    ports.Clock
	// AllowUnverified lets the issue proceed when the chain was not
	// consulted (Unknown). It is the offline mode: the caller states that no
	// chain check is possible. Unknown is never read as "no blocks".
	AllowUnverified bool
}

// IssueOptions are the optional inputs.
type IssueOptions struct {
	// CounterOverride replaces the stored issue counter for this issue. It
	// is upstream's second argument and its correction prompt, as an
	// explicit option instead of a question.
	CounterOverride *uint64
}

// OpCertIssued is the result. Nothing in it is secret.
type OpCertIssued struct {
	Pool      string
	KesNumber int
	Counter   uint64 // the counter the certificate carries
	KesPeriod uint64
	Expiry    pool.KesExpiry
	OpCert    []byte // the text envelope as stored
	// Verified is false when the chain was not consulted. The operator must
	// check the certificate against the chain before it is used.
	Verified bool
	// Source names the provider(s) the counter on the chain was read from;
	// empty when the chain was not consulted.
	Source chain.Source
	// SingleSource is true when the counter rests on one provider and the
	// caller acknowledged that.
	SingleSource bool
}

// snapshot is what the issue was planned from; the commit re-reads it.
type issueSnapshot struct {
	state    pool.KesState
	number   int
	coldVKey []byte
	kesVKey  []byte
	counter  []byte // raw counter file; nil when absent
	coldKey  custody.KeyRef
}

// Run issues the certificate and, only when everything succeeded, stores it
// together with the advanced counters.
func (uc IssueOperationalCertificate) Run(ctx context.Context, poolName string, opts IssueOptions) (OpCertIssued, error) {
	var snap issueSnapshot
	if err := uc.Store.View(ctx, func(r ports.NamedReader) error {
		var err error
		snap, err = loadIssueSnapshot(r, poolName)
		return err
	}); err != nil {
		return OpCertIssued{}, err
	}

	// The counter: an explicit override, else the stored one.
	var counter uint64
	switch {
	case opts.CounterOverride != nil:
		counter = *opts.CounterOverride
	case snap.counter == nil:
		return OpCertIssued{}, ErrNoIssueCounter
	default:
		c, err := pool.ParseIssueCounter(snap.counter)
		if err != nil {
			return OpCertIssued{}, err
		}
		if string(c.ColdVKey[:]) != string(snap.coldVKey) {
			return OpCertIssued{}, ErrCounterKeyMismatch
		}
		counter = c.Next
	}

	// Who holds the cold key, and can they sign? Asked before any effect.
	ref := snap.coldKey
	cold, err := custody.As[custody.PoolCold](ref)
	if err != nil {
		return OpCertIssued{}, err
	}
	if _, err := ports.PlanSignatures(uc.Signers, []custody.Slot{{
		Label:  "operational certificate",
		Key:    ref,
		Demand: custody.Demand{Role: custody.RolePoolCold, Operation: custody.OpIssueOpCert},
	}}); err != nil {
		return OpCertIssued{}, err
	}
	signer, err := ports.SignerForOperation(uc.Signers, ref, custody.OpIssueOpCert)
	if err != nil {
		return OpCertIssued{}, err
	}
	issuer, ok := signer.(ports.OpCertIssuer)
	if !ok {
		return OpCertIssued{}, ErrNoSigner
	}

	tip, err := uc.Tip.Tip(ctx)
	if err != nil {
		return OpCertIssued{}, fmt.Errorf("current slot: %w", err)
	}
	genesis, err := uc.Genesis.Genesis(ctx)
	if err != nil {
		return OpCertIssued{}, fmt.Errorf("genesis: %w", err)
	}
	period, err := pool.KesPeriod(genesis, tip.Slot)
	if err != nil {
		return OpCertIssued{}, err
	}
	expiry, err := pool.NewKesExpiry(genesis, snap.number, period, uc.Clock.Now())
	if err != nil {
		return OpCertIssued{}, err
	}

	// Check the counter against the chain before asking for a signature: a
	// device or a remote party is not bothered for a certificate that would
	// be refused anyway.
	verified, src, single, err := uc.checkChain(ctx, snap.coldVKey, counter)
	if err != nil {
		return OpCertIssued{}, err
	}

	cert, err := issuer.IssueOpCert(ctx, cold, ports.OpCertRequest{KesVKey: snap.kesVKey, Counter: counter, KesPeriod: period})
	if err != nil {
		return OpCertIssued{}, fmt.Errorf("issue operational certificate: %w", err)
	}
	// Whoever signed, the certificate is accepted only if it is over the KES
	// key, counter and period asked for and made by the demanded cold key.
	if err := verifyIssued(cert, snap.coldVKey, snap.kesVKey, counter, period); err != nil {
		return OpCertIssued{}, fmt.Errorf("the signer's operational certificate does not verify: %w", err)
	}

	var vk [32]byte
	copy(vk[:], snap.coldVKey)
	next := pool.IssueCounter{Next: counter + 1, ColdVKey: vk}.Envelope()

	err = uc.Store.Update(ctx, func(w ports.NamedWriter) error {
		// The state may have moved while the signer and the chain were
		// consulted.
		now, err := loadIssueSnapshot(w, poolName)
		if err != nil {
			return err
		}
		if now.number != snap.number || string(now.counter) != string(snap.counter) {
			return ports.ErrConflict
		}
		state, _, err := now.state.Issue()
		if err != nil {
			return err
		}
		if err := w.Put(ports.NamedRef{Name: poolName, Kind: ports.OpCert, Num: snap.number}, cert); err != nil {
			return err
		}
		if err := w.Put(ports.NamedRef{Name: poolName, Kind: ports.NodeCounter}, next); err != nil {
			return err
		}
		if err := w.Put(ports.NamedRef{Name: poolName, Kind: ports.KesExpire}, expiry.JSON()); err != nil {
			return err
		}
		return w.Put(ports.NamedRef{Name: poolName, Kind: ports.KesCounterNext}, pool.FormatCounter(state.NextNumber()))
	})
	if err != nil {
		return OpCertIssued{}, err
	}
	return OpCertIssued{Pool: poolName, KesNumber: snap.number, Counter: counter, KesPeriod: period,
		Expiry: expiry, OpCert: cert, Verified: verified, Source: src, SingleSource: single}, nil
}

// checkChain compares the counter used with what the chain requires. It
// returns whether the chain was consulted, the source the answer rests on and
// whether it rests on one provider by acknowledgement. A counter read from one
// provider, with no second configured, is refused unless acknowledged: this
// command is the harmful one (a wrong counter gets the pool's blocks
// rejected).
func (uc IssueOperationalCertificate) checkChain(ctx context.Context, coldVKey []byte, counter uint64) (bool, chain.Source, bool, error) {
	id, err := chain.PoolIDOf(coldVKey)
	if err != nil {
		return false, "", false, err
	}
	reading, err := uc.Counters.OpCertCounter(ctx, id)
	if err != nil {
		reading = chain.Unknown[uint64](err.Error())
	}
	res := opcounter.Corroborate(ctx, uc.Counters, uc.Cross, id, reading, uc.SingleSource)
	reading = res.Reading
	single := res.Single
	var required uint64
	switch onChain, ok := reading.Get(); {
	case ok:
		required = onChain + 1
	case reading.IsNone():
		required = 0
	default:
		if uc.AllowUnverified {
			return false, "", false, nil
		}
		return false, "", false, fmt.Errorf("%w: %s", ErrChainUnverified, reading.Why())
	}
	if uc.Cross == nil {
		if !uc.SingleSource {
			return false, "", false, fmt.Errorf("%w: only %s was asked", ErrOpCertSingleSource, uc.Counters.Source())
		}
		single = true
	}
	if counter != required {
		return true, res.Source, single, &CounterMismatchError{Issued: counter, Required: required}
	}
	if single {
		if err := uc.OnSingle.Accept(ctx, "the operational certificate counter", res.Source); err != nil {
			return false, "", false, err
		}
	}
	return true, res.Source, single, nil
}

func loadIssueSnapshot(r ports.NamedReader, poolName string) (issueSnapshot, error) {
	var s issueSnapshot
	has := func(k ports.Kind) (bool, error) { return r.Exists(ports.NamedRef{Name: poolName, Kind: k}) }

	skey, err := has(ports.NodeSKey)
	if err != nil {
		return s, err
	}
	hws, err := has(ports.NodeHwsFile)
	if err != nil {
		return s, err
	}
	if !skey && !hws {
		return s, ErrNoColdKey
	}
	// SPO-04d-INV-004: with both stored, the directory prefers the vault.
	if s.coldKey, err = keyring.Resolve(r, custody.RolePoolCold, poolName); err != nil {
		return s, fmt.Errorf("%w: %v", ErrNoColdVKey, err)
	}

	vkeyFile, err := r.Get(ports.NamedRef{Name: poolName, Kind: ports.NodeVKey})
	if errors.Is(err, ports.ErrNotFound) {
		return s, ErrNoColdVKey
	}
	if err != nil {
		return s, err
	}
	env, err := pool.ParseEnvelope(vkeyFile)
	if err == nil {
		s.coldVKey, err = env.Key32()
	}
	if err != nil {
		return s, fmt.Errorf("%s.node.vkey: %w", poolName, err)
	}

	current, err := readCounter(r, ports.NamedRef{Name: poolName, Kind: ports.KesCounter})
	if err != nil {
		return s, err
	}
	next, err := readCounter(r, ports.NamedRef{Name: poolName, Kind: ports.KesCounterNext})
	if err != nil {
		return s, err
	}
	s.state = pool.NewKesState(current, next)
	_, s.number, err = s.state.Issue() // refuses; the state itself stays as stored
	if err != nil {
		return s, err
	}

	kesFile, err := r.Get(ports.NamedRef{Name: poolName, Kind: ports.KesVKey, Num: s.number})
	if errors.Is(err, ports.ErrNotFound) {
		return s, fmt.Errorf("%w: number %03d", ErrNoKesVKey, s.number)
	}
	if err != nil {
		return s, err
	}
	kenv, err := pool.ParseEnvelope(kesFile)
	if err == nil {
		s.kesVKey, err = kenv.Key32()
	}
	if err != nil {
		return s, fmt.Errorf("KES verification key %03d: %w", s.number, err)
	}

	s.counter, err = r.Get(ports.NamedRef{Name: poolName, Kind: ports.NodeCounter})
	if errors.Is(err, ports.ErrNotFound) {
		s.counter = nil
		return s, nil
	}
	return s, err
}

// CreateIssueCounter creates the cold issue counter of a pool that has none
// (upstream's "do you want to create a new one" prompt, PR-002, as a
// command). It never overwrites.
type CreateIssueCounter struct {
	Store ports.NamedStore
}

// ErrIssueCounterExists means the counter file is already there.
var ErrIssueCounterExists = errors.New("the issue counter already exists")

// Run creates the counter with the given next issue number.
func (uc CreateIssueCounter) Run(ctx context.Context, poolName string, value uint64) error {
	return uc.Store.Update(ctx, func(w ports.NamedWriter) error {
		ref := ports.NamedRef{Name: poolName, Kind: ports.NodeCounter}
		if exists, err := w.Exists(ref); err != nil {
			return err
		} else if exists {
			return ErrIssueCounterExists
		}
		b, err := w.Get(ports.NamedRef{Name: poolName, Kind: ports.NodeVKey})
		if errors.Is(err, ports.ErrNotFound) {
			return ErrNoColdVKey
		}
		if err != nil {
			return err
		}
		env, err := pool.ParseEnvelope(b)
		var raw []byte
		if err == nil {
			raw, err = env.Key32()
		}
		if err != nil {
			return fmt.Errorf("%s.node.vkey: %w", poolName, err)
		}
		var vk [32]byte
		copy(vk[:], raw)
		return w.Put(ref, pool.IssueCounter{Next: value, ColdVKey: vk}.Envelope())
	})
}

// verifyIssued checks a returned operational certificate with custody's
// verifier against the demanded cold key (by identity) and the demanded KES
// key, counter and period.
func verifyIssued(cert, coldVKey, kesVKey []byte, counter, period uint64) error {
	oc, err := pool.ParseOpCert(cert)
	if err != nil {
		return err
	}
	want, err := identity.KeyHashOf(coldVKey)
	if err != nil {
		return err
	}
	return custody.VerifyOpCert(custody.OpCert{KesVKey: oc.KesVKey, Counter: oc.Counter, KesPeriod: oc.KesPeriod,
		ColdVKey: oc.ColdVKey, Signature: oc.Signature},
		&custody.OpCertAsk{KesVKey: kesVKey, Counter: counter, KesPeriod: period}, want)
}
