package query

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals of the opcert checks.
var (
	// ErrNoChain: the check needs a chain reader and the composition has none,
	// which is how offline mode shows here (SPO-04e-PRE-001).
	ErrNoChain = errors.New("this check needs access to the chain: use the online or the light mode, not the offline mode")
	// ErrNotSynced: the provider has not caught up (SPO-04e-PRE-002).
	ErrNotSynced = errors.New("the node or the provider is not synced with the chain")
	// ErrNoOpCert: the pool has no operational certificate stored.
	ErrNoOpCert = errors.New("the pool has no operational certificate (.node-NNN.opcert); create one with the KES key and certificate commands")
	// ErrPoolUnresolved: the reference names no pool id (SPO-04e-IF-005).
	ErrPoolUnresolved = errors.New("the reference is neither a pool id nor the name of a pool with a stored pool id")
)

// CounterCheck selects what the certificate's counter is compared with.
type CounterCheck string

// The two checks of SPO-04e-IF-001.
const (
	// CheckCurrent: the certificate on disk is the one the chain has seen
	// last (the counter equals the on-chain counter).
	CheckCurrent CounterCheck = "current"
	// CheckNext: the certificate on disk is the next one the chain will
	// accept (the counter is the on-chain counter plus one).
	CheckNext CounterCheck = "next"
)

// Status is the verdict of a check. It is a value to branch on, not a
// printed word; the exit status of a script is not the verdict
// (SPO-04e-INV-004: upstream exits 0 for every completed check, FALSE
// included, and a caller that gated on the exit status accepted a wrong
// certificate).
type Status string

// Statuses.
const (
	// StatusOK: the check passed.
	StatusOK Status = "ok"
	// StatusFalse: the check completed and failed; Reasons say why.
	StatusFalse Status = "false"
	// StatusUnknown: the chain could not be consulted, or answered
	// something that is not a counter. It is never read as "no block made"
	// (hazard H1; ADR 0006): upstream reads a failed Koios request in light
	// mode as no block yet and prints a confident verdict
	// (SPO-04e-MODE-004's quirk).
	StatusUnknown Status = "unknown"
)

// Reason says why a check is FALSE.
type Reason string

// Reasons.
const (
	// ReasonNotLatestPlusOne: next check, the counter is not the on-chain
	// counter plus one (SPO-04e-OUT-002).
	ReasonNotLatestPlusOne Reason = "the counter is not the latest on the chain plus one"
	// ReasonCounterMismatch: current check, the counter is not the on-chain
	// counter (SPO-04e-OUT-003).
	ReasonCounterMismatch Reason = "the on-chain counter is not equal to the counter of the file"
	// ReasonKesOutOfRange: the KES period of the tip is outside the
	// certificate's window (SPO-04e-OUT-001).
	ReasonKesOutOfRange Reason = "the current KES period is outside the validity of the certificate"
)

// OpCertCheck is the subject of the check: a certificate given as the text of
// an opcert file, or a stored one (the newest of the pool, or a numbered one).
type OpCertCheck struct {
	// OpCert is the content of an opcert file. When empty, Pool names the
	// pool whose stored certificate is used.
	OpCert []byte
	Pool   string
	// Number selects a stored certificate; nil is the newest
	// (SPO-04e-IF-004).
	Number *int
	Check  CounterCheck
}

// OpCertVerdict is the typed result.
type OpCertVerdict struct {
	// Status is the overall verdict: OK when the counter check and the KES
	// check both pass; FALSE when one of them fails; Unknown when the counter
	// could not be read (the KES check is still made and reported).
	Status  Status
	Reasons []Reason
	// Counter is the counter check on its own: OK, FALSE or Unknown.
	Counter Status
	// KES is the KES window check on its own: OK or FALSE.
	KES Status

	PoolID chain.PoolID
	Number *int // the stored certificate's number, when it was looked up
	// OnDisk is the certificate's issue counter; OnChain what the chain has
	// seen (None: the pool has made no block; Unknown: not known).
	OnDisk  uint64
	OnChain chain.Reading[uint64]
	// NextRequired is the counter the next certificate needs: the on-chain
	// counter plus one, or 0 when the chain has seen none. Set only when the
	// chain answered.
	NextRequired *uint64
	// NoBlockYet is true for the current check of a pool that made no block
	// with a certificate of counter 0 (SPO-04e-OUT-003).
	NoBlockYet bool
	// Window is the KES window (SPO-04e-INV-002, SPO-04e-INV-003).
	Window  pool.KesWindow
	TipSlot uint64
	Source  chain.Source
}

// CheckOpCert checks an operational certificate against the chain (upstream
// 04e_checkNodeOpCert with two arguments).
type CheckOpCert struct {
	Store ports.Store
	// Tip, Genesis and Counters are nil in offline mode, which refuses
	// (SPO-04e-PRE-001).
	Tip      ports.TipReader
	Genesis  ports.GenesisReader
	Counters ports.OpCertCounterReader
	// Sync is optional: full online mode checks it (SPO-04e-PRE-002); the
	// light mode has no sync check.
	Sync ports.SyncChecker
}

// Run reads the certificate, the tip, the genesis and the on-chain counter and
// returns the verdict as data. A FALSE verdict is not an error; an Unknown one
// is not either, it is the answer "cannot verify". Errors are failures to ask:
// offline mode, a certificate that cannot be read, a provider that failed
// outright.
//
// spec: SPO-04e-IF-001, SPO-04e-IF-004, SPO-04e-IN-001, SPO-04e-IN-002, SPO-04e-PRE-001, SPO-04e-PRE-002,
// spec: SPO-04e-PRE-003, SPO-04e-EXT-001, SPO-04e-INV-001, SPO-04e-INV-002, SPO-04e-INV-003, SPO-04e-INV-004,
// spec: SPO-04e-OUT-001, SPO-04e-OUT-002, SPO-04e-OUT-003, SPO-04e-MODE-001, SPO-04e-MODE-003, SPO-04e-MODE-004,
// spec: SPO-04e-MODE-005
func (uc CheckOpCert) Run(ctx context.Context, req OpCertCheck) (OpCertVerdict, error) {
	if req.Check != CheckCurrent && req.Check != CheckNext {
		return OpCertVerdict{}, fmt.Errorf("the check is %q or %q", CheckCurrent, CheckNext)
	}
	if uc.Tip == nil || uc.Genesis == nil || uc.Counters == nil {
		return OpCertVerdict{}, ErrNoChain
	}
	oc, num, err := uc.certificate(ctx, req)
	if err != nil {
		return OpCertVerdict{}, err
	}
	id, err := oc.PoolID()
	if err != nil {
		return OpCertVerdict{}, err
	}
	if uc.Sync != nil {
		ok, err := uc.Sync.Synced(ctx)
		if err != nil {
			return OpCertVerdict{}, fmt.Errorf("the sync state from %s: %w", uc.Sync.Source(), err)
		}
		if !ok {
			return OpCertVerdict{}, fmt.Errorf("%w: %s", ErrNotSynced, uc.Sync.Source())
		}
	}
	tip, err := uc.Tip.Tip(ctx)
	if err != nil {
		return OpCertVerdict{}, fmt.Errorf("the tip from %s: %w", uc.Tip.Source(), err)
	}
	genesis, err := uc.Genesis.Genesis(ctx)
	if err != nil {
		return OpCertVerdict{}, fmt.Errorf("genesis: %w", err)
	}
	win, err := pool.CheckKesWindow(genesis, tip.Slot, oc.KesPeriod)
	if err != nil {
		return OpCertVerdict{}, err
	}
	onChain, err := uc.Counters.OpCertCounter(ctx, id)
	if err != nil {
		onChain = chain.Unknown[uint64](err.Error())
	}

	v := OpCertVerdict{PoolID: id, Number: num, OnDisk: oc.Counter, OnChain: onChain, Window: win, TipSlot: tip.Slot,
		Source: uc.Counters.Source(), KES: StatusOK, Counter: StatusUnknown}
	if !win.InRange {
		v.KES = StatusFalse
		v.Reasons = append(v.Reasons, ReasonKesOutOfRange)
	}
	// The counter: Unknown is never -1 (SPO-04e-INV-001 is for a reading the
	// chain gave; a failed request gives no reading).
	switch c, ok := onChain.Get(); {
	case ok:
		next := c + 1
		v.NextRequired = &next
		v.Counter = counterVerdict(req.Check, oc.Counter, next, c, &v)
	case onChain.IsNone():
		zero := uint64(0)
		v.NextRequired = &zero
		switch req.Check {
		case CheckNext:
			v.Counter = pass(oc.Counter == 0, ReasonNotLatestPlusOne, &v)
		default:
			v.NoBlockYet = oc.Counter == 0
			v.Counter = pass(oc.Counter == 0, ReasonCounterMismatch, &v)
		}
	}
	switch {
	case v.Counter == StatusUnknown:
		v.Status = StatusUnknown
		if v.KES == StatusFalse {
			// A failed KES check is a FALSE whatever the counter says.
			v.Status = StatusFalse
		}
	case v.Counter == StatusFalse || v.KES == StatusFalse:
		v.Status = StatusFalse
	default:
		v.Status = StatusOK
	}
	return v, nil
}

func pass(ok bool, why Reason, v *OpCertVerdict) Status {
	if ok {
		return StatusOK
	}
	v.Reasons = append(v.Reasons, why)
	return StatusFalse
}

func counterVerdict(check CounterCheck, onDisk, nextChain, onChain uint64, v *OpCertVerdict) Status {
	if check == CheckNext {
		return pass(onDisk == nextChain, ReasonNotLatestPlusOne, v)
	}
	return pass(onDisk == onChain, ReasonCounterMismatch, v)
}

// certificate finds and decodes the subject.
func (uc CheckOpCert) certificate(ctx context.Context, req OpCertCheck) (pool.OpCert, *int, error) {
	if len(req.OpCert) > 0 {
		oc, err := pool.ParseOpCert(req.OpCert)
		return oc, nil, err
	}
	if uc.Store == nil || req.Pool == "" {
		return pool.OpCert{}, nil, errors.New("the check needs an opcert file or the name of a pool with a stored certificate")
	}
	name := strings.TrimPrefix(req.Pool, "./")
	var raw []byte
	var num int
	err := uc.Store.View(ctx, func(r ports.Reader) error {
		first, last := 0, 0
		if req.Number != nil {
			first, last = *req.Number, *req.Number
		} else {
			// The newest: the highest number below the next KES counter.
			// Probe downwards; the store has no listing.
			n, err := readInt(r, ports.Ref{Name: name, Kind: ports.KesCounterNext})
			if err != nil {
				return err
			}
			c, err := readInt(r, ports.Ref{Name: name, Kind: ports.KesCounter})
			if err != nil {
				return err
			}
			last = max(n, c)
			first = 0
		}
		for i := last; i >= first; i-- {
			b, err := r.Get(ports.Ref{Name: name, Kind: ports.OpCert, Num: i})
			if errors.Is(err, ports.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			raw, num = b, i
			return nil
		}
		return fmt.Errorf("%w: %s", ErrNoOpCert, name)
	})
	if err != nil {
		return pool.OpCert{}, nil, err
	}
	oc, err := pool.ParseOpCert(raw)
	return oc, &num, err
}

// readInt reads a KES counter file; a missing one is 0.
func readInt(r ports.Reader, ref ports.Ref) (int, error) {
	b, err := r.Get(ref)
	if errors.Is(err, ports.ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return pool.ParseCounter(b)
}

// QueryOpCertCounter asks the chain for the last operational certificate
// counter of a pool, and what the next certificate needs (upstream
// 04e_checkNodeOpCert with one argument).
type QueryOpCertCounter struct {
	Store    ports.Store
	Counters ports.OpCertCounterReader
	// Pools adds the pool's name and ticker; optional.
	Pools ports.PoolStateReader
}

// CounterReport is the answer.
type CounterReport struct {
	PoolID chain.PoolID
	Bech32 string
	// Counter is the last counter the chain has seen: None when the pool has
	// made no block, Unknown when the chain could not say.
	Counter chain.Reading[uint64]
	// Next is the counter the next certificate needs: the counter plus one,
	// 0 for a pool with no block; nil when Counter is Unknown.
	Next   *uint64
	Name   string
	Ticker string
	Source chain.Source
}

// Run resolves the reference in the order of SPO-04e-IF-005 (56 hex digits,
// `pool1...`, a pool name with a stored `.pool.id-bech`) and asks the chain.
// An answer the chain did not give is Unknown in the report, and the report is
// still returned: a pool Koios does not know is "cannot verify", never "no
// block, counter 0" (SPO-04e-OUT-004's null counter is None, an empty answer is
// not).
//
// spec: SPO-04e-IF-005, SPO-04e-PRE-001, SPO-04e-PRE-004, SPO-04e-EXT-002, SPO-04e-OUT-004
func (uc QueryOpCertCounter) Run(ctx context.Context, ref string) (CounterReport, error) {
	if uc.Counters == nil {
		return CounterReport{}, ErrNoChain
	}
	id, err := uc.resolve(ctx, ref)
	if err != nil {
		return CounterReport{}, err
	}
	rep := CounterReport{PoolID: id, Bech32: id.Bech32(), Source: uc.Counters.Source()}
	rep.Counter, err = uc.Counters.OpCertCounter(ctx, id)
	if err != nil {
		rep.Counter = chain.Unknown[uint64](err.Error())
	}
	switch c, ok := rep.Counter.Get(); {
	case ok:
		n := c + 1
		rep.Next = &n
	case rep.Counter.IsNone():
		z := uint64(0)
		rep.Next = &z
	}
	if uc.Pools != nil {
		if pr, perr := uc.Pools.PoolState(ctx, id); perr == nil {
			if st, ok := pr.Get(); ok {
				rep.Name, rep.Ticker = st.Name, st.Ticker
			}
		}
	}
	return rep, nil
}

func (uc QueryOpCertCounter) resolve(ctx context.Context, ref string) (chain.PoolID, error) {
	ref = strings.TrimSpace(ref)
	if w, err := stake.ParsePoolWord(ref); err != nil {
		return chain.PoolID{}, fmt.Errorf("%w: %v", ErrPoolUnresolved, err)
	} else if w.IsID {
		return w.Pool, nil
	}
	name := strings.TrimPrefix(ref, "./")
	for _, suf := range []string{".id-bech", ".pool", ".json"} {
		name = strings.TrimSuffix(name, suf)
	}
	if uc.Store == nil || name == "" || strings.ContainsAny(name, "/\\") {
		return chain.PoolID{}, fmt.Errorf("%w: %q", ErrPoolUnresolved, ref)
	}
	var id chain.PoolID
	err := uc.Store.View(ctx, func(r ports.Reader) error {
		b, err := r.Get(ports.Ref{Name: name, Kind: ports.PoolIDBechFile})
		if errors.Is(err, ports.ErrNotFound) || errors.Is(err, ports.ErrInvalidRef) {
			return fmt.Errorf("%w: %q", ErrPoolUnresolved, ref)
		}
		if err != nil {
			return err
		}
		id, err = chain.ParsePoolBech32(strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0]))
		if err != nil {
			return fmt.Errorf("%w: %s.pool.id-bech: %v", ErrPoolUnresolved, name, err)
		}
		return nil
	})
	return id, err
}
