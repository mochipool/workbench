package multisig

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Coordinator is the party that builds a transaction and collects the
// signatures.
type Coordinator struct {
	Node
	// TxIDs recomputes the body hash of a stored body: it is never trusted.
	TxIDs ports.TxIDCalculator
	// NetworkMagic is the workspace's network, put in every request.
	NetworkMagic uint32
	// MaxTxSize is the protocol's maxTxSize; zero takes the upper bound
	// party.DefaultMaxTxSize. The body and its auxiliary data together may not
	// exceed it, which is checked before a request is sealed
	// (SPO-Xparty-INV-008).
	MaxTxSize int
	// Complete runs the use case that assembles and submits (or queues) a
	// complete collection: for a pool registration, RegisterPool.Run on the
	// stored collection (SPO-Xparty-OUT-005). It is a callback so that this
	// package does not depend on the pool use cases; nil leaves a complete
	// collection for the operator to finish.
	Complete func(ctx context.Context, ref CollectionRef) (Completion, error)
}

// Completion is what Complete reports.
type Completion struct {
	Submitted bool
	TxID      chain.TxID
}

// Refusals of the coordinator.
var (
	// ErrColdKeyOverNetwork is SPO-Xparty-PRE-004: a request for a pool cold
	// key is not created for a network transport.
	ErrColdKeyOverNetwork = errors.New("a request for a pool cold key is not sent over a network transport")
	// ErrUnassigned: the slot has no remote party (a revoked party's slot).
	ErrUnassigned = errors.New("the slot is assigned to no party")
	// ErrNotSigner is SPO-Xparty-PRE-003: the slot's party is not an active
	// enrolled signer for the pools the body concerns.
	ErrNotSigner = errors.New("the slot's party is not an active enrolled signer for the pool")
	// ErrUndisplayable: the body has a part a remote signer is not shown, so
	// it would refuse it (SPO-Xparty-PR-002): the coordinator does not send it.
	ErrUndisplayable = errors.New("the body has a part that cannot be displayed in full")
	// ErrNotOpen: the collection is not OpenIncomplete (SPO-Xparty-INV-015).
	ErrNotOpen = errors.New("the collection is not open and incomplete")
	// ErrBodyHash is SPO-Xparty-INV-020: the stored body does not hash to
	// its id.
	ErrBodyHash = errors.New("the stored body does not hash to the collection's body id")
	// ErrCollectionExists: a standalone collection of that name is stored.
	ErrCollectionExists = errors.New("a witness collection of that name already exists")
)

// bodyOf returns the body map of a collection's transaction, checks that its
// hash is the id every witness is made over (SPO-Xparty-INV-020), and decodes
// it with the signer's own viewer: the coordinator never sends a body that a
// signer, running the same decoder and the same rules, would refuse to
// display. It also returns the auxiliary data the request must carry.
func (c Coordinator) bodyOf(coll pool.Collection) ([]byte, party.TxView, []byte, error) {
	body, err := c.Viewer.BodyOf(coll.Body.CBOR)
	if err != nil {
		return nil, party.TxView{}, nil, err
	}
	if h := blake2b.Sum256(body); h != [32]byte(coll.Body.ID) {
		return nil, party.TxView{}, nil, ErrBodyHash
	}
	v, err := c.Viewer.View(body)
	if err != nil {
		return nil, party.TxView{}, nil, err
	}
	if u := v.Undisplayable(); len(u) > 0 {
		return nil, party.TxView{}, nil, fmt.Errorf("%w: %s", ErrUndisplayable, strings.Join(u, "; "))
	}
	if err := v.CheckNetwork(party.NetworkIDOf(c.NetworkMagic)); err != nil {
		return nil, party.TxView{}, nil, err
	}
	aux, err := c.Viewer.AuxOf(coll.Body.CBOR)
	if err != nil {
		return nil, party.TxView{}, nil, err
	}
	if err := party.CheckAuxData(v, aux); err != nil {
		return nil, party.TxView{}, nil, err
	}
	limit := party.DefaultMaxTxSize
	if c.MaxTxSize > 0 {
		limit = min(c.MaxTxSize, limit)
	}
	if err := party.CheckTxSize(len(body), len(aux), limit); err != nil {
		return nil, party.TxView{}, nil, err
	}
	if len(aux) > 0 {
		if _, err := c.Viewer.ViewAux(aux); err != nil {
			return nil, party.TxView{}, nil, err
		}
	}
	return body, v, aux, nil
}

// assignable is SPO-Xparty-PRE-003 for one slot: a slot whose key a remote
// party holds names an active enrolled signer. What we ask of a signer is
// limited by the slot assignment and by the signer's own checks; the Scope
// recorded for a party is what it may ask of us (SPO-Xparty-INV-010) and is
// not read here.
func assignable(ps []party.Party, s pool.Slot) (party.Party, error) {
	if s.Party == "" {
		return party.Party{}, fmt.Errorf("%w: %s", ErrUnassigned, s.Name)
	}
	for _, p := range ps {
		if p.Name != s.Party {
			continue
		}
		if !p.Active() || !p.HasRole(party.RoleSigner) {
			return party.Party{}, fmt.Errorf("%w: %s is %s, roles %v", ErrNotSigner, p.Name, p.State, p.Roles)
		}
		return p, nil
	}
	return party.Party{}, fmt.Errorf("%w: %s is not enrolled", ErrNotSigner, s.Party)
}

// ---- opening ------------------------------------------------------------------

// OpenRequest is a prepared transaction of any use case, ready to be signed
// by several parties (SPO-Xparty-INV-013): the final body, one slot per
// signature, and the signer plan for the slots this machine signs.
type OpenRequest struct {
	// Name of the collection: letters, digits, '-', '_' and single dots.
	Name string
	Body txbuild.TxBody
	TTL  uint64
	// Slots in order, none filled. A remote slot names its party.
	Slots []pool.Slot
	// Local signs the slots whose holder this machine has; they are filled
	// through the same verification a remote response takes. A Prepared
	// with no slots is fine when every slot is remote.
	Local txflow.Prepared
}

// Open stores a new standalone collection, fills the local slots, and starts
// tracking it. It refuses a remote slot whose party is not an active
// enrolled signer (SPO-Xparty-PRE-003) and a body that does not hash to its
// id or that a signer could not display.
//
// spec: SPO-Xparty-PRE-003, SPO-Xparty-INV-012, SPO-Xparty-INV-013, SPO-Xparty-OUT-004
func (c Coordinator) Open(ctx context.Context, req OpenRequest) (CollectionRef, error) {
	ref := CollectionRef{Kind: KindStandalone, Name: req.Name}
	if _, err := c.collectionRef(ref); err != nil {
		return ref, err
	}
	if err := (ports.Ref{Name: req.Name, Kind: ports.MultisigCollection}).Validate(); err != nil {
		return ref, err
	}
	if id, err := c.TxIDs.TransactionID(req.Body.CBOR); err != nil || id != req.Body.ID {
		return ref, fmt.Errorf("%w: the body does not hash to its id", ErrBodyHash)
	}
	now := c.Clock.Now()
	slotNow, err := c.Chain.Slot(ctx, now)
	if err != nil {
		return ref, err
	}
	// The local witnesses are made before the transaction: a vault or a
	// device is not touched while the store is locked.
	sws, err := req.Local.Sign(ctx, req.Body)
	if err != nil {
		return ref, err
	}
	err = c.Store.Update(ctx, func(w ports.Writer) error {
		sref, _ := c.collectionRef(ref)
		if ok, err := w.Exists(sref); err != nil {
			return err
		} else if ok {
			return ErrCollectionExists
		}
		coll, err := pool.OpenCollection(pool.Collection{ID: uint64(now.Unix()), Type: pool.GenericTransaction, TTL: req.TTL,
			Body: req.Body, Slots: req.Slots})
		if err != nil {
			return err
		}
		_, _, _, err = c.bodyOf(coll)
		if err != nil {
			return err
		}
		_, ps, err := c.loadParties(w)
		if err != nil {
			return err
		}
		for _, s := range coll.Slots {
			if s.Holder == custody.HolderRemote {
				if _, err := assignable(ps, s); err != nil {
					return err
				}
			}
		}
		for _, sw := range sws {
			if coll, err = coll.Fill(pool.Fill{Slot: sw.Slot.Label, Witness: sw.Witness, ExpectVersion: coll.Version}, slotNow); err != nil {
				return err
			}
		}
		d, err := newStandalone()
		if err != nil {
			return err
		}
		l := loaded{ref: ref, coll: coll, desc: d}
		if err := c.saveCollection(w, l); err != nil {
			return err
		}
		st, err := readCoord(w)
		if err != nil {
			return err
		}
		id := collectionID(ref, coll)
		st.track(id, ref)
		if err := writeJSON(w, coordRef, st); err != nil {
			return err
		}
		return appendEvent(w, eventOf(now, "collection-opened", hexColl(id), 0, coll.Body.ID))
	})
	return ref, err
}

// ---- requesting ---------------------------------------------------------------

// RequestInput names the collection to ask signatures for.
type RequestInput struct {
	Ref CollectionRef
	// Purpose is shown to the signer as the coordinator's claim, apart from
	// what the signer decodes itself (SPO-Xparty-INV-011).
	Purpose string
	// Renew sends a new request for a slot that already has one outstanding.
	// The old request's response is refused as stale (SPO-Xparty-PRE-005).
	Renew bool
}

// SlotStatus is what RequestSignatures did for one slot.
type SlotStatus string

// The statuses.
const (
	SlotRequested        SlotStatus = "requested"
	SlotAlreadyRequested SlotStatus = "already-requested"
	SlotFilled           SlotStatus = "filled"
	SlotLocal            SlotStatus = "local" // the key is on this machine: not for a request
	SlotRefused          SlotStatus = "refused"
)

// SlotResult is the outcome for one slot. Err explains a refusal.
type SlotResult struct {
	Slot   int
	Name   string
	Party  string
	Status SlotStatus
	Err    error
}

// RequestSignatures builds one SigningRequest per unfilled slot assigned to
// an enrolled signer, seals it, stores it with the record of which request
// was last sent for the slot, and hands the outbox to the transport. The
// requests exist in the store before any is sent: a transport that cannot
// reach the signer now loses nothing (SPO-Xparty-SEC-003).
//
// A request for a pool cold key is refused for a network transport before it
// is sealed (SPO-Xparty-PRE-004); the file transport carries it.
//
// spec: SPO-Xparty-PRE-003, SPO-Xparty-PRE-004, SPO-Xparty-INV-009, SPO-Xparty-INV-012, SPO-Xparty-INV-013, SPO-Xparty-INV-020, SPO-Xparty-OUT-004, SPO-Xparty-SEC-002
func (c Coordinator) RequestSignatures(ctx context.Context, in RequestInput, tr Transport) ([]SlotResult, error) {
	if tr.Sender() != nil && !tr.Kind().Known() {
		return nil, ErrTransportKind
	}
	if c.Offline && tr.Kind() == ports.ViaNetwork {
		return nil, ErrOffline
	}
	local, err := c.Kit.Local(ctx)
	if err != nil {
		return nil, err
	}
	defer local.Destroy()
	now := c.Clock.Now()
	slotNow, err := c.Chain.Slot(ctx, now)
	if err != nil {
		return nil, err
	}
	var results []SlotResult
	err = c.Store.Update(ctx, func(w ports.Writer) error {
		results = nil
		l, err := c.loadCollection(w, c.TxIDs, in.Ref)
		if err != nil {
			return err
		}
		if st := l.coll.StateAtTip(slotNow); st != pool.CollectionOpenIncomplete {
			return fmt.Errorf("%w: it is %s", ErrNotOpen, st)
		}
		body, _, aux, err := c.bodyOf(l.coll)
		if err != nil {
			return err
		}
		ttlTime, err := c.Chain.SlotTime(ctx, l.coll.TTL)
		if err != nil {
			return err
		}
		// INV-009: no later than the time of the TTL slot, no later than 7
		// days after creation.
		expires := now.Add(party.MaxRequestLifetime)
		if ttlTime.Before(expires) {
			expires = ttlTime
		}
		expires = expires.Truncate(time.Second)
		if !expires.After(now) {
			return fmt.Errorf("%w: the ttl slot's time has passed", ErrNotOpen)
		}
		_, ps, err := c.loadParties(w)
		if err != nil {
			return err
		}
		st, err := readCoord(w)
		if err != nil {
			return err
		}
		id := collectionID(in.Ref, l.coll)
		cs := st.track(id, in.Ref)
		var items []OutItem
		for i, s := range l.coll.Slots {
			r := SlotResult{Slot: i, Name: s.Name, Party: s.Party}
			switch {
			case s.Filled():
				r.Status = SlotFilled
			case s.Holder != custody.HolderRemote:
				r.Status = SlotLocal
			default:
				p, err := assignable(ps, s)
				if err != nil {
					r.Status, r.Err = SlotRefused, err
					break
				}
				if s.Role == custody.RolePoolCold && !tr.Kind().IsFile() {
					r.Status, r.Err = SlotRefused, ErrColdKeyOverNetwork
					ev := eventOf(now, "request-not-created", hexColl(id), i, l.coll.Body.ID)
					ev.Peer, ev.Reason = p.Fingerprint.String(), ErrColdKeyOverNetwork.Error()
					if err := appendEvent(w, ev); err != nil {
						return err
					}
					break
				}
				ss := cs.Slots[i]
				if ss.LastRequest != "" && !in.Renew && ss.To == hexFP(p.Fingerprint) && ss.Expires > now.Unix() {
					r.Status = SlotAlreadyRequested
					break
				}
				req := party.SigningRequest{Collection: id, Slot: party.SlotID(i), KeyRole: s.Role, KeyHash: [28]byte(s.KeyHash),
					Operation: string(custody.OpWitnessTx), TxBody: body, BodyHash: [32]byte(l.coll.Body.ID), TTLSlot: l.coll.TTL,
					NetworkMagic: c.NetworkMagic, Purpose: in.Purpose, AuxData: aux}
				if err := party.CheckRequestExpiry(now, expires, ttlTime); err != nil {
					return err
				}
				env, mid, err := local.Seal(p.Identity, req, now, expires)
				if err != nil {
					r.Status, r.Err = SlotRefused, err
					break
				}
				cs.Slots[i] = slotState{LastRequest: hexMsg(mid), RequestedAt: now.Unix(), Expires: expires.Unix(), To: hexFP(p.Fingerprint)}
				items = append(items, OutItem{ID: hexMsg(mid), To: hexFP(p.Fingerprint), Type: string(party.TypeSigningRequest),
					Collection: hexColl(id), Slot: i, Expires: expires.Unix(), Envelope: env, ColdKey: s.Role == custody.RolePoolCold})
				ev := eventOf(now, "request-sealed", hexColl(id), i, l.coll.Body.ID)
				ev.Peer, ev.Detail = p.Fingerprint.String(), hexMsg(mid)
				if err := appendEvent(w, ev); err != nil {
					return err
				}
				r.Status = SlotRequested
			}
			results = append(results, r)
		}
		if err := writeJSON(w, coordRef, st); err != nil {
			return err
		}
		return enqueue(w, now, items...)
	})
	if err != nil {
		return nil, err
	}
	if tr.Sender() != nil {
		if _, err := (Outbox{Store: c.Store, Clock: c.Clock, Offline: c.Offline}).Flush(ctx, tr); err != nil {
			return results, err
		}
	}
	return results, nil
}

// ---- receiving ------------------------------------------------------------------

// authorise is step 8 of SPO-Xparty-PRE-002 for the coordinator: only the
// messages a coordinator receives, from a party the role rules allow, with a
// slot signer taken from the store and never from the message.
func (c Coordinator) authorise(r ports.Reader, st coordState, ps []party.Party, o ports.OpenedEnvelope, sender party.Party, t party.Type, b party.Body) error {
	var concern party.Concern
	switch m := b.(type) {
	case party.SigningResponse:
		concern = c.slotConcern(r, st, ps, m.Collection, m.Slot)
	case party.SigningRefusal:
		concern = c.slotConcern(r, st, ps, m.Collection, m.Slot)
	case party.Hello:
		if err := party.CheckHelloExpiry(o.Created(), o.Expires()); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: a coordinator does not receive a %s", party.ErrNotAuthorised, t)
	}
	return party.Authorise(sender, t, concern)
}

// slotConcern finds, in our own state, who signs the slot a response names.
func (c Coordinator) slotConcern(r ports.Reader, st coordState, ps []party.Party, cid party.CollectionID, slot party.SlotID) party.Concern {
	cs := st.find(cid)
	if cs == nil {
		return party.Concern{}
	}
	l, err := c.loadCollection(r, c.TxIDs, cs.Ref)
	if err != nil || collectionID(cs.Ref, l.coll) != cid || int(slot) >= len(l.coll.Slots) {
		return party.Concern{}
	}
	name := l.coll.Slots[slot].Party
	for _, p := range ps {
		if p.Name == name && name != "" {
			return party.Concern{SlotSigner: p.Fingerprint, HasSlotSigner: true}
		}
	}
	return party.Concern{}
}

// refusal is a refusal found inside a transaction: it rolls the transaction
// back and is recorded afterwards.
type refusal struct{ err error }

func (r *refusal) Error() string { return r.err.Error() }
func (r *refusal) Unwrap() error { return r.err }

// Handle takes one envelope that arrived by file or over a network and runs
// the whole of SPO-Xparty-PRE-002 (decrypt, version, sender, signature,
// recipient, window, replay, authorisation), then the message's effect. The
// replay entry, the effect and the audit event commit in one Store.Update
// (SPO-Xparty-INV-007). A refusal is recorded with its reason and returns
// Handled{Refused: true}; nothing is ever sent back for it (INV-006).
//
// The checks do not depend on how the envelope arrived (SPO-Xparty-SEC-002).
// How it arrived is set by the transport that delivered it and only reaches
// the audit record and the offline rule (SPO-Xparty-INV-024).
//
// A response that was accepted and arrives again, which a signer does when it
// answers a re-sent request from its stored response, is acknowledged without
// effect and without a security event (SPO-Xparty-INV-017).
//
// spec: SPO-Xparty-PRE-002, SPO-Xparty-PRE-005, SPO-Xparty-INV-006, SPO-Xparty-INV-007, SPO-Xparty-INV-010, SPO-Xparty-INV-014, SPO-Xparty-INV-015, SPO-Xparty-INV-017, SPO-Xparty-INV-021, SPO-Xparty-INV-024, SPO-Xparty-SEC-002, SPO-Xparty-OUT-004, SPO-Xparty-OUT-005
func (c Coordinator) Handle(ctx context.Context, rcv ports.Received) (Handled, error) {
	raw, via := rcv.Envelope, rcv.Via()
	if c.Offline && !via.IsFile() {
		return Handled{}, ErrOffline
	}
	local, err := c.Kit.Local(ctx)
	if err != nil {
		return Handled{}, err
	}
	defer local.Destroy()
	now := c.Clock.Now()
	slotNow, err := c.Chain.Slot(ctx, now)
	if err != nil {
		return Handled{}, err
	}
	var o ports.OpenedEnvelope
	var body party.Body
	var answered, dup bool // dup: the id is that of an accepted answer; answered: it is that slot's
	err = c.Store.View(ctx, func(r ports.Reader) error {
		lookup, ps, err := c.loadParties(r)
		if err != nil {
			return err
		}
		if o, err = local.Open(raw, lookup, now); err != nil {
			return err
		}
		st, err := readCoord(r)
		if err != nil {
			return err
		}
		body, err = o.Admit(func(id party.MessageID) (bool, error) {
			if st.isAnswer(hexMsg(id)) {
				dup = true
				return false, nil // INV-017: acknowledged below, if it names its own slot
			}
			return c.Replay.Seen(r, id, now)
		},
			func(sender party.Party, t party.Type, b party.Body) error {
				return c.authorise(r, st, ps, o, sender, t, b)
			})
		return err
	})
	if err != nil {
		if local.IsRefusal(err) {
			return c.refusalEvent(ctx, local, err, via)
		}
		return Handled{}, err
	}
	h := Handled{Type: o.Type(), Sender: o.Sender().Fingerprint, HasSender: true}
	if dup {
		err = c.Store.View(ctx, func(r ports.Reader) error {
			st, err := readCoord(r)
			if err != nil {
				return err
			}
			switch m := body.(type) {
			case party.SigningResponse:
				answered = st.answeredBy(m.Collection, m.Slot, hexMsg(o.ID()))
			case party.SigningRefusal:
				answered = st.answeredBy(m.Collection, m.Slot, hexMsg(o.ID()))
			}
			return nil
		})
		if err != nil {
			return Handled{}, err
		}
		if answered {
			h.Effect, h.Reason = "acknowledged", "duplicate of an accepted answer"
			return h, nil
		}
		return c.refuse(ctx, o, ports.ErrReplay, now)
	}
	err = c.Store.Update(ctx, func(w ports.Writer) error {
		var err error
		switch m := body.(type) {
		case party.SigningResponse:
			h, err = c.onResponse(w, o, m, slotNow, now)
		case party.SigningRefusal:
			h, err = c.onRefusal(w, o, m, now)
		case party.Hello:
			h, err = c.onHello(w, o, now)
		}
		return err
	})
	var rf *refusal
	if errors.As(err, &rf) {
		// The refusal was found while applying the effect: nothing of the
		// effect was kept; the reason is recorded on its own.
		return c.refuse(ctx, o, rf.err, now)
	}
	if err != nil {
		return Handled{}, err
	}
	if h.Complete && c.Complete != nil {
		if err := c.finish(ctx, body.(party.SigningResponse).Collection); err != nil {
			return h, err
		}
	}
	return h, nil
}

// refuse records the refusal of an authenticated sender's message, coalesced
// per sender and reason (SPO-Xparty-INV-023), and returns the Handled for it.
func (c Coordinator) refuse(ctx context.Context, o ports.OpenedEnvelope, why error, now time.Time) (Handled, error) {
	ev := eventOf(now, "message-refused", "", 0, [32]byte{})
	ev.Peer, ev.Reason, ev.Detail = o.Sender().Fingerprint.String(), why.Error(), string(o.Type())
	if uerr := c.Store.Update(ctx, func(w ports.Writer) error { return appendRefusal(w, ev) }); uerr != nil {
		return Handled{}, uerr
	}
	return Handled{Type: o.Type(), Sender: o.Sender().Fingerprint, HasSender: true, Refused: true, Reason: why.Error()}, nil
}

func (c Coordinator) onHello(w ports.Writer, o ports.OpenedEnvelope, now time.Time) (Handled, error) {
	// A Hello authenticates the connection, and it is how the coordinator
	// learns that a signer is connected: every request of that signer that
	// has no answer yet is sent again, with the same message id, until its slot
	// is filled or it expires (SPO-Xparty-INV-017, INV-021). The Hello's id is
	// kept until its expiry, at most five minutes.
	if err := c.Replay.Record(w, o.Sender().Fingerprint, o.ID(), o.Expires(), now); err != nil {
		return Handled{}, &refusal{err}
	}
	from := o.Sender().Fingerprint
	if err := rearm(w, &from); err != nil {
		return Handled{}, err
	}
	ev := eventOf(now, "hello", "", 0, [32]byte{})
	ev.Peer = o.Sender().Fingerprint.String()
	return Handled{Type: party.TypeHello, Sender: o.Sender().Fingerprint, HasSender: true, Effect: "hello"}, appendEvent(w, ev)
}

func (c Coordinator) onRefusal(w ports.Writer, o ports.OpenedEnvelope, m party.SigningRefusal, now time.Time) (Handled, error) {
	st, err := readCoord(w)
	if err != nil {
		return Handled{}, err
	}
	cs := st.find(m.Collection)
	if cs == nil {
		return Handled{}, &refusal{ErrNoCollection}
	}
	ss := cs.Slots[int(m.Slot)]
	if ss.LastRequest != hexMsg(m.Request) {
		return Handled{}, &refusal{party.ErrStaleRequest}
	}
	ss.Refusal = m.Reason.String()
	ss.Answered = hexMsg(o.ID())
	cs.Slots[int(m.Slot)] = ss
	if err := writeJSON(w, coordRef, st); err != nil {
		return Handled{}, err
	}
	if err := settleRequest(w, ss.LastRequest); err != nil { // the answer arrived: stop re-sending the request
		return Handled{}, err
	}
	if err := c.Replay.Record(w, o.Sender().Fingerprint, o.ID(), o.Expires(), now); err != nil {
		return Handled{}, &refusal{err}
	}
	ev := eventOf(now, "request-refused-by-signer", hexColl(m.Collection), int(m.Slot), [32]byte{})
	ev.Peer, ev.Reason = o.Sender().Fingerprint.String(), m.Reason.String()
	return Handled{Type: party.TypeSigningRefusal, Sender: o.Sender().Fingerprint, HasSender: true, Effect: "refusal-recorded", Reason: m.Reason.String()},
		appendEvent(w, ev)
}

// onResponse is SPO-Xparty-PRE-005 and INV-014, in one transaction with the
// replay entry.
func (c Coordinator) onResponse(w ports.Writer, o ports.OpenedEnvelope, m party.SigningResponse, slotNow uint64, now time.Time) (Handled, error) {
	h := Handled{Type: party.TypeSigningResponse, Sender: o.Sender().Fingerprint, HasSender: true}
	st, err := readCoord(w)
	if err != nil {
		return h, err
	}
	cs := st.find(m.Collection)
	if cs == nil {
		return h, &refusal{ErrNoCollection}
	}
	l, err := c.loadCollection(w, c.TxIDs, cs.Ref)
	if err != nil {
		return h, &refusal{err}
	}
	if collectionID(cs.Ref, l.coll) != m.Collection {
		return h, &refusal{fmt.Errorf("%w: it was replaced by another", ErrNoCollection)}
	}
	if int(m.Slot) >= len(l.coll.Slots) {
		return h, &refusal{party.ErrWrongSlot}
	}
	slot := l.coll.Slots[m.Slot]
	_, ps, err := c.loadParties(w)
	if err != nil {
		return h, err
	}
	var assigned party.Fingerprint
	for _, p := range ps {
		if p.Name == slot.Party && slot.Party != "" {
			assigned = p.Fingerprint
		}
	}
	vkey, sig, err := party.DecodeWitness(m.Witness)
	if err != nil {
		return h, &refusal{err}
	}
	ss := cs.Slots[int(m.Slot)]
	if ss.LastRequest == "" {
		return h, &refusal{party.ErrStaleRequest} // no request was sent for the slot
	}
	last, err := msgOfHex(ss.LastRequest)
	if err != nil {
		return h, err
	}
	// The collection must be OpenIncomplete. A response for a slot that is
	// already filled is acknowledged without effect even when that fill
	// completed the collection (INV-014): the duplicate of the response that
	// completed it is not a refusal.
	state := l.coll.StateAtTip(slotNow)
	open := state == pool.CollectionOpenIncomplete || (state == pool.CollectionOpenComplete && slot.Filled())
	err = party.AcceptResponse(party.SlotState{Collection: m.Collection, Slot: m.Slot,
		CollectionOpen: open, Filled: slot.Filled(), AssignedSigner: assigned,
		LastRequest: last, BodyHash: [32]byte(l.coll.Body.ID), KeyHash: [28]byte(slot.KeyHash)}, o.Sender().Fingerprint, m, vkey, sig)
	ev := eventOf(now, "response-accepted", hexColl(m.Collection), int(m.Slot), [32]byte(l.coll.Body.ID))
	ev.Peer = o.Sender().Fingerprint.String()
	switch {
	case errors.Is(err, party.ErrSlotFilled):
		// INV-014: of two valid responses one is stored; the other is
		// acknowledged without effect.
		if err := c.Replay.Record(w, o.Sender().Fingerprint, o.ID(), o.Expires(), now); err != nil {
			return h, &refusal{err}
		}
		ev.Kind, ev.Detail = "response-acknowledged", "slot already filled: no effect"
		h.Effect = "acknowledged"
		return h, appendEvent(w, ev)
	case err != nil:
		return h, &refusal{err}
	}
	if err := c.Replay.Record(w, o.Sender().Fingerprint, o.ID(), o.Expires(), now); err != nil {
		return h, &refusal{err}
	}
	// Fill verifies the witness once more over the stored body and the
	// slot's key hash, and is the compare-and-set on the collection version.
	// A witness that arrives in an envelope is authenticated: not marked
	// Unauthenticated, as an imported 05c file is (IF-007).
	next, err := l.coll.Fill(pool.Fill{Slot: slot.Name, Witness: txbuild.Witness{VKey: vkey, Signature: sig}, ExpectVersion: l.coll.Version}, slotNow)
	if err != nil {
		return h, &refusal{err}
	}
	l.coll = next
	if err := c.saveCollection(w, l); err != nil {
		return h, err
	}
	ss.Answered = hexMsg(o.ID())
	cs.Slots[int(m.Slot)] = ss
	if err := writeJSON(w, coordRef, st); err != nil {
		return h, err
	}
	if err := settleRequest(w, ss.LastRequest); err != nil { // the answer arrived: stop re-sending the request
		return h, err
	}
	h.Effect = "filled"
	h.Complete = next.StateAtTip(slotNow) == pool.CollectionOpenComplete
	if err := appendEvent(w, ev); err != nil {
		return h, err
	}
	if h.Complete {
		if err := appendEvent(w, eventOf(now, "collection-complete", hexColl(m.Collection), 0, [32]byte(next.Body.ID))); err != nil {
			return h, err
		}
	}
	return h, nil
}

// finish runs the Complete callback for a collection that has just become
// complete and announces the outcome to the signers when it was submitted.
func (c Coordinator) finish(ctx context.Context, cid party.CollectionID) error {
	var ref CollectionRef
	err := c.Store.View(ctx, func(r ports.Reader) error {
		st, err := readCoord(r)
		if err != nil {
			return err
		}
		cs := st.find(cid)
		if cs == nil {
			return ErrNoCollection
		}
		ref = cs.Ref
		return nil
	})
	if err != nil {
		return err
	}
	return c.CompleteNow(ctx, ref)
}

// CompleteNow runs the Complete callback for a collection and, when the
// transaction was submitted, announces it (CollectionClosed, submitted with
// its transaction id) to every party that was asked for a signature.
//
// spec: SPO-Xparty-OUT-005, SPO-Xparty-OUT-004
func (c Coordinator) CompleteNow(ctx context.Context, ref CollectionRef) error {
	if c.Complete == nil {
		return errors.New("no completion is wired")
	}
	res, err := c.Complete(ctx, ref)
	if err != nil {
		return err
	}
	if res.Submitted {
		return c.Close(ctx, ref, party.OutcomeSubmitted, res.TxID)
	}
	return nil
}

// ---- closing --------------------------------------------------------------------

// Close announces the end of a collection to every party that was asked for
// a signature on it, as an envelope in the outbox (SPO-Xparty-INV-015,
// OUT-004). A collection is closed once.
//
// spec: SPO-Xparty-INV-015, SPO-Xparty-OUT-004
func (c Coordinator) Close(ctx context.Context, ref CollectionRef, outcome party.Outcome, txid chain.TxID) error {
	local, err := c.Kit.Local(ctx)
	if err != nil {
		return err
	}
	defer local.Destroy()
	now := c.Clock.Now()
	body := party.CollectionClosed{Outcome: outcome}
	if outcome == party.OutcomeSubmitted {
		body.TxID = txid[:]
	}
	return c.Store.Update(ctx, func(w ports.Writer) error {
		st, err := readCoord(w)
		if err != nil {
			return err
		}
		_, ps, err := c.loadParties(w)
		if err != nil {
			return err
		}
		var items []OutItem
		for i := range st.Collections {
			cs := &st.Collections[i]
			if cs.Ref != ref || cs.Closed != "" {
				continue
			}
			cid, err := hexCollOf(cs.ID)
			if err != nil {
				return err
			}
			body.Collection = cid
			sent := map[string]bool{}
			for _, ss := range cs.Slots {
				if ss.To == "" || sent[ss.To] {
					continue
				}
				sent[ss.To] = true
				for _, p := range ps {
					if hexFP(p.Fingerprint) != ss.To || !p.Active() {
						continue
					}
					env, mid, err := local.Seal(p.Identity, body, now, now.Add(24*time.Hour))
					if err != nil {
						return err
					}
					items = append(items, OutItem{ID: hexMsg(mid), To: ss.To, Type: string(party.TypeCollectionClosed),
						Collection: cs.ID, Expires: now.Add(24 * time.Hour).Unix(), Envelope: env})
				}
			}
			cs.Closed = string(outcome)
			// A closed collection asks for nothing more: its requests are not
			// sent again when the signer connects.
			if err := settleCollection(w, cs.ID); err != nil {
				return err
			}
			ev := eventOf(now, "collection-"+string(outcome), cs.ID, 0, [32]byte{})
			if outcome == party.OutcomeSubmitted {
				ev.Detail = txid.String()
			}
			if err := appendEvent(w, ev); err != nil {
				return err
			}
		}
		if err := writeJSON(w, coordRef, st); err != nil {
			return err
		}
		return enqueue(w, now, items...)
	})
}

// Sweep closes the collections that ended without the coordinator saying so:
// one whose TTL slot has passed is Expired (derived from the tip, or the
// clock), one that is gone from its place was discarded (SPO-Xparty-INV-015).
func (c Coordinator) Sweep(ctx context.Context) ([]CollectionRef, error) {
	now := c.Clock.Now()
	slotNow, err := c.Chain.Slot(ctx, now)
	if err != nil {
		return nil, err
	}
	type decision struct {
		ref     CollectionRef
		outcome party.Outcome
	}
	var ds []decision
	err = c.Store.View(ctx, func(r ports.Reader) error {
		st, err := readCoord(r)
		if err != nil {
			return err
		}
		for _, cs := range st.Collections {
			if cs.Closed != "" {
				continue
			}
			cid, err := hexCollOf(cs.ID)
			if err != nil {
				return err
			}
			l, err := c.loadCollection(r, c.TxIDs, cs.Ref)
			switch {
			case errors.Is(err, ErrNoCollection), err == nil && collectionID(cs.Ref, l.coll) != cid:
				ds = append(ds, decision{cs.Ref, party.OutcomeDiscarded})
			case err != nil:
				return err
			case l.coll.StateAtTip(slotNow) == pool.CollectionExpired:
				ds = append(ds, decision{cs.Ref, party.OutcomeExpired})
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	var out []CollectionRef
	for _, d := range ds {
		if err := c.Close(ctx, d.ref, d.outcome, chain.TxID{}); err != nil {
			return out, err
		}
		out = append(out, d.ref)
	}
	return out, nil
}

// ---- revocation -----------------------------------------------------------------

// OnRevoke is the hook for parties.Revoke (SPO-Xparty-INV-005): inside the
// revocation's transaction, every unfilled slot assigned to the revoked party
// becomes unassigned, and the envelopes not yet delivered to it are dropped.
// A slot that is filled keeps its verified witness.
func (c Coordinator) OnRevoke(w ports.Writer, revoked party.Party) error {
	st, err := readCoord(w)
	if err != nil {
		return err
	}
	now := c.Clock.Now()
	for _, cs := range st.Collections {
		if cs.Closed != "" {
			continue
		}
		l, err := c.loadCollection(w, c.TxIDs, cs.Ref)
		if errors.Is(err, ErrNoCollection) {
			continue
		}
		if err != nil {
			return err
		}
		changed := false
		for _, s := range l.coll.Slots {
			if s.Party != revoked.Name || s.Filled() {
				continue
			}
			if l.coll, err = l.coll.Unassign(s.Name); err != nil {
				return err
			}
			changed = true
			ev := eventOf(now, "slot-unassigned", cs.ID, 0, [32]byte{})
			ev.Peer, ev.Detail = revoked.Fingerprint.String(), s.Name
			if err := appendEvent(w, ev); err != nil {
				return err
			}
		}
		if changed {
			if err := c.saveCollection(w, l); err != nil {
				return err
			}
		}
	}
	_, err = dropTo(w, revoked.Fingerprint)
	return err
}

// ---- invitations --------------------------------------------------------------------

// SendInvite seals the coordinator's tailcat address to one enrolled party
// and queues it. The address is a Secret (SPO-Xparty-SEC-001): it travels
// only inside this envelope, to this party, and is never in an event or a log
// line. The invitation is sent by whatever transport tr is, normally a file.
//
// spec: SPO-Xparty-SEC-001, SPO-Xparty-INV-010, SPO-Xparty-OUT-004
func (c Coordinator) SendInvite(ctx context.Context, partyName string, inv party.Invite, tr Transport) error {
	if tr.Sender() != nil && !tr.Kind().Known() {
		return ErrTransportKind
	}
	if c.Offline && tr.Kind() == ports.ViaNetwork {
		return ErrOffline
	}
	local, err := c.Kit.Local(ctx)
	if err != nil {
		return err
	}
	defer local.Destroy()
	now := c.Clock.Now()
	err = c.Store.Update(ctx, func(w ports.Writer) error {
		p, err := c.Parties.ByName(w, partyName)
		if err != nil {
			return err
		}
		if !p.Active() || !p.HasRole(party.RoleSigner) {
			return fmt.Errorf("%w: %s", ErrNotSigner, partyName)
		}
		exp := now.Add(24 * time.Hour)
		env, mid, err := local.Seal(p.Identity, inv, now, exp)
		if err != nil {
			return err
		}
		ev := eventOf(now, "invite-sealed", "", 0, [32]byte{})
		ev.Peer = p.Fingerprint.String()
		if err := appendEvent(w, ev); err != nil {
			return err
		}
		return enqueue(w, now, OutItem{ID: hexMsg(mid), To: hexFP(p.Fingerprint), Type: string(party.TypeInvite), Expires: exp.Unix(), Envelope: env})
	})
	if err != nil {
		return err
	}
	if tr.Sender() != nil {
		_, err = (Outbox{Store: c.Store, Clock: c.Clock, Offline: c.Offline}).Flush(ctx, tr)
	}
	return err
}
