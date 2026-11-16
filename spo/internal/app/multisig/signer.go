package multisig

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// KeyFinder tells the signer which key it holds for a key hash and role. The
// wiring implements it over the workspace's keys; a signer that holds no
// such key refuses the request (SPO-Xparty-PRE-006).
type KeyFinder interface {
	FindKey(ctx context.Context, role custody.Role, hash [28]byte) (custody.KeyRef, bool, error)
}

// Signer is the party asked for a signature.
type Signer struct {
	Node
	// Signers finds the local signer that holds a key: the vault, a
	// hardware wallet. The plan of the signer's own side is built against
	// it (SPO-Xparty-PRE-006).
	Signers ports.SignerDirectory
	Keys    KeyFinder
	// NetworkMagic is the workspace's network.
	NetworkMagic uint32
	// Owned is what this signer owns, from its own store: the review marks
	// every output Own or not by it and resolves the inputs of a body in the
	// UTxO sets of its payment addresses (SPO-Xparty-PR-002). It is never
	// taken from the coordinator. nil owns nothing.
	Owned ports.OwnedAddresses
	// Utxos is the signer's OWN chain provider or offline snapshot, never the
	// coordinator's. nil, or a failing lookup, means the inputs cannot be
	// resolved: a payment-key request is then refused, and the review of any
	// other key says its inputs were not checked.
	Utxos ports.UtxoReader
	// Gate asks the operator to authenticate again before a key signs. There
	// is no default: with no gate Approve refuses (SPO-Xparty-INV-016).
	Gate ports.ApprovalGate
	// MaxTxSize is the protocol's maxTxSize; zero takes the upper bound
	// party.DefaultMaxTxSize (SPO-Xparty-INV-008).
	MaxTxSize int
	// OnInvite stores the tailcat address of an Invite. It runs inside the
	// store transaction that records the invitation's message id, with that
	// transaction's Writer, so the address and the replay entry commit
	// together or not at all (SPO-Xparty-INV-007). The address is a Secret
	// record (SPO-Xparty-SEC-001), which this package cannot make: the hook
	// makes it and calls w.PutSecret. The Invite's node key has already been
	// checked to be the coordinator's enrolled one. A nil hook refuses an
	// Invite.
	OnInvite func(w ports.Writer, from party.Party, inv party.Invite) error
}

// Request states.
const (
	reqPending  = "pending"
	reqSigning  = "signing" // claimed by an approval that has not stored its response
	reqApproved = "approved"
	reqRefused  = "refused"
)

// storedRequest is an admitted request, with what was decided for it. A
// refused request is kept without its body, its auxiliary data and its
// purpose: its id, sender, reason and time, and the collection and body hash
// that a CollectionClosed is matched against.
type storedRequest struct {
	ID         string `json:"id"` // hex message id
	From       string `json:"from"`
	FromName   string `json:"fromName"`
	Collection string `json:"collection"`
	Slot       int    `json:"slot"`
	Role       string `json:"role"`
	KeyHash    string `json:"keyHash"`
	KeyOwner   string `json:"keyOwner,omitempty"`
	Operation  string `json:"operation"`
	BodyHash   string `json:"bodyHash"`
	Body       []byte `json:"body,omitempty"`
	Aux        []byte `json:"aux,omitempty"`
	TTL        uint64 `json:"ttl"`
	Magic      uint32 `json:"magic"`
	Purpose    string `json:"purpose,omitempty"`
	Via        string `json:"via"`
	ReceivedAt int64  `json:"receivedAt"`
	Expires    int64  `json:"expires"`
	State      string `json:"state"`
	// Reviewed is the body hash the operator was shown; an approval needs
	// it to equal BodyHash (SPO-Xparty-INV-016).
	Reviewed string `json:"reviewed,omitempty"`
	Reason   string `json:"reason,omitempty"`
	// Silent: the refusal was kept to ourselves (SPO-Xparty-INV-006).
	Silent bool `json:"silent,omitempty"`
	// Response is the sealed answer, a SigningResponse or a SigningRefusal,
	// kept so that a lost reply can be sent again (SPO-Xparty-INV-017).
	ResponseID string `json:"responseId,omitempty"`
	Response   []byte `json:"response,omitempty"`
	Closed     string `json:"closed,omitempty"` // outcome of a CollectionClosed
}

type signerState struct {
	Requests []storedRequest `json:"requests"`
}

func readSigner(r ports.Reader) (signerState, error) {
	var s signerState
	return s, readJSON(r, signerRef, &s)
}

func (s *signerState) byID(id string) *storedRequest {
	for i := range s.Requests {
		if s.Requests[i].ID == id {
			return &s.Requests[i]
		}
	}
	return nil
}

// pendingFrom counts the undecided requests of one sender
// (SPO-Xparty-INV-022).
func (s *signerState) pendingFrom(from string) int {
	n := 0
	for _, q := range s.Requests {
		if q.From == from && (q.State == reqPending || q.State == reqSigning) {
			n++
		}
	}
	return n
}

// keep drops requests that expired more than a day ago: an answered request
// can only be asked again until its envelope expires.
func (s *signerState) prune(now time.Time) {
	kept := s.Requests[:0]
	for _, q := range s.Requests {
		if q.Expires+86400 >= now.Unix() {
			kept = append(kept, q)
		}
	}
	s.Requests = kept
}

// ---- receiving ----------------------------------------------------------------

// ErrQuota: a sender has as many undecided requests as it may
// (SPO-Xparty-INV-022). Only that sender is refused.
var ErrQuota = errors.New("the sender has too many undecided requests here")

func (s Signer) maxTxSize() int {
	if s.MaxTxSize > 0 {
		return min(s.MaxTxSize, party.DefaultMaxTxSize)
	}
	return party.DefaultMaxTxSize
}

// authorise is step 8 of SPO-Xparty-PRE-002 for the signer: the sender's role,
// and what the signer enforces on receipt before it stores anything: the
// transaction size (SPO-Xparty-INV-008), the request's lifetime
// (SPO-Xparty-INV-009), the sender's quota (INV-022), and that an Invite names
// the coordinator's own enrolled node key. What the request asks for, its
// scope, is decided afterwards, from the decoded body (onRequest).
func (s Signer) authorise(st signerState, slotTime func(uint64) (time.Time, error), o ports.OpenedEnvelope, sender party.Party, t party.Type, b party.Body) error {
	if err := party.Authorise(sender, t, party.Concern{}); err != nil {
		return err
	}
	switch m := b.(type) {
	case party.SigningRequest:
		if err := m.CheckTxSize(s.maxTxSize()); err != nil {
			return err
		}
		ttlTime, err := slotTime(m.TTLSlot)
		if err != nil {
			return fmt.Errorf("%w: the request's lifetime cannot be checked: %v", party.ErrInvalidBody, err)
		}
		if err := party.CheckRequestExpiry(o.Created(), o.Expires(), ttlTime); err != nil {
			return err
		}
		if st.byID(hexMsg(o.ID())) == nil && st.pendingFrom(hexFP(sender.Fingerprint)) >= party.MaxPendingPerSender {
			return ErrQuota
		}
		return nil
	case party.CollectionClosed:
		return nil
	case party.Invite:
		if sender.Identity.Node == nil || *sender.Identity.Node != m.Node {
			return fmt.Errorf("%w: the invitation's node key is not the coordinator's enrolled one", party.ErrNotAuthorised)
		}
		return nil
	}
	return fmt.Errorf("%w: a signer does not receive a %s", party.ErrNotAuthorised, t)
}

// Handle takes one envelope that arrived by file or over a network: the whole
// of SPO-Xparty-PRE-002, then the message's effect, with the replay entry and
// the audit event in the same transaction. A SigningRequest becomes a stored
// pending request, or is refused for one of the reasons of SPO-Xparty-PRE-006;
// a reason that depends on the signer's private state is recorded here and
// never sent.
//
// A request whose id was already answered and arrives again, over any
// transport, is answered again with the stored response, never signed again
// (SPO-Xparty-INV-017).
//
// via is how the envelope arrived; an unknown kind is a network.
//
// spec: SPO-Xparty-PRE-002, SPO-Xparty-PRE-006, SPO-Xparty-INV-006, SPO-Xparty-INV-007, SPO-Xparty-INV-010, SPO-Xparty-INV-017, SPO-Xparty-SEC-002
func (s Signer) Handle(ctx context.Context, raw []byte, via ports.TransportKind) (Handled, error) {
	local, err := s.Kit.Local(ctx)
	if err != nil {
		return Handled{}, err
	}
	defer local.Destroy()
	now := s.Clock.Now()
	slotNow, err := s.Chain.Slot(ctx, now)
	if err != nil {
		return Handled{}, err
	}
	slotTime := s.Chain.slotTimer(ctx)
	var o ports.OpenedEnvelope
	var body party.Body
	var again *storedRequest // an answered request that arrived again
	err = s.Store.View(ctx, func(r ports.Reader) error {
		lookup, _, err := s.loadParties(r)
		if err != nil {
			return err
		}
		if o, err = local.Open(raw, lookup, now); err != nil {
			return err
		}
		st, err := readSigner(r)
		if err != nil {
			return err
		}
		body, err = o.Admit(func(id party.MessageID) (bool, error) {
			if q := st.byID(hexMsg(id)); q != nil && q.Response != nil && q.From == hexFP(o.Sender().Fingerprint) {
				cp := *q
				again = &cp
				return false, nil // INV-017: handled below, not a replay
			}
			return s.Replay.Seen(r, id, now)
		}, func(sender party.Party, t party.Type, b party.Body) error {
			return s.authorise(st, slotTime, o, sender, t, b)
		})
		return err
	})
	if err != nil {
		if local.IsRefusal(err) {
			return s.refusalEvent(ctx, local, err, via)
		}
		return Handled{}, err
	}
	h := Handled{Type: o.Type(), Sender: o.Sender().Fingerprint, HasSender: true}
	switch m := body.(type) {
	case party.SigningRequest:
		if again != nil {
			return s.resend(ctx, o, again, now)
		}
		return s.onRequest(ctx, local, o, m, via, slotNow, now)
	case party.CollectionClosed:
		err = s.Store.Update(ctx, func(w ports.Writer) error {
			st, err := readSigner(w)
			if err != nil {
				return err
			}
			// A collection is closed only by the party that asked for it, and a
			// submission names the transaction that was asked about: its id is
			// the body hash stored with the request (SPO-Xparty-INV-015).
			from, coll := hexFP(o.Sender().Fingerprint), hexColl(m.Collection)
			known, named := false, false
			for _, q := range st.Requests {
				if q.Collection == coll && q.From == from {
					known = true
					named = named || (m.Outcome == party.OutcomeSubmitted && q.BodyHash == hex.EncodeToString(m.TxID))
				}
			}
			if !known {
				return &refusal{errors.New("no request of that coordinator is for that collection")}
			}
			if m.Outcome == party.OutcomeSubmitted && !named {
				return &refusal{errors.New("the submitted transaction id is not the body hash of any request of that collection")}
			}
			if err := s.Replay.Record(w, o.Sender().Fingerprint, o.ID(), o.Expires(), now); err != nil {
				return err
			}
			for i := range st.Requests {
				if st.Requests[i].Collection == coll && st.Requests[i].From == from {
					st.Requests[i].Closed = string(m.Outcome)
				}
			}
			if err := writeJSON(w, signerRef, st); err != nil {
				return err
			}
			if err := settleCollection(w, coll); err != nil { // nothing more to send for it
				return err
			}
			ev := eventOf(now, "collection-closed", coll, 0, [32]byte{})
			ev.Peer, ev.Detail = o.Sender().Fingerprint.String(), string(m.Outcome)
			return appendEvent(w, ev)
		})
		h.Effect = "closed"
	case party.Invite:
		if s.OnInvite == nil {
			return s.rejectEffect(ctx, o, errors.New("this signer takes no invitations"), now)
		}
		err = s.Store.Update(ctx, func(w ports.Writer) error {
			if err := s.Replay.Record(w, o.Sender().Fingerprint, o.ID(), o.Expires(), now); err != nil {
				return err
			}
			if err := s.OnInvite(w, o.Sender(), m); err != nil {
				return err
			}
			ev := eventOf(now, "invite-stored", "", 0, [32]byte{})
			ev.Peer = o.Sender().Fingerprint.String()
			return appendEvent(w, ev)
		})
		h.Effect = "invite"
	}
	var rf *refusal
	if errors.As(err, &rf) {
		return s.rejectEffect(ctx, o, rf.err, now)
	}
	if errors.Is(err, ports.ErrReplay) || errors.Is(err, ports.ErrReplayFull) {
		return s.rejectEffect(ctx, o, err, now)
	}
	return h, err
}

// rejectEffect records a refusal found after the envelope was admitted
// (a replay recorded by a concurrent Handle, a full replay log, a collection
// that was never asked about). The sender is authenticated: a security event.
func (s Signer) rejectEffect(ctx context.Context, o ports.OpenedEnvelope, why error, now time.Time) (Handled, error) {
	ev := eventOf(now, "message-refused", "", 0, [32]byte{})
	ev.Peer, ev.Reason, ev.Detail = o.Sender().Fingerprint.String(), why.Error(), string(o.Type())
	if err := s.Store.Update(ctx, func(w ports.Writer) error { return appendEvent(w, ev) }); err != nil {
		return Handled{}, err
	}
	return Handled{Type: o.Type(), Sender: o.Sender().Fingerprint, HasSender: true, Refused: true, Reason: why.Error()}, nil
}

// resend queues the stored response of an answered request again
// (SPO-Xparty-INV-017).
func (s Signer) resend(ctx context.Context, o ports.OpenedEnvelope, q *storedRequest, now time.Time) (Handled, error) {
	id, err := msgOfHex(q.ID)
	if err != nil {
		return Handled{}, err
	}
	err = s.Store.Update(ctx, func(w ports.Writer) error {
		if err := enqueue(w, now, OutItem{ID: q.ResponseID, To: q.From, Type: responseType(*q), Collection: q.Collection, Slot: q.Slot,
			Expires: q.Expires, Envelope: q.Response}); err != nil {
			return err
		}
		ev := eventOf(now, "response-resent", q.Collection, q.Slot, [32]byte{})
		ev.Peer, ev.Detail = o.Sender().Fingerprint.String(), q.ResponseID
		return appendEvent(w, ev)
	})
	return Handled{Type: party.TypeSigningRequest, Sender: o.Sender().Fingerprint, HasSender: true, Effect: "response-resent", Request: id}, err
}

func responseType(q storedRequest) string {
	if q.State == reqRefused {
		return string(party.TypeSigningRefusal)
	}
	return string(party.TypeSigningResponse)
}

// resolveFlow works out whose money the body moves from the signer's own
// addresses and chain view (SPO-Xparty-PR-002). It never fails: when the
// inputs cannot be resolved the Flow says so, and Flow.Refusal decides what
// that means for the key role.
func (s Signer) resolveFlow(ctx context.Context, v party.TxView, role custody.Role) party.Flow {
	f := party.FlowFacts{}
	if s.Owned != nil {
		f.IsOwnAddress = func(a string) bool { return s.Owned.IsOwn(chain.Address(a)) }
		f.IsOwnReward = func(a string) bool { return s.Owned.IsOwnReward(chain.StakeAddress(a)) }
	}
	notChecked := func(why string) party.Flow {
		if role != custody.RolePayment {
			why = party.NotCheckedText
		}
		f.NotChecked = why
		fl, err := party.BuildFlow(v, f)
		if err != nil {
			return party.Flow{NotChecked: err.Error()}
		}
		return fl
	}
	if s.Utxos == nil {
		return notChecked("this signer has no chain view of its own")
	}
	if s.Owned == nil {
		return notChecked("this signer knows no addresses of its own")
	}
	addrs, err := s.Owned.PaymentAddresses(ctx)
	if err != nil {
		return notChecked("its own addresses cannot be listed: " + err.Error())
	}
	for _, a := range addrs {
		us, err := s.Utxos.Utxos(ctx, a)
		if err != nil {
			return notChecked("the UTxOs of its own address cannot be read: " + err.Error())
		}
		f.OwnUtxos = append(f.OwnUtxos, us...)
	}
	f.Checked = true
	fl, err := party.BuildFlow(v, f)
	if err != nil {
		return party.Flow{NotChecked: err.Error()}
	}
	return fl
}

// decodeRequest is what the signer decodes and verifies about a request from
// its own bytes: the checks of SPO-Xparty-PRE-006 whose answer is public (the
// coordinator could work them out itself), in order. It returns the view and
// the metadata for display, or the reason.
func (s Signer) decodeRequest(req party.SigningRequest, facts party.RequestFacts) (view party.TxView, aux *party.AuxView, reason party.RefusalReason, detail string, refuse bool) {
	if reason, refuse = party.RefuseRequestEarly(req, facts); refuse {
		return
	}
	v, err := s.Viewer.View(req.TxBody)
	switch {
	case err != nil:
		return view, nil, party.RefuseBodyDecode, err.Error(), true
	case v.TTL == nil || *v.TTL != req.TTLSlot:
		// The request's ttl is a claim; the body is what is signed.
		return view, nil, party.RefuseBodyDecode, "the request's ttl slot is not the body's", true
	}
	if err := v.CheckNetwork(party.NetworkIDOf(s.NetworkMagic)); err != nil {
		return view, nil, party.RefuseWrongNetwork, err.Error(), true
	}
	if u := v.Undisplayable(); len(u) > 0 {
		return view, nil, party.RefuseUndisplayable, strings.Join(u, "; "), true
	}
	if err := party.CheckAuxData(v, req.AuxData); err != nil {
		return view, nil, party.RefuseUndisplayable, err.Error(), true
	}
	if len(req.AuxData) > 0 {
		av, err := s.Viewer.ViewAux(req.AuxData)
		if err != nil {
			return view, nil, party.RefuseUndisplayable, err.Error(), true
		}
		aux = &av
	}
	if reason, refuse = party.RefuseRequestLate(req, facts); refuse {
		return
	}
	return v, aux, 0, "", false
}

// onRequest is SPO-Xparty-PRE-006. The checks whose answer is public come
// first and are sent when they refuse; the checks that depend on what this
// signer holds, owns or trusts come last and are never sent: scope, the key
// held, the inputs, the plan. A refusal is kept without the body.
func (s Signer) onRequest(ctx context.Context, local ports.LocalIdentity, o ports.OpenedEnvelope, req party.SigningRequest, via ports.TransportKind, slotNow uint64, now time.Time) (Handled, error) {
	facts := party.RequestFacts{WorkspaceMagic: s.NetworkMagic, CurrentSlot: slotNow, OverNetwork: !via.IsFile()}
	view, _, reason, detail, refuse := s.decodeRequest(req, facts)
	var key custody.KeyRef
	if !refuse {
		if err := party.CheckScope(o.Sender().Scope, req.KeyRole, poolsOf(view)); err != nil {
			reason, detail, refuse = party.RefuseOutOfScope, err.Error(), true
		}
	}
	if !refuse {
		k, holds, err := s.Keys.FindKey(ctx, req.KeyRole, req.KeyHash)
		if err != nil {
			return Handled{}, err
		}
		if !holds {
			reason, refuse = party.RefuseNoKey, true
		}
		key = k
	}
	if !refuse {
		if reason, refuse = s.resolveFlow(ctx, view, req.KeyRole).Refusal(req.KeyRole); refuse {
			detail = reason.String()
		}
	}
	if !refuse {
		// The plan on the signer's side: the signer that holds the key can
		// meet the demand of what the body actually contains.
		plan, perr := ports.PlanSignatures(s.Signers, []custody.Slot{{Label: "request", Key: key,
			Demand: custody.Demand{Role: req.KeyRole, Operation: custody.OpWitnessTx, Features: view.FeaturesFor(req.KeyRole)}}})
		if perr != nil || plan.Empty() {
			reason, refuse = party.RefuseCannotSign, true
			if perr != nil {
				detail = perr.Error()
			}
		}
	}
	q := storedRequest{ID: hexMsg(o.ID()), From: hexFP(o.Sender().Fingerprint), FromName: o.Sender().Name, Collection: hexColl(req.Collection),
		Slot: int(req.Slot), Role: string(req.KeyRole), KeyHash: hex.EncodeToString(req.KeyHash[:]), KeyOwner: key.Owner,
		Operation: req.Operation, BodyHash: hexHash(req.BodyHash), Body: req.TxBody, Aux: req.AuxData, TTL: req.TTLSlot, Magic: req.NetworkMagic,
		Purpose: req.Purpose, Via: via.String(), ReceivedAt: now.Unix(), Expires: o.Expires().Unix(), State: reqPending}
	h := Handled{Type: party.TypeSigningRequest, Sender: o.Sender().Fingerprint, HasSender: true, Request: o.ID(), Effect: "stored"}
	var env []byte
	var rid party.MessageID
	if refuse {
		// A refused request is kept without its body: what an enrolled party
		// can make us hold is bounded (SPO-Xparty-INV-022).
		q.Body, q.Aux, q.Purpose, q.Operation = nil, nil, "", ""
		q.State, q.Reason, q.Silent = reqRefused, reason.String(), !reason.Disclosed()
		h.Effect, h.Reason = "refused", reason.String()
		if reason.Disclosed() {
			// A refusal needs no review: it signs nothing.
			var err error
			env, rid, err = local.Seal(o.Sender().Identity, party.SigningRefusal{Collection: req.Collection, Slot: req.Slot, Request: o.ID(), Reason: reason}, now, o.Expires())
			if err != nil {
				return Handled{}, err
			}
			q.ResponseID, q.Response = hexMsg(rid), env
		}
	}
	err := s.Store.Update(ctx, func(w ports.Writer) error {
		if err := s.Replay.Record(w, o.Sender().Fingerprint, o.ID(), o.Expires(), now); err != nil {
			return err
		}
		st, err := readSigner(w)
		if err != nil {
			return err
		}
		st.prune(now)
		st.Requests = append(st.Requests, q)
		if err := writeJSON(w, signerRef, st); err != nil {
			return err
		}
		ev := eventOf(now, "request-received", q.Collection, q.Slot, req.BodyHash)
		ev.Peer, ev.Detail = o.Sender().Fingerprint.String(), q.ID+" via "+q.Via
		if err := appendEvent(w, ev); err != nil {
			return err
		}
		if !refuse {
			return nil
		}
		ev = eventOf(now, "request-refused", q.Collection, q.Slot, req.BodyHash)
		ev.Peer, ev.Reason, ev.Detail = o.Sender().Fingerprint.String(), reason.String(), detail
		if q.Silent {
			ev.Detail += " (not sent to the coordinator)"
		}
		if err := appendEvent(w, ev); err != nil {
			return err
		}
		if q.Silent {
			return nil
		}
		return enqueue(w, now, OutItem{ID: q.ResponseID, To: q.From, Type: string(party.TypeSigningRefusal), Collection: q.Collection,
			Slot: q.Slot, Expires: q.Expires, Envelope: env})
	})
	if errors.Is(err, ports.ErrReplay) || errors.Is(err, ports.ErrReplayFull) {
		return s.rejectEffect(ctx, o, err, now)
	}
	return h, err
}

// ---- pending requests, review, decision --------------------------------------------

// Pending lists the requests waiting for a decision.
func (s Signer) Pending(ctx context.Context) ([]PendingRequest, error) {
	var out []PendingRequest
	err := s.Store.View(ctx, func(r ports.Reader) error {
		st, err := readSigner(r)
		for _, q := range st.Requests {
			if q.State == reqPending && q.Expires >= s.Clock.Now().Unix() && q.Closed == "" {
				id, _ := msgOfHex(q.ID)
				out = append(out, PendingRequest{ID: id, From: q.FromName, Collection: q.Collection, Slot: q.Slot, Role: custody.Role(q.Role), Via: q.Via,
					Expires: time.Unix(q.Expires, 0).UTC()})
			}
		}
		return err
	})
	return out, err
}

// PendingRequest is a line of the inbox. It carries nothing from the body:
// what the body does is for ReviewRequest.
type PendingRequest struct {
	ID         party.MessageID
	From       string // the local name of the coordinator
	Collection string
	Slot       int
	Role       custody.Role
	Via        string
	Expires    time.Time
}

// Review is a stored request decoded locally for the operator to read
// (SPO-Xparty-PR-002). Everything in View comes from the body bytes, decoded
// here. ClaimedPurpose is the coordinator's text: it is a different field, to
// be shown as a claim, and nothing is derived from it (SPO-Xparty-INV-011).
//
// Only ReviewRequest makes a Review that Approval accepts: the unexported
// token is set there and nowhere else.
type Review struct {
	RequestID party.MessageID
	BodyHash  [32]byte
	Role      custody.Role
	KeyHash   [28]byte
	// Coordinator is the local name of the party that sent the request.
	Coordinator string
	Via         string
	View        party.TxView
	// Flow is whose money the body moves, worked out by this signer from its
	// own addresses and chain view: its own inputs with their value, the
	// outputs marked Own or not, the net outflow, the fee, withdrawals and
	// the deposits the certificates imply. It is the first thing the review
	// shows (SPO-Xparty-PR-002).
	Flow party.Flow
	// Aux is the metadata of the transaction, decoded from the auxiliary data
	// the request carried, when the body has any.
	Aux *party.AuxView
	// TotalOutput is the lovelace of all outputs of the body, own or not:
	// Flow.NetLovelace is what leaves this signer.
	TotalOutput uint64
	// ClaimedPurpose is what the coordinator says the transaction is for.
	ClaimedPurpose string

	token *reviewToken
}

type reviewToken struct {
	id   party.MessageID
	hash [32]byte
}

// Approval is the decision to sign one reviewed request. It can only be
// made from a Review (Review.Approval), for exactly that request id and body
// hash; there is no other constructor, and its fields are not exported, so a
// caller cannot assemble one. Signer.Approve accepts nothing else
// (SPO-Xparty-INV-016: no way to approve without the display).
type Approval struct{ tok *reviewToken }

// ErrCannotReview: the request can no longer be reviewed for approval: its
// flow does not meet the rule of its key role, or it has a part that cannot
// be displayed (the reason is in the error). The operator can still decline it.
var ErrCannotReview = errors.New("the request cannot be approved")

// ErrNoGate: Approve needs an ApprovalGate and the signer has none.
var ErrNoGate = errors.New("this signer has no approval gate: it does not approve without authenticating the operator again")

// ErrNoReview: an approval was asked for a review that ReviewRequest did not
// make.
var ErrNoReview = errors.New("there was no review of this request: a request is approved only from the result of reviewing it")

// Approval turns a review into the decision to sign. The caller calls it
// only after showing View to the operator and receiving an explicit yes; the
// default is No (SPO-Xparty-PR-002).
func (r Review) Approval() (Approval, error) {
	if r.token == nil || r.token.id != r.RequestID || r.token.hash != r.BodyHash {
		return Approval{}, ErrNoReview
	}
	return Approval{tok: r.token}, nil
}

// Request and body-hash refusals of the signer's own decisions.
var (
	ErrUnknownRequest = errors.New("there is no such request")
	ErrNotPending     = errors.New("the request is not waiting for a decision")
)

// ReviewRequest decodes the stored request from its own bytes and returns what
// the operator must read. It recomputes the body hash from the bytes and
// refuses a stored request whose body no longer hashes to its id or no longer
// decodes, and one that does not meet the flow rule of its key role. It records that the review happened with the body hash, which an
// approval requires (SPO-Xparty-INV-016, OUT-006).
//
// spec: SPO-Xparty-PR-002, SPO-Xparty-INV-011, SPO-Xparty-INV-016, SPO-Xparty-OUT-006
func (s Signer) ReviewRequest(ctx context.Context, id party.MessageID) (Review, error) {
	now := s.Clock.Now()
	// Read the request, then decode and resolve outside any store
	// transaction: the chain view of the signer may be a network call.
	var q storedRequest
	err := s.Store.View(ctx, func(r ports.Reader) error {
		st, err := readSigner(r)
		if err != nil {
			return err
		}
		p := st.byID(hexMsg(id))
		if p == nil {
			return ErrUnknownRequest
		}
		q = *p
		return nil
	})
	if err != nil {
		return Review{}, err
	}
	if q.State != reqPending && q.State != reqSigning {
		return Review{}, fmt.Errorf("%w: it is %s", ErrNotPending, q.State)
	}
	hash := blake2b.Sum256(q.Body)
	if hexHash(hash) != q.BodyHash {
		return Review{}, errors.New("the stored body does not hash to the request's body hash")
	}
	view, err := s.Viewer.View(q.Body)
	if err != nil {
		return Review{}, err
	}
	if u := view.Undisplayable(); len(u) > 0 {
		return Review{}, fmt.Errorf("%w: %s", ErrCannotReview, strings.Join(u, "; "))
	}
	if err := party.CheckAuxData(view, q.Aux); err != nil {
		return Review{}, err
	}
	var aux *party.AuxView
	if len(q.Aux) > 0 {
		av, err := s.Viewer.ViewAux(q.Aux)
		if err != nil {
			return Review{}, err
		}
		aux = &av
	}
	kh, err := hex.DecodeString(q.KeyHash)
	if err != nil || len(kh) != 28 {
		return Review{}, errors.New("the stored key hash")
	}
	// The flow is worked out now, from the signer's own view as it is at the
	// time of the review, and an approval is possible only when it meets the
	// rule of the key role (SPO-Xparty-PR-002).
	flow := s.resolveFlow(ctx, view, custody.Role(q.Role))
	if reason, bad := flow.Refusal(custody.Role(q.Role)); bad {
		return Review{}, fmt.Errorf("%w: %s", ErrCannotReview, reason)
	}
	rv := Review{RequestID: id, BodyHash: hash, Role: custody.Role(q.Role), Coordinator: q.FromName, Via: q.Via, View: view, Flow: flow, Aux: aux,
		TotalOutput: view.TotalOutput(), ClaimedPurpose: q.Purpose, token: &reviewToken{id: id, hash: hash}}
	copy(rv.KeyHash[:], kh)
	err = s.Store.Update(ctx, func(w ports.Writer) error {
		st, err := readSigner(w)
		if err != nil {
			return err
		}
		p := st.byID(hexMsg(id))
		if p == nil || (p.State != reqPending && p.State != reqSigning) || p.BodyHash != q.BodyHash {
			return ErrNotPending
		}
		p.Reviewed = p.BodyHash
		if err := writeJSON(w, signerRef, st); err != nil {
			return err
		}
		ev := eventOf(now, "request-reviewed", q.Collection, q.Slot, hash)
		ev.Detail = q.ID
		return appendEvent(w, ev)
	})
	if err != nil {
		return Review{}, err
	}
	return rv, nil
}

// Approve signs a reviewed request: the signer that holds the key witnesses
// the body, the witness is verified as the coordinator will verify it
// (SPO-Xparty-PRE-005), and a SigningResponse is sealed to the coordinator,
// stored, and queued. The request is answered at most once; a second approval
// of an answered request is refused, and the stored response is what goes out
// again (SPO-Xparty-INV-017).
//
// spec: SPO-Xparty-OUT-006, SPO-Xparty-INV-016, SPO-Xparty-INV-017, SPO-Xparty-PRE-005
func (s Signer) Approve(ctx context.Context, a Approval) (Handled, error) {
	if a.tok == nil {
		return Handled{}, ErrNoReview
	}
	if s.Gate == nil {
		return Handled{}, ErrNoGate
	}
	local, err := s.Kit.Local(ctx)
	if err != nil {
		return Handled{}, err
	}
	defer local.Destroy()
	now := s.Clock.Now()
	slotNow, err := s.Chain.Slot(ctx, now)
	if err != nil {
		return Handled{}, err
	}
	var q storedRequest
	var coord party.Party
	// Claim: the request must be pending, reviewed for this body hash, not
	// expired, and not closed; it is marked as being signed.
	err = s.Store.Update(ctx, func(w ports.Writer) error {
		st, err := readSigner(w)
		if err != nil {
			return err
		}
		p := st.byID(hexMsg(a.tok.id))
		if p == nil {
			return ErrUnknownRequest
		}
		if p.State != reqPending && p.State != reqSigning {
			return fmt.Errorf("%w: it is %s", ErrNotPending, p.State)
		}
		if p.Reviewed != hexHash(a.tok.hash) || p.BodyHash != hexHash(a.tok.hash) {
			return ErrNoReview
		}
		if p.Closed != "" || p.Expires < now.Unix() || slotNow >= p.TTL {
			return fmt.Errorf("%w: the request is closed or expired", ErrNotPending)
		}
		fp, err := fpOfHex(p.From)
		if err != nil {
			return err
		}
		_, ps, err := s.loadParties(w)
		if err != nil {
			return err
		}
		found := false
		for _, c := range ps {
			if c.Fingerprint == fp && c.Active() {
				coord, found = c, true
			}
		}
		if !found {
			return errors.New("the coordinator is not an active enrolled party")
		}
		p.State = reqSigning
		q = *p
		return writeJSON(w, signerRef, st)
	})
	if err != nil {
		return Handled{}, err
	}
	env, rid, serr := s.sign(ctx, local, coord, q, now)
	if serr != nil {
		// Nothing was answered: the request is waiting again.
		_ = s.Store.Update(ctx, func(w ports.Writer) error {
			st, err := readSigner(w)
			if err != nil {
				return err
			}
			if p := st.byID(q.ID); p != nil && p.State == reqSigning {
				p.State = reqPending
			}
			return writeJSON(w, signerRef, st)
		})
		return Handled{}, serr
	}
	err = s.Store.Update(ctx, func(w ports.Writer) error {
		st, err := readSigner(w)
		if err != nil {
			return err
		}
		p := st.byID(q.ID)
		if p == nil {
			return ErrUnknownRequest
		}
		p.State, p.ResponseID, p.Response = reqApproved, hexMsg(rid), env
		if err := writeJSON(w, signerRef, st); err != nil {
			return err
		}
		ev := eventOf(now, "request-approved", q.Collection, q.Slot, a.tok.hash)
		ev.Peer, ev.Detail = q.From, "response "+hexMsg(rid)
		if err := appendEvent(w, ev); err != nil {
			return err
		}
		return enqueue(w, now, OutItem{ID: hexMsg(rid), To: q.From, Type: string(party.TypeSigningResponse), Collection: q.Collection,
			Slot: q.Slot, Expires: q.Expires, Envelope: env})
	})
	if err != nil {
		return Handled{}, err
	}
	return Handled{Type: party.TypeSigningRequest, Sender: coord.Fingerprint, HasSender: true, Effect: "approved", Request: a.tok.id}, nil
}

// sign makes the witness with the signer that holds the key, verifies it
// itself, and seals the response.
func (s Signer) sign(ctx context.Context, local ports.LocalIdentity, coord party.Party, q storedRequest, now time.Time) ([]byte, party.MessageID, error) {
	var zero party.MessageID
	kh, err := hex.DecodeString(q.KeyHash)
	if err != nil || len(kh) != 28 {
		return nil, zero, errors.New("the stored key hash")
	}
	var keyHash [28]byte
	copy(keyHash[:], kh)
	key, holds, err := s.Keys.FindKey(ctx, custody.Role(q.Role), keyHash)
	if err != nil {
		return nil, zero, err
	}
	if !holds {
		return nil, zero, errors.New("this machine no longer holds that key")
	}
	// The operator authenticates again for this signature: the gate decides
	// how (the store passphrase for pool cold, payment and owner stake keys).
	hash := blake2b.Sum256(q.Body)
	if err := s.Gate.Reauthenticate(ctx, key, hash); err != nil {
		return nil, zero, err
	}
	signer, err := s.Signers.SignerFor(key)
	if err != nil {
		return nil, zero, err
	}
	wt, ok := signer.(ports.TxWitnesser)
	if !ok {
		return nil, zero, errors.New("the signer of that key cannot witness transactions")
	}
	if hexHash(hash) != q.BodyHash {
		return nil, zero, errors.New("the stored body does not hash to the request's body hash")
	}
	// The signer takes a transaction shaped like cardano-cli's txbody file:
	// [body, {}, true, auxiliary data or null].
	tx := append([]byte{0x84}, q.Body...)
	tx = append(tx, 0xa0, 0xf5)
	if len(q.Aux) > 0 {
		tx = append(tx, q.Aux...)
	} else {
		tx = append(tx, 0xf6)
	}
	w, err := wt.Witness(ctx, key, txbuild.TxBody{CBOR: tx, ID: chain.TxID(hash)})
	if err != nil {
		return nil, zero, err
	}
	// OUT-006: the signer verifies its own witness as the coordinator will.
	if err := party.VerifyWitness(hash, w.VKey, w.Signature, keyHash); err != nil {
		return nil, zero, err
	}
	cid, err := hexCollOf(q.Collection)
	if err != nil {
		return nil, zero, err
	}
	rq, err := msgOfHex(q.ID)
	if err != nil {
		return nil, zero, err
	}
	return local.Seal(coord.Identity, party.SigningResponse{Collection: cid, Slot: party.SlotID(q.Slot), Request: rq,
		Witness: party.EncodeWitness(w.VKey, w.Signature)}, now, time.Unix(q.Expires, 0))
}

// Refuse declines a request: a SigningRefusal with reason "declined" is
// sealed to the coordinator, stored and queued. It needs no review.
//
// spec: SPO-Xparty-OUT-006, SPO-Xparty-PRE-006
func (s Signer) Refuse(ctx context.Context, id party.MessageID) (Handled, error) {
	local, err := s.Kit.Local(ctx)
	if err != nil {
		return Handled{}, err
	}
	defer local.Destroy()
	now := s.Clock.Now()
	var out Handled
	err = s.Store.Update(ctx, func(w ports.Writer) error {
		st, err := readSigner(w)
		if err != nil {
			return err
		}
		q := st.byID(hexMsg(id))
		if q == nil {
			return ErrUnknownRequest
		}
		if q.State != reqPending {
			return fmt.Errorf("%w: it is %s", ErrNotPending, q.State)
		}
		fp, err := fpOfHex(q.From)
		if err != nil {
			return err
		}
		_, ps, err := s.loadParties(w)
		if err != nil {
			return err
		}
		var coord *party.Party
		for i := range ps {
			if ps[i].Fingerprint == fp {
				coord = &ps[i]
			}
		}
		if coord == nil || !coord.Active() {
			return errors.New("the coordinator is not an active enrolled party")
		}
		cid, err := hexCollOf(q.Collection)
		if err != nil {
			return err
		}
		env, rid, err := local.Seal(coord.Identity, party.SigningRefusal{Collection: cid, Slot: party.SlotID(q.Slot), Request: id, Reason: party.RefuseDeclined},
			now, time.Unix(q.Expires, 0))
		if err != nil {
			return err
		}
		q.State, q.Reason, q.ResponseID, q.Response = reqRefused, party.RefuseDeclined.String(), hexMsg(rid), env
		if err := writeJSON(w, signerRef, st); err != nil {
			return err
		}
		ev := eventOf(now, "request-declined", q.Collection, q.Slot, [32]byte{})
		ev.Peer, ev.Reason = q.From, party.RefuseDeclined.String()
		if err := appendEvent(w, ev); err != nil {
			return err
		}
		out = Handled{Type: party.TypeSigningRequest, Sender: coord.Fingerprint, HasSender: true, Effect: "declined", Request: id}
		return enqueue(w, now, OutItem{ID: q.ResponseID, To: q.From, Type: string(party.TypeSigningRefusal), Collection: q.Collection,
			Slot: q.Slot, Expires: q.Expires, Envelope: env})
	})
	return out, err
}

// Hello opens a connection to a coordinator when the signer has nothing else
// to send, so that it can receive its pending requests. It is sent at once,
// not queued, lives five minutes, and has no effect beyond authenticating the
// connection (SPO-Xparty-INV-021).
//
// spec: SPO-Xparty-INV-021
func (s Signer) Hello(ctx context.Context, coordinator string, send ports.EnvelopeSender) error {
	local, err := s.Kit.Local(ctx)
	if err != nil {
		return err
	}
	defer local.Destroy()
	var coord party.Party
	err = s.Store.View(ctx, func(r ports.Reader) error {
		var err error
		coord, err = s.Parties.ByName(r, coordinator)
		return err
	})
	if err != nil {
		return err
	}
	if !coord.Active() || !coord.HasRole(party.RoleCoordinator) {
		return fmt.Errorf("%s is not an active coordinator", coordinator)
	}
	now := s.Clock.Now()
	env, _, err := local.Seal(coord.Identity, party.Hello{}, now, now.Add(party.MaxHelloLifetime))
	if err != nil {
		return err
	}
	return send.Send(ctx, coord.Fingerprint, env)
}
