package multisig

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"slices"
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

// ErrNoAddressInspector: the signer was built without an address inspector.
// Without one it cannot classify an address, so it refuses to work on any
// request rather than pass one unchecked (SPO-Xparty-PR-004). It is a
// configuration error of the wiring, not a refusal of a request.
var ErrNoAddressInspector = errors.New("multisig: the signer has no address inspector: configure Signer.Addresses")

// OwnResolver is the signer's own view of the chain, as the signer use case
// accepts it (SPO-Xparty-PR-005). An offline snapshot is not authenticated:
// whoever wrote it chose what each input is. It is therefore a resolver only
// when it is the signer's own, a snapshot this operator made on this machine
// from a provider it trusts. A transfer file received from another party, a
// coordinator's bundle above all, is never a resolver source: it would let the
// coordinator tell the signer that a script input is its own or a foreign one.
// The two constructors are the only way to make one; the wiring that calls
// OwnSnapshot states that the file is the operator's own.
type OwnResolver struct{ r ports.UtxoResolver }

// OwnProvider is the signer's own chain provider (a node, a Koios connection
// it configured).
func OwnProvider(r ports.UtxoResolver) OwnResolver { return OwnResolver{r} }

// OwnSnapshot is an offline snapshot that the operator took on this machine.
// Never call it with a file that arrived from another party.
func OwnSnapshot(r ports.UtxoResolver) OwnResolver { return OwnResolver{r} }

// IsSet reports whether there is a resolver at all.
func (o OwnResolver) IsSet() bool { return o.r != nil }

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
	// Owned is what this signer owns, as credentials: the key hashes of the
	// payment keys and stake keys in its own store (SPO-Xparty-PR-002). The
	// wiring derives it from the store; it is never taken from the
	// coordinator. The zero value owns nothing.
	Owned party.OwnedKeys
	// Resolver is the signer's OWN chain provider or offline snapshot, never
	// the coordinator's: it resolves every input of a body by reference. Only
	// OwnProvider and OwnSnapshot make one, so a bundle that a coordinator
	// carried cannot be passed by accident (SPO-Xparty-PR-005). The zero value,
	// or an input it cannot resolve, means the inputs were not checked: a
	// payment-key request is then refused, and the review of any other key
	// says its inputs were not checked.
	Resolver OwnResolver
	// Addresses decodes an address, to tell whose it is by its credentials.
	// Without it no input or output can be classified.
	Addresses ports.AddressInspector
	// Gate asks the operator to authenticate again before a key signs. There
	// is no default: with no gate Approve refuses (SPO-Xparty-INV-016).
	Gate ports.ApprovalGate
	// MaxTxSize is the protocol's maxTxSize; zero takes the upper bound
	// party.DefaultMaxTxSize (SPO-Xparty-INV-008).
	MaxTxSize int
	// GateTimeout is how long a claimed approval may hold the request in the
	// signing state before another approval may take it over: a crash between
	// the claim and the stored response leaves it there. Zero takes
	// DefaultGateTimeout (SPO-Xparty-INV-028).
	GateTimeout time.Duration
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

// DefaultGateTimeout is how long a claimed approval is believed to be alive.
const DefaultGateTimeout = 10 * time.Minute

func (s Signer) gateTimeout() time.Duration {
	if s.GateTimeout > 0 {
		return s.GateTimeout
	}
	return DefaultGateTimeout
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
	// SigningSince is the unix time of the claim that put the request in the
	// signing state.
	SigningSince int64  `json:"signingSince,omitempty"`
	Reason       string `json:"reason,omitempty"`
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

// claimable reports that an approval may take the request: it is pending, or
// it was claimed by an approval that never stored its response and has been in
// the signing state longer than timeout (a crash mid-sign). That is the only
// way out of the signing state other than the approval's own end
// (SPO-Xparty-INV-028).
// overNetwork: the request did not arrive by file. A stored via that is
// anything but "file" is a network (SPO-Xparty-PRE-007).
func (q storedRequest) overNetwork() bool { return q.Via != ports.ViaFile.String() }

func (q storedRequest) claimable(now time.Time, timeout time.Duration) bool {
	return q.State == reqPending ||
		(q.State == reqSigning && now.Unix() >= q.SigningSince+int64(timeout/time.Second))
}

// prune drops what can no longer matter. A refused request is dropped when its
// envelope expires: a later duplicate is refused by the window check, and the
// replay log holds the id until then. Every other request is kept a day past
// its expiry. Refused entries per sender are capped at party.MaxReplayPerSender,
// oldest first, so a flood of short-lived refused requests leaves bounded
// state (SPO-Xparty-INV-029).
func (s *signerState) prune(now time.Time) {
	kept := s.Requests[:0]
	for _, q := range s.Requests {
		limit := q.Expires + 86400
		if q.State == reqRefused {
			limit = q.Expires
		}
		if limit >= now.Unix() {
			kept = append(kept, q)
		}
	}
	s.Requests = kept
	refused := map[string]int{}
	for _, q := range s.Requests {
		if q.State == reqRefused {
			refused[q.From]++
		}
	}
	kept = s.Requests[:0]
	for _, q := range s.Requests {
		if q.State == reqRefused && refused[q.From] > party.MaxReplayPerSender {
			refused[q.From]--
			continue
		}
		kept = append(kept, q)
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
// A request whose id is already stored (answered, refused in silence or still
// waiting) and arrives again, which the coordinator does on every new
// connection until the slot is filled, is not a replay and has no security
// event: an answered one is answered again with the stored response, the
// others change nothing (SPO-Xparty-INV-017).
//
// rcv carries how the envelope arrived, set by the transport that delivered
// it (SPO-Xparty-INV-024); an unknown kind is a network.
//
// spec: SPO-Xparty-PRE-002, SPO-Xparty-PRE-006, SPO-Xparty-INV-006, SPO-Xparty-INV-007, SPO-Xparty-INV-010, SPO-Xparty-INV-017, SPO-Xparty-INV-024, SPO-Xparty-SEC-002
func (s Signer) Handle(ctx context.Context, rcv ports.Received) (Handled, error) {
	raw, via := rcv.Envelope, rcv.Via()
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
			if q := st.byID(hexMsg(id)); q != nil && q.From == hexFP(o.Sender().Fingerprint) {
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
		if again != nil && again.Response != nil {
			return s.resend(ctx, o, again, now)
		}
		if again != nil { // waiting, signing or refused in silence: nothing to answer, nothing to record
			return Handled{Type: party.TypeSigningRequest, Sender: o.Sender().Fingerprint, HasSender: true, Request: o.ID(), Effect: "duplicate"}, nil
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
	if err := s.Store.Update(ctx, func(w ports.Writer) error { return appendRefusal(w, ev) }); err != nil {
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
// credentials and chain view (SPO-Xparty-PR-002). Every input is resolved by
// reference through the signer's own resolver and classified by the payment
// credential of the address it is at, so an input at any address form of an
// owned payment key is the signer's, whatever address the coordinator or the
// signer's own lists name. It fails only on an amount beyond any supply or a
// sum that overflows (party.ErrAmount): that body is refused. When the inputs
// cannot be resolved the Flow says so, and Flow.Refusal decides what that means
// for the key role.
func (s Signer) resolveFlow(ctx context.Context, v party.TxView, role custody.Role, overNetwork bool) (party.Flow, error) {
	if s.Addresses == nil {
		return party.Flow{}, ErrNoAddressInspector
	}
	f := party.FlowFacts{Role: role}
	inspect := func(a string) (ports.AddressInfo, bool) {
		info, err := s.Addresses.InspectAddress(chain.Address(a))
		return info, err == nil
	}
	f.OutputOwnership = func(a string) (bool, string) {
		info, ok := inspect(a)
		if !ok {
			return false, ""
		}
		return s.Owned.OutputOwnership(keyHashPtr(info.PaymentKeyHash, info.PaymentIsScript), info.Kind == ports.AddrEnterprise, keyHashPtr(info.StakeKeyHash, false))
	}
	f.IsOwnReward = func(a string) bool {
		info, ok := inspect(a)
		return ok && info.Kind == ports.AddrReward && info.StakeKeyHash != nil && s.Owned.OwnsStake(*info.StakeKeyHash)
	}
	// Fail closed: an account that cannot be inspected, is not a reward
	// account or has no key credential is a script's.
	f.IsScriptReward = func(a string) bool {
		info, ok := inspect(a)
		return !ok || info.Kind != ports.AddrReward || info.StakeKeyHash == nil
	}
	f.IsOwnCredential = s.Owned.OwnsCredential
	// notChecked: why is a stable sentence; whatever the provider said goes in
	// detail, which is shown but not part of the digest (SPO-Xparty-INV-026).
	// For a key that cannot spend from its own address the review says plainly
	// that the inputs were not checked and what that leaves open
	// (SPO-Xparty-PR-004).
	notChecked := func(why, detail string) (party.Flow, error) {
		f.NotChecked, f.NotCheckedDetail = why, detail
		if role != custody.RolePayment {
			f.NotChecked = party.NotCheckedText
			if s.Resolver.IsSet() {
				f.NotChecked += " (" + why + ")"
			}
		}
		return party.BuildFlow(v, f)
	}
	if !s.Resolver.IsSet() {
		return notChecked("this signer has no chain view of its own", "")
	}
	refs := make([]chain.OutRef, 0, len(v.Inputs))
	for _, in := range v.Inputs {
		ref := chain.OutRef{TxID: chain.TxID(in.TxID), Index: in.Index}
		if !slices.Contains(refs, ref) {
			refs = append(refs, ref)
		}
	}
	got, err := s.Resolver.r.ResolveUtxos(ctx, refs)
	if err != nil {
		return notChecked("the inputs cannot be resolved", err.Error())
	}
	f.Inputs = map[party.ViewInput]party.ResolvedInput{}
	for _, in := range v.Inputs {
		ref := chain.OutRef{TxID: chain.TxID(in.TxID), Index: in.Index}
		reading := got[ref]
		u, ok := reading.Get()
		switch {
		case !ok && reading.IsNone():
			return notChecked(fmt.Sprintf("input %s does not exist or is spent, as the provider says", ref), "")
		case !ok:
			return notChecked(fmt.Sprintf("input %s was not resolved", ref), reading.Why())
		}
		info, err := s.Addresses.InspectAddress(u.Address)
		r := party.ResolvedInput{Lovelace: uint64(u.Lovelace)}
		switch {
		case err != nil && overNetwork:
			return notChecked(fmt.Sprintf("input %s is at an address that cannot be read", ref), err.Error())
		case err != nil:
			// Fail closed: an address that cannot be inspected is treated as a
			// script's and refused, never as foreign.
			r.Script = true
			f.Inputs[in] = r
			continue
		}
		// A script payment credential is never own: its input is refused
		// (RefuseScriptInput), not classified foreign. The header of the
		// address says so too, whatever the inspector says.
		r.Script = info.PaymentIsScript || party.AddressPaymentIsScript(string(u.Address))
		if p := keyHashPtr(info.PaymentKeyHash, r.Script); p != nil {
			r.Own = s.Owned.OwnsPayment(*p)
		}
		for _, a := range u.Assets {
			if a.Quantity > math.MaxInt64 {
				return party.Flow{}, party.ErrAmount
			}
			r.Assets = append(r.Assets, party.ViewAsset{Policy: a.Asset.Policy, Name: a.Asset.Name, Quantity: int64(a.Quantity)})
		}
		f.Inputs[in] = r
	}
	f.Checked = true
	return party.BuildFlow(v, f)
}

// keyHashPtr is the key hash of an address credential, nil for a script or a
// credential that is not there.
func keyHashPtr(h *txbuild.KeyHash, isScript bool) *[28]byte {
	if h == nil || isScript {
		return nil
	}
	out := [28]byte(*h)
	return &out
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
//
// spec: SPO-Xparty-PRE-006, SPO-Xparty-PR-004, SPO-Xparty-INV-029
func (s Signer) onRequest(ctx context.Context, local ports.LocalIdentity, o ports.OpenedEnvelope, req party.SigningRequest, via ports.TransportKind, slotNow uint64, now time.Time) (Handled, error) {
	if s.Addresses == nil {
		return Handled{}, ErrNoAddressInspector
	}
	facts := party.RequestFacts{WorkspaceMagic: s.NetworkMagic, CurrentSlot: slotNow, OverNetwork: !via.IsFile()}
	view, _, reason, detail, refuse := s.decodeRequest(req, facts)
	var key custody.KeyRef
	if !refuse {
		if err := party.CheckScope(o.Sender().Scope, req.KeyRole, view); err != nil {
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
		fl, err := s.resolveFlow(ctx, view, req.KeyRole, facts.OverNetwork)
		switch {
		case errors.Is(err, party.ErrAmount):
			reason, detail, refuse = party.RefuseUndisplayable, err.Error(), true
		case err != nil:
			return Handled{}, err
		default:
			if reason, refuse = fl.Refusal(req.KeyRole, facts.OverNetwork); refuse {
				detail = reason.String()
			}
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
		st.Requests = append(st.Requests, q)
		st.prune(now)
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
		if err := appendRefusal(w, ev); err != nil {
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
			if q.claimable(s.Clock.Now(), s.gateTimeout()) && q.Expires >= s.Clock.Now().Unix() && q.Closed == "" {
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
	// flow is the digest of the flow the operator was shown: Approve works
	// the flow out again and refuses when it is another (SPO-Xparty-INV-016).
	flow [32]byte
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

// ErrReviewStale: something the review depended on is not as it was shown when
// the approval is claimed: the sender is no longer an active coordinator, the
// scope it is enrolled with no longer allows the request, or the flow the
// signer works out now differs from the one the operator read. Nothing is
// signed; the request can be reviewed again (SPO-Xparty-INV-016).
var ErrReviewStale = errors.New("the request or the signer's own view changed since the review: nothing was signed, review it again")

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
	if !q.claimable(now, s.gateTimeout()) {
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
	flow, err := s.resolveFlow(ctx, view, custody.Role(q.Role), q.overNetwork())
	if err != nil {
		return Review{}, fmt.Errorf("%w: %v", ErrCannotReview, err)
	}
	if reason, bad := flow.Refusal(custody.Role(q.Role), q.overNetwork()); bad {
		return Review{}, fmt.Errorf("%w: %s", ErrCannotReview, reason)
	}
	rv := Review{RequestID: id, BodyHash: hash, Role: custody.Role(q.Role), Coordinator: q.FromName, Via: q.Via, View: view, Flow: flow, Aux: aux,
		TotalOutput: view.TotalOutput(), ClaimedPurpose: q.Purpose, token: &reviewToken{id: id, hash: hash, flow: flow.Digest()}}
	copy(rv.KeyHash[:], kh)
	err = s.Store.Update(ctx, func(w ports.Writer) error {
		st, err := readSigner(w)
		if err != nil {
			return err
		}
		p := st.byID(hexMsg(id))
		if p == nil || !p.claimable(now, s.gateTimeout()) || p.BodyHash != q.BodyHash {
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
// spec: SPO-Xparty-OUT-006, SPO-Xparty-INV-016, SPO-Xparty-INV-017, SPO-Xparty-INV-025, SPO-Xparty-INV-026, SPO-Xparty-INV-028, SPO-Xparty-PRE-005
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
	// What the claim re-checks is worked out first, outside the store
	// transaction: the chain view of the signer may be a network call. The
	// claim then compares it with what was reviewed.
	var q storedRequest
	if err := s.Store.View(ctx, func(r ports.Reader) error {
		st, err := readSigner(r)
		if err != nil {
			return err
		}
		p := st.byID(hexMsg(a.tok.id))
		if p == nil {
			return ErrUnknownRequest
		}
		q = *p
		return nil
	}); err != nil {
		return Handled{}, err
	}
	var view party.TxView
	var flow party.Flow
	var flowErr error
	view, viewErr := s.Viewer.View(q.Body)
	if viewErr == nil {
		flow, flowErr = s.resolveFlow(ctx, view, custody.Role(q.Role), q.overNetwork())
	}
	var coord party.Party
	// Claim: the request must be pending, reviewed for this body hash, not
	// expired, and not closed; the sender must still be an active
	// coordinator with a scope that still allows it; the flow must be the one
	// reviewed. It is then marked as being signed.
	err = s.Store.Update(ctx, func(w ports.Writer) error {
		st, err := readSigner(w)
		if err != nil {
			return err
		}
		p := st.byID(hexMsg(a.tok.id))
		if p == nil {
			return ErrUnknownRequest
		}
		// Only a pending request is claimed, or one whose earlier claim is
		// older than the gate timeout (a crash mid-sign); a second approval
		// while the first is at the gate is refused (SPO-Xparty-INV-028).
		if !p.claimable(now, s.gateTimeout()) {
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
			if c.Fingerprint == fp {
				coord, found = c, true
			}
		}
		switch {
		case !found || !coord.Active():
			return fmt.Errorf("%w: the coordinator is not an active enrolled party", ErrReviewStale)
		case !coord.HasRole(party.RoleCoordinator):
			return fmt.Errorf("%w: the sender no longer has the coordinator role", ErrReviewStale)
		case viewErr != nil || flowErr != nil:
			return fmt.Errorf("%w: the request no longer displays: %v", ErrReviewStale, errors.Join(viewErr, flowErr))
		}
		if err := party.CheckScope(coord.Scope, custody.Role(p.Role), view); err != nil {
			return fmt.Errorf("%w: %v", ErrReviewStale, err)
		}
		if _, bad := flow.Refusal(custody.Role(p.Role), p.overNetwork()); bad || flow.Digest() != a.tok.flow {
			return fmt.Errorf("%w: what the body moves for this signer is not what was shown", ErrReviewStale)
		}
		p.State, p.SigningSince = reqSigning, now.Unix()
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
			if p := st.byID(q.ID); p != nil && p.State == reqSigning && p.SigningSince == q.SigningSince {
				p.State, p.SigningSince = reqPending, 0
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
		if p.State != reqSigning || p.SigningSince != q.SigningSince {
			// Another approval took over a stale claim: its answer stands.
			return fmt.Errorf("%w: it is %s", ErrNotPending, p.State)
		}
		p.State, p.SigningSince, p.ResponseID, p.Response = reqApproved, 0, hexMsg(rid), env
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
		if !q.claimable(now, s.gateTimeout()) {
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

// NewHello seals a fresh Hello to a coordinator: a new message id and a
// five-minute expiry each time. The tailcat client calls it, through the
// callback the wiring gives it, as the first frame of every connection, so
// that no connection starts with a message that is in the coordinator's
// replay log (SPO-Xparty-INV-018, INV-021). The adapter holds no identity key:
// the key stays here.
//
// spec: SPO-Xparty-INV-018, SPO-Xparty-INV-021
func (s Signer) NewHello(ctx context.Context, coordinator string) ([]byte, error) {
	local, err := s.Kit.Local(ctx)
	if err != nil {
		return nil, err
	}
	defer local.Destroy()
	var coord party.Party
	err = s.Store.View(ctx, func(r ports.Reader) error {
		var err error
		coord, err = s.Parties.ByName(r, coordinator)
		return err
	})
	if err != nil {
		return nil, err
	}
	if !coord.Active() || !coord.HasRole(party.RoleCoordinator) {
		return nil, fmt.Errorf("%s is not an active coordinator", coordinator)
	}
	now := s.Clock.Now()
	env, _, err := local.Seal(coord.Identity, party.Hello{}, now, now.Add(party.MaxHelloLifetime))
	return env, err
}

// Hello sends one Hello to a coordinator at once, not queued. The tailcat
// client already sends one as the first frame of every connection, so a signer
// that has nothing to send only has to connect; Hello is for a transport that
// does not (SPO-Xparty-INV-021).
//
// spec: SPO-Xparty-INV-021
func (s Signer) Hello(ctx context.Context, coordinator string, send ports.EnvelopeSender) error {
	env, err := s.NewHello(ctx, coordinator)
	if err != nil {
		return err
	}
	var coord party.Party
	err = s.Store.View(ctx, func(r ports.Reader) error {
		var err error
		coord, err = s.Parties.ByName(r, coordinator)
		return err
	})
	if err != nil {
		return err
	}
	return send.Send(ctx, coord.Fingerprint, env)
}
