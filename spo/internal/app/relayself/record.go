package relayself

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/mochipool/workbench/spo/internal/app/relaybinding"
	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relaypeer"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// Bounds of the record (SPO-Xmailbox-OUT-097).
const (
	// MaxRecordBytes bounds the stored record; it is checked before it is parsed.
	MaxRecordBytes = 64 << 10
	// MaxPendingRevokes bounds the pending revokes.
	MaxPendingRevokes = 64
	// ReservedRevokes of them are kept for the revokes that must always find
	// room: this device's own forget, the revoke of a lost device and the revoke
	// of the old device at a rotation. A revoke made with `revoke` takes the
	// others only (SPO-Xmailbox-OUT-098).
	ReservedRevokes = 16
	// MaxNotBefores bounds the devices with a stored not-before.
	MaxNotBefores = 64
	recordVersion = 1
)

// ErrCorrupt: the stored record does not decode strictly, is over a bound, or
// holds a statement that does not verify; nothing is decided from it.
var ErrCorrupt = errors.New("relayself: the stored relay state is corrupt")

// Binding is this device's current binding, as stored: the bytes and what they
// say.
type Binding struct {
	Statement, Key []byte
	WalletKey      party.WalletKey
	Device         party.Fingerprint
	From, Until    int64
}

// State is this device's relay state (SPO-Xmailbox-OUT-097).
type State struct {
	Binding  *Binding
	Prepared *relaybinding.Prepared
	Revokes  []relayport.Revoke
	// NotBefore is the latest revoke not-before this device made, per device.
	NotBefore map[party.Fingerprint]int64
	// Foreign is a stored binding that verifies, but for another device than
	// this one (a record written before a rotation cleared it): it is not this
	// device's binding, so it is dropped at the next write and shown to the
	// operator until then. ForeignPrepared says the same of a prepared binding
	// request. Neither is ever encoded.
	Foreign         *Binding
	ForeignPrepared bool
	// RecordedAt is, per pending revoke (by its revokeID), the relays that
	// recorded it, at most MaxRelays names, the latest last. A revoke is owed to
	// every listed relay not named here until it ends (SPO-Xmailbox-OUT-111).
	RecordedAt map[string][]string
}

// mergeRelays adds the names of more not yet in have, the latest last, and keeps
// the last MaxRelays: a name pushed out is only owed the revoke again.
func mergeRelays(have, more []string) []string {
	out := append([]string(nil), have...)
	for _, n := range more {
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	if len(out) > MaxRelays {
		out = out[len(out)-MaxRelays:]
	}
	return out
}

type recordJSON struct {
	V         int            `json:"v"`
	Binding   *bindingJSON   `json:"binding,omitempty"`
	Prepared  *preparedJSON  `json:"prepared,omitempty"`
	Revokes   []revokeJSON   `json:"revokes,omitempty"`
	NotBefore []notBeforeRec `json:"not_before,omitempty"`
}

type bindingJSON struct {
	Statement string `json:"statement"`
	COSEKey   string `json:"cose_key"`
}

type preparedJSON struct {
	Kind       uint8  `json:"kind"`
	WalletKey  string `json:"wallet_key"`
	SignFor    string `json:"sign_for"`
	Payload    string `json:"payload"`
	PreparedAt int64  `json:"prepared_at"`
	ExpiresAt  int64  `json:"expires_at"`
	ID         string `json:"id"`
}

type revokeJSON struct {
	Kind  string `json:"kind"` // "device" or "wallet"
	Until int64  `json:"until"`
	// device-signed
	Ed25519   string `json:"ed25519,omitempty"`
	X25519    string `json:"x25519,omitempty"`
	NotBefore int64  `json:"not_before,omitempty"`
	Signature string `json:"signature,omitempty"`
	// wallet-signed
	Statement string `json:"statement,omitempty"`
	COSEKey   string `json:"cose_key,omitempty"`
	// the relays that recorded it
	RecordedAt []string `json:"recorded_at,omitempty"`
}

type notBeforeRec struct {
	Device string `json:"device"`
	At     int64  `json:"at"`
}

func hx(b []byte) string { return hex.EncodeToString(b) }

// unhx decodes lower-case, even-length hex of min to max bytes, the length
// checked before anything is decoded.
func unhx(s string, minLen, maxLen int) ([]byte, error) {
	if len(s) < 2*minLen || len(s) > 2*maxLen || len(s)%2 != 0 {
		return nil, fmt.Errorf("%w: hex of %d characters, want %d to %d bytes", ErrCorrupt, len(s), minLen, maxLen)
	}
	b, err := hex.DecodeString(s)
	if err != nil || hex.EncodeToString(b) != s {
		return nil, fmt.Errorf("%w: hex is not lower-case canonical", ErrCorrupt)
	}
	return b, nil
}

func fixed(dst []byte, s string) error {
	b, err := unhx(s, len(dst), len(dst))
	if err != nil {
		return err
	}
	copy(dst, b)
	return nil
}

// Encode is the stored form of a state.
func Encode(s State) ([]byte, error) {
	j := recordJSON{V: recordVersion}
	if b := s.Binding; b != nil {
		j.Binding = &bindingJSON{Statement: hx(b.Statement), COSEKey: hx(b.Key)}
	}
	if p := s.Prepared; p != nil {
		j.Prepared = &preparedJSON{Kind: uint8(p.Kind), WalletKey: hx(p.WalletKey[:]), SignFor: hx(p.SignFor), Payload: hx(p.Payload),
			PreparedAt: p.PreparedAt, ExpiresAt: p.ExpiresAt, ID: hx(p.ID[:])}
	}
	if len(s.Revokes) > MaxPendingRevokes || len(s.NotBefore) > MaxNotBefores {
		return nil, fmt.Errorf("relayself: %d revokes or %d not-befores over the bound", len(s.Revokes), len(s.NotBefore))
	}
	for _, r := range s.Revokes {
		at := s.RecordedAt[revokeID(r)]
		if err := checkRecordedAt(at); err != nil {
			return nil, err
		}
		switch r.Kind {
		case relayport.RevokeByDeviceKey:
			j.Revokes = append(j.Revokes, revokeJSON{Kind: "device", Until: r.Until, Ed25519: hx(r.Keys.Ed25519[:]), X25519: hx(r.Keys.X25519[:]),
				NotBefore: r.NotBefore, Signature: hx(r.Signature[:]), RecordedAt: at})
		case relayport.RevokeByWalletKey:
			j.Revokes = append(j.Revokes, revokeJSON{Kind: "wallet", Until: r.Until, Statement: hx(r.Sign1), COSEKey: hx(r.Key), RecordedAt: at})
		default:
			return nil, fmt.Errorf("relayself: a revoke of kind %d", r.Kind)
		}
	}
	devs := make([]party.Fingerprint, 0, len(s.NotBefore))
	for d := range s.NotBefore {
		devs = append(devs, d)
	}
	slices.SortFunc(devs, func(a, b party.Fingerprint) int { return slices.Compare(a[:], b[:]) })
	for _, d := range devs {
		j.NotBefore = append(j.NotBefore, notBeforeRec{Device: hx(d[:]), At: s.NotBefore[d]})
	}
	return json.Marshal(j)
}

// Decode reads the stored record of the device with fingerprint self strictly
// (SPO-Xmailbox-OUT-097): the size first; strict JSON (no duplicate or unknown
// key, version 1); every count within its bound; hex canonical; the binding
// verifies for self at its own from; every revoke verifies at its own
// not-before; the prepared request is well formed (its binding hash is checked
// at import).
func Decode(b []byte, self party.Fingerprint) (State, error) {
	if len(b) > MaxRecordBytes {
		return State{}, fmt.Errorf("%w: %d bytes, at most %d", ErrCorrupt, len(b), MaxRecordBytes)
	}
	var j recordJSON
	if err := ports.UnmarshalStrict(b, &j); err != nil {
		return State{}, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if j.V != recordVersion {
		return State{}, fmt.Errorf("%w: version %d", ErrCorrupt, j.V)
	}
	if len(j.Revokes) > MaxPendingRevokes || len(j.NotBefore) > MaxNotBefores {
		return State{}, fmt.Errorf("%w: %d revokes or %d not-befores, at most %d and %d", ErrCorrupt, len(j.Revokes), len(j.NotBefore), MaxPendingRevokes, MaxNotBefores)
	}
	var s State
	pol := relaybind.DefaultPolicy()
	if jb := j.Binding; jb != nil {
		st, err := unhx(jb.Statement, 1, relaybind.MaxSign1Bytes)
		if err != nil {
			return State{}, err
		}
		key, err := unhx(jb.COSEKey, 1, relaybind.MaxKeyBytes)
		if err != nil {
			return State{}, err
		}
		bd, err := bindingOf(st, key, self)
		switch {
		case err == nil:
			s.Binding = &bd
		default:
			// A binding that verifies for the device it names, another than this
			// one, is a record from before a rotation: dropped with a notice, so it
			// does not make the revokes unreadable. Anything else is corrupt.
			fd, ferr := foreignBindingOf(st, key, self)
			if ferr != nil {
				return State{}, fmt.Errorf("%w: the binding: %v", ErrCorrupt, err)
			}
			s.Foreign = &fd
		}
	}
	if jp := j.Prepared; jp != nil {
		p, err := preparedOf(*jp)
		if err != nil {
			return State{}, err
		}
		if p.Kind == relaybinding.PreparedBindingKind && p.Binding.Device != self {
			s.ForeignPrepared = true // a request for another device: never imported here
		} else {
			s.Prepared = &p
		}
	}
	for _, jr := range j.Revokes {
		r, err := revokeOf(jr, pol)
		if err != nil {
			return State{}, err
		}
		if err := checkRecordedAt(jr.RecordedAt); err != nil {
			return State{}, fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
		s.Revokes = append(s.Revokes, r)
		if len(jr.RecordedAt) > 0 {
			if s.RecordedAt == nil {
				s.RecordedAt = map[string][]string{}
			}
			s.RecordedAt[revokeID(r)] = jr.RecordedAt
		}
	}
	if len(j.NotBefore) > 0 {
		s.NotBefore = make(map[party.Fingerprint]int64, len(j.NotBefore))
	}
	for _, n := range j.NotBefore {
		var d party.Fingerprint
		if err := fixed(d[:], n.Device); err != nil {
			return State{}, err
		}
		if _, dup := s.NotBefore[d]; dup || n.At < 0 || n.At > relaybind.MaxTime {
			return State{}, fmt.Errorf("%w: a not-before entry", ErrCorrupt)
		}
		s.NotBefore[d] = n.At
	}
	return s, nil
}

// checkRecordedAt checks the relays that recorded a revoke: at most MaxRelays
// valid relay names, none twice.
func checkRecordedAt(at []string) error {
	if len(at) > MaxRelays {
		return fmt.Errorf("relayself: a revoke recorded at %d relays, at most %d", len(at), MaxRelays)
	}
	for i, n := range at {
		if !relayNameRE.MatchString(n) || slices.Contains(at[:i], n) {
			return fmt.Errorf("relayself: a relay name %q that a revoke was recorded at", n)
		}
	}
	return nil
}

// bindingOf verifies a binding for self at its own from (the stored binding may
// have ended since) and returns what it says.
func bindingOf(st, key []byte, self party.Fingerprint) (Binding, error) {
	sm, err := relaybind.ParseStatement(st)
	if err != nil {
		return Binding{}, err
	}
	pb, err := relaybind.ParseBinding(sm.Payload())
	if err != nil {
		return Binding{}, err
	}
	ev, err := relaypeer.Verify(st, key, self, pb.From, relaybind.DefaultPolicy(), relaypeer.NetworkAny)
	if err != nil {
		return Binding{}, err
	}
	r := ev.Relay
	return Binding{Statement: r.Statement, Key: r.Key, WalletKey: r.WalletKey, Device: r.Device, From: r.From, Until: r.Until}, nil
}

// foreignBindingOf is a stored binding that names another device than self and
// verifies for that device at its own from; any other binding is an error.
func foreignBindingOf(st, key []byte, self party.Fingerprint) (Binding, error) {
	sm, err := relaybind.ParseStatement(st)
	if err != nil {
		return Binding{}, err
	}
	pb, err := relaybind.ParseBinding(sm.Payload())
	if err != nil {
		return Binding{}, err
	}
	if pb.Device == self {
		return Binding{}, errors.New("the binding names this device and does not verify")
	}
	return bindingOf(st, key, pb.Device)
}

func preparedOf(jp preparedJSON) (relaybinding.Prepared, error) {
	p := relaybinding.Prepared{Kind: relaybinding.PreparedKind(jp.Kind), PreparedAt: jp.PreparedAt, ExpiresAt: jp.ExpiresAt}
	if p.Kind != relaybinding.PreparedBindingKind && p.Kind != relaybinding.PreparedRevokeKind {
		return p, fmt.Errorf("%w: a prepared request of kind %d", ErrCorrupt, jp.Kind)
	}
	if err := errors.Join(fixed(p.WalletKey[:], jp.WalletKey), fixed(p.ID[:], jp.ID)); err != nil {
		return p, fmt.Errorf("%w: the prepared request", ErrCorrupt)
	}
	var err error
	if p.SignFor, err = unhx(jp.SignFor, relaybind.KeyHashSize, relaybind.MaxAddressBytes); err != nil {
		return p, err
	}
	if p.Payload, err = unhx(jp.Payload, 1, relaybind.MaxPayloadBytes); err != nil {
		return p, err
	}
	if p.Kind == relaybinding.PreparedBindingKind {
		p.Binding, err = relaybind.ParseBinding(p.Payload)
	} else {
		p.Revoke, err = relaybind.ParseRevoke(p.Payload)
	}
	if err != nil {
		return p, fmt.Errorf("%w: the prepared payload: %v", ErrCorrupt, err)
	}
	return p, nil
}

func revokeOf(jr revokeJSON, pol relaybind.Policy) (relayport.Revoke, error) {
	r := relayport.Revoke{Until: jr.Until}
	if jr.Until < 0 || jr.Until > relaybind.MaxTime {
		return r, fmt.Errorf("%w: a revoke's until", ErrCorrupt)
	}
	switch jr.Kind {
	case "device":
		if jr.Statement != "" || jr.COSEKey != "" {
			return r, fmt.Errorf("%w: a device revoke with a statement", ErrCorrupt)
		}
		r.Kind, r.NotBefore = relayport.RevokeByDeviceKey, jr.NotBefore
		if err := errors.Join(fixed(r.Keys.Ed25519[:], jr.Ed25519), fixed(r.Keys.X25519[:], jr.X25519), fixed(r.Signature[:], jr.Signature)); err != nil {
			return r, fmt.Errorf("%w: a device revoke", ErrCorrupt)
		}
		if _, err := relaybind.VerifyDeviceRevoke(r.Keys.Ed25519, r.Keys.X25519, r.NotBefore, r.Signature, r.NotBefore, pol); err != nil {
			return r, fmt.Errorf("%w: a device revoke does not verify: %v", ErrCorrupt, err)
		}
	case "wallet":
		if jr.Ed25519 != "" || jr.X25519 != "" || jr.Signature != "" || jr.NotBefore != 0 {
			return r, fmt.Errorf("%w: a wallet revoke with device fields", ErrCorrupt)
		}
		r.Kind = relayport.RevokeByWalletKey
		var err error
		if r.Sign1, err = unhx(jr.Statement, 1, relaybind.MaxSign1Bytes); err != nil {
			return r, err
		}
		if r.Key, err = unhx(jr.COSEKey, 1, relaybind.MaxKeyBytes); err != nil {
			return r, err
		}
		if _, err := verifyWalletRevoke(r.Sign1, r.Key, pol); err != nil {
			return r, fmt.Errorf("%w: a wallet revoke does not verify: %v", ErrCorrupt, err)
		}
	default:
		return r, fmt.Errorf("%w: a revoke of kind %q", ErrCorrupt, jr.Kind)
	}
	return r, nil
}

// verifyWalletRevoke verifies a wallet-signed revoke at its own not-before.
func verifyWalletRevoke(sign1, key []byte, pol relaybind.Policy) (relaybind.VerifiedRevoke, error) {
	st, err := relaybind.ParseStatement(sign1)
	if err != nil {
		return relaybind.VerifiedRevoke{}, err
	}
	vkey, err := relaybind.ParseCOSEKey(key)
	if err != nil {
		return relaybind.VerifiedRevoke{}, err
	}
	rv, err := relaybind.ParseRevoke(st.Payload())
	if err != nil {
		return relaybind.VerifiedRevoke{}, err
	}
	return relaybind.VerifyRevoke(st, vkey, rv.NotBefore, pol)
}

// revokeID names one pending revoke: its signature, or its statement.
func revokeID(r relayport.Revoke) string {
	if r.Kind == relayport.RevokeByDeviceKey {
		return "d" + hx(r.Signature[:])
	}
	return "w" + hx(r.Sign1)
}

// ShortID is the name of a pending revoke the operator types: 16 hex
// characters of the Blake2b-256 of its identity.
func ShortID(r relayport.Revoke) string {
	h := cose.Blake2b256([]byte(revokeID(r)))
	return hx(h[:8])
}

// RevokeView is a pending revoke as the operator sees it.
type RevokeView struct {
	ID        string
	ByDevice  bool              // device-signed (this or an old device's own key) or wallet-signed
	All       bool              // every device of the wallet key
	Device    party.Fingerprint // the device revoked, unless All
	WalletKey party.WalletKey   // the key of a wallet-signed revoke
	NotBefore int64
	Until     int64
	// RecordedAt names the relays that recorded it; OwedTo the listed relays
	// that have not (Status fills both).
	RecordedAt, OwedTo []string
}

// viewOf reads what a pending revoke says. The revokes in a state verified when
// it was decoded or added; one that does not parse again is an error.
func viewOf(r relayport.Revoke) (RevokeView, error) {
	v := RevokeView{ID: ShortID(r), Until: r.Until}
	if r.Kind == relayport.RevokeByDeviceKey {
		v.ByDevice, v.Device, v.NotBefore = true, r.Keys.Fingerprint(), r.NotBefore
		return v, nil
	}
	vr, err := verifyWalletRevoke(r.Sign1, r.Key, relaybind.DefaultPolicy())
	if err != nil {
		return v, err
	}
	rv := vr.Revoke()
	v.All, v.Device, v.NotBefore, v.WalletKey = rv.All, rv.Device, rv.NotBefore, party.WalletKey(vr.Key())
	return v, nil
}

// scopeOf is what a revoke's tombstone covers at the relay: the device alone
// (device-signed), or a wallet key and one device or all of them.
func scopeOf(v RevokeView) string {
	switch {
	case v.ByDevice:
		return "d" + hx(v.Device[:])
	case v.All:
		return "a" + hx(v.WalletKey[:])
	}
	return "k" + hx(v.WalletKey[:]) + hx(v.Device[:])
}
