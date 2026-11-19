package mailbox

import (
	"bytes"
	"math"
	"slices"

	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// v2Message is a message that exists in version 2. The shapes of version 1 that
// changed (Auth, Put, AuthOK) do not implement it, and the shapes that exist
// only in version 2 return an error from fields, so that Encode, which writes
// version 1, refuses them.
type v2Message interface {
	Message
	fieldsV2() ([]any, error)
}

func notV1(m Message) error { return bad(ErrVersion, "%T exists only in version 2", m) }

func (m AuthV2) fields() ([]any, error)         { return nil, notV1(m) }
func (m AuthOKV2) fields() ([]any, error)       { return nil, notV1(m) }
func (m PutV2) fields() ([]any, error)          { return nil, notV1(m) }
func (m RevokeByDevice) fields() ([]any, error) { return nil, notV1(m) }
func (m RevokeByWallet) fields() ([]any, error) { return nil, notV1(m) }
func (m RevokeResult) fields() ([]any, error)   { return nil, notV1(m) }

// The messages that are the same in both versions.
func (m Challenge) fieldsV2() ([]any, error) { return m.fields() }
func (m Fetch) fieldsV2() ([]any, error)     { return m.fields() }
func (m Items) fieldsV2() ([]any, error)     { return m.fields() }
func (m Ack) fieldsV2() ([]any, error)       { return m.fields() }
func (m AckResult) fieldsV2() ([]any, error) { return m.fields() }

// PutResult and Error have the same shape and a wider range in version 2.
func (m PutResult) fieldsV2() ([]any, error) {
	if !m.Status.ValidIn(Version2) {
		return nil, bad(ErrRange, "status %d", m.Status)
	}
	return []any{uint64(m.RequestID), uint64(m.Status)}, nil
}

func (m Error) fieldsV2() ([]any, error) {
	if !m.Code.ValidIn(Version2) {
		return nil, bad(ErrRange, "error code %d", m.Code)
	}
	return []any{uint64(m.Code)}, nil
}

// checkBlob requires 1 to max bytes (a statement is never empty).
func checkBlob(b []byte, max int, what string) error {
	if len(b) < 1 || len(b) > max {
		return bad(ErrRange, "%s is %d bytes; it must be 1 to %d", what, len(b), max)
	}
	return nil
}

// checkSenders requires at most MaxSenders keys in strictly ascending order:
// sorted, and so without a repeat.
func checkSenders(senders []WalletKey) error {
	if len(senders) > MaxSenders {
		return bad(ErrRange, "%d senders; at most %d", len(senders), MaxSenders)
	}
	for i := 1; i < len(senders); i++ {
		if bytes.Compare(senders[i-1][:], senders[i][:]) >= 0 {
			return bad(ErrRange, "the senders are not strictly ascending at %d", i)
		}
	}
	return nil
}

func (m AuthV2) fieldsV2() ([]any, error) {
	if err := checkBlob(m.Sign1, MaxSign1Bytes, "sign1"); err != nil {
		return nil, err
	}
	if err := checkBlob(m.Key, MaxCOSEKeyBytes, "cose key"); err != nil {
		return nil, err
	}
	if err := checkSenders(m.Senders); err != nil {
		return nil, err
	}
	senders := make([]any, 0, len(m.Senders))
	for _, k := range m.Senders {
		senders = append(senders, k[:])
	}
	return []any{
		uint64(Version2), m.Fingerprint[:], m.Signature[:],
		[]any{m.Keys.Ed25519[:], m.Keys.X25519[:], m.Sign1, m.Key},
		senders,
	}, nil
}

// checkUntil requires the `until` of a recorded binding to be a time, 1 to
// MaxTime: a binding that is valid until 0 never was.
func checkUntil(until int64) error {
	if until < 1 || until > MaxTime {
		return bad(ErrRange, "until %d is not 1 to %d", until, int64(MaxTime))
	}
	return nil
}

func (m AuthOKV2) fieldsV2() ([]any, error) {
	if err := checkAuthOKLimits(m.MaxEnvelope, m.MaxEntries, m.MaxBytes, m.RetentionSeconds); err != nil {
		return nil, err
	}
	if err := checkUntil(m.Until); err != nil {
		return nil, err
	}
	return []any{uint64(Version2), m.MaxEnvelope, m.MaxEntries, m.MaxBytes, m.RetentionSeconds, uint64(m.Until)}, nil
}

func (m PutV2) fieldsV2() ([]any, error) {
	if err := checkSize(uint64(m.Size)); err != nil {
		return nil, err
	}
	return []any{uint64(m.RequestID), m.WalletKey[:], m.To[:], m.Mid[:], uint64(m.Size)}, nil
}

// Kinds of Revoke, the third element of the frame.
const (
	revokeKindDevice = 0
	revokeKindWallet = 1
)

func (m RevokeByDevice) fieldsV2() ([]any, error) {
	if m.NotBefore < 0 || m.NotBefore > MaxTime {
		return nil, bad(ErrRange, "not-before %d is not 0 to %d", m.NotBefore, int64(MaxTime))
	}
	return []any{uint64(m.RequestID), uint64(revokeKindDevice), m.Keys.Ed25519[:], m.Keys.X25519[:], uint64(m.NotBefore), m.Signature[:]}, nil
}

func (m RevokeByWallet) fieldsV2() ([]any, error) {
	if err := checkBlob(m.Sign1, MaxSign1Bytes, "sign1"); err != nil {
		return nil, err
	}
	if err := checkBlob(m.Key, MaxCOSEKeyBytes, "cose key"); err != nil {
		return nil, err
	}
	return []any{uint64(m.RequestID), uint64(revokeKindWallet), m.Sign1, m.Key}, nil
}

func (m RevokeResult) fieldsV2() ([]any, error) {
	if !m.Status.Valid() {
		return nil, bad(ErrRange, "revoke status %d", m.Status)
	}
	return []any{uint64(m.RequestID), uint64(m.Status)}, nil
}

// NewPutV2 builds a PutV2 for an envelope whose hash and size the caller
// already has. It refuses a size outside 1 to MaxEnvelopeBytes. It cannot check
// that mid is the hash of the envelope that will follow the header; NewPutV2Of
// makes it by construction.
func NewPutV2(requestID uint32, key WalletKey, to party.Fingerprint, mid Hash, size uint32) (PutV2, error) {
	if err := checkSize(uint64(size)); err != nil {
		return PutV2{}, err
	}
	return PutV2{RequestID: requestID, WalletKey: key, To: to, Mid: mid, Size: size}, nil
}

// NewPutV2Of builds the PutV2 of an envelope: Mid and Size are computed from
// the bytes, so the header cannot disagree with them.
func NewPutV2Of(requestID uint32, key WalletKey, to party.Fingerprint, envelope []byte) (PutV2, error) {
	if len(envelope) == 0 || len(envelope) > MaxEnvelopeBytes {
		return PutV2{}, bad(ErrRange, "envelope size %d is not 1 to %d", len(envelope), MaxEnvelopeBytes)
	}
	return PutV2{RequestID: requestID, WalletKey: key, To: to, Mid: HashOf(envelope), Size: uint32(len(envelope))}, nil
}

// senderOf says who sends type t at the stage, and whether the type exists
// there. Types 10 and 11 exist in every stage but StageV1, where they never
// did.
func senderOf(stage Stage, t uint64) (client, known bool) {
	if stage != StageV1 {
		switch MsgType(t) {
		case MsgRevoke:
			return true, true
		case MsgRevokeResult:
			return false, true
		}
	}
	return fromClient(t)
}

// stageAllows is the table of the spec (OUT-051): which type each side may send
// at each stage. StageV1 is version 1's own rule (every type of the sender).
func stageAllows(stage Stage, client bool, t MsgType) bool {
	switch stage {
	case StageV1:
		return true
	case StageUnversioned:
		if client {
			return t == MsgAuth || t == MsgRevoke
		}
		return t == MsgChallenge || t == MsgError
	case StageV2PreAuth:
		if client {
			return t == MsgAuth || t == MsgRevoke
		}
		return t == MsgAuthOK || t == MsgError || t == MsgRevokeResult
	case StageV2Authed:
		if client {
			return t == MsgPut || t == MsgFetch || t == MsgAck
		}
		return t == MsgPutResult || t == MsgItems || t == MsgAckResult || t == MsgError
	}
	return false
}

// DecodeFromClientIn parses a header frame body that arrived from a client
// (the relay's side), at the given stage of the connection. At StageV1 it is
// DecodeFromClient. Before a version is chosen the relay reads an Auth of
// either version, told apart by the version number it carries, or a Revoke;
// after it has chosen version 2 only the frames of that version's stage.
// Whatever the stage does not allow is refused by its type alone, as ErrStage,
// before any field is read.
func DecodeFromClientIn(stage Stage, frame []byte) (Message, error) {
	return decodeIn(stage, frame, true)
}

// DecodeFromRelayIn parses a header frame body that arrived from the relay (the
// client's side), at the given stage of the connection. At StageV1 it is
// DecodeFromRelay.
func DecodeFromRelayIn(stage Stage, frame []byte) (Message, error) {
	return decodeIn(stage, frame, false)
}

// decodeAuthIn reads the version of an Auth and decodes it in that version's
// shape. Before a version is chosen both are possible; once version 2 is chosen
// an Auth of another version is ErrVersion.
func decodeAuthIn(stage Stage, a []any, arity func(int) error) (Message, error) {
	if len(a) < 2 {
		return nil, bad(ErrMalformed, "an Auth carries its version")
	}
	v, ok := a[1].(uint64)
	if !ok {
		return nil, bad(ErrMalformed, "version is not a non-negative integer")
	}
	switch {
	case stage == StageUnversioned && v == Version1:
		return decodeAuth(a, arity)
	case v == Version2:
		return decodeAuthV2(a, arity)
	}
	return nil, bad(ErrVersion, "an Auth of version %d at the stage %v", v, stage)
}

// asBlob reads a byte string of 1 to max bytes and returns a copy.
func asBlob(v any, max int, what string) ([]byte, error) {
	b, ok := v.([]byte)
	if !ok {
		return nil, bad(ErrMalformed, "%s is not a byte string", what)
	}
	if err := checkBlob(b, max, what); err != nil {
		return nil, err
	}
	return bytes.Clone(b), nil
}

func decodeAuthV2(a []any, arity func(int) error) (Message, error) {
	if err := arity(5); err != nil {
		return nil, err
	}
	f, err := asFixed(a[2], len(party.Fingerprint{}), "fingerprint")
	if err != nil {
		return nil, err
	}
	s, err := asFixed(a[3], SignatureSize, "signature")
	if err != nil {
		return nil, err
	}
	b, err := asArray(a[4], "the binding")
	if err != nil {
		return nil, err
	}
	if len(b) != 4 {
		return nil, bad(ErrMalformed, "a binding is [ed25519, x25519, sign1, cose key], not %d items", len(b))
	}
	ed, err := asFixed(b[0], len(party.Ed25519Public{}), "ed25519 key")
	if err != nil {
		return nil, err
	}
	x, err := asFixed(b[1], len(party.X25519Public{}), "x25519 key")
	if err != nil {
		return nil, err
	}
	sign1, err := asBlob(b[2], MaxSign1Bytes, "sign1")
	if err != nil {
		return nil, err
	}
	key, err := asBlob(b[3], MaxCOSEKeyBytes, "cose key")
	if err != nil {
		return nil, err
	}
	list, err := asArray(a[5], "the senders")
	if err != nil {
		return nil, err
	}
	if len(list) > MaxSenders {
		return nil, bad(ErrRange, "%d senders; at most %d", len(list), MaxSenders)
	}
	m := AuthV2{Sign1: sign1, Key: key}
	copy(m.Fingerprint[:], f)
	copy(m.Signature[:], s)
	copy(m.Keys.Ed25519[:], ed)
	copy(m.Keys.X25519[:], x)
	for _, e := range list {
		k, err := asFixed(e, WalletKeySize, "sender")
		if err != nil {
			return nil, err
		}
		var w WalletKey
		copy(w[:], k)
		m.Senders = append(m.Senders, w)
	}
	if err := checkSenders(m.Senders); err != nil {
		return nil, err
	}
	return m, nil
}

func decodeAuthOKV2(a []any, arity func(int) error) (Message, error) {
	if err := arity(6); err != nil {
		return nil, err
	}
	v, err := asUint(a[1], MaxVersion, "version")
	if err != nil {
		return nil, err
	}
	if v != Version2 {
		return nil, bad(ErrVersion, "an AuthOK of version %d in version 2", v)
	}
	var m AuthOKV2
	if m.MaxEnvelope, err = asRange(a[2], 1, MaxEnvelopeBytes, "max envelope"); err != nil {
		return nil, err
	}
	if m.MaxEntries, err = asRange(a[3], 1, MaxMailboxEntries, "max entries"); err != nil {
		return nil, err
	}
	if m.MaxBytes, err = asRange(a[4], 1, MaxMailboxBytes, "max bytes"); err != nil {
		return nil, err
	}
	if m.RetentionSeconds, err = asRange(a[5], 1, MaxRetentionSeconds, "retention seconds"); err != nil {
		return nil, err
	}
	until, err := asUint(a[6], MaxTime, "until")
	if err != nil {
		return nil, err
	}
	if err := checkUntil(int64(until)); err != nil {
		return nil, err
	}
	m.Until = int64(until)
	return m, nil
}

func decodePutV2(a []any, arity func(int) error) (Message, error) {
	if err := arity(5); err != nil {
		return nil, err
	}
	id, err := asUint(a[1], math.MaxUint32, "request id")
	if err != nil {
		return nil, err
	}
	key, err := asFixed(a[2], WalletKeySize, "wallet key")
	if err != nil {
		return nil, err
	}
	to, err := asFixed(a[3], len(party.Fingerprint{}), "to")
	if err != nil {
		return nil, err
	}
	mid, err := asFixed(a[4], HashSize, "mid")
	if err != nil {
		return nil, err
	}
	size, err := asRange(a[5], 1, MaxEnvelopeBytes, "size")
	if err != nil {
		return nil, err
	}
	m := PutV2{RequestID: uint32(id), Size: uint32(size)}
	copy(m.WalletKey[:], key)
	copy(m.To[:], to)
	copy(m.Mid[:], mid)
	return m, nil
}

// decodeRevoke reads the two shapes of a Revoke, told apart by the kind after
// the request id: 0, signed by the device, [id, 0, ed25519, x25519, not-before,
// signature]; 1, signed by the wallet key, [id, 1, sign1, cose key].
func decodeRevoke(a []any, arity func(int) error) (Message, error) {
	if len(a) < 3 {
		return nil, bad(ErrMalformed, "a Revoke carries a request id and a kind")
	}
	id, err := asUint(a[1], math.MaxUint32, "request id")
	if err != nil {
		return nil, err
	}
	kind, err := asUint(a[2], revokeKindWallet, "revoke kind")
	if err != nil {
		return nil, err
	}
	switch kind {
	case revokeKindDevice:
		if err := arity(6); err != nil {
			return nil, err
		}
		ed, err := asFixed(a[3], len(party.Ed25519Public{}), "ed25519 key")
		if err != nil {
			return nil, err
		}
		x, err := asFixed(a[4], len(party.X25519Public{}), "x25519 key")
		if err != nil {
			return nil, err
		}
		nb, err := asUint(a[5], MaxTime, "not-before")
		if err != nil {
			return nil, err
		}
		s, err := asFixed(a[6], SignatureSize, "signature")
		if err != nil {
			return nil, err
		}
		m := RevokeByDevice{RequestID: uint32(id), NotBefore: int64(nb)}
		copy(m.Keys.Ed25519[:], ed)
		copy(m.Keys.X25519[:], x)
		copy(m.Signature[:], s)
		return m, nil
	default: // revokeKindWallet: asUint refused every other
		if err := arity(4); err != nil {
			return nil, err
		}
		sign1, err := asBlob(a[3], MaxSign1Bytes, "sign1")
		if err != nil {
			return nil, err
		}
		key, err := asBlob(a[4], MaxCOSEKeyBytes, "cose key")
		if err != nil {
			return nil, err
		}
		return RevokeByWallet{RequestID: uint32(id), Sign1: sign1, Key: key}, nil
	}
}

func decodeRevokeResult(a []any, arity func(int) error) (Message, error) {
	if err := arity(2); err != nil {
		return nil, err
	}
	id, err := asUint(a[1], math.MaxUint32, "request id")
	if err != nil {
		return nil, err
	}
	st, err := asUint(a[2], uint64(RevokeRefused), "revoke status")
	if err != nil {
		return nil, err
	}
	if !RevokeStatus(st).Valid() {
		return nil, bad(ErrRange, "revoke status %d", st)
	}
	return RevokeResult{RequestID: uint32(id), Status: RevokeStatus(st)}, nil
}

// CanonicalSenders returns the expected-sender list in its one canonical form:
// strictly ascending by bytes, no repeats, at most MaxSenders. The ADR names no
// order; ascending is the choice, so that one set of keys has one encoding and
// one hash. It sorts a copy and drops repeats; a list that is longer than
// MaxSenders once repeats are dropped is ErrRange.
func CanonicalSenders(keys []WalletKey) ([]WalletKey, error) {
	c := slices.Clone(keys)
	slices.SortFunc(c, func(a, b WalletKey) int { return bytes.Compare(a[:], b[:]) })
	c = slices.Compact(c)
	if len(c) > MaxSenders {
		return nil, bad(ErrRange, "%d senders; at most %d", len(c), MaxSenders)
	}
	if c == nil {
		c = []WalletKey{}
	}
	return c, nil
}

// SendersHash is Blake2b-256 of the canonical CBOR array of the list's byte
// strings (each 28 bytes), in the list's order. The list must already be
// canonical (strictly ascending, at most MaxSenders), or the hash is refused
// with ErrRange: two different encodings of one set must not both have a hash.
func SendersHash(senders []WalletKey) ([HashSize]byte, error) {
	if err := checkSenders(senders); err != nil {
		return [HashSize]byte{}, err
	}
	items := make([]any, 0, len(senders))
	for _, k := range senders {
		items = append(items, k[:])
	}
	b, err := identity.EncodeCanonical(items)
	if err != nil {
		return [HashSize]byte{}, bad(ErrMalformed, "%v", err)
	}
	return blake2b.Sum256(b), nil
}
