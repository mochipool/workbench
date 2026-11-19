package mailbox

import (
	"errors"
	"math"

	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/party"
)

func checkVersion(v uint) error {
	if v < 1 || v > MaxVersion {
		return bad(ErrRange, "version %d", v)
	}
	return nil
}

func checkSize(size uint64) error {
	if size == 0 || size > MaxEnvelopeBytes {
		return bad(ErrRange, "envelope size %d is not 1 to %d", size, MaxEnvelopeBytes)
	}
	return nil
}

func (m Challenge) fields() ([]any, error) {
	if err := checkVersion(m.Min); err != nil {
		return nil, err
	}
	if err := checkVersion(m.Max); err != nil {
		return nil, err
	}
	if m.Min > m.Max {
		return nil, bad(ErrRange, "min %d is above max %d", m.Min, m.Max)
	}
	if m.RelayTime < 0 || m.RelayTime > MaxTime {
		return nil, bad(ErrRange, "relay time %d is not 0 to %d", m.RelayTime, int64(MaxTime))
	}
	return []any{uint64(m.Min), uint64(m.Max), m.Nonce[:], m.RelayKey[:], uint64(m.RelayTime)}, nil
}

// checkAuthOKLimits is the range check of the four limits an AuthOK announces.
func checkAuthOKLimits(maxEnvelope, maxEntries, maxBytes, retention uint64) error {
	if err := checkSize(maxEnvelope); err != nil {
		return err
	}
	if maxEntries < 1 || maxEntries > MaxMailboxEntries {
		return bad(ErrRange, "max entries %d is not 1 to %d", maxEntries, MaxMailboxEntries)
	}
	if maxBytes < 1 || maxBytes > MaxMailboxBytes {
		return bad(ErrRange, "max bytes %d is not 1 to %d", maxBytes, MaxMailboxBytes)
	}
	if retention < 1 || retention > MaxRetentionSeconds {
		return bad(ErrRange, "retention %d is not 1 to %d seconds", retention, MaxRetentionSeconds)
	}
	return nil
}

func (m PutResult) fields() ([]any, error) {
	if !m.Status.Valid() {
		return nil, bad(ErrRange, "status %d", m.Status)
	}
	return []any{uint64(m.RequestID), uint64(m.Status)}, nil
}

func (m Fetch) fields() ([]any, error) {
	if m.MaxItems < 1 || m.MaxItems > MaxItemsPerFetch {
		return nil, bad(ErrRange, "max items %d is not 1 to %d", m.MaxItems, MaxItemsPerFetch)
	}
	if m.WaitSeconds > MaxFetchWaitSeconds {
		return nil, bad(ErrRange, "wait %d is above %d seconds", m.WaitSeconds, MaxFetchWaitSeconds)
	}
	after := []byte{}
	if m.After != nil {
		after = m.After[:]
	}
	return []any{uint64(m.RequestID), after, uint64(m.MaxItems), uint64(m.WaitSeconds)}, nil
}

func (m Items) fields() ([]any, error) {
	if len(m.Entries) > MaxItemsPerFetch {
		return nil, bad(ErrRange, "%d items; at most %d", len(m.Entries), MaxItemsPerFetch)
	}
	if m.More && len(m.Entries) == 0 {
		return nil, bad(ErrRange, "more is set but no item follows")
	}
	entries := make([]any, 0, len(m.Entries))
	seen := make(map[Hash]struct{}, len(m.Entries))
	for _, e := range m.Entries {
		if err := checkSize(uint64(e.Size)); err != nil {
			return nil, err
		}
		if _, dup := seen[e.Mid]; dup {
			return nil, bad(ErrRange, "item %s is repeated", e.Mid)
		}
		seen[e.Mid] = struct{}{}
		entries = append(entries, []any{e.Mid[:], uint64(e.Size)})
	}
	return []any{uint64(m.RequestID), entries, m.More}, nil
}

func (m Ack) fields() ([]any, error) {
	if len(m.Mids) < 1 || len(m.Mids) > MaxAckHashes {
		return nil, bad(ErrRange, "%d hashes; 1 to %d", len(m.Mids), MaxAckHashes)
	}
	seen := make(map[Hash]struct{}, len(m.Mids))
	mids := make([]any, 0, len(m.Mids))
	for _, h := range m.Mids {
		if _, dup := seen[h]; dup {
			return nil, bad(ErrRange, "hash %s is repeated", h)
		}
		seen[h] = struct{}{}
		mids = append(mids, h[:])
	}
	return []any{uint64(m.RequestID), mids}, nil
}

func (m AckResult) fields() ([]any, error) {
	if m.Deleted > MaxAckHashes {
		return nil, bad(ErrRange, "deleted count %d is above %d", m.Deleted, MaxAckHashes)
	}
	return []any{uint64(m.RequestID), uint64(m.Deleted)}, nil
}

func (m Error) fields() ([]any, error) {
	if !m.Code.Valid() {
		return nil, bad(ErrRange, "error code %d", m.Code)
	}
	return []any{uint64(m.Code)}, nil
}

// Encode returns the canonical CBOR of a header frame body: an array whose first
// element is the message type. There is one protocol version, 2; Encode is
// EncodeV(Version2, m).
func Encode(m Message) ([]byte, error) { return EncodeV(Version2, m) }

// EncodeV returns the canonical CBOR of a header frame body for the version,
// which can only be Version2: every other number is ErrVersion. The status and
// code ranges are those of version 2.
func EncodeV(version uint, m Message) ([]byte, error) {
	if m == nil {
		return nil, bad(ErrMalformed, "no message")
	}
	if version != Version2 {
		return nil, bad(ErrVersion, "version %d", version)
	}
	f, err := m.fields()
	if err != nil {
		return nil, err
	}
	b, err := identity.EncodeCanonical(append([]any{uint64(m.Type())}, f...))
	if err != nil {
		return nil, bad(ErrMalformed, "%v", err)
	}
	if len(b) > MaxHeaderFrame {
		return nil, bad(ErrFrameSize, "the encoding is %d bytes", len(b))
	}
	return b, nil
}

// scanShape walks the structure of b before any value is built, refusing what
// the protocol never uses (tags, indefinite lengths, floats and simple values
// other than null and booleans) and what passes a structural bound (nesting,
// array length, map pairs). Every length is compared with what is left of the
// input before it is trusted, so nothing is allocated here and the work is
// bounded by len(b).
func scanShape(b []byte) error {
	end, err := scanItem(b, 0, 0)
	if err != nil {
		return err
	}
	if end != len(b) {
		return bad(ErrNotCanonical, "%d trailing bytes", len(b)-end)
	}
	return nil
}

func scanItem(b []byte, pos, depth int) (int, error) {
	if pos >= len(b) {
		return 0, bad(ErrNotCanonical, "truncated")
	}
	major, info := b[pos]>>5, b[pos]&0x1f
	switch {
	case major == 6:
		return 0, bad(ErrNotCanonical, "a tagged item")
	case major == 7:
		if info != 20 && info != 21 && info != 22 {
			return 0, bad(ErrNotCanonical, "a float or simple item 0x%02x", b[pos])
		}
		return pos + 1, nil
	case info == 31:
		return 0, bad(ErrNotCanonical, "an indefinite length")
	case info > 27:
		return 0, bad(ErrNotCanonical, "reserved additional information")
	}
	head, n := 1, uint64(info)
	if info >= 24 {
		w := 1 << (info - 24)
		if len(b)-pos-1 < w {
			return 0, bad(ErrNotCanonical, "truncated")
		}
		n = 0
		for _, c := range b[pos+1 : pos+1+w] {
			n = n<<8 | uint64(c)
		}
		head += w
	}
	pos += head
	switch major {
	case 0, 1:
		return pos, nil
	case 2, 3:
		if n > uint64(len(b)-pos) {
			return 0, bad(ErrNotCanonical, "a string of %d bytes in %d", n, len(b)-pos)
		}
		return pos + int(n), nil
	case 4:
		if depth+1 > MaxCBORDepth {
			return 0, bad(ErrShape, "nesting above %d", MaxCBORDepth)
		}
		if n > MaxCBORArray {
			return 0, bad(ErrShape, "an array of %d items; at most %d", n, MaxCBORArray)
		}
		var err error
		for i := uint64(0); i < n; i++ {
			if pos, err = scanItem(b, pos, depth+1); err != nil {
				return 0, err
			}
		}
		return pos, nil
	default: // 5
		if depth+1 > MaxCBORDepth {
			return 0, bad(ErrShape, "nesting above %d", MaxCBORDepth)
		}
		if n > MaxCBORMapPairs {
			return 0, bad(ErrShape, "a map of %d pairs; at most %d", n, MaxCBORMapPairs)
		}
		var err error
		for i := uint64(0); i < 2*n; i++ {
			if pos, err = scanItem(b, pos, depth+1); err != nil {
				return 0, err
			}
		}
		return pos, nil
	}
}

func asUint(v any, max uint64, what string) (uint64, error) {
	u, ok := v.(uint64)
	if !ok {
		return 0, bad(ErrMalformed, "%s is not a non-negative integer", what)
	}
	if u > max {
		return 0, bad(ErrRange, "%s is %d; at most %d", what, u, max)
	}
	return u, nil
}

func asRange(v any, min, max uint64, what string) (uint64, error) {
	u, err := asUint(v, max, what)
	if err != nil {
		return 0, err
	}
	if u < min {
		return 0, bad(ErrRange, "%s is %d; at least %d", what, u, min)
	}
	return u, nil
}

func asFixed(v any, n int, what string) ([]byte, error) {
	b, ok := v.([]byte)
	if !ok {
		return nil, bad(ErrMalformed, "%s is not a byte string", what)
	}
	if len(b) != n {
		return nil, bad(ErrMalformed, "%s is %d bytes, not %d", what, len(b), n)
	}
	return b, nil
}

func asArray(v any, what string) ([]any, error) {
	a, ok := v.([]any)
	if !ok {
		return nil, bad(ErrMalformed, "%s is not an array", what)
	}
	return a, nil
}

// Who may send which message type. A session decodes with the function for the
// direction it reads, so a frame the peer may not send is refused by type
// alone, before its fields are looked at.
//
//	client to relay: Auth (1), Put (3), Fetch (5), Ack (7), Revoke (10)
//	relay to client: Challenge (0), AuthOK (2), PutResult (4), Items (6),
//	                 AckResult (8), Error (9), RevokeResult (11)

// senderOf says who sends type t, and whether the type exists. Types 12 and up
// never do.
func senderOf(t uint64) (client, known bool) {
	switch MsgType(t) {
	case MsgAuth, MsgPut, MsgFetch, MsgAck, MsgRevoke:
		return true, true
	case MsgChallenge, MsgAuthOK, MsgPutResult, MsgItems, MsgAckResult, MsgError, MsgRevokeResult:
		return false, true
	}
	return false, false
}

// decodeIn parses one header frame body at a stage of the connection. It refuses
// a body over MaxHeaderFrame by its length, then structure over the bounds, then
// anything that is not canonical CBOR (the decoded value must re-encode to the
// input), then a type that does not exist (ErrUnknownType), a type the sender may
// not send (ErrDirection) and a type the stage does not allow (ErrStage), all by
// the type alone, then any array of the wrong arity, any field of the wrong kind
// or length and any value out of range.
func decodeIn(stage Stage, frame []byte, wantClient bool) (Message, error) {
	if !stage.Valid() {
		return nil, bad(ErrStage, "%v", stage)
	}
	if len(frame) == 0 || len(frame) > MaxHeaderFrame {
		return nil, bad(ErrFrameSize, "a header frame is 1 to %d bytes, not %d", MaxHeaderFrame, len(frame))
	}
	if err := scanShape(frame); err != nil {
		return nil, err
	}
	v, err := identity.DecodeCanonical(frame)
	if err != nil {
		if errors.Is(err, identity.ErrNotCanonical) || errors.Is(err, identity.ErrUnsupported) {
			return nil, bad(ErrNotCanonical, "%v", err)
		}
		return nil, bad(ErrMalformed, "%v", err)
	}
	a, ok := v.([]any)
	if !ok || len(a) == 0 {
		return nil, bad(ErrMalformed, "a header is a non-empty array")
	}
	t, ok := a[0].(uint64)
	if !ok {
		return nil, bad(ErrMalformed, "the message type is not an unsigned integer")
	}
	if client, known := senderOf(t); !known {
		return nil, bad(ErrUnknownType, "type %d", t)
	} else if client != wantClient {
		who := "relay"
		if wantClient {
			who = "client"
		}
		return nil, bad(ErrDirection, "type %d is not sent by the %s", t, who)
	}
	if !stageAllows(stage, wantClient, MsgType(t)) {
		return nil, bad(ErrStage, "type %d at the stage %v", t, stage)
	}
	arity := func(n int) error {
		if len(a) != 1+n {
			return bad(ErrMalformed, "message type %d has %d fields, not %d", t, len(a)-1, n)
		}
		return nil
	}
	switch MsgType(t) { // MsgType is a uint64: nothing is truncated
	case MsgChallenge:
		return decodeChallenge(a, arity)
	case MsgAuth:
		return decodeAuthV2(a, arity)
	case MsgAuthOK:
		return decodeAuthOKV2(a, arity)
	case MsgPut:
		return decodePutV2(a, arity)
	case MsgRevoke:
		return decodeRevoke(a, arity)
	case MsgRevokeResult:
		return decodeRevokeResult(a, arity)
	case MsgPutResult:
		if err := arity(2); err != nil {
			return nil, err
		}
		id, err := asUint(a[1], math.MaxUint32, "request id")
		if err != nil {
			return nil, err
		}
		st, err := asUint(a[2], uint64(StatusUnbound), "status")
		if err != nil {
			return nil, err
		}
		return PutResult{RequestID: uint32(id), Status: Status(st)}, nil
	case MsgFetch:
		return decodeFetch(a, arity)
	case MsgItems:
		return decodeItems(a, arity)
	case MsgAck:
		return decodeAck(a, arity)
	case MsgAckResult:
		if err := arity(2); err != nil {
			return nil, err
		}
		id, err := asUint(a[1], math.MaxUint32, "request id")
		if err != nil {
			return nil, err
		}
		n, err := asUint(a[2], MaxAckHashes, "deleted count")
		if err != nil {
			return nil, err
		}
		return AckResult{RequestID: uint32(id), Deleted: uint(n)}, nil
	case MsgError:
		if err := arity(1); err != nil {
			return nil, err
		}
		c, err := asUint(a[1], uint64(CodeBinding), "error code")
		if err != nil {
			return nil, err
		}
		return Error{Code: Code(c)}, nil
	}
	return nil, bad(ErrUnknownType, "type %d", t) // unreachable: fromClient knows every type
}

func decodeChallenge(a []any, arity func(int) error) (Message, error) {
	if err := arity(5); err != nil {
		return nil, err
	}
	lo, err := asRange(a[1], 1, MaxVersion, "min version")
	if err != nil {
		return nil, err
	}
	hi, err := asRange(a[2], 1, MaxVersion, "max version")
	if err != nil {
		return nil, err
	}
	if lo > hi {
		return nil, bad(ErrRange, "min version %d is above max %d", lo, hi)
	}
	nonce, err := asFixed(a[3], NonceSize, "nonce")
	if err != nil {
		return nil, err
	}
	key, err := asFixed(a[4], len(party.NodeKey{}), "relay node key")
	if err != nil {
		return nil, err
	}
	rt, err := asUint(a[5], MaxTime, "relay time")
	if err != nil {
		return nil, err
	}
	c := Challenge{Min: uint(lo), Max: uint(hi), RelayTime: int64(rt)}
	copy(c.Nonce[:], nonce)
	copy(c.RelayKey[:], key)
	return c, nil
}

func decodeFetch(a []any, arity func(int) error) (Message, error) {
	if err := arity(4); err != nil {
		return nil, err
	}
	id, err := asUint(a[1], math.MaxUint32, "request id")
	if err != nil {
		return nil, err
	}
	raw, ok := a[2].([]byte)
	if !ok || (len(raw) != 0 && len(raw) != HashSize) {
		return nil, bad(ErrMalformed, "after is not empty and not a %d byte hash", HashSize)
	}
	items, err := asRange(a[3], 1, MaxItemsPerFetch, "max items")
	if err != nil {
		return nil, err
	}
	wait, err := asUint(a[4], MaxFetchWaitSeconds, "wait seconds")
	if err != nil {
		return nil, err
	}
	m := Fetch{RequestID: uint32(id), MaxItems: uint(items), WaitSeconds: uint(wait)}
	if len(raw) == HashSize {
		var h Hash
		copy(h[:], raw)
		m.After = &h
	}
	return m, nil
}

func decodeItems(a []any, arity func(int) error) (Message, error) {
	if err := arity(3); err != nil {
		return nil, err
	}
	id, err := asUint(a[1], math.MaxUint32, "request id")
	if err != nil {
		return nil, err
	}
	list, err := asArray(a[2], "the item list")
	if err != nil {
		return nil, err
	}
	if len(list) > MaxItemsPerFetch {
		return nil, bad(ErrRange, "%d items; at most %d", len(list), MaxItemsPerFetch)
	}
	more, ok := a[3].(bool)
	if !ok {
		return nil, bad(ErrMalformed, "more is not a boolean")
	}
	if more && len(list) == 0 {
		return nil, bad(ErrRange, "more is set but no item is listed")
	}
	m := Items{RequestID: uint32(id), More: more}
	seen := make(map[Hash]struct{}, len(list))
	for _, e := range list {
		pair, err := asArray(e, "an item")
		if err != nil || len(pair) != 2 {
			return nil, bad(ErrMalformed, "an item is [mid, size]")
		}
		mid, err := asFixed(pair[0], HashSize, "item mid")
		if err != nil {
			return nil, err
		}
		size, err := asRange(pair[1], 1, MaxEnvelopeBytes, "item size")
		if err != nil {
			return nil, err
		}
		it := Item{Size: uint32(size)}
		copy(it.Mid[:], mid)
		if _, dup := seen[it.Mid]; dup {
			return nil, bad(ErrRange, "item %s is repeated", it.Mid)
		}
		seen[it.Mid] = struct{}{}
		m.Entries = append(m.Entries, it)
	}
	return m, nil
}

func decodeAck(a []any, arity func(int) error) (Message, error) {
	if err := arity(2); err != nil {
		return nil, err
	}
	id, err := asUint(a[1], math.MaxUint32, "request id")
	if err != nil {
		return nil, err
	}
	list, err := asArray(a[2], "the hash list")
	if err != nil {
		return nil, err
	}
	if len(list) < 1 || len(list) > MaxAckHashes {
		return nil, bad(ErrRange, "%d hashes; 1 to %d", len(list), MaxAckHashes)
	}
	m := Ack{RequestID: uint32(id)}
	seen := make(map[Hash]struct{}, len(list))
	for _, e := range list {
		b, err := asFixed(e, HashSize, "ack hash")
		if err != nil {
			return nil, err
		}
		var h Hash
		copy(h[:], b)
		if _, dup := seen[h]; dup {
			return nil, bad(ErrRange, "hash %s is repeated", h)
		}
		seen[h] = struct{}{}
		m.Mids = append(m.Mids, h)
	}
	return m, nil
}
