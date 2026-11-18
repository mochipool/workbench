package layout

import (
	"bytes"
)

// OBJECT KINDS. The first element of every body's CBOR is the object kind,
// inside the seal. A record's kind is the store's kind (a ports.Kind such as
// "kes.skey"); the layout reserves three more.
const (
	KindAudit        = "audit"
	KindManifestRoot = "manifest-root"
	KindManifestPage = "manifest-page"
)

// Page kinds (the second element of a manifest page).
const (
	pageRecords = "records"
	pageAudit   = "audit"
)

// Record classes as the store's kind-to-class rule gives them. The cold-role
// class of the associated data ("secret-cold") is not a class here: whether a
// record is in the cold form is a property of its wrapped key, which the codec
// does not parse.
const (
	ClassSecret    = "secret"
	ClassSensitive = "sensitive"
)

// ClassRule is the store's kind-to-class rule, passed in so that this package
// stays pure: it returns the class of a record kind and false for a kind the
// store does not know. (sqlitestore's classOf over the ports catalogue.)
type ClassRule func(kind string) (class string, known bool)

// Limits of the record fields. They mirror the sealed record format of
// platform/seal and are checked so that a body that decodes holds plausible
// fields; the codec does not parse them further.
const (
	// WrappedKeyMax is W: the width of the wrapped-key field of a record body.
	// A hot record's wrapped key is 72 bytes; a cold-role record's is the
	// canonical CBOR ["spo/cold-record/1", header, outer, recovery wrap] and is
	// at most 1431 bytes (measured in TestWrappedKeyWidthCoversTheWorstColdBlob
	// from a FIDO2 header with a 1024-byte credential id, a previous wrap, the
	// left mark, the outer wrap, the HPKE recovery wrap and the largest
	// fallback counter), rounded up to a multiple of 256. A blob longer than W
	// is refused: it is never moved to a larger bucket.
	WrappedKeyMax = 1536

	wrappedKeyField = 2 + WrappedKeyMax // u16 length || key || zeros

	minOwner = NonceSize + TagSize
)

// RecordFormat is the record encoding of the identity-keyed store (seal.RecordFormat);
// the layout stays pure and a test in archtest compares the two.
const RecordFormat = 2

// Object is what a body holds: a Record, an Audit row, a RecordPage, an
// AuditPage or a Root.
type Object interface{ isObject() }

// Inner is the sealed part of a record, byte for byte as the store holds it:
// the four fields of seal.SealedRecord. The codec never parses, rebuilds or
// re-seals them (a cold-role record's WrappedKey is the cold form and stays
// opaque).
type Inner struct {
	Nonce      []byte
	WrappedKey []byte
	Owner      []byte
	Ciphertext []byte
}

// Record is the body of a record object: the identifying columns of the
// SQLite records row, and the sealed fields.
//
// Columns of the row that the body holds: id (ID), kind (Kind), version
// (Version), nonce, wrapped_key, owner_sealed, ciphertext (Inner), updated_at
// (UpdatedAt). The anchor identity and number (Anchor, Num) are what the
// owner blob holds: they are in the body so that a reader can rebuild the
// lookup tag. The lookup tag column is not stored: it is the keyed hash
// (index key) of the anchor, kind and number and is recomputed by a holder of
// the keys. RecordFormat is the encoding of the record (seal.RecordFormat,
// 2); the row has no such column. Class follows from the kind and is checked
// against the store's rule.
type Record struct {
	Kind         string
	Class        string
	ID           []byte
	Anchor       []byte
	Num          uint64
	Version      uint64
	RecordFormat uint64
	UpdatedAt    int64
	Inner        Inner
}

func (Record) isObject() {}

// Audit is the body of an audit object: the columns of the audit row as
// verify.go reads them.
type Audit struct {
	Seq     int64
	At      int64
	Kind    string // update, slots or rollover
	Event   []byte // the sealed event, as stored
	Touched []byte
	SlotSet []byte // empty in an update row, 32 bytes otherwise
	MAC     []byte
	PrevMAC []byte
}

func (Audit) isObject() {}

// wrappedKeyForm is the wire form of the wrapped-key field: a field of fixed
// width (u16 big-endian true length, the key, zeros to W bytes) and the true
// length again, which only tests change.
type wrappedKeyForm struct {
	Length int
	Field  []byte
}

func newWrappedKeyForm(wk []byte) (wrappedKeyForm, error) {
	if len(wk) == 0 {
		return wrappedKeyForm{}, formatErr("the wrapped key is empty")
	}
	if len(wk) > WrappedKeyMax {
		return wrappedKeyForm{}, formatErr("a wrapped key of %d bytes is longer than W = %d; it is refused, not moved to a larger bucket", len(wk), WrappedKeyMax)
	}
	f := make([]byte, wrappedKeyField)
	f[0], f[1] = byte(len(wk)>>8), byte(len(wk))
	copy(f[2:], wk)
	return wrappedKeyForm{Length: len(wk), Field: f}, nil
}

// EncodeObject is the canonical CBOR of the object (not framed). It refuses
// an object that DecodeObject would refuse, except for the class rule, which
// only the decoder has.
func EncodeObject(o Object) ([]byte, error) {
	switch x := o.(type) {
	case Record:
		return encodeRecord(x, nil)
	case Audit:
		return encodeAudit(x)
	case RecordPage:
		return encodeRecordPage(x)
	case AuditPage:
		return encodeAuditPage(x)
	case Root:
		return encodeRoot(x)
	}
	return nil, formatErr("unknown object type %T", o)
}

// DecodeObject reads canonical CBOR into an object. rule is required: a kind
// it does not know, and a class it does not give for the kind, are refused.
func DecodeObject(cbor []byte, rule ClassRule) (Object, error) {
	v, err := decodeCBOR(cbor)
	if err != nil {
		return nil, err
	}
	a, ok := v.([]any)
	if !ok || len(a) == 0 {
		return nil, formatErr("an object is a non-empty array")
	}
	kind, err := text(a[0], "the object kind")
	if err != nil {
		return nil, err
	}
	var o Object
	switch kind {
	case KindAudit:
		o, err = decodeAudit(a)
	case KindManifestPage:
		o, err = decodePage(a)
	case KindManifestRoot:
		o, err = decodeRoot(a)
	default:
		o, err = decodeRecord(a, rule)
	}
	if err != nil {
		return nil, err
	}
	// The typed object must encode back to the bytes it came from.
	again, err := EncodeObject(o)
	if err != nil || !bytes.Equal(again, cbor) {
		return nil, formatErr("the object does not re-encode to itself")
	}
	return o, nil
}

// EncodeBody is the body of a sealed object: the object's CBOR, framed.
func EncodeBody(o Object) ([]byte, error) {
	c, err := EncodeObject(o)
	if err != nil {
		return nil, err
	}
	return FrameBody(c)
}

// DecodeBody checks the framing of an opened body and decodes the object.
func DecodeBody(body []byte, rule ClassRule) (Object, error) {
	c, err := UnframeBody(body)
	if err != nil {
		return nil, err
	}
	return DecodeObject(c, rule)
}

// ---- records ----

func encodeBodyForm(r Record, mutate func(*wrappedKeyForm)) ([]byte, error) {
	c, err := encodeRecord(r, mutate)
	if err != nil {
		return nil, err
	}
	return FrameBody(c)
}

func encodeRecord(r Record, mutate func(*wrappedKeyForm)) ([]byte, error) {
	if r.Kind == "" || r.Class == "" {
		return nil, formatErr("a record has a kind and a class")
	}
	if len(r.ID) != 16 {
		return nil, formatErr("a record id is 16 bytes")
	}
	if r.RecordFormat != RecordFormat || r.Version < 1 {
		return nil, formatErr("a record has record format %d and a version of at least 1, not format %d and version %d", RecordFormat, r.RecordFormat, r.Version)
	}
	if len(r.Anchor) < 2 || len(r.Anchor) > 40 {
		return nil, formatErr("an anchor is 2 to 40 bytes")
	}
	in := r.Inner
	if len(in.Nonce) != NonceSize || len(in.Owner) < minOwner || len(in.Ciphertext) < TagSize {
		return nil, formatErr("the sealed fields of a record have the wrong sizes")
	}
	wk, err := newWrappedKeyForm(in.WrappedKey)
	if err != nil {
		return nil, err
	}
	if mutate != nil {
		mutate(&wk)
		if len(wk.Field) >= 2 {
			wk.Field[0], wk.Field[1] = byte(wk.Length>>8), byte(wk.Length)
		}
	}
	return encodeCBOR([]any{r.Kind, r.Class, r.ID, r.Anchor, r.Num, r.Version, r.RecordFormat, r.UpdatedAt,
		[]any{in.Nonce, wk.Field, in.Owner, in.Ciphertext}})
}

func decodeRecord(a []any, rule ClassRule) (Record, error) {
	if rule == nil {
		return Record{}, formatErr("no class rule: a record cannot be checked")
	}
	if len(a) != 9 {
		return Record{}, formatErr("a record body has 9 items, not %d", len(a))
	}
	var r Record
	var err error
	if r.Kind, err = text(a[0], "the kind"); err != nil {
		return r, err
	}
	want, known := rule(r.Kind)
	if !known {
		return Record{}, formatErr("unknown object kind %q", r.Kind)
	}
	if r.Class, err = text(a[1], "the class"); err != nil {
		return r, err
	}
	if r.Class != want {
		return Record{}, formatErr("the class %q is not the class %q that the store gives kind %q", r.Class, want, r.Kind)
	}
	if r.ID, err = fixed(a[2], 16, "the record id"); err != nil {
		return r, err
	}
	if r.Anchor, err = bstr(a[3], "the anchor"); err != nil {
		return r, err
	}
	if len(r.Anchor) < 2 || len(r.Anchor) > 40 {
		return Record{}, formatErr("an anchor is 2 to 40 bytes")
	}
	if r.Num, err = uint64Of(a[4], "the number"); err != nil {
		return r, err
	}
	if r.Version, err = uint64Of(a[5], "the version"); err != nil {
		return r, err
	}
	if r.RecordFormat, err = uint64Of(a[6], "the record format"); err != nil {
		return r, err
	}
	if r.UpdatedAt, err = int64Of(a[7], "updated_at"); err != nil {
		return r, err
	}
	if r.RecordFormat != RecordFormat || r.Version < 1 {
		return Record{}, formatErr("a record has record format %d and a version of at least 1, not format %d and version %d", RecordFormat, r.RecordFormat, r.Version)
	}
	in, err := arr(a[8], 4, "the inner record")
	if err != nil {
		return r, err
	}
	if r.Inner.Nonce, err = fixed(in[0], NonceSize, "the payload nonce"); err != nil {
		return r, err
	}
	field, err := fixed(in[1], wrappedKeyField, "the wrapped key field")
	if err != nil {
		return r, err
	}
	n := int(field[0])<<8 | int(field[1])
	if n == 0 || n > WrappedKeyMax {
		return Record{}, formatErr("the wrapped key length %d is not between 1 and W = %d", n, WrappedKeyMax)
	}
	// The fill after the key is not checked here: DecodeObject re-encodes the
	// record, which zero-fills, and refuses a body that differs.
	r.Inner.WrappedKey = field[2 : 2+n]
	if r.Inner.Owner, err = bstr(in[2], "the owner blob"); err != nil {
		return r, err
	}
	if len(r.Inner.Owner) < minOwner {
		return Record{}, formatErr("the owner blob is too short")
	}
	if r.Inner.Ciphertext, err = bstr(in[3], "the ciphertext"); err != nil {
		return r, err
	}
	if len(r.Inner.Ciphertext) < TagSize {
		return Record{}, formatErr("the ciphertext is too short")
	}
	return r, nil
}

// ---- audit rows ----

func validAudit(x Audit) error {
	if x.Seq < 1 {
		return formatErr("an audit sequence number is at least 1")
	}
	switch x.Kind {
	case "update":
		if len(x.SlotSet) != 0 {
			return formatErr("an update row has no slot-set hash")
		}
	case "slots", "rollover":
		if len(x.SlotSet) != HashSize {
			return formatErr("a %s row has a 32-byte slot-set hash", x.Kind)
		}
	default:
		return formatErr("unknown audit row kind %q", x.Kind)
	}
	if len(x.MAC) != HashSize || len(x.PrevMAC) != HashSize {
		return formatErr("an audit MAC is 32 bytes")
	}
	if len(x.Event) == 0 {
		return formatErr("an audit row has an event")
	}
	return nil
}

func encodeAudit(x Audit) ([]byte, error) {
	if err := validAudit(x); err != nil {
		return nil, err
	}
	return encodeCBOR([]any{KindAudit, x.Seq, x.At, x.Kind, x.Event, x.Touched, x.SlotSet, x.MAC, x.PrevMAC})
}

func decodeAudit(a []any) (Audit, error) {
	if len(a) != 9 {
		return Audit{}, formatErr("an audit body has 9 items, not %d", len(a))
	}
	var x Audit
	var err error
	if x.Seq, err = int64Of(a[1], "the audit sequence"); err != nil {
		return x, err
	}
	if x.At, err = int64Of(a[2], "the audit time"); err != nil {
		return x, err
	}
	if x.Kind, err = text(a[3], "the audit kind"); err != nil {
		return x, err
	}
	if x.Event, err = bstr(a[4], "the event"); err != nil {
		return x, err
	}
	if x.Touched, err = bstr(a[5], "touched"); err != nil {
		return x, err
	}
	if x.SlotSet, err = bstr(a[6], "the slot-set hash"); err != nil {
		return x, err
	}
	if x.MAC, err = bstr(a[7], "the MAC"); err != nil {
		return x, err
	}
	if x.PrevMAC, err = bstr(a[8], "the previous MAC"); err != nil {
		return x, err
	}
	return x, validAudit(x)
}
