package tokenmeta

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"golang.org/x/crypto/blake2b"
)

// Property is a property name of an entry.
type Property string

// The properties of CIP-26 this package knows.
const (
	PropName        Property = "name"
	PropDescription Property = "description"
	PropTicker      Property = "ticker"
	PropURL         Property = "url"
	PropLogo        Property = "logo"
	PropDecimals    Property = "decimals"
)

// fileOrder is the order of the keys in the file: the order of the public
// registry's own `mappings/*.json` (every entry there lists subject, url,
// name, ticker, decimals, policy, logo, description, an aeson hash-map order).
var fileOrder = []Property{PropURL, PropName, PropTicker, PropDecimals, "policy", PropLogo, PropDescription}

// Properties lists the attested properties.
func Properties() []Property {
	return []Property{PropName, PropDescription, PropTicker, PropURL, PropLogo, PropDecimals}
}

// Value is the value of a property: text (name, description, ticker, url), an
// unsigned integer (decimals) or bytes (the decoded logo).
type Value struct {
	kind  byte // 't', 'n', 'b'
	text  string
	num   uint64
	bytes []byte
}

// Text, Number and Bytes make values.
func Text(s string) Value   { return Value{kind: 't', text: s} }
func Number(n uint64) Value { return Value{kind: 'n', num: n} }
func Bytes(b []byte) Value  { return Value{kind: 'b', bytes: b} }
func (v Value) String() string {
	switch v.kind {
	case 'n':
		return strconv.FormatUint(v.num, 10)
	case 'b':
		return fmt.Sprintf("<%d bytes>", len(v.bytes))
	}
	return v.text
}

// Text returns the text of a text value.
func (v Value) Text() string { return v.text }

// Number returns the integer of a number value.
func (v Value) Number() uint64 { return v.num }

// Bytes returns the bytes of a byte value (the decoded logo).
func (v Value) Bytes() []byte { return v.bytes }

// Equal compares two values.
func (v Value) Equal(o Value) bool {
	return v.kind == o.kind && v.text == o.text && v.num == o.num && bytes.Equal(v.bytes, o.bytes)
}

// CBOR is the encoding the attestation hashes.
func (v Value) CBOR() []byte {
	switch v.kind {
	case 'n':
		return cborUint(v.num)
	case 'b':
		return cborBytes(v.bytes)
	}
	return cborText(v.text)
}

func hash256(p []byte) []byte { h := blake2b.Sum256(p); return h[:] }

// Message is the message an attestation signs: the hash of the concatenated
// hashes of the CBOR of the subject, the property name, the value and the
// sequence number (CIP-26).
//
// spec: SPO-12a-SEC-001
func Message(subject string, prop Property, v Value, seq uint64) [32]byte {
	var buf []byte
	buf = append(buf, hash256(cborText(subject))...)
	buf = append(buf, hash256(cborText(string(prop)))...)
	buf = append(buf, hash256(v.CBOR())...)
	buf = append(buf, hash256(cborUint(seq))...)
	return blake2b.Sum256(buf)
}

// Attestation is one annotated signature.
type Attestation struct {
	PublicKey [32]byte
	Signature [64]byte
}

// Verify checks the signature over msg.
func (a Attestation) Verify(msg [32]byte) bool {
	return ed25519.Verify(ed25519.PublicKey(a.PublicKey[:]), msg[:], a.Signature[:])
}

// KeyHash is the blake2b-224 hash of the public key, the hash a policy
// script names.
func (a Attestation) KeyHash() [28]byte { return blake224(a.PublicKey[:]) }

// Attested is a property of an entry.
type Attested struct {
	Value      Value
	Sequence   uint64
	Signatures []Attestation
}

// Entry is a registry entry.
type Entry struct {
	Subject string
	// Policy is the `policy` property: hex of [tag, native script]. Empty when
	// the entry has none.
	Policy string
	Props  map[Property]Attested
	// Other lists top-level members this package does not read (the registry
	// server adds `additionalProperties`); they are not verified.
	Other []string
}

// SignFunc signs messages with the policy key: one attestation per message.
type SignFunc func(ctx context.Context, msgs [][32]byte) ([]Attestation, error)

// ErrSigner: the signer returned something other than one attestation per
// message, or an attestation that does not verify.
var ErrSigner = errors.New("the signer's answer is not usable")

// Build makes the signed entry of the fields at a sequence number: the
// validated properties, each attested by the signer, and the policy property
// built from the policy script. The signer's attestations are verified before
// they are put in the entry, so a signer that holds another key than the one
// it claims is caught.
//
// spec: SPO-12a-EXT-001, SPO-12a-EXT-002, SPO-12a-EXT-003, SPO-12a-EXT-004
func Build(ctx context.Context, subject string, policyScript []byte, f Fields, seq uint64, sign SignFunc) (Entry, error) {
	if err := CheckSubject(subject); err != nil {
		return Entry{}, err
	}
	if err := f.Validate(); err != nil {
		return Entry{}, err
	}
	pol, id, err := PolicyValue(policyScript)
	if err != nil {
		return Entry{}, err
	}
	if hex.EncodeToString(id[:]) != subject[:56] {
		return Entry{}, fmt.Errorf("%w: the script hashes to policy id %x, not the subject's %s", ErrPolicy, id, subject[:56])
	}
	e := Entry{Subject: subject, Policy: pol, Props: map[Property]Attested{}}
	var order []Property
	add := func(p Property, v Value) {
		e.Props[p] = Attested{Value: v, Sequence: seq}
		order = append(order, p)
	}
	add(PropName, Text(f.Name))
	add(PropDescription, Text(f.Description))
	if f.Ticker != "" {
		add(PropTicker, Text(f.Ticker))
	}
	if f.URL != "" {
		add(PropURL, Text(f.URL))
	}
	if f.Logo != nil {
		add(PropLogo, Bytes(f.Logo))
	}
	if f.Decimals != "" {
		n, _ := ParseDecimals(f.Decimals)
		add(PropDecimals, Number(n))
	}
	msgs := make([][32]byte, len(order))
	for i, p := range order {
		msgs[i] = Message(subject, p, e.Props[p].Value, seq)
	}
	atts, err := sign(ctx, msgs)
	if err != nil {
		return Entry{}, err
	}
	if len(atts) != len(msgs) {
		return Entry{}, fmt.Errorf("%w: %d attestations for %d messages", ErrSigner, len(atts), len(msgs))
	}
	for i, p := range order {
		if !atts[i].Verify(msgs[i]) {
			return Entry{}, fmt.Errorf("%w: the attestation of %s does not verify", ErrSigner, p)
		}
		a := e.Props[p]
		a.Signatures = []Attestation{atts[i]}
		e.Props[p] = a
	}
	return e, nil
}

// ---- file ------------------------------------------------------------------------

func jsonText(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return string(bytes.TrimRight(b.Bytes(), "\n"))
}

func (v Value) jsonValue() string {
	switch v.kind {
	case 'n':
		return strconv.FormatUint(v.num, 10)
	case 'b':
		return jsonText(base64.StdEncoding.EncodeToString(v.bytes))
	}
	return jsonText(v.text)
}

// JSON renders the entry as the registry's files are written: four-space
// indent, the members in the registry's order, each property as
// sequenceNumber, value, signatures. A final newline ends the file.
//
// spec: SPO-12a-OUT-004
func (e Entry) JSON() []byte {
	var b bytes.Buffer
	b.WriteString("{\n    \"subject\": " + jsonText(e.Subject))
	for _, p := range fileOrder {
		if p == "policy" {
			if e.Policy != "" {
				b.WriteString(",\n    \"policy\": " + jsonText(e.Policy))
			}
			continue
		}
		a, ok := e.Props[p]
		if !ok {
			continue
		}
		b.WriteString(",\n    " + jsonText(string(p)) + ": {\n")
		b.WriteString("        \"sequenceNumber\": " + strconv.FormatUint(a.Sequence, 10) + ",\n")
		b.WriteString("        \"value\": " + a.Value.jsonValue() + ",\n")
		b.WriteString("        \"signatures\": [")
		for i, s := range a.Signatures {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString("\n            {\n")
			b.WriteString("                \"signature\": \"" + hex.EncodeToString(s.Signature[:]) + "\",\n")
			b.WriteString("                \"publicKey\": \"" + hex.EncodeToString(s.PublicKey[:]) + "\"\n")
			b.WriteString("            }")
		}
		if len(a.Signatures) > 0 {
			b.WriteString("\n        ")
		}
		b.WriteString("]\n    }")
	}
	b.WriteString("\n}\n")
	return b.Bytes()
}

// Sequence is the highest sequence number of the entry's properties.
func (e Entry) Sequence() (n uint64, ok bool) {
	for _, a := range e.Props {
		if !ok || a.Sequence > n {
			n, ok = a.Sequence, true
		}
	}
	return n, ok
}
