package tokenmeta

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ErrBadEntry: an entry that is not valid CIP-26 JSON of the shapes this
// package reads.
var ErrBadEntry = errors.New("invalid token registry entry")

// MaxEntryBytes bounds what ParseEntry reads: the largest logo's base64 text
// and room for the rest.
const MaxEntryBytes = 256 << 10

const (
	maxText       = 4096 // bytes of any text value
	maxSignatures = 16
)

func badEntry(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrBadEntry, fmt.Sprintf(format, a...))
}

// ParseEntry reads the entry a registry file or server answer holds. It is
// strict: duplicate members, a value of the wrong type, a sequence number that
// is not a whole number, a signature or key of the wrong length, and sizes over
// the limits are refused. Members it does not know are listed in Other, not
// read.
func ParseEntry(b []byte) (Entry, error) {
	if len(b) > MaxEntryBytes {
		return Entry{}, badEntry("larger than %d bytes", MaxEntryBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return Entry{}, badEntry("not a JSON object")
	}
	raw := map[string]json.RawMessage{}
	var order []string
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return Entry{}, badEntry("not valid JSON")
		}
		k := kt.(string)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return Entry{}, badEntry("not valid JSON")
		}
		if _, dup := raw[k]; dup {
			return Entry{}, badEntry("member %q appears twice", k)
		}
		raw[k] = v
		order = append(order, k)
	}
	if _, err := dec.Token(); err != nil {
		return Entry{}, badEntry("not valid JSON")
	}
	if _, err := dec.Token(); err != io.EOF {
		return Entry{}, badEntry("text after the object")
	}
	e := Entry{Props: map[Property]Attested{}}
	for _, k := range order {
		v := raw[k]
		switch k {
		case "subject":
			if err := json.Unmarshal(v, &e.Subject); err != nil {
				return Entry{}, badEntry("subject is not a string")
			}
		case "policy":
			if err := json.Unmarshal(v, &e.Policy); err != nil {
				return Entry{}, badEntry("policy is not a string")
			}
			if len(e.Policy) > 8192 {
				return Entry{}, badEntry("policy is too long")
			}
		case string(PropName), string(PropDescription), string(PropTicker), string(PropURL), string(PropLogo), string(PropDecimals):
			a, err := parseAttested(Property(k), v)
			if err != nil {
				return Entry{}, err
			}
			e.Props[Property(k)] = a
		default:
			e.Other = append(e.Other, k)
		}
	}
	if err := CheckSubject(e.Subject); err != nil {
		return Entry{}, badEntry("%v", err)
	}
	return e, nil
}

// rawUint reads a JSON number that is a plain non-negative integer; a string,
// a float, a sign or an exponent is refused (json.Number alone would take a
// quoted number).
func rawUint(raw json.RawMessage) (uint64, bool) {
	s := string(bytes.TrimSpace(raw))
	if s == "" || strings.Trim(s, "0123456789") != "" || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	u, err := strconv.ParseUint(s, 10, 64)
	return u, err == nil
}

func parseAttested(p Property, raw json.RawMessage) (Attested, error) {
	var o map[string]json.RawMessage
	if err := json.Unmarshal(raw, &o); err != nil {
		return Attested{}, badEntry("%s is not an object", p)
	}
	for k := range o {
		if k != "value" && k != "sequenceNumber" && k != "signatures" {
			return Attested{}, badEntry("%s has an unknown member %q", p, k)
		}
	}
	var a Attested
	seq, ok := rawUint(o["sequenceNumber"])
	if !ok {
		return Attested{}, badEntry("%s: the sequence number is missing or not a whole number", p)
	}
	a.Sequence = seq
	vraw, ok := o["value"]
	if !ok {
		return Attested{}, badEntry("%s has no value", p)
	}
	switch p {
	case PropDecimals:
		u, ok := rawUint(vraw)
		if !ok || u > MaxDecimals {
			return Attested{}, badEntry("decimals is not a whole number of at most %d", MaxDecimals)
		}
		a.Value = Number(u)
	case PropLogo:
		var s string
		if err := json.Unmarshal(vraw, &s); err != nil {
			return Attested{}, badEntry("logo is not a string")
		}
		if len(s) > MaxLogoBase64 {
			return Attested{}, badEntry("logo is larger than %d base64 characters", MaxLogoBase64)
		}
		png, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return Attested{}, badEntry("logo is not base64")
		}
		a.Value = Bytes(png)
	default:
		var s string
		if err := json.Unmarshal(vraw, &s); err != nil {
			return Attested{}, badEntry("%s is not a string", p)
		}
		if len(s) > maxText || !utf8.ValidString(s) {
			return Attested{}, badEntry("%s is too long or not UTF-8", p)
		}
		a.Value = Text(s)
	}
	if sraw, ok := o["signatures"]; ok && string(bytes.TrimSpace(sraw)) != "null" {
		var sigs []struct {
			Signature string `json:"signature"`
			PublicKey string `json:"publicKey"`
		}
		if err := json.Unmarshal(sraw, &sigs); err != nil || len(sigs) > maxSignatures {
			return Attested{}, badEntry("%s: signatures is not an array of at most %d", p, maxSignatures)
		}
		for _, s := range sigs {
			sig, e1 := hex.DecodeString(s.Signature)
			pk, e2 := hex.DecodeString(s.PublicKey)
			if e1 != nil || e2 != nil || len(sig) != 64 || len(pk) != 32 {
				return Attested{}, badEntry("%s: a signature is 64 bytes and a public key 32 bytes, in hex", p)
			}
			var at Attestation
			copy(at.Signature[:], sig)
			copy(at.PublicKey[:], pk)
			a.Signatures = append(a.Signatures, at)
		}
	}
	return a, nil
}
