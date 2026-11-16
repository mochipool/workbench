// Package keyfile is the pure part of upstream's key files: how a signing
// key file is classified, what a malformed encrypted envelope is, the strong
// password rule, and the transform upstream's password prompt applies.
//
// The cryptography is not here (the gpg adapter does it) and nothing here
// reads a file.
package keyfile

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Form is what a key file holds.
type Form int

const (
	// FormMalformed is a file that is none of the forms below, or an
	// encrypted envelope that cannot be decrypted because it is damaged.
	FormMalformed Form = iota
	// FormPlain is a cardano-cli text envelope of a signing key.
	FormPlain
	// FormEncrypted is upstream's encrypted envelope (SPO-Ckey-OUT-001).
	FormEncrypted
	// FormHardware is a hardware signing file (SPO-Pfiles-OUT-004): no
	// private key.
	FormHardware
)

func (f Form) String() string {
	return [...]string{"malformed", "plain", "encrypted", "hardware"}[f]
}

// Errors of this package. They never contain file content.
var (
	ErrMalformed          = errors.New("the key file is not a signing key envelope")
	ErrMalformedEncrypted = errors.New("the encrypted key envelope is damaged")
)

const (
	encryptedPrefix = "Encrypted "
	// A gpg symmetric message of even one byte is far larger than this; a
	// shorter encrHex cannot be one.
	minEncrHexBytes = 30
)

// Info is what can be said about a key file without opening it. It holds
// no key material.
type Info struct {
	Form        Form
	Type        string
	Description string
}

// fields locates the members of a top-level JSON object without decoding
// their values, so a signing key's cborHex is never copied into an
// ordinary Go string: it stays in the caller's buffer, and callers get
// sub-slices of it.
type fields struct {
	data []byte
	at   map[string][2]int // member name -> value token [start, end)
}

// scan reports ok for a single valid JSON object. A repeated member keeps
// the last value, as encoding/json does.
func scan(data []byte) (fields, bool) {
	if !json.Valid(data) {
		return fields{}, false
	}
	f := fields{data: data, at: map[string][2]int{}}
	i := skipWS(data, 0)
	if i >= len(data) || data[i] != '{' {
		return fields{}, false
	}
	i = skipWS(data, i+1)
	if i < len(data) && data[i] == '}' {
		return f, skipWS(data, i+1) == len(data)
	}
	for {
		ks, ke, ok := stringTok(data, i)
		if !ok {
			return fields{}, false
		}
		var key string
		if json.Unmarshal(data[ks:ke], &key) != nil {
			return fields{}, false
		}
		i = skipWS(data, ke)
		if i >= len(data) || data[i] != ':' {
			return fields{}, false
		}
		i = skipWS(data, i+1)
		end := skipValue(data, i)
		if end < 0 {
			return fields{}, false
		}
		f.at[key] = [2]int{i, end}
		i = skipWS(data, end)
		if i < len(data) && data[i] == ',' {
			i = skipWS(data, i+1)
			continue
		}
		if i < len(data) && data[i] == '}' {
			return f, skipWS(data, i+1) == len(data)
		}
		return fields{}, false
	}
}

func skipWS(b []byte, i int) int {
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	return i
}

// stringTok returns the span of the JSON string starting at i, quotes included.
func stringTok(b []byte, i int) (int, int, bool) {
	if i >= len(b) || b[i] != '"' {
		return 0, 0, false
	}
	for j := i + 1; j < len(b); j++ {
		switch b[j] {
		case '\\':
			j++
		case '"':
			return i, j + 1, true
		}
	}
	return 0, 0, false
}

// skipValue returns the end of the JSON value starting at i, or -1.
func skipValue(b []byte, i int) int {
	if i >= len(b) {
		return -1
	}
	switch b[i] {
	case '"':
		_, e, ok := stringTok(b, i)
		if !ok {
			return -1
		}
		return e
	case '{', '[':
		depth := 0
		for j := i; j < len(b); j++ {
			switch b[j] {
			case '"':
				_, e, ok := stringTok(b, j)
				if !ok {
					return -1
				}
				j = e - 1
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return j + 1
				}
			}
		}
		return -1
	}
	j := i
	for j < len(b) && !strings.ContainsRune(",}] \t\r\n", rune(b[j])) {
		j++
	}
	return j
}

// has reports whether the object has the member.
func (f fields) has(key string) bool { _, ok := f.at[key]; return ok }

// str decodes a member that must be a string. Use it for non-secret members.
func (f fields) str(key string) (string, bool) {
	sp, ok := f.at[key]
	if !ok {
		return "", false
	}
	var v string
	if json.Unmarshal(f.data[sp[0]:sp[1]], &v) != nil {
		return "", false
	}
	return v, true
}

// inner returns the bytes between the quotes of a string member that holds
// no escape sequence, as a sub-slice of the data: no copy is made.
func (f fields) inner(key string) ([]byte, bool) {
	sp, ok := f.at[key]
	if !ok || sp[1]-sp[0] < 2 || f.data[sp[0]] != '"' {
		return nil, false
	}
	in := f.data[sp[0]+1 : sp[1]-1]
	if bytes.IndexByte(in, '\\') >= 0 {
		return nil, false
	}
	return in, true
}

// HasField reports whether data is a JSON object with the named top-level
// member, without decoding any value.
func HasField(data []byte, name string) bool {
	f, ok := scan(data)
	return ok && f.has(name)
}

// ValidObject reports whether data is a single JSON object.
func ValidObject(data []byte) bool { _, ok := scan(data); return ok }

// Classify says which form a signing key file is in. It is structural: the
// text search of upstream (`encrHex` or `Encrypted` anywhere, SPO-Ckey-IN-001)
// is not used, so a plaintext key whose description contains "Encrypted" is
// plain, not a file that asks for a password forever.
//
// A damaged encrypted envelope is reported as FormMalformed with
// ErrMalformedEncrypted, not as something to retry (H8).
//
// spec: SPO-Pfiles-OUT-003, SPO-Pfiles-OUT-004, SPO-Ckey-IN-001, SPO-Ckey-OUT-003, SPO-Ckey-PRE-003, SPO-Ckey-PRE-006, SPO-Ckey-PRE-010
func Classify(data []byte) (Info, error) {
	f, ok := scan(data)
	typ, hasType := f.str("type")
	if !ok || !hasType {
		// Not a JSON object with a type. Upstream would pass such text
		// through read_skeyFILE unchecked (SPO-Ckey-OUT-003); an
		// encrypted-looking blob would loop on prompts (SPO-Ckey-PRE-010).
		if bytes.Contains(data, []byte("encrHex")) {
			return Info{}, ErrMalformedEncrypted
		}
		return Info{}, ErrMalformed
	}
	desc, _ := f.str("description")
	info := Info{Type: typ, Description: desc}
	switch {
	case f.has("encrHex"):
		if _, err := checkEncrypted(f); err != nil {
			info.Form = FormMalformed
			return info, err
		}
		info.Form = FormEncrypted
	case f.has("cborXPubKeyHex") || strings.Contains(typ, "HWSigningFile"):
		info.Form = FormHardware
	case strings.Contains(typ, "SigningKey") && f.has("cborHex"):
		in, ok := f.inner("cborHex")
		if !ok || checkHex(in) != nil {
			return Info{Form: FormMalformed, Type: typ}, ErrMalformed
		}
		info.Form = FormPlain
	default:
		return Info{Form: FormMalformed, Type: typ}, ErrMalformed
	}
	return info, nil
}

func checkHex(s []byte) error {
	if len(s) == 0 || len(s)%2 != 0 {
		return ErrMalformed
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return ErrMalformed
		}
	}
	return nil
}

// Encrypted is a validated encrypted envelope.
type Encrypted struct {
	Type        string
	Description string // as stored, with the "Encrypted " prefix
	EncrHex     []byte // the ASCII hex text of the gpg message
}

func checkEncrypted(f fields) (Encrypted, error) {
	typ, ok1 := f.str("type")
	desc, ok2 := f.str("description")
	h, ok3 := f.inner("encrHex")
	if !ok1 || !ok2 || !ok3 || f.has("cborHex") {
		return Encrypted{}, ErrMalformedEncrypted
	}
	if !strings.Contains(typ, "SigningKey") || !strings.HasPrefix(desc, encryptedPrefix) {
		return Encrypted{}, ErrMalformedEncrypted
	}
	if checkHex(h) != nil || len(h)/2 < minEncrHexBytes {
		return Encrypted{}, ErrMalformedEncrypted
	}
	return Encrypted{Type: typ, Description: desc, EncrHex: append([]byte(nil), h...)}, nil
}

// ParseEncrypted validates an encrypted envelope before any decryption
// attempt: JSON with `type` (containing SigningKey), `description` (starting
// with "Encrypted "), a hex `encrHex` of plausible length, and no `cborHex`.
// Anything else is ErrMalformedEncrypted: a damaged file is reported at
// once, never as a wrong password and never as a reason to ask again (H8).
//
// spec: SPO-Ckey-PRE-003, SPO-Ckey-PRE-006, SPO-Ckey-PRE-010, SPO-Ckey-OUT-001
func ParseEncrypted(data []byte) (Encrypted, error) {
	f, ok := scan(data)
	if !ok {
		return Encrypted{}, ErrMalformedEncrypted
	}
	return checkEncrypted(f)
}

// PlainDescription is the description of the decrypted key: every
// occurrence of "Encrypted " removed, as upstream's decrypt does.
//
// spec: SPO-Ckey-OUT-002
func PlainDescription(encrypted string) string {
	return strings.ReplaceAll(encrypted, encryptedPrefix, "")
}

// EncryptedDescription prefixes a description as encrypt_skeyJSON does.
//
// spec: SPO-Ckey-OUT-001
func EncryptedDescription(plain string) string { return encryptedPrefix + plain }

// Plain is the content of a plain envelope: Type and Description, no key.
type Plain struct {
	Type        string
	Description string
}

// ParsePlain reads the type and description of a plain signing key envelope
// and the length of its cborHex, and checks the shape. The key itself is not
// copied out of data.
//
// spec: SPO-Ckey-PRE-003
func ParsePlain(data []byte) (Plain, int, error) {
	f, ok := scan(data)
	typ, hasType := f.str("type")
	in, hasCbor := f.inner("cborHex")
	if !ok || !hasType || !hasCbor || f.has("encrHex") || !strings.Contains(typ, "SigningKey") || checkHex(in) != nil {
		return Plain{}, 0, ErrMalformed
	}
	desc, _ := f.str("description")
	return Plain{Type: typ, Description: desc}, len(in), nil
}

// CborHexSpan returns the sub-slice of a plain envelope that is its cborHex
// text, without copying it. The slice aliases data.
func CborHexSpan(data []byte) ([]byte, error) {
	f, ok := scan(data)
	in, hasCbor := f.inner("cborHex")
	if !ok || !hasCbor || checkHex(in) != nil {
		return nil, ErrMalformed
	}
	return in, nil
}

func jsonString(s string) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return bytes.TrimRight(b.Bytes(), "\n")
}

// PlainEnvelopeLen is the length AppendPlainEnvelope will produce, so a
// caller can allocate guarded memory of exactly that size.
func PlainEnvelopeLen(typ, desc string, cborLen int, indent string) int {
	return len(AppendPlainEnvelope(nil, typ, desc, nil, cborLen, indent))
}

// AppendPlainEnvelope appends a plain key envelope: type, description,
// cborHex, a newline at the end. indent is four spaces for cardano-cli's
// formatting and two for the `jq -M .` formatting of upstream's decrypt
// (SPO-Ckey-OUT-002). cbor holds the hex text; when it is nil, cborLen
// placeholder bytes are counted instead, so the length can be computed
// without the key.
func AppendPlainEnvelope(dst []byte, typ, desc string, cbor []byte, cborLen int, indent string) []byte {
	dst = append(dst, "{\n"...)
	dst = append(dst, indent...)
	dst = append(dst, `"type": `...)
	dst = append(dst, jsonString(typ)...)
	dst = append(dst, ",\n"...)
	dst = append(dst, indent...)
	dst = append(dst, `"description": `...)
	dst = append(dst, jsonString(desc)...)
	dst = append(dst, ",\n"...)
	dst = append(dst, indent...)
	dst = append(dst, `"cborHex": "`...)
	if cbor != nil {
		dst = append(dst, cbor...)
	} else {
		for i := 0; i < cborLen; i++ {
			dst = append(dst, '0')
		}
	}
	dst = append(dst, "\"\n}\n"...)
	return dst
}

// EncryptedEnvelope renders upstream's encrypted envelope as `jq -M .`
// prints it: two-space indent, members type, description, encrHex, and a
// newline at the end (SPO-01protectKey-OUT-001). The ciphertext is not
// secret.
//
// spec: SPO-Ckey-OUT-001, SPO-01protectKey-OUT-001
func EncryptedEnvelope(typ, plainDescription string, encrHex []byte) []byte {
	var b []byte
	b = append(b, "{\n  \"type\": "...)
	b = append(b, jsonString(typ)...)
	b = append(b, ",\n  \"description\": "...)
	b = append(b, jsonString(EncryptedDescription(plainDescription))...)
	b = append(b, ",\n  \"encrHex\": \""...)
	b = append(b, encrHex...)
	b = append(b, "\"\n}\n"...)
	return b
}

// IsStrongPassword is upstream's strength rule: at least one lower-case
// letter, one upper-case letter, one digit, one character outside a-zA-Z0-9,
// and at least ten characters. The classes are ASCII; a non-ASCII letter is
// "special", as in upstream under the C locale and by the Ckey open question.
//
// spec: SPO-Ckey-INV-001, SPO-Ckey-IF-001
func IsStrongPassword(pw []byte) bool {
	var lower, upper, digit, special bool
	n := 0
	for i := 0; i < len(pw); {
		r, size := decodeRune(pw[i:])
		i += size
		n++
		switch {
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= '0' && r <= '9':
			digit = true
		default:
			special = true
		}
	}
	return lower && upper && digit && special && n >= 10
}

func decodeRune(b []byte) (rune, int) { return utf8.DecodeRune(b) }

// UpstreamRead is what `IFS= read -s pass` (without -r) of upstream's
// ask_pass makes of the typed bytes: a backslash is dropped and the byte
// after it kept (so `ab\cd` is `abcd` and `ab\\cd` is `ab\cd`), a backslash
// before a line break joins the lines, and a backslash at the very end is
// dropped. Leading and trailing spaces are kept (IFS is empty). The result
// is what upstream passed to gpg, both when it encrypted and when it
// decrypted.
//
// spec: SPO-Cui-IF-003, SPO-Cui-SEC-001
func UpstreamRead(typed []byte) []byte {
	out := make([]byte, 0, len(typed))
	for i := 0; i < len(typed); i++ {
		c := typed[i]
		if c != '\\' {
			out = append(out, c)
			continue
		}
		if i+1 >= len(typed) {
			break
		}
		i++
		if typed[i] == '\n' {
			continue
		}
		out = append(out, typed[i])
	}
	return out
}

// PasswordCandidates are the passphrases to try for a password the operator
// typed into the port: as typed (a key the port or a raw reader encrypted),
// and as upstream's prompt would have stored it (a key upstream encrypted).
// They are equal, and so listed once, unless the password has a backslash.
// The caller wipes the returned slices.
//
// spec: SPO-Cui-IF-003, SPO-Ckey-EXT-002, SPO-Pfiles-OUT-003
func PasswordCandidates(typed []byte) [][]byte {
	as := append([]byte(nil), typed...)
	up := UpstreamRead(typed)
	if bytes.Equal(as, up) {
		clear(up)
		return [][]byte{as}
	}
	return [][]byte{as, up}
}

// CborHexBytes decodes a cborHex text; it is for domain checks that need the
// bytes of a verification key, never a signing key.
func CborHexBytes(h string) ([]byte, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("%w: cborHex is not hex", ErrMalformed)
	}
	return b, nil
}
