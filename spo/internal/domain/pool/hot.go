package pool

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// HotKind is one of the three files a block producer's cardano-node reads in
// clear: the KES signing key, the VRF signing key and the operational
// certificate (ADR 0011 decisions 1 and 2). There is no other value, so no cold,
// payment, stake, DRep or committee key and no mnemonic has a kind to be named
// by. This table is the one place where the envelope type and the file name of
// each kind are written; `node export`, the start-up helper and its writer read
// it, and the architecture test pins it.
type HotKind uint8

const (
	HotKES HotKind = iota + 1
	HotVRF
	HotOpCert
)

// HotSpec is what a kind is: the plain file name the node reads, the
// text-envelope type it must carry and the exact length of its cborHex.
type HotSpec struct {
	File string
	Type string
	// CborHexLen is the exact length of the cborHex text, 0 for the certificate,
	// whose length depends on its integers and which is read structurally.
	CborHexLen int
}

var hotSpecs = map[HotKind]HotSpec{
	HotKES:    {"kes.skey", "KesSigningKey_ed25519_kes_2^6", 2 * (3 + 608)},
	HotVRF:    {"vrf.skey", "VrfSigningKey_PraosVRF", 2 * (2 + 64)},
	HotOpCert: {"node.cert", "NodeOperationalCertificate", 0},
}

// HotKinds lists the three kinds in the order they are delivered.
func HotKinds() []HotKind { return []HotKind{HotKES, HotVRF, HotOpCert} }

// Spec returns the specification of a kind; false for any other value.
func (k HotKind) Spec() (HotSpec, bool) { s, ok := hotSpecs[k]; return s, ok }

// CipherFile is the name of the delivered ciphertext of a kind: the plain file
// name and ".age".
func (s HotSpec) CipherFile() string { return s.File + ".age" }

// ErrNotHot means an envelope is not a hot file of the kind it was given as.
var ErrNotHot = errors.New("not a KES signing key, a VRF signing key or an operational certificate of the kind named (envelope type, members or length differ)")

// maxHotEnvelope bounds what is parsed: the largest hot file is about 1.3 KiB.
const maxHotEnvelope = 4096

// ValidateHot checks that data is a text envelope of the kind: exactly the
// members type, description and cborHex, each once; the type of the kind; and a
// cborHex of the exact length of the kind (a CBOR byte string of 608 bytes for a
// KES key, of 64 for a VRF key) or, for a certificate, the structure of
// ParseOpCert. A file that has the envelope type of the kind and other material
// is refused.
func ValidateHot(k HotKind, data []byte) error {
	spec, ok := k.Spec()
	if !ok {
		return fmt.Errorf("%w: unknown kind %d", ErrNotHot, k)
	}
	if len(data) == 0 || len(data) > maxHotEnvelope {
		return fmt.Errorf("%w: size %d", ErrNotHot, len(data))
	}
	members, err := topLevelMembers(data)
	if err != nil {
		return fmt.Errorf("%w: not a plain JSON object of three members", ErrNotHot)
	}
	if len(members) != 3 || !members["type"] || !members["description"] || !members["cborHex"] {
		return fmt.Errorf("%w: the members are not exactly type, description and cborHex", ErrNotHot)
	}
	var e Envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return fmt.Errorf("%w: the members are not strings", ErrNotHot)
	}
	if e.Type != spec.Type {
		return fmt.Errorf("%w: the envelope type is not %q", ErrNotHot, spec.Type)
	}
	raw, err := hex.DecodeString(e.CborHex)
	defer clear(raw)
	if err != nil {
		return fmt.Errorf("%w: cborHex is not hexadecimal", ErrNotHot)
	}
	switch k {
	case HotKES:
		if len(e.CborHex) != spec.CborHexLen || !bytes.HasPrefix(raw, []byte{0x59, 0x02, 0x60}) {
			return fmt.Errorf("%w: a KES signing key is a CBOR byte string of 608 bytes", ErrNotHot)
		}
	case HotVRF:
		if len(e.CborHex) != spec.CborHexLen || !bytes.HasPrefix(raw, []byte{0x58, 0x40}) {
			return fmt.Errorf("%w: a VRF signing key is a CBOR byte string of 64 bytes", ErrNotHot)
		}
	case HotOpCert:
		if _, err := ParseOpCert(data); err != nil {
			return fmt.Errorf("%w: not a certificate of the exact structure", ErrNotHot)
		}
	}
	return nil
}

// HotKeyBytes returns the raw key bytes of a KES or VRF signing key envelope
// that ValidateHot accepted (the 608 or 64 bytes inside the CBOR byte string).
// The caller wipes them.
func HotKeyBytes(k HotKind, data []byte) ([]byte, error) {
	if k != HotKES && k != HotVRF {
		return nil, fmt.Errorf("%w: %d has no key bytes", ErrNotHot, k)
	}
	if err := ValidateHot(k, data); err != nil {
		return nil, err
	}
	var e Envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, ErrNotHot
	}
	raw, err := hex.DecodeString(e.CborHex)
	if err != nil {
		return nil, ErrNotHot
	}
	head := 3
	if k == HotVRF {
		head = 2
	}
	out := append([]byte(nil), raw[head:]...)
	clear(raw)
	return out, nil
}

// topLevelMembers lists the member names of a JSON object and refuses a repeated
// member, a non-object and trailing text.
func topLevelMembers(data []byte) (map[string]bool, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		name, ok := t.(string)
		if !ok || seen[name] {
			return nil, errors.New("a repeated or malformed member")
		}
		seen[name] = true
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return nil, err
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing text")
	}
	return seen, nil
}

// MaxSaneKesPeriod bounds the KES period a delivered certificate may start in: far
// above any period reached in the life of a chain, far below a corrupted field.
const MaxSaneKesPeriod = 1 << 20
