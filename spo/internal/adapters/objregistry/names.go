package objregistry

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
)

// The layout under the identity's prefix, relays/<node public key, 64 hex>/
// (ADR 0015 decision 3):
//
//	registry bucket (versioned, Object Lock)
//	  marker                                              the identity's marker, locked
//	  registry/bindings/<device, 40 hex>                  one record per bound device
//	  registry/tombstones/p-<K, 56 hex>-<device, 40 hex>  scope pair
//	  registry/tombstones/a-<K, 56 hex>                   scope all
//	  registry/tombstones/d-<device, 40 hex>              scope device
//	working bucket (unversioned)
//	  marker                                              the identity's marker
//	  registry/rates                                      the two rate buckets
//
// The names under registry/ are those of the directory store
// (bindingstore/names.go), and so are the record and tombstone encodings, byte
// for byte, so that migrate-store copies files as they are. A tombstone is one
// object per scope key; a raise is a new version of that object.
const (
	bindingsPath   = "registry/bindings/"
	tombstonesPath = "registry/tombstones/"
	ratesPath      = "registry/rates"
	markerPath     = "marker"
	selftestPath   = "selftest/"
)

// Prefix is the identity's prefix in both buckets.
func Prefix(node [32]byte) string { return "relays/" + hex.EncodeToString(node[:]) + "/" }

var (
	deviceRE   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	tombRE     = regexp.MustCompile(`^(?:p-([0-9a-f]{56})-([0-9a-f]{40})|a-([0-9a-f]{56})|d-([0-9a-f]{40}))$`)
	selftestRE = regexp.MustCompile(`^selftest-[0-9a-f]{16}$`) // the self-test's probe of the deny (s3client.SelfTest)
)

func deviceName(d party.Fingerprint) string { return hex.EncodeToString(d[:]) }

func bindingKey(prefix string, d party.Fingerprint) string {
	return prefix + bindingsPath + deviceName(d)
}

func parseDeviceName(name string) (party.Fingerprint, error) {
	var d party.Fingerprint
	if !deviceRE.MatchString(name) {
		return d, fmt.Errorf("%q is not the name of a binding (40 lower-case hex digits)", name)
	}
	b, _ := hex.DecodeString(name)
	copy(d[:], b)
	return d, nil
}

func tombName(k relayregistry.TombKey) string {
	switch k.Scope {
	case relaybind.ScopePair:
		return "p-" + hex.EncodeToString(k.Key[:]) + "-" + hex.EncodeToString(k.Device[:])
	case relaybind.ScopeAll:
		return "a-" + hex.EncodeToString(k.Key[:])
	default:
		return "d-" + hex.EncodeToString(k.Device[:])
	}
}

func tombKey(prefix string, k relayregistry.TombKey) string {
	return prefix + tombstonesPath + tombName(k)
}

func parseTombName(name string) (relayregistry.TombKey, error) {
	var k relayregistry.TombKey
	m := tombRE.FindStringSubmatch(name)
	if m == nil {
		return k, fmt.Errorf("%q is not the name of a tombstone", name)
	}
	switch {
	case m[1] != "":
		k.Scope = relaybind.ScopePair
		b, _ := hex.DecodeString(m[1])
		copy(k.Key[:], b)
		d, _ := hex.DecodeString(m[2])
		copy(k.Device[:], d)
	case m[3] != "":
		k.Scope = relaybind.ScopeAll
		b, _ := hex.DecodeString(m[3])
		copy(k.Key[:], b)
	default:
		k.Scope = relaybind.ScopeDevice
		d, _ := hex.DecodeString(m[4])
		copy(k.Device[:], d)
	}
	return k, nil
}

// ---- encodings ----

const (
	recMagic    = "SPORB1\n"
	tombMagic   = "SPORT1\n"
	markerMagic = "SPORM1\n"
	ratesMagic  = "SPORR1\n"

	// maxRecordBytes is the largest binding record (as the directory store's):
	// magic, 8 bytes of last authentication, 1 of sender count, 64 senders of 28
	// bytes, two 2-byte lengths, a COSE_Sign1 of at most 512 bytes and a COSE_Key
	// of at most 128. A get asks for no more.
	maxRecordBytes = len(recMagic) + 8 + 1 + mailbox.MaxSenders*mailbox.WalletKeySize + 2 + relaybind.MaxSign1Bytes + 2 + relaybind.MaxKeyBytes
	// tombBytes is the size of every tombstone version: magic and 8 bytes of
	// not-before.
	tombBytes = len(tombMagic) + 8
	// markerBytes is the marker: magic and the relay's node public key, so a
	// marker names the identity it was written for.
	markerBytes = len(markerMagic) + 32
	// ratesBytes is the rate object: magic and, for the new-binding bucket and
	// then the revoke bucket, the units and the time (8 bytes each).
	ratesBytes = len(ratesMagic) + 4*8
)

// encodeRecord is a binding object: public bytes only.
func encodeRecord(r relayregistry.Record) []byte {
	out := make([]byte, 0, maxRecordBytes)
	out = append(out, recMagic...)
	out = binary.BigEndian.AppendUint64(out, uint64(r.LastAuth))
	out = append(out, byte(len(r.Senders)))
	for _, s := range r.Senders {
		out = append(out, s[:]...)
	}
	out = binary.BigEndian.AppendUint16(out, uint16(len(r.Sign1)))
	out = append(out, r.Sign1...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(r.COSEKey)))
	return append(out, r.COSEKey...)
}

// storedRecord is what a binding object holds, before verification.
type storedRecord struct {
	lastAuth  int64
	senders   []mailbox.WalletKey
	sendersOK bool // false: the list was not canonical and is dropped
	sign1     []byte
	coseKey   []byte
}

// decodeRecord reads a binding object strictly, as the directory store does:
// the magic, a last authentication in 0 to MaxTime, at most 64 senders, a
// COSE_Sign1 of 1 to 512 bytes and a COSE_Key of 1 to 128, and nothing after.
// Every length is checked against its bound before anything is taken for it;
// the input is at most maxRecordBytes. A sender list that is not strictly
// ascending is dropped (sendersOK false), not an error.
func decodeRecord(b []byte) (storedRecord, error) {
	var s storedRecord
	if len(b) > maxRecordBytes {
		return s, fmt.Errorf("a binding record of %d bytes; at most %d", len(b), maxRecordBytes)
	}
	r := b
	take := func(n int) ([]byte, bool) {
		if n < 0 || n > len(r) {
			return nil, false
		}
		out := r[:n]
		r = r[n:]
		return out, true
	}
	m, ok := take(len(recMagic))
	if !ok || string(m) != recMagic {
		return s, fmt.Errorf("not a binding record (bad magic)")
	}
	la, ok := take(8)
	if !ok {
		return s, fmt.Errorf("truncated before the last authentication")
	}
	v := binary.BigEndian.Uint64(la)
	if v > uint64(relaybind.MaxTime) {
		return s, fmt.Errorf("last authentication %d is out of range", v)
	}
	s.lastAuth = int64(v)
	nb, ok := take(1)
	if !ok || int(nb[0]) > mailbox.MaxSenders {
		return s, fmt.Errorf("sender count missing or over %d", mailbox.MaxSenders)
	}
	if len(r) < int(nb[0])*mailbox.WalletKeySize {
		return s, fmt.Errorf("truncated in the sender list")
	}
	s.senders = make([]mailbox.WalletKey, nb[0])
	for i := range s.senders {
		sb, _ := take(mailbox.WalletKeySize)
		copy(s.senders[i][:], sb)
	}
	canon, err := mailbox.CanonicalSenders(s.senders)
	s.sendersOK = err == nil && slices.Equal(canon, s.senders)
	if !s.sendersOK {
		s.senders = nil
	}
	readLen := func(max int, what string) ([]byte, error) {
		lb, ok := take(2)
		if !ok {
			return nil, fmt.Errorf("truncated before the %s length", what)
		}
		n := int(binary.BigEndian.Uint16(lb))
		if n < 1 || n > max {
			return nil, fmt.Errorf("%s of %d bytes; 1 to %d", what, n, max)
		}
		body, ok := take(n)
		if !ok {
			return nil, fmt.Errorf("truncated in the %s", what)
		}
		return bytes.Clone(body), nil
	}
	if s.sign1, err = readLen(relaybind.MaxSign1Bytes, "COSE_Sign1"); err != nil {
		return s, err
	}
	if s.coseKey, err = readLen(relaybind.MaxKeyBytes, "COSE_Key"); err != nil {
		return s, err
	}
	if len(r) != 0 {
		return s, fmt.Errorf("%d bytes after the record", len(r))
	}
	return s, nil
}

func encodeTomb(notBefore int64) []byte {
	out := make([]byte, 0, tombBytes)
	out = append(out, tombMagic...)
	return binary.BigEndian.AppendUint64(out, uint64(notBefore))
}

// decodeTomb reads one tombstone version: exactly 15 bytes, the magic and a
// not-before in 0 to MaxTime.
func decodeTomb(b []byte) (int64, error) {
	if len(b) != tombBytes || string(b[:len(tombMagic)]) != tombMagic {
		return 0, fmt.Errorf("not a tombstone record (%d bytes)", len(b))
	}
	v := binary.BigEndian.Uint64(b[len(tombMagic):])
	if v > uint64(relaybind.MaxTime) {
		return 0, fmt.Errorf("not-before %d is out of range", v)
	}
	return int64(v), nil
}

func encodeMarker(node [32]byte) []byte {
	return append([]byte(markerMagic), node[:]...)
}

// decodeMarker reads a marker and returns the node key it names.
func decodeMarker(b []byte) ([32]byte, error) {
	var k [32]byte
	if len(b) != markerBytes || string(b[:len(markerMagic)]) != markerMagic {
		return k, fmt.Errorf("not a marker (%d bytes)", len(b))
	}
	copy(k[:], b[len(markerMagic):])
	return k, nil
}

func encodeRates(s relayregistry.RateSnapshot) []byte {
	out := make([]byte, 0, ratesBytes)
	out = append(out, ratesMagic...)
	for _, v := range []int64{s.NewBindings.Units, s.NewBindings.At, s.Revokes.Units, s.Revokes.At} {
		out = binary.BigEndian.AppendUint64(out, uint64(v))
	}
	return out
}

// decodeRates reads the rate object: exactly 39 bytes, each value at most
// MaxTime (the core checks the units and times against their own bounds).
func decodeRates(b []byte) (relayregistry.RateSnapshot, error) {
	var s relayregistry.RateSnapshot
	if len(b) != ratesBytes || string(b[:len(ratesMagic)]) != ratesMagic {
		return s, fmt.Errorf("not a rate object (%d bytes)", len(b))
	}
	var v [4]int64
	for i := range v {
		u := binary.BigEndian.Uint64(b[len(ratesMagic)+8*i:])
		if u > uint64(relaybind.MaxTime) {
			return s, fmt.Errorf("a rate value %d is out of range", u)
		}
		v[i] = int64(u)
	}
	s.NewBindings = relayregistry.RateState{Units: v[0], At: v[1]}
	s.Revokes = relayregistry.RateState{Units: v[2], At: v[3]}
	return s, nil
}
