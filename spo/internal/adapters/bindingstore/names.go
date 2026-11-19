//go:build unix

package bindingstore

import (
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

// The layout of the directory (ADR 0014 decision 7, work package 5):
//
//	<root>/.spo-registry.lock
//	<root>/bindings/<device fingerprint, 40 hex>             one record per bound device
//	<root>/tombstones/p-<K, 56 hex>-<device, 40 hex>         scope pair
//	<root>/tombstones/a-<K, 56 hex>                          scope all
//	<root>/tombstones/d-<device, 40 hex>                     scope device
//	<root>/quarantine/<device, 40 hex>-<16 hex>              a binding that failed verification at load
//
// A binding is named by its device, so one binding per device holds on disk: a
// replacement is one atomic rename over the name. A tombstone is named by its
// scope and what the scope uses; a raise is one rename over the name. Temporary
// files are .tmp-<16 hex> in the directory they are made in.
const (
	lockName      = ".spo-registry.lock"
	bindingsDir   = "bindings"
	tombstonesDir = "tombstones"
	quarantineDir = "quarantine"
	tmpPrefix     = ".tmp-"
)

var (
	deviceRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
	tombRE   = regexp.MustCompile(`^(?:p-([0-9a-f]{56})-([0-9a-f]{40})|a-([0-9a-f]{56})|d-([0-9a-f]{40}))$`)
	tmpRE    = regexp.MustCompile(`^\.tmp-[0-9a-f]{16}$`)
	quarRE   = regexp.MustCompile(`^[0-9a-f]{40}-[0-9a-f]{16}$`)
)

func deviceName(d party.Fingerprint) string { return hex.EncodeToString(d[:]) }

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

// ---- file formats ----

const (
	recMagic  = "SPORB1\n"
	tombMagic = "SPORT1\n"

	// maxRecordBytes is the largest binding record: magic, 8 bytes of last
	// authentication, 1 of sender count, 64 senders of 28 bytes, two 2-byte
	// lengths, a COSE_Sign1 of at most 512 bytes and a COSE_Key of at most 128. A
	// file larger than this is refused on its size, before it is read.
	maxRecordBytes = len(recMagic) + 8 + 1 + mailbox.MaxSenders*mailbox.WalletKeySize + 2 + relaybind.MaxSign1Bytes + 2 + relaybind.MaxKeyBytes
	// tombBytes is the size of every tombstone file: magic and 8 bytes of
	// not-before.
	tombBytes = len(tombMagic) + 8
)

// encodeRecord is the file of a binding: public bytes only.
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

// storedRecord is what a binding file holds, before verification.
type storedRecord struct {
	lastAuth  int64
	senders   []mailbox.WalletKey
	sendersOK bool // false: the list was not canonical and is dropped
	sign1     []byte
	coseKey   []byte
}

// decodeRecord reads a binding file strictly: the magic, a last authentication in
// 0 to MaxTime, at most 64 senders, a COSE_Sign1 of 1 to 512 bytes and a COSE_Key
// of 1 to 128, and nothing after. Every length is checked against its bound
// before anything is taken for it. A sender list that is not strictly ascending
// is not an error: it is dropped (sendersOK false), so the device falls back to
// the stranger allowance.
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
	s.senders = make([]mailbox.WalletKey, nb[0])
	for i := range s.senders {
		sb, ok := take(mailbox.WalletKeySize)
		if !ok {
			return s, fmt.Errorf("truncated in the sender list")
		}
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
		return append([]byte(nil), body...), nil
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

func decodeTomb(b []byte) (int64, error) {
	if len(b) != tombBytes || string(b[:len(tombMagic)]) != tombMagic {
		return 0, fmt.Errorf("not a tombstone record")
	}
	v := binary.BigEndian.Uint64(b[len(tombMagic):])
	if v > uint64(relaybind.MaxTime) {
		return 0, fmt.Errorf("not-before %d is out of range", v)
	}
	return int64(v), nil
}
