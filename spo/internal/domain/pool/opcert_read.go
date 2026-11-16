package pool

import (
	"errors"
	"fmt"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// ErrBadOpCert means a file is not an operational certificate envelope.
var ErrBadOpCert = errors.New("malformed operational certificate")

// OpCert is the content of an operational certificate: the KES verification
// key, the issue counter, the KES start period, the cold key's signature
// and the cold verification key. Upstream reads the counter and the start
// period by hex offset (SPO-04e-MODE-003); this decodes the CBOR array
// structurally.
type OpCert struct {
	KesVKey   [32]byte
	Counter   uint64
	KesPeriod uint64 // the KES period the certificate starts in
	Signature [64]byte
	ColdVKey  [32]byte
}

// PoolID is the pool the certificate belongs to: the hash of its cold key
// (SPO-04e-MODE-004).
func (o OpCert) PoolID() (chain.PoolID, error) { return chain.PoolIDOf(o.ColdVKey[:]) }

// ParseOpCert reads a `NodeOperationalCertificate` text envelope:
// `[[kesVKey, counter, kesPeriod, signature], coldVKey]`.
//
// spec: SPO-04e-MODE-003, SPO-04e-MODE-004
func ParseOpCert(file []byte) (OpCert, error) {
	var oc OpCert
	e, err := ParseEnvelope(file)
	if err != nil || e.Type != TypeOpCert {
		return oc, ErrBadOpCert
	}
	raw, err := unhex(e.CborHex)
	if err != nil {
		return oc, ErrBadOpCert
	}
	bad := func(what string) (OpCert, error) { return OpCert{}, fmt.Errorf("%w: %s", ErrBadOpCert, what) }
	// array(2) of array(4)
	if len(raw) < 2 || raw[0] != 0x82 || raw[1] != 0x84 {
		return bad("not [[...4 items], key]")
	}
	rest := raw[2:]
	bytesN := func(n int, dst []byte) bool {
		major, l, r, err := readHead(rest)
		if err != nil || major != 2 || l != uint64(n) || len(r) < n {
			return false
		}
		copy(dst, r[:n])
		rest = r[n:]
		return true
	}
	uint64At := func(dst *uint64) bool {
		major, v, r, err := readHead(rest)
		if err != nil || major != 0 {
			return false
		}
		*dst, rest = v, r
		return true
	}
	if !bytesN(32, oc.KesVKey[:]) {
		return bad("KES verification key")
	}
	if !uint64At(&oc.Counter) {
		return bad("issue counter")
	}
	if !uint64At(&oc.KesPeriod) {
		return bad("KES period")
	}
	if !bytesN(64, oc.Signature[:]) {
		return bad("signature")
	}
	if !bytesN(32, oc.ColdVKey[:]) {
		return bad("cold verification key")
	}
	if len(rest) != 0 {
		return bad("trailing bytes")
	}
	return oc, nil
}

// KesWindow is where a certificate stands against the KES period of the
// tip (SPO-04e-INV-002, SPO-04e-INV-003, SPO-04e-OUT-001).
type KesWindow struct {
	CurrentPeriod uint64
	StartPeriod   uint64
	ExpirePeriod  uint64 // StartPeriod + maxKESEvolutions
	// InRange is true when StartPeriod <= CurrentPeriod < ExpirePeriod.
	InRange bool
	// NotYetValid is true when the certificate starts in a later period than
	// the tip's: out of range, but not expired.
	NotYetValid bool
	// Remaining is the time left when InRange; SinceExpiry the time since
	// expiry when the certificate has expired.
	Remaining   time.Duration
	SinceExpiry time.Duration
}

// CheckKesWindow computes the window for a certificate starting in period
// `start` at the tip `slot`. The expiry arithmetic is upstream's
// (`expireKESperiod * slotsPerKESPeriod * slotLength - tipSlot`, seconds),
// including its slotLength factor (SPO-04d-INV-001).
//
// spec: SPO-04e-INV-002, SPO-04e-INV-003, SPO-04e-OUT-001
func CheckKesWindow(g chain.Genesis, slot, start uint64) (KesWindow, error) {
	cur, err := KesPeriod(g, slot)
	if err != nil {
		return KesWindow{}, err
	}
	secs, err := slotSeconds(g)
	if err != nil {
		return KesWindow{}, err
	}
	w := KesWindow{CurrentPeriod: cur, StartPeriod: start, ExpirePeriod: start + g.MaxKESEvolutions}
	w.InRange = start <= cur && cur < w.ExpirePeriod
	w.NotYetValid = start > cur
	expireSlot := w.ExpirePeriod * g.SlotsPerKESPeriod * secs
	switch {
	case w.InRange:
		w.Remaining = time.Duration(expireSlot-slot) * time.Second
	case !w.NotYetValid && slot >= expireSlot:
		w.SinceExpiry = time.Duration(slot-expireSlot) * time.Second
	}
	return w, nil
}
