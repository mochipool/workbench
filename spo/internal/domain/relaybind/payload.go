package relaybind

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"strconv"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// Binding is the payload of ADR 0014 decision 3: this device uses the wallet
// key that signs it as its mailbox address, from From until Until (unix
// seconds).
//
//	spo-relay-binding-v1 device <40 hex> from <unix seconds> until <unix seconds>
type Binding struct {
	Device party.Fingerprint
	From   int64
	Until  int64
}

// Render is the one line of lower-case ASCII, single spaces, no line feed. It
// refuses what ParseBinding refuses, so a client cannot build a payload the
// relay would not accept.
func (b Binding) Render() ([]byte, error) {
	if b.From < 0 || b.Until > MaxTime || b.Until < 0 || b.From > MaxTime {
		return nil, fmt.Errorf("%w: binding times %d and %d are not 0 to %d", ErrRange, b.From, b.Until, MaxTime)
	}
	if err := checkLifetime(b.From, b.Until, MaxLifetimeSeconds); err != nil {
		return nil, err
	}
	return b.render(), nil
}

func (b Binding) render() []byte {
	out := make([]byte, 0, 112)
	out = append(out, BindingLabel...)
	out = append(out, " device "...)
	out = appendHex(out, b.Device[:])
	out = append(out, " from "...)
	out = strconv.AppendInt(out, b.From, 10)
	out = append(out, " until "...)
	return strconv.AppendInt(out, b.Until, 10)
}

// checkLifetime requires MinLifetimeSeconds <= until - from <= max. Both times
// are within 0 to MaxTime, so the difference cannot overflow.
//
// A lifetime outside the ADR's bounds (MinLifetimeSeconds to
// MaxLifetimeSeconds) is ErrLifetime. One within them but over a tightened max
// is ErrLifetimePolicy, which also is ErrLifetime.
func checkLifetime(from, until, max int64) error {
	d := until - from
	if d < MinLifetimeSeconds || d > MaxLifetimeSeconds {
		return fmt.Errorf("%w: %d seconds, want %d to %d", ErrLifetime, d, MinLifetimeSeconds, MaxLifetimeSeconds)
	}
	if d > max {
		return fmt.Errorf("%w: %w: %d seconds, this relay's maximum is %d", ErrLifetimePolicy, ErrLifetime, d, max)
	}
	return nil
}

// ParseBinding accepts only the byte-exact canonical rendering of a binding
// whose times are in range and whose lifetime is within the ADR's bounds: it
// parses, re-renders and compares. A payload that is not canonical is
// ErrPayloadNotCanonical; one that is but has a lifetime out of range is
// ErrLifetime.
func ParseBinding(p []byte) (Binding, error) {
	b, err := parseBindingText(p)
	if err != nil {
		return Binding{}, err
	}
	if err := checkLifetime(b.From, b.Until, MaxLifetimeSeconds); err != nil {
		return Binding{}, err
	}
	return b, nil
}

// parseBindingText is the syntax and the time range, without the lifetime.
func parseBindingText(p []byte) (Binding, error) {
	f, ok := fields(p, 7)
	if !ok || f[0] != BindingLabel || f[1] != "device" || f[3] != "from" || f[5] != "until" {
		return Binding{}, notCanonical("not a binding line")
	}
	var b Binding
	var okd, okf, oku bool
	b.Device, okd = parseFingerprint(f[2])
	b.From, okf = parseTime(f[4])
	b.Until, oku = parseTime(f[6])
	if !okd || !okf || !oku {
		return Binding{}, notCanonical("device or times are not in canonical form")
	}
	if !bytes.Equal(b.render(), p) {
		return Binding{}, notCanonical("does not re-render to itself")
	}
	return b, nil
}

// Revoke is the payload of a wallet-signed revoke (ADR 0014 decision 7): it
// names one device of the signing key, or all of them (All), and the time
// before which bindings are revoked.
//
//	spo-relay-revoke-v1 device <40 hex or all> not-before <unix seconds>
type Revoke struct {
	All       bool
	Device    party.Fingerprint // zero when All
	NotBefore int64
}

// Render is the one line. All with a device is refused.
func (r Revoke) Render() ([]byte, error) {
	if r.NotBefore < 0 || r.NotBefore > MaxTime {
		return nil, fmt.Errorf("%w: not-before %d is not 0 to %d", ErrRange, r.NotBefore, MaxTime)
	}
	if r.All && r.Device != (party.Fingerprint{}) {
		return nil, fmt.Errorf("%w: a revoke of all devices names no device", ErrRange)
	}
	return r.render(), nil
}

func (r Revoke) render() []byte {
	out := make([]byte, 0, 96)
	out = append(out, RevokeLabel...)
	out = append(out, " device "...)
	if r.All {
		out = append(out, "all"...)
	} else {
		out = appendHex(out, r.Device[:])
	}
	out = append(out, " not-before "...)
	return strconv.AppendInt(out, r.NotBefore, 10)
}

// ParseRevoke accepts only the byte-exact canonical rendering of a revoke.
func ParseRevoke(p []byte) (Revoke, error) {
	f, ok := fields(p, 5)
	if !ok || f[0] != RevokeLabel || f[1] != "device" || f[3] != "not-before" {
		return Revoke{}, notCanonical("not a revoke line")
	}
	var r Revoke
	var okt bool
	if f[2] == "all" {
		r.All = true
	} else if r.Device, ok = parseFingerprint(f[2]); !ok {
		return Revoke{}, notCanonical("device is neither 40 lower-case hex digits nor all")
	}
	if r.NotBefore, okt = parseTime(f[4]); !okt {
		return Revoke{}, notCanonical("not-before is not in canonical form")
	}
	if !bytes.Equal(r.render(), p) {
		return Revoke{}, notCanonical("does not re-render to itself")
	}
	return r, nil
}

// DeviceRevokeBytes are the bytes a device signs to revoke itself: the
// canonical CBOR array [DeviceRevokeLabel, device fingerprint, not-before], the
// label inside the array as the mailbox auth bytes have it. It starts with
// 0x83, which no ASCII payload does.
func DeviceRevokeBytes(device party.Fingerprint, notBefore int64) ([]byte, error) {
	if notBefore < 0 || notBefore > MaxTime {
		return nil, fmt.Errorf("%w: not-before %d is not 0 to %d", ErrRange, notBefore, MaxTime)
	}
	return identity.EncodeCanonical([]any{DeviceRevokeLabel, device[:], uint64(notBefore)})
}

// VerifyDeviceRevoke checks a device-signed revoke. The device is the
// fingerprint recomputed from the two keys, never one the sender names. pol is
// the relay's Policy (validated; only its skew is used here): not-before must
// not be beyond now plus the skew. A small-order or non-canonical Ed25519 key is
// refused (ErrWeakKey). It returns the revoked device. The revoke carries no
// wallet key, so its tombstone has scope ScopeDevice.
func VerifyDeviceRevoke(ed party.Ed25519Public, x party.X25519Public, notBefore int64, sig [64]byte, now int64, pol Policy) (VerifiedDeviceRevoke, error) {
	if err := pol.Validate(); err != nil {
		return VerifiedDeviceRevoke{}, err
	}
	if err := checkPublicKey(ed[:]); err != nil {
		return VerifiedDeviceRevoke{}, err
	}
	device := party.FingerprintOf(ed, x)
	msg, err := DeviceRevokeBytes(device, notBefore)
	if err != nil {
		return VerifiedDeviceRevoke{}, err
	}
	if futureNotBefore(notBefore, now, pol.Skew) {
		return VerifiedDeviceRevoke{}, ErrRevokeFuture
	}
	if !ed25519.Verify(ed[:], msg, sig[:]) {
		return VerifiedDeviceRevoke{}, ErrBadSignature
	}
	return VerifiedDeviceRevoke{ok: true, device: device, notBefore: notBefore}, nil
}

// futureNotBefore reports notBefore > now + skew without computing the sum
// (now may be anywhere in int64; notBefore is 0 to MaxTime and skew is small).
func futureNotBefore(notBefore, now, skew int64) bool { return notBefore-skew > now }

// IsReserved reports whether a payload starts with "spo-" or "spo/". The
// generic message-signing path refuses such a payload, before any hashing, so
// that only the typed statement methods can produce one (ADR 0014 decision 3).
func IsReserved(payload []byte) bool {
	return bytes.HasPrefix(payload, []byte("spo-")) || bytes.HasPrefix(payload, []byte("spo/"))
}

// --- text helpers -------------------------------------------------------

func notCanonical(why string) error { return fmt.Errorf("%w: %s", ErrPayloadNotCanonical, why) }

// fields splits a payload of at most MaxPayloadBytes on single spaces into
// exactly n fields. An empty field (a double space, a leading or trailing
// space) is kept, and the callers' checks and the re-render refuse it.
func fields(p []byte, n int) ([]string, bool) {
	if len(p) == 0 || len(p) > MaxPayloadBytes {
		return nil, false
	}
	f := strings.Split(string(p), " ")
	return f, len(f) == n
}

const hexDigits = "0123456789abcdef"

func appendHex(dst, src []byte) []byte {
	for _, c := range src {
		dst = append(dst, hexDigits[c>>4], hexDigits[c&15])
	}
	return dst
}

// parseFingerprint reads exactly 40 lower-case hex digits.
func parseFingerprint(s string) (party.Fingerprint, bool) {
	var fp party.Fingerprint
	if len(s) != 2*len(fp) {
		return fp, false
	}
	for i := range fp {
		hi, ok1 := hexVal(s[2*i])
		lo, ok2 := hexVal(s[2*i+1])
		if !ok1 || !ok2 {
			return party.Fingerprint{}, false
		}
		fp[i] = hi<<4 | lo
	}
	return fp, true
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	}
	return 0, false
}

// parseTime reads decimal digits only: no sign, no leading zero (except "0"
// itself), at most 12 digits, and a value no larger than MaxTime.
func parseTime(s string) (int64, bool) {
	if len(s) == 0 || len(s) > 12 || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	var n int64
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int64(s[i]-'0')
	}
	return n, n <= MaxTime
}
