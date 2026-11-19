package relaybinding_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"math/rand"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/relaybinding"
	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relaywallet"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ---- fixtures ---------------------------------------------------------------

type clock struct{ t time.Time }

func (c clock) Now() time.Time { return c.t }

func at(unix int64) clock { return clock{time.Unix(unix, 0)} }

func seedOf(b byte) []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = b + byte(i)
	}
	return s
}

func devFP(b byte) (f party.Fingerprint) {
	for i := range f {
		f[i] = b + byte(i)
	}
	return f
}

// keyHolder is a wallet key: a real Ed25519 key, its identity and its WalletKey.
type keyHolder struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	k    [28]byte
	w    relaywallet.WalletKey
}

func newHolder(t testing.TB, seed byte, role custody.Role) keyHolder {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(seedOf(seed))
	pub := priv.Public().(ed25519.PublicKey)
	id, err := identity.KeyHashOf(pub)
	if err != nil {
		t.Fatal(err)
	}
	w, err := relaywallet.FromRef(custody.KeyRef{Role: role, Identity: id})
	if err != nil {
		t.Fatal(err)
	}
	return keyHolder{priv: priv, pub: pub, k: cose.Blake2b224(pub), w: w}
}

// ---- scripted signer ----------------------------------------------------------

// signer is a ports.RelayStatementSigner whose answers the test scripts; honest
// mimics the vault (bare key hash address, payload embedded, canonical).
type signer struct {
	binding func(relaywallet.WalletKey, relaybind.Binding) (ports.SignedMessage, error)
	revoke  func(relaywallet.WalletKey, relaybind.Revoke) (ports.SignedMessage, error)
	calls   int
}

func (*signer) Profile() custody.Profile { return custody.NewProfile("scripted") }

func (s *signer) SignRelayBinding(_ context.Context, k relaywallet.WalletKey, b relaybind.Binding) (ports.SignedMessage, error) {
	s.calls++
	return s.binding(k, b)
}

func (s *signer) SignRelayRevoke(_ context.Context, k relaywallet.WalletKey, r relaybind.Revoke) (ports.SignedMessage, error) {
	s.calls++
	return s.revoke(k, r)
}

func honestSign(h keyHolder, payload []byte) ports.SignedMessage {
	return build(stmt{h: h, payload: payload})
}

func honest(h keyHolder) *signer {
	return &signer{
		binding: func(_ relaywallet.WalletKey, b relaybind.Binding) (ports.SignedMessage, error) {
			p, err := b.Render()
			if err != nil {
				return ports.SignedMessage{}, err
			}
			return honestSign(h, p), nil
		},
		revoke: func(_ relaywallet.WalletKey, r relaybind.Revoke) (ports.SignedMessage, error) {
			p, err := r.Render()
			if err != nil {
				return ports.SignedMessage{}, err
			}
			return honestSign(h, p), nil
		},
	}
}

// ---- a statement builder with a knob for every hostile variation -----------------

func head(major byte, n int) []byte {
	m := major << 5
	switch {
	case n < 24:
		return []byte{m | byte(n)}
	case n < 256:
		return []byte{m | 24, byte(n)}
	}
	return []byte{m | 25, byte(n >> 8), byte(n)}
}
func bstr(b []byte) []byte { return append(head(2, len(b)), b...) }
func tstr(s string) []byte { return append(head(3, len(s)), s...) }
func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

type stmt struct {
	h         keyHolder          // supplies the key hash for the default address
	signWith  ed25519.PrivateKey // the key that signs; default h.priv
	coseKey   []byte             // default cose.EncodeKey(h.pub)
	address   []byte             // default the 28-byte key hash
	protected []byte             // default {1: -8, "address": address}
	unprot    []byte             // default {"hashed": false}
	payload   []byte
	hashed    bool   // sign and carry the blake2b-224 of the payload, flag true
	arrayHead []byte // default 0x84
	prefix    []byte // before the array, e.g. a tag
	suffix    []byte // after the array
	detached  bool   // payload item null
	sigBytes  []byte // override the signature
}

func build(s stmt) ports.SignedMessage {
	if s.signWith == nil {
		s.signWith = s.h.priv
	}
	if s.coseKey == nil {
		s.coseKey = cose.EncodeKey(s.h.pub)
	}
	if s.address == nil {
		s.address = s.h.k[:]
	}
	if s.protected == nil {
		s.protected = cose.ProtectedHeader(s.address)
	}
	if s.unprot == nil {
		s.unprot = cat(head(5, 1), tstr("hashed"), []byte{0xf4})
		if s.hashed {
			s.unprot = cat(head(5, 1), tstr("hashed"), []byte{0xf5})
		}
	}
	pay := s.payload
	if s.hashed {
		pay = cose.PayloadFor(s.payload, true)
	}
	sig := s.sigBytes
	if sig == nil {
		sig = ed25519.Sign(s.signWith, cose.SigStructure(s.protected, pay))
	}
	if s.arrayHead == nil {
		s.arrayHead = []byte{0x84}
	}
	item := bstr(pay)
	if s.detached {
		item = []byte{0xf6}
	}
	out := cat(s.prefix, s.arrayHead, bstr(s.protected), s.unprot, item, bstr(sig), s.suffix)
	return ports.SignedMessage{Sign1: out, Key: s.coseKey}
}

// ---- the service -----------------------------------------------------------------

const now0 int64 = 1800000000

func history(known bool, roles ...custody.Role) func(context.Context, identity.Ref) (custody.RoleHistory, bool, error) {
	return func(_ context.Context, id identity.Ref) (custody.RoleHistory, bool, error) {
		if !known {
			return custody.RoleHistory{}, false, nil
		}
		h, err := custody.NewRoleHistory(id, roles[0])
		for _, r := range roles[1:] {
			if err == nil {
				h, err = h.With(r)
			}
		}
		return h, true, err
	}
}

func svc(sg ports.RelayStatementSigner, c ports.Clock) relaybinding.Service {
	return relaybinding.Service{Signer: sg, Clock: c, History: history(true, custody.RolePayment)}
}

func verifyAsRelay(t *testing.T, r relaybinding.BindingResult, dev party.Fingerprint, now int64, pol relaybind.Policy) relaybind.VerifiedBinding {
	t.Helper()
	st, err := relaybind.ParseStatement(r.Statement)
	if err != nil {
		t.Fatalf("the statement does not parse: %v", err)
	}
	vkey, err := relaybind.ParseCOSEKey(r.COSEKey)
	if err != nil {
		t.Fatalf("the COSE key does not parse: %v", err)
	}
	vb, err := relaybind.VerifyBinding(st, vkey, dev, now, pol)
	if err != nil {
		t.Fatalf("the statement does not verify: %v", err)
	}
	return vb
}

// ---- tests -----------------------------------------------------------------------

// The use case with an honest signer: the statement verifies under relaybind for
// the device and the time, the payload is the canonical rendering of the binding
// the rule asked for (from = now - 60 s, until = from + 90 days), and the key
// hash, statement identity and full hash are those of the verified statement.
//
// spec: SPO-Xrelaybind-IF-001
func TestSignBindingDefaults(t *testing.T) {
	h := newHolder(t, 7, custody.RolePayment)
	sg := honest(h)
	res, err := svc(sg, at(now0)).SignBinding(context.Background(), h.w, devFP(0x30), 0, relaybind.NoTombstone)
	if err != nil {
		t.Fatal(err)
	}
	wantB := relaybind.Binding{Device: devFP(0x30), From: now0 - 60, Until: now0 - 60 + 90*86400}
	if res.Binding != wantB {
		t.Errorf("binding %+v, want %+v", res.Binding, wantB)
	}
	vb := verifyAsRelay(t, res, devFP(0x30), now0, relaybind.DefaultPolicy())
	if vb.Binding() != wantB || vb.Key() != relaybind.KeyHash(h.k) || res.WalletKey != relaybind.KeyHash(h.k) || res.WalletKey != h.w.KeyHash() {
		t.Errorf("verified %+v key %x", vb.Binding(), vb.Key())
	}
	if res.StatementID != vb.StatementID() || res.FullHash != vb.FullHash() {
		t.Error("the identifiers are not those of the verified statement")
	}
	payload, _ := wantB.Render()
	st, _ := relaybind.ParseStatement(res.Statement)
	if !bytes.Equal(st.Payload(), payload) {
		t.Errorf("payload %q", st.Payload())
	}
	if back, err := relaybind.ParseBinding(st.Payload()); err != nil || back != wantB {
		t.Errorf("the payload does not round-trip: %v %+v", err, back)
	}
	if sg.calls != 1 {
		t.Errorf("the signer was asked %d times", sg.calls)
	}
	// the results are copies: changing them does not change a second answer
	res.Statement[0] ^= 0xff
}

// A stake key signs too, and a custom lifetime is honoured.
//
// spec: SPO-Xrelaybind-IF-001
func TestSignBindingStakeKeyAndLifetime(t *testing.T) {
	h := newHolder(t, 9, custody.RoleStake)
	s := relaybinding.Service{Signer: honest(h), Clock: at(now0), History: history(true, custody.RoleStake)}
	res, err := s.SignBinding(context.Background(), h.w, devFP(1), 30*24*time.Hour, relaybind.NoTombstone)
	if err != nil {
		t.Fatal(err)
	}
	if res.Binding.Until-res.Binding.From != 30*86400 {
		t.Errorf("lifetime %d", res.Binding.Until-res.Binding.From)
	}
	verifyAsRelay(t, res, devFP(1), now0, relaybind.DefaultPolicy())
}

// Property: for random times, lifetimes, tombstones and devices, every statement
// the use case returns verifies under relaybind for the device and the time it
// was made at, its payload round-trips and the from/until are the rule's. A
// refusal is always one of the named errors.
//
// spec: SPO-Xrelaybind-IF-001, SPO-Xrelaybind-OUT-015
func TestEveryReturnedBindingVerifies(t *testing.T) {
	h := newHolder(t, 7, custody.RolePayment)
	rnd := rand.New(rand.NewSource(1))
	pol := relaybind.DefaultPolicy()
	ok, waits := 0, 0
	for i := 0; i < 400; i++ {
		now := rnd.Int63n(relaybind.MaxTime)
		last := int64(relaybind.NoTombstone)
		switch rnd.Intn(4) {
		case 3:
			last = now + relaybind.SkewSeconds - 1 + rnd.Int63n(3) // the edge: no wait, one second, two seconds
		case 0:
			last = now + rnd.Int63n(700) - 400 // around now: the wait window (never beyond skew + 1: that is refused)
		case 1:
			last = now - rnd.Int63n(1000000)
		}
		if last > relaybind.MaxTime || last < relaybind.NoTombstone {
			last = relaybind.NoTombstone
		}
		life := time.Duration(3600+rnd.Int63n(180*86400-3600)) * time.Second
		dev := devFP(byte(rnd.Intn(200)))
		res, err := svc(honest(h), at(now)).SignBinding(context.Background(), h.w, dev, life, last)
		var we *relaybinding.WaitError
		switch {
		case errors.As(err, &we):
			waits++
			_, wait, perr := relaybind.PlanFrom(now, last, pol.Skew)
			if perr != nil || we.Wait != time.Duration(wait)*time.Second || wait <= 0 {
				t.Fatalf("now %d last %d: wait %v, rule says %d (%v)", now, last, we.Wait, wait, perr)
			}
		case err != nil:
			if !errors.Is(err, relaybinding.ErrClock) {
				t.Fatalf("now %d last %d life %v: %v", now, last, life, err)
			}
		default:
			ok++
			vb := verifyAsRelay(t, res, dev, now, pol)
			from, wait, _ := relaybind.PlanFrom(now, last, pol.Skew)
			if wait != 0 || vb.Binding().From != from || vb.Binding().Until != from+int64(life/time.Second) {
				t.Fatalf("now %d last %d: %+v from %d wait %d", now, last, vb.Binding(), from, wait)
			}
			if back, err := relaybind.ParseBinding(mustPayload(t, res)); err != nil || back != vb.Binding() {
				t.Fatalf("round trip: %v", err)
			}
		}
	}
	if ok < 100 || waits < 5 {
		t.Errorf("the property did not exercise enough: %d signed, %d waits", ok, waits)
	}
}

func mustPayload(t *testing.T, r relaybinding.BindingResult) []byte {
	t.Helper()
	st, err := relaybind.ParseStatement(r.Statement)
	if err != nil {
		t.Fatal(err)
	}
	return st.Payload()
}

// The from and wait rule on a fake clock: from = max(now - 60, last + 1); the
// client waits exactly when from - skew > now, with the wait duration of the
// rule, and does not sign (and does not sleep) while it waits.
//
// spec: SPO-Xrelaybind-OUT-015, SPO-Xrelaybind-PRE-019
func TestFromAndWaitRule(t *testing.T) {
	h := newHolder(t, 7, custody.RolePayment)
	skew := relaybind.SkewSeconds
	cases := []struct {
		name     string
		last     int64
		wantFrom int64
		wait     int64
	}{
		{"no tombstone", relaybind.NoTombstone, now0 - 60, 0},
		{"old tombstone", now0 - 1000, now0 - 60, 0},
		{"tombstone just before the backdate", now0 - 62, now0 - 60, 0},
		{"tombstone at the backdate", now0 - 61, now0 - 60, 0},
		{"tombstone one second inside", now0 - 60, now0 - 59, 0},
		{"tombstone now", now0, now0 + 1, 0},
		{"tombstone at now + skew - 1", now0 + skew - 1, now0 + skew, 0},
		{"tombstone at now + skew", now0 + skew, now0 + skew + 1, 1},
		{"tombstone at now + skew + 1", now0 + skew + 1, now0 + skew + 2, 2},
		{"tombstone zero", 0, now0 - 60, 0},
	}
	for _, c := range cases {
		sg := honest(h)
		start := time.Now()
		res, err := svc(sg, at(now0)).SignBinding(context.Background(), h.w, devFP(5), 0, c.last)
		if c.wait > 0 {
			var we *relaybinding.WaitError
			if !errors.As(err, &we) || !errors.Is(err, relaybinding.ErrWait) {
				t.Errorf("%s: %v", c.name, err)
				continue
			}
			if we.Wait != time.Duration(c.wait)*time.Second || we.From != c.wantFrom {
				t.Errorf("%s: wait %v from %d, want %ds from %d", c.name, we.Wait, we.From, c.wait, c.wantFrom)
			}
			if sg.calls != 0 || res.Statement != nil {
				t.Errorf("%s: the wallet was asked to sign while waiting", c.name)
			}
			if time.Since(start) > 500*time.Millisecond {
				t.Errorf("%s: the use case slept", c.name)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if res.Binding.From != c.wantFrom {
			t.Errorf("%s: from %d, want %d", c.name, res.Binding.From, c.wantFrom)
		}
		verifyAsRelay(t, res, devFP(5), now0, relaybind.DefaultPolicy())
	}
	// with a tightened skew of 0 the wait starts one second after now
	pol := relaybind.Policy{Skew: 0, MaxLifetime: relaybind.MaxLifetimeSeconds}
	s := svc(honest(h), at(now0))
	s.Policy = pol
	if _, err := s.SignBinding(context.Background(), h.w, devFP(5), 0, now0-60); err != nil {
		t.Errorf("skew 0, tombstone now-60: %v", err)
	}
	var we *relaybinding.WaitError
	if _, err := s.SignBinding(context.Background(), h.w, devFP(5), 0, now0); !errors.As(err, &we) || we.Wait != time.Second {
		t.Errorf("skew 0, tombstone now: %v", err)
	}
}

// A tombstone more than skew + 1 s ahead of the clock can never be legitimate (a
// relay refuses a revoke dated beyond relay time plus the skew), so it is refused
// as ErrPolicy, not waited for: a far-future tombstone used to make the wait
// overflow a time.Duration into a negative one, and a caller that sleeps and
// retries would have looped without waiting. The edge is exact: now + skew + 1 is
// a wait of two seconds, now + skew + 2 is refused.
//
// spec: SPO-Xrelaybind-PRE-022
func TestAFarFutureTombstoneIsRefusedNotWaitedFor(t *testing.T) {
	h := newHolder(t, 7, custody.RolePayment)
	skew := relaybind.SkewSeconds
	ctx := context.Background()
	for name, last := range map[string]int64{
		"skew + 2 ahead":   now0 + skew + 2,
		"an hour ahead":    now0 + 3600,
		"a year ahead":     now0 + 365*86400,
		"the largest time": relaybind.MaxTime,
		"2.5e11 s ahead":   relaybind.MaxTime - 1000000, // the wanted wait overflowed a Duration
	} {
		sg := honest(h)
		_, err := svc(sg, at(now0)).SignBinding(ctx, h.w, devFP(5), 0, last)
		var we *relaybinding.WaitError
		if !errors.Is(err, relaybinding.ErrPolicy) || errors.As(err, &we) || sg.calls != 0 {
			t.Errorf("%s: %v (calls %d)", name, err, sg.calls)
		}
	}
	// the clock at 0 and the largest tombstone: the wanted wait is about 2.5e11 s
	if _, err := svc(honest(h), at(0)).SignBinding(ctx, h.w, devFP(5), 0, relaybind.MaxTime); !errors.Is(err, relaybinding.ErrPolicy) {
		t.Errorf("clock 0, tombstone at the largest time: %v", err)
	}
	// the edge: skew + 1 ahead still waits, two seconds
	var we *relaybinding.WaitError
	if _, err := svc(honest(h), at(now0)).SignBinding(ctx, h.w, devFP(5), 0, now0+skew+1); !errors.As(err, &we) || we.Wait != 2*time.Second || we.Wait <= 0 {
		t.Errorf("skew + 1 ahead: %v", err)
	}
	// a tightened skew moves the edge with it
	s := svc(honest(h), at(now0))
	s.Policy = relaybind.Policy{Skew: 10, MaxLifetime: relaybind.MaxLifetimeSeconds}
	if _, err := s.SignBinding(ctx, h.w, devFP(5), 0, now0+12); !errors.Is(err, relaybinding.ErrPolicy) {
		t.Errorf("skew 10, tombstone now + 12: %v", err)
	}
	if _, err := s.SignBinding(ctx, h.w, devFP(5), 0, now0+11); !errors.As(err, &we) {
		t.Errorf("skew 10, tombstone now + 11: %v", err)
	}
}

// The software path pins the protected-header bytes: the two keys in the other
// order verify at the relay (the bytes are signed), but the vault never writes
// them so, so a signer that does is not the signer asked for.
//
// spec: SPO-Xrelaybind-SEC-021
func TestSelfVerificationPinsTheProtectedHeaderBytes(t *testing.T) {
	h := newHolder(t, 7, custody.RolePayment)
	swapped := cat(head(5, 2), tstr("address"), bstr(h.k[:]), []byte{0x01, 0x27})
	if string(swapped) == string(cose.ProtectedHeader(h.k[:])) {
		t.Fatal("the swapped header is the standard one")
	}
	sg := honest(h)
	sg.binding = func(_ relaywallet.WalletKey, b relaybind.Binding) (ports.SignedMessage, error) {
		p, _ := b.Render()
		return build(stmt{h: h, payload: p, protected: swapped}), nil
	}
	sg.revoke = func(_ relaywallet.WalletKey, r relaybind.Revoke) (ports.SignedMessage, error) {
		p, _ := r.Render()
		return build(stmt{h: h, payload: p, protected: swapped}), nil
	}
	s := svc(sg, at(now0))
	if res, err := s.SignBinding(context.Background(), h.w, devFP(5), 0, relaybind.NoTombstone); !errors.Is(err, relaybinding.ErrSelfVerify) || res.Statement != nil {
		t.Errorf("a binding with the header keys in the other order: %v", err)
	}
	if res, err := s.SignWalletRevoke(context.Background(), h.w, relaybinding.RevokeTarget{All: true}, now0); !errors.Is(err, relaybinding.ErrSelfVerify) || res.Statement != nil {
		t.Errorf("a revoke with the header keys in the other order: %v", err)
	}
}

// The zero fingerprint is no device: a revoke that is not "all" and names it is
// refused before any signer is asked (and so is a binding to it).
//
// spec: SPO-Xrelaybind-PRE-023
func TestTheZeroDeviceIsRefusedBeforeSigning(t *testing.T) {
	h := newHolder(t, 7, custody.RolePayment)
	sg := honest(h)
	s := svc(sg, at(now0))
	ctx := context.Background()
	if _, err := s.SignWalletRevoke(ctx, h.w, relaybinding.RevokeTarget{Device: party.Fingerprint{}}, now0); !errors.Is(err, relaybinding.ErrPolicy) {
		t.Errorf("a revoke of the zero device: %v", err)
	}
	if _, err := s.SignBinding(ctx, h.w, party.Fingerprint{}, 0, relaybind.NoTombstone); !errors.Is(err, relaybinding.ErrPolicy) {
		t.Errorf("a binding to the zero device: %v", err)
	}
	if sg.calls != 0 {
		t.Errorf("the signer was asked %d times", sg.calls)
	}
	// "all" has no device and still signs; a real device signs
	if _, err := s.SignWalletRevoke(ctx, h.w, relaybinding.RevokeTarget{All: true}, now0); err != nil {
		t.Errorf("all: %v", err)
	}
	if _, err := s.SignWalletRevoke(ctx, h.w, relaybinding.RevokeTarget{Device: devFP(1)}, now0); err != nil {
		t.Errorf("a device: %v", err)
	}
}

// A clock or a tombstone outside the statement range is its own refusal and the
// signer is not asked: the clock before 1970, past year 9999, within a minute of
// the largest time; a tombstone below -1 or past the largest time.
//
// spec: SPO-Xrelaybind-PRE-020
func TestClockAndTombstoneOutOfRange(t *testing.T) {
	h := newHolder(t, 7, custody.RolePayment)
	for name, c := range map[string]clock{
		"before 1970":            at(-1),
		"far before":             {time.Date(1600, 1, 1, 0, 0, 0, 0, time.UTC)},
		"past year 9999":         at(relaybind.MaxTime + 1),
		"year 100000":            {time.Date(100000, 1, 1, 0, 0, 0, 0, time.UTC)},
		"no room before maxtime": at(relaybind.MaxTime - 100),
	} {
		sg := honest(h)
		res, err := svc(sg, c).SignBinding(context.Background(), h.w, devFP(1), 0, relaybind.NoTombstone)
		if !errors.Is(err, relaybinding.ErrClock) || sg.calls != 0 || res.Statement != nil {
			t.Errorf("%s: %v (calls %d)", name, err, sg.calls)
		}
	}
	for name, last := range map[string]int64{"below minus one": -2, "past the largest": relaybind.MaxTime + 1, "min int": -1 << 63} {
		sg := honest(h)
		_, err := svc(sg, at(now0)).SignBinding(context.Background(), h.w, devFP(1), 0, last)
		if !errors.Is(err, relaybinding.ErrPolicy) || sg.calls != 0 {
			t.Errorf("tombstone %s: %v", name, err)
		}
	}
}

// Lifetime and policy bounds: one hour to 180 days (or the policy's tighter
// maximum), whole seconds; zero is the 90 day default. Every refusal comes before
// the signer is asked.
//
// spec: SPO-Xrelaybind-PRE-018
func TestLifetimeAndPolicyBounds(t *testing.T) {
	h := newHolder(t, 7, custody.RolePayment)
	day := 24 * time.Hour
	type tc struct {
		name   string
		life   time.Duration
		pol    relaybind.Policy
		err    error // nil: signed
		secErr error // a second class that must also match
		want   int64 // lifetime seconds when signed
	}
	def := relaybind.DefaultPolicy()
	tight := relaybind.Policy{Skew: 60, MaxLifetime: 30 * 86400}
	for _, c := range []tc{
		{"default", 0, def, nil, nil, 90 * 86400},
		{"one hour", time.Hour, def, nil, nil, 3600},
		{"one second short", time.Hour - time.Second, def, relaybinding.ErrPolicy, relaybind.ErrLifetime, 0},
		{"negative", -time.Hour, def, relaybinding.ErrPolicy, nil, 0},
		{"180 days", 180 * day, def, nil, nil, 180 * 86400},
		{"one second over", 180*day + time.Second, def, relaybinding.ErrPolicy, relaybind.ErrLifetime, 0},
		{"a year", 365 * day, def, relaybinding.ErrPolicy, relaybind.ErrLifetime, 0},
		{"fraction of a second", 90*day + time.Millisecond, def, relaybinding.ErrPolicy, nil, 0},
		{"tight maximum ok", 30 * day, tight, nil, nil, 30 * 86400},
		{"over the tight maximum", 30*day + time.Second, tight, relaybinding.ErrPolicy, relaybind.ErrLifetimePolicy, 0},
		{"default under a tight maximum is the maximum", 0, tight, nil, nil, 30 * 86400},
		{"policy loosened lifetime", 10 * day, relaybind.Policy{Skew: 300, MaxLifetime: 365 * 86400}, relaybinding.ErrPolicy, relaybind.ErrRange, 0},
		{"policy loosened skew", 10 * day, relaybind.Policy{Skew: 301, MaxLifetime: 180 * 86400}, relaybinding.ErrPolicy, relaybind.ErrRange, 0},
		{"policy negative skew", 10 * day, relaybind.Policy{Skew: -1, MaxLifetime: 180 * 86400}, relaybinding.ErrPolicy, relaybind.ErrRange, 0},
	} {
		sg := honest(h)
		s := svc(sg, at(now0))
		s.Policy = c.pol
		res, err := s.SignBinding(context.Background(), h.w, devFP(1), c.life, relaybind.NoTombstone)
		if c.err == nil {
			if err != nil || res.Binding.Until-res.Binding.From != c.want {
				t.Errorf("%s: %v %+v", c.name, err, res.Binding)
			}
			continue
		}
		if !errors.Is(err, c.err) || (c.secErr != nil && !errors.Is(err, c.secErr)) || sg.calls != 0 || res.Statement != nil {
			t.Errorf("%s: %v (calls %d)", c.name, err, sg.calls)
		}
	}
	// a tightened policy is the policy the statement is verified under: a signer
	// that ignores it and signs a longer lifetime is caught
	sg := &signer{binding: func(_ relaywallet.WalletKey, b relaybind.Binding) (ports.SignedMessage, error) {
		b.Until = b.From + 40*86400
		p, _ := b.Render()
		return honestSign(h, p), nil
	}}
	s := svc(sg, at(now0))
	s.Policy = tight
	if _, err := s.SignBinding(context.Background(), h.w, devFP(1), 10*day, relaybind.NoTombstone); !errors.Is(err, relaybinding.ErrSelfVerify) {
		t.Errorf("a signer that lengthened the lifetime: %v", err)
	}
}

// The role of the key and its history are checked before the signer is asked:
// the zero wallet key, a history with a cold role (even one recorded after the
// key was a payment key), a history that cannot be read, and no history source.
// A history with any role outside payment and stake, or none, is refused
// (default-deny, fail closed); none passes only behind the explicit option.
//
// spec: SPO-Xrelaybind-SEC-012, SPO-Xrelaybind-SEC-013
func TestRoleAndHistoryAreRefusedBeforeSigning(t *testing.T) {
	h := newHolder(t, 7, custody.RolePayment)
	ctx := context.Background()
	call := func(w relaywallet.WalletKey, hist func(context.Context, identity.Ref) (custody.RoleHistory, bool, error)) (*signer, error) {
		sg := honest(h)
		s := svc(sg, at(now0))
		s.History = hist
		_, err := s.SignBinding(ctx, w, devFP(1), 0, relaybind.NoTombstone)
		return sg, err
	}
	// every role as a history: refused unless it is payment or stake (default-deny)
	for _, role := range custody.Roles() {
		sg, err := call(h.w, history(true, custody.RolePayment, role))
		switch {
		case role.IsCold():
			if !errors.Is(err, relaywallet.ErrColdHistory) || sg.calls != 0 {
				t.Errorf("history with %s: %v (calls %d)", role, err, sg.calls)
			}
		case role == custody.RolePayment || role == custody.RoleStake:
			if err != nil {
				t.Errorf("history with %s: %v", role, err)
			}
		default:
			if !errors.Is(err, relaywallet.ErrOtherRoleHistory) || sg.calls != 0 {
				t.Errorf("history with %s: %v (calls %d)", role, err, sg.calls)
			}
		}
	}
	// no history of the key: refused, nothing is asked of the signer
	if sg, err := call(h.w, history(false)); !errors.Is(err, relaywallet.ErrNoHistory) || sg.calls != 0 {
		t.Errorf("no history of the key: %v (calls %d)", err, sg.calls)
	}
	// ... unless the explicit option is set (reserved for device-only keys, work
	// package 4; nothing sets it today), and then everything else still refuses
	{
		sg := honest(h)
		s := svc(sg, at(now0))
		s.History = history(false)
		s.AllowUnknownHistory = true
		if _, err := s.SignBinding(ctx, h.w, devFP(1), 0, relaybind.NoTombstone); err != nil || sg.calls != 1 {
			t.Errorf("no history with the option: %v", err)
		}
		s.History = history(true, custody.RolePayment, custody.RoleDRep)
		if _, err := s.SignWalletRevoke(ctx, h.w, relaybinding.RevokeTarget{All: true}, now0); !errors.Is(err, relaywallet.ErrOtherRoleHistory) {
			t.Errorf("a known other-role history with the option: %v", err)
		}
	}
	boom := errors.New("unreadable")
	if sg, err := call(h.w, func(context.Context, identity.Ref) (custody.RoleHistory, bool, error) {
		return custody.RoleHistory{}, false, boom
	}); !errors.Is(err, relaywallet.ErrHistoryUnreadable) || sg.calls != 0 {
		t.Errorf("unreadable history: %v", err)
	}
	if sg, err := call(h.w, nil); !errors.Is(err, relaybinding.ErrNoHistory) || sg.calls != 0 {
		t.Errorf("no history source: %v", err)
	}
	if sg, err := call(relaywallet.WalletKey{}, history(true, custody.RolePayment)); !errors.Is(err, relaywallet.ErrRole) || sg.calls != 0 {
		t.Errorf("the zero wallet key: %v", err)
	}
	// the same for the revokes
	for _, hist := range []func(context.Context, identity.Ref) (custody.RoleHistory, bool, error){history(true, custody.RolePoolCold), nil} {
		sg := honest(h)
		s := svc(sg, at(now0))
		s.History = hist
		_, err := s.SignWalletRevoke(ctx, h.w, relaybinding.RevokeTarget{All: true}, now0)
		if err == nil || sg.calls != 0 {
			t.Errorf("a revoke with a refused history was signed: %v", err)
		}
	}
	// a missing signer or clock is a refusal, not a panic
	if _, err := (relaybinding.Service{History: history(false)}).SignBinding(ctx, h.w, devFP(1), 0, -1); err == nil {
		t.Error("no signer, no clock")
	}
}

// A signer that fails is ErrSigner (and keeps its own error), distinct from a
// signer that returns something that does not verify.
//
// spec: SPO-Xrelaybind-IF-001
func TestSignerFailureIsDistinct(t *testing.T) {
	h := newHolder(t, 7, custody.RolePayment)
	boom := errors.New("device on fire")
	sg := &signer{
		binding: func(relaywallet.WalletKey, relaybind.Binding) (ports.SignedMessage, error) {
			return ports.SignedMessage{}, boom
		},
		revoke: func(relaywallet.WalletKey, relaybind.Revoke) (ports.SignedMessage, error) {
			return ports.SignedMessage{}, boom
		},
	}
	s := svc(sg, at(now0))
	for name, run := range map[string]func() error{
		"binding": func() error { _, e := s.SignBinding(context.Background(), h.w, devFP(1), 0, -1); return e },
		"revoke": func() error {
			_, e := s.SignWalletRevoke(context.Background(), h.w, relaybinding.RevokeTarget{All: true}, now0)
			return e
		},
	} {
		err := run()
		if !errors.Is(err, relaybinding.ErrSigner) || !errors.Is(err, boom) || errors.Is(err, relaybinding.ErrSelfVerify) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// the hardware port answer passes through as itself
	sg.binding = func(relaywallet.WalletKey, relaybind.Binding) (ports.SignedMessage, error) {
		return ports.SignedMessage{}, ports.ErrRelayStatementUnsupported
	}
	if _, err := s.SignBinding(context.Background(), h.w, devFP(1), 0, -1); !errors.Is(err, ports.ErrRelayStatementUnsupported) {
		t.Errorf("unsupported: %v", err)
	}
}

// Self-verification: a signer that returns anything but exactly the statement
// asked for is an error and nothing is returned. Each case is something a
// hostile or broken signer could return that a lenient check would pass.
//
// spec: SPO-Xrelaybind-SEC-014
func TestBindingSelfVerificationCatchesAHostileSigner(t *testing.T) {
	h := newHolder(t, 7, custody.RolePayment)
	other := newHolder(t, 99, custody.RolePayment)
	smallOrder := make([]byte, 32)
	smallOrder[0] = 1 // the identity point
	enterprise := append([]byte{0x61}, h.k[:]...)
	baseAddr := append(append([]byte{0x01}, h.k[:]...), make([]byte, 28)...)
	script := append([]byte{0x71}, h.k[:]...)

	ask := relaybind.Binding{Device: devFP(0x30), From: now0 - 60, Until: now0 - 60 + 90*86400}
	good, _ := ask.Render()
	laterB := ask
	laterB.From++
	later, _ := laterB.Render()
	otherDevB := ask
	otherDevB.Device = devFP(0x31)
	otherDev, _ := otherDevB.Render()
	longB := ask
	longB.Until = ask.From + 30*86400
	shorter, _ := longB.Render()
	rev, _ := relaybind.Revoke{All: true, NotBefore: now0}.Render()
	goodSM := build(stmt{h: h, payload: good})

	flip := func(b []byte, i int) []byte {
		out := bytes.Clone(b)
		out[i] ^= 1
		return out
	}
	cases := map[string]ports.SignedMessage{
		"signature of another key under the wallet key":   build(stmt{h: h, signWith: other.priv, payload: good}),
		"another key signs everything, its own cose key":  build(stmt{h: other, payload: good}),
		"another key with the wallet key's address":       build(stmt{h: other, address: h.k[:], payload: good}),
		"another key, wallet cose key and address":        build(stmt{h: h, signWith: other.priv, address: other.k[:], payload: good}),
		"a different binding (from + 1)":                  build(stmt{h: h, payload: later}),
		"a shorter lifetime":                              build(stmt{h: h, payload: shorter}),
		"a binding for another device":                    build(stmt{h: h, payload: otherDev}),
		"a revoke instead of the binding":                 build(stmt{h: h, payload: rev}),
		"an extra protected header key":                   build(stmt{h: h, protected: cat(head(5, 3), []byte{0x01, 0x27}, tstr("address"), bstr(h.k[:]), tstr("extra"), []byte{0x01})}),
		"protected header with hashed":                    build(stmt{h: h, protected: cat(head(5, 3), []byte{0x01, 0x27}, tstr("address"), bstr(h.k[:]), tstr("hashed"), []byte{0xf4})}),
		"a tagged envelope (tag 18)":                      build(stmt{h: h, payload: good, prefix: []byte{0xd2}}),
		"a hashed payload":                                build(stmt{h: h, payload: good, hashed: true}),
		"hashed flag true, payload embedded":              build(stmt{h: h, payload: good, unprot: cat(head(5, 1), tstr("hashed"), []byte{0xf5})}),
		"a detached payload":                              build(stmt{h: h, payload: good, detached: true}),
		"a non-shortest array head":                       build(stmt{h: h, payload: good, arrayHead: []byte{0x98, 0x04}}),
		"an indefinite array":                             build(stmt{h: h, payload: good, arrayHead: []byte{0x9f}, suffix: []byte{0xff}}),
		"a byte after the structure":                      build(stmt{h: h, payload: good, suffix: []byte{0x00}}),
		"an enterprise address with the wallet key":       build(stmt{h: h, payload: good, address: enterprise}),
		"a base address with the wallet key":              build(stmt{h: h, payload: good, address: baseAddr}),
		"a script credential address":                     build(stmt{h: h, payload: good, address: script}),
		"another key hash as the address":                 build(stmt{h: h, payload: good, address: other.k[:]}),
		"an unprotected header of another form":           build(stmt{h: h, payload: good, unprot: cat(head(5, 0))}),
		"an unprotected header with an extra key":         build(stmt{h: h, payload: good, unprot: cat(head(5, 2), tstr("hashed"), []byte{0xf4}, tstr("x"), []byte{0xf4})}),
		"a small-order COSE key":                          {Sign1: goodSM.Sign1, Key: cose.EncodeKey(smallOrder)},
		"a COSE key of another key":                       {Sign1: goodSM.Sign1, Key: cose.EncodeKey(other.pub)},
		"a COSE key that does not parse":                  {Sign1: goodSM.Sign1, Key: []byte{0xa0}},
		"no COSE key":                                     {Sign1: goodSM.Sign1},
		"a COSE key with a trailing byte":                 {Sign1: goodSM.Sign1, Key: append(cose.EncodeKey(h.pub), 0)},
		"a flipped bit in the signature":                  {Sign1: flip(goodSM.Sign1, len(goodSM.Sign1)-1), Key: goodSM.Key},
		"a flipped bit in the payload":                    {Sign1: flip(goodSM.Sign1, len(goodSM.Sign1)-70), Key: goodSM.Key},
		"empty":                                           {},
		"garbage":                                         {Sign1: []byte("not cbor at all"), Key: goodSM.Key},
		"truncated":                                       {Sign1: goodSM.Sign1[:len(goodSM.Sign1)-3], Key: goodSM.Key},
		"the right statement, signature replaced by zero": build(stmt{h: h, payload: good, sigBytes: make([]byte, 64)}),
	}
	for name, sm := range cases {
		sg := &signer{binding: func(relaywallet.WalletKey, relaybind.Binding) (ports.SignedMessage, error) { return sm, nil }}
		res, err := svc(sg, at(now0)).SignBinding(context.Background(), h.w, devFP(0x30), 0, relaybind.NoTombstone)
		if !errors.Is(err, relaybinding.ErrSelfVerify) || errors.Is(err, relaybinding.ErrSigner) {
			t.Errorf("%s: %v", name, err)
		}
		if res.Statement != nil || res.COSEKey != nil || res.FullHash != ([32]byte{}) || res.StatementID != ([32]byte{}) || res.WalletKey != (relaybind.KeyHash{}) {
			t.Errorf("%s: something was returned: %+v", name, res)
		}
	}
	// and the one honest statement, built by the same builder, passes
	sg := &signer{binding: func(relaywallet.WalletKey, relaybind.Binding) (ports.SignedMessage, error) { return goodSM, nil }}
	if _, err := svc(sg, at(now0)).SignBinding(context.Background(), h.w, devFP(0x30), 0, relaybind.NoTombstone); err != nil {
		t.Errorf("the control statement is refused: %v", err)
	}
}

// The same for the wallet-signed revoke, and the revoke payload is exactly the
// one asked for.
//
// spec: SPO-Xrelaybind-IF-002, SPO-Xrelaybind-SEC-015
func TestSignWalletRevoke(t *testing.T) {
	ctx := context.Background()
	h := newHolder(t, 7, custody.RolePayment)
	for name, target := range map[string]relaybinding.RevokeTarget{
		"one device": {Device: devFP(0x30)},
		"all":        {All: true},
	} {
		res, err := svc(honest(h), at(now0)).SignWalletRevoke(ctx, h.w, target, now0-5)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want := relaybind.Revoke{All: target.All, Device: target.Device, NotBefore: now0 - 5}
		if res.Revoke != want || res.WalletKey != h.w.KeyHash() {
			t.Errorf("%s: %+v", name, res.Revoke)
		}
		st, err := relaybind.ParseStatement(res.Statement)
		if err != nil {
			t.Fatal(err)
		}
		vkey, _ := relaybind.ParseCOSEKey(res.COSEKey)
		vr, err := relaybind.VerifyRevoke(st, vkey, now0, relaybind.DefaultPolicy())
		if err != nil || vr.Revoke() != want || vr.StatementID() != res.StatementID || vr.FullHash() != res.FullHash {
			t.Errorf("%s: %v", name, err)
		}
		if p, _ := want.Render(); !bytes.Equal(st.Payload(), p) {
			t.Errorf("%s: payload %q", name, st.Payload())
		}
	}
	// a not-before up to now + skew is signed, one second more is refused before the signer
	sg := honest(h)
	if _, err := svc(sg, at(now0)).SignWalletRevoke(ctx, h.w, relaybinding.RevokeTarget{All: true}, now0+relaybind.SkewSeconds); err != nil {
		t.Errorf("not-before at now + skew: %v", err)
	}
	calls := sg.calls
	for name, nb := range map[string]int64{"beyond skew": now0 + relaybind.SkewSeconds + 1, "negative": -1, "past max": relaybind.MaxTime + 1} {
		if _, err := svc(sg, at(now0)).SignWalletRevoke(ctx, h.w, relaybinding.RevokeTarget{All: true}, nb); !errors.Is(err, relaybinding.ErrPolicy) || sg.calls != calls {
			t.Errorf("%s: %v", name, err)
		}
	}
	// "all" with a device is refused
	if _, err := svc(sg, at(now0)).SignWalletRevoke(ctx, h.w, relaybinding.RevokeTarget{All: true, Device: devFP(1)}, now0); !errors.Is(err, relaybinding.ErrPolicy) || sg.calls != calls {
		t.Errorf("all with a device: %v", err)
	}
	if _, err := svc(sg, at(relaybind.MaxTime+5)).SignWalletRevoke(ctx, h.w, relaybinding.RevokeTarget{All: true}, now0); !errors.Is(err, relaybinding.ErrClock) {
		t.Errorf("clock past 9999: %v", err)
	}

	// hostile signers
	other := newHolder(t, 99, custody.RolePayment)
	ask := relaybind.Revoke{Device: devFP(0x30), NotBefore: now0}
	good, _ := ask.Render()
	allP, _ := relaybind.Revoke{All: true, NotBefore: now0}.Render()
	laterP, _ := relaybind.Revoke{Device: devFP(0x30), NotBefore: now0 + 1}.Render()
	otherDevP, _ := relaybind.Revoke{Device: devFP(0x31), NotBefore: now0}.Render()
	bind, _ := relaybind.Binding{Device: devFP(0x30), From: 0, Until: relaybind.MinLifetimeSeconds}.Render()
	cases := map[string]ports.SignedMessage{
		"another key":                   build(stmt{h: other, payload: good}),
		"signature of another key":      build(stmt{h: h, signWith: other.priv, payload: good}),
		"all instead of one device":     build(stmt{h: h, payload: allP}),
		"a later not-before":            build(stmt{h: h, payload: laterP}),
		"another device":                build(stmt{h: h, payload: otherDevP}),
		"a binding instead of a revoke": build(stmt{h: h, payload: bind}),
		"a tagged envelope":             build(stmt{h: h, payload: good, prefix: []byte{0xd2}}),
		"a hashed payload":              build(stmt{h: h, payload: good, hashed: true}),
		"an enterprise address":         build(stmt{h: h, payload: good, address: append([]byte{0x61}, h.k[:]...)}),
		"an extra protected key":        build(stmt{h: h, protected: cat(head(5, 3), []byte{0x01, 0x27}, tstr("address"), bstr(h.k[:]), tstr("x"), []byte{0x01})}),
		"a non-canonical array head":    build(stmt{h: h, payload: good, arrayHead: []byte{0x98, 0x04}}),
		"empty":                         {},
	}
	for name, sm := range cases {
		sg := &signer{revoke: func(relaywallet.WalletKey, relaybind.Revoke) (ports.SignedMessage, error) { return sm, nil }}
		res, err := svc(sg, at(now0)).SignWalletRevoke(ctx, h.w, relaybinding.RevokeTarget{Device: devFP(0x30)}, now0)
		if !errors.Is(err, relaybinding.ErrSelfVerify) || res.Statement != nil || res.COSEKey != nil || res.FullHash != ([32]byte{}) {
			t.Errorf("revoke, %s: %v %+v", name, err, res)
		}
	}
}

// ---- the device-signed revoke ------------------------------------------------------

type deviceSigner struct {
	id    party.Identity
	sign  func(nb int64) ([64]byte, error)
	calls int
	bound int64 // the notBeforeBound of the last call
}

func (d *deviceSigner) Identity() party.Identity { return d.id }
func (d *deviceSigner) SignRelayDeviceRevoke(nb, bound int64) ([64]byte, error) {
	d.calls++
	d.bound = bound
	return d.sign(nb)
}

func newDevice(seed byte) (ed25519.PrivateKey, party.Identity) {
	priv := ed25519.NewKeyFromSeed(seedOf(seed))
	var id party.Identity
	copy(id.Ed25519[:], priv.Public().(ed25519.PublicKey))
	copy(id.X25519[:], seedOf(seed+50))
	return priv, id
}

func signDevice(priv ed25519.PrivateKey, fpr party.Fingerprint, nb int64) [64]byte {
	msg, _ := relaybind.DeviceRevokeBytes(fpr, nb)
	var s [64]byte
	copy(s[:], ed25519.Sign(priv, msg))
	return s
}

// The device-signed revoke: the use case asks the typed method, verifies the
// signature with relaybind and returns what the Revoke frame carries. Anything
// the signer returns that does not verify for this device and not-before is an
// error and nothing is returned.
//
// spec: SPO-Xrelaybind-SEC-015, SPO-Xrelaybind-IF-003
func TestSignDeviceRevoke(t *testing.T) {
	ctx := context.Background()
	priv, id := newDevice(11)
	otherPriv, otherID := newDevice(12)
	fpr := id.Fingerprint()
	good := &deviceSigner{id: id, sign: func(nb int64) ([64]byte, error) { return signDevice(priv, fpr, nb), nil }}
	s := svc(honest(newHolder(t, 1, custody.RolePayment)), at(now0))
	res, err := s.SignDeviceRevoke(ctx, good, now0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Device != fpr || res.NotBefore != now0 || res.Ed25519 != id.Ed25519 || res.X25519 != id.X25519 {
		t.Errorf("result %+v", res)
	}
	if got, err := relaybind.VerifyDeviceRevoke(res.Ed25519, res.X25519, res.NotBefore, res.Signature, now0, relaybind.DefaultPolicy()); err != nil || got.Device() != fpr {
		t.Errorf("the result does not verify: %v", err)
	}
	// a not-before up to now + skew is fine, and the signer is told that bound
	if _, err := s.SignDeviceRevoke(ctx, good, now0+relaybind.SkewSeconds); err != nil {
		t.Errorf("at now + skew: %v", err)
	}
	if good.bound != now0+relaybind.SkewSeconds {
		t.Errorf("the bound given to the signer is %d, want now + skew %d", good.bound, now0+relaybind.SkewSeconds)
	}
	tightBound := svc(honest(newHolder(t, 1, custody.RolePayment)), at(now0))
	tightBound.Policy = relaybind.Policy{Skew: 10, MaxLifetime: relaybind.MaxLifetimeSeconds}
	if _, err := tightBound.SignDeviceRevoke(ctx, good, now0); err != nil || good.bound != now0+10 {
		t.Errorf("a tightened skew: bound %d (%v), want %d", good.bound, err, now0+10)
	}

	hostile := map[string]func(nb int64) ([64]byte, error){
		"a signature by another key":         func(nb int64) ([64]byte, error) { return signDevice(otherPriv, fpr, nb), nil },
		"a signature for another not-before": func(nb int64) ([64]byte, error) { return signDevice(priv, fpr, nb+1), nil },
		"a signature for another device":     func(nb int64) ([64]byte, error) { return signDevice(priv, otherID.Fingerprint(), nb), nil },
		"the zero signature":                 func(int64) ([64]byte, error) { return [64]byte{}, nil },
		"a signature over the bytes without the label": func(nb int64) ([64]byte, error) {
			var s [64]byte
			copy(s[:], ed25519.Sign(priv, []byte("spo/relay-revoke-device/v1")))
			return s, nil
		},
	}
	for name, f := range hostile {
		d := &deviceSigner{id: id, sign: f}
		res, err := s.SignDeviceRevoke(ctx, d, now0)
		if !errors.Is(err, relaybinding.ErrSelfVerify) || res.Signature != ([64]byte{}) || res.Device != (party.Fingerprint{}) {
			t.Errorf("%s: %v %+v", name, err, res)
		}
	}
	// an identity whose Ed25519 key is the identity point verifies for every
	// message; it is refused as a weak key
	weak := party.Identity{X25519: id.X25519}
	weak.Ed25519[0] = 1
	wd := &deviceSigner{id: weak, sign: func(int64) ([64]byte, error) { var s [64]byte; s[0] = 1; return s, nil }}
	if _, err := s.SignDeviceRevoke(ctx, wd, now0); !errors.Is(err, relaybinding.ErrSelfVerify) || !errors.Is(err, relaybind.ErrWeakKey) {
		t.Errorf("a weak device key: %v", err)
	}
	// the signer fails
	boom := errors.New("locked")
	bd := &deviceSigner{id: id, sign: func(int64) ([64]byte, error) { return [64]byte{}, boom }}
	if _, err := s.SignDeviceRevoke(ctx, bd, now0); !errors.Is(err, relaybinding.ErrSigner) || !errors.Is(err, boom) {
		t.Errorf("signer failure: %v", err)
	}
	// refusals before the signer
	for name, c := range map[string]struct {
		nb  int64
		clk clock
		err error
	}{
		"beyond skew":    {now0 + relaybind.SkewSeconds + 1, at(now0), relaybinding.ErrPolicy},
		"negative":       {-1, at(now0), relaybinding.ErrPolicy},
		"past max":       {relaybind.MaxTime + 1, at(now0), relaybinding.ErrPolicy},
		"clock before":   {now0, at(-5), relaybinding.ErrClock},
		"clock past max": {now0, at(relaybind.MaxTime + 1), relaybinding.ErrClock},
	} {
		d := &deviceSigner{id: id, sign: good.sign}
		if _, err := svc(honest(newHolder(t, 1, custody.RolePayment)), c.clk).SignDeviceRevoke(ctx, d, c.nb); !errors.Is(err, c.err) || d.calls != 0 {
			t.Errorf("%s: %v (calls %d)", name, err, d.calls)
		}
	}
	// a tightened skew applies
	tight := svc(honest(newHolder(t, 1, custody.RolePayment)), at(now0))
	tight.Policy = relaybind.Policy{Skew: 10, MaxLifetime: relaybind.MaxLifetimeSeconds}
	if _, err := tight.SignDeviceRevoke(ctx, good, now0+11); !errors.Is(err, relaybinding.ErrPolicy) {
		t.Errorf("tightened skew: %v", err)
	}
	if _, err := tight.SignDeviceRevoke(ctx, good, now0+10); err != nil {
		t.Errorf("tightened skew, at the edge: %v", err)
	}
}
