package relaybinding_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/relaybinding"
	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relaywallet"
)

// extSvc is the use case for an external wallet: no signer, a clock, and a history
// source that does not know the key (it lives in the wallet).
func extSvc(now int64) relaybinding.Service {
	return relaybinding.Service{Clock: at(now), History: history(false)}
}

func extWallet(h keyHolder) relaybinding.ExternalWallet {
	return relaybinding.ExternalWallet{KeyHash: relaybind.KeyHash(h.k)}
}

func prepBinding(t *testing.T, h keyHolder, dev party.Fingerprint) relaybinding.Prepared {
	t.Helper()
	p, err := extSvc(now0).PrepareBinding(context.Background(), extWallet(h), dev, 0, relaybind.NoTombstone)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func addrs(h keyHolder) (enterprise, base, reward []byte) {
	enterprise = append([]byte{0x61}, h.k[:]...)
	base = append(append([]byte{0x01}, h.k[:]...), bytes.Repeat([]byte{9}, 28)...)
	reward = append([]byte{0xe1}, h.k[:]...)
	return
}

// What the wallet is given: the exact payload text, its hex, the address to sign
// for (the bare key hash when only a hash is given, else the address as given),
// no hashing, a ten-minute window and a binding hash.
//
// spec: SPO-Xrelaybind-IF-004
func TestPrepareBindingGivesTheExactParameters(t *testing.T) {
	h := newHolder(t, 21, custody.RolePayment)
	dev := devFP(0x33)
	p := prepBinding(t, h, dev)
	want, _ := relaybind.Binding{Device: dev, From: now0 - 60, Until: now0 - 60 + relaybind.DefaultLifetimeSeconds}.Render()
	if p.Kind != relaybinding.PreparedBindingKind || !bytes.Equal(p.Payload, want) || p.PayloadText() != string(want) || p.Hashed() {
		t.Errorf("prepared %+v", p)
	}
	if p.WalletKey != relaybind.KeyHash(h.k) || !bytes.Equal(p.SignFor, h.k[:]) {
		t.Error("the address to sign for is not the bare key hash")
	}
	if p.PreparedAt != now0 || p.ExpiresAt != now0+600 || p.ID == ([32]byte{}) {
		t.Errorf("window %d to %d, id %x", p.PreparedAt, p.ExpiresAt, p.ID)
	}
	ins := p.Instructions()
	for _, must := range []string{string(want), p.PayloadHex(), p.SignForHex(), "Do not hash", "10 minutes"} {
		if !strings.Contains(ins, must) {
			t.Errorf("the instructions lack %q:\n%s", must, ins)
		}
	}
	// by address: the address is what the wallet signs for
	ent, base, reward := addrs(h)
	for name, a := range map[string][]byte{"enterprise": ent, "base": base, "reward": reward} {
		pa, err := extSvc(now0).PrepareBinding(context.Background(), relaybinding.ExternalWallet{Address: a}, dev, 0, relaybind.NoTombstone)
		if err != nil || !bytes.Equal(pa.SignFor, a) || pa.WalletKey != relaybind.KeyHash(h.k) {
			t.Errorf("%s: %v %+v", name, err, pa)
		}
	}
}

// Prepare refuses before anything is printed: no key, both, an address relaybind
// refuses, the zero device, a lifetime out of bounds, a tombstone too far ahead,
// and a key the store knows in another role; a key in the wait window is a
// WaitError.
//
// spec: SPO-Xrelaybind-IF-004, SPO-Xrelaybind-PRE-018
func TestPrepareRefusals(t *testing.T) {
	h := newHolder(t, 21, custody.RolePayment)
	ctx := context.Background()
	s := extSvc(now0)
	ent, _, _ := addrs(h)
	pointer := append([]byte{0x41}, append(h.k[:], 1, 2, 3)...)
	script := append([]byte{0x71}, h.k[:]...)
	for name, w := range map[string]relaybinding.ExternalWallet{
		"nothing":      {},
		"both":         {KeyHash: relaybind.KeyHash(h.k), Address: ent},
		"a pointer":    {Address: pointer},
		"a script":     {Address: script},
		"network 3":    {Address: append([]byte{0x63}, h.k[:]...)},
		"a short hash": {Address: h.k[:27]},
	} {
		if _, err := s.PrepareBinding(ctx, w, devFP(1), 0, relaybind.NoTombstone); !errors.Is(err, relaybinding.ErrPolicy) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := s.PrepareBinding(ctx, extWallet(h), party.Fingerprint{}, 0, relaybind.NoTombstone); !errors.Is(err, relaybinding.ErrPolicy) {
		t.Errorf("the zero device: %v", err)
	}
	if _, err := s.PrepareBinding(ctx, extWallet(h), devFP(1), time.Minute, relaybind.NoTombstone); !errors.Is(err, relaybinding.ErrPolicy) {
		t.Errorf("a lifetime of a minute: %v", err)
	}
	if _, err := s.PrepareBinding(ctx, extWallet(h), devFP(1), 0, now0+3600); !errors.Is(err, relaybinding.ErrPolicy) {
		t.Errorf("a far tombstone: %v", err)
	}
	var we *relaybinding.WaitError
	if _, err := s.PrepareBinding(ctx, extWallet(h), devFP(1), 0, now0+relaybind.SkewSeconds); !errors.As(err, &we) {
		t.Errorf("the wait window: %v", err)
	}
	// the store knows the key in another role, or cannot say, or has no source
	for name, hist := range map[string]func(context.Context, identity.Ref) (custody.RoleHistory, bool, error){
		"drep": history(true, custody.RolePayment, custody.RoleDRep),
		"cold": history(true, custody.RolePoolCold),
		"unreadable": func(context.Context, identity.Ref) (custody.RoleHistory, bool, error) {
			return custody.RoleHistory{}, false, errors.New("x")
		},
	} {
		s2 := extSvc(now0)
		s2.History = hist
		if _, err := s2.PrepareBinding(ctx, extWallet(h), devFP(1), 0, relaybind.NoTombstone); err == nil {
			t.Errorf("%s: prepared", name)
		}
	}
	s3 := extSvc(now0)
	s3.History = nil
	if _, err := s3.PrepareBinding(ctx, extWallet(h), devFP(1), 0, relaybind.NoTombstone); !errors.Is(err, relaybinding.ErrNoHistory) {
		t.Errorf("no history source: %v", err)
	}
	// a key the store knows as payment and stake is fine
	s4 := extSvc(now0)
	s4.History = history(true, custody.RolePayment, custody.RoleStake)
	if _, err := s4.PrepareBinding(ctx, extWallet(h), devFP(1), 0, relaybind.NoTombstone); err != nil {
		t.Errorf("a payment and stake history: %v", err)
	}
}

// The import accepts what the wallet writes for each exact address form and
// reports the form, the key as unknown to the store, and the verified statement.
//
// spec: SPO-Xrelaybind-IF-004, SPO-Xrelaybind-SEC-023
func TestImportBindingAcceptsTheExactAddressForms(t *testing.T) {
	h := newHolder(t, 21, custody.RolePayment)
	dev := devFP(0x33)
	ent, base, reward := addrs(h)
	for name, tc := range map[string]struct {
		addr []byte
		part relaybind.AddressPart
	}{
		"key hash":   {h.k[:], relaybind.PartKeyHash},
		"enterprise": {ent, relaybind.PartEnterprise},
		"base":       {base, relaybind.PartBasePayment},
		"reward":     {reward, relaybind.PartReward},
	} {
		p, err := extSvc(now0).PrepareBinding(context.Background(), relaybinding.ExternalWallet{Address: tc.addr}, dev, 0, relaybind.NoTombstone)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		sm := build(stmt{h: h, payload: p.Payload, address: tc.addr})
		res, err := extSvc(now0+30).ImportBinding(context.Background(), p, sm.Sign1, sm.Key)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if res.AddressPart != tc.part || res.KnownToStore || res.WalletKey != relaybind.KeyHash(h.k) || res.Binding != p.Binding {
			t.Errorf("%s: %+v", name, res)
		}
		if !bytes.Equal(res.Statement, sm.Sign1) || !bytes.Equal(res.COSEKey, sm.Key) {
			t.Errorf("%s: the bytes are not the wallet's", name)
		}
		// verifies as the relay verifies it
		st, _ := relaybind.ParseStatement(res.Statement)
		vk, _ := relaybind.ParseCOSEKey(res.COSEKey)
		if vb, err := relaybind.VerifyBinding(st, vk, dev, now0+30, relaybind.DefaultPolicy()); err != nil || vb.StatementID() != res.StatementID || vb.FullHash() != res.FullHash {
			t.Errorf("%s: the relay: %v", name, err)
		}
	}
	// a key the store knows as payment is reported known
	p := prepBinding(t, h, dev)
	s := extSvc(now0)
	s.History = history(true, custody.RolePayment)
	sm := build(stmt{h: h, payload: p.Payload})
	if res, err := s.ImportBinding(context.Background(), p, sm.Sign1, sm.Key); err != nil || !res.KnownToStore {
		t.Errorf("a known key: %v %+v", err, res)
	}
}

// Hostile wallet answers: each is refused with ErrImport and nothing is returned.
//
// spec: SPO-Xrelaybind-SEC-023
func TestImportBindingRefusesHostileAnswers(t *testing.T) {
	h := newHolder(t, 21, custody.RolePayment)
	other := newHolder(t, 22, custody.RolePayment)
	dev := devFP(0x33)
	p := prepBinding(t, h, dev)
	render := func(b relaybind.Binding) []byte {
		x, err := b.Render()
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	b := p.Binding
	_, base, _ := addrs(h)
	// the key only as the STAKE part of a base address
	stakeOnly := append(append([]byte{0x01}, bytes.Repeat([]byte{9}, 28)...), h.k[:]...)
	script := append([]byte{0x71}, h.k[:]...)
	cases := map[string]stmt{
		"another payload (later from)":   {h: h, payload: render(relaybind.Binding{Device: dev, From: b.From + 1, Until: b.Until})},
		"another payload (until)":        {h: h, payload: render(relaybind.Binding{Device: dev, From: b.From, Until: b.Until - 1})},
		"another device":                 {h: h, payload: render(relaybind.Binding{Device: devFP(0x44), From: b.From, Until: b.Until})},
		"another time (a month later)":   {h: h, payload: render(relaybind.Binding{Device: dev, From: b.From + 30*86400, Until: b.Until + 30*86400})},
		"a revoke instead":               {h: h, payload: []byte("spo-relay-revoke-v1 device all not-before 5")},
		"another key signs the payload":  {h: other, payload: p.Payload},
		"another key, the right address": {h: other, payload: p.Payload, address: h.k[:]},
		"a hashed payload":               {h: h, payload: p.Payload, hashed: true},
		"a tagged envelope":              {h: h, payload: p.Payload, prefix: []byte{0xd2}},
		"a non-shortest head":            {h: h, payload: p.Payload, arrayHead: []byte{0x98, 0x04}},
		"a trailing byte":                {h: h, payload: p.Payload, suffix: []byte{0}},
		"a detached payload":             {h: h, payload: p.Payload, detached: true},
		"K as the stake part only":       {h: h, payload: p.Payload, address: stakeOnly},
		"a script credential address":    {h: h, payload: p.Payload, address: script},
		"a pointer address":              {h: h, payload: p.Payload, address: append([]byte{0x41}, append(h.k[:], 1, 2, 3)...)},
		"a base address of another key":  {h: h, payload: p.Payload, address: append(append([]byte{0x01}, other.k[:]...), h.k[:]...)},
		"an extra protected key":         {h: h, payload: p.Payload, protected: cat(head(5, 3), []byte{0x01, 0x27}, tstr("address"), bstr(h.k[:]), tstr("x"), []byte{1})},
		"another unprotected header":     {h: h, payload: p.Payload, unprot: cat(head(5, 0))},
		"a zero signature":               {h: h, payload: p.Payload, sigBytes: make([]byte, 64)},
	}
	_ = base
	for name, s := range cases {
		sm := build(s)
		res, err := extSvc(now0).ImportBinding(context.Background(), p, sm.Sign1, sm.Key)
		if !errors.Is(err, relaybinding.ErrImport) || res.Statement != nil || res.COSEKey != nil || res.WalletKey != (relaybind.KeyHash{}) {
			t.Errorf("%s: %v %+v", name, err, res)
		}
	}
	// a COSE key of another key, a small-order key, no key, garbage
	good := build(stmt{h: h, payload: p.Payload})
	for name, sm := range map[string][2][]byte{
		"a COSE key of another key": {good.Sign1, cose.EncodeKey(other.pub)},
		"no COSE key":               {good.Sign1, nil},
		"garbage statement":         {[]byte("not cbor"), good.Key},
		"empty":                     {nil, nil},
		"a flipped bit":             {flip(good.Sign1, len(good.Sign1)-1), good.Key},
	} {
		if _, err := extSvc(now0).ImportBinding(context.Background(), p, sm[0], sm[1]); !errors.Is(err, relaybinding.ErrImport) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// the signature of the right key over a payload for the right device but a
	// different prepared request (another preparation of the same binding is a
	// different request: the answer to the first does not import against the second)
	p2, err := extSvc(now0+5).PrepareBinding(context.Background(), extWallet(h), dev, 0, relaybind.NoTombstone)
	if err != nil {
		t.Fatal(err)
	}
	if p2.ID == p.ID {
		t.Fatal("two preparations have one binding hash")
	}
	sm := build(stmt{h: h, payload: p.Payload})
	if _, err := extSvc(now0+5).ImportBinding(context.Background(), p2, sm.Sign1, sm.Key); !errors.Is(err, relaybinding.ErrImport) {
		t.Errorf("an answer to another preparation: %v", err)
	}
	// the honest answer imports
	if _, err := extSvc(now0).ImportBinding(context.Background(), p, good.Sign1, good.Key); err != nil {
		t.Errorf("the honest answer: %v", err)
	}
}

func flip(b []byte, i int) []byte {
	out := bytes.Clone(b)
	out[i] ^= 1
	return out
}

// A prepared request expires ten minutes after it was made, on the clock, and is
// bound by its hash: any change of its content, a hash from another request, a
// request of another kind and a clock before it are refused.
//
// spec: SPO-Xrelaybind-SEC-023
func TestPreparedRequestExpiresAndIsBoundByItsHash(t *testing.T) {
	h := newHolder(t, 21, custody.RolePayment)
	dev := devFP(0x33)
	p := prepBinding(t, h, dev)
	sm := build(stmt{h: h, payload: p.Payload})
	ctx := context.Background()
	for name, tc := range map[string]struct {
		now int64
		err error
	}{
		"at once":       {now0, nil},
		"at 600 s":      {now0 + 600, nil},
		"at 601 s":      {now0 + 601, relaybinding.ErrPreparedExpired},
		"a day later":   {now0 + 86400, relaybinding.ErrPreparedExpired},
		"before it":     {now0 - 1, relaybinding.ErrPrepared},
		"a year before": {now0 - 365*86400, relaybinding.ErrPrepared},
	} {
		_, err := extSvc(tc.now).ImportBinding(ctx, p, sm.Sign1, sm.Key)
		if (tc.err == nil) != (err == nil) || (tc.err != nil && !errors.Is(err, tc.err)) {
			t.Errorf("%s: %v", name, err)
		}
	}
	mut := map[string]func(q *relaybinding.Prepared){
		"a longer window":     func(q *relaybinding.Prepared) { q.ExpiresAt += 86400 },
		"an earlier start":    func(q *relaybinding.Prepared) { q.PreparedAt -= 1 },
		"another wallet key":  func(q *relaybinding.Prepared) { q.WalletKey[0] ^= 1 },
		"another address":     func(q *relaybinding.Prepared) { q.SignFor = append([]byte{0x61}, q.SignFor...) },
		"another payload":     func(q *relaybinding.Prepared) { q.Payload = append(bytes.Clone(q.Payload), ' ') },
		"another binding":     func(q *relaybinding.Prepared) { q.Binding.Until++ },
		"another kind":        func(q *relaybinding.Prepared) { q.Kind = relaybinding.PreparedRevokeKind },
		"the hash of another": func(q *relaybinding.Prepared) { q.ID = prepBinding(t, newHolder(t, 30, custody.RolePayment), dev).ID },
		"a zero hash":         func(q *relaybinding.Prepared) { q.ID = [32]byte{} },
		"a negative time":     func(q *relaybinding.Prepared) { q.PreparedAt = -1 },
	}
	for name, f := range mut {
		q := p
		q.SignFor = bytes.Clone(p.SignFor)
		f(&q)
		if _, err := extSvc(now0).ImportBinding(ctx, q, sm.Sign1, sm.Key); !errors.Is(err, relaybinding.ErrPrepared) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// a binding request is not imported as a revoke and the other way round
	if _, err := extSvc(now0).ImportRevoke(ctx, p, sm.Sign1, sm.Key); !errors.Is(err, relaybinding.ErrPrepared) {
		t.Errorf("a binding as a revoke: %v", err)
	}
	// consistent but forged: a payload and a hash recomputed by someone who edits the
	// struct for another device is still caught by the answer, which is not theirs
	q := p
	q.Binding.Device = devFP(0x77)
	if _, err := extSvc(now0).ImportBinding(ctx, q, sm.Sign1, sm.Key); !errors.Is(err, relaybinding.ErrPrepared) {
		t.Errorf("an edited device: %v", err)
	}
}

// The role history of K is checked at import when the store knows the key: a role
// outside payment and stake, a cold role, an unreadable history and no source
// refuse; an unknown key is allowed and reported.
//
// spec: SPO-Xrelaybind-SEC-023
func TestImportChecksTheHistoryOfAKnownKey(t *testing.T) {
	h := newHolder(t, 21, custody.RolePayment)
	p := prepBinding(t, h, devFP(0x33))
	sm := build(stmt{h: h, payload: p.Payload})
	ctx := context.Background()
	for name, tc := range map[string]struct {
		hist func(context.Context, identity.Ref) (custody.RoleHistory, bool, error)
		want error
	}{
		"drep":           {history(true, custody.RolePayment, custody.RoleDRep), relaywallet.ErrOtherRoleHistory},
		"policy":         {history(true, custody.RolePolicy), relaywallet.ErrOtherRoleHistory},
		"pool cold":      {history(true, custody.RolePoolCold), relaywallet.ErrColdHistory},
		"committee cold": {history(true, custody.RolePayment, custody.RoleCommitteeCold), relaywallet.ErrColdHistory},
		"unreadable": {func(context.Context, identity.Ref) (custody.RoleHistory, bool, error) {
			return custody.RoleHistory{}, false, errors.New("x")
		}, relaywallet.ErrHistoryUnreadable},
		"no source":         {nil, relaybinding.ErrNoHistory},
		"payment":           {history(true, custody.RolePayment), nil},
		"stake and payment": {history(true, custody.RolePayment, custody.RoleStake), nil},
		"unknown":           {history(false), nil},
	} {
		s := extSvc(now0)
		s.History = tc.hist
		// the prepared request was made with an unknown-key source; only the import is under test
		res, err := s.ImportBinding(ctx, p, sm.Sign1, sm.Key)
		if (tc.want == nil) != (err == nil) || (tc.want != nil && !errors.Is(err, tc.want)) {
			t.Errorf("%s: %v", name, err)
		}
		if tc.want != nil && res.Statement != nil {
			t.Errorf("%s: a statement was returned", name)
		}
	}
}

// The wallet-signed revoke goes through the same print and import.
//
// spec: SPO-Xrelaybind-IF-004, SPO-Xrelaybind-SEC-023
func TestPrepareAndImportRevoke(t *testing.T) {
	h := newHolder(t, 21, custody.RolePayment)
	other := newHolder(t, 22, custody.RolePayment)
	ctx := context.Background()
	s := extSvc(now0)
	for name, target := range map[string]relaybinding.RevokeTarget{"one device": {Device: devFP(0x33)}, "all": {All: true}} {
		p, err := s.PrepareRevoke(ctx, extWallet(h), target, now0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want, _ := relaybind.Revoke{All: target.All, Device: target.Device, NotBefore: now0}.Render()
		if p.Kind != relaybinding.PreparedRevokeKind || !bytes.Equal(p.Payload, want) {
			t.Errorf("%s: %+v", name, p)
		}
		sm := build(stmt{h: h, payload: p.Payload})
		res, err := extSvc(now0+60).ImportRevoke(ctx, p, sm.Sign1, sm.Key)
		if err != nil || res.Revoke != p.Revoke || res.WalletKey != relaybind.KeyHash(h.k) || res.KnownToStore || res.AddressPart != relaybind.PartKeyHash {
			t.Errorf("%s: %v %+v", name, err, res)
		}
		// hostile: another key, another payload, a binding, a hashed payload, expired
		other2 := relaybind.Revoke{All: !target.All, Device: devFP(0x34), NotBefore: now0}
		if target.All {
			other2.Device = party.Fingerprint{}
		}
		op, _ := other2.Render()
		for hn, hs := range map[string]stmt{
			"another key":     {h: other, payload: p.Payload},
			"another payload": {h: h, payload: op},
			"another time":    {h: h, payload: bytes.Replace(p.Payload, []byte("not-before 1800000000"), []byte("not-before 1799999999"), 1)},
			"a binding":       {h: h, payload: []byte("spo-relay-binding-v1 device 00 from 0 until 3600")},
			"hashed":          {h: h, payload: p.Payload, hashed: true},
			"tagged":          {h: h, payload: p.Payload, prefix: []byte{0xd2}},
		} {
			bad := build(hs)
			if _, err := extSvc(now0).ImportRevoke(ctx, p, bad.Sign1, bad.Key); !errors.Is(err, relaybinding.ErrImport) {
				t.Errorf("%s, %s: %v", name, hn, err)
			}
		}
		if _, err := extSvc(now0+601).ImportRevoke(ctx, p, sm.Sign1, sm.Key); !errors.Is(err, relaybinding.ErrPreparedExpired) {
			t.Errorf("%s: expired: %v", name, err)
		}
		if _, err := extSvc(now0).ImportBinding(ctx, p, sm.Sign1, sm.Key); !errors.Is(err, relaybinding.ErrPrepared) {
			t.Errorf("%s: a revoke as a binding: %v", name, err)
		}
	}
	// refusals at prepare
	if _, err := s.PrepareRevoke(ctx, extWallet(h), relaybinding.RevokeTarget{Device: party.Fingerprint{}}, now0); !errors.Is(err, relaybinding.ErrPolicy) {
		t.Errorf("the zero device: %v", err)
	}
	if _, err := s.PrepareRevoke(ctx, extWallet(h), relaybinding.RevokeTarget{All: true, Device: devFP(1)}, now0); !errors.Is(err, relaybinding.ErrPolicy) {
		t.Errorf("all with a device: %v", err)
	}
	if _, err := s.PrepareRevoke(ctx, extWallet(h), relaybinding.RevokeTarget{All: true}, now0+relaybind.SkewSeconds+1); !errors.Is(err, relaybinding.ErrPolicy) {
		t.Errorf("not-before beyond the skew: %v", err)
	}
	if _, err := s.PrepareRevoke(ctx, extWallet(h), relaybinding.RevokeTarget{All: true}, now0+relaybind.SkewSeconds); err != nil {
		t.Errorf("not-before at the skew: %v", err)
	}
	if _, err := s.PrepareRevoke(ctx, relaybinding.ExternalWallet{}, relaybinding.RevokeTarget{All: true}, now0); !errors.Is(err, relaybinding.ErrPolicy) {
		t.Errorf("no wallet: %v", err)
	}
	// a not-before in the future of the import clock beyond the skew is the relay's refusal
	p, _ := s.PrepareRevoke(ctx, extWallet(h), relaybinding.RevokeTarget{All: true}, now0+relaybind.SkewSeconds)
	sm := build(stmt{h: h, payload: p.Payload})
	if _, err := extSvc(now0).ImportRevoke(ctx, p, sm.Sign1, sm.Key); err != nil {
		t.Errorf("a not-before at the skew, imported at once: %v", err)
	}
}

// ErrImport and the others are distinct classes.
func TestImportErrorsAreDistinct(t *testing.T) {
	for _, pair := range [][2]error{
		{relaybinding.ErrImport, relaybinding.ErrPrepared}, {relaybinding.ErrImport, relaybinding.ErrPreparedExpired},
		{relaybinding.ErrPrepared, relaybinding.ErrPreparedExpired}, {relaybinding.ErrImport, relaybinding.ErrSelfVerify},
	} {
		if errors.Is(pair[0], pair[1]) || errors.Is(pair[1], pair[0]) {
			t.Errorf("%v and %v are one class", pair[0], pair[1])
		}
	}
}
