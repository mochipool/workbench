package relaypeer_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relaypeer"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

const now = int64(1_800_000_000)

var (
	dev    = relayporttest.Device(1)
	wallet = relayporttest.NewWallet(1)
	pol    = relaybind.DefaultPolicy()
)

func hexOf(fp party.Fingerprint) string { return hex.EncodeToString(fp[:]) }

func good() relayporttest.Statements {
	return wallet.BindingStatement(dev, now-60, now+30*24*3600, false)
}

// A binding that verifies for the party's fingerprint on the enroller's clock is
// evidence: the wallet key, the device, the window and the bytes as given.
//
// spec: SPO-Xparty-PRE-008, SPO-Xparty-OUT-007
func TestVerifyGivesTheRelayIdentity(t *testing.T) {
	st := good()
	ev, err := relaypeer.Verify(st.Sign1, st.COSEKey, dev, now, pol, relaypeer.NetworkAny)
	if err != nil {
		t.Fatal(err)
	}
	r := ev.Relay
	if r.WalletKey != party.WalletKey(wallet.Key) || r.Device != dev || r.From != now-60 || r.Until != now+30*24*3600 {
		t.Fatalf("relay identity %+v", r)
	}
	if !bytes.Equal(r.Statement, st.Sign1) || !bytes.Equal(r.Key, st.COSEKey) || ev.Part != relaybind.PartKeyHash {
		t.Fatal("the evidence is not the bytes given")
	}
	st.Sign1[0] ^= 0 // the copy is the record's own
	if &r.Statement[0] == &st.Sign1[0] {
		t.Fatal("the evidence shares the caller's buffer")
	}
	if err := party.CheckRelay(&r, dev); err != nil {
		t.Fatal(err)
	}
}

// Each hostile binding at enrollment is refused with ErrEvidence: forged,
// truncated, expired, not yet valid, for another device, over a bound, a revoke
// in place of a binding, a lifetime over the policy.
//
// spec: SPO-Xparty-PRE-008
func TestVerifyRefusesHostileBindings(t *testing.T) {
	g := good()
	other := relayporttest.NewWallet(2)
	forged := relayporttest.Statements{Sign1: other.BindingStatement(dev, now-60, now+3600, false).Sign1, COSEKey: wallet.COSEKey()}
	sig := bytes.Clone(g.Sign1)
	sig[len(sig)-1] ^= 1
	tight := relaybind.Policy{Skew: relaybind.SkewSeconds, MaxLifetime: 7 * 24 * 3600}
	cases := map[string]struct {
		s1, key []byte
		dev     party.Fingerprint
		pol     relaybind.Policy
		want    error
	}{
		"forged: another key's signature":              {forged.Sign1, forged.COSEKey, dev, pol, relaybind.ErrBadSignature},
		"forged: header of the key, signed by another": {other.Sign1At(wallet.Key[:], []byte("spo-relay-binding-v1 device "+hexOf(dev)+" from 1799999940 until 1800003600")), wallet.COSEKey(), dev, pol, relaybind.ErrBadSignature},
		"bit flip in the signature":                    {sig, g.COSEKey, dev, pol, relaybind.ErrBadSignature},
		"truncated":                                    {g.Sign1[:len(g.Sign1)-3], g.COSEKey, dev, pol, relaybind.ErrBadEncoding},
		"expired":                                      {wallet.BindingStatement(dev, now-7200, now-1, false).Sign1, g.COSEKey, dev, pol, relaybind.ErrExpired},
		"not yet valid":                                {wallet.BindingStatement(dev, now+301, now+7200, false).Sign1, g.COSEKey, dev, pol, relaybind.ErrNotYetValid},
		"wrong device":                                 {g.Sign1, g.COSEKey, relayporttest.Device(2), pol, relaybind.ErrDeviceMismatch},
		"oversize statement":                           {make([]byte, relaybind.MaxSign1Bytes+1), g.COSEKey, dev, pol, relaypeer.ErrTooLarge},
		"oversize key":                                 {g.Sign1, make([]byte, relaybind.MaxKeyBytes+1), dev, pol, relaypeer.ErrTooLarge},
		"empty":                                        {nil, nil, dev, pol, relaypeer.ErrTooLarge},
		"empty statement":                              {nil, g.COSEKey, dev, pol, relaypeer.ErrTooLarge},
		"empty key":                                    {g.Sign1, nil, dev, pol, relaypeer.ErrTooLarge},
		"a revoke, not a binding":                      {wallet.RevokeStatement(dev, false, now).Sign1, g.COSEKey, dev, pol, relaybind.ErrPayloadNotCanonical},
		"lifetime over the policy":                     {wallet.BindingStatement(dev, now-60, now+30*24*3600, false).Sign1, g.COSEKey, dev, tight, relaybind.ErrLifetimePolicy},
	}
	for name, c := range cases {
		_, err := relaypeer.Verify(c.s1, c.key, c.dev, now, c.pol, relaypeer.NetworkAny)
		if !errors.Is(err, relaypeer.ErrEvidence) || !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
}

// An address in the protected header must be on the workspace's network; the
// bare key hash names no network.
//
// spec: SPO-Xparty-PRE-008
func TestVerifyRefusesAnAddressOfAnotherNetwork(t *testing.T) {
	test := wallet.BindingStatementAt(wallet.EnterpriseAddress(0), dev, now-60, now+3600)
	if _, err := relaypeer.Verify(test.Sign1, test.COSEKey, dev, now, pol, 1); !errors.Is(err, relaypeer.ErrNetwork) {
		t.Fatalf("a test-network address on mainnet: %v", err)
	}
	ev, err := relaypeer.Verify(test.Sign1, test.COSEKey, dev, now, pol, 0)
	if err != nil || ev.Part != relaybind.PartEnterprise {
		t.Fatalf("a test-network address on a test network: %+v %v", ev, err)
	}
	g := good()
	for _, n := range []int{0, 1, relaypeer.NetworkAny} {
		if _, err := relaypeer.Verify(g.Sign1, g.COSEKey, dev, now, pol, n); err != nil {
			t.Fatalf("a bare key hash on network %d: %v", n, err)
		}
	}
	if _, err := relaypeer.Verify(g.Sign1, g.COSEKey, dev, now, pol, 2); err == nil {
		t.Fatal("a network id that is not 0 or 1 was taken")
	}
}

func histRef(t *testing.T, k party.WalletKey) identity.Ref {
	t.Helper()
	id, err := identity.NewRef(identity.KindKeyHash, k[:])
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func history(t *testing.T, k party.WalletKey, roles ...custody.Role) custody.RoleHistory {
	t.Helper()
	h, err := custody.NewRoleHistory(histRef(t, k), roles[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range roles[1:] {
		if h, err = h.With(r); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

// A peer's wallet key that this store knows is held to the cold-key rule; one it
// has no record of lives in the peer's wallet and passes.
//
// spec: SPO-Xparty-PRE-008, SPO-Xmailbox-IF-020
func TestCheckKeyHistory(t *testing.T) {
	k := party.WalletKey(wallet.Key)
	if err := relaypeer.CheckKeyHistory(k, custody.RoleHistory{}, false, nil); err != nil {
		t.Fatalf("unknown to this store: %v", err)
	}
	if err := relaypeer.CheckKeyHistory(k, history(t, k, custody.RolePayment, custody.RoleStake), true, nil); err != nil {
		t.Fatalf("payment and stake: %v", err)
	}
	for name, c := range map[string]struct {
		h     custody.RoleHistory
		known bool
		err   error
	}{
		"pool cold":         {history(t, k, custody.RolePoolCold), true, nil},
		"payment then cold": {history(t, k, custody.RolePayment, custody.RolePoolCold), true, nil},
		"drep":              {history(t, k, custody.RoleDRep), true, nil},
		"unreadable":        {custody.RoleHistory{}, false, errors.New("disk")},
		"another identity":  {history(t, party.WalletKey{9}, custody.RolePayment), true, nil},
	} {
		if err := relaypeer.CheckKeyHistory(k, c.h, c.known, c.err); !errors.Is(err, relaypeer.ErrColdKey) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func active(name string, fp party.Fingerprint, k *party.WalletKey) party.Party {
	p := party.Party{Name: name, Fingerprint: fp, State: party.StateActive, Roles: []party.Role{party.RoleSigner}}
	if k != nil {
		p.Relay = &party.RelayIdentity{WalletKey: *k, Device: fp, From: 1, Until: 2, Statement: []byte{1}, Key: []byte{1}}
	}
	return p
}

// A wallet key claimed by other parties: up to 8 active devices share it (the
// relay's cap) and are named; a ninth is refused; revoked parties and the party
// itself do not count. A wallet key that is a pool id named in any scope is a
// cold key hash and is refused.
//
// spec: SPO-Xparty-PRE-008, SPO-Xparty-PR-007
func TestCheckClaim(t *testing.T) {
	k := party.WalletKey(wallet.Key)
	self := relayporttest.Device(50)
	var ps []party.Party
	for i := range relaypeer.MaxDevicesPerWalletKey - 1 {
		ps = append(ps, active("p"+string(rune('a'+i)), relayporttest.Device(byte(10+i)), &k))
	}
	shared, err := relaypeer.CheckClaim(k, self, ps)
	if err != nil || len(shared) != relaypeer.MaxDevicesPerWalletKey-1 || shared[0] != "pa" {
		t.Fatalf("seven others: %v %v", shared, err)
	}
	// the party itself (an update) does not count against the cap
	withSelf := append(ps, active("self", self, &k))
	if _, err := relaypeer.CheckClaim(k, self, withSelf); err != nil {
		t.Fatalf("the party itself: %v", err)
	}
	full := append(ps, active("eighth", relayporttest.Device(40), &k))
	if _, err := relaypeer.CheckClaim(k, self, full); !errors.Is(err, relaypeer.ErrTooManyDevices) {
		t.Fatalf("eight others: %v", err)
	}
	revoked := active("gone", relayporttest.Device(41), &k)
	revoked.State = party.StateRevoked
	if _, err := relaypeer.CheckClaim(k, self, append(ps, revoked)); err != nil {
		t.Fatalf("a revoked party counted: %v", err)
	}
	var pool chain.PoolID
	copy(pool[:], k[:])
	coord := active("coord", relayporttest.Device(42), nil)
	coord.Scope = party.Scope{Pools: []string{pool.Bech32()}}
	if _, err := relaypeer.CheckClaim(k, self, []party.Party{coord}); !errors.Is(err, relaypeer.ErrColdKey) {
		t.Fatalf("a pool id: %v", err)
	}
}

// An update with an older binding of the same key is refused (the relay refuses
// it too); the same statement is no change; a newer one or another key replaces.
//
// spec: SPO-Xparty-PRE-008
func TestCheckUpdate(t *testing.T) {
	k := party.WalletKey(wallet.Key)
	cur := &party.RelayIdentity{WalletKey: k, Device: dev, From: 100, Until: 200, Statement: []byte{1}, Key: []byte{2}}
	older := *cur
	older.From, older.Statement = 99, []byte{3}
	if _, err := relaypeer.CheckUpdate(cur, older); !errors.Is(err, relaypeer.ErrOlder) {
		t.Fatalf("older: %v", err)
	}
	same, err := relaypeer.CheckUpdate(cur, *cur)
	if err != nil || !same {
		t.Fatalf("same: %v %v", same, err)
	}
	newer := *cur
	newer.From, newer.Statement = 101, []byte{4}
	if same, err := relaypeer.CheckUpdate(cur, newer); err != nil || same {
		t.Fatalf("newer: %v %v", same, err)
	}
	moved := older
	moved.WalletKey = party.WalletKey{1}
	if _, err := relaypeer.CheckUpdate(cur, moved); err != nil {
		t.Fatalf("another key: %v", err)
	}
	if _, err := relaypeer.CheckUpdate(nil, older); err != nil {
		t.Fatalf("no current: %v", err)
	}
}

// A stored relay identity is verified again at load: tampered evidence, a
// recorded field that the statement does not say, or a device other than the
// record's fingerprint refuses it.
//
// spec: SPO-Xparty-OUT-007
func TestReverify(t *testing.T) {
	st := good()
	ev, err := relaypeer.Verify(st.Sign1, st.COSEKey, dev, now, pol, relaypeer.NetworkAny)
	if err != nil {
		t.Fatal(err)
	}
	if err := relaypeer.Reverify(ev.Relay, dev); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(r *party.RelayIdentity){
		"statement bit":  func(r *party.RelayIdentity) { r.Statement[len(r.Statement)-1] ^= 1 },
		"key bit":        func(r *party.RelayIdentity) { r.Key[len(r.Key)-1] ^= 1 },
		"wallet key":     func(r *party.RelayIdentity) { r.WalletKey[0] ^= 1 },
		"from":           func(r *party.RelayIdentity) { r.From++ },
		"until":          func(r *party.RelayIdentity) { r.Until++ },
		"device":         func(r *party.RelayIdentity) { r.Device[0] ^= 1 },
		"truncated":      func(r *party.RelayIdentity) { r.Statement = r.Statement[:10] },
		"empty evidence": func(r *party.RelayIdentity) { r.Statement, r.Key = nil, nil },
	} {
		r := *ev.Relay.Clone()
		mut(&r)
		if err := relaypeer.Reverify(r, dev); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := relaypeer.Reverify(ev.Relay, relayporttest.Device(2)); err == nil {
		t.Error("the evidence of another party's device was accepted")
	}
}

// The route of a party is its wallet key and its own fingerprint as the device;
// a party with none, or not active, has no route.
//
// spec: SPO-Xmailbox-IF-020
func TestRoute(t *testing.T) {
	k := party.WalletKey(wallet.Key)
	p := active("bob", dev, &k)
	gk, gd, ok := relaypeer.Route(p)
	if !ok || gk != k || gd != dev {
		t.Fatalf("route %x %v %v", gk, gd, ok)
	}
	if _, _, ok := relaypeer.Route(active("nokey", dev, nil)); ok {
		t.Fatal("a party without a wallet key routes")
	}
	p.State = party.StateRevoked
	if _, _, ok := relaypeer.Route(p); ok {
		t.Fatal("a revoked party routes")
	}
}
