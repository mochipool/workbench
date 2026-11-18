package mailbox_test

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
)

func params() mailbox.AuthParams {
	return mailbox.AuthParams{
		Version:       1,
		RelayKey:      nk(10),
		ClientNodeKey: nk(20),
		Nonce:         nonce(30),
		RelayTime:     1700000000,
		Fingerprint:   fp(40),
	}
}

func bstr(b []byte) []byte {
	if len(b) < 24 {
		return append([]byte{0x40 + byte(len(b))}, b...)
	}
	return append([]byte{0x58, byte(len(b))}, b...)
}

// By hand: a 7-array, the 19-character label as a text string, the version,
// four byte strings of 32, 32, 32 and 20 bytes wrapped... in the order of
// ADR 0013 decision 3.
func wantAuthBytes(p mailbox.AuthParams) []byte {
	b := []byte{0x87, 0x60 + 19}
	b = append(b, "spo/mailbox-auth/v1"...)
	b = append(b, byte(p.Version)) // 1..23
	b = append(b, bstr(p.RelayKey[:])...)
	b = append(b, bstr(p.ClientNodeKey[:])...)
	b = append(b, bstr(p.Nonce[:])...)
	// 1700000000 = 0x6553F100 in a 4-byte argument.
	b = append(b, 0x1a, 0x65, 0x53, 0xf1, 0x00)
	b = append(b, bstr(p.Fingerprint[:])...)
	return b
}

// spec: SPO-Xmailbox-OUT-007, SPO-Xmailbox-SEC-001
func TestAuthBytesAreTheLabelledArray(t *testing.T) {
	p := params()
	got, err := mailbox.AuthBytes(p)
	if err != nil {
		t.Fatal(err)
	}
	if want := wantAuthBytes(p); !bytes.Equal(got, want) {
		t.Fatalf("got  %x\nwant %x", got, want)
	}
	// The label is the first array element, not a prefix of the bytes.
	if got[0] != 0x87 || !bytes.HasPrefix(got[1:], append([]byte{0x73}, mailbox.AuthLabel...)) {
		t.Error("the label is not the first element of the array")
	}
	if mailbox.AuthLabel != "spo/mailbox-auth/v1" {
		t.Errorf("label %q", mailbox.AuthLabel)
	}
}

// The separation argument of SEC-001: the auth bytes are a CBOR array, so they
// start with 0x87; every other message the party's Ed25519 key signs is an
// ASCII label followed by content, so it starts with a byte below 0x80. No
// label is a prefix of the auth bytes, and none can be the first bytes of an
// auth array.
//
// spec: SPO-Xmailbox-SEC-001
func TestAuthBytesAreSeparatedFromEverythingElseTheKeySigns(t *testing.T) {
	got, err := mailbox.AuthBytes(params())
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != 0x87 {
		t.Fatalf("the auth bytes start with 0x%02x, not the 7-array head 0x87", got[0])
	}
	labels := map[string]string{
		// The envelope domain is a literal: its home, adapters/envelope/seal.go
		// (EnvelopeDomain), links age and cannot be imported by a pure package.
		"envelope signature":   "spo/envelope/v1",
		"identity document":    party.DocumentDomain,
		"rotation, old key":    party.RotationOldDomain,
		"rotation, new key":    party.RotationNewDomain,
		"mailbox auth (label)": mailbox.AuthLabel,
	}
	seen := map[string]bool{}
	for what, l := range labels {
		if l == "" || l[0] >= 0x80 || l[0] == 0x87 {
			t.Errorf("%s: label %q does not start with an ASCII byte", what, l)
		}
		if bytes.HasPrefix(got, []byte(l)) {
			t.Errorf("%s: the auth bytes start with the label %q", what, l)
		}
		if seen[l] {
			t.Errorf("%s: label %q is used twice", what, l)
		}
		seen[l] = true
		if what != "mailbox auth (label)" && bytes.Contains(got, []byte(l)) {
			t.Errorf("%s: the auth bytes carry the label %q", what, l)
		}
	}
}

// Every field is covered: changing any one changes the bytes.
//
// spec: SPO-Xmailbox-SEC-001
func TestEveryAuthFieldChangesTheBytes(t *testing.T) {
	base, _ := mailbox.AuthBytes(params())
	muts := map[string]func(*mailbox.AuthParams){
		"version":    func(p *mailbox.AuthParams) { p.Version = 2 },
		"relay key":  func(p *mailbox.AuthParams) { p.RelayKey[31] ^= 1 },
		"client key": func(p *mailbox.AuthParams) { p.ClientNodeKey[0] ^= 1 },
		"nonce":      func(p *mailbox.AuthParams) { p.Nonce[17] ^= 1 },
		"time":       func(p *mailbox.AuthParams) { p.RelayTime++ },
		"finger":     func(p *mailbox.AuthParams) { p.Fingerprint[19] ^= 1 },
	}
	for name, mut := range muts {
		p := params()
		mut(&p)
		got, err := mailbox.AuthBytes(p)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if bytes.Equal(got, base) {
			t.Errorf("%s does not change the signed bytes", name)
		}
	}
	// Swapping the two node keys changes the bytes.
	p := params()
	p.RelayKey, p.ClientNodeKey = p.ClientNodeKey, p.RelayKey
	if got, _ := mailbox.AuthBytes(p); bytes.Equal(got, base) {
		t.Error("swapped keys give the same bytes")
	}
}

// spec: SPO-Xmailbox-PRE-010, SPO-Xmailbox-PRE-016
func TestAuthBytesRefuseOutOfRangeInputs(t *testing.T) {
	for name, mut := range map[string]func(*mailbox.AuthParams){
		"version 0":      func(p *mailbox.AuthParams) { p.Version = 0 },
		"version 65536":  func(p *mailbox.AuthParams) { p.Version = 65536 },
		"negative time":  func(p *mailbox.AuthParams) { p.RelayTime = -1 },
		"min int64 time": func(p *mailbox.AuthParams) { p.RelayTime = -1 << 63 },
		"time max+1":     func(p *mailbox.AuthParams) { p.RelayTime = mailbox.MaxTime + 1 },
		"max int64 time": func(p *mailbox.AuthParams) { p.RelayTime = 1<<63 - 1 },
	} {
		p := params()
		mut(&p)
		if _, err := mailbox.AuthBytes(p); !errors.Is(err, mailbox.ErrRange) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, mut := range map[string]func(*mailbox.AuthParams){
		"version 65535": func(p *mailbox.AuthParams) { p.Version = 65535 },
		"time 0":        func(p *mailbox.AuthParams) { p.RelayTime = 0 },
		"time max":      func(p *mailbox.AuthParams) { p.RelayTime = mailbox.MaxTime },
	} {
		p := params()
		mut(&p)
		if _, err := mailbox.AuthBytes(p); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func keypair(seed byte) (ed25519.PrivateKey, party.Ed25519Public) {
	priv := ed25519.NewKeyFromSeed(bs(32, seed))
	var pub party.Ed25519Public
	copy(pub[:], priv.Public().(ed25519.PublicKey))
	return priv, pub
}

// listed is an access-list identity with a node key, and the auth parameters
// of a client that is that identity, connecting over the tunnel as it.
func listed(seed byte) (ed25519.PrivateKey, party.Identity, mailbox.AuthParams) {
	priv, pub := keypair(seed)
	node := nk(seed + 50)
	id := party.Identity{Label: "p", Ed25519: pub, Node: &node}
	copy(id.X25519[:], bs(32, seed+100))
	p := params()
	p.ClientNodeKey = node
	p.Fingerprint = id.Fingerprint()
	return priv, id, p
}

func sign(t *testing.T, priv ed25519.PrivateKey, p mailbox.AuthParams) (s [64]byte) {
	t.Helper()
	b, err := mailbox.AuthBytes(p)
	if err != nil {
		t.Fatal(err)
	}
	copy(s[:], ed25519.Sign(priv, b))
	return
}

// Each binding VerifyAuth enforces is refused with its own error, and every
// one of them is also an ErrAuth. The signature in each case is genuine, so
// only the named check can be what refuses.
//
// spec: SPO-Xmailbox-SEC-002, SPO-Xmailbox-SEC-012
func TestVerifyAuthBindsTheIdentity(t *testing.T) {
	priv, id, p := listed(1)
	peer := p.ClientNodeKey
	s := sign(t, priv, p)
	if err := mailbox.VerifyAuth(id, peer, s, p); err != nil {
		t.Fatalf("a good authentication: %v", err)
	}

	// The claimed fingerprint is not the identity's: a signature by the
	// identity's own key over a claim for another fingerprint.
	q := p
	q.Fingerprint = fp(77)
	if err := mailbox.VerifyAuth(id, peer, sign(t, priv, q), q); !errors.Is(err, mailbox.ErrAuthFingerprint) || !errors.Is(err, mailbox.ErrAuth) {
		t.Errorf("another fingerprint: %v", err)
	}
	// The listed identity's fingerprint follows its X25519 key too.
	id2 := id
	id2.X25519[0] ^= 1
	if err := mailbox.VerifyAuth(id2, peer, s, p); !errors.Is(err, mailbox.ErrAuthFingerprint) {
		t.Errorf("another x25519 key: %v", err)
	}
	// The tunnel peer is not the node key the client claims.
	other := nk(99)
	if err := mailbox.VerifyAuth(id, other, s, p); !errors.Is(err, mailbox.ErrAuthTunnelKey) || !errors.Is(err, mailbox.ErrAuth) {
		t.Errorf("another tunnel peer: %v", err)
	}
	// The claimed node key (which is the tunnel's) is not the identity's.
	q = p
	q.ClientNodeKey = nk(98)
	if err := mailbox.VerifyAuth(id, q.ClientNodeKey, sign(t, priv, q), q); !errors.Is(err, mailbox.ErrAuthIdentityNode) || !errors.Is(err, mailbox.ErrAuth) {
		t.Errorf("another identity node key: %v", err)
	}
	// An identity without a node key, or with a zero one, cannot authenticate.
	id3 := id
	id3.Node = nil
	if err := mailbox.VerifyAuth(id3, peer, s, p); !errors.Is(err, mailbox.ErrAuthNoNodeKey) || !errors.Is(err, mailbox.ErrAuth) {
		t.Errorf("no node key: %v", err)
	}
	zero := party.NodeKey{}
	id3.Node = &zero
	q = p
	q.ClientNodeKey = zero
	if err := mailbox.VerifyAuth(id3, zero, sign(t, priv, q), q); !errors.Is(err, mailbox.ErrAuthNoNodeKey) {
		t.Errorf("zero node key: %v", err)
	}
	// The five reasons are different errors.
	reasons := []error{mailbox.ErrAuthNoNodeKey, mailbox.ErrAuthFingerprint, mailbox.ErrAuthTunnelKey, mailbox.ErrAuthIdentityNode}
	for i, a := range reasons {
		for j, b := range reasons {
			if (i == j) != (a == b) {
				t.Errorf("reasons %d and %d", i, j)
			}
		}
	}
}

// The key is the identity's: a signature by another key, over the right
// bytes, is refused as ErrAuth alone, and so is every bit of a signature and
// every changed field.
//
// spec: SPO-Xmailbox-SEC-002
func TestVerifyAuthChecksTheSignature(t *testing.T) {
	priv, id, p := listed(1)
	peer := p.ClientNodeKey
	s := sign(t, priv, p)
	plain := func(err error) bool {
		return errors.Is(err, mailbox.ErrAuth) && !errors.Is(err, mailbox.ErrAuthFingerprint) &&
			!errors.Is(err, mailbox.ErrAuthTunnelKey) && !errors.Is(err, mailbox.ErrAuthIdentityNode) && !errors.Is(err, mailbox.ErrAuthNoNodeKey)
	}
	// Another key signs the same bytes.
	otherPriv, _ := keypair(2)
	if err := mailbox.VerifyAuth(id, peer, sign(t, otherPriv, p), p); !plain(err) {
		t.Errorf("another key: %v", err)
	}
	for i := 0; i < 64; i++ {
		c := s
		c[i] ^= 0x80
		if err := mailbox.VerifyAuth(id, peer, c, p); !plain(err) {
			t.Fatalf("signature byte %d flipped: %v", i, err)
		}
	}
	// A field of the signed bytes that no binding covers: a signature made for
	// other values does not verify for these.
	for name, mut := range map[string]func(*mailbox.AuthParams){
		"version":   func(q *mailbox.AuthParams) { q.Version = 2 },
		"relay key": func(q *mailbox.AuthParams) { q.RelayKey[0] ^= 1 },
		"nonce":     func(q *mailbox.AuthParams) { q.Nonce[0] ^= 1 },
		"time":      func(q *mailbox.AuthParams) { q.RelayTime++ },
	} {
		q := p
		mut(&q)
		if err := mailbox.VerifyAuth(id, peer, s, q); !plain(err) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Invalid parameters never verify.
	q := p
	q.Version = 0
	if err := mailbox.VerifyAuth(id, peer, s, q); !errors.Is(err, mailbox.ErrRange) {
		t.Errorf("version 0: %v", err)
	}
	q = p
	q.RelayTime = mailbox.MaxTime + 1
	if err := mailbox.VerifyAuth(id, peer, sign(t, priv, p), q); !errors.Is(err, mailbox.ErrRange) {
		t.Errorf("relay time above the bound: %v", err)
	}
	// A signature over the same fields under another label does not verify.
	other2 := append([]byte{0x87, 0x60 + 19}, "spo/mailbox-auth/v2"...)
	good, _ := mailbox.AuthBytes(p)
	other2 = append(other2, good[2+19:]...)
	var s2 [64]byte
	copy(s2[:], ed25519.Sign(priv, other2))
	if err := mailbox.VerifyAuth(id, peer, s2, p); !plain(err) {
		t.Errorf("another label: %v", err)
	}
}

// The relay's clock is untrusted: Skew is exact, never negative and saturates
// instead of wrapping, at both ends of the int64 range.
//
// spec: SPO-Xmailbox-SEC-013
func TestSkew(t *testing.T) {
	const max, min = int64(1<<63 - 1), int64(-1 << 63)
	for _, c := range []struct{ relay, now, want int64 }{
		{100, 100, 0}, {100, 40, 60}, {40, 100, 60}, {0, 0, 0},
		{mailbox.MaxTime, 0, mailbox.MaxTime}, {0, mailbox.MaxTime, mailbox.MaxTime},
		{mailbox.MaxTime, -1, mailbox.MaxTime + 1},
		{0, max, max}, {max, 0, max}, {1, max, max - 1},
		{0, min, max}, {mailbox.MaxTime, min, max}, {min, mailbox.MaxTime, max},
		{max, min, max}, {min, max, max}, {-1, max, max}, {max, -1, max},
		{-5, -9, 4}, {-9, -5, 4},
	} {
		if got := mailbox.Skew(c.relay, c.now); got != c.want {
			t.Errorf("Skew(%d, %d) = %d, want %d", c.relay, c.now, got, c.want)
		}
	}
	if mailbox.ClockSkewWarningSeconds != 300 {
		t.Errorf("warning threshold %d seconds", mailbox.ClockSkewWarningSeconds)
	}
}
