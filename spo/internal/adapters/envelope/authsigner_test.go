package envelope

import (
	"bytes"
	"crypto/ed25519"
	"math/rand"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// The local identity signs the version 2 mailbox login through a typed method:
// the bytes are the canonical array of mailbox.AuthBytesV2 built from the
// caller's fixed-length values and the identity's OWN fingerprint, and nothing
// else. The signature is the Ed25519 signature of those bytes by the device key
// (compared with an independent signature), it verifies with VerifyAuthV2 as the
// relay checks it, it does not verify for any other value of the array, and a
// destroyed identity signs nothing.
//
// spec: SPO-Xmailbox-IF-017, SPO-Xmailbox-SEC-071
func TestLocalSignsOnlyTheMailboxAuthArrayForItsOwnFingerprint(t *testing.T) {
	p, err := Generate("dev", nil, time.Unix(1700000000, 0), rand.New(rand.NewSource(11)))
	if err != nil {
		t.Fatal(err)
	}
	l := NewLocal(p, nil)
	var signer relayport.AuthSigner = l
	id := l.Identity()
	fpr := id.Fingerprint()

	relayKey, node := party.NodeKey{1, 2, 3}, party.NodeKey{4, 5, 6}
	var nonce, bh, sh [32]byte
	nonce[0], bh[0], sh[0] = 7, 8, 9
	const rt = int64(1700000123)
	sig, err := signer.SignMailboxAuth(relayKey, node, nonce, rt, bh, sh)
	if err != nil {
		t.Fatal(err)
	}
	params := mailbox.AuthV2Params{RelayKey: relayKey, ClientNodeKey: node, Nonce: nonce, RelayTime: rt, Fingerprint: fpr, BindingHash: bh, SendersHash: sh}
	keys := mailbox.DeviceKeys{Ed25519: id.Ed25519, X25519: id.X25519}
	if err := mailbox.VerifyAuthV2(keys, node, sig, params); err != nil {
		t.Fatalf("the relay cannot verify the signature: %v", err)
	}
	// exactly the Ed25519 signature over the labelled array of the own fingerprint
	msg, err := mailbox.AuthBytesV2(params)
	if err != nil {
		t.Fatal(err)
	}
	var seed []byte
	_ = p.keys.Use(func(b []byte) error { seed = append([]byte(nil), b[:32]...); return nil })
	if want := ed25519.Sign(ed25519.NewKeyFromSeed(seed), msg); !bytes.Equal(sig[:], want) {
		t.Errorf("signature %x, want the Ed25519 signature of the version 2 auth bytes %x", sig, want)
	}
	// and of nothing else: each value of the array changes the bytes, so the
	// signature fails for it
	flip := func(name string, edit func(q *mailbox.AuthV2Params)) {
		q := params
		edit(&q)
		b, err := mailbox.AuthBytesV2(q)
		if err != nil {
			t.Fatal(err)
		}
		if ed25519.Verify(id.Ed25519[:], b, sig[:]) {
			t.Errorf("the signature also verifies with another %s", name)
		}
	}
	flip("relay key", func(q *mailbox.AuthV2Params) { q.RelayKey[0] ^= 1 })
	flip("node key", func(q *mailbox.AuthV2Params) { q.ClientNodeKey[0] ^= 1 })
	flip("nonce", func(q *mailbox.AuthV2Params) { q.Nonce[0] ^= 1 })
	flip("relay time", func(q *mailbox.AuthV2Params) { q.RelayTime++ })
	flip("fingerprint", func(q *mailbox.AuthV2Params) { q.Fingerprint[0] ^= 1 })
	flip("binding hash", func(q *mailbox.AuthV2Params) { q.BindingHash[0] ^= 1 })
	flip("senders hash", func(q *mailbox.AuthV2Params) { q.SendersHash[0] ^= 1 })
	if ed25519.Verify(id.Ed25519[:], msg[1:], sig[:]) || ed25519.Verify(id.Ed25519[:], append([]byte("x"), msg...), sig[:]) {
		t.Error("the signature verifies for bytes that are not the array")
	}
	// a relay time outside the protocol's range is refused, with no signature
	if s, err := signer.SignMailboxAuth(relayKey, node, nonce, -1, bh, sh); err == nil || s != ([64]byte{}) {
		t.Errorf("relay time -1: %v", err)
	}
	if s, err := signer.SignMailboxAuth(relayKey, node, nonce, mailbox.MaxTime+1, bh, sh); err == nil || s != ([64]byte{}) {
		t.Errorf("relay time above the maximum: %v", err)
	}
	// a destroyed identity signs nothing
	l.Destroy()
	if s, err := signer.SignMailboxAuth(relayKey, node, nonce, rt, bh, sh); err == nil && s != ([64]byte{}) {
		t.Error("a destroyed identity signed")
	}
}
