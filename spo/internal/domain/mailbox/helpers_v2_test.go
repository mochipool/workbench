package mailbox_test

import (
	"bytes"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
)

func wk(b byte) (k mailbox.WalletKey) {
	for i := range k {
		k[i] = b + byte(i)
	}
	return
}

func wkb(b byte) []byte { k := wk(b); return k[:] }

func edk(b byte) (k party.Ed25519Public) {
	for i := range k {
		k[i] = b + byte(i)
	}
	return
}

func xk(b byte) (k party.X25519Public) {
	for i := range k {
		k[i] = b + byte(i)
	}
	return
}

func edb(b byte) []byte { k := edk(b); return k[:] }
func xkb(b byte) []byte { k := xk(b); return k[:] }

// stage and side of a frame, for the round trips.
type where struct {
	stage  mailbox.Stage
	client bool // true: the client sent it
}

// samplesV2 is one valid version 2 message of every type that exists in version
// 2 (and the shared ones), each with the stage it is decoded at. The sign1 and
// key are opaque bytes of plausible length: this package checks only lengths.
func samplesV2() []struct {
	m mailbox.Message
	w where
} {
	h := hash(9)
	type s = struct {
		m mailbox.Message
		w where
	}
	pre, authed, none := mailbox.StageV2PreAuth, mailbox.StageV2Authed, mailbox.StageUnversioned
	return []s{
		{mailbox.Challenge{Min: 1, Max: 2, Nonce: nonce(1), RelayKey: nk(2), RelayTime: 1700000000}, where{none, false}},
		{mailbox.AuthV2{Fingerprint: fp(3), Signature: sig(4), Keys: mailbox.DeviceKeys{Ed25519: edk(5), X25519: xk(6)}, Sign1: bs(150, 7), Key: bs(40, 8), Senders: []mailbox.WalletKey{wk(1), wk(2), wk(9)}}, where{pre, true}},
		{mailbox.AuthV2{Fingerprint: fp(3), Signature: sig(4), Keys: mailbox.DeviceKeys{Ed25519: edk(5), X25519: xk(6)}, Sign1: bs(1, 7), Key: bs(1, 8)}, where{pre, true}},
		{mailbox.AuthOKV2{MaxEnvelope: mailbox.MaxEnvelopeBytes, MaxEntries: 256, MaxBytes: 64 << 20, RetentionSeconds: mailbox.DefaultRetentionSeconds, Until: 1707776000}, where{pre, false}},
		{mailbox.PutV2{RequestID: 7, WalletKey: wk(3), To: fp(4), Mid: hash(5), Size: 1234}, where{authed, true}},
		{mailbox.PutResult{RequestID: 7, Status: mailbox.StatusUnbound}, where{authed, false}},
		{mailbox.PutResult{RequestID: 7, Status: mailbox.StatusStored}, where{authed, false}},
		{mailbox.Fetch{RequestID: 8, MaxItems: 16, WaitSeconds: 20}, where{authed, true}},
		{mailbox.Fetch{RequestID: 9, After: &h, MaxItems: 1}, where{authed, true}},
		{mailbox.Items{RequestID: 8, Entries: []mailbox.Item{{Mid: hash(1), Size: 10}, {Mid: hash(2), Size: 20}}, More: true}, where{authed, false}},
		{mailbox.Ack{RequestID: 9, Mids: []mailbox.Hash{hash(1), hash(2)}}, where{authed, true}},
		{mailbox.AckResult{RequestID: 9, Deleted: 2}, where{authed, false}},
		{mailbox.Error{Code: mailbox.CodeNotAllowed}, where{pre, false}},
		{mailbox.Error{Code: mailbox.CodeBinding}, where{pre, false}},
		{mailbox.RevokeByDevice{RequestID: 3, Keys: mailbox.DeviceKeys{Ed25519: edk(5), X25519: xk(6)}, NotBefore: 1700000000, Signature: sig(9)}, where{pre, true}},
		{mailbox.RevokeByWallet{RequestID: 4, Sign1: bs(120, 3), Key: bs(40, 4)}, where{pre, true}},
		{mailbox.RevokeResult{RequestID: 3, Status: mailbox.RevokeRecorded}, where{pre, false}},
		{mailbox.RevokeResult{RequestID: 4, Status: mailbox.RevokeRefused}, where{pre, false}},
	}
}

func mustEncodeV(t testing.TB, version uint, m mailbox.Message) []byte {
	t.Helper()
	b, err := mailbox.EncodeV(version, m)
	if err != nil {
		t.Fatalf("EncodeV(%d, %#v): %v", version, m, err)
	}
	return b
}

// decodeIn decodes with the decoder of the side.
func decodeIn(w where, frame []byte) (mailbox.Message, error) {
	if w.client {
		return mailbox.DecodeFromClientIn(w.stage, frame)
	}
	return mailbox.DecodeFromRelayIn(w.stage, frame)
}

// reencode encodes a decoded message again in the version that its type is
// written in: a version 1 message (the Auth, Put and AuthOK of version 1) in
// version 1, every other in version 2.
func reencode(m mailbox.Message) ([]byte, error) {
	if b, err := mailbox.EncodeV(2, m); err == nil {
		return b, nil
	}
	return mailbox.EncodeV(1, m)
}

func sameBytes(a, b []byte) bool { return bytes.Equal(a, b) }

// maxAuthV2 is an Auth at every bound: sign1 512, key 128, 64 senders.
func maxAuthV2() mailbox.AuthV2 {
	var senders []mailbox.WalletKey
	for i := 0; i < mailbox.MaxSenders; i++ {
		senders = append(senders, wk(byte(i*3)))
	}
	// wk(b) is b..b+27; the first byte rises with i, so the list is ascending.
	return mailbox.AuthV2{
		Fingerprint: fp(3), Signature: sig(4), Keys: mailbox.DeviceKeys{Ed25519: edk(5), X25519: xk(6)},
		Sign1: bs(mailbox.MaxSign1Bytes, 7), Key: bs(mailbox.MaxCOSEKeyBytes, 8), Senders: senders,
	}
}
