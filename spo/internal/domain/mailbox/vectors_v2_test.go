package mailbox_test

// testdata/vectors_v2.json pins the version 2 wire format: the auth bytes with
// a signature of a fixed test key, the expected-sender hashes and every frame
// that version 2 adds or changes (the frames that are the same in both versions
// are in vectors.json). testdata/check_vectors.py encodes each frame again from
// its fields with its own encoder and recomputes the auth bytes and the sender
// hashes. TestVectorsV2 regenerates the file in memory and compares it byte for
// byte with the committed one. Rewrite deliberately with:
//
//	go test ./internal/domain/mailbox -run TestVectorsV2 -update

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"os"
	"testing"

	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
)

type authV2Vector struct {
	Name         string `json:"name"`
	RelayKey     string `json:"relay_key"`
	ClientKey    string `json:"client_node_key"`
	Nonce        string `json:"nonce"`
	RelayTime    int64  `json:"relay_time"`
	Fingerprint  string `json:"fingerprint"`
	BindingHash  string `json:"binding_hash"`
	SendersHash  string `json:"senders_hash"`
	SendersList  string `json:"senders_list"` // the name of the sender-list vector that SendersHash is the hash of
	BytesHex     string `json:"bytes_hex"`
	SeedHex      string `json:"ed25519_seed"`
	PublicHex    string `json:"ed25519_public"`
	SignatureHex string `json:"signature_hex"`
}

type sendersVector struct {
	Name    string   `json:"name"`
	Keys    []string `json:"keys"`
	HashHex string   `json:"hash_hex"`
}

type frameV2Vector struct {
	Name     string         `json:"name"`
	Shape    string         `json:"shape"`
	Type     uint           `json:"type"`
	Stage    string         `json:"stage"`
	Side     string         `json:"side"`
	Fields   map[string]any `json:"fields"`
	CBORHex  string         `json:"cbor_hex"`
	FrameHex string         `json:"frame_hex"`
}

type vectorFileV2 struct {
	Note    string          `json:"note"`
	Auth    []authV2Vector  `json:"auth_v2"`
	Senders []sendersVector `json:"senders"`
	Frames  []frameV2Vector `json:"frames"`
}

var stageNames = map[string]mailbox.Stage{
	"unversioned": mailbox.StageUnversioned, "v2_preauth": mailbox.StageV2PreAuth, "v2_authed": mailbox.StageV2Authed,
}

func hexList(items ...[]byte) []any {
	out := make([]any, 0, len(items))
	for _, b := range items {
		out = append(out, x(b))
	}
	return out
}

func buildVectorsV2(t *testing.T) []byte {
	t.Helper()
	vf := vectorFileV2{Note: "ADR 0014 work package 2; version 2 frames and auth bytes; hex fields are lower-case; numbers are decimal"}
	// The sender lists come first: each auth-bytes vector commits to one of them
	// by its hash, and each Auth frame carries one.
	senderHash := map[string][mailbox.HashSize]byte{}
	for _, c := range []struct {
		name string
		keys []mailbox.WalletKey
	}{
		{"none", nil}, {"one", []mailbox.WalletKey{wk(7)}}, {"three", []mailbox.WalletKey{wk(1), wk(2), wk(9)}},
		{"last byte order", []mailbox.WalletKey{func() mailbox.WalletKey { k := wk(1); k[27] = 3; return k }(), func() mailbox.WalletKey { k := wk(1); k[27] = 9; return k }()}},
		{"sixty-four", maxAuthV2().Senders},
	} {
		h, err := mailbox.SendersHash(c.keys)
		if err != nil {
			t.Fatal(err)
		}
		senderHash[c.name] = h
		var keys []string
		for _, k := range c.keys {
			keys = append(keys, x(k[:]))
		}
		if keys == nil {
			keys = []string{}
		}
		vf.Senders = append(vf.Senders, sendersVector{c.name, keys, x(h[:])})
	}
	priv := ed25519.NewKeyFromSeed(bs(32, 1))
	for _, c := range []struct {
		name, list string
		p          mailbox.AuthV2Params
	}{
		{"typical", "three", paramsV2()},
		{"zeros", "none", mailbox.AuthV2Params{RelayKey: nk(0), ClientNodeKey: nk(0), Nonce: nonce(0), RelayTime: 0, Fingerprint: fp(0)}},
		{"large values", "sixty-four", mailbox.AuthV2Params{RelayKey: nk(200), ClientNodeKey: nk(100), Nonce: nonce(255), RelayTime: mailbox.MaxTime, Fingerprint: fp(250), BindingHash: hash(255)}},
	} {
		p := c.p
		p.SendersHash = senderHash[c.list]
		b, err := mailbox.AuthBytesV2(p)
		if err != nil {
			t.Fatal(err)
		}
		vf.Auth = append(vf.Auth, authV2Vector{
			Name:     c.name,
			RelayKey: x(p.RelayKey[:]), ClientKey: x(p.ClientNodeKey[:]), Nonce: x(p.Nonce[:]),
			RelayTime: p.RelayTime, Fingerprint: x(p.Fingerprint[:]), BindingHash: x(p.BindingHash[:]), SendersHash: x(p.SendersHash[:]), SendersList: c.list,
			BytesHex: x(b), SeedHex: x(bs(32, 1)), PublicHex: x(priv.Public().(ed25519.PublicKey)), SignatureHex: x(ed25519.Sign(priv, b)),
		})
	}
	// The Auth frames carry the fingerprint of their own device keys, as a relay
	// requires (it recomputes it).
	keys := mailbox.DeviceKeys{Ed25519: edk(5), X25519: xk(6)}
	typical := mailbox.AuthV2{Fingerprint: keys.Fingerprint(), Signature: sig(4), Keys: keys, Sign1: bs(150, 7), Key: bs(40, 8), Senders: []mailbox.WalletKey{wk(1), wk(2), wk(9)}}
	empty := mailbox.AuthV2{Fingerprint: keys.Fingerprint(), Signature: sig(4), Keys: keys, Sign1: bs(1, 7), Key: bs(1, 8)}
	max := maxAuthV2()
	max.Fingerprint = keys.Fingerprint()
	sendersOf := func(l []mailbox.WalletKey) []any {
		out := []any{}
		for _, k := range l {
			out = append(out, x(k[:]))
		}
		return out
	}
	authFields := func(a mailbox.AuthV2) map[string]any {
		return map[string]any{
			"version": 2, "fingerprint": x(a.Fingerprint[:]), "signature": x(a.Signature[:]),
			"binding": hexList(a.Keys.Ed25519[:], a.Keys.X25519[:], a.Sign1, a.Key), "senders": sendersOf(a.Senders),
		}
	}
	named := []struct {
		name, shape, stage, side string
		m                        mailbox.Message
		fields                   map[string]any
	}{
		{"challenge_both_versions", "challenge", "unversioned", "relay", mailbox.Challenge{Min: 1, Max: 2, Nonce: nonce(1), RelayKey: nk(2), RelayTime: 1700000000},
			map[string]any{"min": 1, "max": 2, "nonce": x(nonceb(1)), "relay_key": x(nkb(2)), "relay_time": 1700000000}},
		{"challenge_v2_only", "challenge", "unversioned", "relay", mailbox.Challenge{Min: 2, Max: 2, Nonce: nonce(1), RelayKey: nk(2), RelayTime: 1700000000},
			map[string]any{"min": 2, "max": 2, "nonce": x(nonceb(1)), "relay_key": x(nkb(2)), "relay_time": 1700000000}},
		{"auth_v2", "auth_v2", "v2_preauth", "client", typical, authFields(typical)},
		{"auth_v2_no_senders", "auth_v2", "v2_preauth", "client", empty, authFields(empty)},
		{"auth_v2_largest", "auth_v2", "v2_preauth", "client", max, authFields(max)},
		{"auth_ok_v2", "authok_v2", "v2_preauth", "relay", mailbox.AuthOKV2{MaxEnvelope: mailbox.MaxEnvelopeBytes, MaxEntries: 256, MaxBytes: 64 << 20, RetentionSeconds: mailbox.DefaultRetentionSeconds, Until: 1707776000},
			map[string]any{"version": 2, "max_envelope": 1 << 20, "max_entries": 256, "max_bytes": 64 << 20, "retention_seconds": 7 * 86400, "until": 1707776000}},
		{"put_v2", "put_v2", "v2_authed", "client", mailbox.PutV2{RequestID: 7, WalletKey: wk(3), To: fp(4), Mid: hash(5), Size: 1234},
			map[string]any{"request_id": 7, "wallet_key": x(wkb(3)), "to": x(fpb(4)), "mid": x(mid(5)), "size": 1234}},
		{"put_result_unbound", "put_result", "v2_authed", "relay", mailbox.PutResult{RequestID: 7, Status: mailbox.StatusUnbound},
			map[string]any{"request_id": 7, "status": 8}},
		{"error_not_allowed", "error", "v2_preauth", "relay", mailbox.Error{Code: mailbox.CodeNotAllowed}, map[string]any{"code": 6}},
		{"error_binding", "error", "v2_preauth", "relay", mailbox.Error{Code: mailbox.CodeBinding}, map[string]any{"code": 7}},
		{"revoke_by_device", "revoke_device", "v2_preauth", "client", mailbox.RevokeByDevice{RequestID: 3, Keys: keys, NotBefore: 1700000000, Signature: sig(9)},
			map[string]any{"request_id": 3, "kind": 0, "ed25519": x(edb(5)), "x25519": x(xkb(6)), "not_before": 1700000000, "signature": x(sigb(9))}},
		{"revoke_by_wallet", "revoke_wallet", "v2_preauth", "client", mailbox.RevokeByWallet{RequestID: 4, Sign1: bs(120, 3), Key: bs(40, 4)},
			map[string]any{"request_id": 4, "kind": 1, "sign1": x(bs(120, 3)), "key": x(bs(40, 4))}},
		{"revoke_result_recorded", "revoke_result", "v2_preauth", "relay", mailbox.RevokeResult{RequestID: 3, Status: mailbox.RevokeRecorded}, map[string]any{"request_id": 3, "status": 0}},
		{"revoke_result_refused", "revoke_result", "v2_preauth", "relay", mailbox.RevokeResult{RequestID: 4, Status: mailbox.RevokeRefused}, map[string]any{"request_id": 4, "status": 2}},
	}
	for _, n := range named {
		b := mustEncodeV(t, 2, n.m)
		fr, err := mailbox.AppendFrame(nil, b)
		if err != nil {
			t.Fatal(err)
		}
		vf.Frames = append(vf.Frames, frameV2Vector{n.name, n.shape, uint(n.m.Type()), n.stage, n.side, n.fields, x(b), x(fr)})
	}
	out, err := json.MarshalIndent(vf, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

// spec: SPO-Xmailbox-OUT-057
func TestVectorsV2(t *testing.T) {
	got := buildVectorsV2(t)
	const path = "testdata/vectors_v2.json"
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to write it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("testdata/vectors_v2.json differs from the regenerated vectors; a difference is a format change")
	}
}

// The committed file is checked on its own: auth bytes rebuild and verify,
// sender hashes recompute, and every frame decodes at its stage and re-encodes
// to itself.
//
// spec: SPO-Xmailbox-OUT-057, SPO-Xmailbox-INV-029
func TestCommittedVectorsV2StandAlone(t *testing.T) {
	raw, err := os.ReadFile("testdata/vectors_v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var vf vectorFileV2
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatal(err)
	}
	if len(vf.Auth) != 3 || len(vf.Senders) != 5 || len(vf.Frames) != 14 {
		t.Fatalf("vectors: %d auth, %d sender lists, %d frames", len(vf.Auth), len(vf.Senders), len(vf.Frames))
	}
	listHash := map[string]string{}
	for _, v := range vf.Senders {
		listHash[v.Name] = v.HashHex
	}
	for _, v := range vf.Auth {
		if h, ok := listHash[v.SendersList]; !ok || h != v.SendersHash {
			t.Errorf("%s: the senders hash is not that of the list %q", v.Name, v.SendersList)
		}
		var p mailbox.AuthV2Params
		p.RelayTime = v.RelayTime
		copy(p.RelayKey[:], unhex(t, v.RelayKey))
		copy(p.ClientNodeKey[:], unhex(t, v.ClientKey))
		copy(p.Nonce[:], unhex(t, v.Nonce))
		copy(p.Fingerprint[:], unhex(t, v.Fingerprint))
		copy(p.BindingHash[:], unhex(t, v.BindingHash))
		copy(p.SendersHash[:], unhex(t, v.SendersHash))
		b, err := mailbox.AuthBytesV2(p)
		if err != nil || x(b) != v.BytesHex {
			t.Errorf("%s: bytes %x, %v", v.Name, b, err)
		}
		if !ed25519.Verify(unhex(t, v.PublicHex), b, unhex(t, v.SignatureHex)) {
			t.Errorf("%s: the signature does not verify", v.Name)
		}
	}
	for _, v := range vf.Senders {
		var keys []mailbox.WalletKey
		for _, k := range v.Keys {
			var wkey mailbox.WalletKey
			copy(wkey[:], unhex(t, k))
			keys = append(keys, wkey)
		}
		h, err := mailbox.SendersHash(keys)
		if err != nil || x(h[:]) != v.HashHex {
			t.Errorf("%s: hash %x, %v", v.Name, h, err)
		}
		// By hand: the hash of the array of byte strings.
		enc := []byte{0x80 | byte(len(keys))}
		if len(keys) >= 24 {
			enc = []byte{0x98, byte(len(keys))}
		}
		for _, k := range keys {
			enc = append(enc, 0x58, 28)
			enc = append(enc, k[:]...)
		}
		if blake2b.Sum256(enc) != h {
			t.Errorf("%s: the hand-written array hashes differently", v.Name)
		}
	}
	for _, v := range vf.Frames {
		c := unhex(t, v.CBORHex)
		st, ok := stageNames[v.Stage]
		if !ok || (v.Side != "client" && v.Side != "relay") {
			t.Fatalf("%s: stage %q side %q", v.Name, v.Stage, v.Side)
		}
		m, err := decodeIn(where{st, v.Side == "client"}, c)
		if err != nil {
			t.Errorf("%s: %v", v.Name, err)
			continue
		}
		if uint(m.Type()) != v.Type {
			t.Errorf("%s: type %d", v.Name, m.Type())
		}
		if again, err := reencode(m); err != nil || !bytes.Equal(again, c) {
			t.Errorf("%s: re-encode", v.Name)
		}
		if a, ok := m.(mailbox.AuthV2); ok && a.Fingerprint != a.Keys.Fingerprint() {
			t.Errorf("%s: the fingerprint is not that of the device keys", v.Name)
		}
		fr := unhex(t, v.FrameHex)
		if binary.BigEndian.Uint32(fr) != uint32(len(c)) || !bytes.Equal(fr[4:], c) {
			t.Errorf("%s: frame", v.Name)
		}
		if body, err := mailbox.ReadHeaderFrame(bytes.NewReader(fr)); err != nil || !bytes.Equal(body, c) {
			t.Errorf("%s: ReadHeaderFrame: %v", v.Name, err)
		}
	}
}
