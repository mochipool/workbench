package cose

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// The vectors are what cardano-signer 1.35.0 wrote for the public test phrase
// (payment, stake, pool and Calidus keys at their cardano-signer paths); the
// parity tests in spo/test/parity compare fresh signatures byte for byte.

func h(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func b224(b []byte) []byte { x := Blake2b224(b); return x[:] }

const (
	payPub   = "63c5d69570349e4233a0575811464f0e8a3fd329abe76e9bdc3d3f1b95982179"
	baseAddr = "0000b7847c89d5721592fc0cc8932f50a8f8258b39b93861140a1b99fbc2f45a16a6685616e566c00fc081fe59f8bd7ab679ee15e9ce203446"
	stakePub = "366598ec425ab8140830c4b5f91716d0f7b113fd7013ef3c90487e9dd1535437"
	poolPub  = "94ad4dc48eee029c3a342d7de7302eb9447e19282428bb6d78d70086dabffc5c"
)

// The COSE_Sign1 and COSE_Key of "hello" signed with the payment key for a
// testnet base address: protected {1: -8, "address": ...}, unprotected
// {"hashed": false}, the data as payload.
//
// spec: SPO-15-EXT-005
func TestCip8LayoutMatchesCardanoSigner(t *testing.T) {
	sig := h(t, "f4c5f288a4a944581c38a9fefc9773d70f0d6e525b65e493a0f40b994a500dd19dcade6e6c57193c74cf5369bd2d2f44c953469615f5ad7e471904e50512b205")
	s := Sign1{Protected: ProtectedHeader(h(t, baseAddr)), Payload: []byte("hello"), Signature: sig}
	const wantSign1 = "845846a20127676164647265737358390000b7847c89d5721592fc0cc8932f50a8f8258b39b93861140a1b99fbc2f45a16a6685616e566c00fc081fe59f8bd7ab679ee15e9ce203446a166686173686564f44568656c6c6f5840f4c5f288a4a944581c38a9fefc9773d70f0d6e525b65e493a0f40b994a500dd19dcade6e6c57193c74cf5369bd2d2f44c953469615f5ad7e471904e50512b205"
	if got := hex.EncodeToString(s.Encode()); got != wantSign1 {
		t.Errorf("COSE_Sign1\n got  %s\n want %s", got, wantSign1)
	}
	if got, want := hex.EncodeToString(EncodeKey(h(t, payPub))), "a401010327200621582063c5d69570349e4233a0575811464f0e8a3fd329abe76e9bdc3d3f1b95982179"; got != want {
		t.Errorf("COSE_Key\n got  %s\n want %s", got, want)
	}
	v, err := VerifyCip8(h(t, wantSign1), EncodeKey(h(t, payPub)), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if string(v.Payload) != "hello" || v.Hashed || hex.EncodeToString(v.Address) != baseAddr {
		t.Errorf("verified: %+v", v)
	}
	// The data may be given when the message does not carry it, and must
	// agree when it does.
	if _, err := VerifyCip8(h(t, wantSign1), EncodeKey(h(t, payPub)), []byte("hello"), true); err != nil {
		t.Error(err)
	}
	if _, err := VerifyCip8(h(t, wantSign1), EncodeKey(h(t, payPub)), []byte("other"), true); err == nil {
		t.Error("another data verified")
	}
}

// With hashed the payload is the 28-byte blake2b-224 of the data and the flag
// is true; the signed structure uses the hash.
func TestCip8HashedPayload(t *testing.T) {
	if got := hex.EncodeToString(PayloadFor([]byte("hello"), true)); got != "a4963e4ea2aa9b4120672abfc4c4299ba365368fa5a3910d5c559fc5" {
		t.Errorf("hashed payload %s", got)
	}
	if got := PayloadFor([]byte("hello"), false); string(got) != "hello" {
		t.Error("unhashed payload changed")
	}
	// A message signed over the hash verifies; the unprotected flag is read.
	pub, priv, _ := ed25519.GenerateKey(nil)
	addr := append([]byte{0x60}, b224(pub)...)
	prot := ProtectedHeader(addr)
	payload := PayloadFor([]byte("data"), true)
	s := Sign1{Protected: prot, Hashed: true, Payload: payload, Signature: ed25519.Sign(priv, SigStructure(prot, payload))}
	v, err := VerifyCip8(s.Encode(), EncodeKey(pub), []byte("data"), true)
	if err != nil || !v.Hashed {
		t.Fatalf("%v %+v", err, v)
	}
	if !bytes.Contains(s.Encode(), []byte{0xa1, 0x66, 'h', 'a', 's', 'h', 'e', 'd', 0xf5}) {
		t.Error("the hashed flag is not the boolean true in the map")
	}
}

// The hash check: the key must belong to the address, a stake key to a stake
// or a base address, a payment key not to a stake address.
func TestKeyBelongsToAddress(t *testing.T) {
	pay, stake := h(t, payPub), h(t, stakePub)
	base := h(t, baseAddr)
	reward := append([]byte{0xe0}, b224(stake)...)
	if !KeyBelongsToAddress(base, pay) || !KeyBelongsToAddress(base, stake) {
		t.Error("a base address belongs to its payment and its stake key")
	}
	if !KeyBelongsToAddress(reward, stake) || KeyBelongsToAddress(reward, pay) {
		t.Error("a reward address belongs to its stake key only")
	}
	if KeyBelongsToAddress(base, h(t, poolPub)) {
		t.Error("an unrelated key matched")
	}
	if !KeyBelongsToAddress(b224(h(t, poolPub)), h(t, poolPub)) {
		t.Error("a bare 28-byte pool id matches its key")
	}
}

func TestVerifyCip8Refusals(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	addr := append([]byte{0x60}, b224(pub)...)
	prot := ProtectedHeader(addr)
	good := Sign1{Protected: prot, Payload: []byte("m"), Signature: ed25519.Sign(priv, SigStructure(prot, []byte("m")))}
	if _, err := VerifyCip8(good.Encode(), EncodeKey(pub), nil, true); err != nil {
		t.Fatal(err)
	}
	bad := good
	bad.Payload = []byte("n")
	if _, err := VerifyCip8(bad.Encode(), EncodeKey(pub), nil, true); err != ErrSignature {
		t.Errorf("tampered payload: %v", err)
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if _, err := VerifyCip8(good.Encode(), EncodeKey(other), nil, false); err != ErrSignature {
		t.Errorf("another key: %v", err)
	}
	if _, err := VerifyCip8(good.Encode(), EncodeKey(other), nil, true); err == nil {
		t.Error("another key verified")
	}
	for _, garbage := range [][]byte{nil, {0x80}, {0x84, 0x40}, h(t, "9f"), bytes.Repeat([]byte{0x81}, 40)} {
		if _, err := VerifyCip8(garbage, EncodeKey(pub), nil, false); err == nil {
			t.Errorf("garbage %x verified", garbage)
		}
	}
	if _, err := ParseKey(h(t, "a401010327200621582063")); err == nil {
		t.Error("a truncated COSE_Key parsed")
	}
}

// The single-key registration of a stake key: label 61284 with the delegation
// array, stake key, address, nonce and purpose, label 61285 with the witness.
//
// spec: SPO-09a-OUT-006, SPO-09a-INV-003
func TestCip36LayoutMatchesCardanoSigner(t *testing.T) {
	reg := Cip36{Address: h(t, baseAddr), Nonce: 12345}
	copy(reg.StakePub[:], h(t, stakePub))
	vote := Delegation{Weight: 1}
	copy(vote.VotePub[:], h(t, "d1629703c24ccacdb6c4a17c7d39d83ad31ed42c3474f5e027df5564b9f85463"))
	reg.Delegations = []Delegation{vote}
	if got := reg.SigningHash(); hex.EncodeToString(got[:]) != "b6c7c5b68055968aab37909ab01b15218c370d3c93bdcc8e49392000c3c80b2f" {
		t.Errorf("signing hash %x", got)
	}
	sig := h(t, "5463faf0db88191c771c22bf085f2ba0b149b29a52f54c2990028c19e78f17e4591da7c9f5d7251950fc27d15440832ca2a4c7fa8de2c5fa2548d2e6e2295003")
	const want = "a219ef64a50181825820d1629703c24ccacdb6c4a17c7d39d83ad31ed42c3474f5e027df5564b9f8546301025820366598ec425ab8140830c4b5f91716d0f7b113fd7013ef3c90487e9dd15354370358390000b7847c89d5721592fc0cc8932f50a8f8258b39b93861140a1b99fbc2f45a16a6685616e566c00fc081fe59f8bd7ab679ee15e9ce20344604193039050019ef65a10158405463faf0db88191c771c22bf085f2ba0b149b29a52f54c2990028c19e78f17e4591da7c9f5d7251950fc27d15440832ca2a4c7fa8de2c5fa2548d2e6e2295003"
	if got := hex.EncodeToString(reg.Metadata(sig)); got != want {
		t.Errorf("metadata\n got  %s\n want %s", got, want)
	}
	if got, err := VerifyCip36(h(t, want)); err != nil || got.Nonce != 12345 || len(got.Delegations) != 1 || got.Delegations[0].Weight != 1 {
		t.Errorf("verify: %v %+v", err, got)
	}
	if !strings.HasPrefix(reg.MetadataJSON(sig), `{ "61284": { "1": [ [ "0xd162`) || !strings.HasSuffix(reg.MetadataJSON(sig), `5003" } }`) {
		t.Errorf("JSON %s", reg.MetadataJSON(sig))
	}
	// A tampered nonce breaks the witness.
	tampered := bytes.Replace(h(t, want), []byte{0x19, 0x30, 0x39}, []byte{0x19, 0x30, 0x3a}, 1)
	if _, err := VerifyCip36(tampered); err != ErrSignature {
		t.Errorf("tampered: %v", err)
	}
}

func TestCip36Validate(t *testing.T) {
	ok := Cip36{Delegations: []Delegation{{Weight: 1}}, Address: []byte{0x00, 1}}
	if err := ok.Validate(); err != nil {
		t.Error(err)
	}
	for name, r := range map[string]Cip36{
		"no key":      {Address: []byte{0x00}},
		"zero weight": {Delegations: []Delegation{{Weight: 0}, {Weight: 0}}, Address: []byte{0x00}},
		"no address":  {Delegations: []Delegation{{Weight: 1}}},
		"stake addr":  {Delegations: []Delegation{{Weight: 1}}, Address: []byte{0xe0}},
	} {
		if r.Validate() == nil {
			t.Errorf("%s validates", name)
		}
	}
}

// The Calidus registration: payload, payload hash, witness over the hash with
// the pool id as protected address, metadata with 0 for the hashed flag.
//
// spec: SPO-15-INV-005, SPO-15-INV-006, SPO-15-OUT-003, SPO-15-INV-004
func TestCip88LayoutMatchesCardanoSigner(t *testing.T) {
	reg := Cip88{Nonce: 777}
	copy(reg.PoolID[:], h(t, "3311c585ffc66620021527ffca16c8c993b0452c410cb3c51cd017aa"))
	copy(reg.CalidusPub[:], h(t, payPub))
	if got, want := hex.EncodeToString(reg.Payload()), "a5018201581c3311c585ffc66620021527ffca16c8c993b0452c410cb3c51cd017aa02800381020419030907582063c5d69570349e4233a0575811464f0e8a3fd329abe76e9bdc3d3f1b95982179"; got != want {
		t.Errorf("payload\n got  %s\n want %s", got, want)
	}
	if got := reg.PayloadHash(); hex.EncodeToString(got[:]) != "595c54812cd1cb647fbd014246e9f6592aa097104788f92ea0068ea5c5564e26" {
		t.Errorf("payload hash %x", got)
	}
	sig := h(t, "b5a2ec6a5d27110986eb7a2cc44eba94dcccc9708b303eb898ade74ec8f2fd2f60499e8dca4acf14d7553e49a217f5b3fec47458016fce1370df054a4df61c0b")
	const want = "a1190363a3000201a5018201581c3311c585ffc66620021527ffca16c8c993b0452c410cb3c51cd017aa02800381020419030907582063c5d69570349e4233a0575811464f0e8a3fd329abe76e9bdc3d3f1b959821790281a201a401010327200621582094ad4dc48eee029c3a342d7de7302eb9447e19282428bb6d78d70086dabffc5c02845829a201276761646472657373581c3311c585ffc66620021527ffca16c8c993b0452c410cb3c51cd017aa005820595c54812cd1cb647fbd014246e9f6592aa097104788f92ea0068ea5c5564e265840b5a2ec6a5d27110986eb7a2cc44eba94dcccc9708b303eb898ade74ec8f2fd2f60499e8dca4acf14d7553e49a217f5b3fec47458016fce1370df054a4df61c0b"
	got := reg.Metadata(h(t, poolPub), sig)
	if hex.EncodeToString(got) != want {
		t.Errorf("metadata\n got  %x\n want %s", got, want)
	}
	back, err := VerifyCip88(got)
	if err != nil || back != reg {
		t.Errorf("verify: %v %+v", err, back)
	}
	wantJSON := `{"867":{"0":2,"1":{"1":[1,"0x3311c585ffc66620021527ffca16c8c993b0452c410cb3c51cd017aa"],"2":[],"3":[2],"4":777,"7":"0x63c5d69570349e4233a0575811464f0e8a3fd329abe76e9bdc3d3f1b95982179"},"2":[{"1":{"1":1,"3":-8,"-1":6,"-2":"0x94ad4dc48eee029c3a342d7de7302eb9447e19282428bb6d78d70086dabffc5c"},"2":["0xa201276761646472657373581c3311c585ffc66620021527ffca16c8c993b0452c410cb3c51cd017aa",0,"0x595c54812cd1cb647fbd014246e9f6592aa097104788f92ea0068ea5c5564e26","0xb5a2ec6a5d27110986eb7a2cc44eba94dcccc9708b303eb898ade74ec8f2fd2f60499e8dca4acf14d7553e49a217f5b3fec47458016fce1370df054a4df61c0b"]}]}}`
	if j := reg.MetadataJSON(h(t, poolPub), sig); j != wantJSON {
		t.Errorf("JSON\n got  %s\n want %s", j, wantJSON)
	}
	// The registration file is the JSON indented by two spaces.
	file, err := RegistrationFile(wantJSON)
	if err != nil || !strings.HasPrefix(string(file), "{\n  \"867\": {\n    \"0\": 2,\n    \"1\": {\n      \"1\": [\n        1,\n") || !strings.HasSuffix(string(file), "}\n") {
		t.Errorf("registration file %q (%v)", file, err)
	}
	// The witness covers the payload: another nonce, same signature, fails.
	other := reg
	other.Nonce = 778
	if _, err := VerifyCip88(other.Metadata(h(t, poolPub), sig)); err == nil {
		t.Error("a witness for another payload verified")
	}
	// The cold key must be the pool's.
	if _, err := VerifyCip88(reg.Metadata(h(t, payPub), sig)); err == nil {
		t.Error("another cold key verified")
	}
}

// The Calidus id: header a1 and the blake2b-224 hash of the public key, bech32
// with the prefix calidus; the id of the public test phrase's Calidus key.
//
// spec: SPO-15-INV-004
func TestCalidusID(t *testing.T) {
	id, err := CalidusID(h(t, payPub))
	if err != nil || id != "calidus15yqt0pru382hy9vjlsxv3ye02z50sfvt8xunscg5pgden7czfjdjq" {
		t.Errorf("%s %v", id, err)
	}
	if hex.EncodeToString(CalidusIDBytes(h(t, payPub))) != "a100b7847c89d5721592fc0cc8932f50a8f8258b39b93861140a1b99fb" {
		t.Error("id bytes")
	}
	hash, err := ParseCalidusID(id)
	if err != nil || hex.EncodeToString(hash[:]) != "00b7847c89d5721592fc0cc8932f50a8f8258b39b93861140a1b99fb" {
		t.Errorf("parse: %x %v", hash, err)
	}
	if _, err := ParseCalidusID("pool1xvgutp0lcenzqqs4yllu59kgexfmq3fvgyxt83gu6qt65g5nd64"); err == nil {
		t.Error("a pool id parsed as a Calidus id")
	}
	if _, err := CalidusID(make([]byte, 31)); err == nil {
		t.Error("a short key")
	}
}

// The default nonce of cardano-signer: the mainnet slot of the machine time.
// Observed: at Unix time 1794832332 it chose 203266041.
//
// spec: SPO-15-EXT-003
func TestMainnetSlotAt(t *testing.T) {
	if got := MainnetSlotAt(time.Unix(1794832332, 0)); got != 203266041 {
		t.Errorf("slot %d", got)
	}
	if got := MainnetSlotAt(time.Unix(1596059091, 0)); got != 4492800 {
		t.Errorf("shelley start slot %d", got)
	}
}

func TestDecoderRefusals(t *testing.T) {
	for _, in := range []string{"5f", "bf", "9f", "c0", "1c", "a1", "8201", "4301", ""} {
		if _, err := decodeAll(h(t, in)); err == nil {
			t.Errorf("%q decoded", in)
		}
	}
	if _, err := decodeAll(h(t, "01ff")); err == nil {
		t.Error("trailing bytes accepted")
	}
}

func TestVKeyFromEnvelope(t *testing.T) {
	pub, err := VKeyFromEnvelope([]byte(`{"type":"x","description":"y","cborHex":"5820` + payPub + `"}`))
	if err != nil || hex.EncodeToString(pub[:]) != payPub {
		t.Errorf("%x %v", pub, err)
	}
	for _, bad := range []string{`{"cborHex":"5840aa"}`, `nope`, `{"cborHex":"zz"}`} {
		if _, err := VKeyFromEnvelope([]byte(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
