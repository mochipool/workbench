package native

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/bip32"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/porttest"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

const (
	testAddr = "addr_test1vql6v54azljgm6npwncg248rd3r0e7dsr9mvjd7xp30hc4g995pn0"
	testTx   = "6b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c"
)

func testParams() chain.ProtocolParameters {
	return chain.ProtocolParameters{TxFeePerByte: 44, TxFeeFixed: 155381, CoinsPerUTxOByte: 4310, MaxTxSize: 16384, ProtocolMajor: 11}
}

func oneInputSpec() txbuild.BodySpec {
	id, _ := chain.ParseTxID(testTx)
	return txbuild.BodySpec{
		Inputs:  []chain.Utxo{{TxID: id, Index: 0, Lovelace: 100_000_000}},
		Outputs: []txbuild.Output{{Address: testAddr, Lovelace: 5_000_000}, {Address: testAddr, Lovelace: 94_800_000}},
		Fee:     200_000, TTL: 1000,
	}
}

// A body recorded from cardano-cli 11.2.3.0 `build-raw` for the same inputs
// (spo/test/parity compares the two on every run; this vector keeps the
// encoding pinned where the oracle is not available). Tag 258 on the inputs,
// the legacy array form of the outputs, ascending keys, the empty witness
// set, the valid flag and null auxiliary data.
//
// spec: SPO-Ptx-EXT-001, SPO-Ptx-EXT-004
func TestBodyEncodingGolden(t *testing.T) {
	spec := oneInputSpec()
	spec.Outputs = []txbuild.Output{{Address: testAddr, Lovelace: 5_000_000}, {Address: testAddr, Lovelace: 1_000_000,
		Assets: []chain.AssetAmount{{Asset: chain.AssetID{Name: []byte("AB")}, Quantity: 3}}}}
	// cardano-cli --tx-out addr+5000000 --tx-out "addr+1000000+3 aa..aa.4142".
	spec.Outputs[1].Assets[0].Asset.Policy = [28]byte{0: 0xaa, 27: 0xaa}
	b, err := Ledger{}.BuildBody(spec)
	if err != nil {
		t.Fatal(err)
	}
	const want = "84a400d90102818258206b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c00018282581d603fa652bd17e48dea6174f08554e36c46fcf9b01976c937c60c5f7c551a004c4b4082581d603fa652bd17e48dea6174f08554e36c46fcf9b01976c937c60c5f7c55821a000f4240a1581caa0000000000000000000000000000000000000000000000000000aaa142414203021a00030d40031903e8a0f5f6"
	if got := hex.EncodeToString(b.CBOR); got != want {
		t.Errorf("body differs from cardano-cli's\n  want %s\n  got  %s", want, got)
	}
	// The id is the blake2b-256 of the body map, as the library computes it.
	id, err := bursa.TransactionID(b.CBOR)
	if err != nil || id != b.ID.String() {
		t.Errorf("id %s, library %s (%v)", b.ID, id, err)
	}
}

// Properties of the body: the same spec gives the same bytes, inputs are
// sorted whatever their order, a duplicate input is refused, assets are
// sorted, and a message adds the auxiliary data and its hash.
//
// spec: SPO-Ptx-INV-002, SPO-Ptx-EXT-001, SPO-Pparam-OUT-001
func TestBuildBodyProperties(t *testing.T) {
	spec := oneInputSpec()
	a, _ := Ledger{}.BuildBody(spec)
	b, _ := Ledger{}.BuildBody(spec)
	if string(a.CBOR) != string(b.CBOR) {
		t.Error("the same spec gave different bodies")
	}
	i1, i2 := chain.TxID{1}, chain.TxID{2}
	fwd := spec
	fwd.Inputs = []chain.Utxo{{TxID: i1, Index: 5, Lovelace: 1}, {TxID: i2, Index: 0, Lovelace: 1}, {TxID: i1, Index: 1, Lovelace: 1}}
	rev := spec
	rev.Inputs = []chain.Utxo{fwd.Inputs[2], fwd.Inputs[1], fwd.Inputs[0]}
	x, err1 := Ledger{}.BuildBody(fwd)
	y, err2 := Ledger{}.BuildBody(rev)
	if err1 != nil || err2 != nil || string(x.CBOR) != string(y.CBOR) {
		t.Errorf("the order of the inputs changed the body: %v %v", err1, err2)
	}
	dup := spec
	dup.Inputs = []chain.Utxo{fwd.Inputs[0], fwd.Inputs[0]}
	if _, err := (Ledger{}).BuildBody(dup); err == nil {
		t.Error("a duplicate input was accepted")
	}
	if _, err := (Ledger{}).BuildBody(txbuild.BodySpec{}); err == nil {
		t.Error("a body without inputs was accepted")
	}
	big := spec
	big.Inputs = []chain.Utxo{{TxID: i1, Index: 70000, Lovelace: 1}}
	if _, err := (Ledger{}).BuildBody(big); err == nil {
		t.Error("an output index above 65535 was accepted")
	}
	msg := spec
	msg.Message = []string{"hello", "wörld | x"}
	m, err := Ledger{}.BuildBody(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(hex.EncodeToString(m.CBOR), "d90103a100a11902a2a1636d7367") {
		t.Errorf("no CIP-20 auxiliary data in %x", m.CBOR)
	}
	if m.ID == a.ID {
		t.Error("the message did not change the body id")
	}
	// An unparseable address is refused, not encoded.
	bad := spec
	bad.Outputs = []txbuild.Output{{Address: "addr_test1bad", Lovelace: 1}}
	if _, err := (Ledger{}).BuildBody(bad); err == nil {
		t.Error("a bad output address was accepted")
	}
}

// The recorded cardano-cli minimum for a plain enterprise-address output
// with coinsPerUTxOByte 4310: (160 + 37) * 4310. It does not depend on the
// lovelace amount given.
//
// spec: SPO-Ptx-EXT-003, SPO-Cutxo-INV-006, SPO-Cutxo-INV-007, SPO-Cutxo-INV-010
func TestMinOutputIsTheLedgersArrayForm(t *testing.T) {
	for _, l := range []chain.Lovelace{0, 5000, 1_000_000, 9_000_000_000} {
		got, err := Ledger{}.MinOutput(testParams(), txbuild.Output{Address: testAddr, Lovelace: l})
		if err != nil || got != 849_070 {
			t.Errorf("min output at %d lovelace = %d, %v; cardano-cli says 849070", l, got, err)
		}
	}
}

// spec: SPO-Ptx-EXT-002
func TestFeeUsesTheWitnessedSizeWithoutTheValidFlag(t *testing.T) {
	b, _ := Ledger{}.BuildBody(oneInputSpec())
	size, err := Ledger{}.EstimateSize(b, 1)
	if err != nil {
		t.Fatal(err)
	}
	fee, _ := Ledger{}.EstimateFee(testParams(), b, 1)
	// 44 per byte, 155381 fixed, and one byte (is_valid) not charged for.
	if want := chain.Lovelace(44*(size-1) + 155381); fee != want {
		t.Errorf("fee %d, want %d", fee, want)
	}
	if size <= len(b.CBOR) {
		t.Errorf("the estimate %d does not include the witness (unsigned %d)", size, len(b.CBOR))
	}
	// More witnesses cost more.
	f2, _ := Ledger{}.EstimateFee(testParams(), b, 2)
	if f2 <= fee {
		t.Errorf("two witnesses cost %d, one %d", f2, fee)
	}
}

// spec: SPO-Caddr-PRE-001, SPO-Caddr-OUT-002
func TestInspectAddress(t *testing.T) {
	info, err := Ledger{}.InspectAddress(testAddr)
	if err != nil || info.Kind != ports.AddrEnterprise || info.NetworkID != ports.NetworkTestnet || info.PaymentKeyHash == nil || info.PaymentIsScript {
		t.Errorf("%+v %v", info, err)
	}
	for _, bad := range []chain.Address{"", "addr_test1xyz", chain.Address(strings.ToUpper(string(testAddr))[:20])} {
		if _, err := (Ledger{}).InspectAddress(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// ---- witnesses ----------------------------------------------------------------

// vkeyFile is a verification key envelope of a raw key.
func vkeyFile(pub []byte) string {
	return `{"type":"PaymentVerificationKeyShelley_ed25519","description":"x","cborHex":"5820` + hex.EncodeToString(pub) + `"}`
}

// vaultDir writes files in a directory store. A signing key file that has no
// verification key beside it gets one of a key made from its name, so each key
// of the vault has its own identity (a key is found by identity now).
func vaultDir(t *testing.T, files map[string]string) *plainstore.Store {
	t.Helper()
	dir := t.TempDir()
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o400); err != nil {
			t.Fatal(err)
		}
	}
	for n := range files {
		if stem, ok := strings.CutSuffix(n, ".skey"); ok {
			if _, have := files[stem+".vkey"]; !have {
				sum := sha256.Sum256([]byte(n))
				pub := ed25519.NewKeyFromSeed(sum[:]).Public().(ed25519.PublicKey)
				if err := os.WriteFile(filepath.Join(dir, stem+".vkey"), []byte(vkeyFile(pub)), 0o400); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	st, err := plainstore.OpenTestnet(dir)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func someBody(t *testing.T) txbuild.TxBody {
	b, err := Ledger{}.BuildBody(oneInputSpec())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func keyRef(t *testing.T, st ports.Store, role custody.Role, owner string) custody.KeyRef {
	t.Helper()
	return porttest.Key(t, st, role, owner)
}

// A normal and an extended payment key, and a stake key, witness a body; the
// witness verifies with the key hash of the key.
//
// spec: SPO-Ptx-EXT-006, SPO-Ptx-SEC-001, SPO-Pfiles-OUT-002
func TestVaultSignerWitnesses(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(7 * i)
	}
	normal := `{"type":"PaymentSigningKeyShelley_ed25519","description":"Payment Signing Key","cborHex":"5820` + hex.EncodeToString(seed) + `"}`
	stake := `{"type":"StakeSigningKeyShelley_ed25519","description":"Stake Signing Key","cborHex":"5820` + hex.EncodeToString(seed) + `"}`
	xprv := bip32.FromBip39Entropy(make([]byte, 32), nil)
	ext, err := bursa.GetPaymentExtendedSKey(xprv)
	if err != nil {
		t.Fatal(err)
	}
	extJSON, _ := json.Marshal(ext)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)

	vault := vaultDir(t, map[string]string{"n.skey": normal, "e.skey": string(extJSON), "s.staking.skey": stake,
		"n.vkey": vkeyFile(pub), "e.vkey": vkeyFile(xprv.PublicKey()), "s.staking.vkey": vkeyFile(pub)})
	signer := VaultSigner{Vault: vault}
	body := someBody(t)
	for _, tc := range []struct {
		name  string
		key   custody.KeyRef
		vkey  []byte
		hash  txbuild.KeyHash
		check bool
	}{
		{"normal payment key", keyRef(t, vault, custody.RolePayment, "n"), pub, txbuild.HashKey(pub), true},
		{"extended payment key", keyRef(t, vault, custody.RolePayment, "e"), xprv.PublicKey(), txbuild.HashKey(xprv.PublicKey()), true},
		{"stake key of a wallet", keyRef(t, vault, custody.RoleStake, "s"), pub, txbuild.HashKey(pub), true},
	} {
		w, err := signer.Witness(context.Background(), tc.key, body)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if hex.EncodeToString(w.VKey[:]) != hex.EncodeToString(tc.vkey) {
			t.Errorf("%s: the witness key is not the key's", tc.name)
		}
		if err := txbuild.VerifyWitness(body, w, tc.hash); err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	// Ed25519 is deterministic: the same body gives the same witness.
	w1, _ := signer.Witness(context.Background(), keyRef(t, vault, custody.RolePayment, "n"), body)
	w2, _ := signer.Witness(context.Background(), keyRef(t, vault, custody.RolePayment, "n"), body)
	if w1 != w2 {
		t.Error("two witnesses over the same body differ")
	}
}

// Refusals: a missing key, a key of another role, a gpg-encrypted key (the
// `enc` form of SPO-Pfiles-OUT-003), a wrong length, an extended key whose
// public half does not match. None of the messages holds key material.
//
// spec: SPO-Ptx-EXT-006, SPO-Pfiles-OUT-003, SPO-Ptx-SEC-001
func TestVaultSignerRefusals(t *testing.T) {
	seed := strings.Repeat("11", 32)
	good := `{"type":"PaymentSigningKeyShelley_ed25519","description":"x","cborHex":"5820` + seed + `"}`
	files := map[string]string{
		"good.skey":    good,
		"stakey.skey":  `{"type":"StakeSigningKeyShelley_ed25519","description":"x","cborHex":"5820` + seed + `"}`,
		"enc.skey":     `{"type":"PaymentSigningKeyShelley_ed25519","description":"Encrypted Payment Signing Key","encrHex":"` + strings.Repeat("ab", 40) + `"}`,
		"short.skey":   `{"type":"PaymentSigningKeyShelley_ed25519","description":"x","cborHex":"5820` + seed[:60] + `"}`,
		"badext.skey":  `{"type":"PaymentExtendedSigningKeyShelley_ed25519_bip32","description":"x","cborHex":"5880` + strings.Repeat("22", 128) + `"}`,
		"kes.skey":     `{"type":"KesSigningKey_ed25519_kes_2^6","description":"x","cborHex":"5820` + seed + `"}`,
		"notjson.skey": `not json`,
		// a verification key and no signing key in the vault
		"nokey.vkey": vkeyFile(make([]byte, 32)),
	}
	vault := vaultDir(t, files)
	signer := VaultSigner{Vault: vault}
	body := someBody(t)
	for name, want := range map[string]string{"nokey": "holds no signing key", "stakey": "unsupported signing key type", "enc": "gpg-encrypted",
		"short": "not a", "badext": "does not match", "kes": "unsupported signing key type", "notjson": "not a text envelope"} {
		_, err := signer.Witness(context.Background(), keyRef(t, vault, custody.RolePayment, name), body)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", name, err, want)
			continue
		}
		if strings.Contains(err.Error(), seed[:20]) || strings.Contains(err.Error(), "2222222222") {
			t.Errorf("%s: the error holds key material: %v", name, err)
		}
	}
	// A role the vault signer does not witness with.
	if _, err := signer.Witness(context.Background(), custody.KeyRef{Role: custody.RoleKES, Identity: keyRef(t, vault, custody.RolePayment, "good").Identity}, body); err == nil {
		t.Error("a KES key witnessed a transaction")
	}
}

// The profile and the interfaces agree: a signer that claims to witness
// transactions implements TxWitnesser, and the check catches one that does not.
//
// spec: SPO-Ptx-INV-008
func TestVaultSignerConformsToItsProfile(t *testing.T) {
	if err := ports.CheckSigner(VaultSigner{}); err != nil {
		t.Error(err)
	}
	p := VaultSigner{}.Profile()
	for _, role := range []custody.Role{custody.RolePayment, custody.RoleStake} {
		if reason := p.Check(custody.Demand{Role: role, Operation: custody.OpWitnessTx,
			Features: custody.NewFeatures(custody.FeatMultiAssetOutput, custody.FeatMetadata, custody.FeatPlutusScript)}); reason != "" {
			t.Errorf("%s: a software signer has no feature limit: %s", role, reason)
		}
	}
	if reason := p.Check(custody.Demand{Role: custody.RoleVRF, Operation: custody.OpWitnessTx}); reason == "" {
		t.Error("the vault signer claims to witness with a VRF key")
	}
	claimsMore := claimsOnly{custody.NewProfile("liar").Allow(custody.RolePayment, custody.OpWitnessTx)}
	if err := ports.CheckSigner(claimsMore); err == nil {
		t.Error("a signer claiming OpWitnessTx without TxWitnesser passed the check")
	}
}

type claimsOnly struct{ p custody.Profile }

func (c claimsOnly) Profile() custody.Profile { return c.p }

// Assemble refuses an empty witness list and keeps the id.
func TestAssemble(t *testing.T) {
	body := someBody(t)
	if _, err := (Ledger{}).Assemble(body, nil); err == nil {
		t.Error("assembled without witnesses")
	}
	var w txbuild.Witness
	signed, err := Ledger{}.Assemble(body, []txbuild.Witness{w})
	if err != nil || signed.ID != body.ID || len(signed.CBOR) <= len(body.CBOR) {
		t.Errorf("%v", err)
	}
}

// The vault signer is handed the body and rebuilds what it signs from it: a
// transaction id that is not the id of the bytes it was given is refused, and
// the signature is over the id of the bytes, never over a hash handed over
// (ADR 0010 decision 3). A key found by identity that is not the demanded key
// is refused too.
//
// spec: SPO-Xidentity-SEC-006
func TestVaultSignerSignsTheIdOfTheBodyItIsHanded(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(3 * i)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	vault := vaultDir(t, map[string]string{
		"n.skey": `{"type":"PaymentSigningKeyShelley_ed25519","description":"","cborHex":"5820` + hex.EncodeToString(seed) + `"}`,
		"n.vkey": vkeyFile(pub)})
	signer := VaultSigner{Vault: vault}
	key := keyRef(t, vault, custody.RolePayment, "n")
	body := someBody(t)
	forged := body
	forged.ID[0] ^= 1 // an id that is not the id of the bytes
	if _, err := signer.Witness(context.Background(), key, forged); err == nil {
		t.Error("a witness was made over an id that is not the id of the body")
	}
	w, err := signer.Witness(context.Background(), key, body)
	if err != nil {
		t.Fatal(err)
	}
	if err := txbuild.VerifyWitness(body, w, txbuild.HashKey(pub)); err != nil {
		t.Error(err)
	}
	// a body with no bytes cannot be witnessed
	if _, err := signer.Witness(context.Background(), key, txbuild.TxBody{ID: body.ID}); err == nil {
		t.Error("a witness was made with no body to read")
	}
	// the key found for the identity is the key demanded: a vault file whose
	// verification key is another key's is refused
	other := vaultDir(t, map[string]string{
		"n.skey": `{"type":"PaymentSigningKeyShelley_ed25519","description":"","cborHex":"5820` + hex.EncodeToString(seed) + `"}`,
		"n.vkey": vkeyFile(make([]byte, 32))})
	if _, err := (VaultSigner{Vault: other}).Witness(context.Background(), keyRef(t, other, custody.RolePayment, "n"), body); err == nil ||
		!strings.Contains(err.Error(), "another key") {
		t.Errorf("a vault key that is not the demanded key: %v", err)
	}
}
