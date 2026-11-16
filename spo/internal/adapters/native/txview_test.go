package native

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
)

func viewOf(t *testing.T, spec txbuild.BodySpec) (party.TxView, txbuild.TxBody) {
	t.Helper()
	b, err := Ledger{}.BuildBody(spec)
	if err != nil {
		t.Fatal(err)
	}
	body, err := TxViewer{}.BodyOf(b.CBOR)
	if err != nil {
		t.Fatal(err)
	}
	if h := blake2b.Sum256(body); h != [32]byte(b.ID) {
		t.Fatal("BodyOf: the hash of the body bytes is not the transaction id (SPO-Xparty-INV-020)")
	}
	v, err := TxViewer{}.View(body)
	if err != nil {
		t.Fatalf("View: %v", err)
	}
	return v, b
}

// A plain payment with an asset and a message: every input, output with its
// address, value and assets, the fee, the TTL and the auxiliary data hash.
// spec: SPO-Xparty-PR-002, SPO-Xparty-INV-020
func TestViewSend(t *testing.T) {
	spec := oneInputSpec()
	spec.Outputs[1].Assets = []chain.AssetAmount{{Asset: chain.AssetID{Policy: [28]byte{0: 0xaa}, Name: []byte("AB")}, Quantity: 3}}
	spec.Message = []string{"hello"}
	v, b := viewOf(t, spec)
	if len(v.Inputs) != 1 || v.Inputs[0].TxID != [32]byte(spec.Inputs[0].TxID) || v.Inputs[0].Index != 0 {
		t.Errorf("inputs %+v", v.Inputs)
	}
	if len(v.Outputs) != 2 || v.Outputs[0].Address != testAddr || v.Outputs[0].Lovelace != 5_000_000 || v.Outputs[1].Lovelace != 94_800_000 {
		t.Errorf("outputs %+v", v.Outputs)
	}
	if as := v.Outputs[1].Assets; len(as) != 1 || as[0].Quantity != 3 || string(as[0].Name) != "AB" || as[0].Policy[0] != 0xaa {
		t.Errorf("assets %+v", as)
	}
	if v.Fee != 200_000 || v.TTL == nil || *v.TTL != 1000 {
		t.Errorf("fee/ttl %d %v", v.Fee, v.TTL)
	}
	if v.AuxDataHash == nil || len(v.Certificates)+len(v.Withdrawals)+len(v.Mint) != 0 {
		t.Errorf("aux %v", v.AuxDataHash)
	}
	f := v.Features()
	if _, ok := f[custody.FeatMultiAssetOutput]; !ok {
		t.Error("no multi-asset feature")
	}
	if _, ok := f[custody.FeatMetadata]; !ok {
		t.Error("no metadata feature")
	}
	_ = b
}

// Stake certificates and a withdrawal.
// spec: SPO-Xparty-PR-002
func TestViewStakeCertificatesAndWithdrawal(t *testing.T) {
	spec := oneInputSpec()
	stk := stake.KeyHash{1, 2, 3}
	var certs []stake.Certificate
	for _, s := range []stake.Spec{
		{Kind: stake.CertRegistration, Stake: stk, Deposit: 2_000_000},
		{Kind: stake.CertPoolDelegation, Stake: stk, Pool: chain.PoolID{9}},
		{Kind: stake.CertVoteDelegation, Stake: stk, DRep: stake.DRep{Kind: stake.DRepAbstain}},
		{Kind: stake.CertDeregistration, Stake: stk, Deposit: 2_000_000},
	} {
		c, err := Ledger{}.BuildCertificate(s)
		if err != nil {
			t.Fatal(err)
		}
		certs = append(certs, c)
	}
	spec.Certificates = certs
	rew, err := Ledger{}.BuildStakeAddress(0, txbuild.KeyHash(stk))
	if err != nil {
		t.Fatal(err)
	}
	spec.Withdrawals = []txbuild.Withdrawal{{Reward: rew, Amount: 777}}
	v, _ := viewOf(t, spec)
	if len(v.Certificates) != 4 {
		t.Fatalf("certificates %+v", v.Certificates)
	}
	c := v.Certificates
	if c[0].Kind != party.CertStakeRegistration || c[0].Deposit == nil || *c[0].Deposit != 2_000_000 || c[0].Credential == "" {
		t.Errorf("registration %+v", c[0])
	}
	if c[1].Kind != party.CertStakeDelegation || !c[1].HasPool || c[1].Pool != [28]byte{9} {
		t.Errorf("delegation %+v", c[1])
	}
	if c[2].Kind != party.CertVoteDelegation || c[2].DRep != "always-abstain" {
		t.Errorf("vote delegation %+v", c[2])
	}
	if c[3].Kind != party.CertStakeDeregistration || *c[3].Deposit != 2_000_000 {
		t.Errorf("deregistration %+v", c[3])
	}
	if len(v.Withdrawals) != 1 || v.Withdrawals[0].Account != string(rew) || v.Withdrawals[0].Lovelace != 777 {
		t.Errorf("withdrawals %+v", v.Withdrawals)
	}
}

// A pool registration shows every field of the certificate, and a retirement
// its pool and epoch.
// spec: SPO-Xparty-PR-002
func TestViewPoolRegistrationAndRetirement(t *testing.T) {
	rs := sampleSpec()
	reg, err := Ledger{}.BuildPoolRegistration(rs)
	if err != nil {
		t.Fatal(err)
	}
	ret, err := Ledger{}.BuildPoolRetirement(pool.RetirementSpec{Pool: rs.Operator, Epoch: 77})
	if err != nil {
		t.Fatal(err)
	}
	spec := oneInputSpec()
	spec.Certificates = []stake.Certificate{reg.Attachment(500_000_000), ret.Attachment(0)}
	v, _ := viewOf(t, spec)
	if len(v.Certificates) != 2 || v.Certificates[0].PoolReg == nil {
		t.Fatalf("%+v", v.Certificates)
	}
	p := v.Certificates[0].PoolReg
	if p.Operator != [28]byte(rs.Operator) || p.VRFKeyHash != rs.VrfKeyHash || p.Pledge != 7 || p.Cost != 340_000_000 || p.MarginNum != 1 || p.MarginDen != 100 {
		t.Errorf("params %+v", p)
	}
	if len(p.Owners) != 3 || !p.HasMeta || p.MetaURL != "https://x.org/p.json" || p.MetaHash[0] != 0xee || p.RewardAccount == "" {
		t.Errorf("owners/meta %+v", p)
	}
	want := []party.ViewRelay{{Kind: "ipv4", Host: "203.0.113.7", Port: 3001, HasPort: true}, {Kind: "ipv6", Host: "2001:db8::1", Port: 6000, HasPort: true},
		{Kind: "dns", Host: "r.example.org", Port: 1, HasPort: true}, {Kind: "srv", Host: "_c._tcp.example.org"}}
	if len(p.Relays) != 4 {
		t.Fatalf("relays %+v", p.Relays)
	}
	for i, r := range want {
		if p.Relays[i] != r {
			t.Errorf("relay %d: %+v, want %+v", i, p.Relays[i], r)
		}
	}
	r := v.Certificates[1]
	if r.Kind != party.CertPoolRetirement || r.Pool != [28]byte(rs.Operator) || r.Epoch == nil || *r.Epoch != 77 {
		t.Errorf("retirement %+v", r)
	}
	if sp := party.ScopePartsOf(custody.RoleStake, v); len(sp.Pools) != 1 || sp.Pools[0] != chain.PoolID(rs.Operator).Bech32() || len(sp.Unscoped) != 0 {
		t.Errorf("the parts that name a pool: %+v", sp)
	}
	f := v.FeaturesFor(custody.RolePoolCold)
	if _, ok := f[custody.FeatPoolRegistrationOwner]; ok {
		t.Error("the cold key is asked for the owner mode")
	}
	if _, ok := f[custody.FeatPoolRegistrationOper]; !ok {
		t.Error("the cold key is not asked for the operator mode")
	}
	if _, ok := v.FeaturesFor(custody.RoleStake)[custody.FeatPoolRegistrationOper]; ok {
		t.Error("a stake key is asked for the operator mode")
	}
}

// A body with a key the viewer does not know fails: a signer never approves
// what it cannot display. The same for a duplicate key, an unknown
// certificate tag, and bytes that are not definite-length CBOR.
// spec: SPO-Xparty-PR-002, SPO-Xparty-PRE-006
func TestViewRefusesWhatItCannotDisplay(t *testing.T) {
	good, err := Ledger{}.BuildBody(oneInputSpec())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := TxViewer{}.BodyOf(good.CBOR)
	// The map header a4 becomes a5 and the key 99 with a value is appended.
	unknown := append([]byte{0xa5}, body[1:]...)
	unknown = append(unknown, 0x18, 99, 0x01)
	dup := append([]byte{0xa5}, body[1:]...)
	dup = append(dup, 0x02, 0x00) // key 2 (fee) twice
	badCert := append([]byte{0xa5}, body[1:]...)
	badCert = append(badCert, 0x04, 0x81, 0x82, 0x18, 0x63, 0x01) // certificates [[99, 1]]
	indef := append([]byte{0xbf}, body[1:]...)
	indef = append(indef, 0xff)
	for name, b := range map[string][]byte{"unknown key": unknown, "duplicate key": dup, "unknown certificate tag": badCert,
		"indefinite map": indef, "empty": nil, "not a map": {0x80}, "trailing bytes": append(append([]byte(nil), body...), 0)} {
		if _, err := (TxViewer{}).View(b); err == nil {
			t.Errorf("%s: the body was decoded", name)
		}
	}
	// The unknown key is reported as such.
	if _, err := (TxViewer{}).View(unknown); !errors.Is(err, ErrBodyView) || !bytes.Contains([]byte(err.Error()), []byte("key 99")) {
		t.Errorf("unknown key error: %v", err)
	}
	// Every strict prefix of a good body fails.
	for i := 0; i < len(body); i++ {
		if _, err := (TxViewer{}).View(body[:i]); err == nil {
			t.Fatalf("a %d-byte prefix of the body was decoded", i)
		}
	}
	// Text with a control character is refused.
	spec := oneInputSpec()
	rs := sampleSpec()
	rs.MetaURL = "https://x.org/\x1b[2Jp.json"
	if _, err := (Ledger{}).BuildPoolRegistration(rs); err == nil {
		c, _ := Ledger{}.BuildPoolRegistration(rs)
		spec.Certificates = []stake.Certificate{c.Attachment(1)}
		bb, err := Ledger{}.BuildBody(spec)
		if err != nil {
			t.Fatal(err)
		}
		bo, _ := TxViewer{}.BodyOf(bb.CBOR)
		if _, err := (TxViewer{}).View(bo); err == nil {
			t.Error("a URL with an escape sequence was displayed")
		}
	}
}

// BodyOf refuses what is not a transaction.
func TestBodyOfRefusesNonTransactions(t *testing.T) {
	for _, b := range [][]byte{nil, {0xa0}, {0x84, 0x01, 0x02, 0x03, 0x04}, {0x83, 0xa0, 0xa0, 0xf5}} {
		if _, err := (TxViewer{}).BodyOf(b); err == nil {
			t.Errorf("BodyOf(%x) succeeded", b)
		}
	}
}

// withKeys appends extra key/value pairs (each already CBOR) to a body map of
// fewer than 23 entries.
func withKeys(body []byte, extra ...[]byte) []byte {
	out := append([]byte{body[0] + byte(len(extra))}, body[1:]...)
	for _, e := range extra {
		out = append(out, e...)
	}
	return out
}

func goodBody(t *testing.T) []byte {
	t.Helper()
	good, err := Ledger{}.BuildBody(oneInputSpec())
	if err != nil {
		t.Fatal(err)
	}
	body, err := TxViewer{}.BodyOf(good.CBOR)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// ORACLE: the relay addresses of a registration built by the native builder
// (byte-equal to cardano-cli in the parity suite) are shown as the addresses
// that were put in. The wire bytes are checked against constants worked out
// from cardano-cli's output, not from this package's own code: 1.2.3.4 is
// 04030201 and 2001:db8::1 is b80d0120 00000000 00000000 01000000.
// spec: SPO-Xparty-PR-002
func TestViewRelayAddressOracle(t *testing.T) {
	rs := sampleSpec()
	rs.Relays = []pool.Relay{
		{Kind: pool.RelayIPv4, Host: "1.2.3.4", Port: 3001, HasPort: true},
		{Kind: pool.RelayIPv6, Host: "2001:db8::1", Port: 6000, HasPort: true},
	}
	reg, err := Ledger{}.BuildPoolRegistration(rs)
	if err != nil {
		t.Fatal(err)
	}
	spec := oneInputSpec()
	spec.Certificates = []stake.Certificate{reg.Attachment(500_000_000)}
	b, err := Ledger{}.BuildBody(spec)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b.CBOR, []byte{0x44, 0x04, 0x03, 0x02, 0x01}) {
		t.Error("the builder does not write 1.2.3.4 as 04030201")
	}
	v6, _ := hex.DecodeString("50b80d01200000000000000000" + "01000000")
	if !bytes.Contains(b.CBOR, v6) {
		t.Error("the builder does not write 2001:db8::1 as b80d0120 00000000 00000000 01000000")
	}
	body, _ := TxViewer{}.BodyOf(b.CBOR)
	v, err := TxViewer{}.View(body)
	if err != nil {
		t.Fatal(err)
	}
	rl := v.Certificates[0].PoolReg.Relays
	if len(rl) != 2 || rl[0].Host != "1.2.3.4" || rl[0].Kind != "ipv4" || rl[1].Host != "2001:db8::1" || rl[1].Kind != "ipv6" {
		t.Fatalf("relays shown: %+v", rl)
	}
}

// A map or a set that repeats a key or a member is refused at every depth.
// spec: SPO-Xparty-PR-002
func TestViewRefusesDuplicatesInNestedMapsAndSets(t *testing.T) {
	body := goodBody(t)
	stakeAddr := append([]byte{0x58, 29, 0xe0}, bytes.Repeat([]byte{1}, 28)...) // a reward account (testnet)
	wd := func(n int) []byte {                                                  // withdrawals map key 5 with n copies of the same account
		out := []byte{0x05, 0xa0 + byte(n)}
		for i := 0; i < n; i++ {
			out = append(out, stakeAddr...)
			out = append(out, 0x01)
		}
		return out
	}
	if _, err := (TxViewer{}).View(withKeys(body, wd(1))); err != nil {
		t.Fatalf("one withdrawal: %v", err)
	}
	if _, err := (TxViewer{}).View(withKeys(body, wd(2))); err == nil {
		t.Error("a duplicate withdrawal key was displayed")
	}
	// The multi-asset map of a mint: the same policy twice, and the same
	// asset name twice inside one policy.
	pol := append([]byte{0x58, 28}, bytes.Repeat([]byte{7}, 28)...)
	twoPolicies := append(append([]byte{0x09, 0xa2}, pol...), append([]byte{0xa1, 0x41, 'a', 0x01}, append(append([]byte(nil), pol...), 0xa1, 0x41, 'b', 0x01)...)...)
	twoNames := append(append([]byte{0x09, 0xa1}, pol...), 0xa2, 0x41, 'a', 0x01, 0x41, 'a', 0x02)
	for name, extra := range map[string][]byte{"policy twice": twoPolicies, "asset name twice": twoNames} {
		if _, err := (TxViewer{}).View(withKeys(body, extra)); err == nil {
			t.Errorf("%s was displayed", name)
		}
	}
	// A tag-258 set with a member twice: required signers.
	signer := append([]byte{0x58, 28}, bytes.Repeat([]byte{3}, 28)...)
	set := func(n int) []byte {
		out := []byte{0x0e, 0xd9, 0x01, 0x02, 0x80 + byte(n)}
		for i := 0; i < n; i++ {
			out = append(out, signer...)
		}
		return out
	}
	if _, err := (TxViewer{}).View(withKeys(body, set(1))); err != nil {
		t.Fatalf("one required signer: %v", err)
	}
	if _, err := (TxViewer{}).View(withKeys(body, set(2))); err == nil {
		t.Error("a set with a repeated member was displayed")
	}
	// Voting procedures: the same voter twice, the same action twice for a voter.
	voter := []byte{0x82, 0x04, 0x58, 28}
	voter = append(voter, bytes.Repeat([]byte{4}, 28)...)
	act := append([]byte{0x82, 0x58, 32}, append(bytes.Repeat([]byte{5}, 32), 0x00)...)
	proc := []byte{0x82, 0x01, 0xf6} // yes, no anchor
	oneVote := append(append([]byte{0xa1}, act...), proc...)
	votesTwiceVoter := append([]byte{0x13, 0xa2}, append(append(append([]byte(nil), voter...), oneVote...), append(append([]byte(nil), voter...), oneVote...)...)...)
	votesTwiceAction := append(append([]byte{0x13, 0xa1}, voter...), append([]byte{0xa2}, append(append(append(append([]byte(nil), act...), proc...), act...), proc...)...)...)
	for name, extra := range map[string][]byte{"voter twice": votesTwiceVoter, "action twice": votesTwiceAction} {
		if _, err := (TxViewer{}).View(withKeys(body, extra)); err == nil {
			t.Errorf("%s was displayed", name)
		}
	}
	// A single vote, written the same way, is displayed: the test is of the
	// duplicate and not of the encoding.
	one := append(append([]byte{0x13, 0xa1}, voter...), oneVote...)
	if v, err := (TxViewer{}).View(withKeys(body, one)); err != nil || len(v.Votes) != 1 {
		t.Fatalf("one vote: %v, %v", v.Votes, err)
	}
}

// The network of the body's own key 15 and of every address is shown to the
// signer's check.
// spec: SPO-Xparty-PRE-006
func TestViewCarriesNetworks(t *testing.T) {
	spec := oneInputSpec()
	v, _ := viewOf(t, spec)
	for _, o := range v.Outputs {
		if o.Network != 0 {
			t.Errorf("a testnet address shows network %d", o.Network)
		}
	}
	if err := v.CheckNetwork(0); err != nil {
		t.Fatal(err)
	}
	if err := v.CheckNetwork(1); err == nil {
		t.Error("a testnet body passed as mainnet")
	}
	body := goodBody(t)
	mainnetKey := []byte{0x0f, 0x01}
	vv, err := TxViewer{}.View(withKeys(body, mainnetKey))
	if err != nil || vv.NetworkID == nil || *vv.NetworkID != 1 || vv.CheckNetwork(0) == nil {
		t.Fatalf("key 15 = mainnet: %v %v", vv.NetworkID, err)
	}
	// A withdrawal from a mainnet reward account in a testnet body.
	main := append([]byte{0x58, 29, 0xe1}, bytes.Repeat([]byte{1}, 28)...)
	vv, err = TxViewer{}.View(withKeys(body, append(append([]byte{0x05, 0xa1}, main...), 0x01)))
	if err != nil || vv.CheckNetwork(0) == nil {
		t.Fatalf("mainnet withdrawal in a testnet body: %v", err)
	}
}

// Auxiliary data is carried, hashed and shown: labels, values, CIP-20 text.
// spec: SPO-Xparty-PR-002
func TestViewAuxData(t *testing.T) {
	spec := oneInputSpec()
	spec.Message = []string{"hello", "world"}
	b, err := Ledger{}.BuildBody(spec)
	if err != nil {
		t.Fatal(err)
	}
	aux, err := TxViewer{}.AuxOf(b.CBOR)
	if err != nil || aux == nil {
		t.Fatalf("AuxOf = %x, %v", aux, err)
	}
	body, _ := TxViewer{}.BodyOf(b.CBOR)
	v, err := TxViewer{}.View(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := party.CheckAuxData(v, aux); err != nil {
		t.Fatalf("the hash of the carried auxiliary data is not the body's: %v", err)
	}
	av, err := TxViewer{}.ViewAux(aux)
	if err != nil || len(av.Labels) != 1 || av.Labels[0].Label != 674 {
		t.Fatalf("ViewAux = %+v, %v", av, err)
	}
	if m := av.Labels[0].Messages; len(m) != 2 || m[0] != "hello" || m[1] != "world" {
		t.Fatalf("messages %q", m)
	}
	// No auxiliary data: nil.
	plain, _ := Ledger{}.BuildBody(oneInputSpec())
	if a, err := (TxViewer{}).AuxOf(plain.CBOR); err != nil || a != nil {
		t.Fatalf("AuxOf of a transaction without = %x, %v", a, err)
	}
	// Forms that are not the plain metadata map are refused.
	// The other two forms of metadata alone are shown.
	for name, raw := range map[string][]byte{"shelley-ma pair": {0x82, 0xa1, 0x01, 0x01, 0x80}, "plain": {0xa1, 0x01, 0x01}} {
		if v, err := (TxViewer{}).ViewAux(raw); err != nil || len(v.Labels) != 1 || v.Labels[0].Value != "1" {
			t.Errorf("%s: %+v, %v", name, v, err)
		}
	}
	for name, raw := range map[string][]byte{"array with scripts": {0x82, 0xa0, 0x81, 0x80}, "tagged map with scripts": {0xd9, 0x01, 0x03, 0xa2, 0x00, 0xa0, 0x01, 0x80},
		"a key that is not a label": {0xa1, 0x61, 'x', 0x01}, "an escape in text": {0xa1, 0x01, 0x62, 0x1b, 'x'},
		"a line separator in text":      {0xa1, 0x01, 0x64, 'a', 0xe2, 0x80, 0xa8},
		"a paragraph separator in text": {0xa1, 0x01, 0x64, 'a', 0xe2, 0x80, 0xa9},
		"a tag in a value":              {0xa1, 0x01, 0xc2, 0x41, 0x01}, "a label twice": {0xa2, 0x01, 0x01, 0x01, 0x02}} {
		if _, err := (TxViewer{}).ViewAux(raw); err == nil {
			t.Errorf("%s was shown", name)
		}
	}
	// A mismatch is the domain's to refuse.
	other := append([]byte(nil), aux...)
	other[len(other)-1] ^= 1
	if party.CheckAuxData(v, other) == nil || party.CheckAuxData(v, nil) == nil {
		t.Error("a wrong or missing auxiliary data matched the body's hash")
	}
}
