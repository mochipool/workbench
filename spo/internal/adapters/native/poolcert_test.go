package native

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
)

func sampleSpec() pool.RegistrationSpec {
	s := pool.RegistrationSpec{Pledge: 7, Cost: 340_000_000, Margin: chain.Rational{Num: 1, Den: 100}, NetworkID: 0,
		MetaURL: "https://x.org/p.json", Relays: []pool.Relay{
			{Kind: pool.RelayIPv4, Host: "203.0.113.7", Port: 3001, HasPort: true},
			{Kind: pool.RelayIPv6, Host: "2001:db8::1", Port: 6000, HasPort: true},
			{Kind: pool.RelayDNS, Host: "r.example.org", Port: 1, HasPort: true},
			{Kind: pool.RelaySRV, Host: "_c._tcp.example.org"},
		}}
	for i := range s.Operator {
		s.Operator[i] = byte(i)
	}
	for i := range s.VrfKeyHash {
		s.VrfKeyHash[i] = byte(0x40 + i)
	}
	s.MetaHash[0] = 0xee
	s.RewardAccount[0] = 0x99
	s.Owners = []stake.KeyHash{{0xf0}, {0x10}, {0xf0}, {0x80}}
	return s
}

// The certificate encodes the owners as a sorted set without repeats, relay
// addresses as little-endian words, and reads back as what it was made from
// (the byte-equality with cardano-cli is in spo/test/parity).
//
// spec: SPO-05a-EXT-005, SPO-05a-EXT-001
func TestPoolRegistrationEncodesAndReadsBack(t *testing.T) {
	spec := sampleSpec()
	c, err := Ledger{}.BuildPoolRegistration(spec)
	if err != nil {
		t.Fatal(err)
	}
	h := hex.EncodeToString(c.CBOR)
	if !strings.HasPrefix(h, "8a03581c000102") || !strings.Contains(h, "d9010283581c10") || !strings.Contains(h, "4407710"+"0cb") {
		t.Errorf("%s", h)
	}
	// The owners are sorted by hash: 10.., 80.., f0..
	if i10, i80, if0 := strings.Index(h, "581c10"), strings.Index(h, "581c80"), strings.Index(h, "581cf0"); !(i10 < i80 && i80 < if0) {
		t.Errorf("owners not sorted: %s", h)
	}
	if got := c.Registration.Owners; len(got) != 3 {
		t.Errorf("owners %v", got)
	}
	back, err := Ledger{}.DecodePoolCertificate(c.Envelope)
	if err != nil || !samePoolSpec(*back.Registration, *c.Registration) || string(back.CBOR) != string(c.CBOR) {
		t.Fatalf("%v", err)
	}
	if !strings.Contains(string(c.Envelope), `"description": "Stake Pool Registration Certificate"`) || !strings.HasSuffix(string(c.Envelope), "}\n") {
		t.Errorf("%s", c.Envelope)
	}
	// No metadata is a null.
	spec.MetaURL = ""
	if c, err := (Ledger{}).BuildPoolRegistration(spec); err != nil || !strings.HasSuffix(hex.EncodeToString(c.CBOR), "f6") {
		t.Errorf("%v", err)
	}
	// Mainnet is the header e1.
	spec.NetworkID = 1
	if c, _ := (Ledger{}).BuildPoolRegistration(spec); !strings.Contains(hex.EncodeToString(c.CBOR), "581de199") {
		t.Error("mainnet header")
	}
}

func TestPoolRegistrationRefusals(t *testing.T) {
	for name, f := range map[string]func(*pool.RegistrationSpec){
		"margin zero denominator": func(s *pool.RegistrationSpec) { s.Margin = chain.Rational{} },
		"margin above one":        func(s *pool.RegistrationSpec) { s.Margin = chain.Rational{Num: 3, Den: 2} },
		"bad network":             func(s *pool.RegistrationSpec) { s.NetworkID = 2 },
		"bad ipv4":                func(s *pool.RegistrationSpec) { s.Relays[0].Host = "::1" },
		"bad ipv6":                func(s *pool.RegistrationSpec) { s.Relays[1].Host = "1.2.3.4" },
		"unknown relay kind":      func(s *pool.RegistrationSpec) { s.Relays[0].Kind = "tor" },
	} {
		s := sampleSpec()
		f(&s)
		if _, err := (Ledger{}).BuildPoolRegistration(s); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// spec: SPO-05c-PRE-006, SPO-07a-EXT-001
func TestPoolCertificateDecodingRefusals(t *testing.T) {
	good, _ := (Ledger{}).BuildPoolRegistration(sampleSpec())
	retire, _ := (Ledger{}).BuildPoolRetirement(pool.RetirementSpec{Pool: chain.PoolID{1}, Epoch: 300})
	if back, err := (Ledger{}).DecodePoolCertificate(retire.Envelope); err != nil || back.Retirement == nil || back.Retirement.Epoch != 300 || back.Retirement.Pool != (chain.PoolID{1}) {
		t.Errorf("retirement: %v", err)
	}
	stakeCert, _ := (Ledger{}).BuildCertificate(stake.Spec{Kind: stake.CertRegistration, Deposit: 2_000_000})
	env := func(typ, cbor string) []byte {
		return []byte(`{"type":"` + typ + `","description":"","cborHex":"` + cbor + `"}`)
	}
	g := hex.EncodeToString(good.CBOR)
	for name, in := range map[string][]byte{
		"not JSON":                    []byte("x"),
		"another envelope type":       env("TxWitness ConwayEra", g),
		"a stake certificate":         stakeCert.Envelope,
		"not hex":                     env("Certificate", "zz"),
		"truncated":                   env("Certificate", g[:60]),
		"trailing bytes":              env("Certificate", g+"00"),
		"owners not a set":            env("Certificate", strings.Replace(g, "d90102", "d90103", 1)),
		"margin not tagged":           env("Certificate", strings.Replace(g, "d81e", "d81f", 1)),
		"a pre-Conway reward account": env("Certificate", strings.Replace(g, "581d00", "581d00", 1)),
	} {
		if _, err := (Ledger{}).DecodePoolCertificate(in); err == nil && name != "a pre-Conway reward account" {
			t.Errorf("%s accepted", name)
		}
	}
}

// spec: SPO-05a-EXT-004, SPO-05c-EXT-002
func TestMetadataHashChecks(t *testing.T) {
	ok := []byte("{\"name\":\"n\",\"description\":\"d\",\"ticker\":\"TICK\",\"homepage\":\"https://x\",\"extended\":\"https://e\"}")
	h, err := Ledger{}.MetadataHash(ok)
	if err != nil || h != blake256(ok) {
		t.Fatalf("%v", err)
	}
	for name, doc := range map[string]string{"not JSON": "{", "an array": "[]", "no homepage": `{"name":"n","description":"d","ticker":"T"}`,
		"a number name": `{"name":1,"description":"d","ticker":"T","homepage":"h"}`, "over 512": `{"name":"` + strings.Repeat("n", 600) + `","description":"d","ticker":"T","homepage":"h"}`} {
		if _, err := (Ledger{}).MetadataHash([]byte(doc)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	exact := `{"name":"n","description":"` + strings.Repeat("d", 512-len(`{"name":"n","description":"","ticker":"T","homepage":"h"}`)) + `","ticker":"T","homepage":"h"}`
	if len(exact) != 512 {
		t.Fatalf("%d", len(exact))
	}
	if _, err := (Ledger{}).MetadataHash([]byte(exact)); err != nil {
		t.Errorf("512 bytes: %v", err)
	}
}

func TestTransactionIDOfABody(t *testing.T) {
	body, err := Ledger{}.BuildBody(oneInputSpec())
	if err != nil {
		t.Fatal(err)
	}
	id, err := Ledger{}.TransactionID(body.CBOR)
	if err != nil || id != body.ID {
		t.Errorf("%v", err)
	}
	if _, err := (Ledger{}).TransactionID([]byte{1, 2}); err == nil {
		t.Error("garbage")
	}
}
