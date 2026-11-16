package native

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
)

// Vectors written by cardano-cli 11.2.3.0 (`stake-address *-certificate`)
// for one stake key.
const (
	vecStake = "ce93cb74bb4c96e3edcd6349e98d3c5ad6a347f36872aeb3db28b26f"
	vecReg   = "83078200581c" + vecStake + "1a001e8480"
	vecDereg = "83088200581c" + vecStake + "1a001e8480"
	vecDeleg = "83028200581c" + vecStake + "581c00000000000000000000000000000000000000000000000000000001"
	vecAbst  = "83098200581c" + vecStake + "8102"
	vecNoCon = "83098200581c" + vecStake + "8103"
	vecDKey  = "83098200581c" + vecStake + "8200581c11111111111111111111111111111111111111111111111111111111"
	vecDScr  = "83098200581c" + vecStake + "8201581c11111111111111111111111111111111111111111111111111111111"
)

func stakeKey() (k stake.KeyHash) {
	b, _ := hex.DecodeString(vecStake)
	copy(k[:], b)
	return
}

func vecSpecs() map[string]stake.Spec {
	k := stakeKey()
	h11 := [28]byte{}
	for i := range h11 {
		h11[i] = 0x11
	}
	var pool chain.PoolID
	pool[27] = 1
	return map[string]stake.Spec{
		vecReg:   {Kind: stake.CertRegistration, Stake: k, Deposit: 2000000},
		vecDereg: {Kind: stake.CertDeregistration, Stake: k, Deposit: 2000000},
		vecDeleg: {Kind: stake.CertPoolDelegation, Stake: k, Pool: pool},
		vecAbst:  {Kind: stake.CertVoteDelegation, Stake: k, DRep: stake.DRep{Kind: stake.DRepAbstain}},
		vecNoCon: {Kind: stake.CertVoteDelegation, Stake: k, DRep: stake.DRep{Kind: stake.DRepNoConfidence}},
		vecDKey:  {Kind: stake.CertVoteDelegation, Stake: k, DRep: stake.DRep{Kind: stake.DRepKey, Hash: h11}},
		vecDScr:  {Kind: stake.CertVoteDelegation, Stake: k, DRep: stake.DRep{Kind: stake.DRepScript, Hash: h11}},
	}
}

// spec: SPO-Pfiles-OUT-006, SPO-Pfiles-OUT-007, SPO-Pfiles-OUT-008, SPO-Pfiles-OUT-009
func TestCertificatesEncodeAsCardanoCLI(t *testing.T) {
	for want, spec := range vecSpecs() {
		c, err := Ledger{}.BuildCertificate(spec)
		if err != nil {
			t.Fatalf("%+v: %v", spec, err)
		}
		if got := hex.EncodeToString(c.CBOR); got != want {
			t.Errorf("%s: got %s, want %s", spec.Kind, got, want)
		}
		back, err := Ledger{}.DecodeCertificate(c.Envelope)
		if err != nil || back.Spec != spec || !bytes.Equal(back.CBOR, c.CBOR) {
			t.Errorf("%s does not read back: %+v %v", spec.Kind, back.Spec, err)
		}
	}
}

// The structural decoder refuses what it does not understand instead of
// reading offsets of a string (SPO-06-IN-002, SPO-08b-IN-002, SPO-22b-IN-002).
//
// spec: SPO-06-IN-002, SPO-08b-IN-002, SPO-22b-IN-002
func TestDecodeRefusals(t *testing.T) {
	env := func(typ, h string) []byte {
		return []byte(`{"type":"` + typ + `","description":"x","cborHex":"` + h + `"}`)
	}
	legacy := "82008200581c" + vecStake // pre-Conway registration, no deposit
	for name, e := range map[string][]byte{
		"not json":          []byte("hello"),
		"another type":      env("TxSignedShelley", vecReg),
		"not hex":           env("Certificate", "zz"),
		"legacy":            env("Certificate", legacy),
		"a pool retirement": env("Certificate", "83048200581c"+vecStake+"01"),
		"truncated":         env("Certificate", vecReg[:30]),
	} {
		if _, err := (Ledger{}).DecodeCertificate(e); err == nil {
			t.Errorf("%s was accepted", name)
		} else if name == "legacy" && !errors.Is(err, ErrUnsupportedCertificate) {
			t.Errorf("legacy: %v", err)
		}
	}
	if _, err := (Ledger{}).BuildCertificate(stake.Spec{Kind: stake.CertRegistration, Stake: stakeKey()}); err == nil {
		t.Error("a registration with no deposit was built")
	}
}
