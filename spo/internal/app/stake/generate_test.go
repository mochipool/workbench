package stake

import (
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	stk "github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func hex56(b byte) string {
	return strings.Repeat(string("0123456789abcdef"[b>>4])+string("0123456789abcdef"[b&15]), 28)
}

// The delegation certificate names the pool by its id (hex or bech32) or by a
// stored pool's cold key, and is stored as `<delegator>.deleg.cert`,
// replacing an earlier one.
//
// spec: SPO-05b-IF-001, SPO-05b-IF-002, SPO-05b-IF-003, SPO-05b-IN-001, SPO-05b-IN-002, SPO-05b-PRE-001, SPO-05b-EXT-001,
// spec: SPO-05b-OUT-001, SPO-05b-INV-001, SPO-Pfiles-OUT-007
func TestGenerateDelegationCertificate(t *testing.T) {
	id := chain.PoolID{0xcd}
	for i := range id {
		id[i] = 0xcd
	}
	r := newRig(t)
	uc := GenerateDelegationCertificate{Store: r.store, Certs: r.certs}
	coldHash, _ := chain.PoolIDOf(r.signerPub())
	for _, tc := range []struct {
		word string
		want chain.PoolID
	}{
		{hex56(0xcd), id}, {strings.ToUpper(hex56(0xcd)), id}, {id.Bech32(), id}, {"mypool", coldHash}, {"./mypool.pool.json", coldHash},
	} {
		res, err := uc.Run(bg, DelegationRequest{Pool: tc.word, Delegator: "w.staking"})
		if err != nil {
			t.Fatalf("%s: %v", tc.word, err)
		}
		c := res.Certificate
		if c.Kind != stk.CertPoolDelegation || c.Pool != tc.want || c.Stake != r.stakeID || c.Deposit != 0 {
			t.Errorf("%s: %+v", tc.word, c.Spec)
		}
		if got := r.store.files[ports.Ref{Name: "w", Kind: ports.DelegCert}]; string(got) != string(c.Envelope) {
			t.Errorf("stored %q", got)
		}
	}
	if r.l.count("params") != 0 || r.l.count("reward-account") != 0 {
		t.Error("05b never touches the chain")
	}
}

// spec: SPO-05b-IF-001, SPO-05b-IF-003, SPO-05b-IN-001, SPO-05b-IN-002, SPO-05b-PRE-001
func TestGenerateDelegationRefusalsWriteNothing(t *testing.T) {
	flipped := chain.PoolID{1}.Bech32()
	flipped = flipped[:55] + string(map[bool]byte{true: 'p', false: 'q'}[flipped[55] == 'q'])
	for name, req := range map[string]DelegationRequest{
		"no pool":                    {Delegator: "w"},
		"no delegator":               {Pool: hex56(1)},
		"a pool that is not stored":  {Pool: "nosuchpool", Delegator: "w"},
		"a bad bech32 checksum":      {Pool: flipped, Delegator: "w"},
		"a delegator without a vkey": {Pool: hex56(1), Delegator: "nobody"},
		"a delegator with a path":    {Pool: hex56(1), Delegator: "../w"},
	} {
		r := newRig(t)
		if _, err := (GenerateDelegationCertificate{Store: r.store, Certs: r.certs}).Run(bg, req); err == nil || r.store.writes != 0 {
			t.Errorf("%s: %v (%d writes)", name, err, r.store.writes)
		}
	}
	r := newRig(t)
	r.store.files[ports.Ref{Name: "w", Kind: ports.StakingVKey}] = []byte("not an envelope")
	if _, err := (GenerateDelegationCertificate{Store: r.store, Certs: r.certs}).Run(bg, DelegationRequest{Pool: hex56(1), Delegator: "w"}); err == nil {
		t.Error("a bad vkey was accepted")
	}
}

// The target word takes the seven forms of 22a; a local DRep wins over a
// keyword of the same name; the certificate is stored as
// `<delegator>.vote-deleg.cert`.
//
// spec: SPO-22a-IF-001, SPO-22a-IF-002, SPO-22a-IN-001, SPO-22a-IN-002, SPO-22a-EXT-001, SPO-22a-EXT-002, SPO-22a-EXT-003,
// spec: SPO-22a-EXT-004, SPO-22a-EXT-005, SPO-22a-OUT-001, SPO-Pfiles-OUT-008
func TestGenerateVoteDelegationCertificate(t *testing.T) {
	r := newRig(t)
	uc := GenerateVoteDelegationCertificate{Store: r.store, Certs: r.certs}
	h := [28]byte{0x11}
	for i := range h {
		h[i] = 0x11
	}
	legacy, _ := chain.Bech32Encode("drep", h[:])
	script, _ := chain.Bech32Encode("drep_script", h[:])
	cip, _ := chain.Bech32Encode("drep", append([]byte{0x22}, h[:]...))
	cipScript, _ := chain.Bech32Encode("drep", append([]byte{0x23}, h[:]...))
	localHash := chain.DRepID{}
	_ = localHash
	local, _ := vkeyHash(r.store.files[ports.Ref{Name: "d", Kind: ports.DRepVKey}])
	for _, tc := range []struct {
		word string
		want stk.DRep
	}{
		{hex56(0x11), stk.DRep{Kind: stk.DRepKey, Hash: h}},
		{legacy, stk.DRep{Kind: stk.DRepKey, Hash: h}},
		{script, stk.DRep{Kind: stk.DRepScript, Hash: h}},
		{cip, stk.DRep{Kind: stk.DRepKey, Hash: h}},
		{cipScript, stk.DRep{Kind: stk.DRepScript, Hash: h}},
		{"d", stk.DRep{Kind: stk.DRepKey, Hash: local}},
		{"./d.drep", stk.DRep{Kind: stk.DRepKey, Hash: local}},
		{"always-abstain", stk.DRep{Kind: stk.DRepAbstain}},
		{"ALWAYS-NO-CONFIDENCE", stk.DRep{Kind: stk.DRepNoConfidence}},
	} {
		res, err := uc.Run(bg, VoteDelegationRequest{Target: tc.word, Delegator: "w"})
		if err != nil {
			t.Fatalf("%s: %v", tc.word, err)
		}
		if res.Certificate.DRep != tc.want || res.Certificate.Stake != r.stakeID || res.Certificate.Kind != stk.CertVoteDelegation {
			t.Errorf("%s: %+v", tc.word, res.Certificate.Spec)
		}
		if got := r.store.files[ports.Ref{Name: "w", Kind: ports.VoteDelegCert}]; string(got) != string(res.Certificate.Envelope) {
			t.Errorf("stored %q", got)
		}
	}
	// A stored DRep named like a keyword wins (form 5 before forms 6 and 7).
	r.store.files[ports.Ref{Name: "always-abstain", Kind: ports.DRepVKey}] = r.store.files[ports.Ref{Name: "d", Kind: ports.DRepVKey}]
	res, err := uc.Run(bg, VoteDelegationRequest{Target: "always-abstain", Delegator: "w"})
	if err != nil || res.Certificate.DRep.Kind != stk.DRepKey {
		t.Errorf("%+v %v", res.Certificate.DRep, err)
	}
}

// spec: SPO-22a-PRE-001, SPO-22a-PRE-002, SPO-22a-IF-001, SPO-22a-IF-002, SPO-22a-IN-001, SPO-22a-IN-002
func TestGenerateVoteDelegationRefusalsWriteNothing(t *testing.T) {
	cip, _ := chain.Bech32Encode("drep", append([]byte{0x22}, make([]byte, 28)...))
	bad := cip[:57] + string(map[bool]byte{true: 'p', false: 'q'}[cip[57] == 'q'])
	for name, c := range map[string]struct {
		req  VoteDelegationRequest
		want error
		mut  func(*rig, *GenerateVoteDelegationCertificate)
	}{
		"no target":                    {req: VoteDelegationRequest{Delegator: "w"}},
		"no delegator":                 {req: VoteDelegationRequest{Target: "always-abstain"}},
		"a bad checksum":               {req: VoteDelegationRequest{Target: bad, Delegator: "w"}},
		"neither id, name nor keyword": {req: VoteDelegationRequest{Target: "whoever", Delegator: "w"}, want: ErrBadWord},
		"no stake vkey":                {req: VoteDelegationRequest{Target: "always-abstain", Delegator: "nobody"}, want: ErrMissingFile},
		"a pre-Conway era is an error, not exit 0": {req: VoteDelegationRequest{Target: "always-abstain", Delegator: "w"}, want: ErrProtocolTooOld,
			mut: func(r *rig, _ *GenerateVoteDelegationCertificate) { r.chain.params.ProtocolMajor = 8 }},
	} {
		r := newRig(t)
		uc := GenerateVoteDelegationCertificate{Store: r.store, Certs: r.certs, Params: r.chain}
		if c.mut != nil {
			c.mut(r, &uc)
		}
		_, err := uc.Run(bg, c.req)
		if err == nil || (c.want != nil && !errors.Is(err, c.want)) || r.store.writes != 0 {
			t.Errorf("%s: %v (%d writes)", name, err, r.store.writes)
		}
	}
}
