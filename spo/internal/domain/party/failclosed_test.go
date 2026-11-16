package party

import (
	"bytes"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
)

func bech(t *testing.T, hrp string, hdr byte, rest ...byte) string {
	t.Helper()
	s, err := chain.Bech32Encode(hrp, append([]byte{hdr}, rest...))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The header of an address says what its credentials are, with no inspector:
// every form that is not plainly a key form is a script or unknown.
// spec: SPO-Xparty-PR-004
func TestClassifiersReadTheHeaderAndFailClosed(t *testing.T) {
	k, h := bytes.Repeat([]byte{1}, 28), bytes.Repeat([]byte{2}, 29)
	for hdr, want := range map[byte]bool{0x00: false, 0x20: false, 0x40: false, 0x60: false, 0x10: true, 0x30: true, 0x50: true, 0x70: true, 0xe0: true, 0xf0: true, 0x90: true} {
		if got := AddressPaymentIsScript(bech(t, "addr_test", hdr, k...)); got != want {
			t.Errorf("address header %#x: script = %v, want %v", hdr, got, want)
		}
	}
	if AddressPaymentIsScript("garbage") {
		t.Error("a non-bech32 address is left to the inspector")
	}
	for name, tc := range map[string]struct {
		acct string
		want bool
	}{
		"key reward":        {bech(t, "stake_test", 0xe0, k...), false},
		"script reward":     {bech(t, "stake_test", 0xf0, k...), true},
		"a payment address": {bech(t, "stake_test", 0x60, k...), true},
		"wrong length":      {bech(t, "stake_test", 0xe0, h...), true},
		"garbage":           {"stake_garbage", true},
	} {
		if got := RewardAccountIsScript(tc.acct); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
	for cred, want := range map[string]bool{"": false, "key:ab": false, "script:ab": true, "weird:ab": true} {
		if CredentialIsScript(cred) != want {
			t.Errorf("credential %q: want %v", cred, want)
		}
	}
	for voter, want := range map[string]bool{"drep-key:ab": false, "pool:ab": false, "committee-key:ab": false, "committee-script:ab": true, "drep-script:ab": true, "new-kind:ab": true, "": true} {
		if VoterIsScript(voter) != want {
			t.Errorf("voter %q: want %v", voter, want)
		}
	}
}

// BuildFlow marks a script part from the bytes in the view even when the
// caller supplies no inspector (IsScriptReward nil), and a hot credential that
// is a script or unknown is a script part too.
// spec: SPO-Xparty-PR-004
func TestBuildFlowFlagsScriptPartsWithoutAnInspector(t *testing.T) {
	k := bytes.Repeat([]byte{1}, 28)
	for name, v := range map[string]TxView{
		"a script reward withdrawal": {Withdrawals: []ViewWithdrawal{{Account: bech(t, "stake_test", 0xf0, k...), Lovelace: 1}}},
		"an unreadable account":      {Withdrawals: []ViewWithdrawal{{Account: "nonsense", Lovelace: 1}}},
		"a script hot credential": {Certificates: []ViewCert{{Kind: CertCommitteeAuthorize, Credential: "key:" + string(bytes.Repeat([]byte("ab"), 28)),
			HotCredential: "script:00"}}},
		"an unknown credential kind": {Certificates: []ViewCert{{Kind: CertStakeDelegation, Credential: "other:00"}}},
		"an unknown voter":           {Votes: []ViewVote{{Voter: "mystery:00"}}},
	} {
		fl, err := BuildFlow(v, FlowFacts{Role: custody.RoleStake})
		if err != nil {
			t.Fatal(name, err)
		}
		if r, bad := fl.Refusal(custody.RoleStake, false); !bad || r != RefuseScriptInput {
			t.Errorf("%s: refusal = %v %v", name, r, bad)
		}
	}
	fl, _ := BuildFlow(TxView{Withdrawals: []ViewWithdrawal{{Account: bech(t, "stake_test", 0xe0, k...), Lovelace: 1}}}, FlowFacts{Role: custody.RoleStake})
	if _, bad := fl.Refusal(custody.RoleStake, false); bad {
		t.Error("a key reward account is not refused")
	}
}

// Over a network every role needs checked inputs; by file only payment does.
// spec: SPO-Xparty-PRE-007
func TestRefusalNetworkRule(t *testing.T) {
	unchecked := Flow{Checked: false}
	for _, role := range []custody.Role{custody.RoleStake, custody.RolePoolCold, custody.RoleDRep} {
		if r, bad := unchecked.Refusal(role, true); !bad || r != RefuseCannotResolveInputs {
			t.Errorf("%s over a network: %v %v", role, r, bad)
		}
		if _, bad := unchecked.Refusal(role, false); bad {
			t.Errorf("%s by file is warned, not refused", role)
		}
		if _, bad := (Flow{Checked: true}).Refusal(role, true); bad {
			t.Errorf("%s over a network with checked inputs is not refused", role)
		}
	}
}
