package native

import "testing"

// The treasury-withdrawal map is in the ledger's order of reward accounts
// (network, then script before key, then hash), which cardano-cli writes
// whatever the order of its flags (observed with the pinned cardano-cli in
// test/parity: TestGovActionFilesMatchCardanoCLI). The header byte alone would
// put key accounts first.
//
// spec: SPO-25a-EXT-009
func TestRewardAccountOrderPutsScriptAccountsBeforeKeyAccounts(t *testing.T) {
	acct := func(hdr, fill byte) []byte {
		b := []byte{hdr}
		for i := 0; i < 28; i++ {
			b = append(b, fill)
		}
		return b
	}
	key, script := acct(0xe0, 0x5a), acct(0xf0, 0x6b)
	if !rewardAccountLess(script, key) || rewardAccountLess(key, script) {
		t.Error("a script account must precede a key account on the same network")
	}
	if !rewardAccountLess(acct(0xf0, 0x01), acct(0xe1, 0x01)) {
		t.Error("the network id comes first: testnet before mainnet")
	}
	if !rewardAccountLess(acct(0xe0, 0x01), acct(0xe0, 0x02)) || rewardAccountLess(acct(0xe0, 0x02), acct(0xe0, 0x01)) {
		t.Error("equal kinds order by hash")
	}
}
