package n2c

import (
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/blinklabs-io/gouroboros/cbor"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func enc(t testing.TB, v any) []byte {
	t.Helper()
	b, err := cbor.Encode(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fill(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// pico is a relative time as the node sends it: a big integer of picoseconds.
func pico(sec int64) *big.Int {
	return new(big.Int).Mul(big.NewInt(sec), big.NewInt(1_000_000_000_000))
}

// previewStart is the system start of preview, 2022-10-25 00:00:00 UTC, as the
// node states it: year, day of the year, picoseconds of the day.
var previewStart = time.Date(2022, 10, 25, 0, 0, 0, 0, time.UTC)

func systemStartReply() []any { return []any{2022, 298, big.NewInt(0)} }

// The era history of two eras: 20 s slots for 100 slots (2000 s), then 1 s
// slots up to slot 1,000,100, the end of what the node can forecast.
const (
	era2StartSlot = 100
	era2End       = 1_000_100
)

func eraHistoryReply() []any {
	safe := []any{uint8(0), 4320, []any{uint8(0)}}
	return []any{
		[]any{[]any{pico(0), 0, 0}, []any{pico(2000), 100, 1}, []any{100, 20000, safe, 4320}},
		[]any{[]any{pico(2000), 100, 1}, []any{pico(2000 + 1_000_000), era2End, 1 + 3}, []any{432000, 1000, safe, 4320}},
	}
}

// stakeAddr builds a stake address on the test network from a key hash.
func stakeAddr(t testing.TB, mainnet bool, script bool, hash []byte) chain.StakeAddress {
	t.Helper()
	hdr, hrp := byte(0xe0), "stake_test"
	if script {
		hdr = 0xf0
	}
	if mainnet {
		hdr, hrp = hdr|1, "stake"
	}
	s, err := chain.Bech32Encode(hrp, append([]byte{hdr}, hash...))
	if err != nil {
		t.Fatal(err)
	}
	return chain.StakeAddress(s)
}

func testAddr(t testing.TB, hash []byte) (chain.Address, []byte) {
	t.Helper()
	raw := append([]byte{0x60}, hash...) // enterprise, key hash, testnet
	s, err := chain.Bech32Encode("addr_test", raw)
	if err != nil {
		t.Fatal(err)
	}
	return chain.Address(s), raw
}
