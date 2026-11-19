package relaybind_test

import (
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
)

// KeyOfAddress reads K from exactly the address forms the verifiers accept and
// refuses every other, with the verifiers' own errors.
//
// spec: SPO-Xrelaybind-PRE-014, SPO-Xrelaybind-IF-004
func TestKeyOfAddress(t *testing.T) {
	var k relaybind.KeyHash
	for i := range k {
		k[i] = byte(i + 1)
	}
	other := make([]byte, 28)
	addr := func(h byte, parts ...[]byte) []byte {
		out := []byte{h}
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	for name, tc := range map[string]struct {
		in   []byte
		part relaybind.AddressPart
		err  error
	}{
		"key hash":                    {k[:], relaybind.PartKeyHash, nil},
		"enterprise mainnet":          {addr(0x61, k[:]), relaybind.PartEnterprise, nil},
		"enterprise testnet":          {addr(0x60, k[:]), relaybind.PartEnterprise, nil},
		"reward mainnet":              {addr(0xe1, k[:]), relaybind.PartReward, nil},
		"base, key stake":             {addr(0x01, k[:], other), relaybind.PartBasePayment, nil},
		"base, script stake":          {addr(0x21, k[:], other), relaybind.PartBasePayment, nil},
		"network 2":                   {addr(0x62, k[:]), 0, relaybind.ErrAddressForm},
		"script enterprise":           {addr(0x71, k[:]), 0, relaybind.ErrAddressForm},
		"script payment base":         {addr(0x11, k[:], other), 0, relaybind.ErrAddressForm},
		"pointer":                     {addr(0x41, k[:], []byte{1, 2, 3}), 0, relaybind.ErrAddressForm},
		"reward script":               {addr(0xf1, k[:]), 0, relaybind.ErrAddressForm},
		"empty":                       {nil, 0, relaybind.ErrAddressForm},
		"30 bytes":                    {append(addr(0x61, k[:]), 0), 0, relaybind.ErrAddressForm},
		"base with a missing byte":    {addr(0x01, k[:], other[:27]), 0, relaybind.ErrAddressForm},
		"base with a byte too many":   {addr(0x01, k[:], other, []byte{0}), 0, relaybind.ErrAddressForm},
		"byron-looking (header 0x82)": {addr(0x82, k[:]), 0, relaybind.ErrAddressForm},
	} {
		got, part, err := relaybind.KeyOfAddress(tc.in)
		if !errors.Is(err, tc.err) || (tc.err == nil && (got != k || part != tc.part)) || (tc.err != nil && (got != relaybind.KeyHash{} || part != 0)) {
			t.Errorf("%s: %x %v %v", name, got[:2], part, err)
		}
	}
}
