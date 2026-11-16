package native

import (
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// The kind of an address is decoded natively (no `cardano-cli address info`):
// payment kinds, reward addresses and Byron addresses are told apart, which
// is what `type` and `era` gave upstream. A Byron address is a valid
// destination kind and is not a shelley source (SPO-Caddr-OUT-001 leaves that
// to callers).
//
// spec: SPO-Caddr-OUT-002, SPO-Caddr-OUT-003
func TestAddressKinds(t *testing.T) {
	for _, c := range []struct {
		addr string
		kind ports.AddressKind
		pay  bool
	}{
		{testAddr, ports.AddrEnterprise, true},
		{"addr_test1qp20v9uqgpuv9v2zv5rufqtwp930fg8e44e3cde8thg2u20tepjkemk4v508nmgce4dcs0s26lxqkq9ka0vk6ytthtqqe4gct5", ports.AddrBase, true},
		{"stake_test1uqeezcegh25rcskmmn0gy5fzenczfj34n8qeefhmz6taeycqg9wts", ports.AddrReward, false},
		{"Ae2tdPwUPEZFRbyhz3cpfC2CumGzNkFBN2L42rcUc2yjQpEkxDbkPodpMAi", ports.AddrByron, false},
	} {
		info, err := (Ledger{}).InspectAddress(chainAddr(c.addr))
		if err != nil || info.Kind != c.kind || info.Kind.IsPayment() != c.pay {
			t.Errorf("%s: %+v %v", c.addr, info, err)
		}
	}
}

func chainAddr(s string) chain.Address { return chain.Address(s) }
