package poolops

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/keyring"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals shared by the pool registration use cases.
var (
	// ErrNoDescriptor: `<pool>.pool.json` does not exist. Upstream writes a
	// template and exits 1 (SPO-05a-IF-003); the use case writes nothing.
	ErrNoDescriptor = errors.New("the pool descriptor <pool>.pool.json does not exist")
	// ErrMissingFile: an artefact the workflow reads does not exist.
	ErrMissingFile = errors.New("a file the workflow needs does not exist")
	// ErrBadPoolName: the pool word names nothing storable.
	ErrBadPoolName = errors.New("the pool name must be a plain name without a directory part")
	// ErrNoColdSigner: neither a cold signing key nor a hardware signing file.
	ErrNoColdSigner = errors.New("the pool has no cold signing key (.node.skey) or hardware signing file (.node.hwsfile)")
	// ErrNoSigningKey: a payer or owner key has no signing key file.
	ErrNoSigningKey = errors.New("no signing key (.skey) or hardware signing file (.hwsfile)")
	// ErrSourceNotKey: the paying address cannot be spent with a key witness.
	ErrSourceNotKey = errors.New("the paying address does not use a payment key")
	// ErrNetworkMismatch: an address belongs to another network.
	ErrNetworkMismatch = errors.New("the address belongs to a different network")
	// ErrProtocolTooOld: Conway certificates need protocol version 9.
	ErrProtocolTooOld = errors.New("the protocol version is older than 9: the Conway certificates are not available")
	// ErrNoChainReader: a check the workflow needs has no chain reader.
	ErrNoChainReader = errors.New("this workflow needs a chain reader the composition does not provide")
	// ErrParameterMissing: a protocol parameter the workflow needs is not in
	// the provider's answer.
	ErrParameterMissing = errors.New("the protocol parameters do not state a value the workflow needs")
	// ErrBLSRequired: protocol version 12 pool registrations carry a BLS key
	// (SPO-05a-INV-001); this port, on cardano-cli 11.2.3.0, cannot make them.
	ErrBLSRequired = errors.New("protocol version 12 or higher needs a BLS key in the pool registration certificate, which this release cannot make")
	// ErrDeclined: the operator did not approve.
	ErrDeclined = errors.New("the transaction was not approved")
)

// SourcePolicy says what a read of the "harmful if false" class does when it
// rests on one source (ADR 0006): here the registration state of a pool.
type SourcePolicy int

const (
	// RequireCorroboration is the zero value: a second independent source
	// that agrees is needed.
	RequireCorroboration SourcePolicy = iota
	// SingleSourceAcknowledged goes on with one source; the result names it.
	SingleSourceAcknowledged
)

// poolName applies the pool-name rule of SPO-Pfiles-IN-001: a leading `./`,
// then `.json`, then `.pool` are dropped. A directory part is refused
// (hazard H7).
//
// spec: SPO-05a-IF-001, SPO-Pfiles-IN-001
func poolName(s string) (string, error) {
	s = strings.TrimPrefix(s, "./")
	s = strings.TrimSuffix(strings.TrimSuffix(s, ".json"), ".pool")
	if s == "" || strings.ContainsAny(s, "/\\") {
		return "", fmt.Errorf("%w: %q", ErrBadPoolName, s)
	}
	return s, nil
}

func payerName(s string) (string, error) {
	s = strings.TrimSuffix(strings.TrimPrefix(s, "./"), ".addr")
	if s == "" || strings.ContainsAny(s, "/\\") {
		return "", fmt.Errorf("%w: %q", ErrBadPoolName, s)
	}
	return s, nil
}

func firstLine(b []byte) string {
	line, _, _ := strings.Cut(string(b), "\n")
	return strings.TrimSpace(line)
}

func rfc5322(t time.Time) string { return t.Format(time.RFC1123Z) }

func get(r ports.Reader, ref ports.Ref) ([]byte, error) {
	b, err := r.Get(ref)
	if errors.Is(err, ports.ErrNotFound) {
		return nil, fmt.Errorf("%w: %s", ErrMissingFile, ref)
	}
	return b, err
}

// keyOf reads a verification key envelope: the raw key and its hash.
func keyOf(env []byte) ([]byte, txbuild.KeyHash, error) {
	e, err := pool.ParseEnvelope(env)
	if err != nil {
		return nil, txbuild.KeyHash{}, err
	}
	raw, err := e.Key32()
	if err != nil {
		return nil, txbuild.KeyHash{}, err
	}
	return raw, txbuild.HashKey(raw), nil
}

// payer is the paying address of a transaction with its payment key.
type payer struct {
	name string
	addr chain.Address
	hash txbuild.KeyHash
	key  custody.KeyRef
}

func readPayer(r ports.Reader, ins ports.AddressInspector, network uint8, name string) (payer, error) {
	ab, err := get(r, ports.Ref{Name: name, Kind: ports.AddrFile})
	if err != nil {
		return payer{}, err
	}
	key, err := keyring.Held(r, custody.RolePayment, name, ErrNoSigningKey)
	if err != nil {
		return payer{}, err
	}
	p := payer{name: name, addr: chain.Address(firstLine(ab)), key: key}
	info, err := ins.InspectAddress(p.addr)
	if err != nil {
		return payer{}, fmt.Errorf("paying address: %w", err)
	}
	if !info.Kind.IsPayment() || info.PaymentKeyHash == nil {
		return payer{}, fmt.Errorf("%w: %s", ErrSourceNotKey, name)
	}
	if info.NetworkID != network {
		return payer{}, fmt.Errorf("%w: the paying address %s", ErrNetworkMismatch, name)
	}
	p.hash = *info.PaymentKeyHash
	return p, nil
}

// minPoolCost and retireMaxEpoch read the parameters the pool use cases need:
// the typed field when the provider set it, else the provider's document
// (cardano-cli's names, then Koios'). A parameter that is nowhere is an
// error, never zero.
func rawParam(p chain.ProtocolParameters, keys ...string) (uint64, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal(p.Raw, &m) != nil {
		return 0, false
	}
	for _, k := range keys {
		var n uint64
		dec := json.NewDecoder(bytes.NewReader(m[k]))
		if dec.Decode(&n) == nil && m[k] != nil {
			return n, true
		}
		var s string
		if json.Unmarshal(m[k], &s) == nil {
			var v uint64
			if _, err := fmt.Sscanf(s, "%d", &v); err == nil {
				return v, true
			}
		}
	}
	return 0, false
}

func minPoolCost(p chain.ProtocolParameters) (chain.Lovelace, error) {
	if p.MinPoolCost > 0 {
		return p.MinPoolCost, nil
	}
	if v, ok := rawParam(p, "minPoolCost", "min_pool_cost"); ok {
		return chain.Lovelace(v), nil
	}
	return 0, fmt.Errorf("%w: minPoolCost", ErrParameterMissing)
}

func retireMaxEpoch(p chain.ProtocolParameters) (uint64, error) {
	if p.PoolRetireMaxEpoch > 0 {
		return p.PoolRetireMaxEpoch, nil
	}
	if v, ok := rawParam(p, "poolRetireMaxEpoch", "eMax", "e_max", "max_epoch"); ok {
		return v, nil
	}
	return 0, fmt.Errorf("%w: poolRetireMaxEpoch", ErrParameterMissing)
}

// poolIDOf derives the pool id of the cold verification key envelope.
func poolIDOf(env []byte) (chain.PoolID, error) {
	raw, _, err := keyOf(env)
	if err != nil {
		return chain.PoolID{}, err
	}
	return chain.PoolIDOf(raw)
}

func readDescriptor(r ports.Reader, name string) (*pool.Descriptor, error) {
	b, err := r.Get(ports.Ref{Name: name, Kind: ports.PoolDescriptor})
	if errors.Is(err, ports.ErrNotFound) {
		return nil, fmt.Errorf("%w: %s", ErrNoDescriptor, name)
	}
	if err != nil {
		return nil, err
	}
	return pool.ParseDescriptor(b)
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }
