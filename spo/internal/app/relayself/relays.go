package relayself

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// The relays this device uses (ADR 0014 work package 10, SPO-Xmailbox-IF-025):
// a public record of names, pinned relay node keys and ports, and one secret
// record per relay holding its address (which holds the relay's pre-shared key,
// so it is sealed like the coordinator's tailcat address). Relays are
// independent: a revoke, a binding and an expected-sender list are the same for
// every one of them.

// MaxRelays is the most relays a device lists (mailbox.MaxRelays).
const MaxRelays = 8

// MaxRelayListBytes bounds the stored list, checked before it is parsed.
const MaxRelayListBytes = 4 << 10

// DefaultRelayPort is the port a relay serves inside the tunnel by default.
const DefaultRelayPort = 7346

// MaxAddressBytes bounds a relay address.
const MaxAddressBytes = 1 << 10

var (
	relayListRef = ports.NamedRef{Name: "self", Kind: ports.RelayList}
	relayNameRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
)

// Errors of the relay list.
var (
	ErrRelayName    = errors.New("relayself: a relay name is 1 to 32 of a-z, 0-9 and '-', starting with a letter or a digit")
	ErrRelayExists  = errors.New("relayself: a relay of that name or node key is listed")
	ErrRelayUnknown = errors.New("relayself: no relay of that name is listed (see spo party relay list)")
	ErrRelayFull    = fmt.Errorf("relayself: %d relays are listed; remove one first", MaxRelays)
	ErrRelayList    = errors.New("relayself: the stored relay list is not valid")
)

// Relay is one relay of the list.
type Relay struct {
	Name string
	// Key is the relay's node key, pinned: a connection to another key is closed
	// before anything is signed.
	Key  party.NodeKey
	Port uint16
}

// AddressRef is the secret record of a relay's address.
func AddressRef(name string) ports.NamedRef {
	return ports.NamedRef{Name: "relay-" + name, Kind: ports.RelayAddr}
}

type relayJSON struct {
	Name    string `json:"name"`
	NodeKey string `json:"node_key"`
	Port    uint16 `json:"port"`
}

type relayListJSON struct {
	Version int         `json:"version"`
	Relays  []relayJSON `json:"relays"`
}

func checkRelay(r Relay) error {
	switch {
	case !relayNameRE.MatchString(r.Name):
		return ErrRelayName
	case r.Key == (party.NodeKey{}):
		return errors.New("relayself: the relay's node key is zero")
	case r.Port == 0:
		return errors.New("relayself: the relay's port is 0")
	}
	return nil
}

// DecodeRelays reads the stored list strictly: at most MaxRelayListBytes, no
// unknown or repeated key, version 1, at most MaxRelays relays, each valid, no
// name or key twice.
func DecodeRelays(b []byte) ([]Relay, error) {
	if len(b) > MaxRelayListBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrRelayList, len(b))
	}
	var j relayListJSON
	if err := ports.UnmarshalStrict(b, &j); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRelayList, err)
	}
	if j.Version != 1 || len(j.Relays) > MaxRelays {
		return nil, fmt.Errorf("%w: version %d, %d relays", ErrRelayList, j.Version, len(j.Relays))
	}
	out := make([]Relay, 0, len(j.Relays))
	for _, rj := range j.Relays {
		raw, err := hex.DecodeString(rj.NodeKey)
		if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != rj.NodeKey {
			return nil, fmt.Errorf("%w: the node key of %q", ErrRelayList, rj.Name)
		}
		r := Relay{Name: rj.Name, Key: party.NodeKey(raw), Port: rj.Port}
		if err := checkRelay(r); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrRelayList, err)
		}
		for _, o := range out {
			if o.Name == r.Name || o.Key == r.Key {
				return nil, fmt.Errorf("%w: %q is listed twice", ErrRelayList, r.Name)
			}
		}
		out = append(out, r)
	}
	return out, nil
}

// EncodeRelays is the stored form of the list.
func EncodeRelays(rs []Relay) ([]byte, error) {
	j := relayListJSON{Version: 1, Relays: []relayJSON{}}
	for _, r := range rs {
		j.Relays = append(j.Relays, relayJSON{Name: r.Name, NodeKey: hex.EncodeToString(r.Key[:]), Port: r.Port})
	}
	return json.Marshal(j)
}

func readRelays(rd ports.NamedReader) ([]Relay, error) {
	b, err := rd.Get(relayListRef)
	if errors.Is(err, ports.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return DecodeRelays(b)
}

// Relays is the list (empty when none is configured).
func Relays(ctx context.Context, st ports.NamedStore) ([]Relay, error) {
	var out []Relay
	err := st.View(ctx, func(rd ports.NamedReader) error {
		var err error
		out, err = readRelays(rd)
		return err
	})
	return out, err
}

// AddRelay lists a relay and stores its address, in one transaction. The
// caller has checked that the address leads to r.Key (the dialer refuses one
// that does not). The buffer stays the caller's.
func AddRelay(ctx context.Context, st ports.NamedStore, r Relay, address *ports.Secret) error {
	if r.Port == 0 {
		r.Port = DefaultRelayPort
	}
	if err := checkRelay(r); err != nil {
		return err
	}
	if address == nil || address.Len() == 0 || address.Len() > MaxAddressBytes {
		return fmt.Errorf("relayself: the relay address is empty or over %d bytes", MaxAddressBytes)
	}
	return st.Update(ctx, func(w ports.NamedWriter) error {
		rs, err := readRelays(w)
		if err != nil {
			return err
		}
		for _, o := range rs {
			if o.Name == r.Name || o.Key == r.Key {
				return ErrRelayExists
			}
		}
		if len(rs) >= MaxRelays {
			return ErrRelayFull
		}
		b, err := EncodeRelays(append(rs, r))
		if err != nil {
			return err
		}
		if err := w.PutSecret(AddressRef(r.Name), address); err != nil {
			return err
		}
		return w.Put(relayListRef, b)
	})
}

// RemoveRelay drops a relay and its address, in one transaction.
func RemoveRelay(ctx context.Context, st ports.NamedStore, name string) error {
	return st.Update(ctx, func(w ports.NamedWriter) error {
		rs, err := readRelays(w)
		if err != nil {
			return err
		}
		kept := rs[:0]
		found := false
		for _, o := range rs {
			if o.Name == name {
				found = true
				continue
			}
			kept = append(kept, o)
		}
		if !found {
			return ErrRelayUnknown
		}
		b, err := EncodeRelays(kept)
		if err != nil {
			return err
		}
		if err := w.Delete(AddressRef(name)); err != nil && !errors.Is(err, ports.ErrNotFound) {
			return err
		}
		return w.Put(relayListRef, b)
	})
}
