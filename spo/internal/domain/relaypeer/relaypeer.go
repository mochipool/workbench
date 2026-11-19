// Package relaypeer holds the rules about the relay identity of another party
// (ADR 0014 decision 2, work package 8; spec Xparty "Relay identity of a party"
// and Xmailbox "Wallet-key identity on the client side"): whether a binding a
// party gave is evidence for its record, whether its wallet key may be used for
// mail, and where a put to it goes. It is pure: no I/O, no clock of its own and
// no private key.
//
// The evidence never grants authority. A party is enrolled by the typed
// fingerprint check (SPO-Xparty-PR-001); the relay identity is only the address
// of a put at a relay. The envelope is sealed to the party's device, and a
// witness is checked against the slot's own key hash, which is never a route.
package relaypeer

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relaywallet"
)

// MaxDevicesPerWalletKey is how many active enrolled parties may share one wallet
// key: the relay's cap of devices per wallet key (ADR 0014 decision 5).
const MaxDevicesPerWalletKey = 8

// NetworkAny is the network argument of Verify that checks no network.
const NetworkAny = -1

// Refusals.
var (
	// ErrEvidence: the binding is not valid evidence for this party; the reason
	// from relaybind is wrapped.
	ErrEvidence = errors.New("relaypeer: the binding is not valid evidence for this party")
	// ErrTooLarge: the statement or the key is empty or over its bound; nothing
	// was parsed.
	ErrTooLarge = errors.New("relaypeer: the statement or the key is empty or over its bound")
	// ErrNetwork: the address the wallet signed for is on another network than
	// the workspace's.
	ErrNetwork = errors.New("relaypeer: the binding's address is on another network")
	// ErrColdKey: the wallet key is, or may be, a cold key: its role history in
	// this store is cold, holds another role than payment and stake, or cannot be
	// read, or it is a pool id named in a scope.
	ErrColdKey = errors.New("relaypeer: the wallet key is or may be a cold key and is never used for mail")
	// ErrTooManyDevices: the wallet key is the relay identity of
	// MaxDevicesPerWalletKey other active parties already.
	ErrTooManyDevices = errors.New("relaypeer: the wallet key is already the relay identity of 8 other active parties")
	// ErrOlder: the binding is older (an earlier from) than the one recorded for
	// the same wallet key.
	ErrOlder = errors.New("relaypeer: the binding is older than the one recorded for that wallet key")
)

// Evidence is a binding that verified for a party: its relay identity and the
// form of the address the wallet signed for.
type Evidence struct {
	Relay party.RelayIdentity
	Part  relaybind.AddressPart
}

// Verify is the evidence check of SPO-Xparty-PRE-008 that needs no store:
// the sizes before anything is parsed, the strict parse, relaybind.VerifyBinding
// for device on the clock now with the policy (signature, key hash, canonical
// payload, window, lifetime), and, when the header carries an address rather
// than the bare key hash, its network id equal to network (NetworkAny checks
// none). device is the fingerprint the caller computed from the identity being
// enrolled, never one read from the binding.
func Verify(sign1, coseKey []byte, device party.Fingerprint, now int64, pol relaybind.Policy, network int) (Evidence, error) {
	if len(sign1) == 0 || len(sign1) > relaybind.MaxSign1Bytes || len(coseKey) == 0 || len(coseKey) > relaybind.MaxKeyBytes {
		return Evidence{}, fmt.Errorf("%w: %w: statement %d bytes (1 to %d), key %d bytes (1 to %d)", ErrEvidence, ErrTooLarge,
			len(sign1), relaybind.MaxSign1Bytes, len(coseKey), relaybind.MaxKeyBytes)
	}
	st, err := relaybind.ParseStatement(sign1)
	if err != nil {
		return Evidence{}, fmt.Errorf("%w: %w", ErrEvidence, err)
	}
	vkey, err := relaybind.ParseCOSEKey(coseKey)
	if err != nil {
		return Evidence{}, fmt.Errorf("%w: %w", ErrEvidence, err)
	}
	vb, err := relaybind.VerifyBinding(st, vkey, device, now, pol)
	if err != nil {
		return Evidence{}, fmt.Errorf("%w: %w", ErrEvidence, err)
	}
	if network != NetworkAny && vb.AddressPart() != relaybind.PartKeyHash {
		// an address form: its header byte's low nibble is the network id
		if got := int(st.Address()[0] & 0x0f); got != network {
			return Evidence{}, fmt.Errorf("%w: %w: network id %d, the workspace's is %d", ErrEvidence, ErrNetwork, got, network)
		}
	}
	if network != NetworkAny && network != 0 && network != 1 {
		return Evidence{}, fmt.Errorf("%w: %w: the workspace's network id %d is not 0 or 1", ErrEvidence, ErrNetwork, network)
	}
	b := vb.Binding()
	return Evidence{
		Relay: party.RelayIdentity{WalletKey: party.WalletKey(vb.Key()), Device: b.Device, From: b.From, Until: b.Until,
			Statement: bytes.Clone(sign1), Key: bytes.Clone(coseKey)},
		Part: vb.AddressPart(),
	}, nil
}

// CheckKeyHistory is the cold-key rule for a peer's wallet key (h, known and err
// are ports.RoleHistoryOf's answer): a key this store has no history of passes,
// because it lives in the other party's wallet; a known history with a cold role
// or any role other than payment and stake, a history of another identity and
// one that cannot be read are ErrColdKey.
func CheckKeyHistory(k party.WalletKey, h custody.RoleHistory, known bool, err error) error {
	id, rerr := identity.NewRef(identity.KindKeyHash, k[:])
	if rerr != nil {
		return fmt.Errorf("%w: %w", ErrColdKey, rerr)
	}
	// The role is a stand-in: CheckHistory reads the history, not the label.
	wk, rerr := relaywallet.FromRef(custody.KeyRef{Role: custody.RolePayment, Identity: id})
	if rerr != nil {
		return fmt.Errorf("%w: %w", ErrColdKey, rerr)
	}
	if cerr := wk.CheckHistoryAllowingUnknown(h, known, err); cerr != nil {
		return fmt.Errorf("%w: %w", ErrColdKey, cerr)
	}
	return nil
}

// IsPoolID reports whether k is the id of a pool named in the scope of any
// party (the scope keeps pools in bech32). A pool id is the hash of a cold key.
func IsPoolID(k party.WalletKey, existing []party.Party) bool {
	for _, p := range existing {
		for _, s := range p.Scope.Pools {
			if id, err := chain.ParsePoolBech32(s); err == nil && [28]byte(id) == [28]byte(k) {
				return true
			}
		}
	}
	return false
}

// CheckClaim checks a wallet key against the registry: it is not a pool id named
// in any party's scope, and fewer than MaxDevicesPerWalletKey active parties other
// than self have it. It returns the names of the active parties other than self
// that share it, for the operator.
func CheckClaim(k party.WalletKey, self party.Fingerprint, existing []party.Party) ([]string, error) {
	if IsPoolID(k, existing) {
		return nil, fmt.Errorf("%w: it is the id of a pool named in a scope", ErrColdKey)
	}
	var shared []string
	for _, p := range existing {
		if p.Fingerprint != self && p.Active() && p.Relay != nil && p.Relay.WalletKey == k {
			shared = append(shared, p.Name)
		}
	}
	if len(shared) >= MaxDevicesPerWalletKey {
		return shared, fmt.Errorf("%w: %v", ErrTooManyDevices, shared)
	}
	return shared, nil
}

// CheckUpdate compares a new relay identity with the one recorded: same reports
// the same statement again (no change); under the same wallet key a binding with
// an earlier from is ErrOlder.
func CheckUpdate(cur *party.RelayIdentity, next party.RelayIdentity) (same bool, err error) {
	if cur == nil || cur.Unverified != "" {
		return false, nil // nothing verified to compare with: the new binding repairs it
	}
	if cur.WalletKey == next.WalletKey && bytes.Equal(cur.Statement, next.Statement) && bytes.Equal(cur.Key, next.Key) {
		return true, nil
	}
	if cur.WalletKey == next.WalletKey && next.From < cur.From {
		return false, fmt.Errorf("%w: it starts at %d, the recorded one at %d", ErrOlder, next.From, cur.From)
	}
	return false, nil
}

// Reverify checks a stored relay identity again: the evidence verifies for
// device at its own from with the default policy, and says exactly the wallet
// key, device and window recorded.
func Reverify(r party.RelayIdentity, device party.Fingerprint) error {
	if err := party.CheckRelay(&r, device); err != nil {
		return err
	}
	ev, err := Verify(r.Statement, r.Key, device, r.From, relaybind.DefaultPolicy(), NetworkAny)
	if err != nil {
		return err
	}
	if ev.Relay.WalletKey != r.WalletKey || ev.Relay.From != r.From || ev.Relay.Until != r.Until || ev.Relay.Device != r.Device {
		return fmt.Errorf("%w: the record does not say what its evidence says", ErrEvidence)
	}
	return nil
}

// Recheck is Reverify for a load: an error is a stored relay identity that
// cannot be this party's or says something its evidence does not (a damaged or
// altered record, refused); unverified is why evidence that is intact as a
// record no longer verifies under the current policy (its signature, its
// parse, its lifetime), and such a relay identity is kept without a route.
func Recheck(r party.RelayIdentity, device party.Fingerprint) (unverified string, err error) {
	if err := party.CheckRelay(&r, device); err != nil {
		return "", err
	}
	ev, err := Verify(r.Statement, r.Key, device, r.From, relaybind.DefaultPolicy(), NetworkAny)
	if err != nil {
		if errors.Is(err, ErrTooLarge) {
			return "", err
		}
		return err.Error(), nil
	}
	if ev.Relay.WalletKey != r.WalletKey || ev.Relay.From != r.From || ev.Relay.Until != r.Until || ev.Relay.Device != r.Device {
		return "", fmt.Errorf("%w: the record does not say what its evidence says", ErrEvidence)
	}
	return "", nil
}

// Route is where a put to p goes: its wallet key and its own fingerprint as the
// device. A party that is not active, has no relay identity, or whose relay
// identity no longer verifies (RelayIdentity.Unverified) has no route.
// The binding's end is not looked at: the party renews at the relay without a
// new enrollment, and the relay answers unbound when it holds none.
func Route(p party.Party) (party.WalletKey, party.Fingerprint, bool) {
	if !p.Active() || p.Relay == nil || p.Relay.Unverified != "" {
		return party.WalletKey{}, party.Fingerprint{}, false
	}
	return p.Relay.WalletKey, p.Fingerprint, true
}
