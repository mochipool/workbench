// Package relaywallet is the wallet key that may sign a relay binding or a
// wallet-signed revoke (ADR 0014 decision 4). It is a closed sum type: a value
// is made only from a payment-role or a stake-role key reference of the store,
// never from raw key bytes and never from a key of any other role. A pool cold
// key, a committee cold key and every other role are refused at construction,
// and a key whose role history holds a cold role is refused at use.
//
// It is kept out of domain/relaybind on purpose: that package is the pure
// statement format the relay binary links, and imports no custody types
// (SPO-Xrelaybind-INV-001).
//
// What this cannot enforce: a key that was never imported has no role history,
// so a payment-labelled reference to a key that is in truth a cold key held
// only on a device cannot be told apart here. ADR 0014 decision 4 items 2 and
// 3 (the derivation path of a hardware signing file) cover that case on the
// hardware path, which is work package 4. A key hash carries no role, and the
// relay cannot tell a pool id from a payment key hash.
package relaywallet

import (
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
)

var (
	// ErrRole means the key is not a payment or stake key reference with a key
	// hash identity: another role, an unknown role, or a hollow reference.
	ErrRole = errors.New("relaywallet: only a payment key or a stake key can be the wallet key of a relay binding")
	// ErrColdHistory means the key identity was once recorded in a cold role
	// (custody.Role.IsCold): it is never bound, whatever it is labelled now.
	ErrColdHistory = errors.New("relaywallet: the key was recorded in a cold role and is never used for the relay")
	// ErrHistoryUnreadable means the role history could not be read for certain,
	// or is not the history of this key. The cold-key rule fails closed.
	ErrHistoryUnreadable = errors.New("relaywallet: the role history of the key cannot be read for certain")
	// ErrOtherRoleHistory means the key identity was recorded in a role other than
	// payment or stake (a drep, committee hot, policy, KES or any role added later):
	// such a key shares its signing-key envelope or its use with a role that is not a
	// wallet role, and is never bound. The rule is default-deny.
	ErrOtherRoleHistory = errors.New("relaywallet: the key was recorded in a role other than payment or stake and is never used for the relay")
	// ErrNoHistory means no role history is known for the key: it cannot be shown
	// that it was never a cold key, so the rule fails closed.
	ErrNoHistory = errors.New("relaywallet: no role history is known for the key, so it cannot be shown that it was never a cold key")
)

// WalletKey is the key that signs a binding: a payment key or a stake key of
// the store, by reference. The zero value is not a wallet key (IsZero).
type WalletKey struct{ ref custody.KeyRef }

// FromPayment makes a wallet key from a payment key reference.
func FromPayment(k custody.Key[custody.Payment]) (WalletKey, error) {
	return fromRef(k.Ref(), custody.RolePayment)
}

// FromStake makes a wallet key from a stake key reference.
func FromStake(k custody.Key[custody.Stake]) (WalletKey, error) {
	return fromRef(k.Ref(), custody.RoleStake)
}

// FromRef makes a wallet key from an untyped reference, as a command that
// resolved a name does. It is default-deny: only the payment and the stake
// role are accepted, so a role added to custody later is refused until this
// switch is changed on purpose.
func FromRef(ref custody.KeyRef) (WalletKey, error) {
	switch ref.Role {
	case custody.RolePayment:
		k, err := custody.As[custody.Payment](ref)
		if err != nil {
			return WalletKey{}, fmt.Errorf("%w: %w", ErrRole, err)
		}
		return FromPayment(k)
	case custody.RoleStake:
		k, err := custody.As[custody.Stake](ref)
		if err != nil {
			return WalletKey{}, fmt.Errorf("%w: %w", ErrRole, err)
		}
		return FromStake(k)
	}
	return WalletKey{}, fmt.Errorf("%w: %s is not one", ErrRole, ref)
}

// fromRef checks what a typed Key cannot: custody.Key[R]{} is a value anyone
// can write, so the role and the identity are checked again.
func fromRef(ref custody.KeyRef, role custody.Role) (WalletKey, error) {
	if ref.Role != role {
		return WalletKey{}, fmt.Errorf("%w: a %s reference holds the role %q", ErrRole, role, ref.Role)
	}
	if !ref.Identity.Is(identity.KindKeyHash) || len(ref.Identity.Hash()) != relaybind.KeyHashSize {
		return WalletKey{}, fmt.Errorf("%w: %s has no key hash identity", ErrRole, ref)
	}
	return WalletKey{ref: ref}, nil
}

// IsZero reports whether w was never constructed.
func (w WalletKey) IsZero() bool { return w.ref == custody.KeyRef{} }

// Ref is the key reference, for the signer that holds the key.
func (w WalletKey) Ref() custody.KeyRef { return w.ref }

// Role is payment or stake.
func (w WalletKey) Role() custody.Role { return w.ref.Role }

// KeyHash is K, the Blake2b-224 key hash in the identity. It is the only name of
// the signer to display or log.
func (w WalletKey) KeyHash() relaybind.KeyHash {
	var k relaybind.KeyHash
	copy(k[:], w.ref.Identity.Hash())
	return k
}

// CheckHistory applies the cold-key rule to the role history of the key: h,
// known and err are the answer of ports.RoleHistoryOf. A history that cannot be
// read (err) or that belongs to another identity refuses; one with a cold role
// refuses (ErrColdHistory); one with any other role outside payment and stake
// refuses (ErrOtherRoleHistory, default-deny: a role added to custody later is
// refused until this rule is changed on purpose); no history (known false)
// refuses (ErrNoHistory), because it cannot be shown that the key was never cold.
func (w WalletKey) CheckHistory(h custody.RoleHistory, known bool, err error) error {
	return w.checkHistory(h, known, err, true)
}

// CheckHistoryAllowingUnknown is CheckHistory except that a key with no known
// history passes. It is reserved for a device-only key (ADR 0014 work package 4),
// whose safety rests on the derivation-path check instead; nothing in the tree
// calls it today but the use case's opt-in option. A history that is known is
// checked in full.
func (w WalletKey) CheckHistoryAllowingUnknown(h custody.RoleHistory, known bool, err error) error {
	return w.checkHistory(h, known, err, false)
}

func (w WalletKey) checkHistory(h custody.RoleHistory, known bool, err error, refuseUnknown bool) error {
	if err != nil {
		return fmt.Errorf("%w: %w", ErrHistoryUnreadable, err)
	}
	if !known {
		if refuseUnknown {
			return ErrNoHistory
		}
		return nil
	}
	if h.Identity() != w.ref.Identity {
		return fmt.Errorf("%w: the history belongs to another identity", ErrHistoryUnreadable)
	}
	if h.HasColdRole() {
		return fmt.Errorf("%w: recorded roles %v", ErrColdHistory, h.Roles())
	}
	for _, r := range h.Roles() {
		if r != custody.RolePayment && r != custody.RoleStake {
			return fmt.Errorf("%w: recorded roles %v", ErrOtherRoleHistory, h.Roles())
		}
	}
	return nil
}
