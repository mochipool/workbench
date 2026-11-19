package relaybind

import "bytes"

// The protected-header address of a wallet-signed statement (ADR 0014
// decision 3, revised after the package review). It is a claim by the signer;
// the identity is always Blake2b-224 of the verification key. Exactly these
// forms are accepted, and nothing else:
//
//   - the 28-byte key hash K;
//   - an enterprise or reward address of exactly 29 bytes whose credential is a
//     KEY hash equal to K (header types 6 and 14);
//   - a base address of exactly 57 bytes whose PAYMENT credential is a KEY hash
//     equal to K (header types 0 and 2).
//
// K as only the stake part of a base address is refused (owner decision,
// 2026-11-18): a wallet that signs for a base address signs with the payment
// key, and a wallet that signs with the stake key presents the reward address,
// so no honest wallet writes that form, and it would show another party's
// payment address beside K. A wallet without a staking part uses its payment
// key; a stake key identifies itself by the key hash or the reward address.
//
// A script credential never matches, a pointer address and every other type are
// refused, and so is a network id above 1 (the low nibble of the header byte;
// every Cardano network uses 0 or 1). The stake credential of a base address is
// not looked at and may be anyone's, so callers display only the key hash K,
// never the address bytes (see Statement.Address and AddressPart).

// AddressPart says which part of the protected-header address matched K.
type AddressPart uint8

const (
	// PartKeyHash is the bare 28-byte key hash.
	PartKeyHash AddressPart = iota + 1
	// PartEnterprise is the credential of a 29-byte enterprise address.
	PartEnterprise
	// PartReward is the credential of a 29-byte reward address.
	PartReward
	// PartBasePayment is the payment credential of a 57-byte base address.
	PartBasePayment
)

// String names the part.
func (p AddressPart) String() string {
	switch p {
	case PartKeyHash:
		return "key-hash"
	case PartEnterprise:
		return "enterprise"
	case PartReward:
		return "reward"
	case PartBasePayment:
		return "base-payment"
	}
	return "unknown"
}

// Sizes and header types of the accepted address forms.
const (
	enterpriseAddressSize = 1 + KeyHashSize
	baseAddressSize       = 1 + 2*KeyHashSize

	typeBaseKeyKey     = 0 // payment key hash, stake key hash
	typeBaseKeyScript  = 2 // payment key hash, stake script hash
	typeEnterpriseKey  = 6
	typeRewardKey      = 14
	maxAcceptedNetwork = 1
	addressTypeShift   = 4
	addressNetworkMask = 0x0f
)

// KeyOfAddress reads the wallet key hash K out of an address in exactly the forms
// a statement's protected header may carry (the table above): a 29-byte
// enterprise or reward address with a key-hash credential, or a 57-byte base
// address with a key-hash payment credential, network id 0 or 1. It is what a
// caller that is given an address (not a key hash) of an external wallet uses to
// learn K; it uses the same rules as the verifiers, so an address that it refuses
// would also be refused in a statement (ErrAddressForm). A bare 28-byte key hash
// is its own K (PartKeyHash).
func KeyOfAddress(addr []byte) (KeyHash, AddressPart, error) {
	var k KeyHash
	switch len(addr) {
	case KeyHashSize:
		copy(k[:], addr)
	case enterpriseAddressSize:
		copy(k[:], addr[1:])
	case baseAddressSize:
		copy(k[:], addr[1:1+KeyHashSize])
	default:
		return KeyHash{}, 0, ErrAddressForm
	}
	part, err := matchAddress(addr, k[:])
	if err != nil {
		return KeyHash{}, 0, err
	}
	return k, part, nil
}

// matchAddress checks the protected-header address against K, the Blake2b-224
// of the verification key. A form that is not accepted is ErrAddressForm; an
// accepted form that names no key credential equal to K is ErrWrongKey.
func matchAddress(addr, k []byte) (AddressPart, error) {
	switch len(addr) {
	case KeyHashSize:
		if bytes.Equal(addr, k) {
			return PartKeyHash, nil
		}
		return 0, ErrWrongKey
	case enterpriseAddressSize:
		typ, net := addr[0]>>addressTypeShift, addr[0]&addressNetworkMask
		if net > maxAcceptedNetwork || (typ != typeEnterpriseKey && typ != typeRewardKey) {
			return 0, ErrAddressForm
		}
		if !bytes.Equal(addr[1:], k) {
			return 0, ErrWrongKey
		}
		if typ == typeRewardKey {
			return PartReward, nil
		}
		return PartEnterprise, nil
	case baseAddressSize:
		typ, net := addr[0]>>addressTypeShift, addr[0]&addressNetworkMask
		// Only a base address whose PAYMENT credential is a key hash is a form
		// a wallet signs for with a key of ours; the stake part is not looked at.
		if net > maxAcceptedNetwork || (typ != typeBaseKeyKey && typ != typeBaseKeyScript) {
			return 0, ErrAddressForm
		}
		if !bytes.Equal(addr[1:1+KeyHashSize], k) {
			return 0, ErrWrongKey
		}
		return PartBasePayment, nil
	}
	return 0, ErrAddressForm
}
