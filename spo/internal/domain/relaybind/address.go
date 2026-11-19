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
//   - a base address of exactly 57 bytes in which a KEY-hash credential equal to
//     K is the payment part (header types 0 and 2) or the stake part (types 0
//     and 1).
//
// A script credential never matches, a pointer address and every other type are
// refused, and so is a network id above 1 (the low nibble of the header byte;
// every Cardano network uses 0 or 1). The other credential of a base address is
// not looked at: the payment part may be someone else's, and callers must
// therefore display only the key hash K, never the address bytes (see
// Statement.Address and AddressPart).

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
	// PartBaseStake is the stake credential of a 57-byte base address.
	PartBaseStake
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
	case PartBaseStake:
		return "base-stake"
	}
	return "unknown"
}

// Sizes and header types of the accepted address forms.
const (
	enterpriseAddressSize = 1 + KeyHashSize
	baseAddressSize       = 1 + 2*KeyHashSize

	typeBaseKeyKey     = 0 // payment key hash, stake key hash
	typeBaseScriptKey  = 1 // payment script hash, stake key hash
	typeBaseKeyScript  = 2 // payment key hash, stake script hash
	typeEnterpriseKey  = 6
	typeRewardKey      = 14
	maxAcceptedNetwork = 1
	addressTypeShift   = 4
	addressNetworkMask = 0x0f
)

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
		if net > maxAcceptedNetwork || typ > typeBaseKeyScript {
			return 0, ErrAddressForm
		}
		paymentIsKey := typ == typeBaseKeyKey || typ == typeBaseKeyScript
		stakeIsKey := typ == typeBaseKeyKey || typ == typeBaseScriptKey
		switch {
		case paymentIsKey && bytes.Equal(addr[1:1+KeyHashSize], k):
			return PartBasePayment, nil
		case stakeIsKey && bytes.Equal(addr[1+KeyHashSize:], k):
			return PartBaseStake, nil
		}
		return 0, ErrWrongKey
	}
	return 0, ErrAddressForm
}
