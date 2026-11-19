package mailbox

import "time"

// Protocol version 2 (ADR 0014, work package 2), the only version: version 1 was
// deleted when the relay session and the client moved. A field is never added to
// an array: a new shape is a new version. Version 2 is the shape of the ADR, with
// the abuse bounds of decision 5 in it.
const (
	// Version2 is the version of the wallet-key identity.
	Version2 = 2

	// AuthLabelV2 is the first element of the signed auth array. It differs from
	// every other label a device key signs, including
	// "spo/relay-revoke-device/v1" (ADR 0014 decisions 3 and 7).
	AuthLabelV2 = "spo/mailbox-auth/v2"

	// WalletKeySize is the size of a wallet key hash K: Blake2b-224 of the
	// Ed25519 verification key (relaybind.KeyHashSize).
	WalletKeySize = 28
)

// Bounds of the version 2 frames (ADR 0014 decision 7). Each is checked before
// anything of that size is allocated.
const (
	// MaxSenders is the length of the expected-sender list of an Auth.
	MaxSenders = 64
	// MaxSign1Bytes bounds the COSE_Sign1 that carries a binding or a wallet
	// revoke (relaybind.MaxSign1Bytes).
	MaxSign1Bytes = 512
	// MaxCOSEKeyBytes bounds the COSE_Key that travels with it
	// (relaybind.MaxKeyBytes).
	MaxCOSEKeyBytes = 128
)

// Limits of the relay session that this package names but does not count
// (ADR 0014 decision 5). They are the numbers the session must hold; the
// package only pins them.
const (
	// MaxRevokesPerConn is how many Revoke frames one connection may send before
	// Auth. The count is the session's.
	MaxRevokesPerConn = 8
	// UnauthBudget is the time for the whole of an unauthenticated connection.
	UnauthBudget = 5 * time.Second
	// MaxUnauthConnections is the relay-wide number of unauthenticated slots.
	MaxUnauthConnections = 16
	// MaxNewBindingsPerHour and NewBindingBurst cap new bindings, relay-wide.
	MaxNewBindingsPerHour = 60
	NewBindingBurst       = 10
	// MaxBoundDevices is the largest registry size an operator may configure; it
	// needs a global quota of MaxBoundDevices times the queue bound (16 GiB at
	// the default queue bound of OpenMailboxBytes).
	MaxBoundDevices = 4096
	// DefaultBoundDevices is the default registry size (`max_bound_devices`).
	// With the default queue bound of OpenMailboxBytes it reserves exactly the
	// default global quota of 4 GiB.
	DefaultBoundDevices = 1024
	// OpenMailboxBytes and OpenPairBytes are the defaults of open mode for the
	// outstanding bytes in one device's queue and from one sender to one device.
	// ADR 0013's 64 MiB and 8 MiB are the ceilings; with them the default
	// registry would reserve 256 GiB.
	OpenMailboxBytes = 4 << 20
	OpenPairBytes    = 2 << 20
	// MaxDevicesPerKey is how many devices one wallet key may have.
	MaxDevicesPerKey = 8
	// MaxConnsPerDevice is how many live logged-in connections one bound device
	// may hold, and MaxConnsPerWalletKey how many all the devices of one wallet key
	// may hold together: 8 devices of 2 connections. The tunnel node key costs a
	// peer nothing, so these are the bounds that follow the identity a session
	// proved (ADR 0014 decision 5). A server may only tighten them.
	MaxConnsPerDevice    = 2
	MaxConnsPerWalletKey = MaxDevicesPerKey * MaxConnsPerDevice
	// BindingIdleDrop is how long an unauthenticated binding with an empty queue
	// is kept.
	BindingIdleDrop = 30 * 24 * time.Hour

	// StrangerEntries and StrangerBytes are the allowance, per recipient, that
	// all senders not on the recipient's expected-sender list share. They are
	// ceilings for the allowance, and the allowance sits strictly inside the
	// queue bound (OpenQuota.Validate).
	StrangerEntries = 16
	StrangerBytes   = 1 << 20
)

// The default registry reserves no more than the default global quota; this
// does not compile if it does.
const _ = uint64(DefaultGlobalBytes - DefaultBoundDevices*OpenMailboxBytes)
