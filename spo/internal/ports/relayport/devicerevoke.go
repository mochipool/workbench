package relayport

import "github.com/mochipool/workbench/spo/internal/domain/party"

// DeviceRevokeSigner signs the one other thing a device signs for the relay
// besides the mailbox authentication: its own revoke (ADR 0014 decision 7). Like
// AuthSigner it is a typed method and never a callback over bytes. The
// implementation builds the signed bytes itself with relaybind.DeviceRevokeBytes
// from its own fingerprint and the not-before, so it cannot be made to sign
// anything but the labelled array
// ["spo/relay-revoke-device/v1", own fingerprint, not-before].
//
// Identity is the public identity of the key that signs, for the caller to
// verify the result against (relaybind.VerifyDeviceRevoke).
//
// notBeforeBound is the largest not-before the caller will accept: the use case
// passes relay time plus the skew, because a relay refuses a revoke dated beyond
// it, and a tombstone that is further ahead would only be a lasting
// denial-of-service against the device's own later bindings. The method has no
// clock, so the bound is a parameter; the implementation refuses a not-before
// above it, or outside 0 to relaybind.MaxTime, and signs nothing then. Only
// app/relaybinding and the composition root may name this interface (an
// archtest holds that), so a bare ports.LocalIdentity cannot reach it.
//
// spec: SPO-Xrelaybind-IF-003, SPO-Xrelaybind-INV-005
type DeviceRevokeSigner interface {
	Identity() party.Identity
	SignRelayDeviceRevoke(notBefore, notBeforeBound int64) ([64]byte, error)
}
