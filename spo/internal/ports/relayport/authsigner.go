package relayport

import "github.com/mochipool/workbench/spo/internal/domain/party"

// AuthSigner signs the one thing a mailbox client signs for a login: the proof
// that it holds a party's device identity key, for one connection (ADR 0014
// decision 7, protocol version 2). It is a typed method and not a callback over
// bytes, so no wiring can obtain a signature over bytes it chose: the
// implementation builds the signed array itself with mailbox.AuthBytesV2 from
// these fixed-length values and its own fingerprint, the labelled array
//
//	["spo/mailbox-auth/v2", 2, relay node key, client node key, nonce,
//	 relay time, own fingerprint, binding hash, senders hash]
//
// and signs nothing else. There is no fingerprint parameter and no version: the
// fingerprint is the implementation's own and the version is 2.
//
// The caller passes the relay key it pinned and its own node key, never values
// read from the relay's Challenge; only the nonce and the relay's time come from
// the Challenge. bindingHash is relaybind's FullHash of the canonical binding
// the caller presents in the same Auth, and sendersHash is mailbox.SendersHash of
// the canonical expected-sender list it presents. The mailbox client takes this
// port and holds no identity key. The real implementation is on the local
// identity (adapters/envelope).
//
// spec: SPO-Xmailbox-IF-017
type AuthSigner interface {
	SignMailboxAuth(relayKey, clientNodeKey party.NodeKey, nonce [32]byte, relayTime int64, bindingHash, sendersHash [32]byte) ([64]byte, error)
}
