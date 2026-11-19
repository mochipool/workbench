package relayport

import "github.com/mochipool/workbench/spo/internal/domain/party"

// AuthSigner signs the one thing a mailbox client signs: the proof that it
// holds a party's identity key, for one connection (ADR 0013 decision 3). It is
// a typed method and not a callback over bytes, so no wiring can obtain a
// signature over bytes it chose: the implementation builds the signed array
// itself with mailbox.AuthBytes from these fixed-length values, with its own
// fingerprint.
//
// The caller passes the relay key it pinned and its own node key, never values
// read from the relay's Challenge; only the nonce and the relay's time come
// from the Challenge. The mailbox client takes this port and holds no
// identity key. The real implementation (on the local identity) is wired in a
// later work package.
//
// spec: SPO-Xmailbox-IF-008
type AuthSigner interface {
	SignMailboxAuth(relayKey, clientNodeKey party.NodeKey, nonce [32]byte, relayTime int64, version uint) ([64]byte, error)
}
