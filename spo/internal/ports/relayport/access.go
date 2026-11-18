package relayport

import (
	"slices"

	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// AccessEntry is one party the relay admits (ADR 0013 decision 3). Document is
// the party's own signed identity document; the adapter that builds an entry has
// verified its self-signature and refused a document with no node key.
type AccessEntry struct {
	Label       string
	Document    party.Document
	Fingerprint party.Fingerprint // recomputed from the keys in Document
	Node        party.NodeKey     // the tunnel node key; never zero

	// sendTo lists the fingerprints this party may put to. The default is
	// nothing. It is not exported, so that no caller holds a slice that the
	// access list also holds: an entry is read with MaySendTo and SendTo, and
	// built with WithSendTo, which copy.
	sendTo []party.Fingerprint
}

// WithSendTo returns the entry with the list of fingerprints it may put to set
// to a copy of to.
func (e AccessEntry) WithSendTo(to []party.Fingerprint) AccessEntry {
	e.sendTo = slices.Clone(to)
	return e
}

// SendTo is a copy of the fingerprints the entry may put to; changing it
// changes nothing.
func (e AccessEntry) SendTo() []party.Fingerprint { return slices.Clone(e.sendTo) }

// MaySendTo reports whether the entry allows a put to to.
func (e AccessEntry) MaySendTo(to party.Fingerprint) bool {
	return slices.Contains(e.sendTo, to)
}

// AccessList is the interim access list of the relay (ADR 0012 R1). It decides
// who may use the mailbox and gives no authority over what an envelope asks.
//
// spec: SPO-Xmailbox-IF-002
type AccessList interface {
	// Lookup finds an entry by the fingerprint of its party.
	Lookup(fp party.Fingerprint) (AccessEntry, bool)
	// LookupNode finds an entry by the tunnel node key.
	LookupNode(k party.NodeKey) (AccessEntry, bool)
	// NodeKeys is the tunnel allow-list: exactly the node keys of the entries.
	NodeKeys() []party.NodeKey
}
