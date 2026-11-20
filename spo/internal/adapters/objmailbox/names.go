package objmailbox

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// The layout in the working bucket (ADR 0015 decision 3):
//
//	relays/<relay node public key, 64 hex>/mailbox/<recipient, 40 hex>/<arrival, 20 digits>-<mid, 64 hex>-<sender, 40 hex>-<nonce, 16 hex>
//
// Up to the sender the name below the recipient is the directory store's
// entry name (SPO-Xmailbox-OUT-012): the arrival is zero-padded, so the key
// order of a listing is arrival order within a recipient; the sender and the
// id are in the key, and a listing gives the size, so the index and every
// counter are rebuilt from a listing alone, with no GET per entry. The nonce
// is 64 random bits drawn once per put (every PUT a put re-sends carries the
// same key), so no key is ever written by two puts, in this process or in
// another: a request the store applies late (a DELETE, or a PUT whose answer
// was lost) can only reach the object it was sent for (SPO-Xobjstore-OUT-707).
// It plays no part in what an entry is: the entry is the recipient, the
// sender and the id. Every character is in the client's key alphabet
// (lower-case hex, digits, '-' and '/').
const (
	relaysDir  = "relays/"
	mailboxDir = "/mailbox/"

	nodeKeyLen = 64
	fpHexLen   = 2 * len(party.Fingerprint{})
	midHexLen  = 2 * mailbox.HashSize
	arrivalLen = 20
	nonceLen   = 16
	// entryLen is the length of a key below the mailbox prefix.
	entryLen = fpHexLen + 1 + arrivalLen + 1 + midHexLen + 1 + fpHexLen + 1 + nonceLen
)

// validNodeKey reports 64 lower-case hex digits.
func validNodeKey(k string) bool { return len(k) == nodeKeyLen && lowerHex(k) }

func lowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func digits(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// mailboxPrefix is the prefix of every entry of the relay whose node key is node.
func mailboxPrefix(node string) string { return relaysDir + node + mailboxDir }

// The layout for the store tools (adapters/relaystore, ADR 0015 work package
// 9), which list, migrate and repair the mailbox without a Store: the
// adapter's own functions, not copies.

// MailboxPrefix is the prefix of every entry of the relay whose node key is
// node (64 lower-case hex digits).
func MailboxPrefix(node string) string { return mailboxPrefix(node) }

// EntryKey is the object key of an entry under prefix (from MailboxPrefix).
func EntryKey(prefix string, rcpt party.Fingerprint, arrival int64, mid mailbox.Hash, sender party.Fingerprint, nonce uint64) string {
	return entryKey(prefix, rcpt, arrival, mid, sender, nonce)
}

// EntryName is a parsed entry key.
type EntryName struct {
	Recipient, Sender party.Fingerprint
	Arrival           int64
	Mid               mailbox.Hash
	Nonce             uint64
}

// ParseEntryKey reads an entry key under prefix as a load does: exactly the
// shape of EntryKey, lower-case hex, an arrival that fits an int64.
func ParseEntryKey(prefix, key string) (EntryName, error) {
	r, at, mid, s, n, err := parseKey(prefix, key)
	return EntryName{Recipient: r, Sender: s, Arrival: at, Mid: mid, Nonce: n}, err
}

// entryKey is the object key of an entry under prefix (from mailboxPrefix).
func entryKey(prefix string, rcpt party.Fingerprint, arrival int64, mid mailbox.Hash, sender party.Fingerprint, nonce uint64) string {
	return fmt.Sprintf("%s%s/%020d-%s-%s-%016x", prefix, hex.EncodeToString(rcpt[:]), arrival, mid, hex.EncodeToString(sender[:]), nonce)
}

// keyOfEnt is the object key of e, an entry of rcpt with id mid.
func keyOfEnt(prefix string, rcpt party.Fingerprint, mid mailbox.Hash, e ent) string {
	return entryKey(prefix, rcpt, e.arrival, mid, e.sender, e.nonce)
}

// parseKey reads an entry key under prefix strictly: exactly the shape above,
// lower-case hex, an arrival that fits an int64. Anything else is an error.
func parseKey(prefix, key string) (rcpt party.Fingerprint, arrival int64, mid mailbox.Hash, sender party.Fingerprint, nonce uint64, err error) {
	bad := func(why string) error { return fmt.Errorf("%q is not the key of a mailbox entry: %s", key, why) }
	if len(key) < len(prefix) || key[:len(prefix)] != prefix {
		return rcpt, 0, mid, sender, 0, bad("outside the mailbox prefix")
	}
	rest := key[len(prefix):]
	if len(rest) != entryLen {
		return rcpt, 0, mid, sender, 0, bad("not the length of an entry name")
	}
	const (
		aAt = fpHexLen + 1
		mAt = aAt + arrivalLen + 1
		sAt = mAt + midHexLen + 1
		nAt = sAt + fpHexLen + 1
	)
	r, a, m, s, n := rest[:fpHexLen], rest[aAt:aAt+arrivalLen], rest[mAt:mAt+midHexLen], rest[sAt:sAt+fpHexLen], rest[nAt:]
	switch {
	case rest[aAt-1] != '/' || rest[mAt-1] != '-' || rest[sAt-1] != '-' || rest[nAt-1] != '-':
		return rcpt, 0, mid, sender, 0, bad("the separators are not in place")
	case !lowerHex(r) || !lowerHex(m) || !lowerHex(s) || !lowerHex(n):
		return rcpt, 0, mid, sender, 0, bad("not lower-case hex")
	case !digits(a):
		return rcpt, 0, mid, sender, 0, bad("the arrival is not 20 digits")
	}
	at, perr := strconv.ParseInt(a, 10, 64)
	if perr != nil {
		return rcpt, 0, mid, sender, 0, bad("the arrival is out of range")
	}
	nv, nerr := strconv.ParseUint(n, 16, 64)
	if nerr != nil {
		return rcpt, 0, mid, sender, 0, bad("the nonce is out of range")
	}
	hex.Decode(rcpt[:], []byte(r))
	hex.Decode(mid[:], []byte(m))
	hex.Decode(sender[:], []byte(s))
	return rcpt, at, mid, sender, nv, nil
}
