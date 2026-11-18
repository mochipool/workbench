//go:build unix

package mailboxstore

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// The layout of the directory (ADR 0013 decision 7):
//
//	<root>/.spo-relay.lock
//	<root>/mailbox/<recipient fingerprint, 40 hex>/<arrival, 20 digits>-<mid, 64 hex>-<sender, 40 hex>
//
// The arrival time is zero-padded so that name order is arrival order. The
// sender is in the name because the per-pair and per-sender counters are
// rebuilt from the names alone, without reading an envelope. Temporary files
// are .tmp-<16 hex> in the recipient's directory.
const (
	lockName   = ".spo-relay.lock"
	mailboxDir = "mailbox"
	tmpPrefix  = ".tmp-"
)

var (
	recipientRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
	entryRE     = regexp.MustCompile(`^([0-9]{20})-([0-9a-f]{64})-([0-9a-f]{40})$`)
	tmpRE       = regexp.MustCompile(`^\.tmp-[0-9a-f]{16}$`)
)

func recipientName(fp party.Fingerprint) string { return hex.EncodeToString(fp[:]) }

func parseRecipient(name string) (party.Fingerprint, error) {
	var fp party.Fingerprint
	if !recipientRE.MatchString(name) {
		return fp, fmt.Errorf("%q is not the name of a mailbox (40 lower-case hex digits)", name)
	}
	b, _ := hex.DecodeString(name)
	copy(fp[:], b)
	return fp, nil
}

func entryName(arrival int64, mid mailbox.Hash, sender party.Fingerprint) string {
	return fmt.Sprintf("%020d-%s-%s", arrival, mid, recipientName(sender))
}

// parseEntry reads an entry name strictly: exactly the shape above, an arrival
// that fits an int64.
func parseEntry(name string) (arrival int64, mid mailbox.Hash, sender party.Fingerprint, err error) {
	m := entryRE.FindStringSubmatch(name)
	if m == nil {
		return 0, mid, sender, fmt.Errorf("%q is not the name of a mailbox entry", name)
	}
	arrival, perr := strconv.ParseInt(m[1], 10, 64)
	if perr != nil {
		return 0, mid, sender, fmt.Errorf("%q has an arrival time that is out of range", name)
	}
	mb, _ := hex.DecodeString(m[2])
	copy(mid[:], mb)
	sb, _ := hex.DecodeString(m[3])
	copy(sender[:], sb)
	return arrival, mid, sender, nil
}
