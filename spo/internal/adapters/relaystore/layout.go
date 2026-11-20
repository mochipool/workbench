package relaystore

import (
	"encoding/hex"
	"errors"
	"regexp"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objmailbox"
	"github.com/mochipool/workbench/spo/internal/adapters/objregistry"
	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
)

// The layout under relays/<node key, 64 hex>/ (ADR 0015 decision 3) is the
// adapters' own: the names, the encodings, the tombstone retention and the
// marker's lock come from objregistry, the mailbox keys from objmailbox
// (changed after the review of work package 9; they were copies). What is
// left here is the tool's own: the lease's name below the prefix (objlease.Key
// gives the full key), the mailbox prefix's last element (checked against
// objmailbox.MailboxPrefix by TestTheLayoutIsTheAdapters), a device name's
// check and the binding verdicts, which compose relaybind's checks as
// objregistry's load does.
const (
	pathMarker     = objregistry.MarkerPath
	pathLease      = "lease"
	pathBindings   = objregistry.BindingsPath
	pathTombstones = objregistry.TombstonesPath
	pathRates      = objregistry.RatesPath
	pathMailbox    = "mailbox/"
	pathSelftest   = objregistry.SelftestPath

	tombBytes      = objregistry.TombBytes
	markerBytes    = objregistry.MarkerBytes
	ratesBytes     = objregistry.RatesBytes
	maxRecordBytes = objregistry.MaxRecordBytes
)

var (
	deviceRE = regexp.MustCompile(`^[0-9a-f]{40}$`)

	tombName     = objregistry.TombName
	encodeTomb   = objregistry.EncodeTomb
	decodeTomb   = objregistry.DecodeTomb
	encodeMarker = objregistry.EncodeMarker
	decodeMarker = objregistry.DecodeMarker
	entryKey     = objmailbox.EntryKey
	parseEntry   = objmailbox.ParseEntryKey
)

func parseTombName(name string) (relayregistry.TombKey, bool) {
	k, err := objregistry.ParseTombName(name)
	return k, err == nil
}

// scopeName is the scope's word in a report.
func scopeName(s relaybind.Scope) string {
	switch s {
	case relaybind.ScopePair:
		return "pair"
	case relaybind.ScopeAll:
		return "all"
	case relaybind.ScopeDevice:
		return "device"
	}
	return "unknown"
}

func parseDevice(name string) (party.Fingerprint, bool) {
	var d party.Fingerprint
	if !deviceRE.MatchString(name) {
		return d, false
	}
	hex.Decode(d[:], []byte(name))
	return d, true
}

// bindingVerdict is what a load would do with a stored binding.
type bindingVerdict int

const (
	bindLoaded     bindingVerdict = iota // verifies and is admitted
	bindNotYet                           // verifies at its start time; kept, not served
	bindExpired                          // dropped by the load
	bindLifetime                         // over the relay's lifetime: dropped
	bindRevoked                          // below a tombstone: dropped
	bindUnverified                       // fails verification: left in place, not loaded
)

func (v bindingVerdict) String() string {
	names := [...]string{"loads", "not valid yet (kept, not served)", "expired (the load drops it)", "over the relay's maximum lifetime (the load drops it)", "below a tombstone (the load drops it)", "fails verification (left in place, not loaded)"}
	if v < 0 || int(v) >= len(names) {
		return "unknown"
	}
	return names[v]
}

// checkedBinding is a stored binding verified as objregistry's load does
// (verifyStored), before the tombstones are known: a final verdict, or
// bindLoaded with the verified binding and the time it is admitted at.
type checkedBinding struct {
	verdict bindingVerdict
	vb      relaybind.VerifiedBinding
	at      int64
	cause   error
}

// checkBinding decodes and verifies a stored binding of device d at now.
func checkBinding(d party.Fingerprint, data []byte, now int64, pol relaybind.Policy) checkedBinding {
	st, err := objregistry.DecodeRecord(data)
	if err != nil {
		return checkedBinding{verdict: bindUnverified, cause: err}
	}
	stmt, err := relaybind.ParseStatement(st.Sign1)
	if err != nil {
		return checkedBinding{verdict: bindUnverified, cause: err}
	}
	vkey, err := relaybind.ParseCOSEKey(st.COSEKey)
	if err != nil {
		return checkedBinding{verdict: bindUnverified, cause: err}
	}
	at := now
	vb, err := relaybind.VerifyBinding(stmt, vkey, d, at, pol)
	if errors.Is(err, relaybind.ErrNotYetValid) {
		if b, perr := relaybind.ParseBinding(stmt.Payload()); perr == nil {
			at = b.From
			vb, err = relaybind.VerifyBinding(stmt, vkey, d, at, pol)
		}
	}
	switch {
	case errors.Is(err, relaybind.ErrExpired):
		return checkedBinding{verdict: bindExpired, cause: err}
	case errors.Is(err, relaybind.ErrLifetimePolicy):
		return checkedBinding{verdict: bindLifetime, cause: err}
	case errors.Is(err, relaybind.ErrNotYetValid):
		return checkedBinding{verdict: bindNotYet, cause: err}
	case err != nil:
		return checkedBinding{verdict: bindUnverified, cause: err}
	}
	return checkedBinding{verdict: bindLoaded, vb: vb, at: at}
}

// names are the three tombstone names that apply to a verified binding of d.
func (c checkedBinding) names(d party.Fingerprint) []relayregistry.TombKey {
	if c.verdict != bindLoaded {
		return nil
	}
	k := c.vb.Key()
	return []relayregistry.TombKey{
		{Scope: relaybind.ScopePair, Key: k, Device: d},
		{Scope: relaybind.ScopeAll, Key: k},
		{Scope: relaybind.ScopeDevice, Device: d},
	}
}

// admit is the verdict against the tombstones (objregistry's admitStored).
func (c checkedBinding) admit(d party.Fingerprint, now int64, pol relaybind.Policy, tombs func(relaybind.KeyHash, party.Fingerprint) relaybind.Tombstones) (bindingVerdict, error) {
	if c.verdict != bindLoaded {
		return c.verdict, c.cause
	}
	if err := relaybind.Admit(c.vb, tombs(c.vb.Key(), d), c.at, pol); err != nil {
		if errors.Is(err, relaybind.ErrRevoked) {
			return bindRevoked, err
		}
		return bindUnverified, err
	}
	if c.at != now {
		return bindNotYet, nil
	}
	return bindLoaded, nil
}

// tombRetention is the lock objregistry writes for a tombstone version
// (objregistry.TombstoneRetention).
func tombRetention(nb int64, now time.Time, mode s3client.Mode) (*s3client.Retention, error) {
	return objregistry.TombstoneRetention(nb, now, mode)
}

func fp(f party.Fingerprint) string { return hex.EncodeToString(f[:]) }

func short(s string) string {
	if len(s) > 16 {
		return s[:16] + "…"
	}
	return s
}
