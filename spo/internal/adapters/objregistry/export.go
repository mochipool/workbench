package objregistry

import (
	"fmt"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
)

// The layout and the encodings, for the store tools (adapters/relaystore,
// ADR 0015 work package 9), which read and write this adapter's objects
// without a Registry: an operator's tool must name, decode and lock them
// exactly as the relay does. Each is the adapter's own; nothing here is a
// second copy.

// The names below Prefix (IF-802).
const (
	MarkerPath     = markerPath
	BindingsPath   = bindingsPath
	TombstonesPath = tombstonesPath
	RatesPath      = ratesPath
	SelftestPath   = selftestPath
)

// The sizes of the objects, which every get asks for and no more.
const (
	MaxRecordBytes = maxRecordBytes
	TombBytes      = tombBytes
	MarkerBytes    = markerBytes
	RatesBytes     = ratesBytes
)

// MaxLockAhead is the longest a tombstone version may be locked from now, in
// seconds (PRE-808).
const MaxLockAhead = maxLockAhead

// TombName is a tombstone's name below TombstonesPath.
func TombName(k relayregistry.TombKey) string { return tombName(k) }

// ParseTombName reads a tombstone's name strictly.
func ParseTombName(name string) (relayregistry.TombKey, error) { return parseTombName(name) }

// IsProbeName reports the name below TombstonesPath that the self-test's probe
// of the simple-delete deny uses (selftest-<16 hex>): no state, skipped by a
// load.
func IsProbeName(name string) bool { return selftestRE.MatchString(name) }

// EncodeTomb and DecodeTomb are a tombstone version's body.
func EncodeTomb(notBefore int64) []byte { return encodeTomb(notBefore) }

// DecodeTomb reads a tombstone version's body strictly.
func DecodeTomb(b []byte) (int64, error) { return decodeTomb(b) }

// EncodeMarker and DecodeMarker are the marker's body in either bucket.
func EncodeMarker(node [32]byte) []byte { return encodeMarker(node) }

// DecodeMarker reads a marker and returns the node key it names.
func DecodeMarker(b []byte) ([32]byte, error) { return decodeMarker(b) }

// EncodeRates and DecodeRates are the rate object's body.
func EncodeRates(s relayregistry.RateSnapshot) []byte { return encodeRates(s) }

// DecodeRates reads the rate object strictly.
func DecodeRates(b []byte) (relayregistry.RateSnapshot, error) { return decodeRates(b) }

// StoredRecord is a binding object's content before verification.
type StoredRecord struct {
	LastAuth int64
	// SendersOK is false when the expected-sender list is not strictly
	// ascending (the load drops the list, not the binding).
	SendersOK      bool
	Sign1, COSEKey []byte
}

// DecodeRecord reads a binding object as the load does.
func DecodeRecord(b []byte) (StoredRecord, error) {
	s, err := decodeRecord(b)
	return StoredRecord{LastAuth: s.lastAuth, SendersOK: s.sendersOK, Sign1: s.sign1, COSEKey: s.coseKey}, err
}

// MarkerLock is the lock of a registry-bucket marker version written at now:
// MarkerRetention in mode, to the second.
func MarkerLock(now time.Time, mode s3client.Mode) *s3client.Retention {
	return &s3client.Retention{Mode: mode, Until: now.Add(MarkerRetention).UTC().Truncate(time.Second)}
}

// TombstoneLockNeed is the end, in unix seconds, that a version holding the
// not-before nb must stay locked until for the tombstone to outlive every
// binding it revokes: nb plus the maximum lifetime, the skew and a second, when
// the core's sweep may drop it.
func TombstoneLockNeed(nb int64) int64 {
	return nb + relaybind.MaxLifetimeSeconds + relaybind.SkewSeconds + 1
}

// TombstoneRetention is the lock this adapter writes for a tombstone version
// with not-before nb at now (SEC-801, PRE-808): until TombstoneLockNeed(nb),
// never less than an hour from now (the store refuses a date that is not in
// the future), and refused with ErrLockTooLong when it would end more than
// MaxLockAhead from now. A not-before outside 0 to relaybind.MaxTime is
// refused.
func TombstoneRetention(nb int64, now time.Time, mode s3client.Mode) (*s3client.Retention, error) {
	if nb < 0 || nb > relaybind.MaxTime {
		return nil, fmt.Errorf("the not-before %d is not a unix time from 0 to %d", nb, relaybind.MaxTime)
	}
	until := time.Unix(TombstoneLockNeed(nb), 0)
	if floor := now.Add(minRetention).Truncate(time.Second); until.Before(floor) {
		until = floor
	}
	if limit := now.Unix() + maxLockAhead; until.Unix() > limit {
		return nil, fmt.Errorf("%w: not-before %d locks until %d, more than %d s ahead", ErrLockTooLong, nb, until.Unix(), maxLockAhead)
	}
	return &s3client.Retention{Mode: mode, Until: until.UTC()}, nil
}

// LockedAsWanted reports whether a version's retention, as a read reported
// it, is at least the one asked for: the same mode or compliance, and a date
// no earlier (PRE-810).
func LockedAsWanted(got, want *s3client.Retention) bool { return lockedAsWanted(got, want) }

// LocksFor reports whether a version holding nb and locked as lock protects
// that not-before for its whole life in a deployment of mode: locked in mode
// or in compliance, until TombstoneLockNeed(nb) or later. A version that does
// not (a short lock, a governance lock in a compliance deployment, none) is
// still enforced while it exists, but is not counted as stored: whoever can
// write one can delete it by its id once its lock ends (PRE-811).
func LocksFor(nb int64, lock *s3client.Retention, mode s3client.Mode) bool {
	if mode == "" {
		mode = s3client.Compliance
	}
	return lock != nil && (lock.Mode == mode || lock.Mode == s3client.Compliance) && lock.Until.Unix() >= TombstoneLockNeed(nb)
}

// SelftestPerSweep is the most entries of the selftest/ listing one sweep
// reads (one page) for the self-test's objects whose lock has ended
// (OUT-809).
const SelftestPerSweep = 64
