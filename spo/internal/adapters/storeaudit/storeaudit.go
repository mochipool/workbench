// Package storeaudit records the dangerous workspace operations (export,
// unprotect, import) in the store itself (ports.WorkspaceAuditor).
//
// An event is appended to one record, ports.WorkspaceAuditLog, through
// ports.Store.Update. In the sealed store that write is a row of the
// MAC-chained audit log, so the event cannot be removed or reordered without
// breaking verification. The record keeps the newest MaxEvents events; older
// ones are evicted, and the chain keeps proof that each write happened.
//
// The record holds the time, the operation, the owners' names, counts, the
// flags the use case passes and the operator's reason. It never holds key
// material or file contents (ADR 0004: names are Sensitive, so the record is
// sealed in the sealed store).
//
// Record returns an error when the write fails, and the use case stops: an
// operation that cannot be audited does not happen. A stored log that cannot
// be read is also an error, never replaced.
package storeaudit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// MaxEvents is how many events the record keeps.
const MaxEvents = 4096

// MaxReasonBytes bounds the operator's reason.
const MaxReasonBytes = 1024

// Ref is the reference of the log record.
var Ref = ports.Ref{Name: "workspace", Kind: ports.WorkspaceAuditLog}

// ErrReasonTooLong means the reason is longer than MaxReasonBytes.
var ErrReasonTooLong = errors.New("the audit reason is too long")

// ErrBadLog means the stored log does not parse; it is left as it is.
var ErrBadLog = errors.New("the stored workspace audit log cannot be read")

// Event is one entry of the log.
type Event struct {
	Time          time.Time `json:"time"`
	Operation     string    `json:"operation"`
	Owners        []string  `json:"owners,omitempty"`
	PlaintextKeys int       `json:"plaintext_keys"`
	ProtectedKeys int       `json:"protected_keys"`
	Protected     bool      `json:"protected"`
	Acknowledged  bool      `json:"acknowledged"`
	Reason        string    `json:"reason,omitempty"`

	// Set for a read that rested on one source (Operation "single-source-read").
	Command      string `json:"command,omitempty"`
	Read         string `json:"read,omitempty"`
	Source       string `json:"source,omitempty"`
	SingleSource bool   `json:"single_source,omitempty"`
}

type logFile struct {
	Version int     `json:"v"`
	Events  []Event `json:"events"`
}

// Auditor implements ports.WorkspaceAuditor over a store.
type Auditor struct {
	Store ports.Store
	// Reason is the operator's stated reason, recorded with every event this
	// auditor writes. It is not secret and must not hold any.
	Reason string
	// Now gives the time; nil means time.Now.
	Now func() time.Time
}

// Record appends e to the log in one Update.
func (a *Auditor) Record(ctx context.Context, e ports.AuditEvent) error {
	if a == nil || a.Store == nil {
		return errors.New("storeaudit: no store")
	}
	if len(a.Reason) > MaxReasonBytes {
		return ErrReasonTooLong
	}
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}
	ev := Event{
		Time: now().UTC().Truncate(time.Second), Operation: e.Operation, Owners: append([]string(nil), e.Owners...),
		PlaintextKeys: e.PlaintextKeys, ProtectedKeys: e.ProtectedKeys, Protected: e.Protected, Acknowledged: e.Acknowledged,
		Reason: a.Reason, Command: e.Command, Read: e.Read, Source: e.Source, SingleSource: e.SingleSource,
	}
	err := a.Store.Update(ctx, func(w ports.Writer) error {
		var lf logFile
		switch data, err := w.Get(Ref); {
		case errors.Is(err, ports.ErrNotFound):
			lf.Version = 1
		case err != nil:
			return err
		default:
			if json.Unmarshal(data, &lf) != nil || lf.Version != 1 {
				return ErrBadLog
			}
		}
		lf.Events = append(lf.Events, ev)
		if n := len(lf.Events) - MaxEvents; n > 0 {
			lf.Events = append([]Event(nil), lf.Events[n:]...)
		}
		out, err := json.Marshal(lf)
		if err != nil {
			return err
		}
		return w.Put(Ref, out)
	})
	if err != nil {
		return fmt.Errorf("storeaudit: the event was not recorded: %w", err)
	}
	return nil
}

// Events reads the log, oldest first, for reports and tests.
func Events(ctx context.Context, s ports.Store) ([]Event, error) {
	var lf logFile
	err := s.View(ctx, func(r ports.Reader) error {
		data, err := r.Get(Ref)
		if errors.Is(err, ports.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if json.Unmarshal(data, &lf) != nil || lf.Version != 1 {
			return ErrBadLog
		}
		return nil
	})
	return lf.Events, err
}

var _ ports.WorkspaceAuditor = (*Auditor)(nil)
