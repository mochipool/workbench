package sqlitestore

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/checkpoint"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
)

// The checkpoint key record (ADR 0012 stage 2) is a named record. A restore
// replaces the whole file, so the record of the replaced workspace would be lost
// silently: restore_counters.go carries it, or reports a different one.

var checkpointKeyRef = ports.NamedRef{Name: "checkpoint", Kind: ports.CheckpointKey}

// readCheckpointKey returns the record's bytes, or nil when there is none.
func readCheckpointKey(ctx context.Context, s ports.Store) ([]byte, error) {
	var raw []byte
	err := labels.Named(s).View(ctx, func(r ports.NamedReader) error {
		b, err := r.Get(checkpointKeyRef)
		if errors.Is(err, ports.ErrNotFound) {
			return nil
		}
		raw = b
		return err
	})
	return raw, err
}

// checkpointKeyHash is the key hash a record names, nil when it does not parse.
func checkpointKeyHash(raw []byte) []byte {
	if raw == nil {
		return nil
	}
	r, err := checkpoint.ParseKeyRecord(raw)
	if err != nil {
		return nil
	}
	return r.Hash()
}

// txStore is a ports.Store over a writer that is already inside a transaction, so
// that the label resolver can write the record in the transaction of the counters.
type txStore struct{ w ports.Writer }

func (t txStore) View(_ context.Context, fn func(ports.Reader) error) error   { return fn(t.w) }
func (t txStore) Update(_ context.Context, fn func(ports.Writer) error) error { return fn(t.w) }

func putCheckpointKey(ctx context.Context, w ports.Writer, raw []byte) error {
	return labels.Named(txStore{w}).Update(ctx, func(nw ports.NamedWriter) error { return nw.Put(checkpointKeyRef, raw) })
}

func keyEvent(kind string, hashes ...[]byte) []any {
	ev := []any{kind}
	for _, h := range hashes {
		ev = append(ev, hex.EncodeToString(h))
	}
	switch kind {
	case "checkpoint-key-carried":
		return append(ev, "carried from the replaced workspace: the backup held no checkpoint key")
	}
	return append(ev, "the backup's own checkpoint key was kept; the key of the replaced workspace is no longer in this workspace and pins made with it do not match new backups")
}

// checkpointKeyReadable names a record that does not parse, for a verification.
func checkpointKeyProblem(raw []byte) error {
	if _, err := checkpoint.ParseKeyRecord(raw); err != nil {
		return fmt.Errorf("the checkpoint key record is malformed: %w", err)
	}
	return nil
}
