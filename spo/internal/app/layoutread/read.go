package layoutread

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/mochipool/workbench/spo/internal/domain/layout"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var errTooLarge = errors.New("the file is larger than expected")

// maxSigBytes bounds a signature file.
const maxSigBytes = 16 << 10

type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// readAll reads a named file of at most max bytes. A longer file is errTooLarge:
// the reader stops after max+1 bytes, so a hostile file never costs more than
// that.
func readAll(ctx context.Context, r ports.ObjectReader, name string, max int64) ([]byte, error) {
	rc, err := r.Get(ports.WithExpectedSize(ctx, max), name)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(&ctxReader{ctx, rc}, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%w (more than %d bytes)", errTooLarge, max)
	}
	return b, nil
}

// fetchObject reads the object with the hash by name and checks what needs no key:
// that its bytes hash to its name and that its size is a bucket. what says what
// the object is, for the message.
func fetchObject(ctx context.Context, r ports.ObjectReader, hash []byte, what string) ([]byte, error) {
	return fetchBounded(ctx, r, hash, what, layout.MaxBucket)
}

// fetchBounded is fetchObject for an object of a kind with a bound below the
// largest bucket (the slots object): a longer file is refused after max+1 bytes.
func fetchBounded(ctx context.Context, r ports.ObjectReader, hash []byte, what string, max int) ([]byte, error) {
	name := hex.EncodeToString(hash)
	p, err := layout.ObjectPath(name)
	if err != nil {
		return nil, fmt.Errorf("%w: %s has no valid object name", ErrObject, what)
	}
	b, err := readAll(ctx, r, p, int64(max))
	switch {
	case errors.Is(err, ports.ErrObjectNotFound):
		return nil, fmt.Errorf("%w: %s, object %s, is not in the directory", ErrObject, what, name)
	case errors.Is(err, errTooLarge):
		return nil, fmt.Errorf("%w: %s, object %s: the directory holds wrong content under that name (the file is larger than %d bytes, the most %s may be)", ErrObject, what, name, max, what)
	case err != nil:
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%w: %s, object %s, could not be read: %v", ErrObject, what, name, err)
	}
	if layout.ObjectName(b) != name {
		return nil, fmt.Errorf("%w: %s, object %s: the directory holds wrong content under that name (its bytes do not hash to the name)", ErrObject, what, name)
	}
	if !layout.IsBucket(len(b)) {
		return nil, fmt.Errorf("%w: %s, object %s, is %d bytes, which is not a bucket size", ErrObject, what, name, len(b))
	}
	return b, nil
}

// SnapshotOf is the meta row and slot rows of the slots object, as a snapshot
// carries them. The schema version and the transient cleanup marker are the
// writer's.
func SnapshotOf(so layout.SlotsObject) (ports.SnapshotMeta, []ports.SnapshotSlot) {
	m := so.Meta
	meta := ports.SnapshotMeta{
		WorkspaceID: append([]byte{}, m.WorkspaceID...), FormatVersion: int64(m.StoreFormat), CreatedAt: m.CreatedAt,
		KeyEpoch: append([]byte{}, m.KeyEpoch...), EpochMAC: append([]byte{}, m.EpochMAC...), Policy: m.Policy,
	}
	if m.RecoveryPub != nil {
		meta.RecoveryPub = append([]byte{}, m.RecoveryPub...)
	}
	slots := make([]ports.SnapshotSlot, len(so.Slots))
	cp := func(b []byte) []byte {
		if b == nil {
			return nil
		}
		return append([]byte{}, b...)
	}
	cpi := func(p *int64) *int64 {
		if p == nil {
			return nil
		}
		v := *p
		return &v
	}
	for i, s := range so.Slots {
		slots[i] = ports.SnapshotSlot{ID: cp(s.ID), Kind: s.Kind, KDFMemoryKiB: cpi(s.KDFMemoryKiB), KDFPasses: cpi(s.KDFPasses), KDFLanes: cpi(s.KDFLanes),
			Salt: cp(s.Salt), KeyCommit: cp(s.KeyCommit), Nonce: cp(s.Nonce), WrappedKey: cp(s.WrappedKey), Bound: s.Bound, RecHash: cp(s.RecHash), Factors: cp(s.Factors)}
	}
	return meta, slots
}
