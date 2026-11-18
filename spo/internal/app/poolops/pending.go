package poolops

import (
	"fmt"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/assets"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// The pool registration and retirement records are written when the
// transaction is confirmed (hazard H9, SPO-Xconfirm-PR-001, PR-002). A
// command that sends the transaction keeps a pending update under the
// transaction's id (assets.Pending, kinds PendingPoolRegistration and
// PendingPoolRetirement); the appliers below are what settling it does. They
// run inside the store commit that removes the pending update.

// ApplyRegistration writes regEpoch and regSubmitted, as the submit used to.
// It has the signature of the appliers of the settle use case.
func ApplyRegistration(w ports.NamedWriter, p assets.Pending, _ time.Time) error {
	return updateDescriptor(w, p, func(d *pool.Descriptor) { d.RecordSubmission(p.Epoch, p.Stamp) })
}

// ApplyRetirement writes deregSubmitted, as the submit used to.
func ApplyRetirement(w ports.NamedWriter, p assets.Pending, _ time.Time) error {
	return updateDescriptor(w, p, func(d *pool.Descriptor) { d.RecordRetirement(p.Stamp) })
}

func updateDescriptor(w ports.NamedWriter, p assets.Pending, f func(*pool.Descriptor)) error {
	if p.Pool == "" || p.Stamp == "" {
		return fmt.Errorf("the pending update of transaction %s has no pool or no stamp", p.TxID)
	}
	ref := ports.NamedRef{Name: p.Pool, Kind: ports.PoolDescriptor}
	raw, err := w.Get(ref)
	if err != nil {
		return fmt.Errorf("the descriptor of pool %s: %w", p.Pool, err)
	}
	d, err := pool.ParseDescriptor(raw)
	if err != nil {
		return err
	}
	f(d)
	return w.Put(ref, d.Render())
}
