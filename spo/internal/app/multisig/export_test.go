package multisig

import (
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// EnqueueForTest and EnqueueRotationForTest let the external tests call the
// two ways an item enters the outbox.
func (n Node) EnqueueForTest(w ports.Writer, now time.Time, sealer party.Fingerprint, add ...OutItem) error {
	return n.enqueue(w, now, sealer, add...)
}

func (n Node) EnqueueRotationForTest(w ports.Writer, now time.Time, old party.Fingerprint, add ...OutItem) error {
	return n.enqueueRotation(w, now, old, add...)
}
