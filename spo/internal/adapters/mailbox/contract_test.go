package mailbox_test

import (
	"context"
	"testing"

	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/porttest"
)

// ackAfter acknowledges what it delivered, as multisig.Pump does for an
// EnvelopeAcker once the application handled the envelope. The mailbox keeps
// an envelope until it is acknowledged, and a fetch lists what is not
// acknowledged, so a receiver that never acks is delivered the same envelope
// again by design (SPO-Xparty-INV-017: no suppression in the client). The
// contract's "nothing is delivered twice" therefore holds for the receiver as
// the application uses it.
type ackAfter struct{ ports.EnvelopeAcker }

func (a ackAfter) Receive(ctx context.Context) (ports.Received, error) {
	r, err := a.EnvelopeAcker.Receive(ctx)
	if err == nil {
		err = a.EnvelopeAcker.Ack()
	}
	return r, err
}

// The mailbox client passes the same contract as the file bag and tailcat:
// delivery, the size limit, copying, cancellation. The relay is the real one.
//
// spec: SPO-Xmailbox-IF-009, SPO-Xmailbox-OUT-036
func TestTransportContract(t *testing.T) {
	porttest.Run(t, func(t *testing.T) porttest.Pair {
		w := newWorld(t)
		return porttest.Pair{
			Sender:   w.client(w.a),
			Receiver: ackAfter{w.client(w.b)},
			To:       w.b.fp,
			Via:      ports.ViaNetwork,
		}
	})
}
