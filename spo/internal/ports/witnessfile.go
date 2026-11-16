package ports

import (
	"context"

	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// SigningApprover shows a signer what a body does and asks for approval
// before a witness is made. Upstream's 05d `sign` shows the id, the dates,
// the type and the ticker, not the transaction, and asks nothing
// (SPO-05d-INV-008, SPO-05d-SEC-002); the port shows the decoded body and a
// witness is made only on a yes.
type SigningApprover interface {
	// ApproveSigning gets the decoded body (certificates, deposits, outputs,
	// fee, TTL, required signers) and the name of the slot it signs for.
	ApproveSigning(ctx context.Context, slot string, v party.TxView) (bool, error)
}
