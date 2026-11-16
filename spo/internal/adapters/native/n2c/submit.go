package n2c

import (
	"context"
	"errors"
	"fmt"

	"github.com/blinklabs-io/gouroboros/cbor"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/protocol/localstatequery"
	"github.com/blinklabs-io/gouroboros/protocol/localtxsubmission"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var _ ports.TxSubmitter = (*Client)(nil)

// RejectedError: the node's mempool refused the transaction. Reason is the
// node's text of the ledger rule failures when the library could decode them;
// CBOR is the reason as sent.
type RejectedError struct {
	Reason string
	CBOR   []byte
}

func (e *RejectedError) Error() string { return "the node rejected the transaction: " + e.Reason }

// ErrSubmitOutcomeUnknown: the transaction was sent and the answer did not
// come back (timeout, closed connection). It may be in the mempool; query the
// transaction before resubmitting.
var ErrSubmitOutcomeUnknown = errors.New("n2c: the node did not answer the submission; the transaction may be in its mempool")

// txID is the blake2b-256 hash of the transaction body: the first element of
// the transaction array, in the bytes it came in.
func txID(signed []byte) (chain.TxID, error) {
	var parts []cbor.RawMessage
	if _, err := cbor.Decode(signed, &parts); err != nil || len(parts) < 2 {
		return chain.TxID{}, errors.New("n2c submit: the bytes are not a transaction (a CBOR array of body and witnesses)")
	}
	return chain.TxID(lcommon.Blake2b256Hash(parts[0])), nil
}

// Submit sends a signed transaction (CBOR) through local-tx-submission, tagged
// with the node's current era, and returns its id. A refusal is a
// *RejectedError. Once the transaction has been sent, every other error wraps
// ErrSubmitOutcomeUnknown: a protocol error, a decode failure or a dropped
// connection do not say it was not accepted.
func (c *Client) Submit(ctx context.Context, signedTx []byte) (chain.TxID, error) {
	id, err := txID(signedTx)
	if err != nil {
		return chain.TxID{}, err
	}
	var era int
	if err := c.do(ctx, "current era", func(q *localstatequery.Client) error {
		var err error
		era, err = q.GetCurrentEra()
		return err
	}); err != nil {
		return chain.TxID{}, err
	}
	sent := false
	err = c.run(ctx, "submit", func() error {
		sent = true
		return c.conn.LocalTxSubmission().Client.SubmitTx(uint16(era), signedTx)
	})
	if err != nil {
		return chain.TxID{}, submitError(err, sent)
	}
	return id, nil
}

// submitError classifies a failure of the submission exchange: a rejection is
// the node's answer; once the transaction was sent, anything else leaves its
// fate unknown; before that, nothing happened.
func submitError(err error, sent bool) error {
	var rej localtxsubmission.TransactionRejectedError
	if errors.As(err, &rej) {
		return &RejectedError{Reason: rej.Error(), CBOR: rej.ReasonCbor}
	}
	if sent { // once the bytes may have left, no failure but a rejection says the transaction was not taken
		return fmt.Errorf("%w: %v", ErrSubmitOutcomeUnknown, err)
	}
	return err
}

// InMempool asks the node's mempool (local-tx-monitor) whether it holds the
// transaction. Value(false) is a positive "not in the mempool at this
// snapshot", which does not say the transaction was never seen or was
// confirmed; a failed query is Unknown.
func (c *Client) InMempool(ctx context.Context, id chain.TxID) (chain.Reading[bool], error) {
	var era int
	if err := c.do(ctx, "current era", func(q *localstatequery.Client) error {
		var err error
		era, err = q.GetCurrentEra()
		return err
	}); err != nil {
		return unknown[bool](ctx, err)
	}
	var has bool
	err := c.run(ctx, "mempool", func() error {
		m := c.conn.LocalTxMonitor().Client
		defer func() { _ = m.Release() }()
		var err error
		has, err = m.HasTxForEra(uint8(era), id[:])
		return err
	})
	if err != nil {
		return unknown[bool](ctx, err)
	}
	return chain.Value(has), nil
}
