package cli

import "errors"

// Exit codes of the transaction-status and wait commands (SPO-Xconfirm-OUT-001,
// SPO-Xconfirm-OUT-002). Every other failure exits 1.
const (
	// spo tx status
	ExitTxPending  = 10 // seen, in a mempool or not yet at the depth asked
	ExitTxNotSeen  = 11 // every provider answered: not seen
	ExitTxUnknown  = 12 // no usable answer, or seen by one and the rest silent
	ExitTxDisagree = 13 // one provider has seen it and another has not
	// --wait after a submission
	ExitWaitTimedOut = 20
	ExitWaitExpired  = 21
	ExitWaitUnknown  = 22
	ExitWaitDisagree = 23
	ExitWaitCancel   = 130
)

// ExitError is an error that carries the process exit status. The message is
// what is printed; the composition root exits with Code.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string { return e.Err.Error() }
func (e *ExitError) Unwrap() error { return e.Err }

// ExitCode is the exit status for err: the code of an ExitError in its chain,
// else 1 for any other error, else 0.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *ExitError
	if errors.As(err, &ee) && ee.Code > 0 {
		return ee.Code
	}
	return 1
}
