package mailbox

import "errors"

// DecodeAny is the internal decoder without a direction, for tests that
// exercise the codec on every type. Sessions use DecodeFromClient and
// DecodeFromRelay.
func DecodeAny(frame []byte) (Message, error) {
	m, err := decode(frame, true)
	if errors.Is(err, ErrDirection) {
		return decode(frame, false)
	}
	return m, err
}

// UncheckedValid makes a ValidQuota without Validate, for tests of the
// arithmetic with figures the table forbids.
func UncheckedValid(q Quota) ValidQuota { return ValidQuota{q: q, ok: true} }
