package mailbox

import "errors"

// DecodeAny is the internal decoder without a direction or a stage, for tests
// that exercise the codec on every type: it tries each side at each stage and
// returns the first message that decodes. A frame that no combination takes is
// reported with the first error that is not a refusal of its sender or stage (a
// field error), else with the refusal of the first combination. Sessions use
// DecodeFromClientIn and DecodeFromRelayIn.
func DecodeAny(frame []byte) (Message, error) {
	var first error
	for _, c := range []struct {
		stage  Stage
		client bool
	}{{StageV2PreAuth, true}, {StageV2Authed, true}, {StageV2PreAuth, false}, {StageV2Authed, false}} {
		m, err := decodeIn(c.stage, frame, c.client)
		if err == nil {
			return m, nil
		}
		if !errors.Is(err, ErrDirection) && !errors.Is(err, ErrStage) {
			return nil, err
		}
		if first == nil {
			first = err
		}
	}
	return nil, first
}

// UncheckedValid makes a ValidQuota without Validate, for tests of the
// arithmetic with figures the table forbids.
func UncheckedValid(q Quota) ValidQuota { return ValidQuota{q: q, ok: true} }
