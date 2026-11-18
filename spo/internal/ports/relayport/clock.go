package relayport

import "time"

// Clock gives the wall-clock time. It is the same method set as ports.Clock,
// declared here so that the relay ports do not import the package that holds
// the secret buffers (ADR 0013 decision 1): any ports.Clock is a Clock.
type Clock interface {
	Now() time.Time
}
