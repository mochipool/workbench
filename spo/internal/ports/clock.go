package ports

import "time"

// Clock gives the wall-clock time. Tests use a fixed clock.
type Clock interface {
	Now() time.Time
}
