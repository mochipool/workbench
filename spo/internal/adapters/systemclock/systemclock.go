// Package systemclock is the wall clock.
package systemclock

import (
	"time"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// Clock reads the system time.
type Clock struct{}

// Now implements ports.Clock.
func (Clock) Now() time.Time { return time.Now() }

var _ ports.Clock = Clock{}
