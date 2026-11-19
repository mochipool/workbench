// Package relaylock is the relay-login lock of a workspace (ADR 0014 work
// package 9, SPO-Xmailbox-PRE-067): an exclusive advisory lock on a file beside
// the workspace file, held by every process for as long as it is logged in to
// the relays or dials them (serve, connect and login over the relays, forget,
// send-revokes, forget --lost and revoke --import sending), so that one device
// never has two logins from two processes, each with its own revoke book and
// both flushing one outbox. The store's own lock is shared and cannot say this.
//
// The lock is flock(2) on unix, taken without waiting: a second process is
// refused at once. The kernel drops it when the process ends, however it ends,
// so a file left behind by a crash refuses nothing. On a platform without flock
// there is no lock: Acquire succeeds and two processes are not kept apart.
package relaylock

import "errors"

// ErrHeld is the refusal of a second holder.
var ErrHeld = errors.New("another spo process is logged in to the relays with this workspace, or is sending to them")

// Lock is a held relay-login lock.
type Lock struct{ release func() error }

// Release drops the lock; a second call does nothing.
func (l *Lock) Release() error {
	if l == nil || l.release == nil {
		return nil
	}
	r := l.release
	l.release = nil
	return r()
}
