package sqlitestore

import "context"

// setColdStatusHook replaces the cold status read of verifyFile and returns the restore.
func setColdStatusHook(f func(*Store, context.Context) (ColdStatus, error)) func() {
	old := coldStatusFn
	coldStatusFn = f
	return func() { coldStatusFn = old }
}
