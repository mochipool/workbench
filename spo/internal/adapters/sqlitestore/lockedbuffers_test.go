package sqlitestore

import (
	"path/filepath"
	"testing"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// An ordinary unlock holds the locked buffers it held before the object
// envelope of ADR 0012 stage 3: that key is derived on demand by a conversion
// and is not part of an open workspace, so the locked-memory floor of every
// operator is unchanged. The figure is the one at the commit before stage 3.
//
// spec: SPO-Xlayout-SEC-005
func TestOpenHoldsTheSameLockedBuffersAsBeforeTheObjectEnvelope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ws.db")
	rk, err := Init(path, passphrase("pw"))
	if err != nil {
		t.Fatal(err)
	}
	rk.Destroy()
	base := secret.Budget().Live
	pwb := passphrase("pw") // counted: the caller's own credential buffer
	s, err := Open(path, pwb)
	if err != nil {
		t.Fatal(err)
	}
	held := secret.Budget().Live - base
	s.Close()
	pwb.Destroy()
	t.Logf("an open workspace holds %d locked buffers", held)
	if held != lockedBuffersOfAnOpenWorkspace {
		t.Fatalf("an open workspace holds %d locked buffers, want %d", held, lockedBuffersOfAnOpenWorkspace)
	}
	if got := secret.Budget().Live; got != base {
		t.Fatalf("Close left %d buffers", got-base)
	}
}
