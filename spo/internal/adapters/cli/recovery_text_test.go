package cli

import (
	"context"
	"testing"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// The recovery key typed to open a recovery session is held only until the proof has used
// it: after the proof's callback ran, no copy of it is left in the app.
//
// spec: SPO-Xcustody-PRE-035
func TestTheRecoveryTextIsDestroyedOnceTheProofHasUsedIt(t *testing.T) {
	a := newApp(Deps{})
	base := secret.Budget().Live
	a.recText = secret.Take([]byte("ABCD-EFGH"))
	_, cur := a.recoveryOpens("hardware", "", "/dev/x", -1, -1, -1)
	got, err := cur.Recovery(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if a.recText != nil {
		t.Fatal("the app still holds the recovery text after the proof used it")
	}
	got.Destroy()
	if live := secret.Budget().Live; live != base {
		t.Errorf("%d guarded buffers live, %d before", live, base)
	}
}
