package sqlitestore

import (
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// An open through the recovery key that fails after the key was accepted (here
// the verification of an edited audit row) leaves no locked buffer behind: the
// copy of the recovery key the handle would have kept is destroyed with the
// master key and the derived keys.
//
// spec: SPO-Xunlock-SEC-007
func TestAFailedRecoveryOpenLeavesNoLockedBuffer(t *testing.T) {
	s, path, rec := scratch(t)
	put(t, s, counter, "1")
	s.Close()
	db := rawDB(t, path)
	if _, err := db.Exec(`UPDATE audit SET at = at + 1 WHERE seq = (SELECT max(seq) FROM audit)`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	rk := secret.Take([]byte(rec))
	before := secret.Budget().Live
	_, err := OpenWithRecovery(path, rk)
	after := secret.Budget().Live
	rk.Destroy()
	if !errors.Is(err, ErrVerify) {
		t.Fatalf("open with an edited audit row: %v, want a verification error", err)
	}
	if after != before {
		t.Fatalf("the failed open left %d locked buffer(s) alive", after-before)
	}
}
