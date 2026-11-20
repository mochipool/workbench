package sqlitestore

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"testing"

	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// The locked-buffer check of this package. Every secret.Buffer locks at least
// one page against RLIMIT_MEMLOCK, so a buffer that is never destroyed is a
// leak that, repeated, ends a long run with ErrMemoryLimit (go test -count=2 did
// so). Two checks catch one:
//
//   - noLeakedBuffers, which the fixtures (template, scratchUnpresented and so
//     every test that builds a workspace through them) call: the test fails by
//     name when it ends with more live buffers than it began with;
//   - checkNoLeakAtExit in TestMain: the whole run must end with as many live
//     buffers as it began with, which catches a test that uses no fixture.
//
// No test of this package runs in parallel (t.Parallel), so the process-wide
// count is the test's own.
//
// The credential helpers of the tests (pw, passphrase, recovery) make buffers
// the test owns: the store never takes an argument over (its caller destroys
// it), so these are registered with testOwned and destroyed when the check of
// the test that made them runs, before it counts. A buffer the store makes, or
// one a callback hands to the store (pinOf, coldPass: the store destroys those),
// is never registered, so a leak of the store's own still fails the test.

var testOwned struct {
	mu   sync.Mutex
	bufs []*secret.Buffer
}

// owned registers b as the test's own, destroyed at the end of the test.
func owned(b *secret.Buffer) *secret.Buffer {
	testOwned.mu.Lock()
	defer testOwned.mu.Unlock()
	testOwned.bufs = append(testOwned.bufs, b)
	return b
}

// decodeRecovery is seal.DecodeRecoveryKey of a recovery key as printed; the
// raw key it returns is the test's own (owned).
func decodeRecovery(text string) (*secret.Buffer, error) {
	in := secret.Take([]byte(text))
	defer in.Destroy()
	raw, err := seal.DecodeRecoveryKey(in)
	if err != nil {
		return nil, err
	}
	return owned(raw), nil
}

// enrolOwned is EnrolFactor for a test: the plan's output is the caller's
// (cmd/spo destroys it after the rotation), so it is the test's own.
func enrolOwned(ctx context.Context, in FactorInputs, genesisNonce []byte, rnd io.Reader) (FactorPlan, ports.Enrolment, error) {
	p, e, err := EnrolFactor(ctx, in, genesisNonce, rnd)
	owned(p.Output)
	return p, e, err
}

// dropped destroys a buffer a call returned (a recovery key a test does not
// read) and returns the call's error.
func dropped(b *secret.Buffer, err error) error {
	b.Destroy()
	return err
}

// closed closes the handle an open returned (an open that is only checked for
// its error still holds the keys) and returns the open's error.
func closed(s *Store, err error) error {
	if s != nil {
		s.Close()
	}
	return err
}

func ownedMark() int {
	testOwned.mu.Lock()
	defer testOwned.mu.Unlock()
	return len(testOwned.bufs)
}

// destroyOwnedFrom destroys the test-owned buffers registered since mark.
func destroyOwnedFrom(mark int) {
	testOwned.mu.Lock()
	defer testOwned.mu.Unlock()
	if mark > len(testOwned.bufs) {
		return
	}
	for _, b := range testOwned.bufs[mark:] {
		b.Destroy()
	}
	testOwned.bufs = testOwned.bufs[:mark]
}

// noLeakedBuffers fails t when the test ends with more live locked buffers than
// it had at this call. Call it before anything of the test allocates one.
func noLeakedBuffers(t testing.TB) {
	t.Helper()
	base, mark := secret.Budget().Live, ownedMark()
	t.Cleanup(func() {
		destroyOwnedFrom(mark)
		if got := secret.Budget().Live; got > base {
			t.Errorf("this test leaves %d locked buffer(s) alive: a secret.Buffer is not destroyed", got-base)
		}
	})
}

// liveAtStart is the count TestMain saw before the run.
var liveAtStart int

// checkNoLeakAtExit returns a non-zero exit code when the run left buffers
// alive. Fixtures that live for the whole run hold no locked buffer.
func checkNoLeakAtExit(code int) int {
	destroyOwnedFrom(0)
	if got := secret.Budget().Live; got > liveAtStart {
		fmt.Fprintf(os.Stderr, "FAIL: the tests of this package left %d locked buffer(s) alive (a secret.Buffer not destroyed); the fixtures' check names the test when it uses one\n", got-liveAtStart)
		if code == 0 {
			return 1
		}
	}
	return code
}
