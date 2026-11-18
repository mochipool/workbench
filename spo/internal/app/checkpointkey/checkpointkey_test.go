package checkpointkey

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/checkpoint"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/fakesk"
)

type mem struct {
	rec            *checkpoint.KeyRecord
	saves, deletes int
}

func (m *mem) Load(context.Context) (*checkpoint.KeyRecord, error) { return m.rec, nil }
func (m *mem) Save(_ context.Context, r checkpoint.KeyRecord) error {
	m.rec = &r
	m.saves++
	return nil
}
func (m *mem) Delete(context.Context) error { m.rec = nil; m.deletes++; return nil }

func pin(p string) func(context.Context) (*ports.Secret, error) {
	return func(context.Context) (*ports.Secret, error) { return ports.TakeSecret([]byte(p)) }
}

type rig struct {
	t        *testing.T
	sk       *fakesk.Source
	recs     *mem
	env      Env
	recovery int
	recErr   error
	daily    [][]byte
}

var ws = bytes.Repeat([]byte{0xab}, 16)

func newRig(t *testing.T, policy string) *rig {
	r := &rig{t: t, sk: fakesk.New(map[string]string{"/dev/a": "1111", "/dev/b": "2222", "/dev/c": "3333"}), recs: &mem{}}
	r.env = Env{WorkspaceID: ws, Policy: policy, Records: r.recs, Signer: r.sk,
		DailyCredentials: func(context.Context) ([][]byte, error) { return r.daily, nil },
		ProveRecovery:    func(context.Context) error { r.recovery++; return r.recErr },
	}
	return r
}

func (r *rig) enrol(dev string, old *OldKey) (checkpoint.KeyRecord, bool, error) {
	pins := map[string]string{"/dev/a": "1111", "/dev/b": "2222", "/dev/c": "3333"}
	return Enrol(context.Background(), r.env, EnrolInput{Device: dev, PIN: pin(pins[dev]), Old: old, FactorSession: true, SessionDevice: "/dev/a"})
}

func (r *rig) oldKey(dev string) *OldKey {
	pins := map[string]string{"/dev/a": "1111", "/dev/b": "2222", "/dev/c": "3333"}
	return &OldKey{Device: dev, PIN: pin(pins[dev])}
}

// The first enrolment needs only the unlocked workspace, on every policy; the key
// is recorded and its hash is the SSH key's SHA-256.
//
// spec: SPO-Xbackup-PRE-016
func TestFirstEnrolmentNeedsNothingMore(t *testing.T) {
	for _, pol := range []string{"standard", "hardware", "strict"} {
		r := newRig(t, pol)
		rec, replaced, err := r.enrol("/dev/b", nil)
		if err != nil || replaced {
			t.Fatalf("%s: %v", pol, err)
		}
		if r.recovery != 0 || r.recs.rec == nil || !bytes.Equal(r.recs.rec.Hash(), rec.Hash()) || r.sk.Signs != 0 {
			t.Fatalf("%s: recovery presented %d times, %d signatures", pol, r.recovery, r.sk.Signs)
		}
		got, err := Show(context.Background(), r.env)
		if err != nil || got.Key.AuthorizedLine() != rec.Key.AuthorizedLine() {
			t.Fatal(err)
		}
	}
	r := newRig(t, "standard")
	if _, err := Show(context.Background(), r.env); !errors.Is(err, ErrNoKey) {
		t.Errorf("%v", err)
	}
}

// The checkpoint authenticator may not be the daily authenticator of the session
// and may not hold a daily credential; the recovery authenticator is allowed.
//
// spec: SPO-Xbackup-PRE-016
func TestTheCheckpointAuthenticatorIsNotADailyOne(t *testing.T) {
	r := newRig(t, "hardware")
	if _, _, err := r.enrol("/dev/a", nil); !errors.Is(err, ErrDailyDevice) {
		t.Fatalf("the daily device: %v", err)
	}
	if r.sk.Enrols != 0 || r.recs.saves != 0 {
		t.Fatal("a credential was made for a refused authenticator")
	}
	// a daily credential found by the credential-id check (the store's list): the
	// fake gives out a fresh random id each time, so the list is made to hold what
	// the authenticator returns
	r.env.Signer = &echoDaily{Source: r.sk, daily: &r.daily}
	r.env.DailyCredentials = func(context.Context) ([][]byte, error) { return r.daily, nil }
	if _, _, err := r.enrol("/dev/b", nil); !errors.Is(err, ErrDailyCred) {
		t.Fatalf("a daily credential: %v", err)
	}
	if r.recs.saves != 0 {
		t.Error("recorded")
	}
	// the recovery authenticator (any token that is not the session's daily one) works
	r2 := newRig(t, "hardware")
	if _, _, err := r2.enrol("/dev/b", nil); err != nil {
		t.Fatalf("the recovery authenticator: %v", err)
	}
	// without a factor session there is no daily device to compare
	r3 := newRig(t, "standard")
	if _, _, err := Enrol(context.Background(), r3.env, EnrolInput{Device: "/dev/a", PIN: pin("1111"), SessionDevice: "/dev/a"}); err != nil {
		t.Fatalf("standard: %v", err)
	}
}

// echoDaily makes the credential it enrols a "daily credential" of the workspace.
type echoDaily struct {
	*fakesk.Source
	daily *[][]byte
}

func (e *echoDaily) EnrolSigner(ctx context.Context, req ports.SignerEnrolRequest) (ports.SignerEnrolment, error) {
	en, err := e.Source.EnrolSigner(ctx, req)
	*e.daily = [][]byte{en.CredentialID}
	return en, err
}

// Replacing or removing needs the recovery credential under standard and
// hardware, before any credential is made.
//
// spec: SPO-Xbackup-PRE-017
func TestReplacingNeedsTheRecoveryCredentialUnderStandardAndHardware(t *testing.T) {
	for _, pol := range []string{"standard", "hardware"} {
		t.Run(pol, func(t *testing.T) {
			r := newRig(t, pol)
			first, _, err := r.enrol("/dev/b", nil)
			if err != nil {
				t.Fatal(err)
			}
			enrols := r.sk.Enrols
			r.recErr = errors.New("wrong recovery key")
			if _, _, err := r.enrol("/dev/c", nil); err == nil || r.sk.Enrols != enrols || !bytes.Equal(r.recs.rec.Hash(), first.Hash()) {
				t.Fatalf("a replacement without the recovery credential: %v", err)
			}
			if err := Remove(context.Background(), r.env, nil); err == nil || r.recs.rec == nil {
				t.Fatalf("a removal without the recovery credential: %v", err)
			}
			r.recErr = nil
			second, replaced, err := r.enrol("/dev/c", nil)
			if err != nil || !replaced || bytes.Equal(second.Hash(), first.Hash()) || !bytes.Equal(r.recs.rec.Hash(), second.Hash()) {
				t.Fatalf("%v", err)
			}
			if r.sk.Signs != 0 {
				t.Error("the old key was asked to sign under a policy with a recovery path")
			}
			if err := Remove(context.Background(), r.env, nil); err != nil || r.recs.rec != nil {
				t.Fatalf("%v", err)
			}
			if err := Remove(context.Background(), r.env, nil); !errors.Is(err, ErrNoKey) {
				t.Fatalf("%v", err)
			}
		})
	}
}

// A strict workspace has no recovery path: replacing or removing needs a
// signature by the existing key over a replacement statement.
//
// spec: SPO-Xbackup-PRE-018
func TestStrictReplacementNeedsTheExistingKeysSignature(t *testing.T) {
	r := newRig(t, "strict")
	first, _, err := r.enrol("/dev/b", nil)
	if err != nil {
		t.Fatal(err)
	}
	// no signature: refused before a credential is made
	enrols := r.sk.Enrols
	if _, _, err := r.enrol("/dev/c", nil); !errors.Is(err, ErrNeedOldKey) || r.sk.Enrols != enrols {
		t.Fatalf("%v", err)
	}
	if err := Remove(context.Background(), r.env, nil); !errors.Is(err, ErrNeedOldKey) || r.recs.rec == nil {
		t.Fatalf("%v", err)
	}
	// the wrong authenticator cannot sign for the old key
	if _, _, err := r.enrol("/dev/c", r.oldKey("/dev/c")); err == nil || !bytes.Equal(r.recs.rec.Hash(), first.Hash()) {
		t.Fatalf("a signature from the wrong authenticator: %v", err)
	}
	// an authenticator whose answer lacks verification
	r.sk.DropUV = true
	if _, _, err := r.enrol("/dev/c", r.oldKey("/dev/b")); err == nil || !bytes.Equal(r.recs.rec.Hash(), first.Hash()) {
		t.Fatalf("an answer without user verification: %v", err)
	}
	r.sk.DropUV = false
	second, replaced, err := r.enrol("/dev/c", r.oldKey("/dev/b"))
	if err != nil || !replaced || !bytes.Equal(r.recs.rec.Hash(), second.Hash()) {
		t.Fatalf("%v", err)
	}
	if r.recovery != 0 {
		t.Error("a strict workspace was asked for a recovery credential")
	}
	if err := Remove(context.Background(), r.env, r.oldKey("/dev/c")); err != nil || r.recs.rec != nil {
		t.Fatalf("%v", err)
	}
}

// The replacement statement is bound to the workspace and the new key: a stale
// time is refused.
//
// spec: SPO-Xbackup-PRE-018
func TestAStaleReplacementIsRefused(t *testing.T) {
	r := newRig(t, "strict")
	if _, _, err := r.enrol("/dev/b", nil); err != nil {
		t.Fatal(err)
	}
	base := time.Now()
	n := 0
	r.env.Now = func() time.Time { n++; return base.Add(time.Duration(n) * time.Hour) }
	if _, _, err := r.enrol("/dev/c", r.oldKey("/dev/b")); err == nil || !strings.Contains(err.Error(), "not recent") {
		t.Fatalf("%v", err)
	}
}
