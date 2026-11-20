package relaystore

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objlease"
	"github.com/mochipool/workbench/spo/internal/adapters/objregistry"
	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/test/s3stand"
)

// init-store on a new identity writes exactly the markers, the released lease
// and full rate buckets, plus the one locked object of the retention
// self-test, and nothing else; a relay then starts on it.
//
// spec: SPO-Xobjstore-IF-901, SPO-Xobjstore-OUT-901
func TestInitStoreWritesExactlyWhatItSays(t *testing.T) {
	e := newEnv(t)
	rep, err := InitStore(bg(t), e.deps())
	if err != nil {
		t.Fatalf("InitStore: %v", err)
	}
	if rep.AlreadyInitialised {
		t.Error("a new identity reported as initialised")
	}
	reg := e.listAll(regBucket)
	if len(reg) != 2 || reg[0] != "marker" || !strings.HasPrefix(reg[1], "selftest/") || !strings.HasSuffix(reg[1], "-r") {
		t.Errorf("the registry bucket holds %v; want the marker and the retention self-test object", reg)
	}
	mv := e.versions(regBucket, "marker")
	if len(mv) != 1 || mv[0].Mode != "COMPLIANCE" || mv[0].Until.Sub(e.clock.Now()) < 364*24*time.Hour {
		t.Errorf("the marker's versions: %+v", mv)
	}
	work := e.listAll(workBucket)
	if strings.Join(work, ",") != "lease,marker,registry/rates" {
		t.Errorf("the working bucket holds %v", work)
	}
	// the InitRecord, then the tool's own take and release of it
	if rec, ok := e.leaseRecord(); !ok || rec.State != objlease.StateReleased || rec.Node != testNodeHex || rec.Generation != 2 {
		t.Errorf("the lease record is %+v (present %v), want a released record of this node", rec, ok)
	}
	for _, w := range []string{"registry bucket: marker", "working bucket: marker", "working bucket: lease", "working bucket: registry/rates"} {
		if !contains(rep.Written, w) {
			t.Errorf("the report's writes %v lack %q", rep.Written, w)
		}
	}
	if !contains(rep.Left, "selftest/") {
		t.Errorf("the report does not say what the self-test leaves: %v", rep.Left)
	}
	e.noForbiddenRequests()
	if _, _, err := e.openRegistry(); err != nil {
		t.Errorf("a relay's start on the initialised store: %v", err)
	}
	if _, _, err := e.openMailbox(); err != nil {
		t.Errorf("the mailbox on the initialised store: %v", err)
	}
	var out bytes.Buffer
	RenderInit(&out, rep)
	if !has(&out, "initialised") || has(&out, testSecret) || has(&out, testToken) {
		t.Errorf("the rendering: %s", out.String())
	}
}

// A second run changes nothing but the self-test's own object.
//
// spec: SPO-Xobjstore-OUT-901
func TestInitStoreIsIdempotent(t *testing.T) {
	e := newEnv(t)
	if _, err := InitStore(bg(t), e.deps()); err != nil {
		t.Fatal(err)
	}
	before := len(e.srv.Records())
	rep, err := InitStore(bg(t), e.deps())
	if err != nil {
		t.Fatalf("the second run: %v", err)
	}
	if !rep.AlreadyInitialised || len(rep.Written) != 0 {
		t.Errorf("the second run reports writes %v (initialised %v)", rep.Written, rep.AlreadyInitialised)
	}
	for _, r := range e.srv.Records()[before:] {
		if r.Op == s3stand.OpPut && !strings.Contains(r.Key, "/selftest/") && !strings.Contains(r.Key, "/registry/tombstones/selftest-") {
			t.Errorf("the second run wrote %s", r.Key)
		}
	}
	if mv := e.versions(regBucket, "marker"); len(mv) != 1 {
		t.Errorf("the marker has %d versions after two runs", len(mv))
	}
}

// An init stopped at any step is completed by the next run, which leaves the
// same store a single run leaves.
//
// spec: SPO-Xobjstore-OUT-901
func TestInitStoreResumesAfterAnInterruption(t *testing.T) {
	for _, step := range []string{"init:lease", "init:markers", "init:release"} {
		t.Run(step, func(t *testing.T) {
			e := newEnv(t)
			d := e.deps()
			d.hook = func(s string) error {
				if s == step {
					return errors.New("crash")
				}
				return nil
			}
			if _, err := InitStore(bg(t), d); err == nil {
				t.Fatal("the interrupted run reports success")
			}
			e.clock.Advance(time.Minute) // a crashed holder's lease lapses
			d.hook = nil
			stop := e.clock.run(time.Second)
			_, err := InitStore(bg(t), d)
			stop()
			if err != nil {
				t.Fatalf("the second run: %v", err)
			}
			if _, _, err := e.openRegistry(); err != nil {
				t.Errorf("a relay's start: %v", err)
			}
			if work := e.listAll(workBucket); strings.Join(work, ",") != "lease,marker,registry/rates" {
				t.Errorf("the working bucket holds %v", work)
			}
		})
	}
}

// init-store refuses a store whose identity is foreign, emptied or whose lease
// it cannot read, and a bucket that fails the self-test, before it writes a
// marker or the lease.
//
// spec: SPO-Xobjstore-PRE-901
func TestInitStoreRefuses(t *testing.T) {
	other := testNode
	other[0] ^= 1
	cases := []struct {
		name  string
		mod   func(reg, work *s3stand.Bucket)
		plant func(e *env)
		want  error
	}{
		{"a tombstone without a marker", nil, func(e *env) {
			e.putTomb("d-"+strings.Repeat("ab", 20), 1, s3client.Compliance, e.clock.Now().Add(time.Hour))
		}, ErrEmptied},
		{"mail without a marker", nil, func(e *env) {
			e.srv.AdminPutVersion(workBucket, testPrefix+"mailbox/"+strings.Repeat("0", 40)+"/x", []byte("x"))
		}, ErrEmptied},
		{"a working marker without the registry's", nil, func(e *env) {
			e.srv.AdminPutVersion(workBucket, testPrefix+"marker", encodeMarker(testNode))
		}, ErrEmptied},
		{"a marker of another identity", nil, func(e *env) {
			e.srv.AdminPutVersion(regBucket, testPrefix+"marker", encodeMarker(other))
		}, ErrForeign},
		{"an unreadable lease", nil, func(e *env) {
			e.srv.AdminPutVersion(workBucket, testPrefix+"lease", []byte("junk"))
		}, ErrLeaseUnreadable},
		{"a versioned working bucket", func(reg, work *s3stand.Bucket) { work.Versioned = true }, nil, ErrSelfTest},
		{"a registry bucket without Object Lock", func(reg, work *s3stand.Bucket) { reg.ObjectLock = false }, nil, ErrSelfTest},
		{"no deny of a simple delete", func(reg, work *s3stand.Bucket) { reg.DenySimpleDelete = nil }, nil, ErrSelfTest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mod := c.mod
			if mod == nil {
				mod = func(reg, work *s3stand.Bucket) {}
			}
			e := newEnvWith(t, mod)
			if c.plant != nil {
				c.plant(e)
			}
			_, err := InitStore(bg(t), e.deps())
			if !errors.Is(err, c.want) {
				t.Fatalf("InitStore: %v, want %v", err, c.want)
			}
			for _, r := range e.srv.Records() {
				if r.Op == s3stand.OpPut && (strings.HasSuffix(r.Key, "/marker") || strings.HasSuffix(r.Key, "/lease") || strings.HasSuffix(r.Key, "/registry/rates")) {
					t.Errorf("a refused init wrote %s", r.Key)
				}
			}
			if _, _, err := e.openRegistry(); err == nil {
				t.Error("a relay starts on the refused store")
			}
		})
	}
	_ = objregistry.ErrStoreNew
}
