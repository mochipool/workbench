package s3client

import (
	"context"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/test/s3stand"
)

// A self-test whose context ends part-way (a stop during the start) still
// removes what it wrote: the cleanup runs on a context of its own, bounded by
// selfTestCleanup, not on the one that ended.
//
// spec: SPO-Xobjstore-IF-008
func TestACancelledSelfTestCleansUp(t *testing.T) {
	e := newEnv(t)
	for _, c := range []struct {
		cl *Client
		o  SelfTestOptions
	}{{e.wc, SelfTestOptions{Prefix: prefix}}, {e.rc, SelfTestOptions{Prefix: prefix, Registry: true}}} {
		// the read-back after the writes stalls until the context ends
		e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStallBeforeHeaders, Op: s3stand.OpGet, Count: 1, Delay: 10 * time.Second})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := SelfTest(ctx, c.cl, c.o)
		cancel()
		if err == nil {
			t.Fatalf("%s: a stalled self-test passed", c.cl.Bucket())
		}
	}
	ctx := ctx5(t)
	if l, err := e.wc.ListAll(ctx, prefix, 10); err != nil || len(l) != 0 {
		t.Errorf("the working bucket kept %v %v", l, err)
	}
	if vs, err := e.rc.ListAllVersions(ctx, prefix, 10); err != nil || len(vs) != 0 {
		t.Errorf("the registry bucket kept %v %v", vs, err)
	}
}
