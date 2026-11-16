package query

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// pool opcert check and counter: an acknowledged single source (the second
// provider is wired and silent) is recorded once, before the answer is used; a
// failing hook is an error with no verdict; no flag, no record.
//
// spec: ADR 0006 (single source is written to the audit log)
func TestOpCertCheckAndCounterRecordTheSingleSource(t *testing.T) {
	silent := &counters{src: "node", rd: chain.Unknown[uint64]("node down")}
	var reads []string
	hook := func(_ context.Context, read, source string) error {
		reads = append(reads, read+" ["+source+"]")
		return nil
	}
	chk := checker(&counters{src: "koios", rd: chain.Value(uint64(4))}, inRange)
	chk.Cross, chk.SingleSource, chk.OnSingle = silent, true, hook
	if v, err := chk.Run(bg, OpCertCheck{OpCert: opcert(4, 5), Check: CheckCurrent}); err != nil || !v.Single {
		t.Fatalf("%+v %v", v, err)
	}
	if len(reads) != 1 || !strings.Contains(reads[0], "koios") {
		t.Errorf("check records: %v", reads)
	}
	reads = nil
	cnt := QueryOpCertCounter{Counters: &counters{src: "koios", rd: chain.Value(uint64(4))}, Cross: silent, SingleSource: true, OnSingle: hook}
	if _, err := cnt.Run(bg, strings.Repeat("a", 56)); err != nil || len(reads) != 1 {
		t.Fatalf("%v %v", err, reads)
	}

	// A failing hook: an error, no verdict.
	fail := func(context.Context, string, string) error { return errors.New("audit log full") }
	chk.OnSingle = fail
	if _, err := chk.Run(bg, OpCertCheck{OpCert: opcert(4, 5), Check: CheckCurrent}); err == nil || err.Error() != "audit log full" {
		t.Errorf("check: %v", err)
	}
	cnt.OnSingle = fail
	if _, err := cnt.Run(bg, strings.Repeat("a", 56)); err == nil || err.Error() != "audit log full" {
		t.Errorf("counter: %v", err)
	}
	// No hook with the acknowledgement: refused.
	chk.OnSingle = nil
	if _, err := chk.Run(bg, OpCertCheck{OpCert: opcert(4, 5), Check: CheckCurrent}); !errors.Is(err, ports.ErrNoSingleSourceHook) {
		t.Errorf("check without a hook: %v", err)
	}

	// Without --single-source the silent second source makes the reading
	// Unknown and nothing is recorded; two agreeing sources need no record.
	reads = nil
	chk.SingleSource, chk.OnSingle = false, hook
	if v, err := chk.Run(bg, OpCertCheck{OpCert: opcert(4, 5), Check: CheckCurrent}); err != nil || v.Single {
		t.Fatalf("%+v %v", v, err)
	}
	chk.Cross, chk.SingleSource = &counters{src: "node", rd: chain.Value(uint64(4))}, true
	if v, err := chk.Run(bg, OpCertCheck{OpCert: opcert(4, 5), Check: CheckCurrent}); err != nil || v.Single {
		t.Fatalf("%+v %v", v, err)
	}
	if len(reads) != 0 {
		t.Errorf("records without an accepted single source: %v", reads)
	}
}
