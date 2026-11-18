package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/layoutread"
	layoutdom "github.com/mochipool/workbench/spo/internal/domain/layout"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// The credential kind follows from the policy of the table the pin vouches for. A
// hardware or strict table never leads to a passphrase prompt, whatever the table
// the check settled on says: this is the guard, tested apart from the check above
// it that makes it unreachable.
//
// spec: SPO-Xlayout-PRE-028, SPO-Xlayout-PRE-026
func TestAHardwareOrStrictTableNeverLeadsToAPassphrasePrompt(t *testing.T) {
	cases := []struct {
		name, flag, vouched, used string
		factors, wantFactors      bool
		wantErr                   string
	}{
		{"standard", "", "standard", "standard", false, false, ""},
		{"hardware", "", "hardware", "hardware", true, true, ""},
		{"strict", "fido2", "strict", "strict", true, true, ""},
		{"a hardware table vouched, a standard one offered", "", "hardware", "standard", true, true, ""},
		{"the same, with no factor source: refused, not prompted", "", "hardware", "standard", false, false, "no FIDO2 factor source"},
		{"a strict table vouched, a standard one offered, passphrase asked for", "passphrase", "strict", "standard", true, false, "no passphrase opens it"},
		{"a standard table vouched, a hardware one offered", "", "standard", "hardware", true, true, ""},
		{"hardware, passphrase asked for", "passphrase", "hardware", "hardware", true, false, "no passphrase opens it"},
		{"standard, fido2 asked for", "fido2", "standard", "standard", true, false, "opened with its passphrase"},
		{"a value that is none", "bogus", "standard", "standard", true, false, "use passphrase or fido2"},
	}
	for _, c := range cases {
		got, err := layoutCredKind(c.flag, c.vouched, c.used, c.factors)
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		if err != nil || got != c.wantFactors {
			t.Errorf("%s: %v %v", c.name, got, err)
		}
	}
}

type countPins struct {
	advanced []ports.LayoutPin
	err      error
}

func (c *countPins) Load() (ports.LayoutPin, bool, error) { return ports.LayoutPin{}, false, nil }
func (c *countPins) Advance(p ports.LayoutPin) error {
	c.advanced = append(c.advanced, p)
	return c.err
}

// spec: SPO-Xlayout-OUT-024
func TestTheImportPinsOnlyANoteTheInstalledWorkspaceWouldHaveWritten(t *testing.T) {
	ws, epoch := bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16)
	mac := bytes.Repeat([]byte{3}, 32)
	snap := ports.Snapshot{Meta: ports.SnapshotMeta{WorkspaceID: ws, KeyEpoch: epoch}, Audit: []ports.SnapshotAudit{{Seq: 4, MAC: mac}}}
	head := layoutdom.Head{Workspace: ws, Sequence: 2, Previous: bytes.Repeat([]byte{9}, 32), Manifest: bytes.Repeat([]byte{4}, 32), Slots: bytes.Repeat([]byte{5}, 32),
		AuditSeq: 4, AuditMAC: mac, Epoch: epoch, Time: time.Unix(1700000000, 0).UTC()}
	run := func(h layoutdom.Head, installed []byte) (*countPins, string) {
		var out, errb bytes.Buffer
		a := &app{d: Deps{Out: &out, Err: &errb}, restoredKeyHash: installed}
		pins := &countPins{}
		lr := &layoutread.Locked{Used: layoutread.HeadInfo{Head: h, Hash: bytes.Repeat([]byte{8}, 32)}}
		a.recordLayoutPin(LayoutDir{Pins: pins}, "/layout", lr, snap)
		return pins, out.String() + errb.String()
	}
	if pins, out := run(head, nil); len(pins.advanced) != 1 || !strings.Contains(out, "Layout pin recorded") {
		t.Fatalf("an authentic head: %v %s", pins.advanced, out)
	}
	named := head
	named.CheckpointKey = bytes.Repeat([]byte{7}, 32)
	pins, out := run(named, nil)
	if len(pins.advanced) != 0 || !strings.Contains(out, "no layout pin was recorded") || !strings.Contains(out, "fresh directory") {
		t.Fatalf("a head naming a key the workspace does not hold: %v %s", pins.advanced, out)
	}
	if pins, _ := run(named, named.CheckpointKey); len(pins.advanced) != 1 {
		t.Fatal("the installed workspace's own key")
	}
	bad := head
	bad.AuditSeq = 9
	if pins, out := run(bad, nil); len(pins.advanced) != 0 || !strings.Contains(out, "audit position") {
		t.Fatalf("%v %s", pins.advanced, out)
	}
}
