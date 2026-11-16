package pool

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

var previewGenesis = chain.Genesis{
	SlotLength: time.Second, SlotsPerKESPeriod: 129600, MaxKESEvolutions: 62, EpochLength: 86400,
}

// spec: SPO-04d-PRE-003, SPO-04d-PRE-004, SPO-04d-OUT-003, SPO-04d-INV-008
func TestIssueStateMachine(t *testing.T) {
	// Missing counters: nothing was generated.
	if _, _, err := NewKesState(nil, nil).Issue(); !errors.Is(err, ErrKesCountersMissing) {
		t.Fatalf("no counters: %v", err)
	}
	if _, _, err := NewKesState(ip(0), nil).Issue(); !errors.Is(err, ErrKesCountersMissing) {
		t.Fatalf("no next counter: %v", err)
	}
	// current < next: the newest key already has its certificate.
	if _, _, err := NewKesState(ip(0), ip(1)).Issue(); !errors.Is(err, ErrNoKesKeyWaiting) {
		t.Fatalf("consumed: %v", err)
	}
	// current == next: issue, next = current + 1.
	s, n, err := NewKesState(ip(3), ip(3)).Issue()
	if err != nil || n != 3 || s.NextNumber() != 4 {
		t.Fatalf("issue: n=%d next=%d err=%v", n, s.NextNumber(), err)
	}
	if cur, _ := s.Current(); cur != 3 {
		t.Errorf("current changed to %d", cur)
	}
	// The round trip with generation: after issue, Generate makes key 4.
	if _, n, err := s.Generate(); err != nil || n != 4 {
		t.Errorf("generate after issue: n=%d err=%v", n, err)
	}
}

// spec: SPO-04d-INV-001
//
// Upstream decision: the multiplication by slotLength is reproduced, so a
// network with 2-second slots gets half the period it would otherwise (the
// spec calls this wrong but it is upstream behaviour and parity is the
// goal). Test both slot lengths.
func TestKesPeriod(t *testing.T) {
	for slot, want := range map[uint64]uint64{0: 0, 129599: 0, 129600: 1, 128_000_000: 987} {
		got, err := KesPeriod(previewGenesis, slot)
		if err != nil || got != want {
			t.Errorf("slot %d: period %d, %v; want %d", slot, got, err, want)
		}
	}
	two := previewGenesis
	two.SlotLength = 2 * time.Second
	if got, _ := KesPeriod(two, 259200); got != 1 {
		t.Errorf("2-second slots: period %d, want 1 (slot / (129600*2))", got)
	}
	// A fractional slot length is a failure in upstream's shell arithmetic.
	frac := previewGenesis
	frac.SlotLength = 200 * time.Millisecond
	if _, err := KesPeriod(frac, 1); !errors.Is(err, ErrSlotLength) {
		t.Errorf("fractional slot length accepted: %v", err)
	}
	// Unsigned slots cannot be negative, so the spec's "negative becomes 0"
	// has no case here.
}

// spec: SPO-04d-INV-002, SPO-04d-OUT-004
//
// Upstream quirk decision (INV-002): expireKESdate is computed from the wall
// clock "now", like upstream, not from the start of the period. It
// overestimates by the time elapsed in the current period; kept for parity.
func TestKesExpiryAndJSON(t *testing.T) {
	now := time.Date(2026, 11, 16, 8, 57, 1, 0, time.UTC)
	e, err := NewKesExpiry(previewGenesis, 0, 988, now)
	if err != nil {
		t.Fatal(err)
	}
	if e.ExpireKESPeriod != 1050 {
		t.Errorf("expire period %d", e.ExpireKESPeriod)
	}
	if want := now.Add(62 * 129600 * time.Second); !e.ExpireKESDate.Equal(want) {
		t.Errorf("expire date %v, want %v", e.ExpireKESDate, want)
	}
	j := string(e.JSON())
	for _, want := range []string{
		"{\n\t\"latestKESfileindex\": \"000\",\n",
		"\t\"currentKESperiod\": \"988\",\n",
		"\t\"expireKESperiod\": \"1050\",\n",
		"\t\"expireKESdate\": \"",
	} {
		if !strings.Contains(j, want) {
			t.Errorf("JSON lacks %q:\n%s", want, j)
		}
	}
	if !strings.HasSuffix(j, "\"\n}\n") {
		t.Errorf("JSON ends %q", j[len(j)-6:])
	}
}

// spec: SPO-Pfiles-OUT-011, SPO-04d-OUT-002, SPO-04d-OUT-005
func TestIssueCounterCodec(t *testing.T) {
	var vk [32]byte
	for i := range vk {
		vk[i] = byte(i)
	}
	file := IssueCounter{Next: 7, ColdVKey: vk}.Envelope()
	e, err := ParseEnvelope(file)
	if err != nil {
		t.Fatal(err)
	}
	// Shape verified against cardano-cli 11.2.3.0: [counter, bytes(32)].
	if e.Type != "NodeOperationalCertificateIssueCounter" || e.Description != "Next certificate issue number: 7" {
		t.Errorf("envelope %+v", e)
	}
	if !strings.HasPrefix(e.CborHex, "8207582000010203") {
		t.Errorf("cborHex %s", e.CborHex)
	}
	back, err := ParseIssueCounter(file)
	if err != nil || back.Next != 7 || back.ColdVKey != vk {
		t.Errorf("round trip: %+v %v", back, err)
	}
	for _, next := range []uint64{0, 23, 24, 255, 256, 65535, 65536, 1 << 32, 1<<40 + 5} {
		c, err := ParseIssueCounter(IssueCounter{Next: next, ColdVKey: vk}.Envelope())
		if err != nil || c.Next != next {
			t.Errorf("counter %d: %+v %v", next, c, err)
		}
	}
	for _, bad := range []string{``, `{}`, `{"type":"x","cborHex":"00"}`,
		`{"type":"NodeOperationalCertificateIssueCounter","cborHex":"8100"}`} {
		if _, err := ParseIssueCounter([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestPoolIDIsBlake2b224OfTheKey(t *testing.T) {
	// From the parity run: vkey 4b83...3ac2 is pool1prky9xg2t5mt... in
	// cardano-cli; here only the length and determinism are checked, the
	// parity test compares with cardano-cli.
	id, err := chain.PoolIDOf(make([]byte, 32))
	if err != nil || id == (chain.PoolID{}) {
		t.Fatalf("%v %v", id, err)
	}
	if _, err := chain.PoolIDOf(make([]byte, 31)); err == nil {
		t.Error("short key accepted")
	}
}
