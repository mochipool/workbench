package custody

import (
	"bytes"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/identity"
)

// spec: SPO-Xidentity-INV-012, SPO-Xidentity-PRE-002
func TestRoleHistoryOnlyGrows(t *testing.T) {
	id := newKP(40).id(t)
	h, err := NewRoleHistory(id, RoleStake)
	if err != nil {
		t.Fatal(err)
	}
	if h.HasColdRole() || h.Identity() != id {
		t.Error("a stake-only key has no cold role")
	}
	if r, ok := h.MostSensitive(); !ok || r != RoleStake {
		t.Errorf("most sensitive %s", r)
	}
	h2, err := h.With(RolePoolCold)
	if err != nil {
		t.Fatal(err)
	}
	if h.Has(RolePoolCold) || !h2.Has(RolePoolCold) || !h2.Has(RoleStake) {
		t.Error("With must add, keep the old roles and leave the receiver unchanged")
	}
	if !h2.HasColdRole() {
		t.Error("a pool cold role is a cold role")
	}
	if r, _ := h2.MostSensitive(); r != RolePoolCold {
		t.Errorf("most sensitive %s", r)
	}
	if h3, _ := h2.With(RoleStake); len(h3.Roles()) != 2 {
		t.Error("adding a role twice is a no-op")
	}
	hc, _ := NewRoleHistory(id, RoleCommitteeCold)
	if !hc.HasColdRole() {
		t.Error("committee cold is a cold role")
	}
	hk, _ := NewRoleHistory(id, RoleKES)
	if hk.HasColdRole() || hk.Has(RoleCommitteeHot) {
		t.Error("kes")
	}
	// Merge is a union and refuses two identities.
	m, err := hk.Merge(hc)
	if err != nil || !m.Has(RoleKES) || !m.Has(RoleCommitteeCold) {
		t.Errorf("merge %v", err)
	}
	if _, err := hk.Merge(mustHist(t, newKP(41).id(t), RoleKES)); !errors.Is(err, ErrRoleHistory) {
		t.Error("histories of two identities merged")
	}
	// Refusals.
	if _, err := NewRoleHistory(id, "nonsense"); !errors.Is(err, ErrRoleHistory) {
		t.Error("unknown role")
	}
	if _, err := NewRoleHistory(identity.Ref{}, RoleStake); !errors.Is(err, ErrRoleHistory) {
		t.Error("zero identity")
	}
	tx := identity.TxIDOf([]byte{1})
	if _, err := NewRoleHistory(tx, RoleStake); !errors.Is(err, ErrRoleHistory) {
		t.Error("a transaction id is not a key identity")
	}
	if _, ok := (RoleHistory{}).MostSensitive(); ok {
		t.Error("empty history")
	}
	for _, r := range Roles() {
		if r.IsCold() != (r == RolePoolCold || r == RoleCommitteeCold) || r.Sensitivity() == 0 {
			t.Errorf("%s", r)
		}
	}
	for _, r := range Roles() {
		if !r.IsCold() && r.Sensitivity() >= RolePoolCold.Sensitivity() {
			t.Errorf("%s ranks with the cold roles", r)
		}
	}
}

func mustHist(t *testing.T, id identity.Ref, r Role) RoleHistory {
	t.Helper()
	h, err := NewRoleHistory(id, r)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// spec: SPO-Xidentity-INV-012, SPO-Xidentity-INV-009
func TestRoleHistoryEncodingIsCanonical(t *testing.T) {
	id := newKP(42).id(t)
	a, _ := mustHist(t, id, RoleStake).With(RolePayment)
	b, _ := mustHist(t, id, RolePayment).With(RoleStake)
	ea, _ := a.Canonical()
	eb, _ := b.Canonical()
	if !bytes.Equal(ea, eb) {
		t.Error("the order roles were recorded in changed the encoding")
	}
	back, err := ParseRoleHistory(ea)
	if err != nil || back.Identity() != id || !back.Has(RoleStake) || !back.Has(RolePayment) || len(back.Roles()) != 2 {
		t.Fatalf("%v", err)
	}
	ib, _ := id.MarshalBinary()
	enc := func(v any) []byte { b, _ := identity.EncodeCanonical(v); return b }
	for name, raw := range map[string][]byte{
		"unsorted":      enc([]any{ib, []any{"stake", "payment"}}),
		"duplicate":     enc([]any{ib, []any{"stake", "stake"}}),
		"unknown":       enc([]any{ib, []any{"bogus"}}),
		"empty":         enc([]any{ib, []any{}}),
		"not key":       enc([]any{append([]byte{33, 8}, make([]byte, 32)...), []any{"stake"}}),
		"indefinite":    append([]byte{0x9f}, append(bytes.Clone(ea[1:]), 0xff)...),
		"trailing":      append(bytes.Clone(ea), 0),
		"wrong shape":   enc([]any{ib}),
		"role not text": enc([]any{ib, []any{uint64(1)}}),
	} {
		if _, err := ParseRoleHistory(raw); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// spec: SPO-Xidentity-INV-012
func TestRoleHistoryExtends(t *testing.T) {
	id := newKP(43).id(t)
	stored, _ := mustHist(t, id, RoleStake).With(RolePoolCold)
	grown, _ := stored.With(RoleKES)
	if err := grown.Extends(stored); err != nil {
		t.Error(err)
	}
	if err := stored.Extends(stored); err != nil {
		t.Error("equal history")
	}
	if err := stored.Extends(grown); !errors.Is(err, ErrRoleHistoryShrunk) {
		t.Errorf("a history that dropped a role: %v", err)
	}
	dropped := mustHist(t, id, RoleStake) // the cold role is gone
	if err := dropped.Extends(stored); !errors.Is(err, ErrRoleHistoryShrunk) {
		t.Errorf("the cold role was forgotten: %v", err)
	}
	if err := mustHist(t, newKP(44).id(t), RoleStake).Extends(stored); !errors.Is(err, ErrRoleHistoryShrunk) {
		t.Error("another identity")
	}
}
