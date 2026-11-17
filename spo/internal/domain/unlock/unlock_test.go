package unlock

import (
	"bytes"
	"errors"
	"slices"
	"testing"
)

func id(b byte) []byte { return bytes.Repeat([]byte{b}, 16) }

var rhash = bytes.Repeat([]byte{0xc0}, 32)

func slot(n byte, kind SlotKind, fs ...Factor) Slot {
	return Slot{ID: id(n), Kind: kind, Factors: fs, RecoveryPubKeyHash: rhash}
}

// strict builds a strict table: no recovery key exists, so no slot binds a hash.
func strict(ss ...Slot) Table {
	for i := range ss {
		ss[i].RecoveryPubKeyHash = nil
	}
	return Table{Strict, ss}
}

func pass(n byte) Factor { return Factor{Passphrase, id(n)} }
func rec(n byte) Factor  { return Factor{Recovery, id(n)} }
func fido(n byte) Factor { return Factor{FIDO2, id(n)} }
func back(n byte) Factor { return Factor{Backend, id(n)} }

func has(rules []Rule, r Rule) bool { return slices.Contains(rules, r) }

// The tables that the policies accept.
func TestAcceptedTables(t *testing.T) {
	for name, tb := range map[string]Table{
		"standard: passphrase and recovery": {Standard, []Slot{
			slot(1, SlotPassphrase, pass(1)), slot(2, SlotRecovery, rec(2))}},
		"standard: with a hardware slot beside them": {Standard, []Slot{
			slot(1, SlotPassphrase, pass(1)), slot(2, SlotRecovery, rec(2)), slot(3, SlotFIDO2HMAC, fido(3))}},
		"hardware: daily key, composite with passphrase, recovery composite": {Hardware, []Slot{
			slot(1, SlotFIDO2HMAC, fido(1)),
			slot(2, SlotComposite, pass(2), fido(2)),
			slot(3, SlotComposite, rec(3), fido(3))}},
		"hardware: vault with fido2": {Hardware, []Slot{
			slot(1, SlotComposite, fido(1), back(9)),
			slot(2, SlotComposite, rec(3), fido(3))}},
		"strict: two authenticators and no recovery": strict(
			slot(1, SlotFIDO2HMAC, fido(1)), slot(2, SlotFIDO2HMAC, fido(2))),
		"standard: vault with a passphrase": {Standard, []Slot{
			slot(1, SlotPassphrase, pass(1)), slot(2, SlotRecovery, rec(2)),
			slot(3, SlotComposite, pass(4), back(9))}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := Check(tb); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// One refusing case per rule.
//
// spec: SPO-Xunlock-IF-004, SPO-Xunlock-IF-005, SPO-Xunlock-PRE-006, SPO-Xunlock-PRE-007, SPO-Xunlock-PRE-008, SPO-Xunlock-PRE-009, SPO-Xunlock-PRE-010, SPO-Xunlock-PRE-011, SPO-Xunlock-PRE-012, SPO-Xunlock-PRE-013, SPO-Xunlock-PRE-014, SPO-Xunlock-PRE-015, SPO-Xunlock-PRE-018, SPO-Xunlock-PRE-019, SPO-Xunlock-PRE-020, SPO-Xunlock-PRE-021
func TestRefusals(t *testing.T) {
	std := func(extra ...Slot) Table {
		return Table{Standard, append([]Slot{slot(1, SlotPassphrase, pass(1)), slot(2, SlotRecovery, rec(2))}, extra...)}
	}
	hw := func(extra ...Slot) Table {
		return Table{Hardware, append([]Slot{slot(1, SlotFIDO2HMAC, fido(1)), slot(2, SlotComposite, rec(2), fido(2))}, extra...)}
	}
	other := slot(7, SlotFIDO2HMAC, fido(7))
	other.RecoveryPubKeyHash = bytes.Repeat([]byte{0xd0}, 32)
	dupID := slot(1, SlotFIDO2HMAC, fido(5))

	for _, c := range []struct {
		name string
		tb   Table
		rule Rule
		spec string // the requirement the case is for
	}{
		{"unknown policy", Table{"laxer", []Slot{slot(1, SlotPassphrase, pass(1))}}, RuleTable, "PRE-006 IF-004"},
		{"no slot", Table{Standard, nil}, RuleTable, "PRE-006"},
		{"a slot with no id", Table{Standard, []Slot{{Kind: SlotPassphrase, Factors: []Factor{pass(1)}}}}, RuleTable, "PRE-006"},
		{"a repeated slot id", std(dupID), RuleTable, "PRE-006"},
		{"a passphrase slot with a fido2 factor", std(slot(3, SlotPassphrase, fido(3))), RuleShape, "PRE-006"},
		{"a composite of one factor", std(slot(3, SlotComposite, fido(3))), RuleShape, "PRE-006"},
		{"a factor repeated in a composite", std(slot(3, SlotComposite, fido(3), fido(3))), RuleShape, "PRE-006"},
		{"an unknown slot kind", std(slot(3, "device", fido(3))), RuleShape, "PRE-006"},

		{"standard without a passphrase slot", Table{Standard, []Slot{slot(2, SlotRecovery, rec(2))}}, RuleStandardSlots, "PRE-007"},
		{"standard without a recovery slot", Table{Standard, []Slot{slot(1, SlotPassphrase, pass(1))}}, RuleStandardSlots, "PRE-007"},

		{"hardware with a passphrase slot", hw(slot(3, SlotPassphrase, pass(3))), RulePassphraseOnly, "PRE-008"},
		{"strict with a passphrase slot", strict(slot(1, SlotFIDO2HMAC, fido(1)), slot(3, SlotPassphrase, pass(3))), RulePassphraseOnly, "PRE-008"},
		{"hardware with a recovery slot", hw(slot(3, SlotRecovery, rec(3))), RuleRecoveryOnly, "PRE-009"},

		{"hardware: recovery composite without a hardware factor", hw(slot(3, SlotComposite, rec(3), pass(3))), RuleRecoveryComposite, "PRE-010"},
		{"hardware: the recovery composite's authenticator has its own slot",
			Table{Hardware, []Slot{slot(1, SlotFIDO2HMAC, fido(1)), slot(2, SlotComposite, rec(2), fido(1))}}, RuleRecoveryAuthReuse, "PRE-010"},
		{"hardware: the recovery composite's authenticator is also in another composite",
			hw(slot(3, SlotComposite, pass(3), fido(2))), RuleRecoveryAuthReuse, "PRE-010"},
		{"hardware with no recovery composite", Table{Hardware, []Slot{slot(1, SlotFIDO2HMAC, fido(1))}}, RuleRecoveryRequired, "PRE-010"},
		{"two distinct recovery factors", std(slot(3, SlotComposite, rec(8), fido(3))), RuleMultipleRecovery, "PRE-014"},
		{"standard: a slot with no recovery key hash", std(Slot{ID: id(3), Kind: SlotFIDO2HMAC, Factors: []Factor{fido(3)}}), RuleKeyHashMissing, "PRE-014"},
		{"hardware: no slot binds a recovery key hash", Table{Hardware, []Slot{{ID: id(1), Kind: SlotFIDO2HMAC, Factors: []Factor{fido(1)}}, {ID: id(2), Kind: SlotComposite, Factors: []Factor{rec(2), fido(2)}}}}, RuleKeyHashMissing, "PRE-014"},
		{"strict: a slot binds a recovery key hash", Table{Strict, []Slot{slot(1, SlotFIDO2HMAC, fido(1))}}, RuleKeyHashPresent, "PRE-014"},

		{"vault alone in a slot", std(slot(3, SlotComposite, back(3), back(4))), RuleBackend, "PRE-011"},
		{"hardware: vault with a passphrase", hw(slot(3, SlotComposite, pass(3), back(4))), RuleBackend, "PRE-011"},
		{"strict: vault with a passphrase", strict(slot(1, SlotFIDO2HMAC, fido(1)), slot(3, SlotComposite, pass(3), back(4))), RuleBackend, "PRE-011"},
		{"standalone backend slot", std(slot(3, SlotComposite, back(3))), RuleShape, "PRE-011"},

		{"a fido2 factor in a composite and a slot of its own", std(slot(3, SlotFIDO2HMAC, fido(3)), slot(4, SlotComposite, pass(4), fido(3))), RuleStandaloneFactor, "PRE-012"},
		{"hardware: the same", hw(slot(3, SlotComposite, pass(3), fido(1))), RuleStandaloneFactor, "PRE-012"},
		{"a recovery factor in a composite and a recovery slot", std(slot(3, SlotComposite, rec(2), fido(3))), RuleStandaloneFactor, "PRE-012"},

		{"strict with a recovery composite", strict(slot(1, SlotFIDO2HMAC, fido(1)), slot(2, SlotComposite, rec(2), fido(2))), RuleStrictRecovery, "PRE-013"},
		{"strict with a recovery slot", strict(slot(1, SlotFIDO2HMAC, fido(1)), slot(2, SlotRecovery, rec(2))), RuleStrictRecovery, "PRE-013"},

		{"slots that bind different recovery keys", std(other), RuleRecoveryKeyHash, "PRE-014"},

		{"hardware: a composite with no fido2 factor", hw(slot(3, SlotComposite, pass(3), rec(4))), RuleHardwareFactor, "PRE-015"},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := Check(c.tb)
			if err == nil {
				t.Fatal("the table was accepted")
			}
			if !errors.Is(err, ErrPolicy) {
				t.Fatalf("not an unlock policy error: %v", err)
			}
			if !has(Rules(err), c.rule) {
				t.Fatalf("rule %q not violated; got %v (%v)", c.rule, Rules(err), err)
			}
		})
	}
}

// The check reports every broken rule, not the first.
func TestEveryViolationIsReported(t *testing.T) {
	tb := Table{Hardware, []Slot{
		slot(1, SlotPassphrase, pass(1)),
		slot(2, SlotRecovery, rec(2)),
		slot(3, SlotComposite, back(3), pass(4)),
	}}
	r := Rules(Check(tb))
	for _, want := range []Rule{RulePassphraseOnly, RuleRecoveryOnly, RuleBackend} {
		if !has(r, want) {
			t.Errorf("%q missing from %v", want, r)
		}
	}
	if Rules(nil) != nil {
		t.Fatal("rules of no error")
	}
}

// A passphrase is not compared by id: two passphrases typed identically cannot be
// told apart, so the rule is advice (ADR 0011, decision 6).
func TestAPassphraseInACompositeMayShareAnIDWithAStandaloneSlot(t *testing.T) {
	tb := Table{Standard, []Slot{
		slot(1, SlotPassphrase, pass(1)), slot(2, SlotRecovery, rec(2)),
		slot(3, SlotComposite, pass(1), fido(3)),
	}}
	if err := Check(tb); err != nil {
		t.Fatal(err)
	}
}
