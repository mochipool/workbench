package custody

import (
	"strings"
	"testing"
)

func newer(have, min string) bool {
	// A test-only ordering of dotted numbers.
	parse := func(s string) [3]int {
		var v [3]int
		parts := strings.Split(s, ".")
		for i := 0; i < len(parts) && i < 3; i++ {
			for _, c := range parts[i] {
				v[i] = v[i]*10 + int(c-'0')
			}
		}
		return v
	}
	a, b := parse(have), parse(min)
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return true
}

func TestEveryRowNamesItsSourceAndGrantsSomething(t *testing.T) {
	for i, row := range HardwareTable {
		if !strings.Contains(row.Source, "SPO-") {
			t.Errorf("row %d has no requirement id as its source: %q", i, row.Source)
		}
		if len(row.Vendors) == 0 || len(row.Grants) == 0 {
			t.Errorf("row %d is empty", i)
		}
	}
}

func TestProfileIsTheUnionOfTheRowsThatMatch(t *testing.T) {
	has := func(p Profile, r Role, op Operation) bool {
		for _, o := range p.Operations(r) {
			if o == op {
				return true
			}
		}
		return false
	}
	ledger := HardwareProfile(VendorLedger, "8.0.8", newer)
	trezor := HardwareProfile(VendorTrezor, "2.7.2", newer)
	if !has(ledger, RolePoolCold, OpIssueOpCert) || has(trezor, RolePoolCold, OpIssueOpCert) {
		t.Error("opcert is Ledger and Keystone only (SPO-04d-EXT-004)")
	}
	if !has(trezor, RolePayment, OpWitnessTx) || !has(trezor, RolePolicy, OpHardwarePolicyID) {
		t.Error("a Trezor witnesses payment and signs with policy keys")
	}
	if Profile.Check(trezor, Demand{Role: RoleCalidus, Operation: OpExportVKey}) == "" {
		t.Error("Calidus is suspended (SPO-15-PRE-002)")
	}
	// A version below a row's minimum does not get the row.
	old := HardwareProfile(VendorLedger, "7.0.0", newer)
	if got := old.Check(Demand{Role: RolePayment, Operation: OpWitnessTx, Features: NewFeatures(FeatUnrestricted)}); got == "" {
		t.Error("unrestricted mode below Ledger 8.0.0")
	}
	if has(old, RoleCatalystVote, OpExportVKey) != true {
		t.Error("the voting key needs Ledger 6.0.3")
	}
	if has(HardwareProfile(VendorLedger, "6.0.2", newer), RoleCatalystVote, OpExportVKey) {
		t.Error("the voting key below Ledger 6.0.3")
	}
	if HardwareProfile("Nokia", "1.0.0", newer).Check(Demand{Role: RolePayment, Operation: OpWitnessTx}) == "" {
		t.Error("an unknown vendor has a profile")
	}
}

// A firmware release that adds a feature is one row (task 1).
func TestAFirmwareReleaseThatAddsAFeatureIsOneRow(t *testing.T) {
	rows := append([]HardwareRow(nil), HardwareTable...)
	d := Demand{Role: RolePayment, Operation: OpWitnessTx, Features: NewFeatures(FeatGovernanceAction)}
	before := profileFromRows(rows, VendorLedger, "9.0.0", newer)
	if before.Check(d) == "" {
		t.Fatal("governance actions are claimed without a row")
	}
	rows = append(rows, HardwareRow{Source: "SPO-test-001", Vendors: []Vendor{VendorLedger}, Min: "9.0.0",
		Grants: []HardwareGrant{{Role: RolePayment, TxFeatures: []Feature{FeatGovernanceAction}}}})
	if got := profileFromRows(rows, VendorLedger, "9.0.0", newer).Check(d); got != "" {
		t.Errorf("the new row is not honoured: %s", got)
	}
	if profileFromRows(rows, VendorLedger, "8.9.9", newer).Check(d) == "" {
		t.Error("an older app got the new feature")
	}
	// Existing features are kept: rows add up.
	if got := profileFromRows(rows, VendorLedger, "9.0.0", newer).Check(Demand{Role: RolePayment, Operation: OpWitnessTx, Features: NewFeatures(FeatMetadata, FeatGovernanceAction)}); got != "" {
		t.Errorf("%s", got)
	}
}

func TestVendorsAndPaths(t *testing.T) {
	if v, ok := ParseVendor("kEySToNe"); !ok || v != VendorKeystone {
		t.Error(v, ok)
	}
	if _, ok := ParseVendor("x"); ok {
		t.Error("x")
	}
	for p, want := range map[string]bool{"1852H/1815H/0H/0/0": true, "1855H/1815H/0H": true, "": false, "1852h/1": false, "1852H//0": false, "2147483648H": false, "1/2/x": false, "5000000000": false} {
		if ValidHardwarePath(p) != want {
			t.Errorf("%q", p)
		}
	}
	if _, err := HardwarePath(RolePayment, 1<<31, 0, false); err == nil {
		t.Error("account out of range")
	}
}
