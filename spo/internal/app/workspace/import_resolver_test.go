package workspace

import (
	"fmt"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// notes is every note and reason of an owner's row, joined.
func notes(o OwnerReport) string {
	s := ""
	for _, a := range o.Artefacts {
		s += a.Note + "|" + a.Reason + "|"
	}
	return s + o.Reason
}

// regWitnessJSON is an open registration with every member that holds a name:
// the paying wallet, the three kinds of slot (cold key, payer, owner) and the
// metadata file names.
func regWitnessJSON(pay, node, payer, owner, files string) string {
	return fmt.Sprintf(`"regWitness": {"id": 7, "type": "PoolRegistration", "ttl": 9, "regPayName": %q, "regPayAmount": 1, "regPayReturn": 2, "txBody": {}, "hardwareWalletIncluded": "no", "metadataFilesList": %q, "witnesses": {%q: {"witness": {}}, %q: {"witness": {}}, %q: {"witness": {}}}}`,
		pay, files, node+".node", payer, owner+".staking")
}

// Every name inside an open registration goes through the one resolver of the
// descriptor. Each field in turn names an owner that exists in the source, is
// not selected and has other keys in the workspace: the pool is refused, and
// the row names the field. A name that nobody has refuses the pool as well.
//
// spec: SPO-Xmulti-OUT-007, SPO-Xmulti-INV-005, SPO-Xmulti-INV-006, SPO-Xmulti-PRE-011, SPO-Xmulti-PRE-013
func TestXmultiEveryRegWitnessNameGoesThroughTheResolver(t *testing.T) {
	fields := []struct {
		field string
		reg   func(u string) string
	}{
		{"regWitness.regPayName", func(u string) string { return regWitnessJSON(u, "p", "w", "w", "p.metadata.json") }},
		{`regWitness.witnesses["u.node"]`, func(u string) string { return regWitnessJSON("w", u, "w", "w", "p.metadata.json") }},
		{`regWitness.witnesses["u"]`, func(u string) string { return regWitnessJSON("w", "p", u, "w", "p.metadata.json") }},
		{`regWitness.witnesses["u.staking"]`, func(u string) string { return regWitnessJSON("w", "p", "w", u, "p.metadata.json") }},
		{"regWitness.metadataFilesList", func(u string) string {
			return regWitnessJSON("w", "p", "w", "w", `"p.metadata.json" "`+u+`.extended-metadata.json"`)
		}},
	}
	// the fixture is carried when every name is the pool's or the selected owner's
	{
		tr, dst := newTree(), newMem()
		putPool(tr.dir("/d"), "p", 80, descJSON("p", "w", "w", regWitnessJSON("w", "p", "w", "w", `"p.metadata.json" "p.extended-metadata.json"`)))
		putWallet(tr.dir("/d"), "w", 40)
		rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true})
		if err != nil || stored(dst, "p", ports.PoolDescriptor) == "" {
			t.Fatalf("the fixture itself is refused: err %v %+v", err, rep.Owners)
		}
	}
	for _, tc := range fields {
		for _, mode := range []string{"unselected, other keys", "nobody has it"} {
			tr, dst := newTree(), newMem()
			putPool(tr.dir("/d"), "p", 80, descJSON("p", "w", "w", tc.reg("u")))
			putWallet(tr.dir("/d"), "w", 40)
			if mode == "unselected, other keys" {
				putWallet(tr.dir("/d"), "u", 41)
				putWallet(dst, "u", 99)
			}
			rep, _ := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, Only: []Selector{{Name: "p"}, {Name: "w"}}})
			o := ownerOf(rep, "p")
			if o.Written || stored(dst, "p", ports.PoolDescriptor) != "" {
				t.Errorf("%s (%s): the pool was stored: %+v", tc.field, mode, o)
				continue
			}
			if why := artefactReason(o, ports.PoolDescriptor); !strings.Contains(why, tc.field) {
				t.Errorf("%s (%s): the refusal does not name the field: %q", tc.field, mode, why)
			}
		}
	}
}

// A name inside the registration that only the workspace has is carried with a
// note that names the wallet by its stake key hash (and in the same words as a
// poolRewards of that name).
//
// spec: SPO-Xmulti-OUT-007, SPO-Xmulti-INV-005, SPO-Xmulti-PRE-005
func TestXmultiRegWitnessNameOfWorkspaceWalletCarriesANote(t *testing.T) {
	tr, dst := newTree(), newMem()
	putPool(tr.dir("/d"), "p", 80, descJSON("p", "w", "w", regWitnessJSON("pay", "p", "pay", "w", "p.metadata.json")))
	putWallet(tr.dir("/d"), "w", 40)
	putWallet(dst, "pay", 99)
	rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true})
	o := ownerOf(rep, "p")
	if err != nil || !o.Written {
		t.Fatalf("err %v %+v", err, o)
	}
	n := notes(o)
	if !strings.Contains(n, "regWitness.regPayName") || !strings.Contains(n, "stake key hash") {
		t.Errorf("no note naming the workspace wallet: %s", n)
	}
}

// The reviewer's reproduction: regPayName names a source wallet that is not
// selected and whose keys differ from the workspace wallet of that name.
//
// spec: SPO-Xmulti-OUT-007, SPO-Xmulti-PRE-004, SPO-Xmulti-INV-005
func TestXmultiRegPayNameOfUnselectedWalletWithOtherKeysIsRefused(t *testing.T) {
	tr := newTree()
	reg := regWitnessJSON("pay", "p", "pay", "w", "p.metadata.json")
	putPool(tr.dir("/d"), "p", 80, descJSON("p", "w", "w", reg))
	putWallet(tr.dir("/d"), "w", 40)
	putWallet(tr.dir("/d"), "pay", 41)
	dst := newMem()
	putWallet(dst, "pay", 99)
	rep, _ := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, Only: []Selector{{Name: "p"}, {Name: "w"}}})
	if stored(dst, "p", ports.PoolDescriptor) != "" {
		t.Fatalf("p is stored with regPayName bound to the workspace wallet of other keys: %+v", ownerOf(rep, "p"))
	}
	if why := artefactReason(ownerOf(rep, "p"), ports.PoolDescriptor); !strings.Contains(why, "not selected") {
		t.Errorf("reason %q", why)
	}
	// with the same keys in the workspace it is carried, with a note
	dst = newMem()
	putWallet(dst, "pay", 41)
	rep, _ = multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, Only: []Selector{{Name: "p"}, {Name: "w"}}})
	if !ownerOf(rep, "p").Written || !strings.Contains(notes(ownerOf(rep, "p")), "same keys") {
		t.Errorf("%+v", ownerOf(rep, "p"))
	}
}

// A name nobody has is refused in the selective form; the plain form keeps
// storing the descriptor as it is.
//
// spec: SPO-Xmulti-PRE-013, SPO-Xmulti-PRE-009
func TestXmultiNameNobodyHasIsRefusedOnlyInTheSelectiveForm(t *testing.T) {
	tr, dst := newTree(), newMem()
	putPool(tr.dir("/d"), "p", 80, descJSON("p", "w", "ghost"))
	putWallet(tr.dir("/d"), "w", 40)
	rep, _ := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true})
	if why := artefactReason(ownerOf(rep, "p"), ports.PoolDescriptor); stored(dst, "p", ports.PoolDescriptor) != "" || !strings.Contains(why, "ghost") {
		t.Errorf("selective: %q", why)
	}
	dst = newMem()
	rep, _ = plainMulti(tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}})
	if !ownerOf(rep, "p").Written {
		t.Errorf("plain: %+v", ownerOf(rep, "p"))
	}
}
