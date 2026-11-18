package workspace

import (
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// The plain form prints one row per --owner given, as it did before the
// extension: an owner named twice is attempted twice, and the second attempt
// meets what the first one stored.
//
// spec: SPO-Xmulti-PRE-009
func TestXmultiPlainFormRepeatedOwnerGivesTwoRows(t *testing.T) {
	src, dst := newMem(), newMem()
	putWallet(src, "w", 40)
	rep, err := importer(src, dst, &fakeGPG{}).Run(ctx(), ImportOptions{Owners: []string{"w", "w"}})
	if err != nil || len(rep.Owners) != 2 {
		t.Fatalf("%v %+v", err, rep.Owners)
	}
	if !rep.Owners[0].Written || rep.Owners[1].Written || !strings.Contains(rep.Owners[1].Reason, "Overwrite") {
		t.Errorf("%+v", rep.Owners)
	}
	// the same through the folder form
	tr, dst2 := newTree(), newMem()
	putWallet(tr.dir("/d"), "w", 40)
	rep, err = multi(t, tr, dst2).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, ImportOptions: ImportOptions{Owners: []string{"w", "w"}}})
	if err != nil || len(rep.Owners) != 2 {
		t.Fatalf("%v %+v", err, rep.Owners)
	}
}

// A key kept in upstream's encrypted form has no check of its pair with the
// verification key; the row says so, in both forms.
//
// spec: SPO-Xmulti-OUT-015
func TestXmultiKeptEncryptedKeySaysItsPairIsNotChecked(t *testing.T) {
	build := func(dir *memStore) {
		stake := pair(40, "StakeSigningKeyShelley_ed25519", "StakeVerificationKeyShelley_ed25519", "Stake")
		other := pair(41, "StakeSigningKeyShelley_ed25519", "StakeVerificationKeyShelley_ed25519", "Stake")
		dir.put(ports.NamedRef{Name: "w", Kind: ports.StakingSKey}, encryptedOf(t, other, "Correct-Horse-9"))
		dir.put(ports.NamedRef{Name: "w", Kind: ports.StakingVKey}, stake.vkey)
	}
	src, dst := newMem(), newMem()
	build(src)
	deferred := func(o OwnerReport) bool {
		for _, a := range o.Artefacts {
			if a.Status == StatusFailed && a.Reason == ReasonDeferred {
				return true
			}
		}
		return false
	}
	rep, err := importer(src, dst, &fakeGPG{}).Run(ctx(), ImportOptions{DeferEncrypted: true})
	if o := ownerOf(rep, "w"); err != nil || o.Written || !deferred(o) {
		t.Errorf("plain form: %v %+v", err, o)
	}
	tr, dst2 := newTree(), newMem()
	build(tr.dir("/d"))
	rep, err = multi(t, tr, dst2).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true, ImportOptions: ImportOptions{DeferEncrypted: true}})
	if o := ownerOf(rep, "w"); err != nil || o.Written || !deferred(o) {
		t.Errorf("selective form: %v %+v", err, o)
	}
	for _, d := range []*memStore{dst, dst2} {
		for r := range d.snapshot() {
			if r.Kind == ports.UpstreamEncryptedSKey || OwnerOf(r) == "w" {
				t.Errorf("a deferred owner left %v in the workspace", r)
			}
		}
	}
}

// Two pools that name each other are both refused, and the row says why.
//
// spec: SPO-Xmulti-PRE-011, SPO-Xmulti-INV-004
func TestXmultiPoolsNamingEachOtherAreRefusedAsACycle(t *testing.T) {
	tr, dst := newTree(), newMem()
	putPool(tr.dir("/d"), "p1", 80, descJSON("p1", "p2", "p1"))
	putWallet(tr.dir("/d"), "p1", 1)
	putPool(tr.dir("/d"), "p2", 81, descJSON("p2", "p1", "p2"))
	putWallet(tr.dir("/d"), "p2", 2)
	rep, _ := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, Only: []Selector{{Name: "p2"}, {Name: "p1"}}})
	for _, n := range []string{"p1", "p2"} {
		o := ownerOf(rep, n)
		if stored(dst, n, ports.PoolDescriptor) != "" || !strings.Contains(notes(o), "reference cycle") {
			t.Errorf("%s: %+v", n, o)
		}
	}
}

// A swap with --overwrite: the descriptor follows both renames, and each
// owner holds the key material of the source owner the layout names.
//
// spec: SPO-Xmulti-PRE-012, SPO-Xmulti-OUT-014
func TestXmultiSwapRenameWithOverwrite(t *testing.T) {
	tr := newTree()
	putWallet(tr.dir("/d"), "a", 1)
	putWallet(tr.dir("/d"), "b", 2)
	putPool(tr.dir("/d"), "p", 80, descJSON("p", "a", "b"))
	dst := newMem()
	putWallet(dst, "a", 11)
	putWallet(dst, "b", 12)
	src := newMem()
	putWallet(src, "a", 1)
	putWallet(src, "b", 2)
	rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true,
		Renames:       []Rename{{From: Selector{Name: "a"}, To: "b"}, {From: Selector{Name: "b"}, To: "a"}},
		ImportOptions: ImportOptions{Overwrite: true}})
	if err != nil || rep.Failed() != 0 {
		t.Fatalf("%v %+v", err, rep.Owners)
	}
	if stored(dst, "b", ports.StakingVKey) != string(src.files[ref("a", ports.StakingVKey)]) || stored(dst, "a", ports.StakingVKey) != string(src.files[ref("b", ports.StakingVKey)]) {
		t.Error("an owner does not hold the key of the source owner it was renamed from")
	}
	d := stored(dst, "p", ports.PoolDescriptor)
	if !strings.Contains(d, `"ownerName": "b"`) || !strings.Contains(d, `"poolRewards": "a"`) {
		t.Errorf("descriptor not swapped: %s", d)
	}
}

// A wallet that fails to write refuses the pool that names it, even when
// the pool names a second wallet that did write.
//
// spec: SPO-Xmulti-INV-004
func TestXmultiSecondWalletWriteFailureRefusesThePool(t *testing.T) {
	tr := newTree()
	putWallet(tr.dir("/d"), "w1", 40)
	putWallet(tr.dir("/d"), "w2", 41)
	putPool(tr.dir("/d"), "p", 80, descJSON("p", "w1", "w2"))
	dst := newMem()
	t.Cleanup(func() {
		assertINV006(t, &invState{trs: []*memTree{tr}, dst: dst, renames: map[string]string{}})
	})
	u := ImportWorkspace{Dest: failingDest{dst, "w2"}, Deriver: edDeriver{}, Addresses: addrInspector{}, Open: tr.Open}
	_, _ = u.Import(ctx(), ImportRequest{Dirs: []string{"/d"}, Only: []Selector{{Name: "p"}, {Name: "w1"}, {Name: "w2"}}})
	if stored(dst, "p", ports.PoolDescriptor) != "" {
		t.Error("the pool is stored although a wallet it names was not")
	}
}
