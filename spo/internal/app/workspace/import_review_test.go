package workspace

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/ports"
)

type scenario struct {
	name  string
	build func() (*memTree, *memStore)
	req   ImportRequest
}

// samePlan checks that a dry run said what the real run then did: the same
// owners imported or refused for the same reasons, under the same names, with
// the same descriptor rewrites and artefact destinations.
func samePlan(t *testing.T, name string, dry, real *Report, errDry, errReal error) {
	t.Helper()
	if (errDry == nil) != (errReal == nil) || (errDry != nil && errDry.Error() != errReal.Error()) {
		t.Errorf("%s: errors differ: dry %v, real %v", name, errDry, errReal)
		return
	}
	if dry == nil || real == nil {
		if dry != real {
			t.Errorf("%s: one run has no report", name)
		}
		return
	}
	if len(dry.Owners) != len(real.Owners) {
		t.Errorf("%s: %d owners planned, %d in the real run", name, len(dry.Owners), len(real.Owners))
		return
	}
	for i, d := range dry.Owners {
		r := real.Owners[i]
		if d.Owner != r.Owner || d.Dir != r.Dir || d.Final != r.Final || d.Would != r.Written || d.Reason != r.Reason || !reflect.DeepEqual(d.Rewrites, r.Rewrites) {
			t.Errorf("%s: owner %s differs:\n dry  %+v\n real %+v", name, d.Owner, d, r)
			continue
		}
		if len(d.Artefacts) != len(r.Artefacts) {
			t.Errorf("%s: owner %s: artefact counts differ", name, d.Owner)
			continue
		}
		for j, da := range d.Artefacts {
			ra := r.Artefacts[j]
			ds, rs := da.Status, ra.Status
			if ds == StatusPlanned {
				ds = StatusDone
			}
			if ds != rs || da.Ref != ra.Ref || da.To != ra.To || da.Reason != ra.Reason || strings.ReplaceAll(da.Note, "would replace", "replaces") != ra.Note {
				t.Errorf("%s: %s: artefact differs:\n dry  %+v\n real %+v", name, d.Owner, da, ra)
			}
		}
	}
}

func twoWalletsAndPool() (*memTree, *memStore) {
	tr := newTree()
	d := tr.dir("/w")
	putWallet(d, "alice", 1)
	putWallet(d, "bob", 2)
	putPool(d, "p", 80, descJSON("p", "bob", "bob"))
	return tr, newMem()
}

func reviewScenarios() []scenario {
	sel := func(k OwnerKind, n string) Selector { return Selector{Kind: k, Name: n} }
	return []scenario{
		{"rename onto an unselected owner", twoWalletsAndPool, ImportRequest{Dirs: []string{"/w"},
			Only: []Selector{sel(KindWallet, "alice"), sel(KindPool, "p")}, Renames: []Rename{{From: Selector{Name: "alice"}, To: "bob"}}}},
		{"swap", func() (*memTree, *memStore) { tr, d := twoWalletsAndPool(); return tr, d }, ImportRequest{Dirs: []string{"/w"},
			Only: []Selector{sel(KindWallet, "alice"), sel(KindWallet, "bob")}, Renames: []Rename{{From: Selector{Name: "alice"}, To: "bob"}, {From: Selector{Name: "bob"}, To: "alice"}}}},
		{"nested with renames", nestedBuild, ImportRequest{Dirs: []string{"/w/pool", "/w/wallets"}, All: true,
			Renames: []Rename{{From: Selector{Name: "owner"}, To: "boss"}, {From: Selector{Name: "mypool"}, To: "q"}}}},
		{"unselected owner, workspace wallet with the same keys", func() (*memTree, *memStore) {
			tr, d := nestedBuild()
			putWallet(d, "owner", 40)
			return tr, d
		}, ImportRequest{Dirs: []string{"/w/pool", "/w/wallets"}, Only: []Selector{sel(KindPool, "mypool")}}},
		{"unselected owner, workspace wallet with other keys", func() (*memTree, *memStore) {
			tr, d := nestedBuild()
			putWallet(d, "owner", 99)
			return tr, d
		}, ImportRequest{Dirs: []string{"/w/pool", "/w/wallets"}, Only: []Selector{sel(KindPool, "mypool")}}},
		{"collision", func() (*memTree, *memStore) { return twoWalletsOneName(), newMem() }, ImportRequest{Dirs: []string{"/a", "/b"}, All: true}},
		{"rename onto a workspace owner", func() (*memTree, *memStore) {
			tr, d := twoWalletsAndPool()
			putWallet(d, "bob", 2)
			return tr, d
		}, ImportRequest{Dirs: []string{"/w"}, Only: []Selector{sel(KindWallet, "alice")}, Renames: []Rename{{From: Selector{Name: "alice"}, To: "bob"}}}},
		{"rename onto a workspace owner with overwrite", func() (*memTree, *memStore) {
			tr, d := twoWalletsAndPool()
			putWallet(d, "bob", 2)
			return tr, d
		}, ImportRequest{ImportOptions: ImportOptions{Overwrite: true}, Dirs: []string{"/w"}, Only: []Selector{sel(KindWallet, "alice")}, Renames: []Rename{{From: Selector{Name: "alice"}, To: "bob"}}}},
		{"bare name in another folder, renamed", bareBuild, ImportRequest{Dirs: []string{"/w/pool", "/w/wallets"}, All: true, Renames: []Rename{{From: Selector{Name: "owner"}, To: "owner2"}}}},
		{"names that differ by case", func() (*memTree, *memStore) {
			tr := newTree()
			putWallet(tr.dir("/a"), "Owner", 1)
			putWallet(tr.dir("/b"), "owner", 2)
			return tr, newMem()
		}, ImportRequest{Dirs: []string{"/a", "/b"}, All: true}},
	}
}

func nestedBuild() (*memTree, *memStore) { return nestedTree(), newMem() }

func bareBuild() (*memTree, *memStore) {
	tr := newTree()
	putPool(tr.dir("/w/pool"), "p", 80, descJSON("p", "owner", "owner"))
	putWallet(tr.dir("/w/wallets"), "owner", 40)
	return tr, newMem()
}

// For a table of scenarios, the dry run and the real run, on identical
// workspaces, agree on everything the dry run claims.
//
// spec: SPO-Xmulti-INV-003, SPO-Xmulti-OUT-010
func TestXmultiDryRunPlanEqualsRealRun(t *testing.T) {
	for _, sc := range append(reviewScenarios(), propagationScenarios()...) {
		tr, dst := sc.build()
		req := sc.req
		req.DryRun = true
		dry, errDry := multi(t, tr, dst).Import(ctx(), req)
		if len(dst.files) != len(func() map[ports.NamedRef]string { _, d := sc.build(); return d.snapshot() }()) {
			t.Errorf("%s: the dry run wrote", sc.name)
		}
		tr2, dst2 := sc.build()
		req.DryRun = false
		real, errReal := multi(t, tr2, dst2).Import(ctx(), req)
		samePlan(t, sc.name, dry, real, errDry, errReal)
	}
}

// A rename onto the name of an owner that was found and not selected is
// refused before anything is written, in the dry run and the real run alike:
// otherwise the pool that names that owner is bound to the renamed wallet's
// keys. Swaps and chains of renames stay valid.
//
// spec: SPO-Xmulti-PRE-002, SPO-Xmulti-INV-003
func TestXmultiRenameOntoUnselectedOwnerIsRefused(t *testing.T) {
	sc := reviewScenarios()[0]
	for _, dry := range []bool{true, false} {
		tr, dst := sc.build()
		req := sc.req
		req.DryRun = dry
		_, err := multi(t, tr, dst).Import(ctx(), req)
		if !errors.Is(err, ErrBadRename) || !strings.Contains(err.Error(), `"bob"`) || len(dst.files) != 0 || dst.updates != 0 {
			t.Errorf("dry=%v: err %v, files %d", dry, err, len(dst.files))
		}
	}
	// the same name in another case is the same name
	tr, dst := twoWalletsAndPool()
	_, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/w"}, Only: []Selector{{Name: "alice"}}, Renames: []Rename{{From: Selector{Name: "alice"}, To: "BOB"}}})
	if !errors.Is(err, ErrBadRename) {
		t.Errorf("case: %v", err)
	}
	// a swap and a chain are correct
	tr, dst = twoWalletsAndPool()
	before := tr.dirs["/w"].snapshot()
	rep, err := multi(t, tr, dst).Import(ctx(), reviewScenarios()[1].req)
	if err != nil || rep.Failed() != 0 {
		t.Fatalf("swap: %v %+v", err, rep)
	}
	if stored(dst, "bob", ports.StakingVKey) != before[ref("alice", ports.StakingVKey)] || stored(dst, "alice", ports.StakingVKey) != before[ref("bob", ports.StakingVKey)] {
		t.Error("the swap did not exchange the wallets")
	}
	tr, dst = twoWalletsAndPool()
	rep, err = multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/w"}, Only: []Selector{{Name: "alice"}, {Name: "bob"}},
		Renames: []Rename{{From: Selector{Name: "alice"}, To: "bob"}, {From: Selector{Name: "bob"}, To: "carol"}}})
	if err != nil || rep.Failed() != 0 || stored(dst, "carol", ports.StakingVKey) != before[ref("bob", ports.StakingVKey)] || stored(dst, "bob", ports.StakingVKey) != before[ref("alice", ports.StakingVKey)] {
		t.Fatalf("chain: %v %+v", err, rep)
	}
}

// A reference that resolves to a source owner that was found and not selected
// is satisfied by a workspace wallet of that name only when the verification
// keys are the same; with other keys the pool is refused naming both. A name
// found in no source and held by the workspace is accepted with a note that
// says which wallet it was bound to.
//
// spec: SPO-Xmulti-PRE-004, SPO-Xmulti-PRE-010
func TestXmultiUnselectedOwnerNeedsTheSameWorkspaceKeys(t *testing.T) {
	scs := reviewScenarios()
	tr4, dst4 := scs[4].build()
	rep, err := multi(t, tr4, dst4).Import(ctx(), scs[4].req)
	if err != nil || rep.Failed() != 1 {
		t.Fatalf("other keys: %v %+v", err, rep)
	}
	why := artefactReason(ownerOf(rep, "mypool"), ports.PoolDescriptor)
	if !strings.Contains(why, `workspace holds a wallet "owner"`) || !strings.Contains(why, "source wallet") || !strings.Contains(why, "/w/wallets") {
		t.Errorf("reason %q", why)
	}
	tr, dst := scs[3].build()
	rep, err = multi(t, tr, dst).Import(ctx(), scs[3].req)
	if err != nil || rep.Failed() != 0 {
		t.Fatalf("same keys: %v %+v", err, rep)
	}
	// nothing in the sources, a wallet in the workspace: a note names it
	tr, dst = newTree(), newMem()
	putPool(tr.dir("/d"), "p", 80, descJSON("p", "ws-wallet", "ws-wallet"))
	putWallet(dst, "ws-wallet", 7)
	rep, err = multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true})
	if err != nil || rep.Failed() != 0 {
		t.Fatalf("workspace wallet: %v %+v", err, rep)
	}
	note := ""
	for _, a := range ownerOf(rep, "p").Artefacts {
		note += a.Note
	}
	kp := pair(7, "StakeSigningKeyShelley_ed25519", "StakeVerificationKeyShelley_ed25519", "Stake")
	if !strings.Contains(note, `existing workspace wallet "ws-wallet"`) || !strings.Contains(note, fmt.Sprintf("%x", keyHashOf(kp.vkey))) {
		t.Errorf("note %q", note)
	}
}

// A bare name is looked up in the descriptor's folder, then, when it is not
// there and exactly one owner of that name is in the other folders of the run,
// resolves to that one (and follows its rename); several is ambiguous. Names
// inside an open registration follow the same rule.
//
// spec: SPO-Xmulti-PRE-008, SPO-Xmulti-OUT-007, SPO-Xmulti-SEC-003
func TestXmultiBareNameInAnotherFolder(t *testing.T) {
	sc := reviewScenarios()[8]
	tr, dst := sc.build()
	rep, err := multi(t, tr, dst).Import(ctx(), sc.req)
	if err != nil || rep.Failed() != 0 {
		t.Fatalf("%v %+v", err, rep)
	}
	d := stored(dst, "p", ports.PoolDescriptor)
	if strings.Contains(d, `"owner"`) || strings.Count(d, `"owner2"`) != 2 {
		t.Errorf("descriptor:\n%s", d)
	}
	note := ""
	for _, a := range ownerOf(rep, "p").Artefacts {
		note += a.Note
	}
	if !strings.Contains(note, "not in the folder of the descriptor") || len(ownerOf(rep, "p").Rewrites) != 2 {
		t.Errorf("note %q rewrites %+v", note, ownerOf(rep, "p").Rewrites)
	}
	// not selected: refused, naming it
	tr, dst = bareBuild()
	rep, _ = multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/w/pool", "/w/wallets"}, Only: []Selector{{Kind: KindPool, Name: "p"}}})
	if rep.Failed() != 1 || !strings.Contains(artefactReason(ownerOf(rep, "p"), ports.PoolDescriptor), "--only wallet:owner@/w/wallets") {
		t.Errorf("unselected: %+v", rep.Owners)
	}
	// in its own folder it wins over the same name elsewhere
	tr, dst = bareBuild()
	putWallet(tr.dir("/w/pool"), "owner", 41)
	rep, err = multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/w/pool", "/w/wallets"}, Only: []Selector{{Kind: KindPool, Name: "p"}, {Kind: KindWallet, Name: "owner", Dir: "/w/pool"}}})
	if err != nil || rep.Failed() != 0 || len(ownerOf(rep, "p").Rewrites) != 0 {
		t.Errorf("own folder: %v %+v", err, rep)
	}
	// several others: ambiguous
	tr, dst = bareBuild()
	putWallet(tr.dir("/w/more"), "owner", 42)
	rep, _ = multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/w/pool", "/w/wallets", "/w/more"}, All: true,
		Renames: []Rename{{From: Selector{Name: "owner", Dir: "/w/more"}, To: "owner3"}}})
	why := artefactReason(ownerOf(rep, "p"), ports.PoolDescriptor)
	if !strings.Contains(why, "several other folders") || !strings.Contains(why, "/w/wallets") || !strings.Contains(why, "/w/more") {
		t.Errorf("ambiguous: %q", why)
	}
	// a registration naming a wallet that this import renames refuses the pool,
	// even where no descriptor field names the wallet
	tr, dst = newTree(), newMem()
	reg := `"regWitness": {"regPayName": "owner", "witnesses": {"p.node": {}, "owner.staking": {}}}`
	putPool(tr.dir("/w/pool"), "p", 80, descJSON("p", "", "", reg))
	putWallet(tr.dir("/w/wallets"), "owner", 40)
	req := ImportRequest{Dirs: []string{"/w/pool", "/w/wallets"}, All: true, Renames: []Rename{{From: Selector{Name: "owner"}, To: "owner2"}}}
	rep, _ = multi(t, tr, dst).Import(ctx(), req)
	if !strings.Contains(artefactReason(ownerOf(rep, "p"), ports.PoolDescriptor), `names "owner", which this import stores as "owner2"`) || ownerOf(rep, "p").Written {
		t.Errorf("regWitness: %+v", ownerOf(rep, "p"))
	}
	// without the rename it is carried
	req.Renames = nil
	rep, err = multi(t, tr, newMem()).Import(ctx(), req)
	if err != nil || rep.Failed() != 0 {
		t.Errorf("regWitness carried: %v %+v", err, rep)
	}
}

// A rename onto an owner the workspace already holds is refused without
// --overwrite; with it, the checks run over the union of what the workspace
// holds and what comes in, and the table says what was replaced.
//
// spec: SPO-Xmulti-OUT-011
func TestXmultiRenameOntoWorkspaceOwner(t *testing.T) {
	build := func() (*memTree, *memStore) {
		tr, dst := newTree(), newMem()
		putPool(tr.dir("/d"), "p", 80, "")
		for _, k := range []ports.Kind{ports.NodeCounter, ports.KesCounter, ports.KesCounterNext} {
			delete(tr.dir("/d").files, ref("p", k))
		}
		// the workspace holds q with a hardware file and a counter of another cold key
		var vk [32]byte
		env, _ := pool.ParseEnvelope(cold(5).vkey)
		kb, _ := env.Key32()
		copy(vk[:], kb)
		dst.put(ref("q", ports.NodeHwsFile), []byte(`{"type":"x"}`))
		dst.put(ref("q", ports.NodeCounter), pool.IssueCounter{Next: 3, ColdVKey: vk}.Envelope())
		return tr, dst
	}
	req := ImportRequest{Dirs: []string{"/d"}, All: true, Renames: []Rename{{From: Selector{Name: "p"}, To: "q"}}}
	tr, dst := build()
	before := dst.snapshot()
	rep, _ := multi(t, tr, dst).Import(ctx(), req)
	if ownerOf(rep, "p").Written || !strings.Contains(ownerOf(rep, "p").Reason+artefactReason(ownerOf(rep, "p"), ports.NodeVKey), `already holds`) || !reflect.DeepEqual(dst.snapshot(), before) {
		t.Errorf("without overwrite: %+v", ownerOf(rep, "p"))
	}
	req.Overwrite = true
	tr, dst = build()
	rep, _ = multi(t, tr, dst).Import(ctx(), req)
	o := ownerOf(rep, "p")
	if o.Written || !strings.Contains(artefactReasons(o), "issue counter belongs to another cold key") {
		t.Errorf("with overwrite: %+v", o)
	}
	if !reflect.DeepEqual(dst.snapshot(), build2(build)) {
		t.Error("the workspace changed")
	}
	// a plain non-renamed import into a partial owner is checked too
	tr, dst = build()
	dst2 := newMem()
	for r, b := range dst.files {
		dst2.files[ref("p", r.Kind)] = b
	}
	rep, _ = multi(t, tr, dst2).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true})
	if ownerOf(rep, "p").Written {
		t.Errorf("partial owner merged: %+v", ownerOf(rep, "p"))
	}
	// replaced artefacts are stated
	tr, dst = newTree(), newMem()
	putWallet(tr.dir("/d"), "w", 40)
	putWallet(dst, "w", 40)
	rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{ImportOptions: ImportOptions{Overwrite: true}, Dirs: []string{"/d"}, All: true, DryRun: true})
	if err != nil || rep.Failed() != 0 {
		t.Fatalf("%v %+v", err, rep)
	}
	for _, a := range ownerOf(rep, "w").Artefacts {
		if !strings.Contains(a.Note, "would replace the workspace's existing") {
			t.Errorf("%v: note %q", a.Ref, a.Note)
		}
	}
}

func build2(build func() (*memTree, *memStore)) map[ports.NamedRef]string {
	_, d := build()
	return d.snapshot()
}

func artefactReasons(o OwnerReport) string {
	var s []string
	for _, a := range o.Artefacts {
		s = append(s, a.Reason)
	}
	return strings.Join(s, "; ")
}

// Owners whose names differ only by case are one name: within a run they
// collide, and against the workspace they are refused.
//
// spec: SPO-Xmulti-OUT-012
func TestXmultiNamesDifferingByCaseCollide(t *testing.T) {
	sc := reviewScenarios()[9]
	tr, dst := sc.build()
	_, err := multi(t, tr, dst).Import(ctx(), sc.req)
	if !errors.Is(err, ErrNameCollision) || len(dst.files) != 0 {
		t.Errorf("in a run: %v", err)
	}
	req := sc.req
	req.Renames = []Rename{{From: Selector{Name: "owner"}, To: "owner2"}}
	tr, dst = sc.build()
	if rep, err := multi(t, tr, dst).Import(ctx(), req); err != nil || rep.Failed() != 0 {
		t.Errorf("renamed: %v", err)
	}
	// against the workspace
	tr, dst = newTree(), newMem()
	putWallet(tr.dir("/a"), "Owner", 1)
	putWallet(dst, "owner", 2)
	rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{ImportOptions: ImportOptions{Overwrite: true}, Dirs: []string{"/a"}, All: true})
	if err != nil || ownerOf(rep, "Owner").Written || !strings.Contains(artefactReasons(ownerOf(rep, "Owner"))+ownerOf(rep, "Owner").Reason, "differs only by case") {
		t.Errorf("against the workspace: %v %+v", err, ownerOf(rep, "Owner"))
	}
}

// The plain form, one folder with none of the selection options, stores what
// it always stored: every artefact as it is, a descriptor too, whatever is in
// it; what a selective import would have refused is said in a note. (The
// stored result is what the import before Xmulti produced: Run copied each
// artefact unchanged.)
//
// spec: SPO-Xmulti-PRE-009, SPO-Xmulti-IN-003
func TestXmultiPlainFormStoresDescriptorsAsTheyAre(t *testing.T) {
	odd := map[string]string{
		"bom":     "\ufeff" + descJSON("p", "owner", "owner"),
		"regname": descJSON("other-name", "owner", "owner", `"regWitness": {"regPayName": "owner", "witnesses": {"p.node": {}}}`),
		"badref":  descJSON("p", "../x", "../x"),
		"rewrite": descJSON("pool/p", "owner", "owner"),
	}
	for name, desc := range odd {
		tr, dst := newTree(), newMem()
		putPool(tr.dir("/d"), "p", 80, desc)
		putWallet(tr.dir("/d"), "owner", 40)
		rep, err := plainMulti(tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}})
		if err != nil || rep.Failed() != 0 {
			t.Errorf("%s: %v %+v", name, err, rep)
			continue
		}
		if stored(dst, "p", ports.PoolDescriptor) != desc {
			t.Errorf("%s: stored %q", name, stored(dst, "p", ports.PoolDescriptor))
		}
		note := ""
		for _, a := range ownerOf(rep, "p").Artefacts {
			note += a.Note
		}
		if name != "bom" && !strings.Contains(note, "stored as it is and not examined; a selective import") {
			t.Errorf("%s: note %q", name, note)
		}
		if rep.Extended || len(ownerOf(rep, "p").Rewrites) != 0 {
			t.Errorf("%s: the plain form reported as selective", name)
		}
		// the same descriptor in selective mode: a BOM is accepted, the others refused
		tr2 := newTree()
		putPool(tr2.dir("/d"), "p", 80, desc)
		putWallet(tr2.dir("/d"), "owner", 40)
		rep, _ = multi(t, tr2, newMem()).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true})
		switch name {
		case "bom", "rewrite":
			if rep.Failed() != 0 {
				t.Errorf("selective %s: %+v", name, rep.Owners)
			}
		default:
			if rep.Failed() != 1 {
				t.Errorf("selective %s: not refused", name)
			}
		}
	}
	// --owner is the old option: still the plain form
	tr, dst := newTree(), newMem()
	putPool(tr.dir("/d"), "p", 80, descJSON("p", "../x", "../x"))
	putWallet(tr.dir("/d"), "owner", 40)
	rep, err := plainMulti(tr, dst).Import(ctx(), ImportRequest{ImportOptions: ImportOptions{Owners: []string{"p"}}, Dirs: []string{"/d"}})
	if err != nil || rep.Failed() != 0 || len(rep.Owners) != 1 {
		t.Errorf("--owner: %v %+v", err, rep)
	}
}

// A descriptor that starts with a byte order mark keeps it, and a rewrite
// still applies to it.
//
// spec: SPO-Xmulti-PRE-009, SPO-Xmulti-INV-002
func TestXmultiBOMDescriptorIsRewrittenInPlace(t *testing.T) {
	tr, dst := newTree(), newMem()
	desc := "\ufeff" + descJSON("pool/p", "../wallets/owner", "../wallets/owner")
	putPool(tr.dir("/w/pool"), "p", 80, desc)
	putWallet(tr.dir("/w/wallets"), "owner", 40)
	rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/w/pool", "/w/wallets"}, All: true, Renames: []Rename{{From: Selector{Name: "owner"}, To: "boss"}}})
	if err != nil || rep.Failed() != 0 {
		t.Fatalf("%v %+v", err, rep)
	}
	want := "\ufeff" + descJSON("p", "boss", "boss")
	if got := stored(dst, "p", ports.PoolDescriptor); got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

// A renamed wallet and a renamed pool arrive complete under the new name:
// payment keys and addresses, hardware files, upstream-encrypted keys and
// witness files; nothing stays under the old name and nothing is dropped
// without a row in the table.
//
// spec: SPO-Xmulti-IN-004, SPO-Xmulti-OUT-001
func TestXmultiRenameCarriesEveryArtefact(t *testing.T) {
	g := &fakeGPG{}
	tr, dst := newTree(), newMem()
	d := tr.dir("/d")
	pay, stake := payment(1), pair(40, "StakeSigningKeyShelley_ed25519", "StakeVerificationKeyShelley_ed25519", "Stake")
	d.put(ports.NamedRef{Name: "w.payment", Kind: ports.AddrSKey}, pay.skey)
	d.put(ports.NamedRef{Name: "w.payment", Kind: ports.AddrVKey}, pay.vkey)
	d.put(ports.NamedRef{Name: "w.payment", Kind: ports.AddrFile}, addrOf(pay.vkey))
	d.put(ports.NamedRef{Name: "w.payment", Kind: ports.AddrHwsFile}, []byte(`{"type":"PaymentHW"}`))
	d.put(ports.NamedRef{Name: "w", Kind: ports.StakingSKey}, encryptedOf(t, stake, "Correct-Horse-9"))
	d.put(ports.NamedRef{Name: "w", Kind: ports.StakingVKey}, stake.vkey)
	d.put(ports.NamedRef{Name: "w", Kind: ports.StakingHwsFile}, []byte(`{"type":"StakeHW"}`))
	putPool(d, "pl", 80, "")
	d.put(ports.NamedRef{Name: "pl", Kind: ports.NodeHwsFile}, []byte(`{"type":"NodeHW"}`))
	d.put(ports.NamedRef{Name: "pl_0001_abc", Kind: ports.PoolWitnessFile}, []byte(`{"type":"Witness"}`))
	u := multi(t, tr, dst)
	u.Decryptor = g
	pw := sec("Correct-Horse-9")
	rep, err := u.Import(ctx(), ImportRequest{ImportOptions: ImportOptions{Password: pw}, Dirs: []string{"/d"}, All: true,
		Renames: []Rename{{From: Selector{Name: "w"}, To: "w2"}, {From: Selector{Name: "pl"}, To: "pl2"}}})
	if err != nil || rep.Failed() != 0 {
		t.Fatalf("%v %+v", err, rep)
	}
	var want []ports.NamedRef
	for r := range d.files {
		n := strings.Replace(r.Name, "w", "w2", 1)
		if strings.HasPrefix(r.Name, "pl") {
			n = strings.Replace(r.Name, "pl", "pl2", 1)
		}
		want = append(want, ports.NamedRef{Name: n, Kind: r.Kind, Num: r.Num})
	}
	for _, w := range want {
		if _, ok := dst.files[w]; !ok {
			t.Errorf("missing under the new name: %v", w)
		}
	}
	if len(dst.files) != len(d.files) {
		t.Errorf("%d artefacts stored, %d in the source", len(dst.files), len(d.files))
	}
	for r := range dst.files {
		if r.Name == "w" || r.Name == "w.payment" || strings.HasPrefix(r.Name, "pl_") || r.Name == "pl" {
			t.Errorf("old name stored: %v", r)
		}
	}
	rows := 0
	for _, o := range rep.Owners {
		rows += len(o.Artefacts)
	}
	if rows != len(d.files) {
		t.Errorf("%d rows for %d artefacts", rows, len(d.files))
	}
	for _, o := range rep.Owners {
		for _, a := range o.Artefacts {
			if a.Status != StatusDone || (a.To.Name == "" && a.Ref.Name != o.Final) {
				t.Errorf("%v: %+v", a.Ref, a)
			}
		}
	}
}

// A deferred upstream-encrypted key is left in the source under a rename too: no
// record of it is stored under the old or the new name.
//
// spec: SPO-Xmulti-IN-004
func TestXmultiRenameWithDeferredEncryptedKeyStoresNothing(t *testing.T) {
	tr, dst := newTree(), newMem()
	stake := pair(40, "StakeSigningKeyShelley_ed25519", "StakeVerificationKeyShelley_ed25519", "Stake")
	tr.dir("/d").put(ports.NamedRef{Name: "w", Kind: ports.StakingSKey}, encryptedOf(t, stake, "Correct-Horse-9"))
	tr.dir("/d").put(ports.NamedRef{Name: "w", Kind: ports.StakingVKey}, stake.vkey)
	rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{ImportOptions: ImportOptions{DeferEncrypted: true}, Dirs: []string{"/d"}, All: true,
		Renames: []Rename{{From: Selector{Name: "w"}, To: "w2"}}})
	if err != nil || rep.Failed() != 1 {
		t.Fatalf("%v %+v", err, rep)
	}
	if len(dst.files) != 0 {
		t.Errorf("stored %v", dst.files)
	}
}

// The workspace fixture of the older import tests, with the descriptors that
// the examination of a selective import refuses, goes through the plain form
// and arrives artefact for artefact as the import before Xmulti stored it:
// every artefact byte for byte under its own name (git show HEAD:
// spo/internal/app/workspace/import.go copies each ref unchanged).
//
// spec: SPO-Xmulti-PRE-009
func TestXmultiPlainFormEqualsTheOlderImport(t *testing.T) {
	for name, desc := range map[string]string{
		"none":    "",
		"bom":     "\ufeff" + descJSON("mypool", "w", "w"),
		"regname": descJSON("not-mypool", "w", "w", `"regWitness": {"regPayName": "w", "witnesses": {"mypool.node": {}}}`),
		"badref":  descJSON("mypool", "../x", "../x"),
	} {
		src, _ := workspaceFixture(t)
		if desc != "" {
			src.put(ref("mypool", ports.PoolDescriptor), []byte(desc))
		}
		src.put(ref("mypool", ports.NodeHwsFile), []byte(`{"type":"hw"}`))
		tr := newTree()
		tr.dirs["/old"] = &memDir{memStore: src}
		viaImport, viaRun := newMem(), newMem()
		rep, err := ImportWorkspace{Dest: viaImport, Deriver: edDeriver{}, Addresses: addrInspector{}, Open: tr.Open}.Import(ctx(), ImportRequest{Dirs: []string{"/old"}})
		if err != nil || rep.Failed() != 0 {
			t.Fatalf("%s: %v %+v", name, err, rep)
		}
		if _, err := importer(src, viaRun, nil).Run(ctx(), ImportOptions{}); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(viaImport.snapshot(), src.snapshot()) {
			t.Errorf("%s: the plain form stored something else than the source", name)
		}
		if !reflect.DeepEqual(viaImport.snapshot(), viaRun.snapshot()) {
			t.Errorf("%s: Import and Run differ", name)
		}
	}
}

// poolsOverWallet is two pools that name one wallet, in a folder of their own
// beside the wallet's.
func poolsOverWallet(wsSeed byte, wsName string) func() (*memTree, *memStore) {
	return func() (*memTree, *memStore) {
		tr := newTree()
		putPool(tr.dir("/w/pool"), "p1", 80, descJSON("p1", "../wallets/owner", "../wallets/owner"))
		putPool(tr.dir("/w/pool"), "p2", 81, descJSON("p2", "../wallets/owner", "../wallets/owner"))
		putWallet(tr.dir("/w/wallets"), "owner", 40)
		dst := newMem()
		if wsSeed != 0 {
			putWallet(dst, wsName, wsSeed)
		}
		return tr, dst
	}
}

// propagationScenarios are the runs in which a wallet a pool names is
// refused for a reason of its own.
func propagationScenarios() []scenario {
	two := []string{"/w/pool", "/w/wallets"}
	return []scenario{
		{"a: wallet's rename refused", func() (*memTree, *memStore) {
			tr := newTree()
			putWallet(tr.dir("/w"), "alice", 1)
			putPool(tr.dir("/w"), "p", 80, descJSON("p", "alice", "alice"))
			dst := newMem()
			putWallet(dst, "bob", 2)
			return tr, dst
		}, ImportRequest{Dirs: []string{"/w"}, All: true, Renames: []Rename{{From: Selector{Name: "alice"}, To: "bob"}}}},
		{"b: wallet conflicts with the workspace", poolsOverWallet(99, "owner"), ImportRequest{Dirs: two, All: true}},
		{"c: wallet's key pair does not match", func() (*memTree, *memStore) {
			tr, dst := poolsOverWallet(99, "owner")()
			other := newMem()
			putWallet(other, "x", 41)
			tr.dir("/w/wallets").put(ref("owner", ports.StakingSKey), other.files[ref("x", ports.StakingSKey)])
			return tr, dst
		}, ImportRequest{Dirs: two, All: true, ImportOptions: ImportOptions{Overwrite: true}}},
		{"d: wallet refused by the case rule", func() (*memTree, *memStore) {
			tr := newTree()
			putWallet(tr.dir("/w"), "Owner", 40)
			putPool(tr.dir("/w"), "p", 80, descJSON("p", "Owner", "Owner"))
			dst := newMem()
			putWallet(dst, "owner", 99)
			return tr, dst
		}, ImportRequest{Dirs: []string{"/w"}, All: true}},
		{"identical wallet in the workspace", poolsOverWallet(40, "owner"), ImportRequest{Dirs: two, All: true}},
	}
}

func noPoolStored(t *testing.T, name string, dst *memStore, pools ...string) {
	t.Helper()
	for _, p := range pools {
		if _, ok := dst.files[ref(p, ports.PoolDescriptor)]; ok {
			t.Errorf("%s: pool %s was stored", name, p)
		}
		for r := range dst.files {
			if OwnerOf(r) == p {
				t.Errorf("%s: %s of the refused pool %s was stored", name, r, p)
			}
		}
	}
}

// A pool is never stored naming a selected wallet that this run did not
// store: not when the wallet's rename, its case, the workspace conflict or a
// check of its own refuses it, in the dry run and the real run alike; the pool
// row names the wallet and its reason, and so does a second pool sharing it.
//
// spec: SPO-Xmulti-PRE-011, SPO-Xmulti-INV-004
func TestXmultiPoolOfRefusedWalletIsRefused(t *testing.T) {
	want := map[string]struct {
		reason string
		pools  []string
		ws     string
	}{
		"a: wallet's rename refused":             {`wallet it names, alice, is refused`, []string{"p"}, "bob"},
		"b: wallet conflicts with the workspace": {`wallet it names, owner, is refused`, []string{"p1", "p2"}, "owner"},
		"c: wallet's key pair does not match":    {`does not belong to the verification key`, []string{"p1", "p2"}, "owner"},
		"d: wallet refused by the case rule":     {`differs only by case`, []string{"p"}, "owner"},
	}
	for _, sc := range propagationScenarios() {
		w, ok := want[sc.name]
		if !ok {
			continue
		}
		for _, dry := range []bool{true, false} {
			tr, dst := sc.build()
			before := dst.snapshot()
			req := sc.req
			req.DryRun = dry
			rep, err := multi(t, tr, dst).Import(ctx(), req)
			if err != nil {
				t.Fatalf("%s: %v", sc.name, err)
			}
			noPoolStored(t, sc.name, dst, w.pools...)
			if stored(dst, w.ws, ports.StakingVKey) != before[ref(w.ws, ports.StakingVKey)] {
				t.Errorf("%s: the workspace's %s was changed", sc.name, w.ws)
			}
			for _, p := range w.pools {
				o := ownerOf(rep, p)
				why := artefactReason(o, ports.PoolDescriptor)
				if o.Written || o.Would || !strings.Contains(why, "refused because the wallet it names") || !strings.Contains(why, w.reason) {
					t.Errorf("%s dry=%v: pool %s: %+v", sc.name, dry, p, o)
				}
			}
		}
	}
}

// A wallet that is refused only because the workspace already holds the same
// wallet is used by the pool, with a note; with other keys the pool is refused.
//
// spec: SPO-Xmulti-PRE-011
func TestXmultiPoolBindsToIdenticalWorkspaceWallet(t *testing.T) {
	for _, dry := range []bool{true, false} {
		tr, dst := poolsOverWallet(40, "owner")()
		rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/w/pool", "/w/wallets"}, All: true, DryRun: dry})
		if err != nil {
			t.Fatal(err)
		}
		o := ownerOf(rep, "p1")
		note := ""
		for _, a := range o.Artefacts {
			note += a.Note
		}
		if (!o.Written && !o.Would) || !strings.Contains(note, "already holds a wallet") {
			t.Errorf("dry=%v: %+v", dry, o)
		}
		if !dry && stored(dst, "p1", ports.PoolDescriptor) == "" {
			t.Error("pool not stored")
		}
		if ownerOf(rep, "owner").Written || ownerOf(rep, "owner").Would {
			t.Error("the wallet was imported over the identical one")
		}
	}
}

// failingDest fails the write of one owner's artefacts.
type failingDest struct {
	*memStore
	owner string
}

type failingWriter struct {
	ports.NamedWriter
	owner string
}

func (w failingWriter) Put(r ports.NamedRef, b []byte) error {
	if OwnerOf(r) == w.owner {
		return errors.New("disk full")
	}
	return w.NamedWriter.Put(r, b)
}

func (w failingWriter) PutSecret(r ports.NamedRef, b *ports.Secret) error {
	if OwnerOf(r) == w.owner {
		return errors.New("disk full")
	}
	return w.NamedWriter.PutSecret(r, b)
}

func (d failingDest) Update(c context.Context, fn func(ports.NamedWriter) error) error {
	return d.memStore.Update(c, func(w ports.NamedWriter) error { return fn(failingWriter{w, d.owner}) })
}

// When a write fails at run time, nothing of the run is stored (one
// transaction) and every planned owner says so; the wallet is written before
// the pools whatever the order of the folders.
//
// spec: SPO-Xmulti-PRE-011, SPO-Xmulti-INV-004, SPO-Xmulti-INV-008
func TestXmultiWalletWriteFailureRefusesItsPools(t *testing.T) {
	tr, dst := poolsOverWallet(0, "")()
	t.Cleanup(func() {
		assertINV006(t, &invState{trs: []*memTree{tr}, dst: dst, renames: map[string]string{}})
	})
	fd := failingDest{dst, "owner"}
	u := ImportWorkspace{Dest: fd, Deriver: edDeriver{}, Addresses: addrInspector{}, Open: tr.Open}
	rep, err := u.Import(ctx(), ImportRequest{Dirs: []string{"/w/pool", "/w/wallets"}, All: true})
	if err != nil {
		t.Fatal(err)
	}
	// the run is one transaction: a failed write stores none of the owners, and
	// every row of a planned owner says so
	noPoolStored(t, "write failure", dst, "p1", "p2", "owner")
	if len(dst.files) != 0 {
		t.Errorf("the run left %d artefacts", len(dst.files))
	}
	for _, p := range []string{"p1", "p2", "owner"} {
		o := ownerOf(rep, p)
		if o.Written || o.Would || !strings.Contains(o.Reason, "nothing of this run was imported") {
			t.Errorf("%s: %+v", p, o)
		}
	}
	// the order of writing: the wallet is written before the pools
	tr, dst = poolsOverWallet(0, "")()
	var order []string
	rec := recordingDest{memStore: dst, order: &order}
	t.Cleanup(func() {
		assertINV006(t, &invState{trs: []*memTree{tr}, dst: dst, renames: map[string]string{}})
	})
	u = ImportWorkspace{Dest: rec, Deriver: edDeriver{}, Addresses: addrInspector{}, Open: tr.Open}
	if _, err := u.Import(ctx(), ImportRequest{Dirs: []string{"/w/pool", "/w/wallets"}, All: true}); err != nil {
		t.Fatal(err)
	}
	if len(order) != 3 || order[0] != "owner" {
		t.Errorf("order of writing %v", order)
	}
}

type recordingDest struct {
	*memStore
	order *[]string
}

type recordingWriter struct {
	ports.NamedWriter
	seen map[string]bool
	d    recordingDest
}

func (w recordingWriter) note(r ports.NamedRef) {
	if n := OwnerOf(r); !w.seen[n] {
		w.seen[n] = true
		*w.d.order = append(*w.d.order, n)
	}
}
func (w recordingWriter) Put(r ports.NamedRef, b []byte) error {
	w.note(r)
	return w.NamedWriter.Put(r, b)
}
func (w recordingWriter) PutSecret(r ports.NamedRef, b *ports.Secret) error {
	w.note(r)
	return w.NamedWriter.PutSecret(r, b)
}

func (d recordingDest) Update(c context.Context, fn func(ports.NamedWriter) error) error {
	return d.memStore.Update(c, func(w ports.NamedWriter) error { return fn(recordingWriter{w, map[string]bool{}, d}) })
}

// A name in the descriptor that no source owner has is not silently satisfied
// by another owner renamed to it, with or without the workspace holding one.
//
// spec: SPO-Xmulti-PRE-012
func TestXmultiReferenceIsNotSatisfiedByRenameTarget(t *testing.T) {
	for _, ow := range []bool{false, true} {
		tr := newTree()
		putWallet(tr.dir("/w"), "alice", 1)
		putPool(tr.dir("/w"), "p", 80, descJSON("p", "bob", "bob"))
		dst := newMem()
		if ow {
			putWallet(dst, "bob", 2)
		}
		rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/w"}, All: true, ImportOptions: ImportOptions{Overwrite: ow},
			Renames: []Rename{{From: Selector{Name: "alice"}, To: "bob"}}})
		if err != nil {
			t.Fatal(err)
		}
		o := ownerOf(rep, "p")
		why := artefactReason(o, ports.PoolDescriptor)
		if o.Written || !strings.Contains(why, `not the wallet "alice"`) || !strings.Contains(why, "do not rename onto that name") {
			t.Errorf("overwrite=%v: %+v", ow, o)
		}
		if _, ok := dst.files[ref("p", ports.PoolDescriptor)]; ok {
			t.Errorf("overwrite=%v: pool stored", ow)
		}
		if !ownerOf(rep, "alice").Written {
			t.Errorf("overwrite=%v: alice not imported", ow)
		}
	}
}

// With --overwrite the plain form says which artefacts it replaces, and when an
// incoming cold key replaces those of a pool with another cold key; it refuses
// nothing it did not refuse before.
//
// spec: SPO-Xmulti-OUT-013
func TestXmultiPlainFormOverwriteNotes(t *testing.T) {
	for _, dry := range []bool{true, false} {
		tr := newTree()
		d := tr.dir("/w")
		putPool(d, "p", 80, "")
		delete(d.files, ref("p", ports.NodeSKey))
		dst := newMem()
		putPool(dst, "p", 81, "")
		rep, err := plainMulti(tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/w"}, ImportOptions: ImportOptions{Overwrite: true}, DryRun: dry})
		if err != nil || rep.Failed() != 0 || rep.Extended {
			t.Fatalf("dry=%v: %v %+v", dry, err, rep)
		}
		notes := map[ports.Kind]string{}
		for _, a := range ownerOf(rep, "p").Artefacts {
			notes[a.Ref.Kind] = a.Note
		}
		replaces := "replaces"
		if dry {
			replaces = "would replace"
		}
		if !strings.Contains(notes[ports.NodeVKey], replaces+" the workspace's existing") || !strings.Contains(notes[ports.NodeVKey], "cold key of the workspace pool") {
			t.Errorf("dry=%v: node vkey note %q", dry, notes[ports.NodeVKey])
		}
		if !strings.Contains(notes[ports.NodeCounter], "cold key of the workspace pool") {
			t.Errorf("dry=%v: counter note %q", dry, notes[ports.NodeCounter])
		}
	}
}
