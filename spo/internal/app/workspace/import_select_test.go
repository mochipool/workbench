package workspace

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// memDir is a memStore that is also a source directory with sub-folders.
type memDir struct {
	*memStore
	subs []string
}

func (d memDir) Subdirs(context.Context) ([]string, error) { return d.subs, nil }

type memTree struct {
	dirs   map[string]*memDir
	opened []string
}

func newTree() *memTree { return &memTree{dirs: map[string]*memDir{}} }

func (t *memTree) dir(path string) *memStore {
	if d, ok := t.dirs[path]; ok {
		return d.memStore
	}
	t.dirs[path] = &memDir{memStore: newMem()}
	return t.dirs[path].memStore
}

func (t *memTree) sub(parent, name string) *memStore {
	t.dir(parent)
	t.dirs[parent].subs = append(t.dirs[parent].subs, name)
	return t.dir(parent + "/" + name)
}

func (t *memTree) Open(dir string) (Source, error) {
	t.opened = append(t.opened, dir)
	d, ok := t.dirs[dir]
	if !ok {
		return nil, fmt.Errorf("no such folder %s", dir)
	}
	return d, nil
}

// plainMulti builds an importer for a plain-form run, which keeps its old
// outcomes and is not held to the invariant of the selective form.
func plainMulti(tr *memTree, dst *memStore) ImportWorkspace {
	return ImportWorkspace{Dest: dst, Deriver: edDeriver{}, Addresses: addrInspector{}, Open: tr.Open}
}

// recImporter is an importer that remembers what the oracle of the invariant
// needs to know about the run: the workspace as it was, and the renames asked.
type recImporter struct {
	ImportWorkspace
	st *invState
}

func (r recImporter) Import(c context.Context, req ImportRequest) (*Report, error) {
	r.st.pres = append(r.st.pres, r.st.dst.snapshot())
	for _, rn := range req.Renames {
		r.st.renames[rn.From.Name] = rn.To
	}
	return r.ImportWorkspace.Import(c, req)
}

// invStates holds, per workspace store of a test, what the oracle has seen of
// it: every importer a test builds over one store shares it.
var invStates = map[*memStore]*invState{}

// multi builds an importer for a selective-form test. At the end of the test
// the workspace the run left is held to SPO-Xmulti-INV-006 (assertINV006).
func multi(t *testing.T, tr *memTree, dst *memStore) recImporter {
	t.Helper()
	st := invStates[dst]
	if st == nil {
		st = &invState{dst: dst, renames: map[string]string{}}
		invStates[dst] = st
		t.Cleanup(func() { delete(invStates, dst); assertINV006(t, st) })
	}
	st.trs = append(st.trs, tr)
	return recImporter{ImportWorkspace{Dest: dst, Deriver: edDeriver{}, Addresses: addrInspector{}, Open: tr.Open}, st}
}

func putWallet(s *memStore, name string, seed byte) {
	kp := pair(seed, "StakeSigningKeyShelley_ed25519", "StakeVerificationKeyShelley_ed25519", "Stake")
	s.put(ref(name, ports.StakingSKey), kp.skey)
	s.put(ref(name, ports.StakingVKey), kp.vkey)
}

func putPool(s *memStore, name string, seed byte, descriptor string) {
	cl := cold(seed)
	s.put(ref(name, ports.NodeSKey), cl.skey)
	s.put(ref(name, ports.NodeVKey), cl.vkey)
	var vk [32]byte
	env, _ := pool.ParseEnvelope(cl.vkey)
	kb, _ := env.Key32()
	copy(vk[:], kb)
	s.put(ref(name, ports.NodeCounter), pool.IssueCounter{Next: 2, ColdVKey: vk}.Envelope())
	s.put(ref(name, ports.KesCounter), pool.FormatCounter(1))
	s.put(ref(name, ports.KesCounterNext), pool.FormatCounter(2))
	s.put(ports.NamedRef{Name: name, Kind: ports.KesSKey, Num: 1}, []byte(`{"type":"KesSigningKey_ed25519_kes_2^6","description":"KES Signing Key","cborHex":"5860`+strings.Repeat("ab", 96)+`"}`))
	s.put(ports.NamedRef{Name: name, Kind: ports.KesVKey, Num: 1}, pool.MarshalEnvelope(pool.Envelope{Type: "KesVerificationKey_ed25519_kes_2^6", Description: "KES Verification Key", CborHex: "5820" + strings.Repeat("cd", 32)}))
	s.put(ports.NamedRef{Name: name, Kind: ports.OpCert, Num: 1}, opcertOf(kb, bytes.Repeat([]byte{0xcd}, 32)))
	if descriptor != "" {
		s.put(ref(name, ports.PoolDescriptor), []byte(descriptor))
	}
}

// descJSON is a descriptor as upstream's jq writes it.
func descJSON(poolName, owner, rewards string, extra ...string) string {
	s := fmt.Sprintf("{\n  \"poolName\": %q,\n  \"poolOwner\": [\n    {\n      \"ownerName\": %q,\n      \"ownerWitness\": \"local\"\n    }\n  ],\n  \"poolRewards\": %q,\n  \"poolPledge\": \"100000000\"", poolName, owner, rewards)
	for _, e := range extra {
		s += ",\n  " + e
	}
	return s + "\n}\n"
}

func stored(dst *memStore, name string, k ports.Kind) string {
	return string(dst.files[ref(name, k)])
}

func ownerOf(rep *Report, name string) OwnerReport {
	for _, o := range rep.Owners {
		if o.Owner == name {
			return o
		}
	}
	return OwnerReport{}
}

func ctx() context.Context { return context.Background() }

// nestedTree is /w/pool (a pool) beside /w/wallets (its owner wallet).
func nestedTree() *memTree {
	t := newTree()
	putPool(t.dir("/w/pool"), "mypool", 80, descJSON("mypool", "../wallets/owner", "../wallets/owner", `"regProtectionKey": "k"`))
	putWallet(t.dir("/w/wallets"), "owner", 40)
	return t
}

// A pool in one folder whose descriptor names its wallet by a relative path
// in another folder arrives with the flat wallet name; only those two values
// change and each is reported.
//
// spec: SPO-Xmulti-IN-001, SPO-Xmulti-IN-003, SPO-Xmulti-OUT-005, SPO-Xmulti-OUT-009, SPO-Xmulti-INV-002
func TestXmultiNestedRelativeReferences(t *testing.T) {
	tr, dst := nestedTree(), newMem()
	rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/w/pool", "/w/wallets"}, All: true})
	if err != nil || rep.Failed() != 0 {
		t.Fatalf("err %v, report %+v", err, rep)
	}
	want := strings.ReplaceAll(string(tr.dirs["/w/pool"].files[ref("mypool", ports.PoolDescriptor)]), "../wallets/owner", "owner")
	if got := stored(dst, "mypool", ports.PoolDescriptor); got != want {
		t.Errorf("descriptor:\n%s\nwant:\n%s", got, want)
	}
	o := ownerOf(rep, "mypool")
	if len(o.Rewrites) != 2 || o.Rewrites[0].Field != "poolOwner[0].ownerName" || o.Rewrites[1].Field != "poolRewards" ||
		o.Rewrites[1].Old != "../wallets/owner" || o.Rewrites[1].New != "owner" {
		t.Errorf("rewrites: %+v", o.Rewrites)
	}
	if o.Dir != "/w/pool" || o.Kind != KindPool || ownerOf(rep, "owner").Kind != KindWallet {
		t.Errorf("kind and folder: %+v", o)
	}
}

// A descriptor that needs no change is stored byte for byte.
//
// spec: SPO-Xmulti-IN-003, SPO-Xmulti-INV-002
func TestXmultiPlainFlatFolderIsUnchanged(t *testing.T) {
	tr, dst := newTree(), newMem()
	d := descJSON("mypool", "owner", "owner")
	putPool(tr.dir("/flat"), "mypool", 80, d)
	putWallet(tr.dir("/flat"), "owner", 40)
	rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/flat"}})
	if err != nil || rep.Failed() != 0 || len(rep.Owners) != 2 {
		t.Fatalf("err %v, report %+v", err, rep)
	}
	if stored(dst, "mypool", ports.PoolDescriptor) != d {
		t.Error("descriptor changed")
	}
	if len(ownerOf(rep, "mypool").Rewrites) != 0 {
		t.Error("a rewrite was reported")
	}
}

// Only the selected owner is stored; the other is listed as found.
//
// spec: SPO-Xmulti-IN-003, SPO-Xmulti-PRE-001
func TestXmultiSelectsOnePoolOfTwo(t *testing.T) {
	tr, dst := newTree(), newMem()
	putPool(tr.dir("/d"), "a", 80, descJSON("a", "w", "w"))
	putPool(tr.dir("/d"), "b", 81, descJSON("b", "w", "w"))
	putWallet(tr.dir("/d"), "w", 40)
	rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, Only: []Selector{{Kind: KindPool, Name: "a"}, {Kind: KindWallet, Name: "w"}}})
	if err != nil || rep.Failed() != 0 {
		t.Fatalf("err %v, report %+v", err, rep)
	}
	for r := range dst.files {
		if r.Name == "b" {
			t.Fatalf("b was imported: %v", r)
		}
	}
	if len(rep.Found) != 1 || rep.Found[0].Name != "b" || len(rep.Owners) != 2 {
		t.Errorf("found %+v owners %+v", rep.Found, rep.Owners)
	}
	// the kind must match too
	if _, err := multi(t, tr, newMem()).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, Only: []Selector{{Kind: KindWallet, Name: "a"}}}); !errors.Is(err, ErrNoSuchOwner) {
		t.Errorf("wrong kind: %v", err)
	}
	if _, err := multi(t, tr, newMem()).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, Only: []Selector{{Name: "nope"}}}); !errors.Is(err, ErrNoSuchOwner) {
		t.Errorf("unknown: %v", err)
	}
}

// Several folders with no selection import nothing.
//
// spec: SPO-Xmulti-IN-003
func TestXmultiSeveralFoldersNeedASelection(t *testing.T) {
	tr, dst := nestedTree(), newMem()
	if _, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/w/pool", "/w/wallets"}}); !errors.Is(err, ErrNeedSelection) {
		t.Fatalf("err %v", err)
	}
	if _, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/w/pool"}, Depth: 1}); !errors.Is(err, ErrNeedSelection) {
		t.Fatalf("depth: %v", err)
	}
	if len(dst.files) != 0 {
		t.Error("something was stored")
	}
}

func twoWalletsOneName() *memTree {
	t := newTree()
	putWallet(t.dir("/a"), "w", 40)
	putWallet(t.dir("/b"), "w", 50)
	return t
}

// The same wallet name in two folders is refused before anything is written,
// naming both; a rename fixes it and both arrive.
//
// spec: SPO-Xmulti-OUT-002, SPO-Xmulti-IN-004, SPO-Xmulti-OUT-001, SPO-Xmulti-PRE-001
func TestXmultiCollisionRefusedThenRenamed(t *testing.T) {
	tr, dst := twoWalletsOneName(), newMem()
	rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/a", "/b"}, All: true})
	if !errors.Is(err, ErrNameCollision) || !strings.Contains(err.Error(), "/a") || !strings.Contains(err.Error(), "/b") {
		t.Fatalf("err %v", err)
	}
	if len(dst.files) != 0 || dst.updates != 0 {
		t.Error("something was written despite the collision")
	}
	if rep == nil || rep.Failed() != 2 || !strings.Contains(rep.Owners[0].Reason, "/b") {
		t.Errorf("report %+v", rep)
	}
	// the ambiguous selector is refused as well
	if _, err := multi(t, tr, newMem()).Import(ctx(), ImportRequest{Dirs: []string{"/a", "/b"}, Only: []Selector{{Name: "w"}}}); !errors.Is(err, ErrAmbiguous) {
		t.Errorf("ambiguous: %v", err)
	}
	rep, err = multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/a", "/b"},
		Only:    []Selector{{Name: "w", Dir: "/a"}, {Name: "w", Dir: "/b"}},
		Renames: []Rename{{From: Selector{Kind: KindWallet, Name: "w", Dir: "/b"}, To: "w2"}}})
	if err != nil || rep.Failed() != 0 {
		t.Fatalf("err %v report %+v", err, rep)
	}
	if stored(dst, "w", ports.StakingVKey) == "" || stored(dst, "w2", ports.StakingVKey) == "" || stored(dst, "w2", ports.StakingVKey) == stored(dst, "w", ports.StakingVKey) {
		t.Error("the two wallets are not both there under their names")
	}
	// an existing workspace owner is refused as before, without --overwrite
	rep, err = multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/a"}})
	if err != nil || rep.Failed() != 1 || !strings.Contains(rep.Owners[0].Reason, "already holds") {
		t.Errorf("existing: %v %+v", err, rep)
	}
}

// Invalid renames are refused before anything is written.
//
// spec: SPO-Xmulti-PRE-002
func TestXmultiBadRenames(t *testing.T) {
	tr := nestedTree()
	for name, req := range map[string]ImportRequest{
		"unselected": {Dirs: []string{"/w/pool", "/w/wallets"}, Only: []Selector{{Name: "owner"}}, Renames: []Rename{{From: Selector{Name: "mypool"}, To: "x"}}},
		"twice":      {Dirs: []string{"/w/pool", "/w/wallets"}, All: true, Renames: []Rename{{From: Selector{Name: "owner"}, To: "x"}, {From: Selector{Name: "owner"}, To: "y"}}},
		"invalid":    {Dirs: []string{"/w/pool", "/w/wallets"}, All: true, Renames: []Rename{{From: Selector{Name: "owner"}, To: "../x"}}},
	} {
		dst := newMem()
		if _, err := multi(t, tr, dst).Import(ctx(), req); !errors.Is(err, ErrBadRename) || len(dst.files) != 0 {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A reference to an owner that was found but is not selected refuses the pool
// and names the owner to add.
//
// spec: SPO-Xmulti-PRE-004
func TestXmultiReferenceToUnselectedOwner(t *testing.T) {
	tr, dst := nestedTree(), newMem()
	rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/w/pool", "/w/wallets"}, Only: []Selector{{Kind: KindPool, Name: "mypool"}}})
	if err != nil || rep.Failed() != 1 {
		t.Fatalf("err %v report %+v", err, rep)
	}
	o := ownerOf(rep, "mypool")
	if o.Written || !strings.Contains(artefactReason(o, ports.PoolDescriptor), "--only wallet:owner@/w/wallets") {
		t.Errorf("owner %+v", o)
	}
	if len(dst.files) != 0 {
		t.Error("the pool was stored")
	}
	// ...but a wallet of that name already in the workspace is accepted
	putWallet(dst, "owner", 40)
	rep, err = multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/w/pool", "/w/wallets"}, Only: []Selector{{Kind: KindPool, Name: "mypool"}}})
	if err != nil || rep.Failed() != 0 {
		t.Fatalf("err %v report %+v", err, rep)
	}
}

func artefactReason(o OwnerReport, k ports.Kind) string {
	for _, a := range o.Artefacts {
		if a.Ref.Kind == k {
			return a.Reason
		}
	}
	return ""
}

// A reference that resolves to nothing found refuses the pool; one that
// resolves to a wallet the workspace holds is accepted and flattened.
//
// spec: SPO-Xmulti-PRE-005, SPO-Xmulti-OUT-005
func TestXmultiReferenceToNothingOrToWorkspace(t *testing.T) {
	tr, dst := newTree(), newMem()
	putPool(tr.dir("/w/pool"), "mypool", 80, descJSON("mypool", "../wallets/owner", "../wallets/owner"))
	tr.dir("/w/wallets")
	rep, _ := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/w/pool", "/w/wallets"}, All: true})
	if rep.Failed() != 1 || !strings.Contains(artefactReason(ownerOf(rep, "mypool"), ports.PoolDescriptor), "no pool or wallet was found") {
		t.Fatalf("report %+v", rep)
	}
	putWallet(dst, "owner", 40)
	rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/w/pool", "/w/wallets"}, All: true})
	if err != nil || rep.Failed() != 0 {
		t.Fatalf("err %v report %+v", err, rep)
	}
	if !strings.Contains(stored(dst, "mypool", ports.PoolDescriptor), `"ownerName": "owner"`) {
		t.Error("not flattened to the workspace wallet")
	}
}

// Paths that are absolute or leave every source root are refused, not
// followed; a backslash is a separator.
//
// spec: SPO-Xmulti-PRE-006, SPO-Xmulti-SEC-003
func TestXmultiAbsoluteAndEscapingReferences(t *testing.T) {
	for name, tc := range map[string]struct {
		ref, why string
	}{
		"absolute":  {"/w/wallets/owner", "absolute path"},
		"drive":     {`C:\wallets\owner`, "absolute path"},
		"escape":    {"../../etc/owner", "leaves the folders"},
		"sibling":   {"../other/owner", "leaves the folders"},
		"dotdot":    {"..", "not a name"},
		"backslash": {`..\..\x\owner`, "leaves the folders"},
	} {
		tr, dst := newTree(), newMem()
		putPool(tr.dir("/w/pool"), "mypool", 80, descJSON("mypool", tc.ref, tc.ref))
		rep, _ := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/w/pool"}, All: true})
		if rep.Failed() != 1 || !strings.Contains(artefactReason(ownerOf(rep, "mypool"), ports.PoolDescriptor), tc.why) || len(dst.files) != 0 {
			t.Errorf("%s: %+v", name, rep.Owners)
		}
	}
	// the Windows spelling of a legitimate sibling resolves
	tr, dst := newTree(), newMem()
	putPool(tr.dir("/w/pool"), "mypool", 80, descJSON("mypool", `..\wallets\owner`, `.\..\wallets\.\owner`))
	putWallet(tr.dir("/w/wallets"), "owner", 40)
	rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/w/pool", "/w/wallets"}, All: true})
	if err != nil || rep.Failed() != 0 || !strings.Contains(stored(dst, "mypool", ports.PoolDescriptor), `"poolRewards": "owner"`) {
		t.Fatalf("err %v report %+v", err, rep)
	}
}

// Several spellings of one owner, and several pools naming one wallet, give
// one imported owner.
//
// spec: SPO-Xmulti-PRE-007
func TestXmultiOneOwnerManySpellingsAndPools(t *testing.T) {
	tr, dst := newTree(), newMem()
	putPool(tr.dir("/w/p1"), "pa", 80, descJSON("pa", "./../wallets/owner", "../p1/../wallets/owner"))
	putPool(tr.dir("/w/p2/deep"), "pb", 81, descJSON("pb", "../../wallets/owner", "../../wallets/./owner"))
	putWallet(tr.dir("/w/wallets"), "owner", 40)
	rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/w/p1", "/w/p2/deep", "/w/wallets"}, All: true})
	if err != nil || rep.Failed() != 0 {
		t.Fatalf("err %v report %+v", err, rep)
	}
	for _, p := range []string{"pa", "pb"} {
		d := stored(dst, p, ports.PoolDescriptor)
		if strings.Contains(d, "..") || strings.Count(d, `"owner"`) != 2 {
			t.Errorf("%s:\n%s", p, d)
		}
	}
	n := 0
	for _, o := range rep.Owners {
		if o.Owner == "owner" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("owner imported %d times", n)
	}
}

// A rename of a wallet reaches every selected pool that names it; a rename of
// a pool updates poolName and the certificate fields, and every artefact of
// the pool arrives under the new name.
//
// spec: SPO-Xmulti-IN-004, SPO-Xmulti-OUT-004, SPO-Xmulti-OUT-005, SPO-Xmulti-OUT-006
func TestXmultiRenames(t *testing.T) {
	tr, dst := newTree(), newMem()
	cert := `"regCertFile": "../pool/mypool.pool.cert"`
	putPool(tr.dir("/w/pool"), "mypool", 80, descJSON("pool/mypool", "../wallets/owner", "../wallets/owner", cert, `"deregCertFile": "mypool.pool.dereg-cert"`))
	tr.dir("/w/pool").put(ref("mypool", ports.PoolCert), []byte(`{"type":"CertificateShelley","description":"","cborHex":"00"}`))
	tr.dir("/w/pool").put(ref("mypool", ports.PoolDeregCert), []byte(`{"type":"CertificateShelley","description":"","cborHex":"01"}`))
	putPool(tr.dir("/w/pool"), "other", 81, descJSON("other", "../wallets/owner", "../wallets/owner"))
	putWallet(tr.dir("/w/wallets"), "owner", 40)
	rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/w/pool", "/w/wallets"}, All: true,
		Renames: []Rename{{From: Selector{Kind: KindWallet, Name: "owner"}, To: "boss"}, {From: Selector{Kind: KindPool, Name: "mypool"}, To: "newpool"}}})
	if err != nil || rep.Failed() != 0 {
		t.Fatalf("err %v report %+v", err, rep)
	}
	for _, p := range []string{"newpool", "other"} {
		d := stored(dst, p, ports.PoolDescriptor)
		if strings.Contains(d, `"owner"`) || strings.Count(d, `"boss"`) != 2 {
			t.Errorf("%s:\n%s", p, d)
		}
	}
	d := stored(dst, "newpool", ports.PoolDescriptor)
	for _, w := range []string{`"poolName": "newpool"`, `"regCertFile": "newpool.pool.cert"`, `"deregCertFile": "newpool.pool.dereg-cert"`} {
		if !strings.Contains(d, w) {
			t.Errorf("missing %s in\n%s", w, d)
		}
	}
	// every artefact of the renamed pool, numbered ones and counters included
	for _, r := range []ports.NamedRef{ref("newpool", ports.NodeVKey), ref("newpool", ports.NodeSKey), ref("newpool", ports.NodeCounter),
		ref("newpool", ports.KesCounter), ref("newpool", ports.KesCounterNext), ref("newpool", ports.PoolCert), ref("newpool", ports.PoolDeregCert),
		{Name: "newpool", Kind: ports.KesSKey, Num: 1}, {Name: "newpool", Kind: ports.KesVKey, Num: 1}, {Name: "newpool", Kind: ports.OpCert, Num: 1}} {
		if _, ok := dst.files[r]; !ok {
			t.Errorf("%v missing", r)
		}
	}
	for r := range dst.files {
		if r.Name == "mypool" || r.Name == "owner" {
			t.Errorf("old name stored: %v", r)
		}
	}
	if string(dst.files[ref("newpool", ports.KesCounter)]) != string(pool.FormatCounter(1)) {
		t.Error("KES counter content changed")
	}
	if ownerOf(rep, "mypool").Final != "newpool" {
		t.Error("final name not reported")
	}
}

func descWith(t *testing.T, poolName string, extra ...string) (*Report, *memStore, error) {
	t.Helper()
	tr, dst := newTree(), newMem()
	putPool(tr.dir("/d"), "p", 80, descJSON(poolName, "w", "w", extra...))
	tr.dir("/d").put(ref("p", ports.PoolCert), []byte(`{}`))
	putWallet(tr.dir("/d"), "w", 40)
	rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true})
	return rep, dst, err
}

// A poolName with a path prefix, or another name, is stored as the pool's
// name and reported.
//
// spec: SPO-Xmulti-OUT-004
func TestXmultiPoolNameRewritten(t *testing.T) {
	for _, n := range []string{"pool/p", "../pool/p", "something-else"} {
		rep, dst, err := descWith(t, n)
		if err != nil || rep.Failed() != 0 {
			t.Fatalf("%s: %v %+v", n, err, rep)
		}
		if !strings.Contains(stored(dst, "p", ports.PoolDescriptor), `"poolName": "p"`) {
			t.Errorf("%s: %s", n, stored(dst, "p", ports.PoolDescriptor))
		}
		rw := ownerOf(rep, "p").Rewrites
		if len(rw) != 1 || rw[0].Field != "poolName" || rw[0].Old != n || rw[0].New != "p" {
			t.Errorf("%s: %+v", n, rw)
		}
	}
}

// regCertFile that names another certificate refuses the pool; one with a
// folder or one that is missing from the source is handled and said.
//
// spec: SPO-Xmulti-OUT-003, SPO-Xmulti-OUT-006
func TestXmultiCertificateFields(t *testing.T) {
	rep, _, _ := descWith(t, "p", `"regCertFile": "other.pool.cert"`)
	if rep.Failed() != 1 || !strings.Contains(artefactReason(ownerOf(rep, "p"), ports.PoolDescriptor), `regCertFile "other.pool.cert"`) {
		t.Errorf("%+v", rep.Owners)
	}
	rep, dst, err := descWith(t, "p", `"regCertFile": "certs\\p.pool.cert"`)
	if err != nil || rep.Failed() != 0 || !strings.Contains(stored(dst, "p", ports.PoolDescriptor), `"regCertFile": "p.pool.cert"`) {
		t.Errorf("backslash folder: %v %+v", err, rep)
	}
	// a deregCertFile whose file is not in the source: stored, with a note
	rep, dst, err = descWith(t, "p", `"deregCertFile": "p.pool.dereg-cert"`)
	if err != nil || rep.Failed() != 0 {
		t.Fatalf("%v %+v", err, rep)
	}
	note := ""
	for _, a := range ownerOf(rep, "p").Artefacts {
		if a.Ref.Kind == ports.PoolDescriptor {
			note = a.Note
		}
	}
	if !strings.Contains(note, "deregCertFile names a certificate that is not in the source") {
		t.Errorf("note %q", note)
	}
	if _, ok := dst.files[ref("p", ports.PoolDeregCert)]; ok {
		t.Error("a certificate that was not there appeared")
	}
}

// An open multi-witness registration is carried only when no name changes.
//
// spec: SPO-Xmulti-OUT-007
func TestXmultiOpenRegistration(t *testing.T) {
	reg := `"regWitness": {"id": "x", "regPayName": "w", "witnesses": {"p.node": {"witness": {}}, "w.staking": {"witness": {}}}}`
	rep, dst, err := descWith(t, "p", reg)
	if err != nil || rep.Failed() != 0 || !strings.Contains(stored(dst, "p", ports.PoolDescriptor), `"regPayName": "w"`) {
		t.Fatalf("carried: %v %+v", err, rep)
	}
	// a pool name that has to change refuses it
	rep, _, _ = descWith(t, "pool/p", reg)
	if rep.Failed() != 1 || !strings.Contains(artefactReason(ownerOf(rep, "p"), ports.PoolDescriptor), "regWitness") {
		t.Errorf("poolName: %+v", rep.Owners)
	}
	// so does a rename of the wallet it names
	tr, dst2 := newTree(), newMem()
	putPool(tr.dir("/d"), "p", 80, descJSON("p", "w", "w", reg))
	putWallet(tr.dir("/d"), "w", 40)
	rep, _ = multi(t, tr, dst2).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, Renames: []Rename{{From: Selector{Name: "w"}, To: "w9"}}, All: true})
	if rep.Failed() != 1 || ownerOf(rep, "p").Written || len(dst2.files) == 0 {
		// the wallet still arrives; the pool does not
		t.Errorf("rename: %+v", rep.Owners)
	}
	// and so does a rename of the pool
	rep, _ = multi(t, tr, newMem()).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true, Renames: []Rename{{From: Selector{Name: "p"}, To: "q"}}})
	if ownerOf(rep, "q").Written || ownerOf(rep, "p").Written {
		t.Error("renamed pool with an open registration was written")
	}
}

// Legacy string poolOwner, a duplicated field and a path-like unknown field.
//
// spec: SPO-Xmulti-OUT-005, SPO-Xmulti-OUT-008
func TestXmultiLegacyOwnerAndOddFields(t *testing.T) {
	tr, dst := newTree(), newMem()
	d := "{\"poolName\":\"p\",\"poolOwner\":\"../wallets/w\",\"poolRewards\":\"../wallets/w\",\"notes\":\"see ../x\",\"poolMetaUrl\":\"https://a/b\"}"
	putPool(tr.dir("/w/p"), "p", 80, d)
	putWallet(tr.dir("/w/wallets"), "w", 40)
	rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/w/p", "/w/wallets"}, All: true})
	if err != nil || rep.Failed() != 0 {
		t.Fatalf("%v %+v", err, rep)
	}
	want := "{\"poolName\":\"p\",\"poolOwner\":\"w\",\"poolRewards\":\"w\",\"notes\":\"see ../x\",\"poolMetaUrl\":\"https://a/b\"}"
	if got := stored(dst, "p", ports.PoolDescriptor); got != want {
		t.Errorf("got %s", got)
	}
	note := ""
	for _, a := range ownerOf(rep, "p").Artefacts {
		note += a.Note
	}
	if !strings.Contains(note, "notes holds a path-like value") || strings.Contains(note, "poolMetaUrl") {
		t.Errorf("note %q", note)
	}
	// a duplicated field is refused
	tr2 := newTree()
	putPool(tr2.dir("/d"), "p", 80, `{"poolName":"p","poolName":"q"}`)
	rep, _ = multi(t, tr2, newMem()).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true})
	if rep.Failed() != 1 {
		t.Errorf("duplicate field: %+v", rep.Owners)
	}
}

// Discovery reaches sub-folders only to the depth given, refuses a depth above
// the maximum, and stops at the bounds.
//
// spec: SPO-Xmulti-IN-001, SPO-Xmulti-IN-002, SPO-Xmulti-SEC-002
func TestXmultiDepthAndBounds(t *testing.T) {
	tr := newTree()
	putWallet(tr.dir("/r"), "top", 40)
	putWallet(tr.sub("/r", "a"), "mid", 41)
	putWallet(tr.sub("/r/a", "b"), "low", 42)
	for depth, want := range map[int][]string{0: {"top"}, 1: {"top", "mid"}, 2: {"top", "mid", "low"}} {
		rep, err := multi(t, tr, newMem()).Import(ctx(), ImportRequest{Dirs: []string{"/r"}, Depth: depth, All: true, DryRun: true})
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, o := range rep.Owners {
			got = append(got, o.Owner)
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("depth %d: %v want %v", depth, got, want)
		}
	}
	if _, err := multi(t, tr, newMem()).Import(ctx(), ImportRequest{Dirs: []string{"/r"}, Depth: MaxDepth + 1, All: true}); !errors.Is(err, ErrTooDeep) {
		t.Errorf("depth: %v", err)
	}
	// a folder reached twice is read once
	tr.opened = nil
	if _, err := multi(t, tr, newMem()).Import(ctx(), ImportRequest{Dirs: []string{"/r", "/r/a"}, Depth: 1, All: true, DryRun: true}); err != nil {
		t.Fatal(err)
	}
	// too many directories
	big := newTree()
	for i := 0; i < MaxDirs+5; i++ {
		big.sub("/r", fmt.Sprintf("d%d", i))
	}
	if _, err := multi(t, big, newMem()).Import(ctx(), ImportRequest{Dirs: []string{"/r"}, Depth: 1, All: true}); !errors.Is(err, ErrTooMany) {
		t.Errorf("dirs: %v", err)
	}
	// too many files, refused before any is read
	files := newTree()
	for i := 0; i < MaxFiles+1; i++ {
		files.dir("/r").put(ref(fmt.Sprintf("w%d", i), ports.AddrVKey), []byte("x"))
	}
	if _, err := multi(t, files, newMem()).Import(ctx(), ImportRequest{Dirs: []string{"/r"}, All: true}); !errors.Is(err, ErrTooMany) {
		t.Errorf("files: %v", err)
	}
	if _, err := multi(t, tr, newMem()).Import(ctx(), ImportRequest{Dirs: []string{"r"}, All: true}); !errors.Is(err, ErrRelativeSource) {
		t.Errorf("relative: %v", err)
	}
	if _, err := multi(t, tr, newMem()).Import(ctx(), ImportRequest{Dirs: []string{"/r", "/r/"}, All: true}); !errors.Is(err, ErrDuplicateSource) {
		t.Errorf("duplicate: %v", err)
	}
}

// A dry run reads and checks, writes nothing, changes no source, and says
// what would happen and what would be refused.
//
// spec: SPO-Xmulti-OUT-010, SPO-Xmulti-IN-001, SPO-Xmulti-INV-001, SPO-Xmulti-OUT-009
func TestXmultiDryRun(t *testing.T) {
	tr, dst := nestedTree(), newMem()
	before := tr.dirs["/w/pool"].snapshot()
	rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/w/pool", "/w/wallets"}, All: true, DryRun: true})
	if err != nil || rep.Failed() != 0 || !rep.DryRun {
		t.Fatalf("%v %+v", err, rep)
	}
	if len(dst.files) != 0 || dst.updates != 0 {
		t.Error("the dry run wrote")
	}
	o := ownerOf(rep, "mypool")
	if !o.Would || o.Written || len(o.Rewrites) != 2 || o.Artefacts[0].Status != StatusPlanned {
		t.Errorf("owner %+v", o)
	}
	for r, v := range before {
		if tr.dirs["/w/pool"].snapshot()[r] != v {
			t.Error("source changed")
		}
	}
	if rep.Done() == 0 {
		t.Error("planned artefacts are not counted")
	}
	// a refusal shows in the dry run and makes it fail
	rep, _ = multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/w/pool", "/w/wallets"}, Only: []Selector{{Name: "mypool"}}, DryRun: true})
	if rep.Failed() != 1 || len(dst.files) != 0 {
		t.Errorf("%+v", rep.Owners)
	}
	// an existing owner shows as not importable
	putWallet(dst, "owner", 40)
	rep, _ = multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/w/wallets"}, DryRun: true})
	if rep.Failed() != 1 || !strings.Contains(rep.Owners[0].Reason, "already holds") {
		t.Errorf("existing: %+v", rep.Owners)
	}
}

// Keys and counters of a pool survive a rename together with the checks: a
// counter that belongs to another cold key still refuses the pool.
//
// spec: SPO-Xmulti-IN-004, SPO-Xmulti-OUT-001
func TestXmultiChecksStillRunOnRenamedOwner(t *testing.T) {
	tr, dst := newTree(), newMem()
	putPool(tr.dir("/d"), "p", 80, descJSON("p", "w", "w"))
	tr.dir("/d").put(ref("p", ports.NodeVKey), cold(99).vkey)
	rep, _ := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, Renames: []Rename{{From: Selector{Name: "p"}, To: "q"}}, All: true})
	if rep.Failed() != 1 || len(dst.files) != 0 {
		t.Errorf("%+v", rep.Owners)
	}
}

// putPayer gives a wallet a payment key pair under a stem (`w.payment` for the
// payment account of a wallet with a stake key, `e` for a key-only address).
func putPayer(s *memStore, stem string, seed byte) {
	kp := pair(seed, "PaymentSigningKeyShelley_ed25519", "PaymentVerificationKeyShelley_ed25519", "Payment")
	s.put(ref(stem, ports.AddrSKey), kp.skey)
	s.put(ref(stem, ports.AddrVKey), kp.vkey)
}

// An open registration whose payer is the payment account of a wallet
// (`<wallet>.payment`) or an enterprise wallet with no stake key is imported by a
// selective run: the payer is a payment key identity, not a wallet with a stake
// key, so the binding is made on the payment verification key (ADR 0010 decision
// 4; closes the known limit of the first multi-folder import).
//
// spec: SPO-Xmulti-INV-007, SPO-Xmulti-PRE-011
func TestXmultiOpenRegistrationPaidFromAPaymentAccountOrAnEnterpriseWallet(t *testing.T) {
	for _, tc := range []struct{ name, payer, wallet string }{
		{"payment account of a wallet", "w.payment", "w"},
		{"enterprise wallet", "e", "e"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg := `"regWitness": {"id": "x", "regPayName": "` + tc.payer + `", "witnesses": {"p.node": {"witness": {}}, "w.staking": {"witness": {}}, "` + tc.payer + `": {"witness": {}}}}`
			tr, dst := newTree(), newMem()
			putPool(tr.dir("/d"), "p", 80, descJSON("p", "w", "w", reg))
			putWallet(tr.dir("/d"), "w", 40)
			if tc.wallet == "w" {
				putPayer(tr.dir("/d"), "w.payment", 41)
			} else {
				putPayer(tr.dir("/d"), "e", 42)
			}
			sel := []Selector{{Kind: KindPool, Name: "p"}, {Kind: KindWallet, Name: "w"}}
			if tc.wallet == "e" {
				sel = append(sel, Selector{Kind: KindWallet, Name: "e"})
			}
			rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, Only: sel})
			if err != nil || rep.Failed() != 0 || !ownerOf(rep, "p").Written {
				t.Fatalf("a selective import of a pool paid from %s: %v %+v\n%s", tc.payer, err, rep.Owners, reasons(ownerOf(rep, "p")))
			}
			if !strings.Contains(stored(dst, "p", ports.PoolDescriptor), `"regPayName": "`+tc.payer+`"`) {
				t.Errorf("the registration was not carried:\n%s", stored(dst, "p", ports.PoolDescriptor))
			}
			// a payer wallet that this run does not select and the workspace does not
			// hold is not found: the pool is refused
			rep, _ = multi(t, tr, newMem()).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, Only: []Selector{{Kind: KindPool, Name: "p"}, {Kind: KindWallet, Name: "w"}}})
			if tc.wallet == "e" && ownerOf(rep, "p").Written {
				t.Errorf("a pool paid from the unselected wallet %q was written", tc.payer)
			}
		})
	}
}

func reasons(o OwnerReport) string {
	var out []string
	for _, a := range o.Artefacts {
		if a.Status == StatusFailed || (a.Reason != "" && !strings.Contains(a.Reason, "another artefact failed")) {
			out = append(out, a.Ref.String()+": "+a.Reason+" "+a.Note)
		}
	}
	return o.Reason + "; " + strings.Join(out, "; ")
}

// The resolver's conditions by identity: the pool id a descriptor records is the
// hash of the cold key the pool will have; a witness slot's recorded key hash is
// that of the wallet's stake key; two owner names that resolve to one stake key
// are refused, showing both.
//
// spec: SPO-Xmulti-INV-007, SPO-Xidentity-INV-019
func TestXmultiResolutionByIdentity(t *testing.T) {
	cl := cold(80)
	env, _ := pool.ParseEnvelope(cl.vkey)
	kb, _ := env.Key32()
	coldHash := txbuild.HashKey(kb)
	stakeKey := rawOf(pair(40, "StakeSigningKeyShelley_ed25519", "StakeVerificationKeyShelley_ed25519", "Stake").vkey)
	stakeHash := txbuild.HashKey(stakeKey)
	run := func(desc string, wallets ...string) (*Report, error) {
		tr := newTree()
		putPool(tr.dir("/d"), "p", 80, desc)
		for _, w := range wallets {
			putWallet(tr.dir("/d"), w, 40)
		}
		return multi(t, tr, newMem()).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true})
	}
	good := hex.EncodeToString(coldHash[:])
	if rep, err := run(descJSON("p", "w", "w", `"poolID": "`+good+`"`), "w"); err != nil || rep.Failed() != 0 {
		t.Fatalf("a descriptor that agrees with its keys: %v %+v", err, rep)
	}
	rep, _ := run(descJSON("p", "w", "w", `"poolID": "`+strings.Repeat("00", 28)+`"`), "w")
	if !strings.Contains(ownerOf(rep, "p").Reason, "poolID") || ownerOf(rep, "p").Written {
		t.Errorf("a pool id that is not the cold key's: %+v", ownerOf(rep, "p"))
	}
	reg := func(kh string) string {
		return `"regWitness": {"id": "x", "regPayName": "w", "witnesses": {"p.node": {"witness": {}}, "w.staking": {"witness": {}, "keyHash": "` + kh + `"}}}`
	}
	if rep, err := run(descJSON("p", "w", "w", reg(hex.EncodeToString(stakeHash[:]))), "w"); err != nil || rep.Failed() != 0 {
		t.Fatalf("a witness slot that records the wallet's key hash: %v %+v", err, rep)
	}
	rep, _ = run(descJSON("p", "w", "w", reg(strings.Repeat("11", 28))), "w")
	if !strings.Contains(ownerOf(rep, "p").Reason, "key hash") || ownerOf(rep, "p").Written {
		t.Errorf("a slot that records another key hash: %+v", ownerOf(rep, "p"))
	}
	two := "{\n  \"poolName\": \"p\",\n  \"poolOwner\": [{\"ownerName\": \"w\", \"ownerWitness\": \"local\"}, {\"ownerName\": \"w2\", \"ownerWitness\": \"local\"}],\n  \"poolRewards\": \"w\",\n  \"poolPledge\": \"100000000\"\n}\n"
	rep, _ = run(two, "w", "w2")
	if r := ownerOf(rep, "p").Reason; !strings.Contains(r, `"w" and "w2"`) || ownerOf(rep, "p").Written {
		t.Errorf("two names for one key: %+v", ownerOf(rep, "p"))
	}
}

// A payer's witness slot records the hash of the payment key of the wallet it
// names, and the pool's own slot the hash of its cold key; another hash refuses
// the pool, naming the slot.
//
// spec: SPO-Xmulti-INV-007
func TestXmultiPayerAndNodeSlotsRecordTheirKeyHashes(t *testing.T) {
	cl := cold(80)
	env, _ := pool.ParseEnvelope(cl.vkey)
	kb, _ := env.Key32()
	coldHash := txbuild.HashKey(kb)
	payKey := rawOf(pair(41, "PaymentSigningKeyShelley_ed25519", "PaymentVerificationKeyShelley_ed25519", "Payment").vkey)
	payHash := txbuild.HashKey(payKey)
	run := func(nodeHash, payerHash string) *Report {
		reg := `"regWitness": {"id": "x", "regPayName": "w.payment", "witnesses": {"p.node": {"witness": {}, "keyHash": "` + nodeHash + `"}, "w.payment": {"witness": {}, "keyHash": "` + payerHash + `"}}}`
		tr := newTree()
		putPool(tr.dir("/d"), "p", 80, descJSON("p", "w", "w", reg))
		putWallet(tr.dir("/d"), "w", 40)
		putPayer(tr.dir("/d"), "w.payment", 41)
		rep, _ := multi(t, tr, newMem()).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true})
		return rep
	}
	if rep := run(hex.EncodeToString(coldHash[:]), hex.EncodeToString(payHash[:])); !ownerOf(rep, "p").Written {
		t.Fatalf("slots that agree with their keys: %+v", ownerOf(rep, "p"))
	}
	rep := run(strings.Repeat("11", 28), hex.EncodeToString(payHash[:]))
	if r := ownerOf(rep, "p"); r.Written || !strings.Contains(r.Reason, "cold key") {
		t.Errorf("a node slot with another hash: %+v", r)
	}
	rep = run(hex.EncodeToString(coldHash[:]), strings.Repeat("22", 28))
	if r := ownerOf(rep, "p"); r.Written || !strings.Contains(r.Reason, "payment key") {
		t.Errorf("a payer slot with another hash: %+v", r)
	}
}
