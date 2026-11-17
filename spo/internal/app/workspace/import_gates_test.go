package workspace

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/ports"
)

func whyOf(o OwnerReport) string { return o.Reason + " " + artefactReasons(o) }

func noteOf(o OwnerReport) string {
	var s []string
	for _, a := range o.Artefacts {
		s = append(s, a.Note)
	}
	return strings.Join(s, "; ")
}

func unchanged(t *testing.T, what string, before map[ports.Ref]string, dst *memStore) {
	t.Helper()
	if !sameFiles(before, snapshotOf(dst)) {
		t.Errorf("%s: the workspace changed", what)
	}
}

// A source wallet that holds only payment keys is never merged into an
// unrelated workspace wallet of the same name that holds stake keys, with or
// without --overwrite; the pool that names it is refused.
//
// spec: SPO-Xmulti-OUT-016, SPO-Xmulti-INV-006
func TestXmultiGateADisjointMergeIsRefused(t *testing.T) {
	for _, ow := range []bool{false, true} {
		tr, dst := newTree(), newMem()
		putPayment(tr.dir("/d"), "x", 1)
		putPool(tr.dir("/d"), "p", 80, descJSON("p", "x", "x"))
		putWallet(dst, "x", 11)
		before := snapshotOf(dst)
		rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true, ImportOptions: ImportOptions{Overwrite: ow}})
		if err != nil {
			t.Fatal(err)
		}
		if o := ownerOf(rep, "x"); o.Written || !strings.Contains(o.Reason, "not provably one owner") || !strings.Contains(o.Reason, "x/staking.vkey") {
			t.Errorf("overwrite=%v: x: %+v", ow, o)
		}
		if o := ownerOf(rep, "p"); o.Written || stored(dst, "p", ports.PoolDescriptor) != "" {
			t.Errorf("overwrite=%v: p: %+v", ow, o)
		}
		if _, ok := dst.files[ports.Ref{Name: "x.payment", Kind: ports.AddrVKey}]; ok {
			t.Errorf("overwrite=%v: the payment key was merged into the stake wallet", ow)
		}
		_ = before
	}
}

// Role keys merge by the same rule: a half of a pair from the import never joins
// the other half the workspace holds unless it is shown to be its pair.
//
// spec: SPO-Xmulti-OUT-016, SPO-Xmulti-INV-006
func TestXmultiGateARoleKeyHalvesMustBePairs(t *testing.T) {
	for sk, role := range ports.SigningKeyKinds() {
		switch sk {
		case ports.DRepSKey, ports.PolicySKey, ports.VotingSKey, ports.CCColdSKey, ports.CCHotSKey, ports.CalidusSKey:
		default:
			continue
		}
		skT, vkT := "SigningKey_ed25519", "VerificationKey_ed25519"
		a := pair(21, skT, vkT, "A")
		b := pair(22, skT, vkT, "B")
		for _, matching := range []bool{false, true} {
			tr, dst := newTree(), newMem()
			putWallet(dst, "x", 11)
			dst.put(ports.Ref{Name: "x", Kind: role.VKey}, a.vkey)
			src := b
			if matching {
				src = a
			}
			tr.dir("/d").put(ports.Ref{Name: "x", Kind: sk}, src.skey)
			before := snapshotOf(dst)
			rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true})
			if err != nil {
				t.Fatal(err)
			}
			o := ownerOf(rep, "x")
			switch {
			case matching && (!o.Written || !strings.Contains(noteOf(o), "merged into the existing workspace owner")):
				t.Errorf("%s: the matching half was not merged with a note: %+v", sk, o)
			case !matching && o.Written:
				t.Errorf("%s: a half of another pair was merged", sk)
			case !matching:
				unchanged(t, string(sk), before, dst)
			}
		}
	}
}

// Another cold key's KES key and operational certificate, with or without
// --overwrite, never join a workspace pool.
//
// spec: SPO-Xmulti-OUT-016, SPO-Xmulti-INV-006
func TestXmultiGateAKesOnlyOverPoolOfAnotherColdKey(t *testing.T) {
	for _, ow := range []bool{false, true} {
		tr, dst := newTree(), newMem()
		putPool(dst, "x", 90, "")
		tmp := newMem()
		putPool(tmp, "x", 91, "")
		for r, b := range tmp.files {
			if r.Kind == ports.OpCert || r.Kind == ports.KesVKey || r.Kind == ports.KesSKey {
				if r.Num != 0 {
					r.Num = 2
				}
				tr.dir("/d").put(r, b)
			}
		}
		before := snapshotOf(dst)
		rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true, ImportOptions: ImportOptions{Overwrite: ow}})
		if err != nil {
			t.Fatal(err)
		}
		if o := ownerOf(rep, "x"); o.Written || !strings.Contains(o.Reason, "node.opcert#2") || !strings.Contains(o.Reason, "another cold key") {
			t.Errorf("overwrite=%v: %+v", ow, o)
		}
		unchanged(t, "kes only", before, dst)
	}
}

func kesSource(t *testing.T, tr *memTree, cold byte, opcertKes byte) {
	t.Helper()
	d := tr.dir("/d")
	d.put(ports.Ref{Name: "p", Kind: ports.KesSKey, Num: 2}, []byte(`{"type":"KesSigningKey_ed25519_kes_2^6","description":"KES Signing Key","cborHex":"5860`+strings.Repeat("ee", 96)+`"}`))
	d.put(ports.Ref{Name: "p", Kind: ports.KesVKey, Num: 2}, []byte(`{"type":"KesVerificationKey_ed25519_kes_2^6","description":"KES Verification Key","cborHex":"5820`+strings.Repeat("ef", 32)+`"}`))
	d.put(ports.Ref{Name: "p", Kind: ports.OpCert, Num: 2}, opcertOf(rawOf(cold32(cold)), bytes.Repeat([]byte{opcertKes}, 32)))
}

func cold32(seed byte) []byte { return cold(seed).vkey }

// The hot key of an operational certificate must be the KES key of its number,
// and the KES counter must not be behind the numbered keys.
//
// spec: SPO-Xmulti-OUT-016
func TestXmultiGateAOpcertHotKeyAndKesCounter(t *testing.T) {
	cases := []struct {
		name  string
		kes   byte
		count bool
		want  string
	}{
		{"hot key of another KES key", 0xaa, true, "another hot key"},
		{"counter behind the keys", 0xef, false, "behind the numbered KES key 2"},
	}
	for _, c := range cases {
		tr, dst := newTree(), newMem()
		putPool(dst, "p", 80, "")
		kesSource(t, tr, 80, c.kes)
		if c.count {
			tr.dir("/d").put(ref("p", ports.KesCounter), []byte("2\n"))
			tr.dir("/d").put(ref("p", ports.KesCounterNext), []byte("2\n"))
		}
		before := snapshotOf(dst)
		rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true, ImportOptions: ImportOptions{Overwrite: c.count}})
		if err != nil {
			t.Fatal(err)
		}
		if o := ownerOf(rep, "p"); o.Written || !strings.Contains(o.Reason, c.want) {
			t.Errorf("%s: %+v", c.name, o)
		}
		unchanged(t, c.name, before, dst)
	}
}

// Adding the KES key, operational certificate and counters of the same cold key
// to a workspace pool that has only its cold keys is coherent and succeeds,
// without --overwrite, with a note that lists what was added.
//
// spec: SPO-Xmulti-OUT-016
func TestXmultiGateAAdditiveCoherentMerge(t *testing.T) {
	tr, dst := newTree(), newMem()
	putPool(dst, "p", 80, "")
	for _, k := range []ports.Kind{ports.KesCounter, ports.KesCounterNext} {
		delete(dst.files, ref("p", k))
	}
	for _, r := range []ports.Ref{{Name: "p", Kind: ports.KesSKey, Num: 1}, {Name: "p", Kind: ports.KesVKey, Num: 1}, {Name: "p", Kind: ports.OpCert, Num: 1}} {
		delete(dst.files, r)
	}
	putPool(tr.dir("/d"), "p", 80, "")
	for _, k := range []ports.Kind{ports.NodeSKey, ports.NodeVKey, ports.NodeCounter} {
		delete(tr.dir("/d").files, ref("p", k))
	}
	rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true})
	o := ownerOf(rep, "p")
	if err != nil || !o.Written {
		t.Fatalf("%v %+v", err, o)
	}
	if n := noteOf(o); !strings.Contains(n, "merged into the existing workspace owner") || !strings.Contains(n, "p/node.opcert#1") || !strings.Contains(n, "p/kes.vkey#1") {
		t.Errorf("note %q", n)
	}
	if _, ok := dst.files[ports.Ref{Name: "p", Kind: ports.OpCert, Num: 1}]; !ok {
		t.Error("the opcert is not in the workspace")
	}
}

// A pool is never merged into a wallet of the same name (and the reverse), and
// the pool that names the wallet is refused.
//
// spec: SPO-Xmulti-OUT-016, SPO-Xmulti-INV-006
func TestXmultiGateAPoolNamedAsOwnerIsRefused(t *testing.T) {
	tr, dst := newTree(), newMem()
	putPool(tr.dir("/d"), "x", 81, "")
	putPool(tr.dir("/d"), "p", 80, descJSON("p", "x", "x"))
	putWallet(dst, "x", 11)
	before := snapshotOf(dst)
	rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true})
	if err != nil {
		t.Fatal(err)
	}
	if o := ownerOf(rep, "x"); o.Written || !strings.Contains(o.Reason, "other kind") {
		t.Errorf("x: %+v", o)
	}
	if o := ownerOf(rep, "p"); o.Written {
		t.Errorf("p: %+v", o)
	}
	unchanged(t, "pool named as owner", before, dst)

	// and the reverse: a wallet over a workspace pool
	tr, dst = newTree(), newMem()
	putWallet(tr.dir("/d"), "x", 1)
	putPool(dst, "x", 90, "")
	rep, _ = multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true})
	if o := ownerOf(rep, "x"); o.Written || !strings.Contains(o.Reason, "other kind") {
		t.Errorf("reverse: %+v", o)
	}
}

// A descriptor that names an owner by another spelling than the owner has is
// refused as ambiguous, naming both spellings, and is never bound to the
// workspace wallet of the other spelling.
//
// spec: SPO-Xmulti-PRE-014
func TestXmultiReferenceDifferingOnlyByCaseIsAmbiguous(t *testing.T) {
	tr, dst := newTree(), newMem()
	putWallet(tr.dir("/d"), "x", 1)
	putPool(tr.dir("/d"), "p", 80, descJSON("p", "X", "X"))
	putWallet(dst, "X", 11)
	rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true})
	if err != nil {
		t.Fatal(err)
	}
	o := ownerOf(rep, "p")
	why := whyOf(o)
	if o.Written || stored(dst, "p", ports.PoolDescriptor) != "" || !strings.Contains(why, `"X"`) || !strings.Contains(why, `"x"`) || !strings.Contains(why, "apart from case") {
		t.Errorf("p: %+v", o)
	}
}

// A name that only the workspace has says, in its note, that nothing of that
// name was found within the given folders and depth.
//
// spec: SPO-Xmulti-PRE-015
func TestXmultiWorkspaceOnlyNoteNamesTheDepth(t *testing.T) {
	tr, dst := newTree(), newMem()
	putPool(tr.dir("/d"), "p", 80, descJSON("p", "deep", "deep"))
	putWallet(tr.sub("/d", "below"), "deep", 40)
	putWallet(dst, "deep", 40)
	rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true})
	if err != nil {
		t.Fatal(err)
	}
	o := ownerOf(rep, "p")
	if !o.Written || !strings.Contains(noteOf(o), "no wallet of that name was found within the given folders and depth") {
		t.Errorf("p: %+v", o)
	}
}

// A pool whose witness transfer files name an owner that this run stores under
// another name is refused; without the rename it is stored with its files.
//
// spec: SPO-Xmulti-OUT-017
func TestXmultiWitnessFilesOfARenamedOwnerRefuseThePool(t *testing.T) {
	build := func() (*memTree, *memStore) {
		tr := newTree()
		putWallet(tr.dir("/d"), "a", 1)
		putPool(tr.dir("/d"), "p", 80, descJSON("p", "a", "a"))
		tr.dir("/d").put(ports.Ref{Name: "p_a_abc123", Kind: ports.PoolWitnessFile}, []byte(`{"id":"abc123"}`))
		return tr, newMem()
	}
	tr, dst := build()
	rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true, Renames: []Rename{{From: Selector{Name: "a"}, To: "b"}}})
	if err != nil {
		t.Fatal(err)
	}
	if o := ownerOf(rep, "p"); o.Written || !strings.Contains(o.Reason, "witness file") || stored(dst, "p", ports.PoolDescriptor) != "" {
		t.Errorf("renamed owner: %+v", o)
	}
	tr, dst = build()
	rep, err = multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true})
	if err != nil || !ownerOf(rep, "p").Written {
		t.Fatalf("no rename: %v %+v", err, ownerOf(rep, "p"))
	}
	// the pool itself renamed: the slot of its own cold key names the old pool name
	tr, dst = build()
	tr.dir("/d").put(ports.Ref{Name: "p_p.node_abc123", Kind: ports.PoolWitnessFile}, []byte(`{"id":"abc123"}`))
	rep, _ = multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true, Renames: []Rename{{From: Selector{Name: "p"}, To: "q"}}})
	if o := ownerOf(rep, "p"); o.Written || !strings.Contains(o.Reason, "witness file") {
		t.Errorf("renamed pool: %+v", o)
	}
}

// bindHarness runs Gate B on a plan that the test writes by hand, as if the
// path logic had made a mistake: the pool p of /d is planned with the final
// descriptor `final`, and the extra owners with the artefacts in `extra`
// (stored under their name). It returns the refusal Gate B set, "" for none.
func bindHarness(t *testing.T, tr *memTree, dst *memStore, final string, note string, extra map[string]map[ports.Ref][]byte) string {
	t.Helper()
	u := ImportWorkspace{Dest: dst, Deriver: edDeriver{}, Addresses: addrInspector{}, Open: tr.Open}
	req := ImportRequest{Dirs: []string{"/d"}, All: true}
	srcs, err := u.openAll(&req)
	if err != nil {
		t.Fatal(err)
	}
	rep := &Report{}
	sl, err := u.selectOwners(ctx(), req, srcs, rep)
	if err != nil {
		t.Fatal(err)
	}
	ws, err := u.snapshot(ctx(), []string{"p", "x", "w"})
	if err != nil {
		t.Fatal(err)
	}
	res := &resolver{u: u, ctx: ctx(), all: sl.all, roots: rootsOf(srcs), ws: ws, deps: map[*found][]*found{}}
	prep := map[*found]*prepared{}
	var order []*found
	for _, f := range sl.all {
		if f.name == "a" { // a renamed owner: stored as w
			f.final = "w"
		}
		p := &prepared{done: true, final: f.final, results: map[ports.Ref]*ArtefactReport{}}
		switch f.name {
		case "p":
			d := ports.Ref{Name: "p", Kind: ports.PoolDescriptor}
			p.plan = []planned{{src: d, dst: d, data: []byte(final)}}
			p.results[d] = &ArtefactReport{Ref: d, Note: note}
		default:
			if arts, ok := extra[f.name]; ok {
				for r, b := range arts {
					p.plan = append(p.plan, planned{src: r, dst: renameRef(r, f.name, f.final), data: b})
				}
			} else {
				p.fixed = true
			}
		}
		prep[f] = p
		order = append(order, f)
	}
	u.checkBinding(ctx(), res, ws, order, prep)
	for f, p := range prep {
		if f.name == "p" {
			return p.refusal
		}
	}
	return ""
}

// Gate B refuses a pool whose final descriptor names an owner that the planned
// end state does not make the wallet with the very keys of the source owner the
// layout names, whatever path produced the descriptor.
//
// spec: SPO-Xmulti-INV-006, SPO-Xmulti-INV-007
func TestXmultiGateBChecksTheEndStateByKeys(t *testing.T) {
	other := pair(2, "StakeSigningKeyShelley_ed25519", "StakeVerificationKeyShelley_ed25519", "Stake")
	otherPay := payment(7)
	cases := []struct {
		name  string
		setup func(tr *memTree, dst *memStore)
		final string
		note  string
		extra map[string]map[ports.Ref][]byte
		want  string // "" = accepted
	}{
		{"wallet stored with the source's keys",
			func(tr *memTree, dst *memStore) { putWallet(tr.dir("/d"), "w", 1) },
			descJSON("p", "w", "w"), "",
			map[string]map[ports.Ref][]byte{"w": {ref("w", ports.StakingVKey): pair(1, "StakeSigningKeyShelley_ed25519", "StakeVerificationKeyShelley_ed25519", "Stake").vkey}}, ""},
		{"wallet stored with other stake keys than the source owner",
			func(tr *memTree, dst *memStore) { putWallet(tr.dir("/d"), "w", 1) },
			descJSON("p", "w", "w"), "",
			map[string]map[ports.Ref][]byte{"w": {ref("w", ports.StakingVKey): other.vkey}}, "differs from the one of the source owner"},
		{"wallet with the same stake keys and other payment keys",
			func(tr *memTree, dst *memStore) {
				putWallet(tr.dir("/d"), "w", 1)
				putPayment(tr.dir("/d"), "w", 3)
			},
			descJSON("p", "w", "w"), "",
			map[string]map[ports.Ref][]byte{"w": {
				ref("w", ports.StakingVKey):               pair(1, "StakeSigningKeyShelley_ed25519", "StakeVerificationKeyShelley_ed25519", "Stake").vkey,
				{Name: "w.payment", Kind: ports.AddrVKey}: otherPay.vkey}}, "payment verification key of the wallet differs"},
		{"owner is a pool",
			func(tr *memTree, dst *memStore) { putPool(tr.dir("/d"), "x", 81, "") },
			descJSON("p", "x", "x"), "",
			map[string]map[ports.Ref][]byte{"x": {ref("x", ports.NodeVKey): cold(81).vkey}}, "not a wallet"},
		{"owner without a stake key",
			func(tr *memTree, dst *memStore) { putPayment(tr.dir("/d"), "x", 1) },
			descJSON("p", "x", "x"), "",
			map[string]map[ports.Ref][]byte{"x": {{Name: "x.payment", Kind: ports.AddrVKey}: payment(1).vkey}}, "no stake verification key"},
		{"no such owner",
			func(tr *memTree, dst *memStore) {},
			descJSON("p", "ghost", "ghost"), "", nil, "no owner of that name will exist"},
		{"workspace-only wallet with its note",
			func(tr *memTree, dst *memStore) { putWallet(dst, "w", 40) },
			descJSON("p", "w", "w"), "poolOwner[0].ownerName is bound to the existing workspace wallet \"w\"; poolRewards is bound to the existing workspace wallet \"w\"", nil, ""},
		{"workspace-only wallet without its note",
			func(tr *memTree, dst *memStore) { putWallet(dst, "w", 40) },
			descJSON("p", "w", "w"), "", nil, "carries no note"},
		{"workspace-only wallet replaced by the plan",
			func(tr *memTree, dst *memStore) { putWallet(tr.dir("/d"), "a", 2); putWallet(dst, "w", 40) },
			descJSON("p", "w", "w"), "poolOwner[0].ownerName is bound to the existing workspace wallet \"w\"; poolRewards is bound to the existing workspace wallet \"w\"",
			map[string]map[ports.Ref][]byte{"a": {ref("a", ports.StakingVKey): other.vkey}}, "would not be the one the workspace holds now"},
		{"owner named by another spelling",
			func(tr *memTree, dst *memStore) { putWallet(tr.dir("/d"), "w", 1); putWallet(dst, "W", 40) },
			descJSON("p", "W", "W"), "poolOwner[0].ownerName is bound to the existing workspace wallet \"W\"; poolRewards is bound to the existing workspace wallet \"W\"", nil, "differs only by case"},
		{"name inside an open registration",
			func(tr *memTree, dst *memStore) { putWallet(dst, "w", 40) },
			descJSON("p", "w", "w", `"regWitness": {"regPayName": "nobody", "witnesses": {"p.node": {}}}`),
			"poolOwner[0].ownerName is bound to the existing workspace wallet \"w\"; poolRewards is bound to the existing workspace wallet \"w\"", nil, "regWitness.regPayName"},
	}
	for _, c := range cases {
		tr, dst := newTree(), newMem()
		putPool(tr.dir("/d"), "p", 80, descJSON("p", "w", "w"))
		c.setup(tr, dst)
		got := bindHarness(t, tr, dst, c.final, c.note, c.extra)
		if c.want == "" && got != "" || c.want != "" && !strings.Contains(got, c.want) {
			t.Errorf("%s: refusal %q, want %q", c.name, got, c.want)
		}
	}
}

// Gate A, called as the plan calls it with a plan the path logic let through,
// refuses what is not one owner; the same function accepts the coherent one.
//
// spec: SPO-Xmulti-OUT-016
func TestXmultiGateAIsOneFunctionOverTheResult(t *testing.T) {
	u := ImportWorkspace{Deriver: edDeriver{}, Addresses: addrInspector{}}
	dst := newMem()
	putWallet(dst, "x", 11)
	u.Dest = dst
	ws, err := u.snapshot(ctx(), []string{"x"})
	if err != nil {
		t.Fatal(err)
	}
	pk := payment(5)
	plan := []planned{{dst: ports.Ref{Name: "x.payment", Kind: ports.AddrVKey}, data: pk.vkey}}
	if why, _ := u.checkCoherence(ctx(), ws, "x", plan); !strings.Contains(why, "not provably one owner") {
		t.Errorf("disjoint: %q", why)
	}
	// the same payment key with a base address that ties it to the workspace's
	// stake key is one owner
	sh := keyHashOf(rawOfPair(t, dst, "x"))
	ph := keyHashOf(pk.vkey)
	plan = append(plan, planned{dst: ports.Ref{Name: "x.payment", Kind: ports.AddrFile}, data: []byte("addr_" + hex.EncodeToString(ph[:]) + "_" + hex.EncodeToString(sh[:]))})
	if why, note := u.checkCoherence(ctx(), ws, "x", plan); why != "" || !strings.Contains(note, "added") {
		t.Errorf("tied: %q %q", why, note)
	}
}

func rawOfPair(t *testing.T, s *memStore, name string) []byte {
	return s.files[ref(name, ports.StakingVKey)]
}
