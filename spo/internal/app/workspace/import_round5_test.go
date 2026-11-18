package workspace

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// coldHash is the pool id (key hash) of the cold key of a seed.
func coldHash(seed byte) [28]byte {
	h := keyHashOf(cold(seed).vkey)
	return h
}

func coldVK(seed byte) [32]byte {
	var vk [32]byte
	copy(vk[:], rawOf(cold(seed).vkey))
	return vk
}

// A key that occurs twice in one object of a descriptor, or twice apart from
// case, is refused in the selective form, naming the keys, wherever it is: the
// programs that read the descriptor read exact keys and the last of a repeated
// one, so such a descriptor names more than the import checks. The plain form
// stores it as it is and notes it.
//
// spec: SPO-Xmulti-PRE-016
func TestXmultiRepeatedKeysAreRefused(t *testing.T) {
	regPay := `"regWitness": {"id": 7, "type": "PoolRegistration", "ttl": 9, "regPayName": "u", "REGPAYNAME": "w", "regPayAmount": 1, "regPayReturn": 2, "txBody": {}, "hardwareWalletIncluded": "no", "metadataFilesList": "p.metadata.json", "witnesses": {"p.node": {"witness": {}}, "w.staking": {"witness": {}}}}`
	slots := `"regWitness": {"id": 7, "regPayName": "w", "witnesses": {"p.node": {"witness": {}}, "w.staking": {"witness": {}}, "W.staking": {"witness": {}}}}`
	cases := []struct {
		name, desc, want string
	}{
		{"regPayName in another case", descJSON("p", "w", "w", regPay), `"regPayName" and "REGPAYNAME" differ only by case`},
		{"slot keys in another case", descJSON("p", "w", "w", slots), `"w.staking" and "W.staking" differ only by case`},
		{"poolRewards twice", descJSON("p", "w", "w", `"poolRewards": "u"`), `"poolRewards" occurs twice`},
		{"ownerName in another case", strings.Replace(descJSON("p", "w", "w"), `"ownerWitness": "local"`, `"ownerWitness": "local", "OwnerName": "u"`, 1), `"ownerName" and "OwnerName" differ only by case`},
	}
	for _, c := range cases {
		tr, dst := newTree(), newMem()
		putPool(tr.dir("/d"), "p", 80, c.desc)
		putWallet(tr.dir("/d"), "w", 40)
		putWallet(tr.dir("/d"), "u", 41)
		putWallet(dst, "u", 99)
		rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, Only: []Selector{{Name: "p"}, {Name: "w"}}})
		if err != nil {
			t.Fatal(err)
		}
		o := ownerOf(rep, "p")
		if o.Written || !strings.Contains(artefactReason(o, ports.PoolDescriptor), c.want) {
			t.Errorf("%s: %+v", c.name, o)
		}
		if stored(dst, "p", ports.PoolDescriptor) != "" {
			t.Errorf("%s: stored", c.name)
		}
		// the plain form keeps its outcome and says what a selective import would do
		tr2, dst2 := newTree(), newMem()
		putPool(tr2.dir("/d"), "p", 80, c.desc)
		putWallet(dst2, "w", 40)
		rep, err = plainMulti(tr2, dst2).Import(ctx(), ImportRequest{Dirs: []string{"/d"}})
		if err != nil || !ownerOf(rep, "p").Written || !strings.Contains(artefactReason(ownerOf(rep, "p"), ports.PoolDescriptor)+artefactNote(ownerOf(rep, "p")), "a selective import") {
			t.Errorf("%s: plain form: %v %+v", c.name, err, ownerOf(rep, "p"))
		}
	}
}

func artefactNote(o OwnerReport) string {
	var s string
	for _, a := range o.Artefacts {
		s += a.Note
	}
	return s
}

// The names Gate B checks are the ones the domain's readers return, not the
// ones a string-valued enumeration finds: a number is a name to Owners and to
// Text of poolRewards (jq -r prints it), so a descriptor whose rewards value is
// the number 7 names a wallet "7", which the workspace does not hold.
//
// spec: SPO-Xmulti-INV-007
func TestXmultiGateBReadsNamesLikeTheConsumers(t *testing.T) {
	tr, dst := newTree(), newMem()
	d := strings.Replace(descJSON("p", "w", "w"), `"poolRewards": "w"`, `"poolRewards": 7`, 1)
	putPool(tr.dir("/d"), "p", 80, d)
	putWallet(tr.dir("/d"), "w", 40)
	rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true})
	if err != nil {
		t.Fatal(err)
	}
	o := ownerOf(rep, "p")
	if o.Written || !strings.Contains(o.Reason, `poolRewards names "7"`) {
		t.Errorf("%+v", o)
	}
}

// poolIDRig is a workspace pool p (cold key 80) and a source that brings the
// issue counter of that cold key (which anchors the merge) with one more record.
func poolIDRig(t *testing.T, extra func(s *memStore)) (*Report, *memStore, map[ports.NamedRef]string) {
	tr, dst := newTree(), newMem()
	putWallet(dst, "w", 40)
	putPool(dst, "p", 80, descJSON("p", "w", "w"))
	s := tr.dir("/d")
	s.put(ref("p", ports.NodeCounter), pool.IssueCounter{Next: 5, ColdVKey: coldVK(80)}.Envelope())
	extra(s)
	before := snapshotOf(dst)
	rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true, ImportOptions: ImportOptions{Overwrite: true}})
	if err != nil {
		t.Fatal(err)
	}
	return rep, dst, before
}

func certOf(op [28]byte) []byte {
	raw := append([]byte{0x83, 0x04, 0x58, 0x1c}, op[:]...)
	raw = append(raw, 0x19, 0x01, 0x02)
	return pool.MarshalEnvelope(pool.Envelope{Type: "CertificateShelley", CborHex: hex.EncodeToString(raw)})
}

// A pool record that carries the pool id (descriptor poolID and poolIDbech, the
// id files, the registration and retirement certificates) is checked against
// the result's cold key; one that names another pool refuses the merge, one
// that names this pool is merged.
//
// spec: SPO-Xmulti-OUT-018
func TestXmultiGateAPoolIdentityOfRecords(t *testing.T) {
	mine, other := coldHash(80), coldHash(81)
	bech := func(h [28]byte) string { return chain.PoolID(h).Bech32() }
	cases := []struct {
		name  string
		put   func(s *memStore)
		want  string // "" is accepted
		check ports.Kind
	}{
		{"descriptor poolID of another pool", func(s *memStore) {
			s.put(ref("p", ports.PoolDescriptor), []byte(descJSON("p", "w", "w", `"poolID": "`+hex.EncodeToString(other[:])+`"`)))
		}, "poolID is not the pool id of the cold key", ports.PoolDescriptor},
		{"descriptor poolIDbech of another pool", func(s *memStore) {
			s.put(ref("p", ports.PoolDescriptor), []byte(descJSON("p", "w", "w", `"poolIDbech": "`+bech(other)+`"`)))
		}, "poolIDbech is not the pool id of the cold key", ports.PoolDescriptor},
		{"id-bech file of another pool", func(s *memStore) {
			s.put(ref("p", ports.PoolIDBechFile), []byte(bech(other)+"\n"))
		}, "pool id of the cold key", ports.PoolIDBechFile},
		{"id file of another pool", func(s *memStore) {
			s.put(ref("p", ports.PoolIDFile), []byte(hex.EncodeToString(other[:])+"\n"))
		}, "pool id", ports.PoolIDFile},
		{"registration certificate of another pool", func(s *memStore) { s.put(ref("p", ports.PoolCert), certOf(other)) }, "pool id of the cold key", ports.PoolCert},
		{"retirement certificate of another pool", func(s *memStore) { s.put(ref("p", ports.PoolDeregCert), certOf(other)) }, "pool id of the cold key", ports.PoolDeregCert},
		{"all of this pool", func(s *memStore) {
			s.put(ref("p", ports.PoolDescriptor), []byte(descJSON("p", "w", "w", `"poolID": "`+hex.EncodeToString(mine[:])+`"`, `"poolIDbech": "`+bech(mine)+`"`)))
			s.put(ref("p", ports.PoolIDBechFile), []byte(bech(mine)+"\n"))
			s.put(ref("p", ports.PoolIDFile), []byte(hex.EncodeToString(mine[:])+"\n"))
			s.put(ref("p", ports.PoolCert), certOf(mine))
			s.put(ref("p", ports.PoolDeregCert), certOf(mine))
		}, "", ""},
	}
	for _, c := range cases {
		rep, dst, before := poolIDRig(t, c.put)
		o := ownerOf(rep, "p")
		if c.want == "" {
			if !o.Written {
				t.Errorf("%s: %+v", c.name, o)
			}
			continue
		}
		if o.Written || !strings.Contains(o.Reason, c.want) || !strings.Contains(o.Reason, ref("p", c.check).String()) {
			t.Errorf("%s: %+v", c.name, o)
		}
		if !sameFiles(before, snapshotOf(dst)) {
			t.Errorf("%s: the workspace changed", c.name)
		}
	}
}

// A merge into an existing owner needs an identity anchor: something both sides
// have in common that shows they are one owner. An unrelated source owner of
// the same name that holds only DRep keys is not merged; the same keys with
// the workspace wallet's stake key are, and the note says what was verified.
//
// spec: SPO-Xmulti-OUT-019
func TestXmultiMergeNeedsAnIdentityAnchor(t *testing.T) {
	drep := pair(43, "DRepSigningKey_ed25519", "DRepVerificationKey_ed25519", "Delegated Representative")
	for _, shared := range []bool{false, true} {
		tr, dst := newTree(), newMem()
		putWallet(dst, "w", 40)
		tr.dir("/d").put(ref("w", ports.DRepSKey), drep.skey)
		tr.dir("/d").put(ref("w", ports.DRepVKey), drep.vkey)
		if shared {
			tr.dir("/d").put(ref("w", ports.StakingVKey), dst.files[ref("w", ports.StakingVKey)])
		}
		before := snapshotOf(dst)
		rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true, ImportOptions: ImportOptions{Overwrite: shared}})
		if err != nil {
			t.Fatal(err)
		}
		o := ownerOf(rep, "w")
		if !shared {
			if o.Written || !strings.Contains(o.Reason, "nothing shows that the source owner and the workspace owner of this name are the same") || !strings.Contains(o.Reason, "import it under a new name") {
				t.Errorf("unrelated: %+v", o)
			}
			if !sameFiles(before, snapshotOf(dst)) {
				t.Error("unrelated: the workspace changed")
			}
			continue
		}
		note := artefactNote(o)
		if !o.Written || !strings.Contains(note, "verified:") || !strings.Contains(note, "staking.vkey") || strings.Contains(note, "provably") {
			t.Errorf("shared stake key: %+v", o)
		}
	}
}

// The next KES key, operational certificate and counters of a pool the workspace
// holds are merged: the counter and the certificate name the pool's cold key,
// which is the anchor.
//
// spec: SPO-Xmulti-OUT-019
func TestXmultiNextKesSetOfAWorkspacePoolIsAnchoredByItsColdKey(t *testing.T) {
	tr, dst := newTree(), newMem()
	putWallet(dst, "w", 40)
	putPool(dst, "p", 80, descJSON("p", "w", "w"))
	kb := rawOf(cold(80).vkey)
	s := tr.dir("/d")
	s.put(ports.NamedRef{Name: "p", Kind: ports.KesSKey, Num: 2}, []byte(`{"type":"KesSigningKey_ed25519_kes_2^6","description":"KES Signing Key","cborHex":"5860`+strings.Repeat("ef", 96)+`"}`))
	s.put(ports.NamedRef{Name: "p", Kind: ports.KesVKey, Num: 2}, pool.MarshalEnvelope(pool.Envelope{Type: "KesVerificationKey_ed25519_kes_2^6", Description: "KES Verification Key", CborHex: "5820" + strings.Repeat("ee", 32)}))
	s.put(ports.NamedRef{Name: "p", Kind: ports.OpCert, Num: 2}, opcertOf(kb, []byte(strings.Repeat("\xee", 32))))
	s.put(ref("p", ports.NodeCounter), pool.IssueCounter{Next: 3, ColdVKey: coldVK(80)}.Envelope())
	s.put(ref("p", ports.KesCounter), pool.FormatCounter(2))
	s.put(ref("p", ports.KesCounterNext), pool.FormatCounter(3))
	rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true, ImportOptions: ImportOptions{Overwrite: true}})
	if err != nil || !ownerOf(rep, "p").Written || !strings.Contains(artefactNote(ownerOf(rep, "p")), "verified: ") {
		t.Fatalf("%v %+v", err, ownerOf(rep, "p"))
	}
}

// racingDest changes the workspace after the run has read it, as another
// process would: the hook runs at the start of the first Update.
type racingDest struct {
	*memStore
	hook func()
	done bool
}

func (d *racingDest) Update(c context.Context, fn func(ports.NamedWriter) error) error {
	if !d.done {
		d.done = true
		d.hook()
	}
	return d.memStore.Update(c, fn)
}

// The whole selective run is one transaction: a failing write stores none of
// the planned owners, and a workspace that changed after the snapshot, an
// artefact the decisions read or one the run is to write, refuses the whole
// run with the rows of the planned owners still shown.
//
// spec: SPO-Xmulti-INV-008
func TestXmultiRunIsAtomicAndRefusesAMovedWorkspace(t *testing.T) {
	build := func() (*memTree, *memStore) {
		tr, dst := newTree(), newMem()
		putWallet(tr.dir("/d"), "a", 1)
		putWallet(tr.dir("/d"), "b", 2)
		putPool(tr.dir("/d"), "p", 80, descJSON("p", "a", "b"))
		return tr, dst
	}
	// a write fails on the last owner: nothing of the run is kept
	tr, dst := build()
	fd := failingDest{dst, "p"}
	u := ImportWorkspace{Dest: fd, Deriver: edDeriver{}, Addresses: addrInspector{}, Open: tr.Open}
	rep, err := u.Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true})
	if err != nil || len(dst.files) != 0 || dst.updates != 0 || rep.Failed() != 3 {
		t.Errorf("failing write: %v files=%d updates=%d %+v", err, len(dst.files), dst.updates, rep.Owners)
	}
	for _, o := range rep.Owners {
		if !strings.Contains(o.Reason, "nothing of this run was imported") || len(o.Artefacts) == 0 {
			t.Errorf("failing write: row %+v", o)
		}
	}
	// an artefact the run read changed after it was read
	tr, dst = build()
	putWallet(dst, "a", 11)
	rd := &racingDest{memStore: dst, hook: func() { putWallet(dst, "a", 12) }}
	u = ImportWorkspace{Dest: rd, Deriver: edDeriver{}, Addresses: addrInspector{}, Open: tr.Open}
	rep, err = u.Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true, ImportOptions: ImportOptions{Overwrite: true}})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range rep.Owners {
		if o.Written {
			t.Errorf("moved workspace: %s written: %+v", o.Owner, o)
		}
	}
	if len(dst.files) != 2 || string(dst.files[ref("a", ports.StakingVKey)]) != string(pair(12, "StakeSigningKeyShelley_ed25519", "StakeVerificationKeyShelley_ed25519", "Stake").vkey) {
		t.Errorf("moved workspace: the workspace was written: %d files", len(dst.files))
	}
	// an artefact the run is to write appeared after the snapshot (no --overwrite)
	tr, dst = build()
	rd = &racingDest{memStore: dst, hook: func() { putWallet(dst, "b", 13) }}
	u = ImportWorkspace{Dest: rd, Deriver: edDeriver{}, Addresses: addrInspector{}, Open: tr.Open}
	rep, err = u.Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true})
	if err != nil {
		t.Fatal(err)
	}
	moved := 0
	for _, o := range rep.Owners {
		if o.Written {
			t.Errorf("appeared artefact: %s written", o.Owner)
		}
		if strings.Contains(o.Reason, "the workspace changed while the import was running") {
			moved++
		}
	}
	if moved != 3 {
		t.Errorf("appeared artefact: %d rows say the workspace moved: %+v", moved, rep.Owners)
	}
	if _, ok := dst.files[ref("a", ports.StakingVKey)]; ok {
		t.Error("appeared artefact: a was written")
	}
	// the same run when nothing moves: all three, in one transaction
	tr, dst = build()
	rep, err = multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true})
	if err != nil || rep.Failed() != 0 || dst.updates != 1 {
		t.Errorf("clean run: %v updates=%d %+v", err, dst.updates, rep.Owners)
	}
}

// A wallet of the workspace that a workspace pool names, which this run does
// not replace, is not replaced with other keys; with the same keys it is.
//
// spec: SPO-Xmulti-INV-009
func TestXmultiWorkspacePoolKeepsItsWallet(t *testing.T) {
	for _, same := range []bool{false, true} {
		tr, dst := newTree(), newMem()
		putWallet(dst, "w", 40)
		putPool(dst, "q", 82, descJSON("q", "w", "w"))
		if same {
			putWallet(tr.dir("/d"), "w", 40)
		} else {
			putWallet(tr.dir("/d"), "w", 41)
		}
		before := snapshotOf(dst)
		rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, Only: []Selector{{Name: "w"}}, ImportOptions: ImportOptions{Overwrite: true}})
		if err != nil {
			t.Fatal(err)
		}
		o := ownerOf(rep, "w")
		if same {
			if !o.Written {
				t.Errorf("same keys: %+v", o)
			}
			continue
		}
		if o.Written || !strings.Contains(o.Reason, "workspace pool(s) q") || !strings.Contains(o.Reason, "stake verification key") {
			t.Errorf("other keys: %+v", o)
		}
		if !sameFiles(before, snapshotOf(dst)) {
			t.Error("other keys: the workspace changed")
		}
	}
}

// The oracle is itself tested: each workspace below breaks one clause of
// INV-006 and the oracle must say so.
//
// spec: SPO-Xmulti-INV-006
func TestOracleReportsEachViolation(t *testing.T) {
	type tc struct {
		name, want string
		build      func(tr *memTree, dst *memStore, st *invState)
	}
	pw := func(dst *memStore, name string, seed byte, desc string) { putPool(dst, name, seed, desc) }
	cases := []tc{
		{"wallet and pool under one name", "holds wallet and pool artefacts", func(tr *memTree, dst *memStore, st *invState) {
			pw(dst, "x", 80, "")
			putWallet(dst, "x", 40)
		}},
		{"signing key of another verification key", "does not belong to", func(tr *memTree, dst *memStore, st *invState) {
			putWallet(dst, "x", 40)
			dst.put(ref("x", ports.StakingSKey), pair(41, "StakeSigningKeyShelley_ed25519", "StakeVerificationKeyShelley_ed25519", "Stake").skey)
		}},
		{"counter of another cold key", "names another cold key", func(tr *memTree, dst *memStore, st *invState) {
			pw(dst, "x", 80, "")
			dst.put(ref("x", ports.NodeCounter), pool.IssueCounter{Next: 2, ColdVKey: coldVK(81)}.Envelope())
		}},
		{"opcert of another cold key", "names another cold key", func(tr *memTree, dst *memStore, st *invState) {
			pw(dst, "x", 80, "")
			dst.put(ports.NamedRef{Name: "x", Kind: ports.OpCert, Num: 1}, opcertOf(rawOf(cold(81).vkey), make([]byte, 32)))
		}},
		{"pool without cold key material but with disagreeing counter and opcert", "more than one cold key", func(tr *memTree, dst *memStore, st *invState) {
			dst.put(ref("x", ports.NodeCounter), pool.IssueCounter{Next: 2, ColdVKey: coldVK(80)}.Envelope())
			dst.put(ports.NamedRef{Name: "x", Kind: ports.OpCert, Num: 1}, opcertOf(rawOf(cold(81).vkey), make([]byte, 32)))
		}},
		{"descriptor poolID of another pool", "poolID is not the pool id", func(tr *memTree, dst *memStore, st *invState) {
			putWallet(dst, "w", 40)
			h := coldHash(81)
			pw(dst, "x", 80, descJSON("x", "w", "w", `"poolID": "`+hex.EncodeToString(h[:])+`"`))
		}},
		{"id-bech file of another pool", "is not the pool id of the cold key", func(tr *memTree, dst *memStore, st *invState) {
			pw(dst, "x", 80, "")
			dst.put(ref("x", ports.PoolIDBechFile), []byte(chain.PoolID(coldHash(81)).Bech32()))
		}},
		{"certificate of another pool", "is about another pool id", func(tr *memTree, dst *memStore, st *invState) {
			pw(dst, "x", 80, "")
			dst.put(ref("x", ports.PoolCert), certOf(coldHash(81)))
		}},
		{"address of another payment key", "is not derived from the payment key", func(tr *memTree, dst *memStore, st *invState) {
			pk := putPayment(dst, "x", 3)
			dst.put(ports.NamedRef{Name: "x.payment", Kind: ports.AddrFile}, addrOf(pair(9, "PaymentSigningKeyShelley_ed25519", "PaymentVerificationKeyShelley_ed25519", "Payment").vkey))
			_ = pk
		}},
		{"stake and payment keys nothing ties", "nothing ties together", func(tr *memTree, dst *memStore, st *invState) {
			putWallet(dst, "x", 40)
			dst.put(ports.NamedRef{Name: "x.payment", Kind: ports.AddrVKey}, payment(3).vkey)
		}},
		{"descriptor names no wallet", "no wallet of the workspace has that name", func(tr *memTree, dst *memStore, st *invState) {
			pw(dst, "x", 80, descJSON("x", "ghost", "ghost"))
			pw(tr.dir("/d"), "x", 80, descJSON("x", "ghost", "ghost"))
		}},
		{"registration names no wallet", "regWitness.regPayName", func(tr *memTree, dst *memStore, st *invState) {
			putWallet(dst, "w", 40)
			d := descJSON("x", "w", "w", `"regWitness": {"id": 7, "regPayName": "ghost", "witnesses": {"x.node": {}}}`)
			pw(dst, "x", 80, d)
			pw(tr.dir("/d"), "x", 80, d)
			putWallet(tr.dir("/d"), "w", 40)
		}},
		{"descriptor field missing from the source descriptor", "the source descriptor has no such field", func(tr *memTree, dst *memStore, st *invState) {
			putWallet(dst, "w", 40)
			putWallet(dst, "u", 41)
			pw(dst, "x", 80, descJSON("x", "w", "u"))
			pw(tr.dir("/d"), "x", 80, strings.Replace(descJSON("x", "w", "u"), `"poolRewards": "u",`, "", 1))
			putWallet(tr.dir("/d"), "w", 40)
			putWallet(tr.dir("/d"), "u", 41)
		}},
		{"wallet with other keys than the source owner the folder rule names", "other stake keys than the source owner the layout names", func(tr *memTree, dst *memStore, st *invState) {
			// the source descriptor in /d/pool names ../a/w; another folder has a w
			// with the workspace's keys, which a lookup by base name would accept
			putWallet(dst, "w", 41)
			pw(dst, "x", 80, descJSON("x", "w", "w"))
			pw(tr.dir("/d/pool"), "x", 80, descJSON("x", "../a/w", "../a/w"))
			putWallet(tr.dir("/d/a"), "w", 40)
			putWallet(tr.dir("/d/b"), "w", 41)
		}},
		{"wallet differs only by case from the source owner", "differs only by case", func(tr *memTree, dst *memStore, st *invState) {
			putWallet(dst, "Alice", 41)
			pw(dst, "x", 80, descJSON("x", "Alice", "Alice"))
			pw(tr.dir("/d"), "x", 80, descJSON("x", "Alice", "Alice"))
			putWallet(tr.dir("/d"), "alice", 40)
		}},
		{"pool the run did not replace names a wallet the run changed", "the run changed the wallet a pool it did not replace names", func(tr *memTree, dst *memStore, st *invState) {
			putWallet(dst, "w", 41)
			pw(dst, "q", 82, descJSON("q", "w", "w"))
			st.pres = append(st.pres, map[ports.NamedRef]string{ref("w", ports.StakingVKey): string(pair(40, "StakeSigningKeyShelley_ed25519", "StakeVerificationKeyShelley_ed25519", "Stake").vkey), ref("q", ports.PoolDescriptor): string(dst.files[ref("q", ports.PoolDescriptor)])})
		}},
	}
	for _, c := range cases {
		tr, dst := newTree(), newMem()
		st := &invState{dst: dst, renames: map[string]string{}}
		c.build(tr, dst, st)
		st.trs = []*memTree{tr}
		bad := oracleINV006(st)
		if !strings.Contains(strings.Join(bad, "\n"), c.want) {
			t.Errorf("%s: want a violation with %q, the oracle said %q", c.name, c.want, bad)
		}
	}
	// and a clean workspace is clean
	tr, dst := newTree(), newMem()
	putWallet(dst, "w", 40)
	putPool(dst, "p", 80, descJSON("p", "w", "w"))
	putWallet(tr.dir("/d"), "w", 40)
	putPool(tr.dir("/d"), "p", 80, descJSON("p", "w", "w"))
	if bad := oracleINV006(&invState{dst: dst, trs: []*memTree{tr}, renames: map[string]string{}}); len(bad) != 0 {
		t.Errorf("a clean workspace: %q", bad)
	}
}

// The workflows the new checks must leave alone: the same folder imported again
// with --overwrite, and a pool imported into a workspace that already holds its
// owner wallet.
//
// spec: SPO-Xmulti-OUT-019, SPO-Xmulti-INV-009
func TestXmultiLegitimateWorkflowsStillWork(t *testing.T) {
	tr, dst := newTree(), newMem()
	putWallet(tr.dir("/d"), "w", 40)
	putPool(tr.dir("/d"), "p", 80, descJSON("p", "w", "w"))
	for i, ow := range []bool{false, true} {
		rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true, ImportOptions: ImportOptions{Overwrite: ow}})
		if err != nil || rep.Failed() != 0 {
			t.Errorf("run %d (overwrite=%v): %v %+v", i, ow, err, rep.Owners)
		}
	}
	tr, dst = newTree(), newMem()
	putWallet(dst, "w", 40)
	putWallet(tr.dir("/d"), "w", 40)
	putPool(tr.dir("/d"), "p", 80, descJSON("p", "w", "w"))
	rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, Only: []Selector{{Name: "p"}}})
	if err != nil || !ownerOf(rep, "p").Written {
		t.Errorf("pool into a workspace holding its owner: %v %+v", err, ownerOf(rep, "p"))
	}
}
