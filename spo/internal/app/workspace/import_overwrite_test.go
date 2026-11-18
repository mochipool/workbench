package workspace

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/ports"
)

func overwriteRename(t *testing.T, tr *memTree, dst *memStore, from, to string) (*Report, error) {
	return multi(t, tr, dst).Import(ctx(), ImportRequest{
		Dirs: []string{"/d"}, All: true, Renames: []Rename{{From: Selector{Name: from}, To: to}},
		ImportOptions: ImportOptions{Overwrite: true},
	})
}

func snapshotOf(s *memStore) map[ports.NamedRef]string {
	out := map[ports.NamedRef]string{}
	for r, b := range s.files {
		out[r] = string(b)
	}
	return out
}

func sameFiles(a, b map[ports.NamedRef]string) bool {
	if len(a) != len(b) {
		return false
	}
	for r, v := range a {
		if b[r] != v {
			return false
		}
	}
	return true
}

func putPayment(s *memStore, name string, seed byte) keyPair {
	pk := payment(seed)
	s.put(ports.NamedRef{Name: name + ".payment", Kind: ports.AddrSKey}, pk.skey)
	s.put(ports.NamedRef{Name: name + ".payment", Kind: ports.AddrVKey}, pk.vkey)
	return pk
}

func hwsFor(vkey []byte) []byte {
	return []byte(`{"type":"StakeHWSigningFileShelley_ed25519","description":"Hardware","cborXPubKeyHex":"5840` + hex.EncodeToString(rawOf(vkey)) + strings.Repeat("00", 32) + `"}`)
}

// --overwrite into a workspace wallet that is a hardware wallet: the incoming
// stake keys would sit beside the hardware signing file of the old owner, so
// the owner is refused and the workspace keeps exactly what it held.
//
// spec: SPO-Xmulti-OUT-014, SPO-Xmulti-INV-006
func TestXmultiOverwriteRenameOntoHardwareWalletIsRefused(t *testing.T) {
	tr := newTree()
	putWallet(tr.dir("/d"), "a", 1)
	putPool(tr.dir("/d"), "p", 80, descJSON("p", "a", "a"))
	dst := newMem()
	putWallet(dst, "b", 2)
	delete(dst.files, ref("b", ports.StakingSKey))
	dst.put(ref("b", ports.StakingHwsFile), []byte(`{"type":"StakeHWSigningFileShelley_ed25519","description":"Hardware","cborXPubKeyHex":"58400000"}`))
	before := snapshotOf(dst)
	rep, _ := overwriteRename(t, tr, dst, "a", "b")
	if o := ownerOf(rep, "a"); o.Written || !strings.Contains(o.Reason, "staking.hwsfile") || !strings.Contains(o.Reason, "--rename") {
		t.Errorf("a: %+v", o)
	}
	if !sameFiles(before, snapshotOf(dst)) {
		t.Error("the workspace changed")
	}
	if stored(dst, "p", ports.PoolDescriptor) != "" {
		t.Error("the pool of the refused owner was stored")
	}
}

// A hardware signing file that stores the very verification key the owner
// ends up with belongs with it.
//
// spec: SPO-Xmulti-OUT-014
func TestXmultiOverwriteKeepsHardwareFileOfTheSameKey(t *testing.T) {
	tr := newTree()
	putWallet(tr.dir("/d"), "a", 1)
	dst := newMem()
	kp := pair(1, "StakeSigningKeyShelley_ed25519", "StakeVerificationKeyShelley_ed25519", "Stake")
	dst.put(ref("b", ports.StakingVKey), kp.vkey)
	dst.put(ref("b", ports.StakingHwsFile), hwsFor(kp.vkey))
	rep, err := overwriteRename(t, tr, dst, "a", "b")
	if o := ownerOf(rep, "a"); err != nil || !o.Written {
		t.Fatalf("%v %+v", err, o)
	}
	if _, ok := dst.files[ref("b", ports.StakingHwsFile)]; !ok {
		t.Error("the hardware file was deleted")
	}
}

// Workspace wallet with payment keys and no base address, incoming stake keys
// of another wallet: the result would be stake keys of a and payment keys of
// b, tied by nothing.
//
// spec: SPO-Xmulti-OUT-014, SPO-Xmulti-INV-006
func TestXmultiOverwriteRenameOntoPaymentOnlyWalletIsRefused(t *testing.T) {
	for _, addr := range []string{"none", "enterprise"} {
		tr := newTree()
		putWallet(tr.dir("/d"), "a", 1)
		dst := newMem()
		pk := putPayment(dst, "b", 3)
		if addr == "enterprise" {
			dst.put(ports.NamedRef{Name: "b.payment", Kind: ports.AddrFile}, addrOf(pk.vkey))
		}
		before := snapshotOf(dst)
		rep, _ := overwriteRename(t, tr, dst, "a", "b")
		if o := ownerOf(rep, "a"); o.Written || !strings.Contains(o.Reason, "b.payment/addr.vkey") {
			t.Errorf("%s: %+v", addr, o)
		}
		if !sameFiles(before, snapshotOf(dst)) {
			t.Errorf("%s: the workspace changed", addr)
		}
	}
}

// The same wallet with a base address that names the incoming stake key and
// the payment key: the payment keys provably belong with the stake keys.
//
// spec: SPO-Xmulti-OUT-014
func TestXmultiOverwriteKeepsPaymentKeysTiedByABaseAddress(t *testing.T) {
	tr := newTree()
	putWallet(tr.dir("/d"), "a", 1)
	stake := pair(1, "StakeSigningKeyShelley_ed25519", "StakeVerificationKeyShelley_ed25519", "Stake")
	dst := newMem()
	pk := putPayment(dst, "b", 3)
	ph, sh := keyHashOf(pk.vkey), keyHashOf(stake.vkey)
	dst.put(ports.NamedRef{Name: "b.payment", Kind: ports.AddrFile}, []byte("addr_"+hex.EncodeToString(ph[:])+"_"+hex.EncodeToString(sh[:])))
	rep, err := overwriteRename(t, tr, dst, "a", "b")
	if o := ownerOf(rep, "a"); err != nil || !o.Written {
		t.Fatalf("%v %+v", err, o)
	}
	if _, ok := dst.files[ports.NamedRef{Name: "b.payment", Kind: ports.AddrSKey}]; !ok {
		t.Error("the payment key was deleted")
	}
}

// A key kept in upstream's encrypted form cannot be checked against anything:
// it never counts as belonging to the incoming keys.
//
// spec: SPO-Xmulti-OUT-014, SPO-Xmulti-INV-006
func TestXmultiOverwriteOntoOwnerWithKeptEncryptedKeyIsRefused(t *testing.T) {
	tr := newTree()
	putWallet(tr.dir("/d"), "a", 1)
	dst := newMem()
	putWallet(dst, "b", 2)
	pk := payment(3)
	dst.put(ports.NamedRef{Name: "b.payment", Kind: ports.UpstreamEncryptedSKey}, encryptedOf(t, pk, "Correct-Horse-9"))
	dst.put(ports.NamedRef{Name: "b.payment", Kind: ports.AddrVKey}, pk.vkey)
	before := snapshotOf(dst)
	rep, _ := overwriteRename(t, tr, dst, "a", "b")
	if o := ownerOf(rep, "a"); o.Written || !strings.Contains(o.Reason, "encrypted") {
		t.Errorf("%+v", o)
	}
	if !sameFiles(before, snapshotOf(dst)) {
		t.Error("the workspace changed")
	}
}

// Importing an owner over itself, and adding the next numbered KES key and the
// updated counters to a pool of the same cold key, leave a coherent owner.
//
// spec: SPO-Xmulti-OUT-014
func TestXmultiOverwriteOfTheSameOwnerAndTheNextKesKeySucceed(t *testing.T) {
	tr := newTree()
	putWallet(tr.dir("/d"), "w", 40)
	dst := newMem()
	putWallet(dst, "w", 40)
	rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true, ImportOptions: ImportOptions{Overwrite: true}})
	if o := ownerOf(rep, "w"); err != nil || !o.Written {
		t.Fatalf("same wallet: %v %+v", err, o)
	}

	// the workspace pool holds KES key 1 and opcert 1; the source has KES key 2
	tr, dst = newTree(), newMem()
	putPool(dst, "p", 80, "")
	putPool(tr.dir("/d"), "p", 80, "")
	src := tr.dir("/d")
	delete(src.files, ports.NamedRef{Name: "p", Kind: ports.KesSKey, Num: 1})
	delete(src.files, ports.NamedRef{Name: "p", Kind: ports.KesVKey, Num: 1})
	delete(src.files, ports.NamedRef{Name: "p", Kind: ports.OpCert, Num: 1})
	src.put(ports.NamedRef{Name: "p", Kind: ports.KesSKey, Num: 2}, []byte(`{"type":"KesSigningKey_ed25519_kes_2^6","description":"KES Signing Key","cborHex":"5860`+strings.Repeat("ee", 96)+`"}`))
	src.put(ports.NamedRef{Name: "p", Kind: ports.KesVKey, Num: 2}, []byte(`{"type":"KesVerificationKey_ed25519_kes_2^6","description":"KES Verification Key","cborHex":"5820`+strings.Repeat("ef", 32)+`"}`))
	src.put(ports.NamedRef{Name: "p", Kind: ports.OpCert, Num: 2}, opcertOf(rawOf(cold(80).vkey), bytes.Repeat([]byte{0xef}, 32)))
	src.put(ref("p", ports.KesCounter), []byte("2\n"))
	src.put(ref("p", ports.KesCounterNext), []byte("2\n"))
	rep, err = multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true, ImportOptions: ImportOptions{Overwrite: true}})
	if o := ownerOf(rep, "p"); err != nil || !o.Written {
		t.Fatalf("next KES key: %v %+v", err, o)
	}
	for _, n := range []int{1, 2} {
		if _, ok := dst.files[ports.NamedRef{Name: "p", Kind: ports.KesVKey, Num: n}]; !ok {
			t.Errorf("KES key %d is not in the workspace", n)
		}
	}

	// the same import of a pool with another cold key must not leave the old
	// KES keys and opcerts under the new cold key
	tr, dst = newTree(), newMem()
	putPool(dst, "p", 80, "")
	putPool(tr.dir("/d"), "p", 81, "")
	delete(tr.dir("/d").files, ports.NamedRef{Name: "p", Kind: ports.KesSKey, Num: 1})
	delete(tr.dir("/d").files, ports.NamedRef{Name: "p", Kind: ports.KesVKey, Num: 1})
	delete(tr.dir("/d").files, ports.NamedRef{Name: "p", Kind: ports.OpCert, Num: 1})
	before := snapshotOf(dst)
	rep, _ = multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true, ImportOptions: ImportOptions{Overwrite: true}})
	if o := ownerOf(rep, "p"); o.Written || !strings.Contains(o.Reason, "node.opcert#1") {
		t.Errorf("another cold key: %+v", o)
	}
	if !sameFiles(before, snapshotOf(dst)) {
		t.Error("the workspace changed")
	}
}

// The plain form (one folder, no selection options) has not changed: it still
// stores into an owner that holds other artefacts, as it did at the commit
// before the extension.
//
// spec: SPO-Xmulti-PRE-009, SPO-Xmulti-OUT-013
func TestXmultiPlainFormOverwriteIsNotRefusedForLeftovers(t *testing.T) {
	src, dst := newMem(), newMem()
	putWallet(src, "a", 1)
	putWallet(dst, "a", 2)
	dst.put(ref("a", ports.StakingHwsFile), []byte(`{"type":"x","description":"y","cborXPubKeyHex":"5840"}`))
	rep, err := importer(src, dst, &fakeGPG{}).Run(ctx(), ImportOptions{Overwrite: true})
	if o := ownerOf(rep, "a"); err != nil || !o.Written {
		t.Fatalf("%v %+v", err, o)
	}
}
