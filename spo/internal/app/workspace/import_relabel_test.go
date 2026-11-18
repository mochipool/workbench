package workspace

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// A cold key relabelled as a VRF (or KES) key is refused on import, as the node
// export refuses it: the Ed25519 identity of the declared verification key has a
// role history, or is a member of an owner in a role other than KES or VRF.
//
// spec: SPO-Xcustody-PRE-017
func TestImportRefusesAColdKeyRelabelledAsVRFOrKES(t *testing.T) {
	other := cold(99)
	env, _ := pool.ParseEnvelope(other.vkey)
	pub, _ := env.Key32()
	eid, err := identity.KeyHashOf(pub)
	if err != nil {
		t.Fatal(err)
	}
	vrf := pool.MarshalEnvelope(pool.Envelope{Type: "VrfVerKey", Description: "VRF Verification Key", CborHex: "5820" + hexOf(pub)})
	kes := pool.MarshalEnvelope(pool.Envelope{Type: "KesVerificationKey_ed25519_kes_2^6", Description: "KES Verification Key", CborHex: "5820" + hexOf(pub)})

	hist := func(ctx context.Context, id identity.Ref) (custody.RoleHistory, bool, error) {
		if id != eid {
			return custody.RoleHistory{}, false, nil
		}
		h, err := custody.NewRoleHistory(id, custody.RolePoolCold)
		return h, true, err
	}
	homes := func(ctx context.Context, id identity.Ref) ([]ports.KeyHome, error) {
		if id != eid {
			return nil, nil
		}
		return []ports.KeyHome{{Role: custody.RolePayment, Identity: id}}, nil
	}
	for _, c := range []struct {
		name string
		kind ports.Kind
		num  int
		body []byte
		set  func(u *recImporter)
	}{
		{"vrf with a history", ports.VrfVKey, 0, vrf, func(u *recImporter) { u.History = hist }},
		{"vrf with a non-hot home", ports.VrfVKey, 0, vrf, func(u *recImporter) { u.Homes = homes }},
		{"kes with a history", ports.KesVKey, 1, kes, func(u *recImporter) { u.History = hist }},
	} {
		t.Run(c.name, func(t *testing.T) {
			tr, dst := newTree(), newMem()
			putWallet(tr.dir("/d"), "x", 1)
			putPool(tr.dir("/d"), "p", 80, descJSON("p", "x", "x"))
			tr.dir("/d").put(ports.NamedRef{Name: "p", Kind: c.kind, Num: c.num}, c.body)
			u := multi(t, tr, dst)
			c.set(&u)
			rep, err := u.Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true})
			if err != nil {
				t.Fatal(err)
			}
			o := ownerOf(rep, "p")
			if o.Written || !strings.Contains(o.Reason+" "+refReasons(o), ErrRelabelledHotKey.Error()) {
				t.Fatalf("p was imported or refused for another reason: %+v", o)
			}
		})
	}
	// without the check the same pool imports: the refusal is the check's
	tr, dst := newTree(), newMem()
	putWallet(tr.dir("/d"), "x", 1)
	putPool(tr.dir("/d"), "p", 80, descJSON("p", "x", "x"))
	tr.dir("/d").put(ports.NamedRef{Name: "p", Kind: ports.VrfVKey}, vrf)
	rep, err := multi(t, tr, dst).Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true})
	if err != nil {
		t.Fatal(err)
	}
	if o := ownerOf(rep, "p"); !o.Written {
		t.Fatalf("control import without the check failed: %+v", o)
	}
	_ = errors.Is
}

func refReasons(o OwnerReport) string {
	var b strings.Builder
	for _, a := range o.Artefacts {
		b.WriteString(a.Reason + " ")
	}
	return b.String()
}

func hexOf(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, x := range b {
		out = append(out, d[x>>4], d[x&15])
	}
	return string(out)
}

type leafDeriver struct {
	ports.HotVKeyDeriver
	leaf []byte
}

func (d leafDeriver) DeriveKESLeaf(context.Context, *ports.Secret) ([]byte, error) {
	return d.leaf, nil
}

// A cold key presented as a Calidus or a Catalyst voting key is refused, and a KES
// signing key whose leaf is a known cold key is refused although the verification
// key file declares another root.
//
// spec: SPO-Xcustody-PRE-017
func TestImportRelabelCheckCoversCalidusCatalystAndTheKESLeaf(t *testing.T) {
	other := cold(98)
	env, _ := pool.ParseEnvelope(other.vkey)
	pub, _ := env.Key32()
	eid, _ := identity.KeyHashOf(pub)
	hist := func(ctx context.Context, id identity.Ref) (custody.RoleHistory, bool, error) {
		if id != eid {
			return custody.RoleHistory{}, false, nil
		}
		h, err := custody.NewRoleHistory(id, custody.RolePoolCold)
		return h, true, err
	}
	vk := pool.MarshalEnvelope(pool.Envelope{Type: "VerificationKey_ed25519", CborHex: "5820" + hexOf(pub)})
	for _, kind := range []ports.Kind{ports.CalidusVKey, ports.VotingVKey} {
		tr, dst := newTree(), newMem()
		putWallet(tr.dir("/d"), "x", 1)
		tr.dir("/d").put(ports.NamedRef{Name: "x", Kind: kind}, vk)
		u := multi(t, tr, dst)
		u.History = hist
		rep, err := u.Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true})
		if err != nil {
			t.Fatal(err)
		}
		if o := ownerOf(rep, "x"); o.Written || !strings.Contains(o.Reason+" "+refReasons(o), ErrRelabelledHotKey.Error()) {
			t.Errorf("%s: %+v", kind, o)
		}
	}
	// the KES leaf
	own := pair(60, "KesSigningKey_ed25519_kes_2^6", "KesVerificationKey_ed25519_kes_2^6", "Kes")
	root := own.vkey
	tr, dst := newTree(), newMem()
	putWallet(tr.dir("/d"), "x", 1)
	putPool(tr.dir("/d"), "p", 80, descJSON("p", "x", "x"))
	tr.dir("/d").put(ports.NamedRef{Name: "p", Kind: ports.KesVKey, Num: 1}, root)
	tr.dir("/d").put(ports.NamedRef{Name: "p", Kind: ports.KesSKey, Num: 1}, own.skey)
	u := multi(t, tr, dst)
	u.History = hist
	u.HotDeriver = leafDeriver{leaf: pub}
	rep, err := u.Import(ctx(), ImportRequest{Dirs: []string{"/d"}, All: true})
	if err != nil {
		t.Fatal(err)
	}
	if o := ownerOf(rep, "p"); o.Written || !strings.Contains(o.Reason+" "+refReasons(o), ErrRelabelledHotKey.Error()) {
		t.Errorf("kes leaf: %+v", o)
	}
}
