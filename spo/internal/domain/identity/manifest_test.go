package identity_test

import (
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/identity"
)

func kh(t *testing.T, seed byte) identity.Ref { return must(t)(identity.KeyHashOf(vk(seed))) }

func walletManifest(t *testing.T) (identity.Manifest, identity.Ref, identity.Ref) {
	t.Helper()
	pay, stake := kh(t, 20), kh(t, 21)
	m, err := identity.NewManifest(identity.OwnerWallet, pay, []identity.Member{{Role: identity.MemberPayment, Identity: pay}})
	if err != nil {
		t.Fatal(err)
	}
	return m, pay, stake
}

func poolManifest(t *testing.T) (identity.Manifest, identity.Ref) {
	t.Helper()
	cold := kh(t, 50)
	m, err := identity.NewManifest(identity.OwnerPool, cold, []identity.Member{{Role: identity.MemberCold, Identity: cold}})
	if err != nil {
		t.Fatal(err)
	}
	return m, cold
}

// spec: SPO-Xidentity-INV-013
func TestManifestIsImmutableAndAppendOnly(t *testing.T) {
	m1, pay, stake := walletManifest(t)
	id1 := must(t)(m1.ID())
	if id1.Kind() != identity.KindOwnerManifest || !m1.Predecessor().IsZero() || m1.Owner() != identity.OwnerWallet {
		t.Fatal("first version")
	}
	m2, err := m1.Add(identity.Member{Role: identity.MemberStake, Identity: stake})
	if err != nil {
		t.Fatal(err)
	}
	if len(m1.Members()) != 1 || must(t)(m1.ID()) != id1 {
		t.Error("Add changed the earlier version")
	}
	if m2.Predecessor() != id1 || m2.Anchor() != pay || len(m2.Members()) != 2 {
		t.Error("the next version names its predecessor by hash and keeps the anchor")
	}
	if err := m2.Extends(m1); err != nil {
		t.Error(err)
	}
	if err := m1.Extends(m2); err == nil {
		t.Error("a predecessor is not an extension of its successor")
	}
	other := kh(t, 22)
	if _, err := m2.Add(identity.Member{Role: identity.MemberStake, Identity: other}); !errors.Is(err, identity.ErrManifestAppend) {
		t.Errorf("replace a role: %v", err)
	}
	// One key may be a member under two roles of one owner (a wallet whose payment
	// and stake keys are one key); the owner is still anchored by the payment role.
	if same, err := m1.Add(identity.Member{Role: identity.MemberStake, Identity: pay}); err != nil {
		t.Errorf("the same key under a second role of one owner: %v", err)
	} else if err := same.CheckAnchor(pay); err != nil {
		t.Error(err)
	}
	// A forged "next version" with no predecessor link does not extend.
	forged, _ := identity.NewManifest(identity.OwnerWallet, pay, []identity.Member{{Role: "payment", Identity: pay}, {Role: "stake", Identity: other}})
	if err := forged.Extends(m1); err == nil {
		t.Error("a manifest with no predecessor link verified as an extension")
	}

	// KES keys are numbered: a second number is a new member, the same one a replacement.
	p1, cold := poolManifest(t)
	k := func(seed byte) identity.Ref { return must(t)(identity.KESKeyHashOf(vk(seed))) }
	p2, err := p1.Add(identity.Member{Role: identity.MemberKES, Num: 0, Identity: k(30)})
	if err != nil {
		t.Fatal(err)
	}
	p3, err := p2.Add(identity.Member{Role: identity.MemberKES, Num: 1, Identity: k(31)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p3.Add(identity.Member{Role: identity.MemberKES, Num: 1, Identity: k(32)}); !errors.Is(err, identity.ErrManifestAppend) {
		t.Error("replacing KES number 1")
	}
	if err := p3.Extends(p1); err == nil {
		t.Error("skipping a version must not verify as a direct extension")
	}
	if p3.Anchor() != cold {
		t.Error("the anchor changed")
	}
}

// spec: SPO-Xidentity-PRE-002, SPO-Xidentity-INV-013
func TestManifestVocabularyAndAnchorRule(t *testing.T) {
	pay, stake, other := kh(t, 20), kh(t, 21), kh(t, 22)
	vrf := must(t)(identity.VRFKeyHashOf(vk(60)))
	kes := must(t)(identity.KESKeyHashOf(vk(61)))
	script := identity.NativeScriptHashOf([]byte{1})
	M := func(role string, id identity.Ref) identity.Member { return identity.Member{Role: role, Identity: id} }
	cases := map[string]struct {
		owner   identity.OwnerKind
		anchor  identity.Ref
		members []identity.Member
	}{
		"no anchor":                    {identity.OwnerWallet, identity.Ref{}, []identity.Member{M("payment", pay)}},
		"anchor not a member":          {identity.OwnerWallet, other, []identity.Member{M("payment", pay)}},
		"unknown owner kind":           {"nothing", pay, []identity.Member{M("payment", pay)}},
		"empty role":                   {identity.OwnerWallet, pay, []identity.Member{M("", pay)}},
		"unknown role":                 {identity.OwnerWallet, pay, []identity.Member{M("payment", pay), M("bogus", other)}},
		"a pool role in a wallet":      {identity.OwnerWallet, pay, []identity.Member{M("payment", pay), M("vrf", vrf)}},
		"zero identity":                {identity.OwnerWallet, pay, []identity.Member{M("payment", pay), M("stake", identity.Ref{})}},
		"role twice":                   {identity.OwnerWallet, pay, []identity.Member{M("payment", pay), M("payment", other)}},
		"no members":                   {identity.OwnerWallet, pay, nil},
		"second payment key":           {identity.OwnerWallet, pay, []identity.Member{M("payment", pay), {Role: "payment", Num: 1, Identity: other}}},
		"number on an unnumbered role": {identity.OwnerWallet, pay, []identity.Member{{Role: "payment", Num: 3, Identity: pay}}},
		"wrong identity kind":          {identity.OwnerPool, other, []identity.Member{M("cold", other), M("vrf", kes)}},
		"kes by key hash":              {identity.OwnerPool, other, []identity.Member{M("cold", other), M("kes", stake)}},
		"wallet anchored by stake while it has payment": {identity.OwnerWallet, stake, []identity.Member{M("payment", pay), M("stake", stake)}},
		"pool anchored by vrf":                          {identity.OwnerPool, vrf, []identity.Member{M("cold", other), M("vrf", vrf)}},
		"policy needs a script hash":                    {identity.OwnerPolicy, pay, []identity.Member{M("script", pay)}},
	}
	for name, c := range cases {
		if _, err := identity.NewManifest(c.owner, c.anchor, c.members); !errors.Is(err, identity.ErrManifest) {
			t.Errorf("%s: %v", name, err)
		}
	}
	good := []struct {
		owner   identity.OwnerKind
		anchor  identity.Ref
		members []identity.Member
	}{
		{identity.OwnerWallet, pay, []identity.Member{M("payment", pay), M("stake", stake)}},
		{identity.OwnerWallet, stake, []identity.Member{M("stake", stake)}},                // stake-only wallet
		{identity.OwnerWallet, pay, []identity.Member{M("payment", pay), M("stake", pay)}}, // one key under two roles of one owner
		{identity.OwnerPool, other, []identity.Member{M("cold", other), M("vrf", vrf), {Role: "kes", Num: 7, Identity: kes}}},
		{identity.OwnerDRep, other, []identity.Member{M("drep", other)}},
		{identity.OwnerCommittee, other, []identity.Member{M("cold", other), M("hot", pay)}},
		{identity.OwnerPolicy, script, []identity.Member{M("script", script)}},
	}
	for i, c := range good {
		if _, err := identity.NewManifest(c.owner, c.anchor, c.members); err != nil {
			t.Errorf("case %d: %v", i, err)
		}
	}
	// A stake-only wallet that gains a payment key keeps its stake anchor.
	so, _ := identity.NewManifest(identity.OwnerWallet, stake, []identity.Member{M("stake", stake)})
	both, err := so.Add(M("payment", pay))
	if err != nil || both.Anchor() != stake || both.Extends(so) != nil {
		t.Errorf("stake-only wallet gaining a payment key: %v", err)
	}
	// A second payment key cannot be added at another number.
	m1, _, _ := walletManifest(t)
	if _, err := m1.Add(identity.Member{Role: "payment", Num: 1, Identity: other}); !errors.Is(err, identity.ErrManifest) {
		t.Errorf("second payment key: %v", err)
	}
}

// spec: SPO-Xidentity-INV-013, SPO-Xidentity-INV-009, SPO-Xidentity-INV-008
func TestManifestEncodingIsCanonicalAndOrderIndependent(t *testing.T) {
	_, pay, stake := walletManifest(t)
	a, _ := identity.NewManifest(identity.OwnerWallet, pay, []identity.Member{{Role: "payment", Identity: pay}, {Role: "stake", Identity: stake}})
	b, _ := identity.NewManifest(identity.OwnerWallet, pay, []identity.Member{{Role: "stake", Identity: stake}, {Role: "payment", Identity: pay}})
	if must(t)(a.ID()) != must(t)(b.ID()) {
		t.Error("the order members are given in changed the identity")
	}
	enc, err := a.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	back, err := identity.ParseManifest(enc)
	if err != nil || must(t)(back.ID()) != must(t)(a.ID()) || back.Owner() != identity.OwnerWallet {
		t.Fatalf("parse: %v", err)
	}
	if via := must(t)(identity.ContentOfEncoded(identity.TagOwnerManifest, enc)); via != must(t)(a.ID()) {
		t.Error("ID is the content hash of the canonical encoding")
	}
	m2, _ := a.Add(identity.Member{Role: "stake", Identity: kh(t, 99)})
	_ = m2
	p1, _ := poolManifest(t)
	p2, _ := p1.Add(identity.Member{Role: "vrf", Identity: must(t)(identity.VRFKeyHashOf(vk(40)))})
	enc2, _ := p2.Canonical()
	back2, err := identity.ParseManifest(enc2)
	if err != nil || back2.Predecessor() != must(t)(p1.ID()) {
		t.Errorf("predecessor lost on parse: %v", err)
	}
	for name, raw := range map[string][]byte{
		"trailing":       append(append([]byte(nil), enc...), 0),
		"indefinite":     append([]byte{0x9f}, append(append([]byte(nil), enc[1:]...), 0xff)...),
		"not a manifest": {0x01},
		"empty":          nil,
	} {
		if _, err := identity.ParseManifest(raw); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	ab, _ := pay.MarshalBinary()
	sb, _ := stake.MarshalBinary()
	unordered, _ := identity.EncodeCanonical([]any{"wallet", ab, nil, []any{[]any{"stake", uint64(0), sb}, []any{"payment", uint64(0), ab}}})
	if _, err := identity.ParseManifest(unordered); !errors.Is(err, identity.ErrManifest) {
		t.Errorf("members out of order: %v", err)
	}
	// A predecessor that is not an owner manifest identity is refused.
	notManifest := must(t)(identity.ContentOf(identity.TagAuditEvent, "x"))
	pb, _ := notManifest.MarshalBinary()
	bad, _ := identity.EncodeCanonical([]any{"wallet", ab, pb, []any{[]any{"payment", uint64(0), ab}}})
	if _, err := identity.ParseManifest(bad); !errors.Is(err, identity.ErrManifest) {
		t.Errorf("a predecessor of another content kind: %v", err)
	}
	tx := identity.TxIDOf([]byte{1})
	tb, _ := tx.MarshalBinary()
	bad, _ = identity.EncodeCanonical([]any{"wallet", ab, tb, []any{[]any{"payment", uint64(0), ab}}})
	if _, err := identity.ParseManifest(bad); !errors.Is(err, identity.ErrManifest) {
		t.Errorf("a predecessor that is a transaction id: %v", err)
	}
}

// spec: SPO-Xidentity-INV-014
func TestManifestAnchorCheck(t *testing.T) {
	m, pay, stake := walletManifest(t)
	if err := m.CheckAnchor(pay); err != nil {
		t.Error(err)
	}
	if err := m.CheckAnchor(stake); !errors.Is(err, identity.ErrAnchorMismatch) {
		t.Errorf("a manifest bound to another anchor was accepted: %v", err)
	}
	if err := m.CheckAnchor(identity.Ref{}); !errors.Is(err, identity.ErrAnchorMismatch) {
		t.Error("zero anchor")
	}
}
