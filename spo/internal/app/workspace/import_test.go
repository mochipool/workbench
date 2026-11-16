package workspace

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/keyfile"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func importer(src, dst *memStore, g *fakeGPG) ImportWorkspace {
	return ImportWorkspace{Source: src, SourceVault: src, Lister: src, Dest: dst, Decryptor: g, Deriver: edDeriver{}, Addresses: addrInspector{}}
}

func ref(name string, k ports.Kind) ports.Ref { return ports.Ref{Name: name, Kind: k} }

// Everything of a realistic workspace arrives; secrets are written with
// PutSecret (the memStore, like the real stores, refuses Put for them); the
// source is not touched.
//
// spec: SPO-Pfiles-OUT-001, SPO-Pfiles-OUT-002, SPO-Pfiles-OUT-005, SPO-Pfiles-OUT-010, SPO-Pfiles-OUT-011, SPO-Pfiles-OUT-013, SPO-Pfiles-OUT-014, SPO-Pfiles-SEC-001, SPO-Pfiles-IN-003
func TestImportWholeWorkspace(t *testing.T) {
	src, _ := workspaceFixture(t)
	dst := newMem()
	before := src.snapshot()
	rep, err := importer(src, dst, &fakeGPG{}).Run(context.Background(), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Failed() != 0 {
		t.Fatalf("report: %+v", rep)
	}
	if len(rep.Owners) != 2 || rep.Owners[0].Owner != "mypool" || rep.Owners[1].Owner != "w" {
		t.Errorf("owners: %+v", rep.Owners)
	}
	after := dst.snapshot()
	if len(after) != len(before) {
		t.Errorf("imported %d artefacts, source has %d", len(after), len(before))
	}
	for r, want := range before {
		if after[r] != want {
			t.Errorf("%v differs after import", r)
		}
	}
	// one atomic Update per owner
	if dst.updates != 2 {
		t.Errorf("updates: %d, want one per owner", dst.updates)
	}
	// the source is unchanged
	for r, want := range before {
		if src.snapshot()[r] != want {
			t.Errorf("source %v changed", r)
		}
	}
	// the stake account of a 03a wallet belongs to the same owner as the payment account
	for _, o := range rep.Owners {
		if o.Owner == "w" && len(o.Artefacts) != 6 {
			t.Errorf("wallet owner has %d artefacts: %+v", len(o.Artefacts), o.Artefacts)
		}
	}
}

// An encrypted key is decrypted with the operator's password and sealed as a
// plain envelope. One password opens many keys. A password with a backslash
// opens a key upstream encrypted with what its prompt produced.
//
// spec: SPO-Ckey-EXT-002, SPO-Ckey-OUT-002, SPO-Ckey-PR-003, SPO-Pfiles-OUT-003, SPO-Cui-IF-003
func TestImportDecryptsEncryptedKeysWithOnePasswordIncludingBackslash(t *testing.T) {
	src, keys := workspaceFixture(t)
	const typed = `Abc\def-12345` // what the operator types
	const stored = "Abcdef-12345" // what upstream's `read` stored and encrypted with
	src.put(ref("w.payment", ports.AddrSKey), encryptedOf(t, keys["pay"], stored))
	src.put(ref("w", ports.StakingSKey), encryptedOf(t, keys["stake"], stored))
	dst := newMem()
	g := &fakeGPG{}
	rep, err := importer(src, dst, g).Run(context.Background(), ImportOptions{Owners: []string{"w"}, Password: sec(typed)})
	if err != nil || rep.Failed() != 0 {
		t.Fatalf("%v %+v", err, rep)
	}
	got := dst.snapshot()[ref("w.payment", ports.AddrSKey)]
	info, cerr := keyfile.Classify([]byte(got))
	if cerr != nil || info.Form != keyfile.FormPlain {
		t.Fatalf("sealed key is not a plain envelope: %v %v", info, cerr)
	}
	if info.Description != "Payment Signing Key" {
		t.Errorf("description %q (the Encrypted prefix must be removed)", info.Description)
	}
	span, _ := keyfile.CborHexSpan([]byte(got))
	if string(span) != keys["pay"].cbor {
		t.Error("the decrypted key differs from the original")
	}
	// the typed form was tried first, then the stored form; the second key
	// goes straight to the form that worked.
	if len(g.seen) != 3 || g.seen[0] != typed || g.seen[1] != stored || g.seen[2] != stored {
		t.Errorf("passphrases tried: %q", g.seen)
	}
}

// Without a password an encrypted key fails its owner; with KeepEncrypted it
// is kept as an opaque record.
//
// spec: SPO-Pfiles-OUT-003
func TestImportEncryptedWithoutPassword(t *testing.T) {
	src, keys := workspaceFixture(t)
	src.put(ref("mypool", ports.NodeSKey), encryptedOf(t, keys["cold"], "Str0ng-Passw0rd!"))
	dst := newMem()
	rep, err := importer(src, dst, &fakeGPG{}).Run(context.Background(), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var pr OwnerReport
	for _, o := range rep.Owners {
		if o.Owner == "mypool" {
			pr = o
		}
	}
	if pr.Written {
		t.Fatal("a pool with an encrypted key and no password was imported")
	}
	for r := range dst.snapshot() {
		if OwnerOf(r) == "mypool" {
			t.Errorf("%v was written for a failed owner", r)
		}
	}
	// the wallet is independent
	if rep.Failed() != 1 {
		t.Errorf("failed owners: %d", rep.Failed())
	}
	// keep-encrypted
	dst = newMem()
	rep, err = importer(src, dst, &fakeGPG{}).Run(context.Background(), ImportOptions{Owners: []string{"mypool"}, KeepEncrypted: true})
	if err != nil || rep.Failed() != 0 {
		t.Fatalf("%v %+v", err, rep)
	}
	kept := dst.snapshot()[ref("mypool.node", ports.UpstreamEncryptedSKey)]
	if info, _ := keyfile.Classify([]byte(kept)); info.Form != keyfile.FormEncrypted {
		t.Error("the kept record is not the encrypted envelope")
	}
	if _, ok := dst.snapshot()[ref("mypool", ports.NodeSKey)]; ok {
		t.Error("a signing key record was made from an undecrypted key")
	}
}

// A wrong password fails the owner with no partial import.
//
// spec: SPO-Ckey-PRE-007
func TestImportWrongPasswordImportsNothingOfTheOwner(t *testing.T) {
	src, keys := workspaceFixture(t)
	src.put(ref("w.payment", ports.AddrSKey), encryptedOf(t, keys["pay"], "Str0ng-Passw0rd!"))
	dst := newMem()
	rep, _ := importer(src, dst, &fakeGPG{}).Run(context.Background(), ImportOptions{Owners: []string{"w"}, Password: sec("Wrong-Passw0rd!x")})
	if rep.Failed() != 1 || len(dst.snapshot()) != 0 {
		t.Fatalf("failed=%d, destination holds %d artefacts", rep.Failed(), len(dst.snapshot()))
	}
	found := false
	for _, a := range rep.Owners[0].Artefacts {
		if a.Status == StatusFailed && strings.Contains(a.Reason, "password") {
			found = true
		}
		if a.Status == StatusDone {
			t.Errorf("%v reported done in a failed owner", a.Ref)
		}
	}
	if !found {
		t.Error("the wrong password is not named in the report")
	}
}

// H8: a damaged encrypted envelope is refused at once, before gpg, and never
// as a wrong password.
//
// spec: SPO-Ckey-PRE-003, SPO-Ckey-PRE-006, SPO-Ckey-PRE-010
func TestImportMalformedEncryptedFailsFastWithoutDecrypting(t *testing.T) {
	src, keys := workspaceFixture(t)
	good := encryptedOf(t, keys["pay"], "Str0ng-Passw0rd!")
	for name, bad := range map[string][]byte{
		"truncated":  good[:len(good)-8],
		"no hex":     []byte(`{"type":"PaymentSigningKeyShelley_ed25519","description":"Encrypted x","encrHex":"zzzz"}`),
		"no type":    []byte(`{"description":"Encrypted x","encrHex":"` + strings.Repeat("ab", 40) + `"}`),
		"not json":   []byte("encrHex garbage"),
		"empty file": nil,
	} {
		s2, _ := workspaceFixture(t)
		s2.put(ref("w.payment", ports.AddrSKey), bad)
		g := &fakeGPG{}
		rep, err := importer(s2, newMem(), g).Run(context.Background(), ImportOptions{Owners: []string{"w"}, Password: sec("Str0ng-Passw0rd!")})
		if err != nil || rep.Failed() != 1 {
			t.Errorf("%s: %v %+v", name, err, rep)
			continue
		}
		if g.decrypts != 0 {
			t.Errorf("%s: gpg was asked %d times about a damaged file", name, g.decrypts)
		}
		for _, a := range rep.Owners[0].Artefacts {
			if a.Status == StatusFailed && strings.Contains(a.Reason, "password") && !strings.Contains(a.Reason, "damaged") {
				t.Errorf("%s: reported as a wrong password: %s", name, a.Reason)
			}
		}
	}
	_ = src
}

// Nothing of an owner is imported when a consistency check fails.
//
// spec: SPO-Pfiles-OUT-002, SPO-Pfiles-OUT-001, SPO-Pfiles-OUT-011, SPO-Pfiles-OUT-013
func TestImportConsistencyChecksRefuseTheWholeOwner(t *testing.T) {
	other := payment(9)
	cases := map[string]func(s *memStore, k map[string]keyPair){
		"vkey of another key": func(s *memStore, k map[string]keyPair) {
			s.put(ref("w.payment", ports.AddrVKey), other.vkey)
		},
		"address of another key": func(s *memStore, k map[string]keyPair) {
			s.put(ref("w.payment", ports.AddrFile), addrOf(other.vkey))
		},
		"node counter of another cold key": func(s *memStore, k map[string]keyPair) {
			var vk [32]byte
			env, _ := pool.ParseEnvelope(other.vkey)
			kb, _ := env.Key32()
			copy(vk[:], kb)
			s.put(ref("mypool", ports.NodeCounter), pool.IssueCounter{Next: 1, ColdVKey: vk}.Envelope())
		},
		"kes counters disagree": func(s *memStore, k map[string]keyPair) {
			s.put(ref("mypool", ports.KesCounterNext), pool.FormatCounter(5))
		},
		"kes counter is not a number": func(s *memStore, k map[string]keyPair) {
			s.put(ref("mypool", ports.KesCounter), []byte("one\n"))
		},
		"next counter without current": func(s *memStore, k map[string]keyPair) {
			delete(s.files, ref("mypool", ports.KesCounter))
		},
	}
	for name, mutate := range cases {
		src, keys := workspaceFixture(t)
		mutate(src, keys)
		dst := newMem()
		rep, err := importer(src, dst, &fakeGPG{}).Run(context.Background(), ImportOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if rep.Failed() != 1 {
			t.Errorf("%s: %d owners failed, want 1", name, rep.Failed())
			continue
		}
		bad := "w"
		if strings.Contains(name, "counter") {
			bad = "mypool"
		}
		for r := range dst.snapshot() {
			if OwnerOf(r) == bad {
				t.Errorf("%s: %v of the failed owner was written", name, r)
			}
		}
		if len(dst.snapshot()) == 0 {
			t.Errorf("%s: the other owner was not imported", name)
		}
	}
}

// The report and every error hold no secret material.
//
// spec: SPO-Pfiles-SEC-001, SPO-Ckey-SEC-002
func TestReportHoldsNoSecret(t *testing.T) {
	src, keys := workspaceFixture(t)
	const pw = "Zq8!unique-password-xx"
	src.put(ref("w.payment", ports.AddrSKey), encryptedOf(t, keys["pay"], pw))
	src.unknown = append(src.unknown, ports.SourceUnknown{File: "notes.txt", Reason: "not an artefact of the upstream catalogue"})
	dst := newMem()
	for _, password := range []string{pw, "Wrong-Passw0rd!x"} {
		rep, err := importer(src, dst, &fakeGPG{}).Run(context.Background(), ImportOptions{Password: sec(password), Overwrite: true})
		if err != nil {
			t.Fatal(err)
		}
		text := fmt.Sprintf("%+v %v", rep, err)
		for _, needle := range []string{pw, "Wrong-Passw0rd", keys["pay"].cbor[4:20], keys["cold"].cbor[4:20], "abandon ability"} {
			if strings.Contains(text, needle) {
				t.Errorf("the report contains secret material %q", needle)
			}
		}
	}
}

// Unknown files are reported and never imported; an unknown owner name is an
// error; an owner already in the destination is not overwritten by default.
//
// spec: SPO-Pfiles-IN-001
func TestImportUnknownFilesOwnersAndConflicts(t *testing.T) {
	src, _ := workspaceFixture(t)
	src.unknown = []ports.SourceUnknown{{File: "notes.txt", Reason: "not an artefact of the upstream catalogue"}}
	dst := newMem()
	imp := importer(src, dst, &fakeGPG{})
	if _, err := imp.Run(context.Background(), ImportOptions{Owners: []string{"nobody"}}); !errors.Is(err, ErrNoSuchOwner) {
		t.Errorf("unknown owner: %v", err)
	}
	rep, err := imp.Run(context.Background(), ImportOptions{Owners: []string{"mypool"}})
	if err != nil || rep.Failed() != 0 || len(rep.Unknown) != 1 || rep.Unknown[0].File != "notes.txt" {
		t.Fatalf("%v %+v", err, rep)
	}
	for r := range dst.snapshot() {
		if OwnerOf(r) != "mypool" {
			t.Errorf("%v: only the named owner may be imported", r)
		}
	}
	rep, _ = imp.Run(context.Background(), ImportOptions{Owners: []string{"mypool"}})
	if rep.Failed() != 1 || !strings.Contains(rep.Owners[0].Reason, "Overwrite") {
		t.Errorf("a second import must be refused without Overwrite: %+v", rep.Owners)
	}
	rep, _ = imp.Run(context.Background(), ImportOptions{Owners: []string{"mypool"}, Overwrite: true})
	if rep.Failed() != 0 {
		t.Errorf("Overwrite: %+v", rep.Owners)
	}
}

// Hardware signing files are imported as plain records; the descriptor with a
// regProtectionKey is reported; a key file that is a hardware file is refused.
//
// spec: SPO-Pfiles-OUT-004, SPO-Pfiles-OUT-017, SPO-Pfiles-SEC-001
func TestImportHardwareFilesAndDescriptor(t *testing.T) {
	src := newMem()
	hw := []byte(`{"type":"PaymentHWSigningFileShelley_ed25519","description":"Payment Hardware Signing File","path":["1852H","1815H","0H","0","0"],"cborXPubKeyHex":"5840aa"}`)
	src.put(ref("h", ports.AddrHwsFile), hw)
	src.put(ref("p", ports.PoolDescriptor), []byte(`{"poolName":"p","regProtectionKey":"top-secret-value"}`))
	dst := newMem()
	rep, err := importer(src, dst, &fakeGPG{}).Run(context.Background(), ImportOptions{})
	if err != nil || rep.Failed() != 0 {
		t.Fatalf("%v %+v", err, rep)
	}
	if dst.snapshot()[ref("h", ports.AddrHwsFile)] != string(hw) {
		t.Error("hardware file not imported verbatim")
	}
	if len(rep.Warnings) < 1 || !strings.Contains(strings.Join(rep.Warnings, "|"), "regProtectionKey") {
		t.Errorf("warnings: %q", rep.Warnings)
	}
	if strings.Contains(fmt.Sprint(rep), "top-secret-value") {
		t.Error("the report holds the regProtectionKey value")
	}
	// a hardware file under a signing key name
	src2 := newMem()
	src2.put(ref("h", ports.AddrSKey), hw)
	rep, _ = importer(src2, newMem(), &fakeGPG{}).Run(context.Background(), ImportOptions{})
	if rep.Failed() != 1 {
		t.Errorf("a hardware file named .skey must fail: %+v", rep)
	}
}

// Decision: a plaintext key whose description contains "Encrypted" is plain
// (upstream would loop on prompts for it).
//
// spec: SPO-Ckey-IN-001, SPO-Ckey-OUT-003
func TestImportPlainKeyWithEncryptedInItsDescription(t *testing.T) {
	src := newMem()
	kp := pair(3, "PaymentSigningKeyShelley_ed25519", "PaymentVerificationKeyShelley_ed25519", "Encrypted Payment")
	src.put(ref("e", ports.AddrSKey), kp.skey)
	src.put(ref("e", ports.AddrVKey), kp.vkey)
	dst := newMem()
	rep, _ := importer(src, dst, &fakeGPG{}).Run(context.Background(), ImportOptions{})
	if rep.Failed() != 0 {
		t.Fatalf("%+v", rep)
	}
	if dst.snapshot()[ref("e", ports.AddrSKey)] != string(kp.skey) {
		t.Error("the key was altered")
	}
}

// Without a deriver the checks are skipped and the report says so.
func TestImportWithoutDeriverSaysSo(t *testing.T) {
	src, _ := workspaceFixture(t)
	imp := importer(src, newMem(), &fakeGPG{})
	imp.Deriver, imp.Addresses = nil, nil
	rep, _ := imp.Run(context.Background(), ImportOptions{})
	if rep.Failed() != 0 || len(rep.Warnings) == 0 {
		t.Errorf("%+v", rep)
	}
}

func TestStemsRoundTrip(t *testing.T) {
	for _, r := range []ports.Ref{
		{Name: "p", Kind: ports.NodeSKey}, {Name: "p", Kind: ports.KesSKey, Num: 3}, {Name: "w.payment", Kind: ports.AddrSKey},
		{Name: "w", Kind: ports.StakingSKey}, {Name: "d", Kind: ports.DRepSKey}, {Name: "p", Kind: ports.VrfSKey},
	} {
		stem, ok := KeyStem(r)
		back, ok2 := SKeyRefFromStem(stem)
		if !ok || !ok2 || back != r {
			t.Errorf("%v -> %q -> %v", r, stem, back)
		}
	}
}
