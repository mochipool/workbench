package sqlitestore

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/layoutdir"
	"github.com/mochipool/workbench/spo/internal/app/layoutexport"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/layout"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// exportFixture exports the closed workspace f to a new directory with the real
// store, the real directory adapter and the use case, and returns the directory,
// the result and a copy of the snapshot that was exported.
func exportFixture(t *testing.T, f snapFix) (*layoutdir.Dir, string, layoutexport.Result, ports.Snapshot) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "layout")
	d, err := layoutdir.Open(root, f.path)
	if err != nil {
		t.Fatal(err)
	}
	ref, _, err := ReadSnapshot(context.Background(), f.path, f.cred())
	if err != nil {
		t.Fatal(err)
	}
	res, err := layoutexport.Run(context.Background(), layoutexport.Input{
		Dir:         layoutexport.Dir{Writer: d, Reader: d, Lister: d, Locker: d, Pins: d},
		WorkspaceID: ref.Meta.WorkspaceID,
		Now:         func() time.Time { return time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC) },
		Unlock: func(ctx context.Context) (layoutexport.Material, error) {
			m, err := TakeExport(ctx, f.path, f.cred())
			if err != nil {
				return layoutexport.Material{}, err
			}
			return layoutexport.Material{Snapshot: m.Snapshot, Refs: m.Refs, Sealer: m.Sealer, Notices: m.Facts.Notices, Close: m.Sealer.Close}, nil
		},
	})
	if err != nil {
		t.Fatalf("%s: %v", f.name, err)
	}
	return d, root, res, ref
}

func readTree(t *testing.T, root string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Name() == layoutdir.LockName {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			t.Fatal(rerr)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s has mode %v", rel, info.Mode().Perm())
		}
		out[filepath.ToSlash(rel)] = b
		return nil
	})
	return out
}

func classRule(kind string) (string, bool) {
	k := ports.Kind(kind)
	if !k.Known() {
		return "", false
	}
	return classOf(k), true
}

// Every fixture family is exported with the real store: the objects open with the
// workspace keys, carry the snapshot's bytes, name the anchor and number their
// owner blobs give, and a hot record opens from the fields of its object while a
// cold-role record does not open with the workspace keys alone. A second run
// finds everything and writes nothing.
//
// spec: SPO-Xlayout-INV-010, SPO-Xlayout-INV-011, SPO-Xlayout-INV-007, SPO-Xlayout-INV-008, SPO-Xlayout-INV-009, SPO-Xlayout-SEC-007, SPO-Xlayout-SEC-006, SPO-Xlayout-OUT-014, SPO-Xlayout-OUT-015, SPO-Xlayout-IF-001
func TestExportOfEveryFixtureFamilyWithTheRealStore(t *testing.T) {
	for _, b := range snapBuilders() {
		t.Run(b.name, func(t *testing.T) {
			f := b.build(t)
			d, root, res, want := exportFixture(t, f)
			if !res.HeadWritten || res.HeadSequence != 1 || res.ObjectsWritten == 0 {
				t.Fatalf("%+v", res)
			}
			tree := readTree(t, root)
			s := f.open(t, f.path)
			ws := want.Meta.WorkspaceID
			epoch := want.Meta.KeyEpoch

			byID := map[string]ports.SnapshotRecord{}
			for _, r := range want.Records {
				byID[string(r.ID)] = r
			}
			var rpages []layout.RecordPage
			var apages []layout.AuditPage
			recs, audits := 0, 0
			var root0 layout.Root
			var slotsObj layout.SlotsObject
			stored := map[string][]byte{}
			for p, bs := range tree {
				if strings.HasPrefix(p, "objects/") {
					stored[strings.TrimPrefix(p[len("objects/xx/"):], "")] = bs
				}
			}
			cold := 0
			var needles [][]byte // the anchors of the records and every form of the hash in them
			for name, bs := range stored {
				if layout.ObjectName(bs) != name {
					t.Fatalf("%s is not named by its hash", name)
				}
				if bs[0] == layout.FormatSlots {
					_, so, err := layout.ParseSlotsObject(bs)
					if err != nil {
						t.Fatal(err)
					}
					slotsObj = so
					continue
				}
				body, err := s.keys.OpenObject(bs, ws, epoch)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				obj, err := layout.DecodeBody(body, classRule)
				if err != nil {
					t.Fatal(err)
				}
				switch x := obj.(type) {
				case layout.Record:
					recs++
					needles = append(needles, anchorForms(x.Anchor)...)
					row, ok := byID[string(x.ID)]
					if !ok {
						t.Fatalf("a record object of %x is not in the snapshot", x.ID)
					}
					in := x.Inner
					if !bytes.Equal(in.Nonce, row.Nonce) || !bytes.Equal(in.WrappedKey, row.WrappedKey) || !bytes.Equal(in.Owner, row.OwnerSealed) || !bytes.Equal(in.Ciphertext, row.Ciphertext) {
						t.Errorf("%s: the inner fields of %x differ from the store's", f.name, x.ID)
					}
					if x.Kind != row.Kind || x.Version != uint64(row.Version) || x.UpdatedAt != row.UpdatedAt {
						t.Errorf("%s: the columns of %x differ", f.name, x.ID)
					}
					// INV-010: the anchor and number are those of the owner blob, and
					// the lookup tag recomputed from them is the row's
					sr := seal.SealedRecord{Nonce: in.Nonce, WrappedKey: in.WrappedKey, Owner: in.Owner, Ciphertext: in.Ciphertext}
					anchor, num, err := s.keys.OpenOwnerRef(ws, x.ID, x.Kind, sr)
					if err != nil || !bytes.Equal(anchor, x.Anchor) || num != x.Num {
						t.Errorf("%s: the anchor and number of %x are not the owner blob's (%v)", f.name, x.ID, err)
					}
					ref, err := identity.UnmarshalRef(x.Anchor)
					if err != nil {
						t.Fatal(err)
					}
					tag, err := tagFor(s.keys, ref, x.Kind, int(x.Num))
					if err != nil || !bytes.Equal(tag, row.LookupTag) {
						t.Errorf("%s: the lookup tag recomputed for %x is not the row's", f.name, x.ID)
					}
					// SEC-007: a hot record opens from the exported fields; a cold-role
					// record does not open with the workspace keys alone
					m := seal.RecordMeta{WorkspaceID: ws, RecordID: x.ID, Kind: x.Kind, Anchor: x.Anchor, Num: x.Num, Class: x.Class, Version: x.Version, Format: layout.RecordFormat}
					var oerr error
					if x.Class == layout.ClassSecret {
						var sb *secretBuf
						sb, oerr = openSecretBuf(s.keys, m, sr)
						sb.destroy()
					} else {
						_, oerr = s.keys.OpenRecord(m, sr)
					}
					isCold := len(in.WrappedKey) > 100 // the cold form is CBOR and far longer than a 72-byte hot wrap
					if isCold {
						cold++
						if oerr == nil {
							t.Errorf("%s: a cold-role record opened with the workspace keys alone", f.name)
						}
					} else if oerr != nil {
						t.Errorf("%s: a hot %s record does not open from the fields of its object: %v", f.name, x.Kind, oerr)
					}
				case layout.Audit:
					audits++
				case layout.RecordPage:
					rpages = append(rpages, x)
				case layout.AuditPage:
					apages = append(apages, x)
				case layout.Root:
					root0 = x
				}
			}
			if recs != len(want.Records) || audits != len(want.Audit) {
				t.Fatalf("%d records and %d audit objects for %d and %d rows", recs, audits, len(want.Records), len(want.Audit))
			}
			// order the pages as the root lists them, and verify the manifest
			byHash := func(h []byte) []byte { return stored[hexString(h)] }
			var rp []layout.RecordPage
			var ap []layout.AuditPage
			for _, h := range root0.RecordPages {
				body, _ := s.keys.OpenObject(byHash(h), ws, epoch)
				o, _ := layout.DecodeBody(body, classRule)
				rp = append(rp, o.(layout.RecordPage))
			}
			for _, h := range root0.AuditPages {
				body, _ := s.keys.OpenObject(byHash(h), ws, epoch)
				o, _ := layout.DecodeBody(body, classRule)
				ap = append(ap, o.(layout.AuditPage))
			}
			if err := layout.VerifyManifest(root0, rp, ap); err != nil {
				t.Fatal(err)
			}
			// INV-009: the root's audit head is the chain's
			if n := len(want.Audit); root0.AuditSeq != uint64(want.Audit[n-1].Seq) || !bytes.Equal(root0.AuditMAC, want.Audit[n-1].MAC) {
				t.Error("the root's audit head is not the chain's")
			}
			// INV-011: the slot-set hash is the newest slots or rollover row's
			h, err := layout.SlotSetHash(slotsObj.Meta.Policy, slotsObj.Slots)
			if err != nil {
				t.Fatal(err)
			}
			var newest []byte
			for _, a := range want.Audit {
				if a.Kind == "slots" || a.Kind == "rollover" {
					newest = a.SlotSet
				}
			}
			if newest != nil && !bytes.Equal(h, newest) {
				t.Errorf("%s: the slots object's hash is not the newest slot-table row's", f.name)
			}
			if !bytes.Equal(slotsObj.Meta.EpochMAC, want.Meta.EpochMAC) {
				t.Error("the epoch MAC changed")
			}
			// SEC-006: no test secret and no record kind in any byte written
			for p, bs := range tree {
				for _, sec := range f.secrets {
					for _, form := range secretForms(sec) {
						if bytes.Contains(bs, form) {
							t.Errorf("%s: %q is in %s (as %q)", f.name, sec, p, form)
						}
					}
				}
				if strings.HasPrefix(p, "objects/") && bs[0] == layout.FormatSealed {
					for _, r := range want.Records {
						if bytes.Contains(bs, []byte(r.Kind)) {
							t.Errorf("%s: the kind %q is in %s", f.name, r.Kind, p)
						}
					}
				}
			}
			for p, bs := range tree {
				for _, n := range needles {
					if len(n) >= 8 && bytes.Contains(bs, n) {
						t.Errorf("%s: a pool id, key hash or anchor (%.20q...) is in %s in the clear", f.name, n, p)
					}
				}
			}
			// a second run: nothing is put, no head, the pin does not move
			before := readTree(t, root)
			res2, err := layoutexport.Run(context.Background(), layoutexport.Input{
				Dir: layoutexport.Dir{Writer: d, Reader: d, Lister: d, Locker: d, Pins: d}, WorkspaceID: ws,
				Unlock: func(ctx context.Context) (layoutexport.Material, error) {
					s.Close() // the store handle of this test holds the file
					m, err := TakeExport(ctx, f.path, f.cred())
					if err != nil {
						return layoutexport.Material{}, err
					}
					return layoutexport.Material{Snapshot: m.Snapshot, Refs: m.Refs, Sealer: m.Sealer, Close: m.Sealer.Close}, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !res2.UpToDate || res2.ObjectsWritten != 0 || res2.HeadWritten {
				t.Fatalf("%s: a second export of an unchanged workspace: %+v", f.name, res2)
			}
			after := readTree(t, root)
			if len(after) != len(before) {
				t.Errorf("%s: the second export changed the directory", f.name)
			}
			t.Logf("%s: %d objects (%d records, %d audit rows, %d cold-role), head 1", f.name, res.ObjectsWritten, recs, audits, cold)
		})
	}
}

// secretForms are the byte strings a search for the test secret sec looks for:
// the secret as it is, and the forms a value written by the store would take (a
// CBOR text and byte string with their header, and quoted as JSON or TOML
// text). The raw form is searched for a secret of 8 bytes or more only. A
// shorter one cannot be: the written bytes are mostly ciphertext and hex text,
// and four given bytes occur in them by chance (once seen as a four-digit test
// PIN "in objects/cc/…"), so a raw match could not tell a leak from noise. The
// hardware fixtures' PINs (pinA, pinB, pinC) are long and not hex for that
// reason; the short fixture seeds are searched in the framed forms only.
func secretForms(sec string) [][]byte {
	if sec == "" {
		return nil
	}
	var forms [][]byte
	if len(sec) >= 8 {
		forms = append(forms, []byte(sec))
	}
	return append(forms,
		append(cborHead(0x60, len(sec)), sec...), // CBOR text string
		append(cborHead(0x40, len(sec)), sec...), // CBOR byte string
		[]byte(`"`+sec+`"`),
		[]byte(`'`+sec+`'`),
	)
}

// cborHead is the header of a CBOR string of major type mt and length n < 256.
func cborHead(mt byte, n int) []byte {
	if n < 24 {
		return []byte{mt | byte(n)}
	}
	return []byte{mt | 24, byte(n)}
}

// Every PIN of the hardware fixtures is searched for as it is: it is long
// enough, and has bytes that are not hex digits, so a raw match is a leak.
//
// spec: SPO-Xsnapshot-SEC-002
func TestTheFixturePINsAreSearchedForAsTheyAre(t *testing.T) {
	for _, p := range []string{pinA, pinB, pinC} {
		forms := secretForms(p)
		if len(p) < 8 || len(forms) == 0 || string(forms[0]) != p {
			t.Errorf("%q is not searched for raw", p)
		}
		nonHex := 0
		for _, r := range p {
			if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
				nonHex++
			}
		}
		if nonHex < 4 {
			t.Errorf("%q has %d bytes that are not hex digits", p, nonHex)
		}
	}
}

func hexString(b []byte) string { return hexOfBytes(b) }

func hexOfBytes(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 2*len(b))
	for i, c := range b {
		out[2*i], out[2*i+1] = digits[c>>4], digits[c&15]
	}
	return string(out)
}

type secretBuf struct{ b interface{ Destroy() } }

func (s *secretBuf) destroy() {
	if s != nil && s.b != nil {
		s.b.Destroy()
	}
}

func openSecretBuf(k *seal.Keys, m seal.RecordMeta, r seal.SealedRecord) (*secretBuf, error) {
	b, err := k.OpenSecret(m, r)
	if err != nil {
		return nil, err
	}
	return &secretBuf{b: b}, nil
}

// A workspace whose meta row was edited does not verify, so nothing is exported:
// the epoch MAC is checked by the verification the snapshot is taken through.
//
// spec: SPO-Xlayout-INV-017
func TestAnEditedEpochMACIsNotExported(t *testing.T) {
	s, path, _ := scratch(t)
	put(t, s, counter, "1")
	s.Close()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE meta SET epoch_mac = ?`, bytes.Repeat([]byte{7}, 32)); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, err := TakeExport(context.Background(), path, SnapshotCredential{Passphrase: passphrase(testPass)}); err == nil {
		t.Fatal("a workspace with an edited epoch MAC was exported")
	}
	ents, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".snapshot-") {
			t.Errorf("leftover %s", e.Name())
		}
	}
}

// A lookup tag that does not match its owner blob refuses the export; the
// sealer is destroyed on every error path.
//
// spec: SPO-Xlayout-INV-010, SPO-Xlayout-SEC-005
func TestAMismatchedLookupTagRefusesTheExportAndReleasesTheKeys(t *testing.T) {
	s, path, _ := scratch(t)
	put(t, s, counter, "1")
	s.Close()
	exportRefHook = func(tag *[]byte) { *tag = bytes.Repeat([]byte{1}, 32) }
	defer func() { exportRefHook = nil }()
	pw := passphrase(testPass)
	defer pw.Destroy()
	before := secret.Budget().Live
	if _, err := TakeExport(context.Background(), path, SnapshotCredential{Passphrase: pw}); err == nil || !strings.Contains(err.Error(), "lookup tag") {
		t.Fatalf("%v", err)
	}
	if got := secret.Budget().Live; got != before {
		t.Errorf("%d locked buffers after the refusal, %d before", got, before)
	}
	exportRefHook = nil
	m, err := TakeExport(context.Background(), path, SnapshotCredential{Passphrase: pw})
	if err != nil {
		t.Fatal(err)
	}
	if got := secret.Budget().Live; got != before+2 {
		t.Errorf("a live sealer holds %d buffers, want 2", got-before)
	}
	m.Sealer.Close()
	m.Sealer.Close()
	if got := secret.Budget().Live; got != before {
		t.Errorf("%d locked buffers after Close, %d before", got, before)
	}
	// an export holds no more than the sealer's two buffers beyond the open handle
	if m.CheckpointKey != nil {
		t.Error("a checkpoint key where there is none")
	}
}

// A panic inside the callback that takes the keys from the verified copy destroys
// the sealer before it goes on.
//
// spec: SPO-Xlayout-SEC-005
func TestAPanicWhileTakingTheExportReleasesTheKeys(t *testing.T) {
	s, path, _ := scratch(t)
	put(t, s, counter, "1")
	s.Close()
	pw := passphrase(testPass)
	defer pw.Destroy()
	exportRefHook = func(*[]byte) { panic("boom") }
	defer func() { exportRefHook = nil }()
	before := secret.Budget().Live
	func() {
		defer func() {
			if r := recover(); r != "boom" {
				t.Errorf("recovered %v", r)
			}
		}()
		TakeExport(context.Background(), path, SnapshotCredential{Passphrase: pw})
	}()
	if got := secret.Budget().Live; got != before {
		t.Errorf("%d locked buffers after a panic, %d before", got, before)
	}
}

// anchorForms are the byte and text forms in which the identity an anchor names
// could leak: the binary anchor, the hash in it raw and in hex, and its bech32
// forms as a pool id and as a key hash.
func anchorForms(anchor []byte) [][]byte {
	out := [][]byte{anchor}
	if len(anchor) > 2 {
		h := anchor[2:]
		out = append(out, h, []byte(hexOfBytes(h)), []byte(strings.ToUpper(hexOfBytes(h))), []byte(anchorHex(anchor)))
		for _, hrp := range []string{"pool", "stake", "stake_test", "addr_vkh", "drep", "cc_hot", "cc_cold"} {
			out = append(out, []byte(bech32Of(hrp, h)))
		}
	}
	return out
}

func anchorHex(a []byte) string { return hexOfBytes(a) }

// bech32Of encodes data under hrp (BIP 173).
func bech32Of(hrp string, data []byte) string {
	const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	var five []byte
	acc, bits := 0, 0
	for _, b := range data {
		acc = acc<<8 | int(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			five = append(five, byte(acc>>bits&31))
		}
	}
	if bits > 0 {
		five = append(five, byte(acc<<(5-bits)&31))
	}
	polymod := func(v []byte) uint32 {
		gen := []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
		chk := uint32(1)
		for _, x := range v {
			top := chk >> 25
			chk = chk&0x1ffffff<<5 ^ uint32(x)
			for i := 0; i < 5; i++ {
				if top>>i&1 == 1 {
					chk ^= gen[i]
				}
			}
		}
		return chk
	}
	var exp []byte
	for _, c := range hrp {
		exp = append(exp, byte(c>>5))
	}
	exp = append(exp, 0)
	for _, c := range hrp {
		exp = append(exp, byte(c&31))
	}
	pm := polymod(append(append(exp, five...), 0, 0, 0, 0, 0, 0)) ^ 1
	var sb strings.Builder
	sb.WriteString(hrp + "1")
	for _, v := range five {
		sb.WriteByte(charset[v])
	}
	for i := 0; i < 6; i++ {
		sb.WriteByte(charset[pm>>(5*(5-i))&31])
	}
	return sb.String()
}
