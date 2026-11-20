package sqlitestore

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
)

func envKey(typ, label string) []byte {
	sum := sha256.Sum256([]byte("rename test " + label))
	pub := ed25519.NewKeyFromSeed(sum[:]).Public().(ed25519.PublicKey)
	return []byte(fmt.Sprintf(`{"type":%q,"description":"","cborHex":"5820%s"}`, typ, hex.EncodeToString(pub)))
}

type rowBytes struct {
	kind                           string
	version                        int64
	tag, nonce, wrapped, owner, ct []byte
}

func snapshotRows(t *testing.T, s *Store) map[string]rowBytes {
	t.Helper()
	rows, err := s.db.Query(`SELECT id, kind, version, lookup_tag, nonce, wrapped_key, owner_sealed, ciphertext FROM records`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]rowBytes{}
	for rows.Next() {
		var id []byte
		var r rowBytes
		if err := rows.Scan(&id, &r.kind, &r.version, &r.tag, &r.nonce, &r.wrapped, &r.owner, &r.ct); err != nil {
			t.Fatal(err)
		}
		out[string(id)] = r
	}
	return out
}

// Renaming an owner replaces one label record and no other record: the sealed
// bytes (payload, wrapped key, owner blob, lookup tag, version) of every key,
// address and certificate of the owner, its manifests and its owner record stay
// as they were (ADR 0010 decision 2).
//
// spec: SPO-Xidentity-INV-021
func TestRenameRewritesOneLabelRecordAndNothingElse(t *testing.T) {
	s, _ := newStore(t)
	n := labels.Named(s)
	for _, w := range []func(ports.NamedWriter) error{
		func(w ports.NamedWriter) error {
			return w.Put(ports.NamedRef{Name: "alice.payment", Kind: ports.AddrVKey}, envKey("PaymentVerificationKeyShelley_ed25519", "alice pay"))
		},
		func(w ports.NamedWriter) error {
			return w.Put(ports.NamedRef{Name: "alice", Kind: ports.StakingVKey}, envKey("StakeVerificationKeyShelley_ed25519", "alice stake"))
		},
		func(w ports.NamedWriter) error {
			return w.PutSecret(ports.NamedRef{Name: "alice.payment", Kind: ports.AddrSKey}, owned(secret.Take([]byte(`{"cborHex":"5820aa"}`))))
		},
		func(w ports.NamedWriter) error {
			return w.Put(ports.NamedRef{Name: "alice.payment", Kind: ports.AddrFile}, []byte("addr_test1qz\n"))
		},
		func(w ports.NamedWriter) error {
			return w.Put(ports.NamedRef{Name: "bob", Kind: ports.AddrVKey}, envKey("PaymentVerificationKeyShelley_ed25519", "bob pay"))
		},
	} {
		if err := n.Update(ctx, w); err != nil {
			t.Fatal(err)
		}
	}
	before := snapshotRows(t, s)
	auditBefore := count(t, s, "audit")

	if err := s.Update(ctx, func(w ports.Writer) error { return labels.Rename(w, identity.OwnerWallet, "alice", "carol") }); err != nil {
		t.Fatal(err)
	}
	after := snapshotRows(t, s)

	removed, added := 0, 0
	for id, b := range before {
		a, still := after[id]
		switch {
		case !still:
			if b.kind != string(ports.Label) {
				t.Errorf("a %s record was removed by a rename", b.kind)
			}
			removed++
		case a.version != b.version || string(a.nonce) != string(b.nonce) || string(a.wrapped) != string(b.wrapped) ||
			string(a.owner) != string(b.owner) || string(a.ct) != string(b.ct) || string(a.tag) != string(b.tag):
			t.Errorf("a %s record changed its bytes by a rename", b.kind)
		}
	}
	for id, a := range after {
		if _, was := before[id]; !was {
			if a.kind != string(ports.Label) {
				t.Errorf("a %s record was added by a rename", a.kind)
			}
			added++
		}
	}
	if removed != 1 || added != 1 {
		t.Fatalf("one label record replaced: removed %d, added %d", removed, added)
	}
	// the owner answers to the new name only, and the audit chain recorded it
	for name, want := range map[string]bool{"alice": false, "alice.payment": false, "carol": true, "carol.payment": true, "bob": true} {
		var ok bool
		_ = n.View(ctx, func(r ports.NamedReader) error {
			ok, _ = r.Exists(ports.NamedRef{Name: name, Kind: ports.AddrVKey})
			return nil
		})
		if ok != want {
			t.Errorf("addr.vkey of %q found: %v, want %v", name, ok, want)
		}
	}
	if count(t, s, "audit") != auditBefore+1 {
		t.Errorf("the rename is not one audit row")
	}
	if err := s.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	// a name another owner has is refused, and nothing changes
	if err := s.Update(ctx, func(w ports.Writer) error { return labels.Rename(w, identity.OwnerWallet, "bob", "carol") }); err == nil {
		t.Error("a second owner took an existing name")
	}
}
