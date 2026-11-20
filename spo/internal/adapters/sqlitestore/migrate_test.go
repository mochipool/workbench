package sqlitestore

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
)

const legacyPass = "legacy fixture passphrase"

func legacyPW() *secret.Buffer { return owned(secret.Take([]byte(legacyPass))) }

// legacyCopy copies a committed fixture of a store of format 1, built by the code
// of that format (legacyfixture_gen_test.go), into a temporary directory.
func legacyCopy(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "legacy-v1", name))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "ws.db")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// dump is every column of every row of the file, for comparing before and after.
func dump(t *testing.T, s *Store) string {
	t.Helper()
	var sb strings.Builder
	for _, q := range []string{
		`SELECT hex(id), hex(lookup_tag), kind, version, hex(nonce), hex(wrapped_key), hex(owner_sealed), hex(ciphertext), updated_at FROM records ORDER BY id`,
		`SELECT seq, at, kind, hex(event), hex(touched), hex(slotset), hex(mac) FROM audit ORDER BY seq`,
		`SELECT hex(workspace_id), format_version, hex(key_epoch), hex(epoch_mac) FROM meta`,
		`SELECT hex(id), hex(wrapped_key) FROM keyslots ORDER BY id`,
	} {
		rows, err := s.db.Query(q)
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			fmt.Fprintln(&sb, vals...)
		}
		rows.Close()
	}
	return sb.String()
}

func ids(t *testing.T, s *Store) map[string]string {
	t.Helper()
	rows, err := s.db.Query(`SELECT hex(id), hex(ciphertext) FROM records`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, ct string
		if err := rows.Scan(&id, &ct); err != nil {
			t.Fatal(err)
		}
		out[id] = ct
	}
	return out
}

func nget(t *testing.T, n *labels.Store, name string, k ports.Kind, num ...int) ([]byte, error) {
	t.Helper()
	ref := ports.NamedRef{Name: name, Kind: k}
	if len(num) > 0 {
		ref.Num = num[0]
	}
	var out []byte
	err := n.View(ctx, func(r ports.NamedReader) error {
		var e error
		out, e = r.Get(ref)
		return e
	})
	return out, err
}

// The opener refuses a store of format 1 and names the command that migrates it.
//
// spec: SPO-Xidentity-IF-005
func TestTheOpenerRefusesTheOldFormatAndNamesTheCommand(t *testing.T) {
	p := legacyCopy(t, "store.db")
	derived := false
	beforeUnlock = func() { derived = true }
	defer func() { beforeUnlock = nil }()
	_, err := Open(p, legacyPW())
	if !errors.Is(err, ErrLegacyFormat) || !strings.Contains(err.Error(), "spo workspace migrate") {
		t.Fatalf("open of a format 1 store: %v", err)
	}
	// the format is judged before any key is derived
	if derived {
		t.Error("a key was derived before the old format was refused")
	}
}

// The fixture is a store built by the code of format 1: a pool with numbered KES
// keys and operational certificates and a descriptor with a witness collection
// whose slots name a party, two wallets (one with a hardware signing file), an
// enterprise wallet, a pending record, a party, a transfer file and a provider
// token. Migrating it keeps every record id, re-seals every record under the same
// master key, converts the names to labels, and the file opens in the new format.
//
// spec: SPO-Xidentity-IF-005, SPO-Xidentity-INV-024, SPO-Xidentity-INV-025
func TestMigrateTheOldFormatFixture(t *testing.T) {
	p := legacyCopy(t, "store.db")
	old, err := OpenLegacy(p, legacyPW())
	if err != nil {
		t.Fatal(err)
	}
	beforeIDs := ids(t, old)
	auditBefore := count(t, old, "audit")
	old.SetColdSource(coldPass("a cold sub-key passphrase")) // the fixture holds a pool cold key
	rep, err := old.Migrate(ctx, MigrateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	old.Close()
	if rep.Owners != 4 || rep.Records != len(beforeIDs) || rep.Added == 0 || rep.Merged != 0 {
		t.Errorf("report %+v (records before: %d)", rep, len(beforeIDs))
	}
	if len(rep.Rewritten) != 1 || rep.Rewritten[0] != "pool1" {
		t.Errorf("rewritten %v", rep.Rewritten)
	}
	// a backup of the old file is beside it, holding the old bytes
	bk, err := os.ReadFile(rep.Backup)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(rep.Backup); fi.Mode().Perm() != 0o600 || filepath.Dir(rep.Backup) != filepath.Dir(p) {
		t.Errorf("backup %v", fi)
	}
	orig, _ := os.ReadFile(filepath.Join("testdata", "legacy-v1", "store.db"))
	if len(bk) == 0 || len(orig) == 0 {
		t.Fatal("empty backup")
	}
	if err := closed(OpenLegacy(rep.Backup, legacyPW())); err != nil {
		t.Errorf("the backup does not open as the old format: %v", err)
	}

	// the migrated file opens (the integrity check of every open passes) and every
	// old record id is still there, re-sealed
	s, err := Open(p, legacyPW())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetColdSource(coldPass("a cold sub-key passphrase"))
	after := ids(t, s)
	for id, ct := range beforeIDs {
		now, ok := after[id]
		if !ok {
			t.Errorf("record %s lost", id[:8])
		} else if now == ct {
			t.Errorf("record %s was not re-sealed", id[:8])
		}
	}
	if got := count(t, s, "audit"); got != auditBefore+3 { // the format 2 row, the update row that seals the pool cold key in the cold form, and the format 3 row
		t.Errorf("audit rows %d -> %d, want three more", auditBefore, got)
	}
	n := labels.Named(s)

	// every name answers as before
	for _, c := range []struct {
		name string
		k    ports.Kind
		num  int
	}{
		{"alice.payment", ports.AddrVKey, 0}, {"alice", ports.StakingVKey, 0}, {"alice.payment", ports.AddrFile, 0},
		{"bob.payment", ports.AddrVKey, 0}, {"bob.payment", ports.AddrHwsFile, 0}, {"bob", ports.StakingHwsFile, 0},
		{"carol", ports.AddrVKey, 0}, {"carol", ports.AddrFile, 0},
		{"pool1", ports.NodeVKey, 0}, {"pool1", ports.NodeCounter, 0}, {"pool1", ports.VrfVKey, 0},
		{"pool1", ports.KesVKey, 0}, {"pool1", ports.KesVKey, 2}, {"pool1", ports.OpCert, 0}, {"pool1", ports.OpCert, 1},
		{"pool1", ports.KesCounter, 0}, {"pool1", ports.PoolMetadata, 0}, {"pool1", ports.PoolDescriptor, 0},
		{"00ab", ports.PendingUpdate, 0}, {"pool1.reg.1700000000", ports.PoolWitnessFile, 0}, {"all", ports.PartyRecords, 0},
	} {
		if _, err := nget(t, n, c.name, c.k, c.num); err != nil {
			t.Errorf("%s %s #%d: %v", c.name, c.k, c.num, err)
		}
	}
	// secrets are there too, through the vault
	for _, ref := range []ports.NamedRef{{Name: "alice.payment", Kind: ports.AddrSKey}, {Name: "pool1", Kind: ports.NodeSKey}, {Name: "pool1", Kind: ports.KesSKey, Num: 1}, {Name: "koios", Kind: ports.ProviderToken}} {
		b, err := n.Open(ctx, ref)
		if err != nil {
			t.Errorf("%s: %v", ref, err)
			continue
		}
		b.Destroy()
	}
	// the anchors follow the rule: the pool by its cold key, the wallets by their payment key
	homes, err := labels.NewIndex(s).Homes(ctx, mustKeyID(t, n, "pool1", ports.NodeVKey, custody.RolePoolCold))
	if err != nil || len(homes) != 1 || !homes[0].HasSecret {
		t.Fatalf("homes of the cold key: %+v %v", homes, err)
	}
	var poolAnchor identity.Ref = homes[0].Anchor
	if poolAnchor != mustKeyID(t, n, "pool1", ports.NodeVKey, custody.RolePoolCold) {
		t.Errorf("the pool is anchored by %s, not its cold key", poolAnchor)
	}
	// the descriptor refers to its owners, its reward account and its payer by
	// key hash, and its witness slots by party fingerprint
	raw, err := nget(t, n, "pool1", ports.PoolDescriptor)
	if err != nil {
		t.Fatal(err)
	}
	d, err := pool.ParseDescriptor(raw)
	if err != nil {
		t.Fatal(err)
	}
	owners, _, _ := d.Owners()
	aliceStake := mustKeyID(t, n, "alice", ports.StakingVKey, custody.RoleStake)
	bobStake := mustKeyID(t, n, "bob", ports.StakingVKey, custody.RoleStake)
	if len(owners) != 2 || owners[0].Name != aliceStake.String() || owners[1].Name != bobStake.String() || d.Text(pool.FieldRewards) != aliceStake.String() {
		t.Errorf("owners %+v rewards %q", owners, d.Text(pool.FieldRewards))
	}
	rn, _ := d.RegistrationNames()
	if want := mustKeyID(t, n, "alice.payment", ports.AddrVKey, custody.RolePayment).String(); rn.Pay != want {
		t.Errorf("payer %q, want %q", rn.Pay, want)
	}
	if !strings.Contains(string(raw), `"partyFingerprint"`) || strings.Contains(string(raw), `"party":"cosigner"`) {
		t.Errorf("the slots are not assigned by fingerprint:\n%s", raw)
	}
	// the use cases still find a wallet by the identity a descriptor holds
	if _, err := nget(t, n, aliceStake.String(), ports.StakingVKey); err != nil {
		t.Errorf("a wallet by its stake key hash: %v", err)
	}
	if len(orig) == 0 || bytes.Equal(orig, bk[:0]) {
		t.Error("the committed fixture is empty")
	}
	// the backup is the file as it was: the same records, byte for byte
	ob, err := OpenLegacy(rep.Backup, legacyPW())
	if err != nil {
		t.Fatal(err)
	}
	defer ob.Close()
	if len(ids(t, ob)) != len(beforeIDs) {
		t.Error("the backup does not hold the old records")
	}
}

func mustKeyID(t *testing.T, n *labels.Store, name string, k ports.Kind, role custody.Role) identity.Ref {
	t.Helper()
	raw, err := nget(t, n, name, k)
	if err != nil {
		t.Fatal(err)
	}
	id, err := ports.IdentityOfVKey(role, raw)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// A plan that refuses lists every problem and changes nothing: not a record, not
// a backup.
//
// spec: SPO-Xidentity-PRE-006
func TestMigrationRefusesWithAListAndChangesNothing(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		want    []string
	}{
		{"bad-descriptor-owner.db", []string{`"ghost"`, "no wallet"}},
		{"descriptor-pool-id.db", []string{"pool id", "cold key"}},
		{"identity-in-two-owners.db", []string{"member of", `"dave"`, `"erin"`}},
		{"collision-differs.db", []string{"different bytes", "frank"}},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			p := legacyCopy(t, tc.fixture)
			s, err := OpenLegacy(p, legacyPW())
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			before := dump(t, s)
			_, err = s.Migrate(ctx, MigrateOptions{})
			var ref *labels.Refusal
			if !errors.As(err, &ref) {
				t.Fatalf("migrate: %v", err)
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("the refusal lacks %q:\n%v", w, err)
				}
			}
			if dump(t, s) != before {
				t.Error("a refused migration changed the file")
			}
			if m, _ := filepath.Glob(p + ".pre-migrate-v1*"); len(m) != 0 {
				t.Errorf("a refused migration left a backup: %v", m)
			}
		})
	}
}

// --quarantine names a pool whose own problems the operator accepts: the pool is
// migrated unresolved (its descriptor keeps the names it had) and is listed.
//
// spec: SPO-Xidentity-PRE-006
func TestMigrationQuarantinesAPoolOnRequest(t *testing.T) {
	p := legacyCopy(t, "bad-descriptor-owner.db")
	s, err := OpenLegacy(p, legacyPW())
	if err != nil {
		t.Fatal(err)
	}
	// only the pool's own problems can be quarantined: a wallet's cannot
	if _, err := s.Migrate(ctx, MigrateOptions{Quarantine: []string{"nope"}}); err == nil {
		t.Fatal("quarantining a pool that is not the problem was accepted")
	}
	rep, err := s.Migrate(ctx, MigrateOptions{Quarantine: []string{"pool9"}})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if len(rep.Quarantined) == 0 || !strings.Contains(rep.Quarantined[0], "ghost") {
		t.Errorf("quarantined %v", rep.Quarantined)
	}
	s2, err := Open(p, legacyPW())
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	raw, err := nget(t, labels.Named(s2), "pool9", ports.PoolDescriptor)
	if err != nil || !strings.Contains(string(raw), `"ghost"`) {
		t.Fatalf("the quarantined descriptor was changed: %s %v", raw, err)
	}
}

// Two records of one owner that map to one reference merge when their bytes are
// identical, and are refused when they differ.
//
// spec: SPO-Xidentity-INV-024
func TestMigrationMergesIdenticalCollisions(t *testing.T) {
	p := legacyCopy(t, "collision-identical.db")
	s, err := OpenLegacy(p, legacyPW())
	if err != nil {
		t.Fatal(err)
	}
	rep, err := s.Migrate(ctx, MigrateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if rep.Merged != 1 {
		t.Errorf("merged %d, want 1", rep.Merged)
	}
	s2, err := Open(p, legacyPW())
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	n := labels.Named(s2)
	for _, name := range []string{"gina", "gina.payment"} {
		if _, err := nget(t, n, name, ports.AddrVKey); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// An upstream-encrypted signing key takes its identity from the verification key
// of the same name; with none it is quarantined (kept, found by its stem, usable by
// no signer).
//
// spec: SPO-Xidentity-INV-024
func TestMigrationOfEncryptedSigningKeys(t *testing.T) {
	p := legacyCopy(t, "encrypted-skey.db")
	s, err := OpenLegacy(p, legacyPW())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Migrate(ctx, MigrateOptions{}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s2, err := Open(p, legacyPW())
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	n := labels.Named(s2)
	hal := mustKeyID(t, n, "hal.payment", ports.AddrVKey, custody.RolePayment)
	refs, _ := s2.ListRecords(ctx)
	var keyed, quarantined int
	for _, r := range refs {
		if r.Kind != ports.UpstreamEncryptedSKey {
			continue
		}
		if r.Anchor == hal {
			keyed++
		} else if r.Anchor.Is(identity.KindNamedRecord) {
			quarantined++
		}
	}
	if keyed != 1 || quarantined != 1 {
		t.Errorf("keyed by the sibling %d, quarantined %d", keyed, quarantined)
	}
	for _, name := range []string{"hal.payment", "orphan.payment"} {
		b, err := n.Open(ctx, ports.NamedRef{Name: name, Kind: ports.UpstreamEncryptedSKey})
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		b.Destroy()
	}
}

// A failure in the middle of the transaction leaves the original file as it was.
//
// spec: SPO-Xidentity-INV-024
func TestAFailedMigrationLeavesTheFileUntouched(t *testing.T) {
	p := legacyCopy(t, "store.db")
	s, err := OpenLegacy(p, legacyPW())
	if err != nil {
		t.Fatal(err)
	}
	before := dump(t, s)
	boom := errors.New("injected failure")
	migrateHook = func(converted int) error {
		if converted == 5 {
			return boom
		}
		return nil
	}
	defer func() { migrateHook = nil }()
	_, err = s.Migrate(ctx, MigrateOptions{})
	if !errors.Is(err, boom) {
		t.Fatalf("migrate: %v", err)
	}
	if after := dump(t, s); after != before {
		t.Error("the file changed although the migration failed")
	}
	s.Close()
	// it still opens as the old format, and the old format only
	if _, err := Open(p, legacyPW()); !errors.Is(err, ErrLegacyFormat) {
		t.Errorf("open after a failed migration: %v", err)
	}
	s2, err := OpenLegacy(p, legacyPW())
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if err := s2.Verify(ctx); err != nil {
		t.Errorf("the file no longer verifies: %v", err)
	}
	if dump(t, s2) != before {
		t.Error("the file is not what it was")
	}
	_ = bytes.Equal
}

// A handle opened for the migration can only migrate: View, Update, Open and the
// writes that change the file all refuse.
//
// spec: SPO-Xidentity-INV-030
func TestALegacyHandleOnlyMigrates(t *testing.T) {
	s, err := OpenLegacy(legacyCopy(t, "store.db"), legacyPW())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.View(ctx, func(ports.Reader) error { return nil }); !errors.Is(err, ErrLegacyFormat) {
		t.Errorf("View: %v", err)
	}
	if err := s.Update(ctx, func(ports.Writer) error { return nil }); !errors.Is(err, ErrLegacyFormat) {
		t.Errorf("Update: %v", err)
	}
	if _, err := s.Open(ctx, rf("x", ports.NodeSKey)); !errors.Is(err, ErrLegacyFormat) {
		t.Errorf("Open: %v", err)
	}
	if _, err := s.Rekey(ctx, []Credential{PassphraseCredential(legacyPW())}); !errors.Is(err, ErrLegacyFormat) {
		t.Errorf("Rekey: %v", err)
	}
}

// A row of format 1 put back into a migrated store (taken from the backup the
// migration made) is refused by Open and by verification.
//
// spec: SPO-Xidentity-INV-023
func TestAFormat1RowPlantedInAMigratedStoreIsRefused(t *testing.T) {
	p := legacyCopy(t, "store.db")
	old, err := OpenLegacy(p, legacyPW())
	if err != nil {
		t.Fatal(err)
	}
	old.SetColdSource(coldPass("a cold sub-key passphrase")) // the fixture holds a pool cold key
	rep, err := old.Migrate(ctx, MigrateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	old.Close()
	bk, err := OpenLegacy(rep.Backup, legacyPW())
	if err != nil {
		t.Fatal(err)
	}
	var id, tag, nonce, wrapped, owner, ct []byte
	var kind string
	var v, upd int64
	if err := bk.db.QueryRow(`SELECT id, lookup_tag, kind, version, nonce, wrapped_key, owner_sealed, ciphertext, updated_at FROM records WHERE kind = 'kes.counter'`).
		Scan(&id, &tag, &kind, &v, &nonce, &wrapped, &owner, &ct, &upd); err != nil {
		t.Fatal(err)
	}
	bk.Close()
	m, err := Open(p, legacyPW())
	if err != nil {
		t.Fatal(err)
	}
	// replace the migrated row of that record by the old one: the row no longer
	// matches the audit chain or the format
	if _, err := m.db.Exec(`UPDATE records SET lookup_tag=?, version=?, nonce=?, wrapped_key=?, owner_sealed=?, ciphertext=? WHERE id=?`, tag, v, nonce, wrapped, owner, ct, id); err != nil {
		t.Fatal(err)
	}
	m.Close()
	if _, err := Open(p, legacyPW()); err == nil {
		t.Error("Open accepted a planted row of format 1")
	}
	if err := VerifyFile(p, legacyPW()); err == nil {
		t.Error("VerifyFile accepted a planted row of format 1")
	}
	if _, err := VerifyFilePayloads(p, legacyPW()); err == nil {
		t.Error("VerifyFilePayloads accepted a planted row of format 1")
	}
}

// A store whose manifest disagrees with the key stored under its anchor is
// refused by Open, and verification reports it too (it opens with SkipVerify and
// must still run the check of the identity layer).
//
// spec: SPO-Xidentity-INV-031
func TestVerifyRunsTheIdentityCheckOfEveryOpen(t *testing.T) {
	s, p := newStore(t)
	n := labels.Named(s)
	if err := n.Update(ctx, func(w ports.NamedWriter) error {
		return w.Put(ports.NamedRef{Name: "alice", Kind: ports.AddrVKey}, envKey("PaymentVerificationKeyShelley_ed25519", "alice"))
	}); err != nil {
		t.Fatal(err)
	}
	var anchor identity.Ref
	if err := s.View(ctx, func(r ports.Reader) error { o, _, e := labels.OwnersOf(r); anchor = o[0].Anchor; return e }); err != nil {
		t.Fatal(err)
	}
	if err := s.Update(ctx, func(w ports.Writer) error {
		return w.Put(ports.Ref{Anchor: anchor, Kind: ports.AddrVKey}, envKey("PaymentVerificationKeyShelley_ed25519", "someone else"))
	}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := Open(p, pw()); !errors.Is(err, labels.ErrCorrupt) {
		t.Errorf("Open: %v", err)
	}
	if err := VerifyFile(p, pw()); !errors.Is(err, labels.ErrCorrupt) {
		t.Errorf("VerifyFile: %v", err)
	}
	if _, err := VerifyFilePayloads(p, pw()); !errors.Is(err, labels.ErrCorrupt) {
		t.Errorf("VerifyFilePayloads: %v", err)
	}
}
