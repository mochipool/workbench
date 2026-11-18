//go:build legacyfixture

package sqlitestore

// This generator built testdata/legacy-v1/store.db with the code of format
// version 1 (name-keyed records), before ADR 0010 decision 4 changed the
// format. It cannot run against the current code; it is kept as the record of
// what the fixture holds. Run once, at the last commit that still had format 1:
//
//	go test -tags legacyfixture -run TestGenerateLegacyFixture ./internal/adapters/sqlitestore/
//
// The passphrase is "legacy fixture passphrase" and the keys are derived from
// fixed seeds, so the file can be rebuilt. The file holds no real secret.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/partystore"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func seedKey(label string) (ed25519.PublicKey, []byte) {
	s := sha256.Sum256([]byte("legacy fixture seed " + label))
	k := ed25519.NewKeyFromSeed(s[:])
	return k.Public().(ed25519.PublicKey), s[:]
}

func vkeyEnv(typ string, pub []byte) []byte {
	return []byte(fmt.Sprintf(`{"type":%q,"description":"","cborHex":"5820%s"}`, typ, hex.EncodeToString(pub)))
}

func skeyEnv(typ string, seed []byte) []byte {
	return []byte(fmt.Sprintf(`{"type":%q,"description":"","cborHex":"5820%s"}`, typ, hex.EncodeToString(seed)))
}

func TestGenerateLegacyFixture(t *testing.T) {
	out := os.Getenv("LEGACY_FIXTURE_OUT")
	if out == "" {
		t.Skip("LEGACY_FIXTURE_OUT not set")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "store.db")
	rk, err := Init(path, secret.Take([]byte("legacy fixture passphrase")))
	if err != nil {
		t.Fatal(err)
	}
	rk.Destroy()
	st, err := Open(path, secret.Take([]byte("legacy fixture passphrase")))
	if err != nil {
		t.Fatal(err)
	}
	put := func(w ports.Writer, name string, k ports.Kind, num int, data []byte) {
		t.Helper()
		ref := ports.Ref{Name: name, Kind: k, Num: num}
		var e error
		if k.Secret() {
			e = w.PutSecret(ref, secret.Take(append([]byte(nil), data...)))
		} else {
			e = w.Put(ref, data)
		}
		if e != nil {
			t.Fatal(e)
		}
	}
	err = st.Update(ctx, func(w ports.Writer) error {
		// alice: a software wallet made by 03a, payment stem "alice.payment".
		ap, as := seedKey("alice payment")
		sp, ss := seedKey("alice stake")
		put(w, "alice.payment", ports.AddrVKey, 0, vkeyEnv("PaymentVerificationKeyShelley_ed25519", ap))
		put(w, "alice.payment", ports.AddrSKey, 0, skeyEnv("PaymentSigningKeyShelley_ed25519", as))
		put(w, "alice.payment", ports.AddrFile, 0, []byte("addr_test1qzalice\n"))
		put(w, "alice", ports.StakingVKey, 0, vkeyEnv("StakeVerificationKeyShelley_ed25519", sp))
		put(w, "alice", ports.StakingSKey, 0, skeyEnv("StakeSigningKeyShelley_ed25519", ss))
		put(w, "alice", ports.StakingAddr, 0, []byte("stake_test1uzalice\n"))
		// bob: a hardware-file wallet; the hardware signing file holds the key's
		// public key in cborXPubKeyHex (32-byte key, 32-byte chain code).
		bp, _ := seedKey("bob payment")
		bs, _ := seedKey("bob stake")
		hws := func(pub []byte) []byte {
			return []byte(fmt.Sprintf(`{"type":"PaymentHWSigningFileShelley_ed25519","description":"Payment Hardware Verification Key","cborXPubKeyHex":"5840%s%s"}`,
				hex.EncodeToString(pub), hex.EncodeToString(make([]byte, 32))))
		}
		put(w, "bob.payment", ports.AddrVKey, 0, vkeyEnv("PaymentVerificationKeyShelley_ed25519", bp))
		put(w, "bob.payment", ports.AddrHwsFile, 0, hws(bp))
		put(w, "bob.payment", ports.AddrFile, 0, []byte("addr_test1qzbob\n"))
		put(w, "bob", ports.StakingVKey, 0, vkeyEnv("StakeVerificationKeyShelley_ed25519", bs))
		put(w, "bob", ports.StakingHwsFile, 0, hws(bs))
		put(w, "bob", ports.StakingAddr, 0, []byte("stake_test1uzbob\n"))
		// carol: an enterprise wallet made by 02 (stem "carol", no stake key).
		cp, cs := seedKey("carol payment")
		put(w, "carol", ports.AddrVKey, 0, vkeyEnv("PaymentVerificationKeyShelley_ed25519", cp))
		put(w, "carol", ports.AddrSKey, 0, skeyEnv("PaymentSigningKeyShelley_ed25519", cs))
		put(w, "carol", ports.AddrFile, 0, []byte("addr_test1vzcarol\n"))

		// pool1: cold, VRF, numbered KES keys and operational certificates.
		np, ns := seedKey("pool1 cold")
		vp, vs := seedKey("pool1 vrf")
		put(w, "pool1", ports.NodeVKey, 0, vkeyEnv("StakePoolVerificationKey_ed25519", np))
		put(w, "pool1", ports.NodeSKey, 0, skeyEnv("StakePoolSigningKey_ed25519", ns))
		put(w, "pool1", ports.NodeCounter, 0, []byte(`{"type":"NodeOperationalCertificateIssueCounter","description":"Next certificate issue number: 2","cborHex":"82025820`+hex.EncodeToString(np)+`"}`))
		put(w, "pool1", ports.VrfVKey, 0, vkeyEnv("VrfVerificationKey_PraosVRF", vp))
		put(w, "pool1", ports.VrfSKey, 0, skeyEnv("VrfSigningKey_PraosVRF", vs))
		for n := 0; n < 3; n++ {
			kp, ks := seedKey(fmt.Sprintf("pool1 kes %d", n))
			put(w, "pool1", ports.KesVKey, n, vkeyEnv("KesVerificationKey_ed25519_kes_2^6", kp))
			put(w, "pool1", ports.KesSKey, n, skeyEnv("KesSigningKey_ed25519_kes_2^6", ks))
		}
		put(w, "pool1", ports.KesCounter, 0, []byte("2\n"))
		put(w, "pool1", ports.KesCounterNext, 0, []byte("3\n"))
		for n := 0; n < 2; n++ {
			put(w, "pool1", ports.OpCert, n, []byte(fmt.Sprintf(`{"type":"NodeOperationalCertificate","description":"","cborHex":"82%02x"}`, n)))
		}
		put(w, "pool1", ports.KesExpire, 0, []byte(`{"kesExpiry":"2099-01-01"}`))
		put(w, "pool1", ports.PoolMetadata, 0, []byte(`{"name":"Pool One","ticker":"ONE"}`))

		// The descriptor names its owners and its reward account by wallet name,
		// holds a witness collection whose slots are assigned to the party
		// "cosigner" by name, and records the payer by stem.
		pid, _ := identity.KeyHashOf(np)
		poolID := hex.EncodeToString(pid.Hash())
		desc := fmt.Sprintf(`{"poolName":"pool1","poolOwner":[{"ownerName":"alice","ownerWitness":"local"},{"ownerName":"bob","ownerWitness":"external"}],"poolRewards":"alice","poolPledge":"1000000","poolCost":"340000000","poolMargin":"0.05","poolRelays":[],"poolMetaName":"Pool One","poolMetaTicker":"ONE","poolMetaHomepage":"https://example.invalid","poolMetaUrl":"https://example.invalid/m.json","poolMetaDescription":"d","poolID":%q,"regWitness":{"id":1700000000,"type":"PoolRegistration","ttl":123456,"regPayName":"alice.payment","txBody":{"type":"Unwitnessed Tx ConwayEra","description":"","cborHex":"a0"},"witnesses":{"pool1.node":{"witness":{},"role":"pool-cold","party":"cosigner"},"bob.staking":{"witness":{},"role":"stake","party":"cosigner"}},"regPayAmount":500000000,"regPayReturn":0,"hardwareWalletIncluded":"no","metadataFilesList":[],"version":1}}`, poolID)
		put(w, "pool1", ports.PoolDescriptor, 0, []byte(desc))

		// A pending record, a party and a witness-collection transfer file.
		put(w, "00ab", ports.PendingUpdate, 0, []byte(`{"kind":"pool-registration","txid":"00ab","pool":"pool1","date":"2026-01-01T00:00:00Z"}`))
		ep, _ := seedKey("cosigner ed25519")
		xp, _ := seedKey("cosigner x25519")
		var p party.Party
		p.Name = "cosigner"
		copy(p.Identity.Ed25519[:], ep)
		copy(p.Identity.X25519[:], xp)
		p.Identity.Label = "cosigner"
		p.Identity.Created = time.Unix(1700000000, 0).UTC()
		p.Fingerprint = p.Identity.Fingerprint()
		p.Roles = []party.Role{party.RoleSigner}
		p.State = party.StateActive
		p.EnrolledAt = time.Unix(1700000001, 0).UTC()
		if err := (partystore.Registry{}).Put(w, p); err != nil {
			t.Fatal(err)
		}
		put(w, "pool1.reg.1700000000", ports.PoolWitnessFile, 0, []byte(`{"type":"Tx ConwayEra","description":"","cborHex":"a0"}`))
		put(w, "koios", ports.ProviderToken, 0, []byte("not-a-real-token"))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestGenerateLegacyVariants builds the small stores the migration refusals are
// tested against: each holds one defect the migration must list.
func TestGenerateLegacyVariants(t *testing.T) {
	outDir := os.Getenv("LEGACY_FIXTURE_DIR")
	if outDir == "" {
		t.Skip("LEGACY_FIXTURE_DIR not set")
	}
	vk := func(typ, label string) []byte { p, _ := seedKey(label); return vkeyEnv(typ, p) }
	pay := "PaymentVerificationKeyShelley_ed25519"
	variants := map[string]func(put func(string, ports.Kind, int, []byte)){
		// a descriptor owner that names a wallet the store does not hold
		"bad-descriptor-owner": func(put func(string, ports.Kind, int, []byte)) {
			cp, _ := seedKey("pool9 cold")
			pid, _ := identity.KeyHashOf(cp)
			put("pool9", ports.NodeVKey, 0, vkeyEnv("StakePoolVerificationKey_ed25519", cp))
			put("pool9", ports.PoolDescriptor, 0, []byte(`{"poolName":"pool9","poolOwner":[{"ownerName":"ghost","ownerWitness":"local"}],"poolRewards":"ghost","poolID":"`+hex.EncodeToString(pid.Hash())+`"}`))
			put("keeper", ports.AddrVKey, 0, vk(pay, "keeper"))
		},
		// a descriptor whose poolID disagrees with the cold key under its name
		"descriptor-pool-id": func(put func(string, ports.Kind, int, []byte)) {
			cp, _ := seedKey("pool8 cold")
			put("pool8", ports.NodeVKey, 0, vkeyEnv("StakePoolVerificationKey_ed25519", cp))
			put("pool8", ports.PoolDescriptor, 0, []byte(`{"poolName":"pool8","poolOwner":[{"ownerName":"w8","ownerWitness":"local"}],"poolRewards":"w8","poolID":"`+hex.EncodeToString(make([]byte, 28))+`"}`))
			put("w8", ports.StakingVKey, 0, vk("StakeVerificationKeyShelley_ed25519", "w8 stake"))
		},
		// one payment key under two wallet names
		"identity-in-two-owners": func(put func(string, ports.Kind, int, []byte)) {
			put("dave", ports.AddrVKey, 0, vk(pay, "shared payment"))
			put("erin", ports.AddrVKey, 0, vk(pay, "shared payment"))
		},
		// "frank" and "frank.payment" both hold a payment verification key
		"collision-differs": func(put func(string, ports.Kind, int, []byte)) {
			put("frank", ports.AddrVKey, 0, vk(pay, "frank one"))
			put("frank.payment", ports.AddrVKey, 0, vk(pay, "frank two"))
		},
		"collision-identical": func(put func(string, ports.Kind, int, []byte)) {
			put("gina", ports.AddrVKey, 0, vk(pay, "gina"))
			put("gina.payment", ports.AddrVKey, 0, vk(pay, "gina"))
			put("gina.payment", ports.AddrFile, 0, []byte("addr_test1qzgina\n"))
		},
		// an upstream-encrypted signing key with and without its verification key
		"encrypted-skey": func(put func(string, ports.Kind, int, []byte)) {
			put("hal.payment", ports.AddrVKey, 0, vk(pay, "hal"))
			put("hal.payment", ports.UpstreamEncryptedSKey, 0, []byte("gpg-wrapped bytes"))
			put("orphan.payment", ports.UpstreamEncryptedSKey, 0, []byte("gpg-wrapped bytes"))
		},
	}
	for name, fill := range variants {
		dir := t.TempDir()
		path := filepath.Join(dir, "store.db")
		rk, err := Init(path, secret.Take([]byte("legacy fixture passphrase")))
		if err != nil {
			t.Fatal(err)
		}
		rk.Destroy()
		st, err := Open(path, secret.Take([]byte("legacy fixture passphrase")))
		if err != nil {
			t.Fatal(err)
		}
		err = st.Update(ctx, func(w ports.Writer) error {
			fill(func(n string, k ports.Kind, num int, data []byte) {
				ref := ports.Ref{Name: n, Kind: k, Num: num}
				var e error
				if k.Secret() {
					e = w.PutSecret(ref, secret.Take(append([]byte(nil), data...)))
				} else {
					e = w.Put(ref, data)
				}
				if e != nil {
					t.Fatal(e)
				}
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		st.Close()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(outDir, name+".db"), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
