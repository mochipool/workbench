package native

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/gouroboros/ledger/common"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

func vaultWith(t *testing.T, skeyEnvelope string) *plainstore.Store {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "mypool.node.skey"), []byte(skeyEnvelope), 0o400); err != nil {
		t.Fatal(err)
	}
	st, err := plainstore.OpenTestnet(dir)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func coldKey(t *testing.T) custody.Key[custody.PoolCold] {
	t.Helper()
	k, err := custody.As[custody.PoolCold](custody.KeyRef{Role: custody.RolePoolCold, Holder: custody.HolderVault, Owner: "mypool"})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// spec: SPO-04d-EXT-003, SPO-04d-INV-005, SPO-04d-SEC-002
//
// Decision (SEC-002): the cold key is opened from the vault into guarded
// memory for the one call and destroyed after it; the signer writes no file
// and starts no process. A software-key issue still needs the cold key on
// the issuing machine, as upstream does.
func TestVaultSignerIssuesAVerifiableCertificate(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(100 + i)
	}
	vk := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	kes := make([]byte, 32)
	for i := range kes {
		kes[i] = byte(i * 3)
	}
	skey := `{"type":"StakePoolSigningKey_ed25519","description":"x","cborHex":"5820` + hex.EncodeToString(seed) + `"}`
	s := VaultSigner{Vault: vaultWith(t, skey)}

	out, err := s.IssueOpCert(context.Background(), coldKey(t), ports.OpCertRequest{KesVKey: kes, Counter: 300, KesPeriod: 988})
	if err != nil {
		t.Fatal(err)
	}
	env, err := pool.ParseEnvelope(out)
	if err != nil || env.Type != "NodeOperationalCertificate" || env.Description != "" {
		t.Fatalf("envelope %+v %v", env, err)
	}
	if string(out) != string(pool.MarshalEnvelope(env)) {
		t.Error("formatting differs from cardano-cli's (four-space indent, trailing newline)")
	}
	raw, _ := hex.DecodeString(env.CborHex)
	dec, err := bursa.DecodeOpCert(raw)
	if err != nil {
		t.Fatal(err)
	}
	if dec.IssueNumber != 300 || dec.KESPeriod != 988 || string(dec.KESVKey) != string(kes) || string(dec.ColdVKey) != string(vk) {
		t.Errorf("decoded %+v", dec)
	}
	if !ed25519.Verify(vk, common.OpCertSignableBytes(kes, 300, 988), dec.ColdSig) {
		t.Error("the cold signature does not verify")
	}
}

func TestVaultSignerRefusesWhatItCannotSign(t *testing.T) {
	for name, skey := range map[string]string{
		"extended key": `{"type":"StakePoolExtendedSigningKey_ed25519_bip32","cborHex":"5840` + strings.Repeat("00", 64) + `"}`,
		"short key":    `{"type":"StakePoolSigningKey_ed25519","cborHex":"5820aa"}`,
		"not json":     `nope`,
	} {
		s := VaultSigner{Vault: vaultWith(t, skey)}
		if _, err := s.IssueOpCert(context.Background(), coldKey(t), ports.OpCertRequest{KesVKey: make([]byte, 32)}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// No key in the vault.
	st, _ := plainstore.OpenTestnet(t.TempDir())
	if _, err := (VaultSigner{Vault: st}).IssueOpCert(context.Background(), coldKey(t), ports.OpCertRequest{KesVKey: make([]byte, 32)}); err == nil {
		t.Error("missing key accepted")
	}
}

// The profile agrees with the interfaces (ADR 0008) and the directory gives
// the vault signer for vault keys and a clear refusal for other holders.
func TestSignerConformanceAndDirectory(t *testing.T) {
	st, _ := plainstore.OpenTestnet(t.TempDir())
	if err := ports.CheckSigner(VaultSigner{Vault: st}); err != nil {
		t.Fatal(err)
	}
	d := Signers{Vault: st}
	sg, err := d.SignerFor(custody.KeyRef{Role: custody.RolePoolCold, Holder: custody.HolderVault, Owner: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ports.CheckSigner(sg); err != nil {
		t.Fatal(err)
	}
	if _, err := d.SignerFor(custody.KeyRef{Role: custody.RolePoolCold, Holder: custody.HolderHardware}); err == nil ||
		!strings.Contains(err.Error(), "no hardware signer is configured") {
		t.Errorf("hardware: %v", err)
	}
	if _, err := d.SignerFor(custody.KeyRef{Holder: custody.HolderRemote}); err == nil {
		t.Error("remote accepted")
	}
	// A plan for a pool cold key in the vault passes; payment and stake keys
	// are witnessed by the same signer now (TxWitnesser); a VRF key is not offered.
	_, err = ports.PlanSignatures(d, []custody.Slot{{
		Label: "opcert", Key: custody.KeyRef{Role: custody.RolePoolCold, Holder: custody.HolderVault, Owner: "p"},
		Demand: custody.Demand{Role: custody.RolePoolCold, Operation: custody.OpIssueOpCert},
	}})
	if err != nil {
		t.Errorf("plan: %v", err)
	}
	_, err = ports.PlanSignatures(d, []custody.Slot{{
		Label: "tx", Key: custody.KeyRef{Role: custody.RolePayment, Holder: custody.HolderVault, Owner: "p"},
		Demand: custody.Demand{Role: custody.RolePayment, Operation: custody.OpWitnessTx},
	}})
	if err != nil {
		t.Errorf("a payment witness is planned for the vault: %v", err)
	}
	_, err = ports.PlanSignatures(d, []custody.Slot{{
		Label: "tx", Key: custody.KeyRef{Role: custody.RoleVRF, Holder: custody.HolderVault, Owner: "p"},
		Demand: custody.Demand{Role: custody.RoleVRF, Operation: custody.OpWitnessTx},
	}})
	if err == nil {
		t.Error("the vault signer claims to witness with a VRF key")
	}
}
