package native

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/fsstore"
	dassets "github.com/mochipool/workbench/spo/internal/domain/assets"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/tokenmeta"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// The policy id of domain/tokenmeta (its own native-script encoder) is the one
// the ledger adapter computes, for every script form the policy use cases write.
func TestTokenmetaPolicyIDAgreesWithLedger(t *testing.T) {
	kh := "39a1df51147b6de6689a4727846962fb6540c3a3c7859a1a79b9420f"
	scripts := [][]byte{
		dassets.PolicyScript(kh, 0, false),
		dassets.PolicyScript(kh, 98_000_000, true),
		[]byte(`{"type":"atLeast","required":2,"scripts":[{"type":"sig","keyHash":"` + kh + `"},{"type":"sig","keyHash":"` + kh + `"},{"type":"after","slot":7}]}`),
		[]byte(`{"type":"any","scripts":[{"type":"sig","keyHash":"` + kh + `"}]}`),
	}
	for _, s := range scripts {
		want, err := Ledger{}.PolicyID(s)
		if err != nil {
			t.Fatal(err)
		}
		_, got, err := tokenmeta.PolicyValue(s)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s: id %x, the ledger adapter says %x", s, got, want)
		}
	}
}

// The vault signs registry messages with the policy key and with nothing else.
func TestVaultRegistrySigner(t *testing.T) {
	st, err := fsstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pair, err := SoftwareKeys{}.GeneratePayment(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer pair.SKey.Destroy()
	if err := st.Update(context.Background(), func(w ports.Writer) error {
		if err := w.Put(ports.Ref{Name: "tok", Kind: ports.PolicyVKey}, pair.VKey); err != nil {
			return err
		}
		return w.PutSecret(ports.Ref{Name: "tok", Kind: ports.PolicySKey}, pair.SKey)
	}); err != nil {
		t.Fatal(err)
	}
	s := VaultRegistry{VaultSignatures{VaultSigner{Vault: st}}}
	if err := ports.CheckRegistrySigner(s); err != nil {
		t.Fatal(err)
	}
	p := s.Profile()
	if !contains(p.Operations(custody.RolePolicy), custody.OpSignRegistryEntry) {
		t.Error("the policy role lacks the registry operation")
	}
	for _, r := range []custody.Role{custody.RolePayment, custody.RoleStake, custody.RolePoolCold} {
		if contains(p.Operations(r), custody.OpSignRegistryEntry) {
			t.Errorf("%s can sign a registry entry", r)
		}
	}
	key, err := custody.As[custody.Policy](custody.KeyRef{Role: custody.RolePolicy, Holder: custody.HolderVault, Owner: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	msg := tokenmeta.Message(hex.EncodeToString(make([]byte, 28)), tokenmeta.PropName, tokenmeta.Text("x"), 1)
	got, err := s.SignRegistryMessages(context.Background(), key, [][32]byte{msg})
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", err, got)
	}
	env, _ := pool.ParseEnvelope(pair.VKey)
	raw, _ := env.Key32()
	if !ed25519.Verify(raw, msg[:], got[0].Signature[:]) || string(got[0].PublicKey[:]) != string(raw) {
		t.Error("the attestation does not verify under the policy's verification key")
	}
	// A key of another role is refused, and a hardware or remote holder has no signer.
	pay, _ := custody.As[custody.Payment](custody.KeyRef{Role: custody.RolePayment, Owner: "tok"})
	_ = pay // typed keys only exist for the role asked; the signer takes custody.Policy
	dir := RegistrySigners{Vault: st}
	for _, h := range []custody.Holder{custody.HolderHardware, custody.HolderRemote, "other"} {
		if _, err := dir.SignerFor(custody.KeyRef{Role: custody.RolePolicy, Holder: h, Owner: "tok"}); err == nil {
			t.Errorf("holder %s has a signer", h)
		}
	}
}

func contains(ops []custody.Operation, op custody.Operation) bool {
	for _, o := range ops {
		if o == op {
			return true
		}
	}
	return false
}
