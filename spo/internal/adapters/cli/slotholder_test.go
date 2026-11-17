package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

// What the operator is shown is what signs: the holder of a slot comes from the
// signer directory, and a key that answers through another name says so and
// names the record that will sign.
//
// spec: SPO-Xidentity-INV-016
func TestSlotHolderIsTheDirectorysAnswerAndNamesTheRecordThatSigns(t *testing.T) {
	dir := t.TempDir()
	vk := `{"type":"PaymentVerificationKeyShelley_ed25519","description":"","cborHex":"5820` + strings.Repeat("ab", 32) + `"}`
	for n, c := range map[string]string{"a.vkey": vk, "a.skey": `{"type":"PaymentSigningKeyShelley_ed25519","description":"","cborHex":"5820` + strings.Repeat("11", 32) + `"}`, "b.vkey": vk} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	st, err := plainstore.OpenTestnet(dir)
	if err != nil {
		t.Fatal(err)
	}
	var slots []slotInfo
	_ = st.View(context.Background(), func(r ports.Reader) error {
		slots = []slotInfo{
			slotInfo{name: "b", role: "payment", holder: "NOT in this workspace"}.withKey(r, custody.RolePayment, "b"),
			slotInfo{name: "a", role: "payment", holder: "x"}.withKey(r, custody.RolePayment, "a"),
		}
		return nil
	})
	partyLabeler{signers: native.Signers{Vault: st}}.describe(context.Background(), st, slots)
	if !strings.Contains(slots[0].holder, "this workspace") || !strings.Contains(slots[0].holder, "the key stored as \"a\" answers for it") {
		t.Errorf("b: %q", slots[0].holder)
	}
	if slots[1].holder != "this workspace" {
		t.Errorf("a: %q", slots[1].holder)
	}
}
