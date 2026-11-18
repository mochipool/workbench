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
// signer directory. One verification key is a member of one owner (ADR 0010), so
// a key that answers through another name cannot arise: a directory that stores
// one key under two names is refused when it is read, showing both owners, and
// the old "answers through another name" text of the slot display is gone.
//
// spec: SPO-Xidentity-INV-016, SPO-Xidentity-INV-019
func TestSlotHolderIsTheDirectorysAnswerAndAKeyUnderTwoNamesIsRefused(t *testing.T) {
	dir := t.TempDir()
	vk := `{"type":"PaymentVerificationKeyShelley_ed25519","description":"","cborHex":"5820` + strings.Repeat("ab", 32) + `"}`
	sk := `{"type":"PaymentSigningKeyShelley_ed25519","description":"","cborHex":"5820` + strings.Repeat("11", 32) + `"}`
	for n, c := range map[string]string{"a.vkey": vk, "a.skey": sk} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	st, err := plainstore.OpenTestnet(dir)
	if err != nil {
		t.Fatal(err)
	}
	var slots []slotInfo
	_ = st.View(context.Background(), func(r ports.NamedReader) error {
		slots = []slotInfo{slotInfo{name: "a", role: "payment", holder: "x"}.withKey(r, custody.RolePayment, "a")}
		return nil
	})
	partyLabeler{signers: native.Signers{Vault: st.Anchor()}}.describe(context.Background(), st, slots)
	if slots[0].holder != "this workspace" {
		t.Errorf("a: %q", slots[0].holder)
	}
	// the same key under a second name: the directory is refused, both shown
	if err := os.WriteFile(filepath.Join(dir, "b.vkey"), []byte(vk), 0o600); err != nil {
		t.Fatal(err)
	}
	err = st.View(context.Background(), func(r ports.NamedReader) error {
		_, e := r.Get(ports.NamedRef{Name: "a", Kind: ports.AddrVKey})
		return e
	})
	if err == nil || !strings.Contains(err.Error(), `wallet "a"`) || !strings.Contains(err.Error(), `wallet "b"`) {
		t.Fatalf("one key under two names: %v", err)
	}
}
