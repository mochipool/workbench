package custody

import (
	"errors"
	"strings"
	"testing"
)

func TestPlanGenerationRefusesNonVaultHolders(t *testing.T) {
	if _, err := PlanGeneration(KeyRef{Role: RolePayment, Holder: HolderVault, Owner: "w"}, KeyRef{Role: RoleStake, Owner: "w"}); err != nil {
		t.Fatal(err)
	}
	for _, h := range []Holder{HolderHardware, HolderRemote} {
		_, err := PlanGeneration(KeyRef{Role: RolePayment, Holder: HolderVault, Owner: "w"}, KeyRef{Role: RoleStake, Holder: h, Owner: "w"})
		var ue *UnsupportedError
		if !errors.As(err, &ue) || len(ue.Problems) != 1 || ue.Problems[0].Slot.Key.Role != RoleStake {
			t.Fatalf("%s: %v", h, err)
		}
	}
}

func TestNormalizeMnemonic(t *testing.T) {
	in := "  " + strings.ToUpper(strings.Repeat("Word ", 12)) + "\t" + strings.Repeat("x  ", 12) + "\n"
	out, err := NormalizeMnemonic([]byte(in))
	if err != nil || string(out) != strings.TrimSpace(strings.Repeat("word ", 12)+strings.Repeat("x ", 12)) {
		t.Fatalf("%q %v", out, err)
	}
	_, err = NormalizeMnemonic([]byte("secret words only"))
	if !errors.Is(err, ErrMnemonicWords) || strings.Contains(err.Error(), "secret") {
		t.Fatal(err)
	}
}
