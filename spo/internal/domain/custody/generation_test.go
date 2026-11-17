package custody

import (
	"errors"
	"strings"
	"testing"
)

func TestPlanGenerationRefusesUnwiredPlacements(t *testing.T) {
	if _, err := PlanGeneration(PlaceVault, RolePayment, RoleStake); err != nil {
		t.Fatal(err)
	}
	_, err := PlanGeneration(PlaceHardware, RoleStake)
	var ue *UnsupportedError
	if !errors.As(err, &ue) || len(ue.Problems) != 1 || ue.Problems[0].Slot.Key.Role != RoleStake {
		t.Fatalf("%v", err)
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
