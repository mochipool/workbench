package hwcli_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/hwcli"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// spec: SPO-Pfiles-OUT-004, SPO-Chw-IN-001, SPO-Ptx-SEC-001
// Exercised, still waived until a use case enables the hardware path: SPO-Pfiles-INV-001
//
// Decision (X2): nothing secret reaches the tool. Its argv holds only the
// subcommand words, numbers, bech32 public keys and paths inside the private
// working directory; the environment is the one the session names; the
// directory is 0700 while it exists and gone afterwards.
func TestTheToolSeesNoSecretsAndTheWorkingDirectoryIsPrivateAndRemoved(t *testing.T) {
	var spawned int
	r := newRig(t, "Ledger", "8.0.8")
	r.cfg.Runner = execx.OS{Observe: func(s execx.Spawn) {
		spawned++
		if len(s.Env) != 1 || !strings.HasPrefix(s.Env[0], "FAKEHW_CONFIG=") {
			t.Errorf("environment %v", s.Env)
		}
		for _, a := range s.Argv[1:] {
			low := strings.ToLower(a)
			if strings.Contains(low, "skey") || strings.Contains(low, testSeed) || strings.Contains(low, "mnemonic") {
				t.Errorf("secret-looking argument %q", a)
			}
			if strings.HasPrefix(a, "/") {
				if !strings.HasPrefix(a, r.tempRoot+"/spo-hw-") {
					t.Errorf("a path outside the private directory: %q", a)
					continue
				}
				if st, err := os.Stat(filepath.Dir(a)); err != nil || st.Mode().Perm() != 0o700 {
					t.Errorf("%q: directory mode %v %v", a, st, err)
				}
			}
		}
	}}
	s := r.open()
	r.export(s, custody.RolePoolCold, "p", "1853H/1815H/0H/0H")
	r.export(s, custody.RolePayment, "w", "1852H/1815H/0H/0/0")
	cold := mustAs[custody.PoolCold](t, hwKey(custody.RolePoolCold, "p"))
	if _, err := s.IssueOpCert(context.Background(), cold, ports.OpCertRequest{KesVKey: bytes.Repeat([]byte{3}, 32), Counter: 1, KesPeriod: 2}); err != nil {
		t.Fatal(err)
	}
	body := realBody(t)
	if _, err := s.WitnessWith(context.Background(), hwKey(custody.RolePayment, "w"), body, ports.HardwareTxOptions{ChangeKeys: []custody.KeyRef{hwKey(custody.RolePayment, "w")}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Witness(context.Background(), hwKey(custody.RolePayment, "w"), legacyBody(t, "x")); err == nil {
		t.Fatal("a non-canonical body was witnessed")
	}
	// A failing run leaves nothing behind either.
	r.fake.Action = "disconnect"
	r.writeFake()
	if _, err := s.Witness(context.Background(), hwKey(custody.RolePayment, "w"), body); err == nil {
		t.Fatal("no error")
	}
	if spawned < 8 {
		t.Errorf("only %d processes were observed", spawned)
	}
	if left, _ := os.ReadDir(r.tempRoot); len(left) != 0 {
		t.Errorf("working directories were left behind: %v", left)
	}
}

func lazyFor(r *rig) *hwcli.Lazy { return hwcli.NewLazy(context.Background(), r.cfg) }

// spec: SPO-Chw-PRE-003, SPO-Chw-PRE-004, SPO-Pfiles-INV-002
//
// Decision (ADR 0008): the profile is built from the device the session found
// and the plan refuses, before anything is built or shown, what the vendor lacks.
func TestPlansAreRefusedOrAcceptedByTheDevicesProfile(t *testing.T) {
	slot := func(role custody.Role, op custody.Operation, feats ...custody.Feature) custody.Slot {
		return custody.Slot{Label: string(op), Key: hwKey(role, "o"), Demand: custody.Demand{Role: role, Operation: op, Features: custody.NewFeatures(feats...)}}
	}
	type tc struct {
		vendor, app string
		slot        custody.Slot
		ok          bool
	}
	W := custody.OpWitnessTx
	for _, c := range []tc{
		// Ledger: everything the scripts' hardware paths use.
		{"Ledger", "8.0.8", slot(custody.RolePoolCold, custody.OpIssueOpCert), true},
		{"Ledger", "8.0.8", slot(custody.RolePayment, W, custody.FeatMultiAssetOutput, custody.FeatMetadata), true},
		{"Ledger", "8.0.8", slot(custody.RolePayment, W, custody.FeatMint), true},
		{"Ledger", "8.0.8", slot(custody.RoleStake, W, custody.FeatStakeDelegation, custody.FeatVoteDelegation), true},
		{"Ledger", "8.0.8", slot(custody.RolePoolCold, W, custody.FeatPoolRegistrationOper), true},
		{"Ledger", "8.0.8", slot(custody.RoleDRep, W, custody.FeatDRepRegistration), true},
		{"Ledger", "8.0.8", slot(custody.RoleDRep, W, custody.FeatDRepUpdate), true}, // SPO-21b-INV-006: the update has the signing forms of the registration
		{"Ledger", "8.0.8", slot(custody.RolePayment, W, custody.FeatDRepUpdate), true},
		{"Ledger", "8.0.8", slot(custody.RoleDRep, W, custody.FeatVote), true},
		{"Ledger", "8.0.8", slot(custody.RolePayment, W, custody.FeatVote), true},
		{"Ledger", "8.0.8", slot(custody.RoleCommitteeHot, W, custody.FeatVote), true},
		{"Ledger", "8.0.8", slot(custody.RoleCommitteeCold, W, custody.FeatCommitteeAuthorize), true},
		{"Ledger", "8.0.8", slot(custody.RolePayment, W, custody.FeatUnrestricted), true},
		{"Ledger", "8.0.8", slot(custody.RolePolicy, custody.OpHardwarePolicyID), true},
		{"Ledger", "8.0.8", slot(custody.RoleCatalystVote, custody.OpExportVKey), true},
		{"Ledger", "8.0.8", slot(custody.RoleStake, custody.OpSignCip36), true},
		// What no row states is refused for every vendor.
		{"Ledger", "8.0.8", slot(custody.RolePayment, W, custody.FeatGovernanceAction), false}, // SPO-25b-PRE-002
		{"Ledger", "8.0.8", slot(custody.RolePayment, W, custody.FeatPlutusScript), false},
		{"Ledger", "8.0.8", slot(custody.RoleCalidus, custody.OpExportVKey), false}, // SPO-15-PRE-002
		{"Ledger", "8.0.8", slot(custody.RoleKES, custody.OpExportVKey), false},
		{"Ledger", "8.0.8", slot(custody.RoleVRF, W), false},
		{"Ledger", "8.0.8", slot(custody.RolePoolCold, custody.OpSignCip88), true}, // SPO-15-EXT-004
		{"Keystone", "1.7.7", slot(custody.RolePoolCold, custody.OpSignCip88), true},
		{"Trezor", "2.7.2", slot(custody.RolePoolCold, custody.OpSignCip88), false},
		{"Ledger", "8.0.8", slot(custody.RoleCalidus, custody.OpSignText), false}, // SPO-15-IF-006
		{"Keystone", "1.7.7", slot(custody.RoleCalidus, custody.OpExportVKey), false},
		{"Trezor", "2.7.2", slot(custody.RoleCalidus, custody.OpExportVKey), false},
		{"Trezor", "2.7.2", slot(custody.RoleCatalystVote, custody.OpExportVKey), false}, // SPO-09a-EXT-002
		{"Keystone", "1.7.7", slot(custody.RoleCatalystVote, custody.OpExportVKey), false},
		{"Ledger", "8.0.8", slot(custody.RolePayment, custody.OpSignMessage), false},
		{"Ledger", "8.0.8", slot(custody.RoleDRep, W, custody.FeatMint), false},
		// Keystone: Ledger or Keystone keys, no voting, no unrestricted mode.
		{"Keystone", "1.7.7", slot(custody.RolePoolCold, custody.OpIssueOpCert), true},
		{"Keystone", "1.7.7", slot(custody.RoleDRep, W, custody.FeatDRepRegistration), true},
		{"Keystone", "1.7.7", slot(custody.RoleDRep, W, custody.FeatDRepUpdate), true},
		{"Keystone", "1.7.7", slot(custody.RoleDRep, W, custody.FeatVote), false},
		{"Keystone", "1.7.7", slot(custody.RolePayment, W, custody.FeatUnrestricted), false},
		{"Keystone", "1.7.7", slot(custody.RoleStake, custody.OpSignCip36), false},
		// Trezor: payment, stake and policy keys only.
		{"Trezor", "2.7.2", slot(custody.RolePayment, W, custody.FeatMultiAssetOutput), true},
		{"Trezor", "2.7.2", slot(custody.RolePolicy, W, custody.FeatMint), true},
		{"Trezor", "2.7.2", slot(custody.RolePoolCold, custody.OpIssueOpCert), false},
		{"Trezor", "2.7.2", slot(custody.RolePoolCold, W, custody.FeatPoolRegistrationOper), false},
		{"Trezor", "2.7.2", slot(custody.RoleDRep, W, custody.FeatDRepRegistration), false},
		{"Trezor", "2.7.2", slot(custody.RoleDRep, W, custody.FeatDRepUpdate), false},
		{"Trezor", "2.7.2", slot(custody.RolePayment, W, custody.FeatVote), false},
		{"Trezor", "2.7.2", slot(custody.RolePayment, W, custody.FeatDRepRegistration), false},
	} {
		r := newRig(t, c.vendor, c.app)
		dir := native.Signers{Keys: hwIndex{}, Hardware: lazyFor(r)}
		_, err := ports.PlanSignatures(dir, []custody.Slot{c.slot})
		var ue *custody.UnsupportedError
		switch {
		case c.ok && err != nil:
			t.Errorf("%s %s %v %v: %v", c.vendor, c.app, c.slot.Key.Role, c.slot.Demand.Operation, err)
		case !c.ok && !errors.As(err, &ue):
			t.Errorf("%s %s %v %v: accepted (%v)", c.vendor, c.app, c.slot.Key.Role, c.slot.Demand.Operation, err)
		}
	}
}

// spec: SPO-Chw-PRE-001, SPO-Chw-PR-001
func TestTheDirectoryOpensTheSessionOnceAtPlanTimeAndNeverForSoftwareKeys(t *testing.T) {
	r := newRig(t, "Ledger", "8.0.8")
	lazy := lazyFor(r)
	dir := native.Signers{Keys: hwIndex{}, Hardware: lazy}

	// A key no device holds has no signer, and asking never touches the device.
	nobody, _ := identity.KeyHashOf(make([]byte, 32))
	if _, err := dir.SignerFor(custody.KeyRef{Role: custody.RolePayment, Identity: nobody}); !errors.Is(err, ports.ErrNoSignerFor) {
		t.Fatalf("a key no device holds: %v", err)
	}
	if r.called("device", "version") != 0 {
		t.Error("the device was probed for a vault key")
	}
	sg, err := dir.SignerFor(hwKey(custody.RolePayment, "w"))
	if err != nil {
		t.Fatal(err)
	}
	if r.called("device", "version") != 0 {
		t.Error("SignerFor opened the session")
	}
	for i := 0; i < 3; i++ {
		_ = sg.Profile()
	}
	if n := r.called("device", "version"); n != 1 {
		t.Errorf("the session was opened %d times", n)
	}
	if err := ports.CheckSigner(sg); err != nil {
		t.Error(err)
	}
	if err := ports.CheckSignatureSigner(sg); err != nil {
		t.Error(err)
	}

	// Without a hardware signer wired the error names what is missing.
	_, err = native.Signers{Keys: hwIndex{}}.SignerFor(hwKey(custody.RolePayment, "w"))
	if !errors.Is(err, ports.ErrNoHardwareSigner) || !strings.Contains(err.Error(), "cardano-hw-cli") || !strings.Contains(err.Error(), "device") {
		t.Errorf("%v", err)
	}

	// With no device the plan says why.
	nr := newRig(t, "Ledger", "8.0.8", func(f *fakeCfg, c *hwcli.Config) { f.Device = "nodevice"; c.Timeout = 100 * time.Millisecond })
	nl := lazyFor(nr)
	_, err = ports.PlanSignatures(native.Signers{Keys: hwIndex{}, Hardware: nl}, []custody.Slot{{Label: "witness", Key: hwKey(custody.RolePayment, "w"),
		Demand: custody.Demand{Role: custody.RolePayment, Operation: custody.OpWitnessTx}}})
	if err == nil || !strings.Contains(err.Error(), "unavailable") || !errors.Is(nl.Err(), hwcli.ErrNoDevice) {
		t.Errorf("%v / %v", err, nl.Err())
	}
	// Methods return the typed error, not a panic.
	if _, err := nl.ExportHardwareKey(context.Background(), hwKey(custody.RolePayment, "w"), "1852H/1815H/0H/0/0"); !errors.Is(err, hwcli.ErrNoDevice) {
		t.Errorf("%v", err)
	}
}

// Exercised, still waived until a use case enables the hardware path: SPO-02-EXT-003, SPO-03a-EXT-002, SPO-04a-EXT-003
func TestGenerationPlansAcceptHardwareKeysOnlyWithAHardwareSigner(t *testing.T) {
	if _, err := custody.PlanGeneration(custody.PlaceHardware, custody.RolePoolCold); err == nil {
		t.Fatal("PlanGeneration (software only) accepted a hardware key")
	}
	profile := func(l *hwcli.Lazy) func(custody.Placement) (custody.Profile, error) {
		return func(custody.Placement) (custody.Profile, error) { return l.Profile(), nil }
	}
	if _, err := custody.PlanGenerationWith(profile(lazyFor(newRig(t, "Keystone", "1.7.7"))), custody.PlaceHardware, custody.RolePoolCold); err != nil {
		t.Errorf("Keystone cold key: %v", err)
	}
	var ue *custody.UnsupportedError
	if _, err := custody.PlanGenerationWith(profile(lazyFor(newRig(t, "Trezor", "2.7.2"))), custody.PlaceHardware, custody.RolePoolCold); !errors.As(err, &ue) {
		t.Errorf("Trezor cold key: %v", err)
	}
	if _, err := custody.PlanGenerationWith(nil, custody.PlaceHardware, custody.RolePoolCold); err == nil {
		t.Error("no hardware signer, accepted")
	}
}
