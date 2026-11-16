package hwcli

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// What the key scripts rewrite in the files the tool wrote, per role: the
// hardware marker of the verification key's description
// (spec: SPO-Pfiles-INV-001) and the types the other tools expect.
type exportRewrite struct{ vkey, hws map[string]string }

var exportRewrites = map[custody.Role]exportRewrite{
	custody.RolePayment:      {vkey: map[string]string{"description": "Payment Hardware Verification Key"}},                                                                                             // SPO-02-OUT-002, SPO-03a-OUT-001
	custody.RoleStake:        {vkey: map[string]string{"description": "Stake Hardware Verification Key"}},                                                                                               // SPO-03a-OUT-001
	custody.RolePolicy:       {vkey: map[string]string{"description": "Mint Hardware Verification Key"}},                                                                                                // SPO-10-OUT-004
	custody.RoleDRep:         {vkey: map[string]string{"type": "DRepVerificationKey_ed25519", "description": "Hardware Delegate Representative Verification Key"}},                                      // SPO-21a-OUT-004
	custody.RoleCommitteeHot: {vkey: map[string]string{"type": "ConstitutionalCommitteeHotVerificationKey_ed25519"}, hws: map[string]string{"type": "ConstitutionalCommitteeHotHWSigningFile_ed25519"}}, // SPO-23b-OUT-003
	custody.RoleCatalystVote: {vkey: map[string]string{"description": "Hardware Catalyst Vote Verification Key"}, hws: map[string]string{"description": "Hardware Catalyst Vote Signing File"}},         // SPO-09a-OUT-004
	// Left as the tool wrote them: the pool cold key (SPO-04a has no rewrite) and the
	// committee cold key (SPO-23a-OUT-003).
}

func copySet(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// ExportHardwareKey implements ports.HardwareKeyExporter: `address key-gen`
// (`node key-gen` for the pool cold key) at the derivation path, with the
// verification key and signing file written to the private directory and read
// back. The verification key's description (and type, where the scripts set it)
// is rewritten to the hardware marker forms of SPO-Pfiles-INV-001. For a cold
// key the tool also writes the issue counter; it is discarded here, because the
// counter is a domain artefact the caller creates from the verification key.
//
// spec: SPO-02-EXT-003, SPO-02-OUT-002, SPO-03a-EXT-002, SPO-03a-EXT-004, SPO-03a-OUT-001, SPO-04a-EXT-003, SPO-04a-EXT-004, SPO-04a-PRE-005, SPO-10-EXT-002, SPO-10-OUT-004, SPO-21a-EXT-004, SPO-21a-OUT-004, SPO-23a-EXT-004, SPO-23a-OUT-003, SPO-23b-EXT-004, SPO-23b-OUT-003, SPO-09a-EXT-002, SPO-09a-OUT-004, SPO-Pfiles-OUT-004
func (s *Session) ExportHardwareKey(ctx context.Context, key custody.KeyRef, path string) (ports.HardwareKey, error) {
	if err := s.has(key.Role, custody.OpExportVKey); err != nil {
		return ports.HardwareKey{}, err
	}
	if !custody.ValidHardwarePath(path) {
		return ports.HardwareKey{}, fmt.Errorf("%q is not a derivation path (numbers separated by '/', 'H' for hardened)", path)
	}
	sc, err := s.scratch()
	if err != nil {
		return ports.HardwareKey{}, err
	}
	defer sc.done()
	vk, hws := sc.path("key.vkey"), sc.path("key.hwsfile")

	var args []string
	if key.Role == custody.RolePoolCold {
		args = []string{"node", "key-gen", "--path", path, "--cold-verification-key-file", vk, "--hw-signing-file", hws,
			"--operational-certificate-issue-counter-file", sc.path("key.counter")}
	} else {
		args = []string{"address", "key-gen", "--path", path, "--verification-key-file", vk, "--hw-signing-file", hws}
	}
	if _, err := s.run(ctx, args...); err != nil {
		return ports.HardwareKey{}, err
	}
	vkey, err1 := os.ReadFile(vk)
	hwsfile, err2 := os.ReadFile(hws)
	if err1 != nil || err2 != nil {
		return ports.HardwareKey{}, fmt.Errorf("%w: the verification key or the signing file was not written", ErrBadDeviceOutput)
	}
	env, err := pool.ParseEnvelope(vkey)
	if err != nil {
		return ports.HardwareKey{}, fmt.Errorf("%w: the verification key is not a text envelope", ErrBadDeviceOutput)
	}
	if pub, ok := hwsfilePubKey(hwsfile); ok {
		if raw, err := env.Key32(); err == nil && !bytes.Equal(raw, pub) {
			return ports.HardwareKey{}, fmt.Errorf("%w: the verification key is not the signing file's public key", ErrBadDeviceOutput)
		}
	}
	rw := exportRewrites[key.Role]
	if rw.vkey != nil {
		if vkey, err = rewriteFields(vkey, copySet(rw.vkey)); err != nil {
			return ports.HardwareKey{}, err
		}
	}
	if rw.hws != nil {
		if hwsfile, err = rewriteFields(hwsfile, copySet(rw.hws)); err != nil {
			return ports.HardwareKey{}, err
		}
	}
	return ports.HardwareKey{VKey: vkey, SigningFile: hwsfile}, nil
}
