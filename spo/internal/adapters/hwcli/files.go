package hwcli

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
)

// StoreFiles reads the hardware signing file of a key from the workspace
// store (SPO-Pfiles-OUT-004): the file is Sensitive, so it comes from the store
// and never from a path the operator names.
type StoreFiles struct{ Store ports.Store }

var hwsKinds = map[custody.Role]ports.Kind{
	custody.RolePayment:       ports.AddrHwsFile,
	custody.RoleStake:         ports.StakingHwsFile,
	custody.RolePoolCold:      ports.NodeHwsFile,
	custody.RoleDRep:          ports.DRepHwsFile,
	custody.RoleCommitteeCold: ports.CCColdHwsFile,
	custody.RoleCommitteeHot:  ports.CCHotHwsFile,
	custody.RolePolicy:        ports.PolicyHwsFile,
	custody.RoleCatalystVote:  ports.VotingHwsFile,
	custody.RoleCalidus:       ports.CalidusHwsFile,
}

// HardwareSigningFile implements SigningFiles. The file is found by the
// identity of the key the demand names, through the stored hardware-key
// records: the device answers for the keys it has exported a verification key
// for (ADR 0010 decision 3).
func (f StoreFiles) HardwareSigningFile(ctx context.Context, key custody.KeyRef) ([]byte, error) {
	if _, ok := hwsKinds[key.Role]; !ok {
		return nil, fmt.Errorf("a %s key has no hardware signing file", key.Role)
	}
	idx := labels.NewIndex(f.Store)
	homes, err := idx.Homes(ctx, key.Identity)
	if err != nil {
		return nil, err
	}
	h, ok := ports.HardwareHome(homes, key.Role)
	if !ok {
		return nil, fmt.Errorf("%w: no hardware signing file is stored for the %s", ports.ErrNotFound, key)
	}
	var out []byte
	err = f.Store.View(ctx, func(r ports.Reader) error {
		b, err := r.Get(h.HardwareRef())
		out = b
		return err
	})
	return out, err
}

// hwsfilePubKey returns the 32-byte public key of a hardware signing file: the
// first 32 bytes of `cborXPubKeyHex` after its 2-byte CBOR header (the extended
// public key is key and chain code; SPO-24b-PRE-008).
func hwsfilePubKey(file []byte) ([]byte, bool) {
	var j struct {
		X string `json:"cborXPubKeyHex"`
	}
	if json.Unmarshal(file, &j) != nil {
		return nil, false
	}
	raw, err := hex.DecodeString(j.X)
	if err != nil || len(raw) < 2+32 || raw[0] != 0x58 {
		return nil, false
	}
	return raw[2 : 2+32], true
}

// ErrWrongKey means the device answered for another key than the demanded one:
// the hardware signing file stored for the identity has the public key of
// another account (ADR 0010 decision 3: a wrong device account is refused).
var ErrWrongKey = ports.ErrWrongHardwareFile

// wantID is the identity every answer of the device is verified against: the
// demanded identity, which must be the hash of the public key of the signing
// file the answer was made with. A reference with no identity (a key being
// made) takes the file's own.
func wantID(key custody.KeyRef, pub []byte) (identity.Ref, error) {
	got, err := identity.KeyHashOf(pub)
	if err != nil {
		return identity.Ref{}, fmt.Errorf("%w: %v", ErrBadDeviceOutput, err)
	}
	if key.Identity.Is(identity.KindKeyHash) && key.Identity != got {
		return identity.Ref{}, fmt.Errorf("%w: the signing file for the %s has the key %s, not %s", ErrWrongKey, key.Role, got, key.Identity)
	}
	return got, nil
}

// rewriteFields sets top-level string members of a JSON object, keeping the
// order of the members and everything else (the `jq` edit of SPO-Pfiles-INV-001).
// It returns the input unchanged when nothing differs.
func rewriteFields(file []byte, set map[string]string) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(file))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, fmt.Errorf("%w: not a JSON object", ErrBadDeviceOutput)
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
	changed, first := false, true
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBadDeviceOutput, err)
		}
		key := kt.(string)
		var val json.RawMessage
		if err := dec.Decode(&val); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBadDeviceOutput, err)
		}
		if want, ok := set[key]; ok {
			nv, _ := json.Marshal(want)
			if !bytes.Equal(nv, bytes.TrimSpace(val)) {
				val, changed = nv, true
			}
			delete(set, key)
		}
		if !first {
			buf.WriteByte(',')
		}
		first = false
		kb, _ := json.Marshal(key)
		buf.Write(kb)
		buf.WriteByte(':')
		buf.Write(val)
	}
	if _, err := dec.Token(); err != nil && err != io.EOF {
		return nil, fmt.Errorf("%w: %v", ErrBadDeviceOutput, err)
	}
	for k, v := range set { // members the tool did not write are added
		kb, _ := json.Marshal(k)
		vb, _ := json.Marshal(v)
		if !first {
			buf.WriteByte(',')
		}
		first = false
		buf.Write(kb)
		buf.WriteByte(':')
		buf.Write(vb)
		changed = true
	}
	buf.WriteByte('}')
	if !changed {
		return file, nil
	}
	var out bytes.Buffer
	if err := json.Indent(&out, buf.Bytes(), "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}
