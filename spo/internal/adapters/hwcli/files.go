package hwcli

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/ports"
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

// HardwareSigningFile implements SigningFiles.
func (f StoreFiles) HardwareSigningFile(ctx context.Context, key custody.KeyRef) ([]byte, error) {
	kind, ok := hwsKinds[key.Role]
	if !ok {
		return nil, fmt.Errorf("a %s key has no hardware signing file", key.Role)
	}
	var out []byte
	err := f.Store.View(ctx, func(r ports.Reader) error {
		b, err := r.Get(ports.Ref{Name: key.Owner, Kind: kind})
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
