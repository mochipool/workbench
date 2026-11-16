package catalyst

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/adapters/qrcode"
	domcat "github.com/mochipool/workbench/spo/internal/domain/catalyst"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func (r rig) qrUC() ExportVotingKeyQR {
	return ExportVotingKeyQR{Store: r.store, Source: native.VotingKeyQR{Vault: r.store}, Renderer: qrcode.Renderer{}}
}

// voteSecret is the 64 bytes the QR code must carry: the first 64 bytes of the
// 128 of the stored extended key.
func (r rig) voteSecret(t *testing.T, name string) []byte {
	t.Helper()
	env, err := r.store.Open(context.Background(), ports.Ref{Name: name, Kind: ports.VotingSKey})
	if err != nil {
		t.Fatal(err)
	}
	defer env.Destroy()
	var out []byte
	_ = env.Use(func(b []byte) error {
		var e struct {
			CborHex string `json:"cborHex"`
		}
		if err := json.Unmarshal(b, &e); err != nil {
			t.Fatal(err)
		}
		raw, _ := hex.DecodeString(e.CborHex)
		out = append([]byte(nil), raw[2:66]...)
		return nil
	})
	return out
}

// spec: SPO-09a-EXT-005, SPO-09a-OUT-007, SPO-09a-PRE-010
// The PNG exists with mode 0600, the terminal drawing is the second output, the
// key file is unchanged, and the payload behind it decrypts with the PIN to the
// stored extended key.
func TestExportVotingKeyQR(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	m := secret.Take([]byte(phrase))
	defer m.Destroy()
	if _, err := r.keyUC().Run(ctx, GenerateVotingKeyRequest{Name: "v", Mnemonic: m}); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "v.catalyst-qrcode.png")
	res, err := r.qrUC().Run(ctx, QRRequest{Name: "./v", PIN: []byte("1234"), Path: out})
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(out); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("png: %v %v", st, err)
	}
	if res.Name != "v" || !strings.Contains(res.Terminal, "█") {
		t.Errorf("%+v", res)
	}
	// A second run does not overwrite.
	before, _ := os.ReadFile(out)
	if _, err := r.qrUC().Run(ctx, QRRequest{Name: "v", PIN: []byte("1234"), Path: out}); !errors.Is(err, ports.ErrQRFileExists) {
		t.Errorf("overwrite: %v", err)
	}
	if after, _ := os.ReadFile(out); !bytes.Equal(before, after) {
		t.Error("the file changed")
	}
	// The payload round trips to the stored key.
	pin, _ := domcat.ParsePIN([]byte("1234"))
	payload, err := native.VotingKeyQR{Vault: r.store}.VotingKeyQRPayload(ctx, "v", pin)
	if err != nil {
		t.Fatal(err)
	}
	got, err := domcat.Decode(payload, pin)
	if err != nil || !bytes.Equal(got, r.voteSecret(t, "v")) {
		t.Errorf("round trip: %v", err)
	}
	if _, err := domcat.Decode(payload, domcat.PIN{9, 9, 9, 9}); err == nil {
		t.Error("another PIN decrypts")
	}
}

// spec: SPO-09a-PRE-008, SPO-09a-PRE-009
// A missing key, a hardware key and a bad PIN are refused in the spec's order,
// before a file is written.
func TestExportVotingKeyQRRefusals(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	dir := t.TempDir()
	out := filepath.Join(dir, "x.png")
	if _, err := r.qrUC().Run(ctx, QRRequest{Name: "nope", PIN: []byte("1234"), Path: out}); !errors.Is(err, ErrMissingFile) {
		t.Errorf("missing: %v", err)
	}
	r.put(t, ports.Ref{Name: "hw", Kind: ports.VotingHwsFile}, []byte("{}"))
	if _, err := r.qrUC().Run(ctx, QRRequest{Name: "hw", PIN: []byte("1234"), Path: out}); !errors.Is(err, ErrHardwareVotingKey) {
		t.Errorf("hardware: %v", err)
	}
	m := secret.Take([]byte(phrase))
	defer m.Destroy()
	if _, err := r.keyUC().Run(ctx, GenerateVotingKeyRequest{Name: "v", Mnemonic: m}); err != nil {
		t.Fatal(err)
	}
	for _, pin := range []string{"", "123", "12345", "12a4", "-123"} {
		if _, err := r.qrUC().Run(ctx, QRRequest{Name: "v", PIN: []byte(pin), Path: out}); !errors.Is(err, domcat.ErrBadPIN) {
			t.Errorf("pin %q: %v", pin, err)
		}
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("a refusal wrote the file")
	}
	if _, err := r.qrUC().Run(ctx, QRRequest{Name: "../v", PIN: []byte("1234"), Path: out}); !errors.Is(err, ErrBadName) {
		t.Errorf("name: %v", err)
	}
}
