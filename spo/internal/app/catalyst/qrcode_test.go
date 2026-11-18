package catalyst

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/adapters/qrcode"
	domcat "github.com/mochipool/workbench/spo/internal/domain/catalyst"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// qrAudit keeps the audit events and says what the vault had been asked for by
// then, so a test can pin that the record comes first.
type qrAudit struct {
	events []ports.AuditEvent
	fail   error
	order  *[]string
}

func (a *qrAudit) Record(_ context.Context, e ports.AuditEvent) error {
	if a.order != nil {
		*a.order = append(*a.order, "audit")
	}
	if a.fail != nil {
		return a.fail
	}
	a.events = append(a.events, e)
	return nil
}

type orderSource struct {
	ports.VotingKeyQRSource
	order *[]string
}

func (o orderSource) VotingKeyQRPayload(ctx context.Context, n string, p domcat.PIN) ([]byte, error) {
	*o.order = append(*o.order, "payload")
	return o.VotingKeyQRSource.VotingKeyQRPayload(ctx, n, p)
}

func (r rig) qrUC() ExportVotingKeyQR {
	return ExportVotingKeyQR{Store: r.store, Source: native.VotingKeyQR{Vault: r.store}, Renderer: qrcode.Renderer{}, Auditor: &qrAudit{}}
}

// voteSecret is the 64 bytes the QR code must carry: the first 64 bytes of the
// 128 of the stored extended key.
func (r rig) voteSecret(t *testing.T, name string) []byte {
	t.Helper()
	env, err := r.store.Open(context.Background(), ports.NamedRef{Name: name, Kind: ports.VotingSKey})
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

// spec: SPO-09a-EXT-005, SPO-09a-OUT-007, SPO-Xcustody-INV-001, SPO-Xcustody-OUT-004, SPO-Xcustody-PRE-005
// The drawing is the one output: nothing is written to the file system, the
// display is audited before the payload is built, the audit record names the
// key and holds no secret, and the payload behind the drawing decrypts with the
// PIN to the stored extended key.
func TestExportVotingKeyQR(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	m := secret.Take([]byte(phrase))
	defer m.Destroy()
	if _, err := r.keyUC().Run(ctx, GenerateVotingKeyRequest{Name: "v", Mnemonic: m}); err != nil {
		t.Fatal(err)
	}
	wd := t.TempDir()
	t.Chdir(wd)
	var order []string
	aud := &qrAudit{order: &order}
	uc := r.qrUC()
	uc.Auditor = aud
	uc.Source = orderSource{uc.Source, &order}
	res, err := uc.Run(ctx, QRRequest{Name: "./v", PIN: []byte("1234")})
	if err != nil {
		t.Fatal(err)
	}
	if res.Name != "v" || !strings.Contains(res.Terminal, "█") {
		t.Errorf("%+v", res)
	}
	if len(order) != 2 || order[0] != "audit" || order[1] != "payload" {
		t.Errorf("order %v: the display must be audited before the payload is built", order)
	}
	if len(aud.events) != 1 || aud.events[0].Operation != QRDisplayOperation || len(aud.events[0].Owners) != 1 || aud.events[0].Owners[0] != "v" {
		t.Errorf("audit %+v", aud.events)
	}
	if ents, _ := os.ReadDir(wd); len(ents) != 0 {
		t.Errorf("the use case wrote files: %v", ents)
	}
	// A display that cannot be recorded is not made.
	order = nil
	uc.Auditor = &qrAudit{fail: errors.New("disk full"), order: &order}
	if res, err := uc.Run(ctx, QRRequest{Name: "v", PIN: []byte("1234")}); err == nil || res.Terminal != "" {
		t.Errorf("unaudited display: %v %+v", err, res)
	}
	if len(order) != 1 {
		t.Errorf("the payload was built after the audit failed: %v", order)
	}
	// No auditor: not configured.
	uc.Auditor = nil
	if _, err := uc.Run(ctx, QRRequest{Name: "v", PIN: []byte("1234")}); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("no auditor: %v", err)
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
// before anything is audited or drawn.
func TestExportVotingKeyQRRefusals(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if _, err := r.qrUC().Run(ctx, QRRequest{Name: "nope", PIN: []byte("1234")}); !errors.Is(err, ErrMissingFile) {
		t.Errorf("missing: %v", err)
	}
	r.put(t, ports.NamedRef{Name: "hw", Kind: ports.VotingHwsFile}, []byte("{}"))
	if _, err := r.qrUC().Run(ctx, QRRequest{Name: "hw", PIN: []byte("1234")}); !errors.Is(err, ErrHardwareVotingKey) {
		t.Errorf("hardware: %v", err)
	}
	m := secret.Take([]byte(phrase))
	defer m.Destroy()
	if _, err := r.keyUC().Run(ctx, GenerateVotingKeyRequest{Name: "v", Mnemonic: m}); err != nil {
		t.Fatal(err)
	}
	for _, pin := range []string{"", "123", "12345", "12a4", "-123"} {
		if _, err := r.qrUC().Run(ctx, QRRequest{Name: "v", PIN: []byte(pin)}); !errors.Is(err, domcat.ErrBadPIN) {
			t.Errorf("pin %q: %v", pin, err)
		}
	}
	if _, err := r.qrUC().Run(ctx, QRRequest{Name: "../v", PIN: []byte("1234")}); !errors.Is(err, ErrBadName) {
		t.Errorf("name: %v", err)
	}
}
