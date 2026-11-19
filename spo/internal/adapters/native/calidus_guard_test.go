package native

import (
	"context"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/porttest"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

// openCounter counts the keys the vault releases.
type openCounter struct {
	ports.Vault
	n int
}

func (o *openCounter) Open(ctx context.Context, ref ports.Ref) (*secret.Buffer, error) {
	o.n++
	return o.Vault.Open(ctx, ref)
}

// The adapter's SignText refuses data that is not UTF-8 text and the signing
// input of a relay statement, before it opens any key, and still signs text.
//
// spec: SPO-Xidentity-SEC-008, SPO-Xrelaybind-SEC-018
func TestSignTextRefusesRawStatementInputBeforeOpeningTheKey(t *testing.T) {
	ctx := context.Background()
	st, _ := plainstore.OpenTestnet(t.TempDir())
	m := secret.Take([]byte(testPhrase))
	defer m.Destroy()
	pair, err := SoftwareKeys{}.DeriveCalidus(ctx, m, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer pair.SKey.Destroy()
	if err := st.Update(ctx, func(w ports.NamedWriter) error {
		if err := w.Put(ports.NamedRef{Name: "cal", Kind: ports.CalidusVKey}, pair.VKey); err != nil {
			return err
		}
		return w.PutSecret(ports.NamedRef{Name: "cal", Kind: ports.CalidusSKey}, pair.SKey)
	}); err != nil {
		t.Fatal(err)
	}
	ref := porttest.Key(t, st, custody.RoleCalidus, "cal")
	key, err := custody.As[custody.Calidus](ref)
	if err != nil {
		t.Fatal(err)
	}
	oc := &openCounter{Vault: st.Anchor()}
	s := VaultSignatures{VaultSigner{Vault: oc, Keys: nil}}
	s.Keys, _ = VaultSigner{Vault: st.Anchor()}.index()

	var k [28]byte
	ss := cose.SigStructure(cose.ProtectedHeader(k[:]), cose.PayloadFor([]byte("spo-relay-binding-v1 device 00 from 0 until 3600"), false))
	for name, tc := range map[string]struct {
		in   []byte
		want error
	}{
		"Sig_structure": {ss, ports.ErrNotText},
		"not utf-8":     {[]byte{0x84, 0x6a}, ports.ErrNotText},
		"reserved":      {[]byte("spo-relay-binding-v1 x"), relaybind.ErrRawStatementInput},
	} {
		if _, err := s.SignText(ctx, key, tc.in); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	if oc.n != 0 {
		t.Errorf("the key was opened %d times for refused data", oc.n)
	}
	if _, err := s.SignText(ctx, key, []byte("hello pool")); err != nil {
		t.Errorf("ordinary text: %v", err)
	}
	if oc.n != 1 {
		t.Errorf("opens %d", oc.n)
	}
}
