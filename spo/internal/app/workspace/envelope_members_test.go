package workspace

import (
	"context"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// withExtraMember adds a member to an encrypted envelope, as an attacker or a
// careless tool would to carry a plaintext key beside the ciphertext.
func withExtraMember(t *testing.T, env []byte) []byte {
	t.Helper()
	s := string(env)
	i := strings.LastIndex(s, "}")
	if i < 0 {
		t.Fatal("no object")
	}
	return []byte(s[:i] + `, "cborHex2": "5820aabb"` + s[i:])
}

// An encrypted envelope with a member other than type, description and
// encrHex is neither imported (with or without --keep-encrypted) nor exported.
//
// spec: SPO-Xcustody-INV-005
func TestEncryptedEnvelopeWithAnExtraMemberIsRefusedOnImportAndExport(t *testing.T) {
	src, keys := workspaceFixture(t)
	bad := withExtraMember(t, encryptedOf(t, keys["cold"], "Str0ng-Passw0rd!-And-Long"))
	src.put(ref("mypool", ports.NodeSKey), bad)

	for _, keep := range []bool{true, false} {
		dst := newMem()
		opts := ImportOptions{Owners: []string{"mypool"}, KeepEncrypted: keep}
		rep, _ := importer(src, dst, &fakeGPG{}).Run(context.Background(), opts)
		if rep != nil && rep.Failed() == 0 {
			t.Errorf("keep=%v: the import accepted the envelope", keep)
		}
		for r, b := range dst.snapshot() {
			if r.Kind == ports.UpstreamEncryptedSKey || r == ref("mypool", ports.NodeSKey) {
				t.Errorf("keep=%v: stored %v (%d bytes)", keep, r, len(b))
			}
		}
	}

	// In the workspace store: the export does not copy it verbatim.
	ws := newMem()
	ws.put(ref("mypool", ports.NodeSKey), bad)
	out := newMem()
	rep, _ := exporter(ws, out, &fakeGPG{}, &auditLog{}).Run(context.Background(), ExportOptions{Owners: []string{"mypool"}, Password: sec("Str0ng-Passw0rd!-And-Long")})
	if rep != nil && rep.Failed() == 0 {
		t.Error("the export accepted the envelope")
	}
	if _, ok := out.snapshot()[ref("mypool", ports.NodeSKey)]; ok {
		t.Error("the envelope with an extra member was written")
	}
}
