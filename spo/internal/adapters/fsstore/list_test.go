package fsstore

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Every artefact family of the catalogue maps from its file name to a
// reference and back; the most specific name wins.
//
// spec: SPO-Pfiles-IN-001, SPO-Pfiles-IN-003, SPO-Pfiles-OUT-001, SPO-Pfiles-OUT-002, SPO-Pfiles-OUT-004, SPO-Pfiles-OUT-005, SPO-Pfiles-OUT-010, SPO-Pfiles-OUT-013, SPO-Pfiles-OUT-014, SPO-Pfiles-OUT-016, SPO-Pfiles-OUT-022, SPO-Pfiles-OUT-031, SPO-Pfiles-OUT-032, SPO-Pfiles-OUT-033, SPO-Pfiles-OUT-034, SPO-Pfiles-OUT-035, SPO-Pfiles-OUT-036
func TestRefOfNamesEveryFamily(t *testing.T) {
	cases := map[string]ports.Ref{
		"w.addr":                    {Name: "w", Kind: ports.AddrFile},
		"w.vkey":                    {Name: "w", Kind: ports.AddrVKey},
		"w.payment.skey":            {Name: "w.payment", Kind: ports.AddrSKey},
		"w.staking.skey":            {Name: "w", Kind: ports.StakingSKey},
		"w.staking.addr":            {Name: "w", Kind: ports.StakingAddr},
		"w.payment.hwsfile":         {Name: "w.payment", Kind: ports.AddrHwsFile},
		"w.payment.mnemonics":       {Name: "w", Kind: ports.PaymentMnemonics},
		"p.node.skey":               {Name: "p", Kind: ports.NodeSKey},
		"p.node.hwsfile":            {Name: "p", Kind: ports.NodeHwsFile},
		"p.node.counter":            {Name: "p", Kind: ports.NodeCounter},
		"p.vrf.skey":                {Name: "p", Kind: ports.VrfSKey},
		"p.kes-003.skey":            {Name: "p", Kind: ports.KesSKey, Num: 3},
		"p.kes-012.vkey":            {Name: "p", Kind: ports.KesVKey, Num: 12},
		"p.kes.counter":             {Name: "p", Kind: ports.KesCounter},
		"p.kes.counter-next":        {Name: "p", Kind: ports.KesCounterNext},
		"p.node-004.opcert":         {Name: "p", Kind: ports.OpCert, Num: 4},
		"p.kes-expire.json":         {Name: "p", Kind: ports.KesExpire},
		"p.bls.skey":                {Name: "p", Kind: ports.BLSSKey},
		"p.itn.skey":                {Name: "p", Kind: ports.PoolItnSKey},
		"p.pool.json":               {Name: "p", Kind: ports.PoolDescriptor},
		"p.pool.id-bech":            {Name: "p", Kind: ports.PoolIDBechFile},
		"p.metadata.json":           {Name: "p", Kind: ports.PoolMetadata},
		"p_123_abcd.witness":        {Name: "p_123_abcd", Kind: ports.PoolWitnessFile},
		"d.drep.skey":               {Name: "d", Kind: ports.DRepSKey},
		"d.drep.vkey":               {Name: "d", Kind: ports.DRepVKey},
		"c.cc-cold.skey":            {Name: "c", Kind: ports.CCColdSKey},
		"pol.policy.skey":           {Name: "pol", Kind: ports.PolicySKey},
		"pol.coin.asset":            {Name: "pol.coin", Kind: ports.AssetFile},
		"v.voting.mnemonics":        {Name: "v", Kind: ports.VotingMnemonics},
		"v.catalyst-qrcode.png":     {Name: "v", Kind: ports.CatalystQRCode},
		"k.calidus.skey":            {Name: "k", Kind: ports.CalidusSKey},
		"w.upstream-encrypted.skey": {Name: "w", Kind: ports.UpstreamEncryptedSKey},
	}
	for file, want := range cases {
		got, ok := RefOf(file)
		if !ok || got != want {
			t.Errorf("%s: got %v %v, want %v", file, got, ok, want)
			continue
		}
		back, err := FileName(got)
		if err != nil || back != file {
			t.Errorf("%s: renders back as %q (%v)", file, back, err)
		}
	}
	for _, file := range []string{"offlineTransfer.json", "README", "x.txt", ".hidden.skey", "a b.skey", "notes.json"} {
		if ref, ok := RefOf(file); ok {
			t.Errorf("%s was recognised as %v", file, ref)
		}
	}
}

// spec: SPO-Pfiles-IN-001
func TestListReportsUnknownAndNeverFollowsLinks(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"p.node.vkey", "p.node.skey", "notes.txt", "offlineTransfer.json", ".spo-tmp-123"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o400); err != nil {
			t.Fatal(err)
		}
	}
	os.Mkdir(filepath.Join(dir, "sub"), 0o700)
	os.Symlink("p.node.skey", filepath.Join(dir, "link.skey"))
	st, _ := Open(dir)
	l, err := st.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Entries) != 2 {
		t.Errorf("entries: %v", l.Entries)
	}
	got := map[string]string{}
	for _, u := range l.Unknown {
		got[u.File] = u.Reason
	}
	for _, f := range []string{"notes.txt", "offlineTransfer.json", "sub", "link.skey"} {
		if got[f] == "" {
			t.Errorf("%s not reported as unknown: %v", f, got)
		}
	}
	if _, ok := got[".spo-tmp-123"]; ok {
		t.Error("a temporary file of this program was reported")
	}
}

// Modes of the artefacts that stay unlocked (SPO-Pfiles-INV-004) and of the
// published metadata (SPO-Pfiles-INV-005); everything else is 0400. The
// offline transfer bag is not a workspace artefact (SPO-Pfiles-OUT-037): the
// lister reports it and nothing writes it.
//
// spec: SPO-Pfiles-INV-004, SPO-Pfiles-INV-005, SPO-Pfiles-OUT-037
func TestModesOfUnlockedArtefacts(t *testing.T) {
	dir := t.TempDir()
	st, _ := Open(dir)
	want := map[ports.Ref]os.FileMode{
		{Name: "p", Kind: ports.PoolMetadata}:           0o444,
		{Name: "p", Kind: ports.PoolExtendedMetadata}:   0o444,
		{Name: "p", Kind: ports.PoolAdditionalMetadata}: 0o644,
		{Name: "p_1_ab", Kind: ports.PoolWitnessFile}:   0o644,
		{Name: "v", Kind: ports.VoteRegistration}:       0o644,
		{Name: "k", Kind: ports.CalidusRegistration}:    0o644,
		{Name: "pol", Kind: ports.PolicyScript}:         0o400,
		{Name: "p", Kind: ports.NodeVKey}:               0o400,
	}
	err := st.Update(context.Background(), func(w ports.Writer) error {
		for r := range want {
			if err := w.Put(r, []byte("{}")); err != nil {
				return err
			}
		}
		return w.PutSecret(ports.Ref{Name: "v", Kind: ports.CatalystQRCode}, secret.Take([]byte("png")))
	})
	if err != nil {
		t.Fatal(err)
	}
	for r, m := range want {
		name, _ := FileName(r)
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil || fi.Mode().Perm() != m {
			t.Errorf("%s: %v %v, want %v", name, fi, err, m)
		}
	}
	// upstream leaves the QR code at the process default; it is secret, so it is 0400 here
	if fi, _ := os.Stat(filepath.Join(dir, "v.catalyst-qrcode.png")); fi == nil || fi.Mode().Perm() != 0o400 {
		t.Errorf("the secret QR code must be 0400: %v", fi)
	}
}
