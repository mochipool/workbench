package upstreamdir

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// Every artefact family of the catalogue maps from its file name to a
// reference and back; the most specific name wins.
//
// spec: SPO-Pfiles-IN-001, SPO-Pfiles-IN-003, SPO-Pfiles-OUT-001, SPO-Pfiles-OUT-002, SPO-Pfiles-OUT-004, SPO-Pfiles-OUT-005, SPO-Pfiles-OUT-010, SPO-Pfiles-OUT-013, SPO-Pfiles-OUT-014, SPO-Pfiles-OUT-016, SPO-Pfiles-OUT-022, SPO-Pfiles-OUT-031, SPO-Pfiles-OUT-032, SPO-Pfiles-OUT-033, SPO-Pfiles-OUT-034, SPO-Pfiles-OUT-035, SPO-Pfiles-OUT-036
func TestRefOfNamesEveryFamily(t *testing.T) {
	cases := map[string]ports.NamedRef{
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
