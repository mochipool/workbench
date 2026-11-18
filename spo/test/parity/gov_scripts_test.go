package parity

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/governance"
	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	dgov "github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// govSnap is what parity compares of the key files of one name: for each
// artefact its mode, and its content where the content is deterministic (a
// mnemonic key, a given phrase). Random keys are compared by envelope type,
// description and the length of the cborHex.
func govSnap(t *testing.T, dir, prefix string, deterministic bool) state {
	t.Helper()
	out := state{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range entries {
		name := en.Name()
		if !strings.HasPrefix(name, prefix+".") {
			continue
		}
		info, _ := en.Info()
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		desc := "mode=" + info.Mode().Perm().String() + " "
		var envl struct {
			Type, Description, CborHex string
		}
		switch {
		case deterministic && strings.HasSuffix(name, ".skey"):
			desc += "secret len=" + itoa(len(raw)) // the key itself is compared below, never printed
		case deterministic:
			desc += "content=" + string(raw)
		case json.Unmarshal(raw, &envl) == nil && envl.Type != "":
			desc += "envelope=" + envl.Type + " description=" + envl.Description + " cborHexLen=" + itoa(len(envl.CborHex)) + " bytes=" + itoa(len(raw))
		case strings.HasSuffix(name, ".id"):
			desc += "id prefix=" + string(raw[:5]) + " len=" + itoa(len(raw))
		case strings.HasSuffix(name, ".hash"):
			desc += "hash len=" + itoa(len(raw)) + " newline=" + itoa(strings.Count(string(raw), "\n"))
		case strings.HasSuffix(name, ".mnemonics"):
			desc += "words=" + itoa(len(strings.Fields(string(raw)))) + " newline=" + itoa(strings.Count(string(raw), "\n"))
		default:
			desc += "content=" + string(raw)
		}
		out[name] = desc
	}
	return out
}

func govKeys() native.SoftwareKeys { return native.SoftwareKeys{} }

const publicPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

type keyScript struct {
	name, script, prefix string
	run                  func(st ports.NamedStore, req governance.GenerateKeysRequest) error
}

func keyScripts() []keyScript {
	return []keyScript{
		{"DRep", "21a_genDRepKeys.sh", "x", func(st ports.NamedStore, req governance.GenerateKeysRequest) error {
			_, err := governance.GenerateDRepKeys{Store: st, Keys: govKeys(), Deriver: govKeys(), Mnemonics: govKeys()}.Run(context.Background(), req)
			return err
		}},
		{"committee cold", "23a_genComColdKeys.sh", "x", func(st ports.NamedStore, req governance.GenerateKeysRequest) error {
			_, err := governance.GenerateCommitteeColdKeys{Store: st, Keys: govKeys(), Deriver: govKeys(), Mnemonics: govKeys()}.Run(context.Background(), req)
			return err
		}},
		{"committee hot", "23b_genComHotKeys.sh", "x", func(st ports.NamedStore, req governance.GenerateKeysRequest) error {
			_, err := governance.GenerateCommitteeHotKeys{Store: st, Keys: govKeys(), Deriver: govKeys(), Mnemonics: govKeys()}.Run(context.Background(), req)
			return err
		}},
	}
}

// Random governance keys: the artefacts, their modes, the envelope types and
// descriptions and the id or hash files are those of 21a, 23a and 23b with
// the key type `cli`.
//
// spec: SPO-21a-EXT-001, SPO-21a-EXT-005, SPO-21a-INV-003, SPO-21a-IF-001, SPO-21a-OUT-001, SPO-Pfiles-OUT-024,
// spec: SPO-23a-EXT-001, SPO-23a-EXT-005, SPO-23a-INV-003, SPO-23b-EXT-001, SPO-23b-EXT-005, SPO-23b-INV-003, SPO-Pfiles-OUT-026, SPO-Pfiles-OUT-027
func TestGovKeyGenerationParity(t *testing.T) {
	e := setup(t)
	for _, ks := range keyScripts() {
		t.Run(ks.name, func(t *testing.T) {
			upDir := e.upstreamWorkspace(t)
			st, portDir := openStore(t)
			if code := e.upstream(t, upDir, "exec", ks.script, ks.prefix, "cli"); code != 0 {
				t.Fatalf("upstream %s exited %d", ks.script, code)
			}
			if err := ks.run(st, governance.GenerateKeysRequest{Name: ks.prefix, Source: governance.KeysRandom}); err != nil {
				t.Fatal(err)
			}
			up := govSnap(t, upDir, ks.prefix, false)
			if len(up) != 3 {
				t.Fatalf("upstream artefacts: %v", up)
			}
			diff(t, ks.script, up, govSnap(t, portDir, ks.prefix, false))
		})
	}
}

// Mnemonic-derived DRep and committee keys, for the public test phrase and
// two account/index pairs, are byte-equal to what cardano-signer derives in
// the upstream scripts: the verification and signing key files, the id or hash
// file and the mnemonics file. The signing keys are compared without being printed.
//
// spec: SPO-21a-EXT-003, SPO-21a-INV-002, SPO-21a-OUT-002, SPO-21a-OUT-003, SPO-21a-IF-003, SPO-21a-IF-004,
// spec: SPO-23a-EXT-003, SPO-23a-INV-002, SPO-23a-OUT-002, SPO-23b-EXT-003, SPO-23b-INV-002, SPO-23b-OUT-002, SPO-23a-IF-003, SPO-23b-IF-003
func TestGovMnemonicKeysMatchUpstream(t *testing.T) {
	e := setup(t)
	e.needSigner(t)
	for _, ks := range keyScripts() {
		for _, ai := range []struct {
			a, i uint32
		}{{0, 0}, {3, 7}} {
			t.Run(fmt.Sprintf("%s acc %d idx %d", ks.name, ai.a, ai.i), func(t *testing.T) {
				upDir := e.upstreamWorkspace(t)
				st, portDir := openStore(t)
				if code := e.upstream(t, upDir, "exec", ks.script, ks.prefix, "mnemonics", fmt.Sprintf("acc:%d", ai.a), fmt.Sprintf("idx:%d", ai.i), "mnemonics:"+publicPhrase); code != 0 {
					t.Fatalf("upstream %s exited %d", ks.script, code)
				}
				m := secret.Take([]byte(publicPhrase))
				defer m.Destroy()
				if err := ks.run(st, governance.GenerateKeysRequest{Name: ks.prefix, Source: governance.KeysMnemonic, Account: ai.a, Index: ai.i, Mnemonic: m}); err != nil {
					t.Fatal(err)
				}
				up := govSnap(t, upDir, ks.prefix, true)
				if len(up) != 4 {
					t.Fatalf("upstream artefacts: %v", up)
				}
				diff(t, ks.script, up, govSnap(t, portDir, ks.prefix, true))
				for name := range up {
					if a, b := readFile(t, upDir, name), readFile(t, portDir, name); a != b {
						if strings.HasSuffix(name, ".skey") {
							t.Errorf("%s differs (not shown: signing key)", name)
						} else {
							t.Errorf("%s differs\n  upstream: %q\n  native:   %q", name, a, b)
						}
					}
				}
			})
		}
	}
}

// Upstream generates the phrase; the native derivation of that phrase gives the
// files the script made, and the native generator's phrase has the shape of
// upstream's.
//
// spec: SPO-21a-EXT-003, SPO-21a-OUT-002, SPO-21a-SEC-002, SPO-23a-OUT-002, SPO-23b-OUT-002
func TestGovFreshMnemonicParity(t *testing.T) {
	e := setup(t)
	e.needSigner(t)
	for _, ks := range keyScripts() {
		t.Run(ks.name, func(t *testing.T) {
			upDir := e.upstreamWorkspace(t)
			st, portDir := openStore(t)
			if code := e.upstream(t, upDir, "exec", ks.script, ks.prefix, "mnemonics"); code != 0 {
				t.Fatalf("upstream %s exited %d", ks.script, code)
			}
			if err := ks.run(st, governance.GenerateKeysRequest{Name: ks.prefix, Source: governance.KeysMnemonic}); err != nil {
				t.Fatal(err)
			}
			diff(t, ks.script+" fresh phrase", govSnap(t, upDir, ks.prefix, false), govSnap(t, portDir, ks.prefix, false))
			mn := ".drep.mnemonics"
			derive := govKeys().DeriveDRep
			switch ks.script[:3] {
			case "23a":
				mn, derive = ".cc-cold.mnemonics", govKeys().DeriveCommitteeCold
			case "23b":
				mn, derive = ".cc-hot.mnemonics", govKeys().DeriveCommitteeHot
			}
			words := secret.Take([]byte(strings.TrimSpace(readFile(t, upDir, ks.prefix+mn))))
			defer words.Destroy()
			pair, err := derive(context.Background(), words, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer pair.SKey.Destroy()
			vk := strings.TrimSuffix(mn, ".mnemonics") + ".vkey"
			if string(pair.VKey) != readFile(t, upDir, ks.prefix+vk) {
				t.Error("native derivation of upstream's generated phrase gives another verification key")
			}
		})
	}
}

// Refusals of upstream and of the port agree: the second run on the same name
// is refused (exit 2 upstream) and writes nothing new; the hot key replace
// needs the explicit answer.
//
// spec: SPO-21a-PRE-004, SPO-21a-PRE-005, SPO-21a-PRE-006, SPO-23a-PRE-003, SPO-23b-PR-001
func TestGovKeyRefusalsMatchUpstream(t *testing.T) {
	e := setup(t)
	for _, ks := range keyScripts() {
		t.Run(ks.name, func(t *testing.T) {
			upDir := e.upstreamWorkspace(t)
			st, portDir := openStore(t)
			if code := e.upstream(t, upDir, "exec", ks.script, ks.prefix, "cli"); code != 0 {
				t.Fatalf("upstream first run exited %d", code)
			}
			if err := ks.run(st, governance.GenerateKeysRequest{Name: ks.prefix, Source: governance.KeysRandom}); err != nil {
				t.Fatal(err)
			}
			before := govSnap(t, portDir, ks.prefix, false)
			err := ks.run(st, governance.GenerateKeysRequest{Name: ks.prefix, Source: governance.KeysRandom})
			if err == nil {
				t.Fatal("the port generated over existing keys")
			}
			diff(t, "after the refused run", before, govSnap(t, portDir, ks.prefix, false))
			if ks.script[:3] == "23b" {
				// Upstream asks "delete them and generate new ones?" (default No): its
				// refusal is the declined prompt, exit 1 with no input.
				if code := e.upstream(t, upDir, "exec", ks.script, ks.prefix, "cli"); code != 1 {
					t.Errorf("upstream second 23b exited %d, want 1", code)
				}
				return
			}
			if code := e.upstream(t, upDir, "exec", ks.script, ks.prefix, "cli"); code != 2 {
				t.Errorf("upstream second run exited %d, want 2", code)
			}
		})
	}
}

// ---- the queued transactions --------------------------------------------------

func govBase(k kit) governance.Base {
	return governance.Base{Store: k.store, Addresses: k.led, Params: k.file, Tip: k.base.Tip, Utxos: k.file, NetworkID: ports.NetworkTestnet,
		Pipeline: k.base.Pipeline}
}

// govCase is one transaction use case against its upstream script, offline.
type govCase struct {
	name   string
	drep   map[string]any
	script string
	args   []string
	// ttl is the validity the script adds to the slot: 100000, or 25000 for 25b.
	ttl uint64
	run func(t *testing.T, k kit) (txflow.Result, error)
	// wantFiles are files both sides must hold equal afterwards.
	wantFiles []string
}

func (e env) govBase(t *testing.T) stakeBase {
	t.Helper()
	b := e.stakeBase(t)
	// Vote and action files made by the Go builders, byte-equal to cardano-cli's
	// (TestGovVoteFilesMatchCardanoCLI), shared by both workspaces.
	led := native.Ledger{}
	drep := e.fileKeyHash(t, filepath.Join(b.dir, "d.drep.vkey"))
	pool := e.fileKeyHash(t, filepath.Join(b.dir, "mypool.node.vkey"))
	tx1 := mustTxID(t, "6b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c")
	tx2 := mustTxID(t, "0b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c")
	put := func(name string, mode os.FileMode, data []byte) {
		if err := os.WriteFile(filepath.Join(b.dir, name), data, mode); err != nil {
			t.Fatal(err)
		}
	}
	for name, v := range map[string]dgov.Vote{
		"d_240101000001.drep.vote":      {Voter: dgov.Voter{Role: dgov.RoleDRep, Cred: dgov.Credential{Hash: drep}}, Action: dgov.ActionID{TxID: tx1, Index: 2}, Decision: dgov.Yes},
		"d_240101000002.drep.vote":      {Voter: dgov.Voter{Role: dgov.RoleDRep, Cred: dgov.Credential{Hash: drep}}, Action: dgov.ActionID{TxID: tx2, Index: 0}, Decision: dgov.Abstain, Anchor: govAnchor(t)},
		"mypool_240101000003.pool.vote": {Voter: dgov.Voter{Role: dgov.RolePool, Cred: dgov.Credential{Hash: pool}}, Action: dgov.ActionID{TxID: tx1, Index: 2}, Decision: dgov.No},
	} {
		vf, err := led.BuildVoteFile(v, "Fund the thing")
		if err != nil {
			t.Fatal(err)
		}
		put(name, 0o644, vf.Envelope)
	}
	ret := dgov.Credential{Hash: e.fileKeyHash(t, filepath.Join(b.dir, "w.staking.vkey"))}
	retAddr := chain.StakeAddress(b.stakeAddr)
	mk := func(a dgov.Action) []byte {
		a.Deposit, a.Return, a.ReturnKey, a.Anchor = 10_000_000, retAddr, ret, govAnchor(t)
		af, err := led.BuildActionFile(a)
		if err != nil {
			t.Fatal(err)
		}
		return af.Envelope
	}
	put("w_infoaction_240101000004.action", 0o400, mk(dgov.Action{Kind: dgov.InfoAction}))
	put("w_noconfidence_240101000005.action", 0o400, mk(dgov.Action{Kind: dgov.NoConfidenceAction}))
	hf := dgov.Action{Kind: dgov.HardForkInitiation, Version: dgov.Version{Major: 12}}
	put("w_hardforkinitiation_240101000006.action", 0o400, mk(hf))
	return b
}

func (e env) runGovCase(t *testing.T, b stakeBase, tc govCase) {
	t.Helper()
	cli, err := e.tc.Tool(bg, ports.CardanoCLI)
	if err != nil {
		t.Fatal(err)
	}
	s := snap{drep: tc.drep}
	up, port := twoWorkspaces(t, b, s)
	for _, dir := range []string{up, port} {
		bigFunds(t, b, dir)
	}
	if code := e.upstream(t, up, append([]string{"-y", "exec", tc.script}, tc.args...)...); code != 0 {
		t.Fatalf("upstream %s exited %d", tc.script, code)
	}
	_, upTxs := readQueue(t, up)
	if len(upTxs) != 1 {
		t.Fatalf("upstream queued %d transactions", len(upTxs))
	}
	upFee, upTTL := bodyOf(t, upTxs[0].TxJSON.CborHex)
	ttl := tc.ttl
	if ttl == 0 {
		ttl = 100000
	}
	k := e.newKit(t, port, upTTL-ttl, cli.Version)
	res, err := tc.run(t, k)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	if !res.Queued {
		t.Fatalf("the port did not queue: %+v", res)
	}
	if uint64(res.Fee) != upFee {
		t.Errorf("fee: upstream %d, port %d", upFee, res.Fee)
	}
	up0 := queuedEntryEqual(t, up, port)
	for _, f := range tc.wantFiles {
		if u, p := fileMode(t, up, f), fileMode(t, port, f); u != p {
			t.Errorf("%s differs\n  upstream: %q\n  port:     %q", f, u, p)
		}
	}
	if id := strings.TrimSpace(e.cli(t, lits("transaction", "txid", "--tx-file", writeTxFile(t, up0.TxJSON.CborHex), "--output-text")...)); id != res.TxID.String() {
		t.Errorf("txid %s, port %s", id, res.TxID)
	}
}

// bigFunds raises the first UTxO of the paying address to 800 ADA, so a DRep
// registration (the deposit of the recorded parameters is 500 ADA) can be paid.
func bigFunds(t *testing.T, b stakeBase, dir string) {
	t.Helper()
	p := filepath.Join(dir, "offlineTransfer.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	a := doc["address"].(map[string]any)[b.payAddr].(map[string]any)
	a["totalamount"] = 820_000_000
	a["utxoJSON"].(map[string]any)["6b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c#0"].(map[string]any)["value"].(map[string]any)["lovelace"] = "800000000"
	out, _ := json.MarshalIndent(doc, "", "  ")
	if err := os.WriteFile(p, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

func drepEntry(id string, state any) map[string]any { return map[string]any{id: state} }

// The queued transactions of 21b (registration and update, with and without
// an anchor), 21d, 24b (one vote, two votes, a pool vote) and 25b (one and
// several proposals) are byte-equal to upstream's offline, body and signed
// transaction, and so are the transfer file mutations; so are the certificate
// files 21b and 21d write.
//
// spec: SPO-21b-IF-001, SPO-21b-IF-003, SPO-21b-IN-001, SPO-21b-IN-003, SPO-21b-EXT-001, SPO-21b-EXT-005, SPO-21b-EXT-006, SPO-21b-OUT-001, SPO-21b-OUT-002,
// spec: SPO-21b-INV-004, SPO-21b-INV-005, SPO-21b-MODE-001, SPO-21b-MODE-002, SPO-21b-MODE-003, SPO-21b-INV-007, SPO-21b-INV-012, SPO-21b-INV-013, SPO-21b-INV-014, SPO-21b-INV-018,
// spec: SPO-21d-IF-001, SPO-21d-IN-001, SPO-21d-EXT-001, SPO-21d-EXT-002, SPO-21d-OUT-001, SPO-21d-OUT-002, SPO-21d-INV-001, SPO-21d-INV-002, SPO-21d-INV-003, SPO-21d-INV-010, SPO-21d-INV-011, SPO-21d-INV-012,
// spec: SPO-24b-IF-001, SPO-24b-IF-005, SPO-24b-IN-001, SPO-24b-OUT-001, SPO-24b-INV-002, SPO-24b-MODE-003, SPO-24b-EXT-003, SPO-24b-INV-009, SPO-24b-INV-014,
// spec: SPO-25b-IF-001, SPO-25b-IF-004, SPO-25b-IN-001, SPO-25b-INV-001, SPO-25b-INV-003, SPO-25b-INV-004, SPO-25b-EXT-006, SPO-25b-EXT-007, SPO-25b-EXT-008, SPO-25b-INV-009, SPO-25b-OUT-002,
// spec: SPO-Ptx-INV-006, SPO-Ptx-INV-007, SPO-Ptx-INV-010, SPO-Ptx-EXT-001, SPO-Ptx-EXT-002, SPO-Ptx-EXT-004, SPO-Ptx-MODE-004, SPO-Ptx-MODE-006, SPO-Ptx-MODE-007, SPO-Ptx-MODE-010,
// spec: SPO-Ptx-PR-003, SPO-Ptransfer-OUT-010, SPO-Ptransfer-OUT-011, SPO-Ptransfer-OUT-012, SPO-Pfiles-OUT-025
func TestGovTransactionsMatchUpstream(t *testing.T) {
	e := setup(t)
	b := e.govBase(t)
	id := strings.TrimSpace(readFile(t, b.dir, "d.drep.id"))
	anchorWords := []string{"url:" + govURL, "hash:" + govHash}
	registered := func(deposit uint64) map[string]any {
		return drepEntry(id, []any{map[string]any{}, map[string]any{"deposit": deposit}})
	}
	regDRep := func(url, hash string) func(*testing.T, kit) (txflow.Result, error) {
		return func(t *testing.T, k kit) (txflow.Result, error) {
			res, err := governance.RegisterDRep{Base: govBase(k), Certs: k.led, DReps: k.file, AnchorUnverifiedAcknowledged: true}.Run(bg, governance.RegisterDRepRequest{DRep: "d", Payer: "w.payment", URL: url, Hash: hash})
			if err == nil {
				wantKind := "registration"
				if res.Deposit == 0 {
					wantKind = "update"
				}
				t.Logf("21b made a %s", wantKind)
			}
			return res.Result, err
		}
	}
	vote := func(voter string, files ...string) func(*testing.T, kit) (txflow.Result, error) {
		return func(t *testing.T, k kit) (txflow.Result, error) {
			res, err := governance.RegisterVote{Base: govBase(k), Votes: k.led}.Run(bg, governance.RegisterVoteRequest{Voter: voter, Payer: "w.payment", Files: files})
			return res.Result, err
		}
	}
	act := func(files ...string) func(*testing.T, kit) (txflow.Result, error) {
		return func(t *testing.T, k kit) (txflow.Result, error) {
			res, err := governance.RegisterAction{Base: govBase(k), Actions: k.led, AllowUnverified: true}.Run(bg, governance.RegisterActionRequest{Payer: "w.payment", Files: files})
			return res.Result.Result, err
		}
	}
	cases := []govCase{
		{name: "21b registration", drep: drepEntry(id, []any{}), script: "21b_regDRepCert.sh", args: []string{"d", "w.payment"}, run: regDRep("", ""), wantFiles: []string{"d.drep-reg.cert"}},
		{name: "21b registration with an anchor", drep: drepEntry(id, []any{}), script: "21b_regDRepCert.sh", args: append([]string{"d", "w.payment"}, anchorWords...),
			run: regDRep(govURL, govHash), wantFiles: []string{"d.drep-reg.cert"}},
		{name: "21b update", drep: registered(500_000_000), script: "21b_regDRepCert.sh", args: append([]string{"d", "w.payment"}, anchorWords...),
			run: regDRep(govURL, govHash), wantFiles: []string{"d.drep-reg.cert"}},
		{name: "21d retirement refunds the on-chain deposit", drep: registered(123_456_789), script: "21d_retDRepCert.sh", args: []string{"d", "w.payment"},
			run: func(t *testing.T, k kit) (txflow.Result, error) {
				res, err := governance.RetireDRep{Base: govBase(k), Certs: k.led, DReps: k.file, Sources: governance.SingleSourceAcknowledged, OnSingle: noopSingle}.Run(bg, governance.RetireDRepRequest{DRep: "d", Payer: "w.payment"})
				return res.Result, err
			}, wantFiles: []string{"d.drep-ret.cert"}},
		{name: "24b one DRep vote", script: "24b_regVote.sh", args: []string{"d.drep", "w.payment", "d_240101000001.drep.vote"}, run: vote("d.drep", "d_240101000001.drep.vote")},
		{name: "24b two DRep votes", script: "24b_regVote.sh", args: []string{"d.drep", "w.payment", "d_240101000001.drep.vote", "d_240101000002.drep.vote"},
			run: vote("d.drep", "d_240101000001.drep.vote", "d_240101000002.drep.vote")},
		{name: "24b a pool vote", script: "24b_regVote.sh", args: []string{"mypool", "w.payment", "mypool_240101000003.pool.vote"}, run: vote("mypool", "mypool_240101000003.pool.vote")},
		{name: "25b one proposal", ttl: 25000, script: "25b_regAction.sh", args: []string{"w.payment", "w_infoaction_240101000004.action"}, run: act("w_infoaction_240101000004.action")},
		{name: "25b three proposals", ttl: 25000, script: "25b_regAction.sh",
			args: []string{"w.payment", "w_noconfidence_240101000005.action", "w_infoaction_240101000004.action", "w_hardforkinitiation_240101000006.action"},
			run:  act("w_noconfidence_240101000005.action", "w_infoaction_240101000004.action", "w_hardforkinitiation_240101000006.action")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { e.runGovCase(t, b, tc) })
	}
	_ = hex.EncodeToString
	_ = sort.Strings
	_ = dgov.Yes
}

// 23c, 23e, 24a and 24c refuse offline upstream and so do the use cases: 23c and
// 23e print that offline is not supported and exit 0 with nothing queued (an
// error here), 24a and 24c exit 1.
//
// spec: SPO-23c-MODE-001, SPO-23e-MODE-001, SPO-24a-PRE-001, SPO-24c-PRE-001, SPO-23d-PRE-002
func TestGovOfflineRefusalsMatchUpstream(t *testing.T) {
	e := setup(t)
	b := e.govBase(t)
	for _, run := range [][]string{{"23a_genComColdKeys.sh", "m", "cli"}, {"23b_genComHotKeys.sh", "m", "cli"}} {
		if code := e.upstream(t, b.dir, append([]string{"exec"}, run...)...); code != 0 {
			t.Fatalf("upstream %v exited %d", run, code)
		}
	}
	up, port := twoWorkspaces(t, b, snap{})
	cli, _ := e.tc.Tool(bg, ports.CardanoCLI)
	k := e.newKit(t, port, 0, cli.Version)
	for _, tc := range []struct {
		script string
		args   []string
		code   int
		run    func() error
	}{
		{"23c_regComAuthCert.sh", []string{"m", "m", "w.payment"}, 0, func() error {
			_, err := governance.AuthorizeCommitteeHotKey{Base: govBase(k), Certs: k.led}.Run(bg, governance.AuthorizeRequest{Cold: "m", Hot: "m", Payer: "w.payment"})
			return err
		}},
		{"23e_retComColdKeys.sh", []string{"m", "w.payment"}, 0, func() error {
			_, err := governance.ResignCommitteeColdKey{Base: govBase(k), Certs: k.led}.Run(bg, governance.ResignRequest{Cold: "m", Payer: "w.payment"})
			return err
		}},
		{"24a_genVote.sh", []string{"d", "all"}, 1, func() error {
			_, err := governance.GenerateVote{Offline: true}.Run(bg, governance.GenerateVoteRequest{Voter: "d", Action: "all"})
			return err
		}},
		{"24c_queryVote.sh", []string{"all"}, 1, func() error {
			_, err := governance.QueryVote{Offline: true}.Run(bg, governance.QueryFilter{})
			return err
		}},
		{"23d_checkComOnChain.sh", []string{"m"}, 1, func() error {
			_, err := governance.CheckCommittee{Offline: true}.Run(bg, "m")
			return err
		}},
	} {
		t.Run(tc.script, func(t *testing.T) {
			if code := e.upstream(t, up, append([]string{"-y", "exec", tc.script}, tc.args...)...); code != tc.code {
				t.Errorf("upstream %s exited %d, want %d", tc.script, code, tc.code)
			}
			if err := tc.run(); err == nil || !strings.Contains(err.Error(), "needs the chain") {
				t.Errorf("the port: %v", err)
			}
		})
	}
	if _, txs := readQueue(t, up); len(txs) != 0 {
		t.Errorf("upstream queued %d transactions", len(txs))
	}
}
