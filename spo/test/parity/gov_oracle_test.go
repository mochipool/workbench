package parity

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports/porttest"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

// govKit is a directory with the governance keys cardano-cli makes.
type govKit struct {
	dir                   string
	e                     env
	drep, cold, hot, pool [28]byte
	stakeAddr             chain.StakeAddress
	stakeKey              [28]byte
}

func (k govKit) p(n string) string { return filepath.Join(k.dir, n) }

func (e env) newGovKit(t *testing.T) govKit {
	t.Helper()
	k := govKit{dir: t.TempDir(), e: e}
	e.cli(t, lits("governance", "drep", "key-gen", "--verification-key-file", k.p("d.vkey"), "--signing-key-file", k.p("d.skey"))...)
	e.cli(t, lits("governance", "committee", "key-gen-cold", "--cold-verification-key-file", k.p("cc.vkey"), "--cold-signing-key-file", k.p("cc.skey"))...)
	e.cli(t, lits("governance", "committee", "key-gen-hot", "--verification-key-file", k.p("ch.vkey"), "--signing-key-file", k.p("ch.skey"))...)
	e.cli(t, lits("node", "key-gen", "--cold-verification-key-file", k.p("n.vkey"), "--cold-signing-key-file", k.p("n.skey"), "--operational-certificate-issue-counter-file", k.p("n.counter"))...)
	e.cli(t, lits("stake-address", "key-gen", "--verification-key-file", k.p("s.vkey"), "--signing-key-file", k.p("s.skey"))...)
	k.drep, k.cold, k.hot, k.pool = e.fileKeyHash(t, k.p("d.vkey")), e.fileKeyHash(t, k.p("cc.vkey")), e.fileKeyHash(t, k.p("ch.vkey")), e.fileKeyHash(t, k.p("n.vkey"))
	k.stakeKey = e.fileKeyHash(t, k.p("s.vkey"))
	k.stakeAddr = chain.StakeAddress(strings.TrimSpace(e.cli(t, lits("stake-address", "build", "--testnet-magic", "2", "--stake-verification-key-file", k.p("s.vkey"))...)))
	return k
}

const (
	govURL  = "https://example.org/anchor.json"
	govHash = "0000000000000000000000000000000000000000000000000000000000000001"
)

func govAnchor(t *testing.T) governance.Anchor {
	h, err := governance.ParseHash32(govHash)
	if err != nil {
		t.Fatal(err)
	}
	return governance.Anchor{URL: govURL, Hash: h}
}

type govCertCase struct {
	name string
	spec stake.Spec
	cli  []string // arguments of the cardano-cli command, without --out-file
}

func (k govKit) certCases(t *testing.T) []govCertCase {
	anch := govAnchor(t)
	anchorFlags := func(prefix string) []string {
		return []string{"--" + prefix + "-metadata-url", govURL, "--" + prefix + "-metadata-hash", govHash}
	}
	dv := []string{"--drep-verification-key-file", k.p("d.vkey")}
	cs := []string{"--cold-verification-key-file", k.p("cc.vkey")}
	cat := func(parts ...[]string) []string {
		var out []string
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	d, c, h := stake.KeyHash(k.drep), stake.KeyHash(k.cold), stake.KeyHash(k.hot)
	return []govCertCase{
		{"drep registration", stake.Spec{Kind: stake.CertDRepRegistration, Stake: d, Deposit: 500_000_000},
			cat([]string{"governance", "drep", "registration-certificate"}, dv, []string{"--key-reg-deposit-amt", "500000000"})},
		{"drep registration with anchor", stake.Spec{Kind: stake.CertDRepRegistration, Stake: d, Deposit: 500_000_000, Anchor: anch},
			cat([]string{"governance", "drep", "registration-certificate"}, dv, []string{"--key-reg-deposit-amt", "500000000"}, anchorFlags("drep"))},
		{"drep registration with the key hash", stake.Spec{Kind: stake.CertDRepRegistration, Stake: d, Deposit: 2_000_000, Anchor: anch},
			cat([]string{"governance", "drep", "registration-certificate", "--drep-key-hash", hex.EncodeToString(k.drep[:]), "--key-reg-deposit-amt", "2000000"}, anchorFlags("drep"))},
		{"drep update", stake.Spec{Kind: stake.CertDRepUpdate, Stake: d},
			cat([]string{"governance", "drep", "update-certificate"}, dv)},
		{"drep update with anchor", stake.Spec{Kind: stake.CertDRepUpdate, Stake: d, Anchor: anch},
			cat([]string{"governance", "drep", "update-certificate"}, dv, anchorFlags("drep"))},
		{"drep retirement", stake.Spec{Kind: stake.CertDRepRetirement, Stake: d, Deposit: 500_000_000},
			cat([]string{"governance", "drep", "retirement-certificate"}, dv, []string{"--deposit-amt", "500000000"})},
		{"committee hot key authorisation", stake.Spec{Kind: stake.CertCommitteeAuthorize, Stake: c, Hot: h},
			cat([]string{"governance", "committee", "create-hot-key-authorization-certificate"}, cs, []string{"--hot-verification-key-file", k.p("ch.vkey")})},
		{"committee cold resignation", stake.Spec{Kind: stake.CertCommitteeResign, Stake: c},
			cat([]string{"governance", "committee", "create-cold-key-resignation-certificate"}, cs)},
		{"committee cold resignation with anchor", stake.Spec{Kind: stake.CertCommitteeResign, Stake: c, Anchor: anch},
			cat([]string{"governance", "committee", "create-cold-key-resignation-certificate"}, cs, anchorFlags("resignation"))},
	}
}

// The DRep and committee certificates are byte-equal to the files cardano-cli
// writes, text envelope included, and read back as the same certificate.
//
// spec: SPO-Pfiles-OUT-025, SPO-Pfiles-OUT-028, SPO-21b-EXT-005, SPO-21b-EXT-006, SPO-21b-INV-003, SPO-21d-EXT-002,
// spec: SPO-23c-EXT-003, SPO-23e-EXT-002
func TestGovCertificatesMatchCardanoCLI(t *testing.T) {
	e := setup(t)
	k := e.newGovKit(t)
	led := native.Ledger{}
	for _, tc := range k.certCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			out := k.p("x.cert")
			e.cli(t, lits(append(tc.cli, "--out-file", out)...)...)
			want, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			c, err := led.BuildCertificate(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			if string(c.Envelope) != string(want) {
				t.Fatalf("certificate differs\n  cardano-cli: %q\n  go:          %q", want, c.Envelope)
			}
			back, err := led.DecodeCertificate(want)
			if err != nil || back.Spec != tc.spec {
				t.Fatalf("cardano-cli's file reads back as %+v (%v), want %+v", back.Spec, err, tc.spec)
			}
		})
	}
}

// The DRep id in its three spellings and the committee key hashes equal what
// cardano-cli prints.
//
// spec: SPO-21a-EXT-005, SPO-21a-INV-003, SPO-21c-INV-001, SPO-23a-EXT-005, SPO-23a-INV-003, SPO-23b-EXT-005, SPO-23b-INV-003,
// spec: SPO-23c-IN-002, SPO-23d-INV-001
func TestGovIDsMatchCardanoCLI(t *testing.T) {
	e := setup(t)
	k := e.newGovKit(t)
	ids, err := governance.DRepIDsOf(governance.Credential{Hash: k.drep})
	if err != nil {
		t.Fatal(err)
	}
	for form, want := range map[string]string{"--output-bech32": ids.Legacy, "--output-hex": ids.Hex, "--output-cip129": ids.CIP129} {
		if got := e.cli(t, lits("governance", "drep", "id", "--drep-verification-key-file", k.p("d.vkey"), form, "--out-file", "/dev/stdout")...); got != want {
			t.Errorf("drep id %s: cardano-cli %q, go %q", form, got, want)
		}
	}
	if got := e.cli(t, lits("governance", "drep", "id", "--drep-verification-key-file", k.p("d.vkey"), "--out-file", "/dev/stdout")...); got != ids.Legacy {
		t.Errorf("the default drep id form is %q, go's legacy form is %q", got, ids.Legacy)
	}
	// The same ids from the hash, cardano-cli to go.
	if got := e.cli(t, lits("governance", "drep", "id", "--drep-key-hash", ids.Hex, "--output-cip129", "--out-file", "/dev/stdout")...); got != ids.CIP129 {
		t.Errorf("CIP-129 from the hash: %q, want %q", got, ids.CIP129)
	}
	for _, c := range []struct {
		vkey string
		hash [28]byte
		hot  bool
	}{{"cc.vkey", k.cold, false}, {"ch.vkey", k.hot, true}} {
		want := strings.TrimSpace(e.cli(t, lits("governance", "committee", "key-hash", "--verification-key-file", k.p(c.vkey))...))
		ci, err := governance.CommitteeIDsOf(governance.Credential{Hash: c.hash}, c.hot)
		if err != nil {
			t.Fatal(err)
		}
		if ci.Hex != want {
			t.Errorf("committee key hash of %s: cardano-cli %s, go %s", c.vkey, want, ci.Hex)
		}
		// The id spellings round-trip through the parser of 23d.
		for _, w := range []string{ci.Hex, ci.Legacy, ci.CIP129} {
			if got, isID, err := governance.ParseCommitteeWord(w); err != nil || !isID || got.Hash != c.hash {
				t.Errorf("ParseCommitteeWord(%s) = %+v %v %v", w, got, isID, err)
			}
		}
	}
}

type voteCase struct {
	name  string
	vote  governance.Vote
	flags []string
}

func (k govKit) voteCases(t *testing.T) []voteCase {
	tx := mustTxID(t, "6b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c")
	anch := govAnchor(t)
	roles := []struct {
		role  governance.Role
		hash  [28]byte
		flags []string
	}{
		{governance.RoleDRep, k.drep, []string{"--drep-verification-key-file", k.p("d.vkey")}},
		{governance.RolePool, k.pool, []string{"--cold-verification-key-file", k.p("n.vkey")}},
		{governance.RoleCommitteeHot, k.hot, []string{"--cc-hot-verification-key-file", k.p("ch.vkey")}},
	}
	var out []voteCase
	for _, r := range roles {
		for _, d := range []governance.Decision{governance.Yes, governance.No, governance.Abstain} {
			for _, withAnchor := range []bool{false, true} {
				v := governance.Vote{Voter: governance.Voter{Role: r.role, Cred: governance.Credential{Hash: r.hash}},
					Action: governance.ActionID{TxID: tx, Index: 2}, Decision: d}
				fl := append([]string{"--" + string(d)}, r.flags...)
				name := fmt.Sprintf("%s %s", r.role, d)
				if withAnchor {
					v.Anchor = anch
					fl = append(fl, "--anchor-url", govURL, "--anchor-data-hash", govHash)
					name += " with anchor"
				}
				out = append(out, voteCase{name, v, fl})
			}
		}
	}
	return out
}

// Vote files: every voter role, every decision, with and without an anchor,
// byte-equal to `governance vote create`, and the file upstream stores (the
// description injected with jq) equal to what jq makes of it.
//
// spec: SPO-24a-EXT-004, SPO-24a-OUT-001, SPO-Pfiles-OUT-029, SPO-24b-IF-005
func TestGovVoteFilesMatchCardanoCLI(t *testing.T) {
	e := setup(t)
	k := e.newGovKit(t)
	led := native.Ledger{}
	jq, jqErr := exec.LookPath("jq")
	for _, tc := range k.voteCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			out := k.p("v.vote")
			e.cli(t, lits(append(append([]string{"governance", "vote", "create"}, tc.flags...),
				"--governance-action-tx-id", tc.vote.Action.TxID.String(), "--governance-action-index", strconv.Itoa(int(tc.vote.Action.Index)), "--out-file", out)...)...)
			want, _ := os.ReadFile(out)
			vf, err := led.BuildVoteFile(tc.vote, "")
			if err != nil {
				t.Fatal(err)
			}
			if string(vf.CLIEnvelope) != string(want) {
				t.Fatalf("vote file differs\n  cardano-cli: %q\n  go:          %q", want, vf.CLIEnvelope)
			}
			back, err := led.DecodeVoteFile(want)
			if err != nil || back.Vote != tc.vote {
				t.Fatalf("cardano-cli's file reads back as %+v (%v)", back.Vote, err)
			}
			title := governance.Anchor{}.URL + "Treasury 2025: ‘fund’ <it> & \"quote\" §5"
			clean := native.SanitizeVoteDescription(title)
			vf2, err := led.BuildVoteFile(tc.vote, clean)
			if err != nil {
				t.Fatal(err)
			}
			if jqErr == nil {
				cmd := exec.Command(jq, "-r", fmt.Sprintf(". += { \"description\": %q }", clean))
				cmd.Stdin = strings.NewReader(string(want))
				got, err := cmd.Output()
				if err != nil {
					t.Fatal(err)
				}
				if string(got) != string(vf2.Envelope) {
					t.Errorf("the stored vote file differs from jq's\n  jq: %q\n  go: %q", got, vf2.Envelope)
				}
			}
		})
	}
}

func (k govKit) actionCases(t *testing.T) []actionCase {
	anch := govAnchor(t)
	tx := mustTxID(t, "6b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c")
	prev := &governance.ActionID{TxID: tx, Index: 3}
	deposit := chain.Lovelace(100_000_000_000)
	base := func(kind governance.ActionKind) governance.Action {
		return governance.Action{Kind: kind, Deposit: deposit, Return: k.stakeAddr, ReturnKey: governance.Credential{Hash: k.stakeKey}, Anchor: anch}
	}
	common := []string{"--testnet", "--governance-action-deposit", "100000000000", "--deposit-return-stake-verification-key-file", k.p("s.vkey"),
		"--anchor-url", govURL, "--anchor-data-hash", govHash}
	cat := func(parts ...[]string) []string {
		out := append([]string(nil), common...)
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	prevFlags := []string{"--prev-governance-action-tx-id", tx.String(), "--prev-governance-action-index", "3"}
	recv := governance.Credential{Hash: policy(0x5a)}
	recvAddr := stakeAddrOf(t, recv, false)
	sh := policy(0xab)
	m1, m2, r1 := governance.Credential{Hash: policy(0x11)}, governance.Credential{Hash: policy(0x22), Script: true}, governance.Credential{Hash: policy(0x33)}
	hex28 := func(c [28]byte) string { return hex.EncodeToString(c[:]) }
	var cases []actionCase
	add := func(name string, a governance.Action, sub string, flags []string) {
		cases = append(cases, actionCase{name, a, append([]string{"governance", "action", sub}, flags...)})
	}
	add("info", base(governance.InfoAction), "create-info", cat())
	nc := base(governance.NoConfidenceAction)
	add("no confidence", nc, "create-no-confidence", cat())
	nc.Prev = prev
	add("no confidence with a previous action", nc, "create-no-confidence", cat(prevFlags))
	hf := base(governance.HardForkInitiation)
	hf.Version = governance.Version{Major: 10, Minor: 0}
	add("hard fork", hf, "create-hardfork", cat([]string{"--protocol-major-version", "10", "--protocol-minor-version", "0"}))
	hf.Prev = prev
	hf.Version = governance.Version{Major: 11, Minor: 0}
	add("hard fork with a previous action", hf, "create-hardfork", cat(prevFlags, []string{"--protocol-major-version", "11", "--protocol-minor-version", "0"}))
	ct := base(governance.NewConstitution)
	ct.Constitution = governance.Anchor{URL: "https://example.org/constitution.txt"}
	ct.Constitution.Hash[31] = 2
	cflags := []string{"--constitution-url", ct.Constitution.URL, "--constitution-hash", ct.Constitution.HashHex()}
	add("new constitution", ct, "create-constitution", cat(cflags))
	ct.Guardrails, ct.Prev = &sh, prev
	add("new constitution with a script and a previous action", ct, "create-constitution", cat(prevFlags, cflags, []string{"--constitution-script-hash", hex28(sh)}))
	uc := base(governance.UpdateCommittee)
	uc.Threshold = chain.Rational{Num: 2, Den: 3}
	uc.Add = []governance.CommitteeAdd{{Cold: m1, Epoch: 500}, {Cold: m2, Epoch: 500}}
	uc.Remove = []governance.Credential{r1}
	add("update committee", uc, "update-committee", cat([]string{"--threshold", "2/3",
		"--add-cc-cold-verification-key-hash", hex28(m1.Hash), "--epoch", "500", "--add-cc-cold-script-hash", hex28(m2.Hash), "--epoch", "500",
		"--remove-cc-cold-verification-key-hash", hex28(r1.Hash)}))
	uc2 := base(governance.UpdateCommittee)
	uc2.Threshold, uc2.Prev = chain.Rational{Num: 33, Den: 50}, prev
	add("update committee, threshold only, as a decimal", uc2, "update-committee", cat(prevFlags, []string{"--threshold", "0.66"}))
	uc3 := base(governance.UpdateCommittee)
	uc3.Threshold = chain.Rational{Num: 1, Den: 2}
	uc3.Remove = []governance.Credential{m2, m1}
	add("update committee removing a script and a key", uc3, "update-committee", cat([]string{"--threshold", "1/2",
		"--remove-cc-cold-script-hash", hex28(m2.Hash), "--remove-cc-cold-verification-key-hash", hex28(m1.Hash)}))
	tw := base(governance.TreasuryWithdrawals)
	tw.Withdrawals = []governance.Withdrawal{{Account: recvAddr, Key: recv, Amount: 5_000_000}}
	add("treasury withdrawal", tw, "create-treasury-withdrawal", cat([]string{"--funds-receiving-stake-key-hash", hex28(recv.Hash), "--transfer", "5000000"}))
	tw.Guardrails = &sh
	add("treasury withdrawal with a guardrails script", tw, "create-treasury-withdrawal",
		cat([]string{"--funds-receiving-stake-key-hash", hex28(recv.Hash), "--transfer", "5000000", "--constitution-script-hash", hex28(sh)}))
	// A key account and a script account in one withdrawal map: the order of
	// the entries is the ledger's order of reward accounts, which cardano-cli
	// writes whatever the order of the flags (the header byte alone would put
	// the key accounts, e0/e1, before the script accounts, f0/f1).
	scr := governance.Credential{Hash: policy(0x6b), Script: true}
	scrAddr := stakeAddrOf(t, scr, false)
	two := base(governance.TreasuryWithdrawals)
	two.Withdrawals = []governance.Withdrawal{{Account: recvAddr, Key: recv, Amount: 5_000_000}, {Account: scrAddr, Key: scr, Amount: 7_000_000}}
	add("treasury withdrawal to a key and a script account, key first", two, "create-treasury-withdrawal", cat([]string{
		"--funds-receiving-stake-key-hash", hex28(recv.Hash), "--transfer", "5000000", "--funds-receiving-stake-address", string(scrAddr), "--transfer", "7000000"}))
	add("treasury withdrawal to a key and a script account, script first", two, "create-treasury-withdrawal", cat([]string{
		"--funds-receiving-stake-address", string(scrAddr), "--transfer", "7000000", "--funds-receiving-stake-key-hash", hex28(recv.Hash), "--transfer", "5000000"}))
	return cases
}

type actionCase struct {
	name   string
	action governance.Action
	cli    []string
}

func stakeAddrOf(t *testing.T, c governance.Credential, mainnet bool) chain.StakeAddress {
	hdr, hrp := byte(0xe0), "stake_test"
	if c.Script {
		hdr = 0xf0
	}
	if mainnet {
		hdr, hrp = hdr|1, "stake"
	}
	s, err := chain.Bech32Encode(hrp, append([]byte{hdr}, c.Hash[:]...))
	if err != nil {
		t.Fatal(err)
	}
	return chain.StakeAddress(s)
}

// Action files for the six kinds other than the parameter change, byte-equal to
// `governance action create-*` (the parameter change has its own test,
// TestGovParameterChangeFilesMatchCardanoCLI). The guardrails script hash is a
// flag of the file; the script is a witness of the transaction that proposes it.
//
// spec: SPO-25a-EXT-005, SPO-25a-EXT-006, SPO-25a-EXT-007, SPO-25a-EXT-008, SPO-25a-EXT-009, SPO-25a-EXT-010, SPO-25a-EXT-012,
// spec: SPO-25a-OUT-002, SPO-Pfiles-OUT-030, SPO-25b-IN-002
func TestGovActionFilesMatchCardanoCLI(t *testing.T) {
	e := setup(t)
	k := e.newGovKit(t)
	led := native.Ledger{}
	for _, tc := range k.actionCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			out := k.p("a.action")
			e.cli(t, lits(append(append([]string(nil), tc.cli...), "--out-file", out)...)...)
			want, _ := os.ReadFile(out)
			af, err := led.BuildActionFile(tc.action)
			if err != nil {
				t.Fatal(err)
			}
			if string(af.Envelope) != string(want) {
				t.Fatalf("action file differs\n  cardano-cli: %q\n  go:          %q", want, af.Envelope)
			}
			back, err := led.DecodeActionFile(want)
			if err != nil || back.Action.Kind != tc.action.Kind || back.Action.Deposit != tc.action.Deposit {
				t.Fatalf("cardano-cli's file reads back as %+v (%v)", back.Action, err)
			}
		})
	}
}

// Transaction bodies carrying each certificate, a vote, several votes (of the
// three roles and two actions, merged under one map) and proposals (in both
// orders) are byte-equal to `transaction build-raw`, with the same id, the
// fee of `calculate-min-fee` at the specs' witness counts, the witnesses of the
// DRep, committee and pool keys and the assembled transaction.
//
// spec: SPO-21b-INV-004, SPO-21b-INV-005, SPO-21d-INV-002, SPO-21d-INV-003, SPO-23c-INV-004, SPO-23e-INV-002,
// spec: SPO-24b-OUT-001, SPO-24b-INV-002, SPO-24b-IF-005, SPO-25b-INV-001, SPO-25b-INV-009, SPO-25b-EXT-006, SPO-25b-EXT-007,
// spec: SPO-Ptx-EXT-001, SPO-Ptx-EXT-002, SPO-Ptx-EXT-004, SPO-Ptx-EXT-006, SPO-Ptx-INV-006
func TestGovTransactionsMatchCardanoCLI(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	params := testParams(t)
	led := native.Ledger{}
	keys := e.newKeys(t, false)
	k := e.newGovKit(t)
	// The vault reads the governance keys as <name>.drep.skey and so on.
	// A signing key in a workspace has its verification key beside it: key
	// generation writes both and an import derives a missing one, so a key is found
	// in the vault by the identity of that verification key.
	for from, to := range map[string]string{"d.skey": "d.drep.skey", "cc.skey": "m.cc-cold.skey", "ch.skey": "h.cc-hot.skey", "n.skey": "pool.node.skey",
		"d.vkey": "d.drep.vkey", "cc.vkey": "m.cc-cold.vkey", "ch.vkey": "h.cc-hot.vkey", "n.vkey": "pool.node.vkey"} {
		raw, err := os.ReadFile(k.p(from))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(keys.dir, to), raw, 0o400); err != nil {
			t.Fatal(err)
		}
	}
	store, err := plainstore.OpenTestnet(keys.dir)
	if err != nil {
		t.Fatal(err)
	}
	signer := native.VaultSigner{Vault: store}
	p := func(n string) string { return filepath.Join(keys.dir, n) }

	certs := map[string]stake.Certificate{}
	certFile := map[string]string{}
	for _, tc := range k.certCases(t) {
		out := p(strings.ReplaceAll(tc.name, " ", "-") + ".cert")
		e.cli(t, lits(append(tc.cli, "--out-file", out)...)...)
		c, err := led.BuildCertificate(tc.spec)
		if err != nil {
			t.Fatal(err)
		}
		certs[tc.name], certFile[tc.name] = c, out
	}
	h1 := mustTxID(t, "6b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c")
	h2 := mustTxID(t, "0b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c")
	inputs := []chain.Utxo{{TxID: h1, Index: 0, Lovelace: 600_000_000}, {TxID: h2, Index: 3, Lovelace: 400_000_000}}

	// Votes: one file per case of voteCases for the first action, plus two on
	// another action, for several-vote bodies.
	var voteAtt []txbuild.VoteAttachment
	var voteFiles []string
	mkVote := func(role governance.Role, hash [28]byte, flags []string, tx chain.TxID, ix uint32, d governance.Decision) {
		v := governance.Vote{Voter: governance.Voter{Role: role, Cred: governance.Credential{Hash: hash}}, Action: governance.ActionID{TxID: tx, Index: ix}, Decision: d}
		out := p(fmt.Sprintf("v%d.vote", len(voteFiles)))
		e.cli(t, lits(append(append([]string{"governance", "vote", "create", "--" + string(d)}, flags...),
			"--governance-action-tx-id", tx.String(), "--governance-action-index", strconv.Itoa(int(ix)), "--out-file", out)...)...)
		vf, err := led.BuildVoteFile(v, "")
		if err != nil {
			t.Fatal(err)
		}
		voteAtt = append(voteAtt, txbuild.VoteAttachment{Vote: v, CBOR: vf.CBOR})
		voteFiles = append(voteFiles, out)
	}
	dflags := []string{"--drep-verification-key-file", k.p("d.vkey")}
	mkVote(governance.RoleDRep, k.drep, dflags, h1, 2, governance.Yes)
	mkVote(governance.RoleDRep, k.drep, dflags, h2, 1, governance.No)
	mkVote(governance.RolePool, k.pool, []string{"--cold-verification-key-file", k.p("n.vkey")}, h1, 2, governance.No)
	mkVote(governance.RoleCommitteeHot, k.hot, []string{"--cc-hot-verification-key-file", k.p("ch.vkey")}, h1, 2, governance.Abstain)
	mkVote(governance.RoleDRep, k.drep, dflags, h1, 0, governance.Abstain)

	// Proposals.
	var propAtt []txbuild.ProposalAttachment
	var propFiles []string
	for _, ac := range k.actionCases(t) {
		if ac.name != "info" && ac.name != "no confidence" && ac.name != "update committee" && ac.name != "treasury withdrawal" {
			continue
		}
		out := p(strings.ReplaceAll(ac.name, " ", "-") + ".action")
		e.cli(t, lits(append(append([]string(nil), ac.cli...), "--out-file", out)...)...)
		af, err := led.BuildActionFile(ac.action)
		if err != nil {
			t.Fatal(err)
		}
		propAtt, propFiles = append(propAtt, txbuild.ProposalAttachment{Action: ac.action, CBOR: af.CBOR}), append(propFiles, out)
	}

	roleKey := map[string]custody.KeyRef{
		"drep":    porttest.Key(t, store, custody.RoleDRep, "d"),
		"cold":    porttest.Key(t, store, custody.RoleCommitteeCold, "m"),
		"hot":     porttest.Key(t, store, custody.RoleCommitteeHot, "h"),
		"pool":    porttest.Key(t, store, custody.RolePoolCold, "pool"),
		"payment": porttest.Key(t, store, custody.RolePayment, "w"),
	}
	skeyOf := map[string][]byte{}
	for name, f := range map[string]string{"drep": "d.drep.skey", "cold": "m.cc-cold.skey", "hot": "h.cc-hot.skey", "pool": "pool.node.skey"} {
		skeyOf[name], _ = os.ReadFile(p(f))
	}
	skeyOf["payment"] = keys.skeyBytes

	type bodyCase struct {
		name      string
		certs     []stake.Certificate
		certFiles []string
		votes     []txbuild.VoteAttachment
		voteFiles []string
		props     []txbuild.ProposalAttachment
		propFiles []string
		signers   []string // after the payment key
		witnesses uint
		deposit   chain.Lovelace
	}
	one := func(n string, signer string) bodyCase {
		return bodyCase{name: n, certs: []stake.Certificate{certs[n]}, certFiles: []string{certFile[n]}, signers: []string{signer}, witnesses: 2}
	}
	cases := []bodyCase{
		one("drep registration", "drep"), one("drep registration with anchor", "drep"), one("drep update", "drep"), one("drep update with anchor", "drep"),
		one("drep retirement", "drep"), one("committee hot key authorisation", "cold"), one("committee cold resignation", "cold"),
		one("committee cold resignation with anchor", "cold"),
		{name: "one vote", votes: voteAtt[:1], voteFiles: voteFiles[:1], signers: []string{"drep"}, witnesses: 2},
		{name: "several votes of three roles", votes: voteAtt, voteFiles: voteFiles, signers: []string{"drep", "pool", "hot"}, witnesses: 2},
		{name: "votes in another order", votes: []txbuild.VoteAttachment{voteAtt[4], voteAtt[3], voteAtt[2], voteAtt[1], voteAtt[0]},
			voteFiles: []string{voteFiles[4], voteFiles[3], voteFiles[2], voteFiles[1], voteFiles[0]}, signers: []string{"drep", "pool", "hot"}, witnesses: 2},
		{name: "one proposal", props: propAtt[:1], propFiles: propFiles[:1], witnesses: 1},
		{name: "four proposals", props: propAtt, propFiles: propFiles, witnesses: 1},
		{name: "proposals in another order", props: []txbuild.ProposalAttachment{propAtt[3], propAtt[1], propAtt[2], propAtt[0]},
			propFiles: []string{propFiles[3], propFiles[1], propFiles[2], propFiles[0]}, witnesses: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			outs := []txbuild.Output{{Address: keys.base, Lovelace: 997_000_000}}
			spec := txbuild.BodySpec{Inputs: inputs, Outputs: outs, Fee: 200_000, TTL: 123456, Certificates: tc.certs, Votes: tc.votes, Proposals: tc.props}
			args := []string{"transaction", "build-raw"}
			for _, in := range inputs {
				args = append(args, "--tx-in", fmt.Sprintf("%s#%d", in.TxID, in.Index))
			}
			args = append(args, "--tx-out", textOut(outs[0]), "--invalid-hereafter", "123456", "--fee", "200000", "--out-file", p("b.txbody"))
			for _, f := range tc.certFiles {
				args = append(args, "--certificate-file", f)
			}
			for _, f := range tc.voteFiles {
				args = append(args, "--vote-file", f)
			}
			for _, f := range tc.propFiles {
				args = append(args, "--proposal-file", f)
			}
			e.cli(t, lits(args...)...)
			body, err := led.BuildBody(spec)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := hex.EncodeToString(body.CBOR), cborHexOf(t, p("b.txbody")); got != want {
				t.Fatalf("body differs\n  cardano-cli: %s\n  go:          %s", want, got)
			}
			if id := strings.TrimSpace(e.cli(t, lits("transaction", "txid", "--tx-body-file", p("b.txbody"), "--output-text")...)); id != body.ID.String() {
				t.Errorf("txid %s, cardano-cli %s", body.ID, id)
			}
			out := e.cli(t, lits("transaction", "calculate-min-fee", "--tx-body-file", p("b.txbody"), "--protocol-params-file", lightParameters,
				"--witness-count", strconv.Itoa(int(tc.witnesses)), "--reference-script-size", "0", "--output-text")...)
			wantFee, _ := strconv.ParseUint(strings.Fields(out)[0], 10, 64)
			if gotFee, err := led.EstimateFee(params, body, tc.witnesses); err != nil || uint64(gotFee) != wantFee {
				t.Errorf("fee at %d witnesses: go %d (%v), cardano-cli %d", tc.witnesses, gotFee, err, wantFee)
			}
			var ws []txbuild.Witness
			var wfiles []execx.Arg
			for i, name := range append([]string{"payment"}, tc.signers...) {
				w, err := signer.Witness(ctx, roleKey[name], body)
				if err != nil {
					t.Fatalf("%s witness: %v", name, err)
				}
				wf := p(fmt.Sprintf("w%d.witness", i))
				e.cli(t, append(lits("transaction", "witness", "--tx-body-file", p("b.txbody"), "--out-file", wf, "--signing-key-file"),
					execx.SecretIn(secret.Take(append([]byte(nil), skeyOf[name]...))))...)
				if got, want := "825820"+hex.EncodeToString(w.VKey[:])+"5840"+hex.EncodeToString(w.Signature[:]), cborHexOf(t, wf); got != want {
					t.Fatalf("%s witness differs\n  cardano-cli: %s\n  go:          %s", name, want, got)
				}
				ws = append(ws, w)
				wfiles = append(wfiles, execx.Lit("--witness-file"), execx.Lit(wf))
			}
			e.cli(t, append(lits("transaction", "assemble", "--tx-body-file", p("b.txbody")), append(wfiles, lits("--out-file", p("a.tx"))...)...)...)
			signed, err := led.Assemble(body, ws)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := hex.EncodeToString(signed.CBOR), cborHexOf(t, p("a.tx")); got != want {
				t.Fatalf("assembled transaction differs\n  cardano-cli: %s\n  go:          %s", want, got)
			}
		})
	}
}
