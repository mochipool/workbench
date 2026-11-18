package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	dgov "github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

const guardScript = `{"type":"PlutusScriptV3","description":"","cborHex":"4e4d01000033222220051200120011"}`

// guardKoios is the loopback Koios of the light-mode tests extended for the
// proposal of a parameter change that carries a guardrails script:
//
//   - the hosted parameters are the recorded preview document with ONE
//     hand-derived change: constitution.script is the hash of the test script
//     (the real preview guardrails script is not in this repository, so its
//     hash cannot be matched by a file here);
//   - address_utxos answers a large UTxO and a 6 ADA one (hand-written);
//   - account_info answers a registered stake address, proposal_list none;
//   - /ogmios answers evaluateTransaction as Ogmios v6 documents it. NO REAL
//     KOIOS ANSWER of that endpoint is recorded: the shape here is the one
//     the adapter's comment names as unconfirmed.
type guardKoios struct {
	*koiosStandIn
	scriptHash string
	utxos      string
	ogmios     func(tx []byte) (int, string)
	ogmiosReqs [][]byte
	stake      string
}

func (k *guardKoios) RoundTrip(req *http.Request) (*http.Response, error) {
	switch req.URL.Host {
	case "uptime.live":
		doc, err := os.ReadFile(lightParamsDoc)
		if err != nil {
			return nil, err
		}
		var m map[string]any
		if err := json.Unmarshal(doc, &m); err != nil {
			return nil, err
		}
		m["sposcriptsLightMode"].(map[string]any)["lastUpdate"] = time.Now().Format(time.RFC1123Z)
		m["constitution"].(map[string]any)["script"] = k.scriptHash
		out, _ := json.Marshal(m)
		k.calls = append(k.calls, req.Method+" "+req.URL.Host+req.URL.Path)
		return k.respond(200, out, req), nil
	case koiosLoopback:
		switch req.Method + " " + req.URL.Path {
		case "POST /api/v1/address_utxos":
			k.calls = append(k.calls, req.Method+" "+req.URL.Host+req.URL.Path)
			return k.respond(200, []byte(k.utxos), req), nil
		case "POST /api/v1/account_info":
			k.calls = append(k.calls, req.Method+" "+req.URL.Host+req.URL.Path)
			return k.respond(200, []byte(`[{"stake_address":"`+k.stake+`","status":"registered","delegated_pool":null,"delegated_drep":null,"rewards_available":"0","deposit":"2000000"}]`), req), nil
		case "GET /api/v1/proposal_list":
			k.calls = append(k.calls, req.Method+" "+req.URL.Host+req.URL.Path)
			return k.respond(200, []byte(`[]`), req), nil
		case "POST /api/v1/ogmios":
			k.calls = append(k.calls, req.Method+" "+req.URL.Host+req.URL.Path)
			body, _ := io.ReadAll(req.Body)
			var rpc struct {
				Method string `json:"method"`
				Params struct {
					Transaction struct {
						CBOR string `json:"cbor"`
					} `json:"transaction"`
				} `json:"params"`
			}
			if err := json.Unmarshal(body, &rpc); err != nil || rpc.Method != "evaluateTransaction" {
				return k.respond(400, []byte(`"bad request"`), req), nil
			}
			tx, err := hex.DecodeString(rpc.Params.Transaction.CBOR)
			if err != nil {
				return k.respond(400, []byte(`"bad hex"`), req), nil
			}
			k.ogmiosReqs = append(k.ogmiosReqs, tx)
			status, answer := k.ogmios(tx)
			return k.respond(status, []byte(answer), req), nil
		}
	}
	return k.koiosStandIn.RoundTrip(req)
}

func ogmiosBudget(mem, cpu int) func([]byte) (int, string) {
	return func([]byte) (int, string) {
		return 200, fmt.Sprintf(`{"jsonrpc":"2.0","method":"evaluateTransaction","result":[{"validator":{"index":0,"purpose":"propose"},"budget":{"memory":%d,"cpu":%d}}],"id":null}`, mem, cpu)
	}
}

func utxoRows(rows ...string) string { return "[" + strings.Join(rows, ",") + "]" }

func utxoRow(tx byte, ix int, lovelace uint64) string {
	return fmt.Sprintf(`{"tx_hash":"%s","tx_index":%d,"value":"%d","asset_list":[],"datum_hash":null,"inline_datum":null,"reference_script":null}`,
		strings.Repeat(fmt.Sprintf("%02x", tx), 32), ix, lovelace)
}

// A parameter change that carries the constitution's guardrails script, end to
// end through the binary's command tree in light mode against a loopback Koios:
// `action create` lists every parameter with its old and new value; `action
// submit` reads the constitution from the hosted parameters, verifies the script
// file against it, asks the provider's evaluate endpoint for the execution units
// of the body (twice: once with none, once with them), builds the transaction
// with the script, the redeemer, the collateral and the script-data hash, and
// submits exactly what was evaluated. Every refusal is checked to have signed and
// submitted nothing.
func TestGuardrailsParameterChangeAgainstALoopbackKoios(t *testing.T) {
	script, err := txbuild.ParseScriptFile([]byte(guardScript))
	if err != nil {
		t.Fatal(err)
	}
	stake := "stake_test1uqeezcegh25rcskmmn0gy5fzenczfj34n8qeefhmz6taeycqg9wts"
	k := &guardKoios{koiosStandIn: &koiosStandIn{t: t}, scriptHash: hex.EncodeToString(script.Hash[:]), stake: stake,
		utxos: utxoRows(utxoRow(0x6b, 0, 3_000_000_000_000), utxoRow(0x6c, 2, 6_000_000)), ogmios: ogmiosBudget(1_500_000, 900_000_000)}
	old := http.DefaultTransport
	http.DefaultTransport = k // not k.install: that would install the embedded stand-in
	t.Cleanup(func() { http.DefaultTransport = old })

	dir := copyWorkspace(t)
	importWallet(t, dir)
	toml := "network = \"preview\"\nmode = \"light\"\n[koios]\nurl = \"http://" + koiosLoopback + "/api/v1\"\n"
	if err := os.WriteFile(filepath.Join(dir, "spo.toml"), []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(t.TempDir(), "guardrails-script.plutus")
	if err := os.WriteFile(scriptPath, []byte(guardScript), 0o600); err != nil {
		t.Fatal(err)
	}
	var all strings.Builder
	run := func(args ...string) (string, error) {
		out, err := withPass(t, dir, testPass, args...)
		all.WriteString(out)
		return out, err
	}
	must := func(args ...string) string {
		t.Helper()
		out, err := run(args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		return out
	}

	// ---- the capability is listed, with its provider.
	out := must("capabilities")
	if !regexp.MustCompile(`(?m)^  plutus-script-evaluation\s+koios preview`).MatchString(out) {
		t.Errorf("the Koios evaluator is not listed:\n%s", out)
	}

	// ---- the action file, as `action create` writes it (stored the way another
	// machine would: the offline composition has no constitution reader and the
	// light one would fetch the anchor over the network, which no test does).
	_, stakeData, err := chain.Bech32Decode(stake)
	if err != nil {
		t.Fatal(err)
	}
	params, err := dgov.CheckParams([]dgov.ParamChange{{Name: "max-tx-size", Value: "20000"}, {Name: "collateral-percent", Value: "170"}, {Name: "ref-script-cost-per-byte", Value: "16"}})
	if err != nil {
		t.Fatal(err)
	}
	ah, err := dgov.ParseHash32(govAHash)
	if err != nil {
		t.Fatal(err)
	}
	act := dgov.Action{Kind: dgov.ParameterChange, Deposit: 100_000_000_000, Return: chain.StakeAddress(stake), Anchor: dgov.Anchor{URL: govAnchor, Hash: ah},
		Params: params, Guardrails: &script.Hash}
	copy(act.ReturnKey.Hash[:], stakeData[1:])
	built, err := native.Ledger{}.BuildActionFile(act)
	if err != nil {
		t.Fatal(err)
	}
	file := []string{"", "ret_parameterchange_261116000000"}
	putPublic(t, dir, ports.NamedRef{Name: file[1], Kind: ports.GovActionFile}, built.Envelope)

	genesis := writeGenesis(t)
	submit := func(extra ...string) (string, error) {
		return run(append([]string{"action", "submit", walletName, file[1], "--guardrails-script", scriptPath, "--shelley-genesis", genesis}, extra...)...)
	}
	nothing := func(what string) {
		t.Helper()
		if len(k.submitted) != 0 {
			t.Fatalf("%s: a transaction was submitted", what)
		}
	}

	// ---- refusals: nothing signed or submitted.
	other := filepath.Join(t.TempDir(), "other.plutus")
	os.WriteFile(other, []byte(`{"type":"PlutusScriptV3","description":"","cborHex":"4e4d01000033222220051200120012"}`), 0o600)
	if out, err := run("action", "submit", walletName, file[1], "--guardrails-script", other, "--shelley-genesis", genesis, "--yes"); err == nil || !strings.Contains(err.Error(), "does not match the constitution's") {
		t.Errorf("a script file that is not the constitution's: %v\n%s", err, out)
	}
	if len(k.ogmiosReqs) != 0 {
		t.Error("the provider was asked to evaluate with a script that is not the constitution's")
	}
	nothing("a wrong script")

	k.ogmios = func([]byte) (int, string) {
		return 200, `{"jsonrpc":"2.0","method":"evaluateTransaction","error":{"code":3010,"message":"Some scripts of the transactions terminated with error(s).","data":[]},"id":null}`
	}
	if out, err := submit("--yes"); err == nil || !strings.Contains(err.Error(), "failed when the provider evaluated it") || !strings.Contains(err.Error(), "nothing was signed") {
		t.Errorf("a failing script: %v\n%s", err, out)
	}
	nothing("a failing script")
	k.ogmios = func([]byte) (int, string) { return 502, `bad gateway` }
	if out, err := submit("--yes"); err == nil || !strings.Contains(err.Error(), "could not be determined") || !strings.Contains(err.Error(), "HTTP 502") {
		t.Errorf("a provider that cannot say: %v\n%s", err, out)
	}
	nothing("a provider that cannot say")
	k.ogmios = ogmiosBudget(1_500_000, 900_000_000)
	k.utxos = utxoRows(utxoRow(0x6b, 0, 3_000_000_000_000))
	if out, err := submit("--yes"); err == nil || !strings.Contains(err.Error(), "5 to 10 ADA") {
		t.Errorf("no collateral: %v\n%s", err, out)
	}
	nothing("no collateral")
	k.utxos = utxoRows(utxoRow(0x6b, 0, 3_000_000_000_000), utxoRow(0x6c, 2, 6_000_000))

	// ---- declined at the prompt: the summary names the script, the units, the collateral and the provider.
	asked := len(k.ogmiosReqs)
	f, fd := fdIn(t, testPass+"\n")
	defer f.Close()
	out, err = exec(t, &fakeTerm{lines: []string{"n"}}, "-C", dir, "--passphrase-fd", fd, "action", "submit", walletName, file[1], "--guardrails-script", scriptPath, "--shelley-genesis", genesis)
	all.WriteString(out)
	if err == nil || !strings.Contains(err.Error(), "not approved") {
		t.Fatalf("declined: %v\n%s", err, out)
	}
	mustHave(t, out, "guardrails script "+k.scriptHash, "redeemer for proposal 1 (proposing, data {}): memory 1500000, steps 900000000",
		"script fee 151440 lovelace", "collateral at risk: at most ", "the rest of "+strings.Repeat("6c", 32)+"#2 returns to the payer", "NOT evaluated by this program", "koios preview",
		"max-tx-size: 16384 -> 20000", "ref-script-cost-per-byte: 15 -> 16")
	if len(k.ogmiosReqs)-asked != 2 {
		t.Errorf("the provider was asked %d times, want 2", len(k.ogmiosReqs)-asked)
	}
	nothing("declined")

	// ---- the transaction.
	submitOK := func() string {
		return must("action", "submit", walletName, file[1], "--guardrails-script", scriptPath, "--shelley-genesis", genesis, "--yes")
	}
	out = submitOK()
	mustHave(t, out, "Submitted transaction ", "Proposal 1 will be action ", "script fee 151440 lovelace", "max-tx-size: 16384 -> 20000", "collateral-percent: 150 -> 170",
		"ref-script-cost-per-byte: 15 -> 16")
	if len(k.submitted) != 1 {
		t.Fatalf("submitted %d\n%s", len(k.submitted), out)
	}
	tx := k.submitted[0]
	v := native.TxViewer{}
	bodyBytes, err := v.BodyOf(tx)
	if err != nil {
		t.Fatal(err)
	}
	view, err := v.View(bodyBytes)
	if err != nil {
		t.Fatal(err)
	}
	col := strings.Repeat("6c", 32)
	if len(view.CollateralInputs) != 1 || fmt.Sprintf("%x", view.CollateralInputs[0].TxID[:]) != col || view.CollateralInputs[0].Index != 2 ||
		len(view.Inputs) != 1 || fmt.Sprintf("%x", view.Inputs[0].TxID[:]) != strings.Repeat("6b", 32) {
		t.Errorf("collateral %+v inputs %+v", view.CollateralInputs, view.Inputs)
	}
	// The loss is bounded by the body, whatever the provider said of the UTxO:
	// total collateral is 150% of the fee, and the rest goes back to the payer.
	if view.TotalCollateral == nil || *view.TotalCollateral != (view.Fee*150+99)/100 || view.CollateralReturn == nil ||
		view.CollateralReturn.Lovelace != 6_000_000-*view.TotalCollateral || view.CollateralReturn.Address != view.Outputs[0].Address {
		t.Errorf("fee %d, total collateral %v, collateral return %+v", view.Fee, view.TotalCollateral, view.CollateralReturn)
	}
	// The script-data hash is the one of the units the provider reported and
	// the PlutusV3 cost model of the hosted parameters.
	raw, _ := os.ReadFile(lightParamsDoc)
	pp, err := txbuild.ParsePlutusParams(raw)
	if err != nil {
		t.Fatal(err)
	}
	var dummy chain.Utxo
	dummy.Lovelace = 5_000_000
	want, err := native.ScriptDataHash(&txbuild.PlutusAttachment{Script: script, CostModel: pp.CostModelV3, Collateral: []chain.Utxo{dummy},
		Redeemers: []txbuild.Redeemer{{Tag: txbuild.RedeemProposing, Index: 0, Data: []byte{0xa0}, Units: txbuild.ExUnits{Mem: 1_500_000, Steps: 900_000_000}}}})
	if err != nil {
		t.Fatal(err)
	}
	if view.ScriptDataHash == nil || *view.ScriptDataHash != want {
		t.Errorf("script-data hash %x, want %x", view.ScriptDataHash, want)
	}
	// The body the provider evaluated last is the body that was submitted: the
	// same inputs, collateral and fee.
	last := k.ogmiosReqs[len(k.ogmiosReqs)-1]
	lastBody, err := v.BodyOf(last)
	if err != nil {
		t.Fatal(err)
	}
	if string(lastBody) != string(bodyBytes) {
		t.Error("the transaction that was submitted is not the body that was evaluated last")
	}
	// ---- offline mode cannot evaluate: refused naming the capability, before
	// the workspace passphrase or anything else is asked, with no request made.
	calls := len(k.calls)
	term := &fakeTerm{}
	out, err = exec(t, term, "-C", dir, "action", "submit", walletName, file[1], "--offline", "--shelley-genesis", genesis)
	if err == nil || !strings.Contains(err.Error(), "plutus-script-evaluation: no provider evaluates Plutus scripts here") {
		t.Errorf("offline: %v\n%s", err, out)
	}
	if len(term.asked) != 0 || len(k.calls) != calls || len(k.submitted) != 1 {
		t.Errorf("offline refusal: asked %v, requests %v, submitted %d", term.asked, k.calls[calls:], len(k.submitted))
	}
	notLeaked(t, all.String(), secretHex(t, dir, ports.NamedRef{Name: walletName, Kind: ports.AddrSKey}))
	for _, c := range k.calls {
		if !strings.Contains(c, koiosLoopback) && !strings.Contains(c, "uptime.live") {
			t.Errorf("a request went elsewhere: %s", c)
		}
	}
}
