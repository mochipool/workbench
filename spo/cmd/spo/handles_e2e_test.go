package main

import (
	"bytes"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/handle"
)

const handleLoopback = "127.0.0.1:2"

// handleStandIn is the Koios stand-in that also knows ADA Handles: `$alice`
// is a CIP-68 handle held, once, by destAddress; no classic asset exists. The
// Handle API (sub-handles) lives at another loopback address and is not
// asked for a root handle.
type handleStandIn struct {
	*koiosStandIn
	handleCalls int
}

func (h *handleStandIn) RoundTrip(req *http.Request) (*http.Response, error) {
	name := hex.EncodeToString([]byte("alice"))
	cip68 := handle.LabelCIP68 + name
	if req.URL.Host == handleLoopback {
		h.handleCalls++
		return h.respond(404, []byte(`{"message":"not found"}`), req), nil
	}
	if req.URL.Host == koiosLoopback {
		switch req.Method + " " + req.URL.Path {
		case "GET /api/v1/asset_addresses":
			q, _ := url.ParseQuery(req.URL.RawQuery)
			if q.Get("_asset_policy") != handle.PolicyCurrent {
				h.t.Errorf("the lookup used the policy %s, not the current handle policy", q.Get("_asset_policy"))
			}
			if q.Get("_asset_name") == cip68 {
				return h.respond(200, []byte(`[{"payment_address":"`+destAddress+`","quantity":"1"}]`), req), nil
			}
			return h.respond(200, []byte(`[]`), req), nil
		case "POST /api/v1/address_utxos":
			body, _ := io.ReadAll(req.Body)
			req.Body = io.NopCloser(bytes.NewReader(body))
			if strings.Contains(string(body), destAddress) {
				return h.respond(200, []byte(`[{"tx_hash":"`+strings.Repeat("7c", 32)+`","tx_index":0,"value":"2000000","asset_list":[{"policy_id":"`+
					handle.PolicyCurrent+`","asset_name":"`+cip68+`","quantity":"1"}],"datum_hash":null,"inline_datum":null,"reference_script":null}]`), req), nil
			}
		}
	}
	return h.koiosStandIn.RoundTrip(req)
}

func handlesWorkspace(t *testing.T) (dir string, k *handleStandIn) {
	t.Helper()
	k = &handleStandIn{koiosStandIn: &koiosStandIn{t: t}}
	old := http.DefaultTransport
	http.DefaultTransport = k
	t.Cleanup(func() { http.DefaultTransport = old })
	dir = copyWorkspace(t)
	toml := "network = \"preview\"\nmode = \"light\"\n[koios]\nurl = \"http://" + koiosLoopback + "/api/v1\"\n[handles]\nurl = \"http://" + handleLoopback + "\"\n"
	if err := os.WriteFile(filepath.Join(dir, "spo.toml"), []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, k
}

// A payment to $alice: the output names the handle and the address it
// resolved to before the question; the default answer is No; a yes submits
// the transaction to the address the chain says holds the handle.
func TestHandlePaymentShowsHandleAndAddressThenSubmits(t *testing.T) {
	dir, k := handlesWorkspace(t)
	importWallet(t, dir)
	g := writeGenesis(t)

	out, err := exec2(t, dir, []string{""}, "wallet", "send", walletName, "$Alice", "ALL", "--shelley-genesis", g)
	if err == nil || !strings.Contains(err.Error(), "not approved") {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "to           $alice ("+destAddress+")")
	if len(k.submitted) != 0 {
		t.Fatal("a declined payment was submitted")
	}
	out, err = exec2(t, dir, []string{"y"}, "wallet", "send", walletName, "$alice", "ALL", "--shelley-genesis", g)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "to           $alice ("+destAddress+")", "Submitted transaction ")
	if len(k.submitted) != 1 || !bytes.Contains([]byte(hex.EncodeToString(k.submitted[0])), []byte(hex.EncodeToString(addrBytes(t, destAddress)))) {
		t.Errorf("submitted %d transactions, or none pays the holder of the handle", len(k.submitted))
	}
	if k.handleCalls != 0 {
		t.Errorf("a root handle asked the Handle API %d times", k.handleCalls)
	}

	// An unknown handle is an error; nothing else is submitted.
	out, err = exec2(t, dir, []string{"y"}, "wallet", "send", walletName, "$nobody", "ALL", "--shelley-genesis", g)
	if err == nil || !strings.Contains(err.Error(), "no holder found") || len(k.submitted) != 1 {
		t.Errorf("%v\n%s", err, out)
	}

	// The address command shows both too.
	out, err = exec2(t, dir, nil, "address", "$alice")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "address $alice "+destAddress, "ADA Handle   $alice resolved to "+destAddress)
}

// Offline there is no resolver that can answer, and the refusal says so.
func TestHandleRefusedOffline(t *testing.T) {
	dir := copyWorkspace(t)
	importWallet(t, dir)
	transfer := filepath.Join(t.TempDir(), "offlineTransfer.json")
	_, addr := walletKey()
	writeTransferFile(t, transfer, addr)
	out, err := exec2(t, dir, nil, "wallet", "send", walletName, "$alice", "ALL", "--transfer-file", transfer, "--shelley-genesis", writeGenesis(t), "--yes")
	if err == nil || !strings.Contains(err.Error(), "not offline") {
		t.Fatalf("%v\n%s", err, out)
	}
	out, err = exec2(t, dir, nil, "capabilities")
	if err != nil {
		t.Fatal(err)
	}
	mustHave(t, out, "ada-handle", "ADA Handles can only be resolved with a chain provider")
}

func addrBytes(t *testing.T, bech string) []byte {
	t.Helper()
	info, err := native.Ledger{}.InspectAddress(chain.Address(bech))
	if err != nil || info.PaymentKeyHash == nil {
		t.Fatalf("%v", err)
	}
	return info.PaymentKeyHash[:]
}
