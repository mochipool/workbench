package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// calidusOfAbandonArt is the Calidus id of the public test phrase at account 0,
// index 0 (spo/internal/domain/cose and the poolkey tests record it).
const calidusOfAbandonArt = "calidus15yqt0pru382hy9vjlsxv3ye02z50sfvt8xunscg5pgden7czfjdjq"

// step runs a command on dir with the passphrase on a descriptor and fails on error.
func stepOn(t *testing.T, dir string, all *strings.Builder, args ...string) string {
	t.Helper()
	out, err := withPass(t, dir, testPass, args...)
	all.WriteString(out)
	if err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return out
}

// lastQueuedTx returns the signed transaction of the last queue entry: the
// body, the auxiliary data as it is in the transaction, and its hash from the
// body.
func lastQueuedTx(t *testing.T, path string) (aux []byte, bodyHash []byte) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	all := cborHexRE.FindAllStringSubmatch(string(raw), -1)
	if len(all) == 0 {
		t.Fatal("no queued transaction")
	}
	b, _ := hex.DecodeString(all[len(all)-1][1])
	var tx []cbor.RawMessage
	if err := cbor.Unmarshal(b, &tx); err != nil || len(tx) != 4 {
		t.Fatalf("not a transaction: %v", err)
	}
	var body map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(tx[0], &body); err != nil {
		t.Fatal(err)
	}
	if err := cbor.Unmarshal(body[7], &bodyHash); err != nil {
		t.Fatalf("no auxiliary data hash in the body: %v", err)
	}
	return tx[3], bodyHash
}

// metadataOf returns the metadata map of an auxiliary data item (Alonzo form,
// tag 259 over {0: metadata}).
func metadataOf(t *testing.T, aux []byte) []byte {
	t.Helper()
	var wrapped map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(aux, &wrapped); err != nil || wrapped[0] == nil {
		t.Fatalf("the auxiliary data does not decode: %v", err)
	}
	return wrapped[0]
}

// The Calidus pool key from the first command to a transaction that carries its
// registration: generate the pool keys, derive the Calidus key from the public
// test phrase, sign the registration with the pool cold key, and attach the
// stored record to a payment without ever writing a file.
func TestCalidusKeyAndRegistrationThroughCommands(t *testing.T) {
	dir := copyWorkspace(t)
	genesis := writeGenesis(t)
	var all strings.Builder

	stepOn(t, dir, &all, "pool", "keys", "generate", "p")

	pf, pfd := fdIn(t, testPass+"\n")
	defer pf.Close()
	mf, mfd := fdIn(t, abandonArt+"\n")
	defer mf.Close()
	out, err := exec(t, nil, "-C", dir, "--passphrase-fd", pfd, "pool", "calidus", "new", "c", "--mnemonic-in-fd", mfd)
	all.WriteString(out)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Generated the Calidus key c.", calidusOfAbandonArt, "spo pool calidus register-metadata c <pool>")
	if strings.Contains(out, "recovery phrase was generated") {
		t.Errorf("a given phrase is not announced as generated:\n%s", out)
	}
	// A fresh phrase is generated and stored, never shown.
	out = stepOn(t, dir, &all, "pool", "calidus", "new", "fresh")
	mustHave(t, out, "Generated the Calidus key fresh.", "calidus1", "stored sealed in the workspace")
	if out, err = withPass(t, dir, testPass, "pool", "calidus", "new", "c"); err == nil {
		t.Errorf("a Calidus key was generated over an existing one:\n%s", out)
	}

	out = stepOn(t, dir, &all, "pool", "calidus", "register-metadata", "c", "p", "--nonce", "123")
	m := regexp.MustCompile(`stored as\s+(p_\d{12}\.calidus-registration\.json)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no stored record named:\n%s", out)
	}
	mustHave(t, out, "Calidus id   "+calidusOfAbandonArt, "nonce        123", "pool id      pool1",
		"spo wallet send <payer> <payer> MIN --metadata-record "+m[1])

	// The stored record is the signer's JSON: nonce and Calidus key in its payload.
	st := storeOf(t, dir)
	var stored []byte
	if err := st.View(context.Background(), func(r ports.NamedReader) error {
		var e error
		stored, e = r.Get(ports.NamedRef{Name: strings.TrimSuffix(m[1], ".calidus-registration.json"), Kind: ports.CalidusRegistration})
		return e
	}); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		R struct {
			Payload struct {
				Nonce uint64 `json:"4"`
				Cal   string `json:"7"`
			} `json:"1"`
		} `json:"867"`
	}
	if err := json.Unmarshal(stored, &doc); err != nil || doc.R.Payload.Nonce != 123 || !strings.HasPrefix(doc.R.Payload.Cal, "0x") {
		t.Fatalf("the stored registration: %v\n%s", err, stored)
	}

	// Attached to a payment: the transaction's metadata is that registration,
	// signed by the pool cold key.
	_, addr := importWallet(t, dir)
	file := filepath.Join(dir, cli.TransferFileName)
	writeTransferFile(t, file, addr)
	out = stepOn(t, dir, &all, "wallet", "send", walletName, walletName, "MIN", "--metadata-record", m[1], "--yes", "--shelley-genesis", genesis)
	mustHave(t, out, "Queued transaction ")
	aux, auxHash := lastQueuedTx(t, file)
	if h := blake2b.Sum256(aux); hex.EncodeToString(h[:]) != hex.EncodeToString(auxHash) {
		t.Errorf("the body's auxiliary data hash %x is not the hash of the auxiliary data %x", auxHash, h)
	}
	reg, err := cose.VerifyCip88(metadataOf(t, aux)) // checks the COSE signature with the cold key in the record
	if err != nil {
		t.Fatalf("the registration in the transaction does not verify: %v", err)
	}
	cold := vkeyOf(t, dir, ports.NamedRef{Name: "p", Kind: ports.NodeVKey})
	h224, _ := blake2b.New(28, nil)
	h224.Write(cold)
	if hex.EncodeToString(reg.PoolID[:]) != hex.EncodeToString(h224.Sum(nil)) {
		t.Errorf("the registration is for pool %x, the cold key hashes to %x", reg.PoolID, h224.Sum(nil))
	}
	if id, _ := cose.CalidusID(reg.CalidusPub[:]); id != calidusOfAbandonArt || reg.Nonce != 123 {
		t.Errorf("calidus %s nonce %d", id, reg.Nonce)
	}

	// A record that is not in the workspace, and a bad name, are refused.
	if out, err = withPass(t, dir, testPass, "wallet", "send", walletName, walletName, "MIN", "--metadata-record", "nope.calidus-registration.json", "--yes", "--shelley-genesis", genesis); err == nil {
		t.Errorf("a record the workspace does not hold:\n%s", out)
	}
	if out, err = withPass(t, dir, testPass, "wallet", "send", walletName, walletName, "MIN", "--metadata-record", "p_1", "--yes"); err == nil || !strings.Contains(err.Error(), "NAME.calidus-registration.json") {
		t.Errorf("a record name without its extension: %v\n%s", err, out)
	}

	// Calidus status: the capability is absent, honestly.
	if out, err = withPass(t, dir, testPass, "pool", "calidus", "status", "c"); err == nil || !strings.Contains(err.Error(), "calidus-registrations") {
		t.Errorf("status: %v\n%s", err, out)
	}

	notLeaked(t, all.String(), abandonArt, "abandon abandon",
		secretHex(t, dir, ports.NamedRef{Name: "c", Kind: ports.CalidusSKey}), secretHex(t, dir, ports.NamedRef{Name: "p", Kind: ports.NodeSKey}), "SigningKey")
	stepOn(t, dir, &all, "store", "verify")
}

// Catalyst: a voting key, a stake account, a registration signed by the stake
// key and carried by a payment.
func TestCatalystRegistrationThroughCommands(t *testing.T) {
	dir := copyWorkspace(t)
	genesis := writeGenesis(t)
	var all strings.Builder

	out := stepOn(t, dir, &all, "catalyst", "key", "new", "v")
	m := regexp.MustCompile(`public key\s+(cvote_vk1\S+)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no voting public key:\n%s", out)
	}
	stepOn(t, dir, &all, "wallet", "new", "s", "--stake")

	// A weight, two keys, and a rewards address given by name.
	out = stepOn(t, dir, &all, "catalyst", "register", "s", "s.payment", "--vote-key", "v:3", "--vote-key", m[1], "--nonce", "123")
	r := regexp.MustCompile(`stored as\s+(s_\d{12}\.vote-registration\.cbor)`).FindStringSubmatch(out)
	if r == nil {
		t.Fatalf("no stored record named:\n%s", out)
	}
	mustHave(t, out, "nonce        123", "weight 3", "weight 1", "spo wallet send <payer> <payer> MIN --metadata-record "+r[1])

	_, addr := importWallet(t, dir)
	file := filepath.Join(dir, cli.TransferFileName)
	writeTransferFile(t, file, addr)
	stepOn(t, dir, &all, "wallet", "send", walletName, walletName, "MIN", "--metadata-record", r[1], "--message", "catalyst", "--yes", "--shelley-genesis", genesis)
	aux, auxHash := lastQueuedTx(t, file)
	if h := blake2b.Sum256(aux); hex.EncodeToString(h[:]) != hex.EncodeToString(auxHash) {
		t.Errorf("auxiliary data hash %x, body %x", h, auxHash)
	}
	reg, err := cose.VerifyCip36(metadataOf(t, aux))
	if err != nil {
		t.Fatalf("the registration in the transaction does not verify: %v", err)
	}
	stakeKey := vkeyOf(t, dir, ports.NamedRef{Name: "s", Kind: ports.StakingVKey})
	if hex.EncodeToString(reg.StakePub[:]) != hex.EncodeToString(stakeKey) || reg.Nonce != 123 || len(reg.Delegations) != 2 ||
		reg.Delegations[0].Weight != 3 || reg.Delegations[1].Weight != 1 || reg.Delegations[0].VotePub != reg.Delegations[1].VotePub {
		t.Errorf("registration %+v (stake key %x)", reg, stakeKey)
	}

	// Refusals before anything is built: no voting key, an unknown key, a zero nonce.
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"catalyst", "register", "s", "s.payment"}, "--vote-key is required"},
		{[]string{"catalyst", "register", "s", "s.payment", "--vote-key", "ghost"}, "voting key"},
		{[]string{"catalyst", "register", "s", "s.payment", "--vote-key", "v:x", "--nonce", "1"}, "weight"},
		{[]string{"catalyst", "register", "s", "s.payment", "--vote-key", "v", "--nonce", "0"}, "greater than zero"},
	} {
		if out, err := withPass(t, dir, testPass, tc.args...); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: %v\n%s", tc.args, err, out)
		}
	}
	notLeaked(t, all.String(), secretHex(t, dir, ports.NamedRef{Name: "v", Kind: ports.VotingSKey}), secretHex(t, dir, ports.NamedRef{Name: "s", Kind: ports.StakingSKey}), "SigningKey")
	stepOn(t, dir, &all, "store", "verify")
}
