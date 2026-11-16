// Command fakehw is a stand-in for cardano-hw-cli, for tests without a device.
// It reproduces the contract the specs describe (spec/upstream/common/Chw.md,
// Ctx.md and the script specs) and the flags of cardano-hw-cli 1.20.0's --help;
// the exact bytes a real Ledger, Trezor or Keystone writes can only be confirmed
// on a device. It is configured by a JSON file named in FAKEHW_CONFIG and
// appends every invocation's argument vector to the file's "log".
//
// Keys: the key of a derivation path is the Ed25519 key of the seed
// sha256(seed || "|" || path-joined-by-"/"), so a test can recompute it.
// Bodies: a transaction whose inputs are a plain array (not the tag-258 set)
// is "non-canonical"; `transform` gives it the tagged set. One that contains the
// text "needs-unrestricted-mode" (a message in its metadata, say) needs
// --allow-unrestricted-mode: without the flag the tool prints SECURITY and fails.
// The signature of a witness is over the transaction id of the CBOR (the
// hash of its body map, as a real device signs), so a body built by the real
// ledger adapter verifies. `transform` also gives a body whose inputs are not
// a tag-258 set (valid CBOR, a legacy form) the canonical tagged set, so the
// canonical body has another id than the one first built.
//
// This is the one fake: internal/adapters/hwcli's tests and test/hardware (via
// test/world) both build it. An earlier fake signed blake2b-256 of the whole
// transaction and hashed the policy script text, so the adapter was only ever
// checked against synthetic bodies.
//
// Misbehaviour: the "misbehave" setting makes the tool do what a broken or
// hostile tool could, so a test can see the adapter refuse it:
//
//	witness:   wrongkey (another key signs and is named), badsig (a signature over
//	           another body id), truncated (half the file), exitafter (the file is
//	           written, then the tool exits 1 with no message)
//	opcert:    counter, kes, period (the certificate is over another one), coldkey
//	           (signed by another cold key), badsig, truncated, exitafter
//	policyid:  wrongpolicy (another id), truncated
//	key-gen:   wrongvkey (the verification key is not the signing file's)
//	message:   msgwrongpayload (another payload is embedded), msgbadsig, msgwrongkey
//	           (another key signs and is named), msgaddr (the address header is not
//	           the key's hash), msgtruncated
//	vote:      votewrongkey (another stake key signs), votebadsig, votewrongaddr
//	           (another rewards address is registered), votetruncated
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
)

type config struct {
	Vendor      string `json:"vendor"`
	App         string `json:"app"`
	ToolVersion string `json:"toolVersion"`
	// Device: ok, nodevice, hang, general, unreadable, raw (prints DeviceText).
	Device     string `json:"device"`
	DeviceText string `json:"deviceText"`
	// Action: ok, disconnect, rejected, error, errorzero, warning.
	Action string `json:"action"`
	// Misbehave: see the package comment; empty is a correct tool.
	Misbehave string `json:"misbehave"`
	Seed      string `json:"seed"`
	Log       string `json:"log"`
}

var cfg config

func main() {
	raw, err := os.ReadFile(os.Getenv("FAKEHW_CONFIG"))
	if err != nil || json.Unmarshal(raw, &cfg) != nil {
		// The toolchain probes `version` with an empty environment.
		if len(os.Args) == 2 && os.Args[1] == "version" {
			fmt.Print("Cardano HW CLI Tool version 1.20.0\nCommit hash: 0000\n")
			return
		}
		fmt.Fprintln(os.Stderr, "fakehw: no FAKEHW_CONFIG")
		os.Exit(3)
	}
	if cfg.Log != "" {
		f, _ := os.OpenFile(cfg.Log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		line, _ := json.Marshal(os.Args[1:])
		fmt.Fprintf(f, "%s\n", line)
		f.Close()
	}
	args := os.Args[1:]
	if len(args) == 0 {
		os.Exit(2)
	}
	switch {
	case args[0] == "version":
		fmt.Printf("Cardano HW CLI Tool version %s\nCommit hash: 0000\n", cfg.ToolVersion)
	case len(args) >= 2 && args[0] == "device" && args[1] == "version":
		deviceVersion()
	case len(args) >= 2 && args[0] == "address" && args[1] == "key-gen":
		actionGate()
		keyGen(parse(args[2:]), false)
	case len(args) >= 2 && args[0] == "node" && args[1] == "key-gen":
		actionGate()
		keyGen(parse(args[2:]), true)
	case len(args) >= 2 && args[0] == "node" && args[1] == "issue-op-cert":
		actionGate()
		issueOpCert(parse(args[2:]))
	case len(args) >= 2 && args[0] == "transaction" && args[1] == "transform":
		transform(parse(args[2:]))
	case len(args) >= 2 && args[0] == "transaction" && args[1] == "validate":
		f := parse(args[2:])
		if c := readTx(f.one("--tx-file")); !bytes.Equal(tagInputs(c), c) {
			fmt.Println("ERROR: transaction is not in canonical form")
			os.Exit(1)
		}
	case len(args) >= 2 && args[0] == "transaction" && args[1] == "witness":
		actionGate()
		witness(parse(args[2:]))
	case len(args) >= 2 && args[0] == "transaction" && args[1] == "policyid":
		actionGate()
		f := parse(args[2:])
		script, _ := os.ReadFile(f.one("--script-file"))
		// A device shows the hash of the script; the real ledger adapter computes it.
		id, err := native.Ledger{}.PolicyID(script)
		if err != nil {
			fmt.Println("ERROR: not a native script")
			os.Exit(1)
		}
		if cfg.Misbehave == "wrongpolicy" {
			id[0] ^= 1
		}
		text := hex.EncodeToString(id[:])
		if cfg.Misbehave == "truncated" {
			text = text[:20]
		}
		fmt.Println(text)
	case len(args) >= 2 && args[0] == "message" && args[1] == "sign":
		actionGate()
		messageSign(parse(args[2:]))
	case len(args) >= 2 && args[0] == "vote" && args[1] == "registration-metadata":
		actionGate()
		voteRegistration(parse(args[2:]))
	default:
		fmt.Fprintln(os.Stderr, "usage: cardano-hw-cli: error: invalid choice:", strings.Join(args, " "))
		os.Exit(2)
	}
}

func deviceVersion() {
	switch cfg.Device {
	case "nodevice":
		fmt.Fprintln(os.Stderr, "Error: Error occurred while trying to find hw transport, make sure Ledger or Trezor or Keystone is connected to your computer")
		os.Exit(1)
	case "hang":
		time.Sleep(time.Hour)
	case "general":
		fmt.Fprintln(os.Stderr, "General error")
		os.Exit(1)
	case "unreadable":
		fmt.Printf("%s app version undefined\n", cfg.Vendor)
	case "raw":
		fmt.Println(cfg.DeviceText)
	default:
		fmt.Printf("%s app version %s\n", cfg.Vendor, cfg.App)
		fmt.Fprintln(os.Stderr, "(progress on stderr)")
	}
}

// actionGate makes a signing command fail the way a device does.
func actionGate() {
	switch cfg.Action {
	case "disconnect":
		fmt.Println("DISCONNECT: the device was disconnected")
		os.Exit(1)
	case "rejected":
		fmt.Println("Error: Action rejected by user. REJECTED")
		os.Exit(1)
	case "error":
		fmt.Println("ERROR: something broke")
		os.Exit(1)
	case "warning":
		fmt.Fprintln(os.Stderr, "WARNING: unusual request")
	}
}

type flags map[string][]string

func (f flags) one(k string) string {
	if v := f[k]; len(v) > 0 {
		return v[0]
	}
	fmt.Fprintln(os.Stderr, "missing", k)
	os.Exit(2)
	return ""
}

var boolFlags = map[string]bool{"--allow-unrestricted-mode": true, "--hashed": true, "--prefer-hex": true, "--mainnet": true}

func parse(a []string) flags {
	f := flags{}
	for i := 0; i < len(a); i++ {
		k := a[i]
		if boolFlags[k] {
			f[k] = append(f[k], "")
			continue
		}
		if i+1 >= len(a) {
			fmt.Fprintln(os.Stderr, "missing value for", k)
			os.Exit(2)
		}
		f[k] = append(f[k], a[i+1])
		i++
	}
	return f
}

func seedFor(path string) ed25519.PrivateKey {
	h := sha256.Sum256([]byte(cfg.Seed + "|" + path))
	return ed25519.NewKeyFromSeed(h[:])
}

// keyOf reads a hardware signing file and returns the key of its path.
func keyOf(file string) (ed25519.PrivateKey, []byte) {
	raw, err := os.ReadFile(file)
	var j struct {
		Path []string `json:"path"`
	}
	if err != nil || json.Unmarshal(raw, &j) != nil {
		fmt.Fprintln(os.Stderr, "ERROR: unreadable signing file")
		os.Exit(1)
	}
	k := seedFor(strings.Join(j.Path, "/"))
	return k, k.Public().(ed25519.PublicKey)
}

// only fails the call when it carries a flag that the argument vector of the
// spec (or cardano-hw-cli's --help) does not have: the fake checks exactly the
// vectors the specs give.
func only(f flags, allowed ...string) {
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	for k := range f {
		if !ok[k] {
			fmt.Println("ERROR: unknown option", k)
			os.Exit(2)
		}
	}
}

// network demands the network argument of a vote registration (`--mainnet` or
// `--testnet-magic N`: SPO-09a-EXT-004 passes the network magic argument).
func network(f flags) {
	if len(f["--mainnet"]) == 0 && len(f["--testnet-magic"]) == 0 {
		fmt.Println("ERROR: no network")
		os.Exit(1)
	}
}

func writeJSON(path string, v any) {
	b, _ := json.MarshalIndent(v, "", "    ")
	if err := os.WriteFile(path, append(b, '\n'), 0o400); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func keyGen(f flags, cold bool) {
	path := f.one("--path")
	k := seedFor(path)
	pub := k.Public().(ed25519.PublicKey)
	var vkFile string
	vkType, vkDesc, hwsType := "PaymentVerificationKeyShelley_ed25519", "Payment Verification Key", "PaymentHWSigningFileShelley_ed25519"
	if !cold {
		vkFile = f.one("--verification-key-file")
	} else {
		vkFile, vkType, vkDesc, hwsType = f.one("--cold-verification-key-file"), "StakePoolVerificationKey_ed25519", "Stake Pool Operator Verification Key", "StakePoolHWSigningFileShelley_ed25519"
	}
	vkPub := pub
	if cfg.Misbehave == "wrongvkey" {
		_, vkPub = otherKey(pub)
	}
	writeJSON(vkFile, map[string]string{"type": vkType, "description": vkDesc, "cborHex": "5820" + hex.EncodeToString(vkPub)})
	writeJSON(f.one("--hw-signing-file"), map[string]any{
		"type": hwsType, "description": "Hardware Signing File", "path": strings.Split(path, "/"),
		"cborXPubKeyHex": "5840" + hex.EncodeToString(pub) + strings.Repeat("00", 32),
	})
	if cold {
		var vk [32]byte
		copy(vk[:], pub)
		os.WriteFile(f.one("--operational-certificate-issue-counter-file"), pool.IssueCounter{Next: 0, ColdVKey: vk}.Envelope(), 0o400)
	}
}

func issueOpCert(f flags) {
	k, pub := keyOf(f.one("--hw-signing-file"))
	if cfg.Misbehave == "coldkey" {
		k, pub = otherKey(pub)
	}
	counterRaw, err := os.ReadFile(f.one("--operational-certificate-issue-counter-file"))
	if err != nil {
		fmt.Println("ERROR: no counter file")
		os.Exit(1)
	}
	ctr, err := pool.ParseIssueCounter(counterRaw)
	if err != nil {
		fmt.Println("ERROR: bad counter file")
		os.Exit(1)
	}
	kesRaw, _ := os.ReadFile(f.one("--kes-verification-key-file"))
	env, err := pool.ParseEnvelope(kesRaw)
	var kes []byte
	if err == nil {
		kes, err = env.Key32()
	}
	if err != nil {
		fmt.Println("ERROR: bad KES key file")
		os.Exit(1)
	}
	var period uint64
	fmt.Sscan(f.one("--kes-period"), &period)
	switch cfg.Misbehave {
	case "counter":
		ctr.Next++
	case "period":
		period++
	case "kes":
		kes = append([]byte(nil), kes...)
		kes[0] ^= 1
	}
	signable := append([]byte{}, kes...)
	for _, n := range []uint64{ctr.Next, period} {
		for s := 56; s >= 0; s -= 8 {
			signable = append(signable, byte(n>>uint(s)))
		}
	}
	sig := ed25519.Sign(k, signable)
	if cfg.Misbehave == "badsig" {
		sig = append([]byte(nil), sig...)
		sig[0] ^= 1
	}
	b := []byte{0x82, 0x84, 0x58, 0x20}
	b = append(b, kes...)
	b = appendUint(b, ctr.Next)
	b = appendUint(b, period)
	b = append(b, 0x58, 0x40)
	b = append(b, sig...)
	b = append(b, 0x58, 0x20)
	b = append(b, pub...)
	os.WriteFile(f.one("--out-file"), pool.MarshalEnvelope(pool.Envelope{Type: pool.TypeOpCert, Description: "", CborHex: hex.EncodeToString(b)}), 0o600)
	// The tool advances the counter file, as the real one does.
	var vk [32]byte
	copy(vk[:], pub)
	os.WriteFile(f.one("--operational-certificate-issue-counter-file"), pool.IssueCounter{Next: ctr.Next + 1, ColdVKey: vk}.Envelope(), 0o600)
	finish(f.one("--out-file"))
}

// otherKey is a key that is not the one asked for.
func otherKey(pub []byte) (ed25519.PrivateKey, []byte) {
	h := sha256.Sum256(append([]byte("another key|"), pub...))
	k := ed25519.NewKeyFromSeed(h[:])
	return k, k.Public().(ed25519.PublicKey)
}

// finish applies the misbehaviour that is about the files the tool has just
// written: truncated cuts them in half, exitafter fails after writing them.
func finish(files ...string) {
	switch cfg.Misbehave {
	case "truncated":
		for _, p := range files {
			if raw, err := os.ReadFile(p); err == nil {
				os.WriteFile(p, raw[:len(raw)/2], 0o600)
			}
		}
	case "exitafter":
		os.Exit(1)
	}
}

func appendUint(b []byte, n uint64) []byte {
	switch {
	case n < 24:
		return append(b, byte(n))
	case n < 1<<8:
		return append(b, 0x18, byte(n))
	case n < 1<<16:
		return append(b, 0x19, byte(n>>8), byte(n))
	default:
		return append(b, 0x1a, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
}

func readTx(file string) []byte {
	raw, err := os.ReadFile(file)
	if err != nil {
		fmt.Println("ERROR: cannot read the transaction file")
		os.Exit(1)
	}
	cbor, err := pool.ParseTxEnvelope(raw)
	if err != nil {
		fmt.Println("ERROR: not a transaction envelope")
		os.Exit(1)
	}
	return cbor
}

var needsUnrestricted = []byte("needs-unrestricted-mode")

func transform(f flags) {
	cbor := readTx(f.one("--tx-file"))
	if bytes.Contains(cbor, needsUnrestricted) && len(f["--allow-unrestricted-mode"]) == 0 {
		fmt.Println("SECURITY: the transaction needs unrestricted mode")
		os.Exit(1)
	}
	cbor = tagInputs(cbor)
	if cfg.Misbehave == "stale-aux" {
		// Re-serialise the auxiliary data (the last byte changes) without the
		// body's hash of it: the stale-hash case of SPO-Ctx-IN-001.
		cbor = append([]byte(nil), cbor...)
		cbor[len(cbor)-1] ^= 1
	}
	os.WriteFile(f.one("--out-file"), pool.TxEnvelope(cbor), 0o600)
	fmt.Println("Transaction successfully transformed")
}

func witness(f flags) {
	cbor := readTx(f.one("--tx-file"))
	if bytes.Contains(cbor, needsUnrestricted) && len(f["--allow-unrestricted-mode"]) == 0 {
		fmt.Println("SECURITY: the transaction needs unrestricted mode (enable expert mode on the device)")
		os.Exit(1)
	}
	files, outs := f["--hw-signing-file"], f["--out-file"]
	if len(files) != len(outs) {
		fmt.Println("ERROR: one --out-file per --hw-signing-file")
		os.Exit(1)
	}
	if len(f["--mainnet"]) == 0 && len(f["--testnet-magic"]) == 0 {
		fmt.Println("ERROR: no network")
		os.Exit(1)
	}
	id := blake2b.Sum256(cbor)
	if tid, err := (native.Ledger{}).TransactionID(cbor); err == nil {
		id = tid
	}
	signed := id[:]
	if cfg.Misbehave == "badsig" {
		other := sha256.Sum256(id[:])
		signed = other[:]
	}
	for i, file := range files {
		k, pub := keyOf(file)
		if cfg.Misbehave == "wrongkey" {
			k, pub = otherKey(pub)
		}
		var w txbuild.Witness
		copy(w.VKey[:], pub)
		copy(w.Signature[:], ed25519.Sign(k, signed))
		os.WriteFile(outs[i], pool.WitnessEnvelope(w), 0o600)
	}
	finish(outs...)
	if cfg.Action == "errorzero" {
		fmt.Println("ERROR: but exit zero")
	}
}

// messageSign writes a CIP-8 COSE_Sign1 and COSE_Key. ASSUMPTION a device must
// confirm (hardware-device-checklist item 6): the protected header names the
// blake2b-224 hash of the signing key as its address, which for a pool cold key
// is the pool id, and the payload is embedded as given (hashed with --hashed).
func messageSign(f flags) {
	// SPO-15-EXT-004: message sign --message-hex M --signing-path-hwsfile F --out-file O
	only(f, "--message-hex", "--signing-path-hwsfile", "--out-file", "--hashed")
	k, pub := keyOf(f.one("--signing-path-hwsfile"))
	msg, _ := hex.DecodeString(f.one("--message-hex"))
	hashed := len(f["--hashed"]) > 0
	payload := cose.PayloadFor(msg, hashed)
	signed := payload
	switch cfg.Misbehave {
	case "msgwrongpayload":
		payload = append([]byte(nil), payload...)
		payload[0] ^= 1
	case "msgbadsig":
		other := sha256.Sum256(payload)
		signed = other[:]
	case "msgwrongkey":
		k, pub = otherKey(pub)
	}
	addr := cose.Blake2b224(pub)
	addrBytes := addr[:]
	switch cfg.Misbehave {
	case "msgaddr":
		addrBytes = bytes.Repeat([]byte{1}, 28)
	case "msgwrongkey":
		// the tool signs and names its other key; the address follows that key
	}
	protected := cose.ProtectedHeader(addrBytes)
	sig := ed25519.Sign(k, cose.SigStructure(protected, signed))
	s1 := cose.Sign1{Protected: protected, Hashed: hashed, Payload: payload, Signature: sig}.Encode()
	key := cose.EncodeKey(pub)
	sign1Hex := hex.EncodeToString(s1)
	if cfg.Misbehave == "msgtruncated" {
		sign1Hex = sign1Hex[:20]
	}
	writeJSON(f.one("--out-file"), map[string]string{"COSE_Sign1_hex": sign1Hex, "COSE_Key_hex": hex.EncodeToString(key)})
}

func voteRegistration(f flags) {
	// SPO-09a-EXT-004: vote registration-metadata --vote-public-key-string V
	// --vote-weight W (repeated) --payment-address A --nonce N <network>
	// [--payment-address-signing-key-hwsfile P] --stake-signing-key-hwsfile S
	// --metadata-cbor-out-file O
	only(f, "--vote-public-key-string", "--vote-weight", "--payment-address", "--nonce", "--mainnet", "--testnet-magic",
		"--payment-address-signing-key-hwsfile", "--stake-signing-key-hwsfile", "--metadata-cbor-out-file", "--voting-purpose")
	network(f)
	if len(f["--vote-public-key-string"]) != len(f["--vote-weight"]) || len(f["--vote-public-key-string"]) == 0 {
		fmt.Println("ERROR: one --vote-weight for each --vote-public-key-string")
		os.Exit(1)
	}
	k, pub := keyOf(f.one("--stake-signing-key-hwsfile"))
	if cfg.Misbehave == "votewrongkey" {
		k, pub = otherKey(pub)
	}
	var reg cose.Cip36
	copy(reg.StakePub[:], pub)
	for i, v := range f["--vote-public-key-string"] {
		_, data, err := chain.Bech32Decode(v)
		if err != nil || len(data) != 32 {
			fmt.Println("ERROR: bad vote key")
			os.Exit(1)
		}
		var d cose.Delegation
		copy(d.VotePub[:], data)
		fmt.Sscan(f["--vote-weight"][i], &d.Weight)
		reg.Delegations = append(reg.Delegations, d)
	}
	_, addr, err := chain.Bech32Decode(f.one("--payment-address"))
	if err != nil {
		fmt.Println("ERROR: bad address")
		os.Exit(1)
	}
	reg.Address = addr
	fmt.Sscan(f.one("--nonce"), &reg.Nonce)
	if p := f["--voting-purpose"]; len(p) > 0 {
		fmt.Sscan(p[0], &reg.Purpose)
	}
	if p := f["--payment-address-signing-key-hwsfile"]; len(p) > 0 {
		// The device takes the payment key to recognise the rewards address as its own.
		_, ppub := keyOf(p[0])
		h := cose.Blake2b224(ppub)
		if len(addr) < 29 || !bytes.Equal(addr[1:29], h[:]) {
			fmt.Println("ERROR: the payment signing key is not the payment key of the address")
			os.Exit(1)
		}
	}
	if cfg.Misbehave == "votewrongaddr" {
		reg.Address = append([]byte(nil), reg.Address...)
		reg.Address[1] ^= 1
	}
	h := reg.SigningHash()
	sig := ed25519.Sign(k, h[:])
	if cfg.Misbehave == "votebadsig" {
		other := sha256.Sum256(h[:])
		sig = ed25519.Sign(k, other[:])
	}
	out := reg.Metadata(sig)
	if cfg.Misbehave == "votetruncated" {
		out = out[:len(out)/2]
	}
	os.WriteFile(f.one("--metadata-cbor-out-file"), out, 0o600)
}

// tagInputs gives key 0 of the body (the inputs) the tag-258 set form when it
// is a plain array. A body that is not a 4-array with a small map is returned
// as it is.
func tagInputs(cbor []byte) []byte {
	if len(cbor) < 8 || cbor[0] != 0x84 {
		return cbor
	}
	hdr := 2
	switch {
	case cbor[1]&0xe0 == 0xa0 && cbor[1]&0x1f < 24:
	case cbor[1] == 0xb8:
		hdr = 3
	default:
		return cbor
	}
	if cbor[hdr] != 0x00 || cbor[hdr+1]&0xe0 != 0x80 {
		return cbor // already tagged, or not the shape this fake knows
	}
	out := append([]byte(nil), cbor[:hdr+1]...)
	out = append(out, 0xd9, 0x01, 0x02)
	return append(out, cbor[hdr+1:]...)
}
