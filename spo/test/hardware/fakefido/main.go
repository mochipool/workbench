// Command fakefido is a stand-in for the libfido2 command-line tools fido2-token,
// fido2-cred and fido2-assert, for tests without an authenticator (ADR 0011,
// decision 9). It is one program: it acts as the tool named by the base name it
// is started under, so a test links it three times (fido2-token, fido2-cred,
// fido2-assert) into a temporary directory.
//
// It speaks the interface of the tools as far as adapters/fido2cli uses it
// (man pages and source of libfido2 1.16.0): the input lines of -M and -G, the
// output lines, -h, -c, -v, -p, -q, -t up|uv|pin=, -i, -o, `fido2-token -L`,
// `-I` and `-V`. What a real authenticator does under those options can only be
// confirmed on a device.
//
// It is driven by the JSON file named in FAKEFIDO_CONFIG, and appends one JSON
// line per invocation to the file's "log": the tool, its argument vector, the
// number of bytes it read from standard input (never their content) and whether
// it runs as the leader of its own session (no controlling terminal).
//
// hmac-secret: the credential has two secrets, one for assertions that are user
// verified and one for assertions that are not (CTAP 2.1, section 12.5), both
// HMAC-SHA-256 of the credential id under the seed; the output for a salt is
// HMAC-SHA-256(secret, salt). The credential id is a nonce and a tag over the
// nonce and the relying-party id, so a credential id for another relying party
// or another seed is "not held" (FIDO_ERR_NO_CREDENTIALS). With credProtect 3 an
// assertion that is not user verified finds no credential, as CTAP 2.1 says.
//
// Misbehaviour, set by "misbehave":
//
//	noUVFlag        user verification happens but the UV flag is clear
//	noUVFlagEnrol   the credential is made but its UV flag is clear
//	noUPFlag        the answer to a request for presence has the UP flag clear
//	otherSecret     the output is the one of the non-verified secret
//	credProtect     the credential confirms credProtect level 1
//	wrongCredential every assertion finds no credential
//	noExtension     no hmac-secret in the answer: the real tool ends with
//	                "output error" (assert_get.c, base64.c) and prints nothing
//	probeTimeout    an assertion with up=false ends with FIDO_ERR_ACTION_TIMEOUT
//	bigInfo         fido2-token -I prints 200 KiB first (a finite flood)
//	noneAttestation fido2-cred ends with "output error" (empty signature)
//	timeout         the tool exits with FIDO_ERR_ACTION_TIMEOUT
//	hang            the tool sleeps for a minute (a deadline must stop it)
//	noTouch         an assertion with up=false returns an output (the probe)
//	shortOutput     the hmac secret is one byte short
//	sameOutputs     with two salts both halves are equal
//	noEnrolHMAC     the credential does not carry the hmac-secret extension
package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

type config struct {
	Seed string `json:"seed"`
	// Devices are the paths `fido2-token -L` lists and the tools accept.
	Devices []string `json:"devices"`
	// PIN is the authenticator's PIN; empty means it has none.
	PIN string `json:"pin"`
	// Pins gives a device its own PIN (by device path); a device not listed has PIN.
	Pins map[string]string `json:"pins"`
	// Options are the getInfo options as `fido2-token -I` prints them (a false
	// option has the prefix "no"): "clientPin" means a PIN is set, "uv" that
	// built-in verification is configured. Default: rk, up, plat, clientPin.
	Options []string `json:"options"`
	// Versions and Extensions are what `fido2-token -I` prints.
	Versions   []string `json:"versions"`
	Extensions []string `json:"extensions"`
	// CredProtect is the level the authenticator confirms; default 3.
	CredProtect *int `json:"credProtect"`
	// TouchEnforced: an assertion with up=false is refused. Default true.
	TouchEnforced *bool  `json:"touchEnforced"`
	Misbehave     string `json:"misbehave"`
	Log           string `json:"log"`
}

var (
	cfg   config
	tool  string
	stdin int // bytes read from standard input
)

func main() {
	tool = filepath.Base(os.Args[0])
	raw, err := os.ReadFile(os.Getenv("FAKEFIDO_CONFIG"))
	if err != nil || json.Unmarshal(raw, &cfg) != nil {
		if tool == "fido2-token" && len(os.Args) == 2 && os.Args[1] == "-V" {
			fmt.Fprintln(os.Stderr, "1.16.0") // the real tool prints its version on stderr
			return
		}
		fail("no FAKEFIDO_CONFIG")
	}
	defer logCall()
	switch tool {
	case "fido2-token":
		token(os.Args[1:])
	case "fido2-cred":
		cred(os.Args[1:])
	case "fido2-assert":
		assert(os.Args[1:])
	default:
		fail("unknown tool " + tool)
	}
}

func logCall() {
	if cfg.Log == "" {
		return
	}
	f, err := os.OpenFile(cfg.Log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	leader := sessionLeader()
	line, _ := json.Marshal(map[string]any{
		"tool": tool, "argv": os.Args[1:], "stdinBytes": stdin, "sessionLeader": leader,
	})
	fmt.Fprintf(f, "%s\n", line)
}

func fail(msg string) {
	fmt.Fprintf(os.Stderr, "%s: %s\n", tool, msg)
	logCall()
	os.Exit(1)
}

// mis reports whether a misbehave mode is set; several may be listed, comma separated.
func mis(m string) bool { return strings.Contains(","+cfg.Misbehave+",", ","+m+",") }

// options parsed from the argument vector, as getopt would.
type opts struct {
	flags  map[byte]bool
	values map[byte][]string
	rest   []string
}

func parse(args []string, withValue string) opts {
	o := opts{flags: map[byte]bool{}, values: map[byte][]string{}}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) < 2 || a[0] != '-' {
			o.rest = append(o.rest, a)
			continue
		}
		c := a[1]
		if strings.IndexByte(withValue, c) >= 0 {
			if i+1 >= len(args) {
				fail("missing option argument")
			}
			i++
			o.values[c] = append(o.values[c], args[i])
		}
		o.flags[c] = true
	}
	return o
}

func (o opts) toggle(key string) (val, set bool) {
	for _, t := range o.values['t'] {
		k, v, ok := strings.Cut(t, "=")
		if !ok || (v != "true" && v != "false") {
			fail("invalid assignment '" + t + "'")
		}
		if k == key {
			val, set = v == "true", true
		}
	}
	return
}

func (c config) credProtect() int {
	if mis("credProtect") {
		return 1
	}
	if c.CredProtect != nil {
		return *c.CredProtect
	}
	return 3
}

func (c config) touchEnforced() bool {
	if mis("noTouch") {
		return false
	}
	return c.TouchEnforced == nil || *c.TouchEnforced
}

func hasDevice(d string) bool {
	for _, x := range cfg.Devices {
		if x == d {
			return true
		}
	}
	return false
}

// curDev is the device the running tool opened; checkPIN compares with its PIN.
var curDev string

func openDev(d string) {
	if !hasDevice(d) {
		fail("fido_dev_open " + d + ": FIDO_ERR_INTERNAL")
	}
	curDev = d
}

// devicePIN is the PIN of the device the tool opened.
func devicePIN() string {
	if p, ok := cfg.Pins[curDev]; ok {
		return p
	}
	return cfg.PIN
}

func token(args []string) {
	o := parse(args, "ikn")
	switch {
	case o.flags['V']:
		fmt.Fprintln(os.Stderr, "1.16.0")
	case o.flags['L']:
		for _, d := range cfg.Devices {
			fmt.Printf("%s: vendor=0x1050, product=0x0407 (Fake Authenticator)\n", d)
		}
	case o.flags['I']:
		if len(o.rest) != 1 {
			fail("usage")
		}
		openDev(o.rest[0])
		if mis("bigInfo") {
			fmt.Println(strings.Repeat("x", 200<<10)) // finite: over the adapter's bound
		}
		fmt.Printf("proto: 0x02\nmajor: 0x05\nminor: 0x04\nbuild: 0x03\ncaps: 0x05 (wink, cbor)\n")
		fmt.Printf("version strings: %s\n", strings.Join(cfg.Versions, ", "))
		fmt.Printf("extension strings: %s\n", strings.Join(cfg.Extensions, ", "))
		fmt.Printf("options: %s\n", strings.Join(optionsList(), ", "))
		fmt.Printf("transport strings: usb\npin retries: 8\n")
	default:
		fail("usage")
	}
}

// input reads the lines of -i or standard input.
func input(o opts) []string {
	var r io.Reader = os.Stdin
	if p := o.values['i']; len(p) > 0 && p[0] != "-" {
		f, err := os.Open(p[0])
		if err != nil {
			fail("open " + p[0])
		}
		defer f.Close()
		r = f
	}
	b, err := io.ReadAll(r)
	if err != nil {
		fail("input error")
	}
	if o.values['i'] == nil {
		stdin += len(b)
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

func out(o opts) io.WriteCloser {
	if p := o.values['o']; len(p) > 0 && p[0] != "-" {
		f, err := os.OpenFile(p[0], os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			fail("open " + p[0])
		}
		return f
	}
	return nopCloser{os.Stdout}
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

func b64d(s string) []byte {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		fail("input error")
	}
	return b
}

func mac(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

func seed() []byte { return []byte(cfg.Seed) }

func credID(rpID string, userID []byte) []byte {
	nonce := mac(seed(), []byte("nonce"), []byte(rpID), userID)
	return append(nonce, mac(seed(), []byte("cred"), nonce, []byte(rpID))[:16]...)
}

func credValid(rpID string, id []byte) bool {
	if len(id) != 48 {
		return false
	}
	return hmac.Equal(id[32:], mac(seed(), []byte("cred"), id[:32], []byte(rpID))[:16])
}

func secretFor(id []byte, uv bool) []byte {
	label := "nouv"
	if uv {
		label = "uv"
	}
	return mac(seed(), []byte("hmac-secret/"+label), id)
}

// readPIN reads the PIN line as readpassphrase does without a terminal. The
// fake has no terminal path; a test that needs the tool to find none reads
// sessionLeader from the log.
func readPIN() string {
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	stdin += len(line)
	return strings.TrimRight(line, "\r\n")
}

func optionsList() []string {
	if cfg.Options == nil {
		return []string{"rk", "up", "plat", "clientPin"}
	}
	return cfg.Options
}

func hasOpt(o string) bool {
	for _, x := range optionsList() {
		if x == o {
			return true
		}
	}
	return false
}

// checkPIN reads the PIN line and compares it, as the tool's prompt and the
// authenticator do.
func checkPIN(what string) {
	pin := readPIN()
	if len(pin) < 4 || len(pin) > 63 {
		fail("invalid PIN length")
	}
	if pin != devicePIN() {
		fail(what + ": FIDO_ERR_PIN_INVALID")
	}
}

// credVerify models fido2-cred (cred_make.c, libfido2 1.16.0 and 1.17.0). With
// -v the request carries uv=true and the tool tries without a PIN first: an
// authenticator with built-in verification (option uv) verifies; one without it
// refuses the option (the error name is the device's; INVALID_OPTION here), and
// the tool never reaches its PIN prompt, which is only for PIN_REQUIRED. Without
// -v a PIN-protected authenticator answers PIN_REQUIRED and the tool prompts
// (unless -q). It returns whether the credential is user verified.
func credVerify(o opts) bool {
	if o.flags['v'] {
		if !hasOpt("uv") {
			fail("fido_dev_make_cred: FIDO_ERR_INVALID_OPTION")
		}
		return true
	}
	if hasOpt("clientPin") {
		if o.flags['q'] {
			fail("fido_dev_make_cred: FIDO_ERR_PIN_REQUIRED")
		}
		checkPIN("fido_dev_make_cred")
		return true
	}
	return false
}

// assertVerify models fido2-assert: pin=true (-v) prompts and sends the PIN;
// uv=true without a PIN uses built-in verification, which a PIN-only
// authenticator lacks.
func assertVerify(uvWant, pinWant bool) bool {
	switch {
	case pinWant:
		if !hasOpt("clientPin") {
			fail("fido_dev_get_assert: FIDO_ERR_PIN_NOT_SET")
		}
		checkPIN("fido_dev_get_assert")
		return true
	case uvWant:
		if !hasOpt("uv") {
			fail("fido_dev_get_assert: FIDO_ERR_PIN_REQUIRED")
		}
		return true
	}
	return false
}

func cred(args []string) {
	o := parse(args, "aciot")
	if !o.flags['M'] || len(o.rest) < 1 {
		fail("usage")
	}
	lines := input(o)
	if len(lines) != 4 {
		fail("input error")
	}
	rpID, userID := lines[1], b64d(lines[3])
	b64d(lines[0])
	openDev(o.rest[0])
	if up, set := o.toggle("up"); set && !up {
		fail("unsupported toggle: 'up=false'")
	}
	if mis("hang") {
		time.Sleep(time.Minute)
	}
	if mis("timeout") {
		fail("fido_dev_make_cred: FIDO_ERR_ACTION_TIMEOUT")
	}
	if mis("noneAttestation") {
		// print_attcred base64-encodes an empty signature, which fails (base64.c:
		// ptr == NULL), so the real tool ends with "output error" and prints nothing.
		fail("output error")
	}
	uv := credVerify(o)
	if mis("noUVFlagEnrol") {
		uv = false // the credential is made verified but the flag is clear
	}
	id := credID(rpID, userID)

	flags := byte(flagUP | flagAT)
	if uv {
		flags |= flagUV
	}
	ext := map[string]any{}
	if o.flags['c'] {
		ext["credProtect"] = cfg.credProtect()
	}
	if o.flags['h'] && !mis("noEnrolHMAC") && !mis("noExtension") {
		ext["hmac-secret"] = true
	}
	if len(ext) > 0 {
		flags |= flagED
	}
	h := sha256.Sum256([]byte(rpID))
	ad := append(h[:], flags, 0, 0, 0, 0)
	ad = append(ad, make([]byte, 16)...) // aaguid
	ad = binary.BigEndian.AppendUint16(ad, uint16(len(id)))
	ad = append(ad, id...)
	key, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: make([]byte, 32), -3: make([]byte, 32)})
	ad = append(ad, key...)
	if len(ext) > 0 {
		e, _ := cbor.Marshal(ext)
		ad = append(ad, e...)
	}
	w := out(o)
	defer w.Close()
	fmt.Fprintf(w, "%s\n%s\n%s\n%s\n%s\n%s\n", lines[0], rpID, "packed", wrap(ad), b64(id), b64([]byte("sig")))
}

const (
	flagUP = 1
	flagUV = 4
	flagAT = 0x40
	flagED = 0x80
)

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// wrap is the CBOR byte string around the raw authenticator data.
func wrap(ad []byte) string {
	b, _ := cbor.Marshal(ad)
	return b64(b)
}

func assert(args []string) {
	o := parse(args, "iot")
	if !o.flags['G'] || len(o.rest) != 1 {
		fail("usage")
	}
	lines := input(o)
	want := 3
	if o.flags['h'] {
		want = 4
	}
	if len(lines) != want {
		fail("input error")
	}
	rpID, id := lines[1], b64d(lines[2])
	var salt []byte
	if o.flags['h'] {
		salt = b64d(lines[3])
		if len(salt) != 32 && len(salt) != 64 {
			fail("fido_assert_set_hmac_salt: FIDO_ERR_INVALID_ARGUMENT")
		}
	}
	openDev(o.rest[0])
	if mis("hang") {
		time.Sleep(time.Minute)
	}
	if mis("timeout") {
		fail("fido_dev_get_assert: FIDO_ERR_ACTION_TIMEOUT")
	}
	up := true
	if v, set := o.toggle("up"); set {
		up = v
	}
	if o.flags['p'] {
		up = true
	}
	uvWant, _ := o.toggle("uv")
	pinWant, _ := o.toggle("pin")
	if o.flags['v'] {
		uvWant, pinWant = true, true
	}
	// libfido2 obtains the PIN token (and the authenticator refuses a wrong PIN)
	// before the assertion looks for the credential.
	uv := assertVerify(uvWant, pinWant)
	if !credValid(rpID, id) || mis("wrongCredential") {
		fail("fido_dev_get_assert: FIDO_ERR_NO_CREDENTIALS")
	}
	if cfg.credProtect() >= 3 && !uv {
		// credProtect 3: the credential is invisible to an assertion without verification
		fail("fido_dev_get_assert: FIDO_ERR_NO_CREDENTIALS")
	}
	if !up && mis("probeTimeout") {
		fail("fido_dev_get_assert: FIDO_ERR_ACTION_TIMEOUT")
	}
	if !up && cfg.touchEnforced() {
		fail("fido_dev_get_assert: FIDO_ERR_UP_REQUIRED")
	}

	flags := byte(0)
	if up && !mis("noUPFlag") {
		flags |= flagUP
	}
	if uv && !mis("noUVFlag") {
		flags |= flagUV
	}
	h := sha256.Sum256([]byte(rpID))
	withHMAC := o.flags['h'] && !mis("noExtension")
	if o.flags['h'] && !withHMAC {
		// no hmac secret came back: print_assert cannot encode it and the real tool
		// ends with "output error" before it prints anything.
		fail("output error")
	}
	if withHMAC {
		flags |= flagED
	}
	ad := append(h[:], flags, 0, 0, 0, 1)
	if withHMAC {
		// the authenticator's extension output: the encrypted hmac-secret
		e, _ := cbor.Marshal(map[string][]byte{"hmac-secret": make([]byte, 16*len(salt)/32*2)})
		ad = append(ad, e...)
	}
	w := out(o)
	defer w.Close()
	fmt.Fprintf(w, "%s\n%s\n%s\n%s\n", lines[0], rpID, wrap(ad), b64([]byte("sig")))
	if withHMAC {
		sec := secretFor(id, uv)
		if mis("otherSecret") {
			sec = secretFor(id, !uv)
		}
		var res []byte
		for i := 0; i < len(salt); i += 32 {
			half := mac(sec, salt[i:i+32])
			if mis("sameOutputs") && i == 32 {
				half = res[:32]
			}
			res = append(res, half...)
		}
		if mis("shortOutput") {
			res = res[:len(res)-1]
		}
		fmt.Fprintf(w, "%s\n", b64(res))
	}
}

// sessionLeader reports whether this process leads its own session, which is
// what a child started without a controlling terminal is (Linux: /proc).
func sessionLeader() bool {
	b, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return false
	}
	f := strings.Fields(string(b[strings.LastIndexByte(string(b), ')')+1:]))
	// after the command name: state ppid pgrp session ...
	return len(f) > 3 && f[3] == fmt.Sprint(os.Getpid())
}
