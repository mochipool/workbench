package archtest

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// The relay's stored bytes are sealed envelopes it cannot open, so the code that
// stores them, the code that reads its configuration and the ports between them
// must not have anything that opens one in their import closure: not the age
// library, not the envelope adapter, not a database, not the secret buffers.
// The closure is listed by the go tool, so a package reached through a port
// counts (a direct-import check would miss it).
//
// The binding and revoke statements (ADR 0014) are linked by the relay too, so
// their domain package is in the list.
//
// spec: SPO-Xmailbox-SEC-009, SPO-Xrelaybind-INV-001

var relayPackages = []string{
	module + "/internal/domain/relaybind",
	module + "/internal/domain/relayregistry",
	module + "/internal/domain/relayconf",
	module + "/internal/adapters/mailboxstore",
	module + "/internal/adapters/bindingstore",
	module + "/internal/adapters/relayconfig",
	module + "/internal/ports/relayport",
	module + "/internal/app/relay",
	module + "/internal/app/relayhost",
	// cmd/spo-relay links the tunnel adapter, whose transport crypto is allowed
	// below it only: the binary is a root of the tunnel rule
	// (tunnel_closure_test.go) and of TestTheRelayBinaryLinksNoSignerWalletStoreOrCommandLine.
}

// relayBinaryBans are what the relay binary must not link beyond relayBanned
// (SPO-Xmailbox-SEC-078): nothing that signs with a wallet or a party key or
// holds a wallet, nothing that reads or decrypts the workspace store, no command
// line of the spo tool and no mailbox client.
var relayBinaryBans = []string{
	"/internal/adapters/native",
	"/internal/adapters/hwcli",
	"/internal/adapters/fido2cli",
	"/internal/adapters/gpg",
	"/internal/adapters/envelope",
	"/internal/adapters/sqlitestore",
	"/internal/adapters/vaultkms", // the unlock backends: the relay links no store encryption
	"/internal/adapters/partystore",
	"/internal/adapters/cli",
	"/internal/adapters/tui",
	"/internal/adapters/mailbox",
	"/internal/app/relaybinding",
	"/internal/app/relayself",
	"/internal/app/multisig",
	"/internal/domain/relaywallet",
	"/internal/domain/unlock",
	"/internal/platform/seal",
	"/internal/platform/secret",
	"/internal/ports", // the workspace ports (they hold secret buffers); relayport is allowed below
	"github.com/spf13/cobra",
	"filippo.io/age",
}

// The relay binary and its assembly link nothing that signs, holds a wallet,
// opens the workspace or is the spo command line.
//
// spec: SPO-Xmailbox-SEC-078
func TestTheRelayBinaryLinksNoSignerWalletStoreOrCommandLine(t *testing.T) {
	for _, root := range []string{module + "/cmd/spo-relay", module + "/internal/app/relayhost"} {
		set := depsOf(t, root)
		if !set[root] || len(set) < 20 {
			t.Fatalf("a closure of %d packages is not a listing", len(set))
		}
		for dep := range set {
			for _, b := range relayBinaryBans {
				hit := strings.Contains(dep, b)
				if b == "/internal/ports" {
					hit = dep == module+"/internal/ports"
				}
				if b == "/internal/adapters/mailbox" {
					hit = dep == module+"/internal/adapters/mailbox"
				}
				if hit {
					t.Errorf("%s reaches %s (banned for the relay binary: %s)", root, dep, b)
				}
			}
		}
	}
	// the list bites: the spo tool's main reaches several of them
	set := depsOf(t, module+"/cmd/spo")
	for _, must := range []string{module + "/internal/adapters/native", module + "/internal/adapters/cli", module + "/internal/ports"} {
		if !set[must] {
			t.Errorf("the bite check: cmd/spo does not reach %s", must)
		}
	}
}

// relayBanned are the import-path fragments no one of the packages above
// may reach: the hard bans and the primitive bans of tunnel_closure_test.go,
// which states the rule for the whole relay side, the tunnel adapter included.
var relayBanned = slices.Concat(relayHardBans, relayPrimitiveBans)

// bannedBy returns the banned fragment that dep contains, or "".
func bannedBy(dep string) string { return banOf(dep, relayBanned) }

// The banned list bites what it names and spares what the relay needs (ed25519
// verification, blake2b ids, crypto/rand).
//
// spec: SPO-Xmailbox-SEC-009
func TestRelayBannedListBitesWhatItNames(t *testing.T) {
	for _, dep := range []string{
		"crypto/ecdh", "golang.org/x/crypto/curve25519", "crypto/hpke", "crypto/mlkem", "crypto/hkdf",
		"golang.org/x/crypto/hkdf", "golang.org/x/crypto/nacl/box", "golang.org/x/crypto/nacl/secretbox", "golang.org/x/crypto/nacl/sign",
		"golang.org/x/crypto/chacha20poly1305", "filippo.io/age", module + "/internal/domain/unlock",
	} {
		if bannedBy(dep) == "" {
			t.Errorf("%s is not banned", dep)
		}
	}
	for _, dep := range []string{
		"crypto/ed25519", "crypto/rand", "golang.org/x/crypto/blake2b", "crypto/sha256",
		module + "/internal/domain/custody", module + "/internal/domain/party",
	} {
		if b := bannedBy(dep); b != "" {
			t.Errorf("%s is banned by %q, but the relay links it", dep, b)
		}
	}
}

// depsOf lists the non-test import closure of pkgs, standard library included.
func depsOf(t *testing.T, pkgs ...string) map[string]bool {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("the go tool is absent")
	}
	args := append([]string{"list", "-deps", "-test=false", "-json=ImportPath"}, pkgs...)
	out, err := exec.Command("go", args...).Output()
	if err != nil {
		t.Fatalf("go list failed, so the rule cannot be checked (this is a failure, not a skip): %v", err)
	}
	set := map[string]bool{}
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for dec.More() {
		var p depPkg
		if err := dec.Decode(&p); err != nil {
			t.Fatal(err)
		}
		set[p.ImportPath] = true
	}
	return set
}

func TestRelayPackagesReachNothingThatCouldOpenAnEnvelope(t *testing.T) {
	for _, p := range relayPackages {
		t.Run(strings.TrimPrefix(p, module+"/"), func(t *testing.T) {
			set := depsOf(t, p)
			if !set[p] {
				t.Fatalf("%s is not in its own closure", p)
			}
			if len(set) < 5 {
				t.Fatalf("a closure of %d packages is not a listing", len(set))
			}
			for dep := range set {
				if b := bannedBy(dep); b != "" {
					t.Errorf("%s reaches %s (banned: %s)", p, dep, b)
				}
			}
		})
	}
}

func parseNonTest(t *testing.T, dir string) []*ast.File {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi fs.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, p := range pkgs {
		for _, f := range p.Files {
			files = append(files, f)
		}
	}
	if len(files) == 0 {
		t.Fatalf("no Go files in %s", dir)
	}
	return files
}

func mentions(fl *ast.FieldList, typ string) bool {
	if fl == nil {
		return false
	}
	found := false
	for _, f := range fl.List {
		ast.Inspect(f.Type, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == typ {
				found = true
			}
			return true
		})
	}
	return found
}

// A device-signed revoke reaches the registry only as a
// relaybind.VerifiedDeviceRevoke, which only VerifyDeviceRevoke makes: no other
// function of relaybind returns the type, no code outside VerifyDeviceRevoke
// fills one, its fields are unexported, and the registry's only constructors of a
// RevokeRecord are WalletRevoke (from a VerifiedRevoke) and DeviceRevoke (from a
// VerifiedDeviceRevoke). Together with the compiler (a type with unexported
// fields cannot be built outside its package) this is what "the registry accepts
// only the verified type" rests on.
//
// spec: SPO-Xmailbox-SEC-062
func TestVerifiedDeviceRevokeIsMadeOnlyByItsVerification(t *testing.T) {
	var makers []string
	for _, f := range parseNonTest(t, "../domain/relaybind") {
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if mentions(d.Type.Results, "VerifiedDeviceRevoke") {
					makers = append(makers, d.Name.Name)
				}
				ast.Inspect(d, func(n ast.Node) bool {
					if cl, ok := n.(*ast.CompositeLit); ok {
						if id, ok := cl.Type.(*ast.Ident); ok && id.Name == "VerifiedDeviceRevoke" && len(cl.Elts) > 0 && d.Name.Name != "VerifyDeviceRevoke" {
							t.Errorf("%s fills a VerifiedDeviceRevoke; only VerifyDeviceRevoke may", d.Name.Name)
						}
					}
					return true
				})
			case *ast.GenDecl:
				for _, s := range d.Specs {
					ts, ok := s.(*ast.TypeSpec)
					if !ok || ts.Name.Name != "VerifiedDeviceRevoke" {
						continue
					}
					st, ok := ts.Type.(*ast.StructType)
					if !ok {
						t.Fatal("VerifiedDeviceRevoke is not a struct")
					}
					for _, fl := range st.Fields.List {
						for _, n := range fl.Names {
							if n.IsExported() {
								t.Errorf("VerifiedDeviceRevoke has the exported field %s", n.Name)
							}
						}
					}
				}
			}
		}
	}
	if !slices.Equal(makers, []string{"VerifyDeviceRevoke"}) {
		t.Errorf("functions of relaybind that return a VerifiedDeviceRevoke: %v, want only VerifyDeviceRevoke", makers)
	}
	got := map[string]bool{}
	for _, f := range parseNonTest(t, "../domain/relayregistry") {
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.IsExported() && mentions(fd.Type.Results, "RevokeRecord") {
				got[fd.Name.Name] = true
				if fd.Name.Name == "DeviceRevoke" && !mentions(fd.Type.Params, "VerifiedDeviceRevoke") {
					t.Errorf("DeviceRevoke does not take a VerifiedDeviceRevoke")
				}
			}
		}
	}
	if len(got) != 2 || !got["WalletRevoke"] || !got["DeviceRevoke"] {
		t.Errorf("exported functions of relayregistry that return a RevokeRecord: %v, want WalletRevoke and DeviceRevoke", got)
	}
}

// The closure of the relay ports (and of their test-support package) stays within
// {mailbox, party, relaybind, relayregistry, cose} of this module, plus the ports
// themselves and the standard library: the whole transitive closure is listed by
// the go tool, so a package reached through one of those counts (a check of the
// direct imports alone would miss it). The third-party packages the closure may
// reach are the relay's own (see TestRelayPackagesReachNothingThatCouldOpenAnEnvelope).
//
// spec: SPO-Xmailbox-SEC-016
func TestRelayPortsClosureStaysWithinTheRegistryDomains(t *testing.T) {
	ok := map[string]bool{
		module + "/internal/domain/mailbox":                true,
		module + "/internal/domain/party":                  true,
		module + "/internal/domain/relaybind":              true,
		module + "/internal/domain/relayregistry":          true,
		module + "/internal/domain/cose":                   true,
		module + "/internal/ports/relayport":               true,
		module + "/internal/ports/relayport/relayporttest": true,
	}
	roots := []string{module + "/internal/ports/relayport", module + "/internal/ports/relayport/relayporttest"}
	// 1. what the ports (and their test support) import themselves: only the five
	n := 0
	for _, p := range load(t) {
		if p.ImportPath != roots[0] && p.ImportPath != roots[1] {
			continue
		}
		n++
		for _, imp := range p.Imports {
			if strings.HasPrefix(imp, module+"/") && !ok[imp] {
				t.Errorf("%s imports %s, which is not one of mailbox, party, relaybind, relayregistry, cose", p.ImportPath, imp)
			}
		}
	}
	if n != 2 {
		t.Fatalf("found %d of the 2 relay port packages", n)
	}
	// 2. the transitive closure: nothing of this module but those five, the ports
	// and the pure domain packages THEY import (identity, chain and custody are
	// reached through party, mailbox and relaybind; they are domains, with no I/O).
	// No adapter, app or other port is ever in it.
	set := depsOf(t, roots...)
	for _, r := range roots {
		if !set[r] {
			t.Fatalf("%s is not in its own closure", r)
		}
	}
	for dep := range set {
		if strings.HasPrefix(dep, module+"/") && !ok[dep] && !strings.HasPrefix(dep, module+"/internal/domain/") {
			t.Errorf("the relay ports' closure reaches %s, which is neither one of the five domains nor a pure domain package", dep)
		}
	}
}
