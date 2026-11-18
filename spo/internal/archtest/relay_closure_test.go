package archtest

import (
	"encoding/json"
	"os/exec"
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
// spec: SPO-Xmailbox-SEC-009

var relayPackages = []string{
	module + "/internal/adapters/mailboxstore",
	module + "/internal/adapters/relayconfig",
	module + "/internal/ports/relayport",
	module + "/internal/app/relay",
}

// relayBanned are the import-path fragments no relay package may reach.
var relayBanned = []string{
	"filippo.io/age",
	"/internal/adapters/envelope",
	"/internal/adapters/sqlitestore",
	"modernc.org/sqlite",
	"/internal/platform/secret",
	"github.com/awnumar/memguard",
	"golang.org/x/crypto/chacha20poly1305",
	"/internal/domain/unlock",
	// key agreement, key encapsulation, key derivation and authenticated
	// encryption: what an envelope is opened with, or a tunnel is keyed with
	"crypto/ecdh",
	"golang.org/x/crypto/curve25519",
	"crypto/hpke",
	"crypto/mlkem",
	"crypto/hkdf",
	"golang.org/x/crypto/hkdf",
	"golang.org/x/crypto/nacl", // every package below it
}

// bannedBy returns the banned fragment that dep contains, or "".
func bannedBy(dep string) string {
	for _, b := range relayBanned {
		if strings.Contains(dep, b) {
			return b
		}
	}
	return ""
}

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

// The relay ports import the standard library, the mailbox domain and the party
// domain, and nothing else of this module. Their test-support package likewise.
//
// spec: SPO-Xmailbox-SEC-016
func TestRelayPortsImportOnlyTheTwoDomains(t *testing.T) {
	ok := map[string]bool{
		module + "/internal/domain/mailbox": true,
		module + "/internal/domain/party":   true,
	}
	n := 0
	for _, p := range load(t) {
		if p.ImportPath != module+"/internal/ports/relayport" &&
			p.ImportPath != module+"/internal/ports/relayport/relayporttest" {
			continue
		}
		n++
		for _, imp := range p.Imports {
			if strings.HasPrefix(imp, module+"/") && !ok[imp] && imp != module+"/internal/ports/relayport" {
				t.Errorf("%s imports %s", p.ImportPath, imp)
			}
		}
	}
	if n != 2 {
		t.Fatalf("found %d of the 2 relay port packages", n)
	}
}
