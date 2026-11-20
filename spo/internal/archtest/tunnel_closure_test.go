package archtest

import (
	"encoding/json"
	"os/exec"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
)

// The relay links a tunnel library (tailcat, tailscale, gVisor, WireGuard) that
// carries its own transport crypto: key agreement, key derivation, AEAD. That
// crypto is not envelope crypto and must not be confused with it, and nothing
// else in the relay may use it. The rule has four parts, each a pure function
// over an import graph so that a synthetic graph can show it bites:
//
//  1. Hard bans over the FULL closure of every relay-side package, the tunnel
//     adapter included: the age library, the envelope adapter, the sqlite
//     driver and store, the secret buffers, memguard, the unlock domain.
//  2. Primitive bans over the import WALK from the relay-side roots that does
//     not descend into the tunnel adapter: tunnel transport crypto is allowed
//     below the tunnel adapter's import path and nowhere else. The walk is
//     made from the import lists, not from a difference of two closures: a
//     difference hides a relay package that imports a primitive directly when
//     the tunnel adapter reaches the same primitive.
//  3. An explicit allow-list of the tunnel adapter's direct imports.
//  4. The first-party importers of the tunnel libraries are an explicit list.
//
// spec: SPO-Xmailbox-SEC-009

// tunnelPkg is the tunnel adapter of the relay (ADR 0013 work package 5).
const tunnelPkg = module + "/internal/adapters/tailcat/stream"

// relayRoots are the relay-side packages. The relay main (cmd/spo-relay, a later
// work package) is one more line here.
var relayRoots = []string{
	module + "/internal/app/relay",
	module + "/internal/adapters/mailboxstore",
	module + "/internal/adapters/bindingstore",
	module + "/internal/adapters/relayconfig",
	module + "/internal/ports/relayport",
	module + "/internal/domain/mailbox",
	module + "/internal/domain/relayregistry",
	module + "/internal/domain/relayconf",
	module + "/internal/app/relayhost",
	tunnelPkg,
	module + "/cmd/spo-relay",
	// the object store (ADR 0015 work packages 2 and 6 to 10): reached from
	// cmd/spo-relay, listed so that a rename cannot leave them unchecked
	module + "/internal/adapters/objstore/s3client",
	module + "/internal/platform/sigv4",
	module + "/internal/adapters/objlease",
	module + "/internal/adapters/objmailbox",
	module + "/internal/adapters/objregistry",
	module + "/internal/adapters/webidentity",
	module + "/internal/platform/stsweb",
	module + "/internal/platform/mountfile",
}

// relayHardBans are the import-path fragments that nothing in the closure of a
// relay-side package, the tunnel adapter included, may be.
var relayHardBans = []string{
	"filippo.io/age",
	"/internal/adapters/envelope",
	"/internal/adapters/sqlitestore",
	"modernc.org/sqlite",
	"/internal/platform/secret",
	"github.com/awnumar/memguard",
	"/internal/domain/unlock",
}

// relayPrimitiveBans are the key agreement, key encapsulation, key derivation
// and authenticated encryption packages: what an envelope is opened with, and
// what the tunnel is keyed with. Only the tunnel adapter's own subtree may
// reach them.
var relayPrimitiveBans = []string{
	"crypto/ecdh",
	"crypto/hpke",
	"crypto/mlkem",
	"crypto/hkdf",
	"golang.org/x/crypto/curve25519",
	"golang.org/x/crypto/hkdf",
	"golang.org/x/crypto/chacha20poly1305",
	"golang.org/x/crypto/nacl", // every package below it
}

// importGraph maps an import path to its direct imports.
type importGraph map[string][]string

func graphOf(pkgs []depPkg) importGraph {
	g := importGraph{}
	for _, p := range pkgs {
		g[p.ImportPath] = p.Imports
	}
	return g
}

// walkImports follows the import lists from roots and returns every package it
// reached with the package it was reached from ("" for a root). It does not
// enter stop and does not return it: a package reached only through stop is not
// reached. An empty stop walks the whole closure.
func walkImports(g importGraph, roots []string, stop string) map[string]string {
	via := map[string]string{}
	var queue []string
	for _, r := range roots {
		if r == stop {
			continue
		}
		if _, seen := via[r]; !seen {
			via[r] = ""
			queue = append(queue, r)
		}
	}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		for _, imp := range g[p] {
			if imp == stop {
				continue
			}
			if _, seen := via[imp]; seen {
				continue
			}
			via[imp] = p
			queue = append(queue, imp)
		}
	}
	return via
}

func chainTo(via map[string]string, p string) string {
	var parts []string
	for ; p != ""; p = via[p] {
		parts = append(parts, p)
	}
	slices.Reverse(parts)
	return strings.Join(parts, " -> ")
}

func banOf(dep string, bans []string) string {
	for _, b := range bans {
		if strings.Contains(dep, b) {
			return b
		}
	}
	return ""
}

func banViolations(via map[string]string, bans []string) []string {
	var out []string
	for dep := range via {
		if b := banOf(dep, bans); b != "" {
			out = append(out, "reaches "+dep+" (banned: "+b+") via "+chainTo(via, dep))
		}
	}
	sort.Strings(out)
	return out
}

// missingRoots reports the roots that the graph does not contain: a root that
// was renamed or removed would otherwise make the walk empty and the rule vacuous.
func missingRoots(g importGraph, roots []string) []string {
	var out []string
	for _, r := range roots {
		if _, ok := g[r]; !ok {
			out = append(out, "root "+r+" is not in the import graph")
		}
	}
	return out
}

// hardBanViolations is part 1: the full closure of every root.
func hardBanViolations(g importGraph, roots []string) []string {
	out := missingRoots(g, roots)
	return append(out, banViolations(walkImports(g, roots, ""), relayHardBans)...)
}

// primitiveBanViolations is part 2: the walk from the roots that does not
// descend into the tunnel adapter, nor (since ADR 0015 work package 10,
// concern S22) into the standard library's TLS stack, crypto/tls and
// crypto/x509 (tlsStack), which the store client links for its connection to
// the object store and STS. Every package the walk reaches, each relay
// package's own direct imports included, is still checked: only what lies
// below those three packages and is reached through them alone is let through.
//
// What the rule does not see (the residual of the exception): it is a rule on
// imports, and values cross packages without one. crypto/x509 hands out values
// of crypto/ecdh's types (ParsePKIXPublicKey returns an *ecdh.PublicKey for an
// X25519 key; from memory of the standard library, not checked here), and
// relay code could call their methods through an interface or reflect with no
// import of crypto/ecdh, which this walk cannot tell from the TLS stack's own
// use. crypto/cipher and crypto/aes were never in relayPrimitiveBans (the list
// is key agreement, HPKE, ML-KEM, HKDF and x/crypto's curve25519,
// chacha20poly1305 and nacl), so an AES-GCM in relay code is not caught here
// either.
// Neither is checked by a cheaper honest rule (banning reflect is not one: the
// standard library uses it everywhere); review and SPO-Xmailbox-SEC-009 part 1
// (no age anywhere) cover them.
func primitiveBanViolations(g importGraph, roots []string, tunnel string) []string {
	out := missingRoots(g, roots)
	stops := map[string]bool{tunnel: true}
	for p := range tlsStack {
		stops[p] = true
	}
	return append(out, banViolations(walkStops(g, roots, stops), relayPrimitiveBans)...)
}

// walkStops is walkImports with a set of packages it neither enters nor
// returns (a root in the set included).
func walkStops(g importGraph, roots []string, stops map[string]bool) map[string]string {
	via := map[string]string{}
	var queue []string
	for _, r := range roots {
		if _, seen := via[r]; seen || stops[r] {
			continue
		}
		via[r] = ""
		queue = append(queue, r)
	}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		for _, imp := range g[p] {
			if _, seen := via[imp]; seen || stops[imp] {
				continue
			}
			via[imp] = p
			queue = append(queue, imp)
		}
	}
	return via
}

// tunnelDirectImports is part 3: the direct, non-test imports of the tunnel
// adapter. A new import fails the test until it is added here on purpose; that
// also forbids age, the envelope adapter and the secret buffers by construction.
var tunnelDirectImports = []string{
	// standard library
	"context", "crypto/rand", "errors", "fmt", "io", "net", "os", "reflect",
	"slices", "strings", "sync", "sync/atomic", "time", "unsafe",
	// the tunnel library and the packages of it the adapter uses
	"github.com/tailscale/tailcat",
	"go4.org/mem",
	"gvisor.dev/gvisor/pkg/tcpip",
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet",
	"tailscale.com/derp/derphttp",
	"tailscale.com/net/netmon",
	"tailscale.com/net/netns",
	"tailscale.com/tailcfg",
	"tailscale.com/types/key",
	"tailscale.com/wgengine/filter",
	// this module
	module + "/internal/domain/party",
	module + "/internal/domain/relayconf",
	module + "/internal/platform/tunnelenv",
	module + "/internal/ports/relayport",
}

// allowListViolations compares imports with an exact allow-list: an import that
// is not listed fails, and so does a listed entry that nothing imports (a wide
// list would let a new import through unseen).
func allowListViolations(imports, allow []string) []string {
	var out []string
	for _, imp := range imports {
		if !slices.Contains(allow, imp) {
			out = append(out, "imports "+imp+", which is not in the allow-list")
		}
	}
	for _, a := range allow {
		if !slices.Contains(imports, a) {
			out = append(out, "the allow-list names "+a+", which is not imported")
		}
	}
	sort.Strings(out)
	return out
}

// tunnelLibraries are the import-path roots of the tunnel libraries.
var tunnelLibraries = []string{
	"github.com/tailscale/tailcat",
	"github.com/tailscale/wireguard-go",
	"tailscale.com",
	"gvisor.dev",
	"golang.zx2c4.com/wireguard",
}

func isTunnelLibrary(imp string) bool {
	for _, l := range tunnelLibraries {
		if imp == l || strings.HasPrefix(imp, l+"/") {
			return true
		}
	}
	return false
}

// tunnelImporters is part 4: the first-party packages that may import a tunnel
// library, each with the imports it may use ("*": any of them).
var tunnelImporters = map[string][]string{
	module + "/internal/adapters/tailcat":        {"*"},
	module + "/internal/adapters/tailcat/stream": {"*"},
	// Existing gap, not moved yet: cmd/spo/party.go imports tailscale.com/tailcfg
	// to type its test hook `var derpRegion *tailcfg.DERPRegion` (the DERP region
	// of an in-process relay). It needs that one type and nothing else; any
	// further import, or any other importer, fails.
	module + "/cmd/spo": {"tailscale.com/tailcfg"},
}

func tunnelImporterViolations(pkgs []pkg, allowed map[string][]string) []string {
	var out []string
	for _, p := range pkgs {
		for _, imp := range p.Imports {
			if !isTunnelLibrary(imp) {
				continue
			}
			only, ok := allowed[p.ImportPath]
			switch {
			case !ok:
				out = append(out, p.ImportPath+" imports "+imp+"; only the tunnel adapters may import a tunnel library")
			case !slices.Contains(only, "*") && !slices.Contains(only, imp):
				out = append(out, p.ImportPath+" imports "+imp+"; it may import only "+strings.Join(only, ", "))
			}
		}
	}
	sort.Strings(out)
	return out
}

var (
	graphMu    sync.Mutex
	graphCache importGraph
)

// realRelayGraph lists the non-test import graph below the relay-side roots.
func realRelayGraph(t *testing.T) importGraph {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("the go tool is absent")
	}
	graphMu.Lock()
	defer graphMu.Unlock()
	if graphCache != nil {
		return graphCache
	}
	args := []string{"list", "-deps", "-test=false", "-json=ImportPath,Imports"}
	if buildTags != "" {
		args = append(args, "-tags", buildTags)
	}
	out, err := exec.Command("go", append(args, relayRoots...)...).Output()
	if err != nil {
		t.Fatalf("go list failed, so the rule cannot be checked (this is a failure, not a skip): %v", err)
	}
	var pkgs []depPkg
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for dec.More() {
		var p depPkg
		if err := dec.Decode(&p); err != nil {
			t.Fatal(err)
		}
		pkgs = append(pkgs, p)
	}
	g := graphOf(pkgs)
	if len(g) < 50 {
		t.Fatalf("a graph of %d packages is not a listing", len(g))
	}
	graphCache = g
	return g
}

// Part 1 on the real tree.
//
// spec: SPO-Xmailbox-SEC-009
func TestRelaySideReachesNoHardBannedPackage(t *testing.T) {
	g := realRelayGraph(t)
	for _, v := range hardBanViolations(g, relayRoots) {
		t.Error(v)
	}
}

// Part 2 on the real tree. Since ADR 0015 work package 10 the relay binary
// reaches crypto/tls through its store client, and the TLS stack's own key
// agreement and AEAD are what the stop set lets through: without it the walk
// fails (the bite check below).
//
// spec: SPO-Xmailbox-SEC-009
func TestRelaySideUsesNoPrimitiveOutsideTheTunnelAdapter(t *testing.T) {
	g := realRelayGraph(t)
	for _, v := range primitiveBanViolations(g, relayRoots, tunnelPkg) {
		t.Error(v)
	}
	if v := banViolations(walkImports(g, relayRoots, tunnelPkg), relayPrimitiveBans); len(v) == 0 {
		t.Error("the bite check: the walk without the TLS stop reaches no primitive, so the stop set is untested")
	}
}

// Part 3 on the real tree.
//
// spec: SPO-Xmailbox-SEC-009
func TestTunnelAdapterDirectImportsAreAllowListed(t *testing.T) {
	n := 0
	for _, p := range load(t) {
		if p.ImportPath != tunnelPkg {
			continue
		}
		n++
		for _, v := range allowListViolations(p.Imports, tunnelDirectImports) {
			t.Errorf("%s %s", p.ImportPath, v)
		}
	}
	if n != 1 {
		t.Fatalf("found %d of the tunnel adapter package", n)
	}
}

// Part 4 on the real tree.
//
// spec: SPO-Xmailbox-SEC-009
func TestTunnelLibrariesHaveTwoImporters(t *testing.T) {
	pkgs := load(t)
	if len(pkgs) < 20 {
		t.Fatalf("a listing of %d packages is not the module", len(pkgs))
	}
	for _, v := range tunnelImporterViolations(pkgs, tunnelImporters) {
		t.Error(v)
	}
}

func syntheticGraph() importGraph {
	return importGraph{
		"R": {"X", "crypto/ed25519"}, "X": {"crypto/rand"}, "crypto/ed25519": nil, "crypto/rand": nil,
		"T": {"net", "crypto/ecdh"}, "net": nil, "crypto/ecdh": nil,
	}
}

// Each part of the rule bites on a synthetic graph, and the walk catches what a
// difference of closures would hide.
//
// spec: SPO-Xmailbox-SEC-009
func TestTunnelRuleBitesOnSyntheticGraphs(t *testing.T) {
	const R, T = "R", "T"
	t.Run("a clean graph passes", func(t *testing.T) {
		g := syntheticGraph()
		if v := hardBanViolations(g, []string{R, T}); len(v) != 0 {
			t.Errorf("hard: %v", v)
		}
		if v := primitiveBanViolations(g, []string{R, T}, T); len(v) != 0 {
			t.Errorf("primitive: %v", v)
		}
	})
	t.Run("every hard ban bites, in a relay package and in the tunnel adapter", func(t *testing.T) {
		for _, b := range []string{
			"filippo.io/age", "filippo.io/age/armor", module + "/internal/adapters/envelope",
			module + "/internal/adapters/sqlitestore", "modernc.org/sqlite", "modernc.org/sqlite/lib",
			module + "/internal/platform/secret", "github.com/awnumar/memguard", module + "/internal/domain/unlock",
		} {
			viaRelay := importGraph{R: {"mid"}, "mid": {b}, b: nil, T: nil}
			if v := hardBanViolations(viaRelay, []string{R, T}); len(v) == 0 {
				t.Errorf("%s reached from a relay package passes", b)
			}
			inTunnel := importGraph{R: nil, T: {"mid"}, "mid": {b}, b: nil}
			if v := hardBanViolations(inTunnel, []string{R, T}); len(v) == 0 {
				t.Errorf("%s reached from the tunnel adapter passes", b)
			}
			// and through the tunnel adapter from a relay package that imports it
			throughTunnel := importGraph{R: {T}, T: {b}, b: nil}
			if v := hardBanViolations(throughTunnel, []string{R}); len(v) == 0 {
				t.Errorf("%s reached through the tunnel adapter passes", b)
			}
		}
	})
	primitives := []string{
		"crypto/ecdh", "crypto/hpke", "crypto/mlkem", "crypto/hkdf",
		"golang.org/x/crypto/curve25519", "golang.org/x/crypto/hkdf", "golang.org/x/crypto/chacha20poly1305",
		"golang.org/x/crypto/nacl/box", "golang.org/x/crypto/nacl/secretbox", "golang.org/x/crypto/nacl/sign",
		"vendor/golang.org/x/crypto/chacha20poly1305",
	}
	t.Run("every primitive ban bites in a relay package", func(t *testing.T) {
		for _, b := range primitives {
			direct := importGraph{R: {b}, b: nil, T: nil}
			if v := primitiveBanViolations(direct, []string{R, T}, T); len(v) == 0 {
				t.Errorf("%s imported by a relay package passes", b)
			}
			deep := importGraph{R: {"mid"}, "mid": {b}, b: nil, T: nil}
			if v := primitiveBanViolations(deep, []string{R, T}, T); len(v) == 0 {
				t.Errorf("%s below a relay package passes", b)
			}
		}
	})
	t.Run("a primitive below the tunnel adapter is allowed", func(t *testing.T) {
		for _, b := range primitives {
			g := importGraph{R: {T}, T: {"mid"}, "mid": {b}, b: nil}
			if v := primitiveBanViolations(g, []string{R, T}, T); len(v) != 0 {
				t.Errorf("%s below the tunnel adapter is reported: %v", b, v)
			}
		}
	})
	t.Run("a direct import of a primitive is caught when the tunnel adapter reaches it too", func(t *testing.T) {
		g := importGraph{R: {"crypto/ecdh"}, T: {"crypto/ecdh"}, "crypto/ecdh": nil}
		if v := primitiveBanViolations(g, []string{R, T}, T); len(v) != 1 {
			t.Fatalf("the walk reported %v, want exactly the import of crypto/ecdh by R", v)
		}
		// The mistake this rule avoids: closure(relay) minus closure(tunnel) is empty
		// here, so a check built on the difference would pass.
		diff := 0
		inTunnel := walkImports(g, []string{T}, "")
		for p := range walkImports(g, []string{R}, "") {
			if _, ok := inTunnel[p]; !ok && banOf(p, relayPrimitiveBans) != "" {
				diff++
			}
		}
		if diff != 0 {
			t.Fatalf("the set difference reports %d, so this graph does not show the mistake", diff)
		}
	})
	t.Run("a package shared with the tunnel adapter is caught when a relay package imports it", func(t *testing.T) {
		g := importGraph{R: {T}, "R2": {"shared"}, T: {"shared"}, "shared": {"golang.org/x/crypto/curve25519"}, "golang.org/x/crypto/curve25519": nil}
		if v := primitiveBanViolations(g, []string{R, "R2", T}, T); len(v) != 1 {
			t.Fatalf("got %v, want one violation through R2", v)
		}
		g["R2"] = nil
		if v := primitiveBanViolations(g, []string{R, "R2", T}, T); len(v) != 0 {
			t.Fatalf("with R2 not importing it the walk reported %v", v)
		}
	})
	t.Run("what the relay needs is not banned", func(t *testing.T) {
		g := importGraph{R: {"crypto/ed25519", "golang.org/x/crypto/blake2b", "crypto/rand", "crypto/sha256"}}
		for _, d := range g[R] {
			g[d] = nil
		}
		if v := primitiveBanViolations(g, []string{R}, T); len(v) != 0 {
			t.Errorf("reported %v", v)
		}
		if v := hardBanViolations(g, []string{R}); len(v) != 0 {
			t.Errorf("reported %v", v)
		}
	})
	// ADR 0015 work package 10 (concern S22): the store connection's TLS is the
	// second transport whose primitives are allowed below it only.
	t.Run("a primitive below crypto/tls or crypto/x509 is allowed", func(t *testing.T) {
		for _, stop := range []string{"crypto/tls", "crypto/x509"} {
			for _, b := range primitives {
				g := importGraph{R: {stop}, stop: {"mid"}, "mid": {b}, b: nil, T: nil}
				if v := primitiveBanViolations(g, []string{R, T}, T); len(v) != 0 {
					t.Errorf("%s below %s is reported: %v", b, stop, v)
				}
			}
		}
	})
	t.Run("a direct use of a primitive is caught beside crypto/tls", func(t *testing.T) {
		for _, b := range primitives {
			// the relay package imports TLS and the primitive itself
			g := importGraph{R: {"crypto/tls", b}, "crypto/tls": {b}, b: nil, T: nil}
			if v := primitiveBanViolations(g, []string{R, T}, T); len(v) != 1 {
				t.Errorf("%s imported directly next to crypto/tls: %v", b, v)
			}
			// a package of the relay that reaches it other than through TLS
			g = importGraph{R: {"crypto/tls", "mid"}, "crypto/tls": {"mid"}, "mid": {b}, b: nil, T: nil}
			if v := primitiveBanViolations(g, []string{R, T}, T); len(v) != 1 {
				t.Errorf("%s through a package that TLS shares: %v", b, v)
			}
		}
	})
	t.Run("only the two TLS packages are stops", func(t *testing.T) {
		for _, near := range []string{"crypto/tlsx", "crypto/x509/pkix", "net/http", "vendor/golang.org/x/net/http2", "crypto/internal/fips140/tls13"} {
			g := importGraph{R: {near}, near: {"crypto/ecdh"}, "crypto/ecdh": nil, T: nil}
			if v := primitiveBanViolations(g, []string{R, T}, T); len(v) != 1 {
				t.Errorf("%s is treated as a stop: %v", near, v)
			}
		}
	})
	t.Run("a root that is not in the graph is a violation", func(t *testing.T) {
		g := importGraph{R: nil}
		if v := hardBanViolations(g, []string{R, "gone"}); len(v) != 1 {
			t.Errorf("hard: %v", v)
		}
		if v := primitiveBanViolations(g, []string{R, "gone"}, T); len(v) != 1 {
			t.Errorf("primitive: %v", v)
		}
	})
	t.Run("the walk never enters the stop package and stops at a cycle", func(t *testing.T) {
		g := importGraph{R: {T, "a"}, T: {"hidden"}, "a": {"b"}, "b": {"a"}, "hidden": nil}
		got := walkImports(g, []string{R}, T)
		if _, ok := got["hidden"]; ok {
			t.Error("the walk entered the stop package")
		}
		if _, ok := got[T]; ok {
			t.Error("the walk returned the stop package")
		}
		if _, ok := got["b"]; !ok {
			t.Error("the walk missed a package")
		}
	})
}

// Part 3 bites: a new import, a first-party one in particular, fails, and so does
// a stale entry.
//
// spec: SPO-Xmailbox-SEC-009
func TestTunnelAllowListBitesOnSyntheticImports(t *testing.T) {
	if v := allowListViolations(tunnelDirectImports, tunnelDirectImports); len(v) != 0 {
		t.Fatalf("the list does not match itself: %v", v)
	}
	for _, extra := range []string{
		"net/http", "os/exec", "crypto/cipher", "filippo.io/age",
		module + "/internal/adapters/envelope", module + "/internal/platform/secret",
		"tailscale.com/net/netcheck", "gvisor.dev/gvisor/pkg/tcpip/stack",
	} {
		got := append(slices.Clone(tunnelDirectImports), extra)
		if v := allowListViolations(got, tunnelDirectImports); len(v) != 1 || !strings.Contains(v[0], extra) {
			t.Errorf("a new import %s gave %v", extra, v)
		}
	}
	short := tunnelDirectImports[:len(tunnelDirectImports)-1]
	if v := allowListViolations(short, tunnelDirectImports); len(v) != 1 {
		t.Errorf("a stale allow-list entry gave %v", v)
	}
}

// Part 4 bites: any further importer fails, a lookalike prefix included, and
// cmd/spo may import the one type it needs and nothing else.
//
// spec: SPO-Xmailbox-SEC-009
func TestTunnelImporterRuleBitesOnSyntheticPackages(t *testing.T) {
	ok := []pkg{
		{ImportPath: module + "/internal/adapters/tailcat", Imports: []string{"github.com/tailscale/tailcat", "tailscale.com/types/key", "gvisor.dev/gvisor/pkg/tcpip"}},
		{ImportPath: module + "/internal/adapters/tailcat/stream", Imports: []string{"github.com/tailscale/tailcat", "golang.zx2c4.com/wireguard/device"}},
		{ImportPath: module + "/cmd/spo", Imports: []string{"tailscale.com/tailcfg", "github.com/spf13/cobra"}},
		{ImportPath: module + "/internal/adapters/other", Imports: []string{"github.com/tailscale/hujson", "tailscale.com.example/x", "gvisor.dev.example/x"}},
	}
	if v := tunnelImporterViolations(ok, tunnelImporters); len(v) != 0 {
		t.Fatalf("a legal graph reported %v", v)
	}
	for _, bad := range []pkg{
		{ImportPath: module + "/internal/adapters/mailbox", Imports: []string{"github.com/tailscale/tailcat"}},
		{ImportPath: module + "/internal/app/relay", Imports: []string{"tailscale.com/types/key"}},
		{ImportPath: module + "/internal/adapters/tailcatx", Imports: []string{"gvisor.dev/gvisor/pkg/tcpip"}},
		{ImportPath: module + "/internal/adapters/tailcat/other", Imports: []string{"github.com/tailscale/tailcat"}},
		{ImportPath: module + "/cmd/spo-relay", Imports: []string{"golang.zx2c4.com/wireguard/device"}},
		{ImportPath: module + "/cmd/spo", Imports: []string{"tailscale.com/types/key"}},
		{ImportPath: module + "/cmd/spo", Imports: []string{"github.com/tailscale/tailcat"}},
		{ImportPath: module + "/internal/adapters/x", Imports: []string{"github.com/tailscale/wireguard-go/device"}},
		{ImportPath: module + "/internal/adapters/x", Imports: []string{"tailscale.com"}},
	} {
		if v := tunnelImporterViolations([]pkg{bad}, tunnelImporters); len(v) != 1 {
			t.Errorf("%s importing %v gave %v", bad.ImportPath, bad.Imports, v)
		}
	}
}
