package archtest

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The TUI's relay session cannot bypass the cold-key rule (ADR 0014 work
// package 9): the session sends only by the outbox's flush, which the command
// line wires; the TUI reaches it through the command tree and the shared loop
// only. The TUI imports, of this module, only platform packages and
// app/relayloop; app/relayloop imports no use case and no adapter, and its code
// names no transport and no sender, so nothing the TUI holds can send an
// envelope that the outbox's rule (SPO-Xparty-PRE-004) has not seen.

const (
	tuiPkg       = module + "/internal/adapters/tui"
	relayloopPkg = module + "/internal/app/relayloop"
)

// relaySessionViolations checks the import graph and relayloop's sources.
func relaySessionViolations(pkgs []pkg, relayloopSrc map[string]string) []string {
	var out []string
	for _, p := range pkgs {
		for _, imp := range p.Imports {
			if !strings.HasPrefix(imp, module+"/") {
				continue
			}
			switch p.ImportPath {
			case tuiPkg:
				if imp != relayloopPkg && !strings.HasPrefix(imp, module+"/internal/platform/") {
					out = append(out, tuiPkg+" imports "+imp)
				}
			case relayloopPkg:
				if strings.HasPrefix(imp, module+"/internal/app/") || strings.HasPrefix(imp, module+"/internal/adapters/") {
					out = append(out, relayloopPkg+" imports "+imp)
				}
			}
		}
	}
	names := make([]string, 0, len(relayloopSrc))
	for name := range relayloopSrc {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		src := relayloopSrc[name]
		for _, word := range []string{"ports.Transport", "EnvelopeSender", "NetworkTransport", "FileTransport", ".Send("} {
			if strings.Contains(src, word) {
				out = append(out, name+" names "+word)
			}
		}
	}
	return out
}

func relayloopSources(t *testing.T) map[string]string {
	t.Helper()
	dir := filepath.Join("..", "app", "relayloop")
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range es {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = string(b)
	}
	if len(out) == 0 {
		t.Fatal("no source of app/relayloop")
	}
	return out
}

// sessionCompositionViolations checks the session's composition in the command
// tree (adapters/cli/party_relaynet.go): the session holds the composite as
// sessionClient, an interface that is declared there with no Send method and
// embeds nothing; the field client of relaySession has that type; nothing in
// the file asserts the client to another type; the file calls .Send( nowhere;
// and it takes the composite's Transport() once (the opening), so the steps'
// closures reach an envelope sender only as the flush's transport.
//
// What it cannot prove: that another file of the package does not reach the
// composite (RelayClient, which has Send, is still what RelayOps.Connect
// returns), nor what the flush function given to the loop does with the
// transport (it is the outbox's own Flush in relayExchange; the outbox's rule
// is SPO-Xparty-PRE-004 and has its own tests). It reads source text, so a
// reflective call or an unsafe cast would pass it.
func sessionCompositionViolations(name, src string) []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		return []string{name + ": " + err.Error()}
	}
	var out []string
	var iface *ast.InterfaceType
	clientType := ""
	transports := 0
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.TypeSpec:
			switch n.Name.Name {
			case "sessionClient":
				iface, _ = n.Type.(*ast.InterfaceType)
			case "relaySession":
				if st, ok := n.Type.(*ast.StructType); ok {
					for _, fl := range st.Fields.List {
						for _, nm := range fl.Names {
							if nm.Name == "client" {
								if id, ok := fl.Type.(*ast.Ident); ok {
									clientType = id.Name
								} else {
									clientType = "?"
								}
							}
						}
					}
				}
			}
		case *ast.TypeAssertExpr:
			if sel, ok := n.X.(*ast.SelectorExpr); ok && sel.Sel.Name == "client" {
				out = append(out, name+": the session's client is asserted to another type")
			}
		case *ast.CallExpr:
			if sel, ok := n.Fun.(*ast.SelectorExpr); ok {
				switch sel.Sel.Name {
				case "Send":
					out = append(out, name+": calls .Send(")
				case "Transport":
					transports++
				}
			}
		}
		return true
	})
	switch {
	case iface == nil:
		out = append(out, name+": no sessionClient interface")
	default:
		for _, m := range iface.Methods.List {
			if len(m.Names) == 0 {
				out = append(out, name+": sessionClient embeds an interface")
			}
			for _, nm := range m.Names {
				if nm.Name == "Send" {
					out = append(out, name+": sessionClient has Send")
				}
			}
		}
	}
	if clientType != "sessionClient" {
		out = append(out, name+": relaySession.client is "+clientType+", not sessionClient")
	}
	if transports != 1 {
		out = append(out, fmt.Sprintf("%s: Transport() is taken %d times, not once at the opening", name, transports))
	}
	return out
}

// spec: SPO-Xmailbox-SEC-082
func TestTheSessionsStepsCannotSendButByTheFlush(t *testing.T) {
	path := filepath.Join("..", "adapters", "cli", "party_relaynet.go")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range sessionCompositionViolations("party_relaynet.go", string(b)) {
		t.Error(v)
	}
}

// The composition rule bites: a client with Send, an embedded interface, the
// session holding the wide client, a type assertion, a direct send and a
// second Transport() are each refused.
//
// spec: SPO-Xmailbox-SEC-082
func TestTheSessionCompositionRuleBites(t *testing.T) {
	good := `package cli
type sessionClient interface{ Receive() }
type relaySession struct{ client sessionClient }
func open(c RelayClient) { _ = c.Transport() }
`
	if v := sessionCompositionViolations("good.go", good); len(v) != 0 {
		t.Fatalf("the good source: %v", v)
	}
	for name, src := range map[string]string{
		"send in the interface": strings.Replace(good, "Receive()", "Receive(); Send()", 1),
		"embedded":              strings.Replace(good, "Receive()", "Receive(); RelayClient", 1),
		"wide client":           strings.Replace(good, "client sessionClient", "client RelayClient", 1),
		"assertion":             good + "func f(s relaySession) { _ = s.client.(RelayClient) }\n",
		"direct send":           good + "func f(c RelayClient) { c.Send(nil, nil, nil) }\n",
		"second transport":      good + "func f(c RelayClient) { _ = c.Transport() }\n",
	} {
		if v := sessionCompositionViolations(name, src); len(v) == 0 {
			t.Errorf("%s: not refused", name)
		}
	}
}

// spec: SPO-Xmailbox-SEC-082
func TestTheTUISessionCannotBypassTheColdKeyRule(t *testing.T) {
	pkgs := load(t)
	seen := 0
	for _, p := range pkgs {
		if p.ImportPath == tuiPkg || p.ImportPath == relayloopPkg {
			seen++
		}
	}
	if seen != 2 {
		t.Fatalf("found %d of the two packages", seen)
	}
	for _, v := range relaySessionViolations(pkgs, relayloopSources(t)) {
		t.Error(v)
	}
}

// The rule bites: a TUI that imports a use case or an adapter, a relayloop that
// imports a use case, and a relayloop that names a transport are refused.
//
// spec: SPO-Xmailbox-SEC-082
func TestTheTUISessionRuleBites(t *testing.T) {
	got := relaySessionViolations([]pkg{
		{ImportPath: tuiPkg, Imports: []string{relayloopPkg, module + "/internal/platform/secret", module + "/internal/app/multisig", module + "/internal/ports"}},
		{ImportPath: relayloopPkg, Imports: []string{module + "/internal/ports", module + "/internal/app/multisig", module + "/internal/adapters/mailbox"}},
	}, map[string]string{"x.go": "func f(t ports.Transport) {}", "y.go": "c.Send(ctx, to, env)"})
	want := []string{
		tuiPkg + " imports " + module + "/internal/app/multisig",
		tuiPkg + " imports " + module + "/internal/ports",
		relayloopPkg + " imports " + module + "/internal/app/multisig",
		relayloopPkg + " imports " + module + "/internal/adapters/mailbox",
		"x.go names ports.Transport",
		"y.go names .Send(",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("violations:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
