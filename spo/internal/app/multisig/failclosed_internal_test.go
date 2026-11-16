package multisig

import (
	"bytes"
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

type fcRes struct {
	m map[chain.OutRef]chain.Reading[chain.ResolvedUtxo]
}

func (fcRes) Source() chain.Source { return "test" }
func (r fcRes) ResolveUtxos(_ context.Context, refs []chain.OutRef) (map[chain.OutRef]chain.Reading[chain.ResolvedUtxo], error) {
	out := map[chain.OutRef]chain.Reading[chain.ResolvedUtxo]{}
	for _, ref := range refs {
		if v, ok := r.m[ref]; ok {
			out[ref] = v
		} else {
			out[ref] = chain.Unknown[chain.ResolvedUtxo]("unknown")
		}
	}
	return out, nil
}

// failingInspector reads nothing.
type failingInspector struct{}

func (failingInspector) InspectAddress(chain.Address) (ports.AddressInfo, error) {
	return ports.AddressInfo{}, errors.New("cannot inspect")
}

func fcAddr(t *testing.T, hrp string, hdr byte, rest ...byte) string {
	t.Helper()
	s, err := chain.Bech32Encode(hrp, append([]byte{hdr}, rest...))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func fcView(addr string) party.TxView {
	return party.TxView{Inputs: []party.ViewInput{{TxID: [32]byte{1}}}, Fee: 200000}
}

func fcSigner(addr string, insp ports.AddressInspector) Signer {
	s := Signer{Addresses: insp}
	if addr != "" {
		s.Resolver = OwnProvider(fcRes{map[chain.OutRef]chain.Reading[chain.ResolvedUtxo]{
			{TxID: chain.TxID{1}}: chain.Value(chain.ResolvedUtxo{Address: chain.Address(addr), Lovelace: 5_000_000})}})
	}
	return s
}

// A signer without an inspector cannot work out a flow at all.
// spec: SPO-Xparty-PR-004
func TestResolveFlowWithoutAnInspectorIsAConfigurationError(t *testing.T) {
	_, err := Signer{}.resolveFlow(context.Background(), party.TxView{}, custody.RoleStake, false)
	if !errors.Is(err, ErrNoAddressInspector) {
		t.Fatalf("err = %v", err)
	}
}

// Whatever fails inspection is a script: a withdrawal from an account the
// inspector cannot read, and an input at an address it cannot read, are
// refused, not classified foreign.
// spec: SPO-Xparty-PR-004
func TestUninspectableIsTreatedAsScript(t *testing.T) {
	k := bytes.Repeat([]byte{0x11}, 28)
	good := fcAddr(t, "addr_test", 0x60, k...)
	// An account that fails inspection (and a key account by its own header
	// is still key: the inspector failing must not make it a script by
	// itself only when the header says script).
	v := fcView(good)
	v.Withdrawals = []party.ViewWithdrawal{{Account: fcAddr(t, "stake_test", 0xe0, k...), Lovelace: 1}}
	fl, err := fcSigner(good, failingInspector{}).resolveFlow(context.Background(), v, custody.RoleStake, false)
	if err != nil {
		t.Fatal(err)
	}
	if r, bad := fl.Refusal(custody.RoleStake, false); !bad || r != party.RefuseScriptInput {
		t.Fatalf("file: %v %v (%+v)", r, bad, fl)
	}
	// Over a network an unreadable input address is an unresolved input.
	fl, err = fcSigner(good, failingInspector{}).resolveFlow(context.Background(), fcView(good), custody.RoleStake, true)
	if err != nil {
		t.Fatal(err)
	}
	if r, bad := fl.Refusal(custody.RoleStake, true); !bad || r != party.RefuseCannotResolveInputs {
		t.Fatalf("network: %v %v", r, bad)
	}
}

// A script reward account is refused with a working inspector, and a script
// payment credential is refused by the header even when the inspector calls
// the address a key's.
// spec: SPO-Xparty-PR-004
func TestHeaderOverridesALyingInspector(t *testing.T) {
	k := bytes.Repeat([]byte{0x11}, 28)
	scriptIn := fcAddr(t, "addr_test", 0x70, k...)
	s := fcSigner(scriptIn, keyOnly{native.Ledger{}})
	s.Owned = party.OwnedKeys{Payment: [][28]byte{[28]byte(k)}}
	fl, err := s.resolveFlow(context.Background(), fcView(scriptIn), custody.RolePayment, false)
	if err != nil {
		t.Fatal(err)
	}
	if r, bad := fl.Refusal(custody.RolePayment, false); !bad || r != party.RefuseScriptInput || len(fl.OwnInputs) != 0 {
		t.Fatalf("%v %v %+v", r, bad, fl)
	}
}

// keyOnly is an inspector that reports every payment credential as a key, as
// a buggy or hostile one would.
type keyOnly struct{ ports.AddressInspector }

func (k keyOnly) InspectAddress(a chain.Address) (ports.AddressInfo, error) {
	i, err := k.AddressInspector.InspectAddress(a)
	if err == nil && i.PaymentIsScript {
		_, b, _ := chain.Bech32Decode(string(a))
		kh := txbuild.KeyHash(b[1:29])
		i.PaymentIsScript, i.PaymentKeyHash = false, &kh
	}
	return i, err
}

// A transfer bundle that arrived from another party cannot become an
// OwnResolver through any exported path of this package or of the party
// domain: the only ways to make an OwnResolver are OwnProvider and OwnSnapshot,
// each taking one ports.UtxoResolver and nothing else (not a party.Bundle, an
// attachment, a received envelope or bytes); OwnResolver has no exported
// field to set; and no other exported function or method of the two packages
// returns a UtxoResolver or an OwnResolver. What a caller passes to
// OwnSnapshot is the wiring's to guard (SPO-Xparty-PR-005): a path the
// operator named, never one that the store of received messages, a transport
// or the party's bundle handling wrote.
// spec: SPO-Xparty-PR-005
func TestReceivedBundleCannotBecomeAnOwnSnapshotSource(t *testing.T) {
	fset := token.NewFileSet()
	typeText := func(e ast.Expr) string {
		switch x := e.(type) {
		case *ast.Ident:
			return x.Name
		case *ast.SelectorExpr:
			return x.X.(*ast.Ident).Name + "." + x.Sel.Name
		}
		return "?"
	}
	var seenMakers []string
	for _, dir := range []string{".", "../../domain/party"} {
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, name := range files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, name, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range f.Decls {
				switch d := d.(type) {
				case *ast.FuncDecl:
					if d.Type.Results == nil {
						continue
					}
					for _, r := range d.Type.Results.List {
						tt := typeText(r.Type)
						if !strings.Contains(tt, "OwnResolver") && !strings.Contains(tt, "UtxoResolver") {
							continue
						}
						if d.Name.Name != "OwnProvider" && d.Name.Name != "OwnSnapshot" {
							t.Errorf("%s: %s returns a %s: only OwnProvider and OwnSnapshot may", name, d.Name.Name, tt)
							continue
						}
						seenMakers = append(seenMakers, d.Name.Name)
						ps := d.Type.Params.List
						if len(ps) != 1 || typeText(ps[0].Type) != "ports.UtxoResolver" {
							t.Errorf("%s: %s must take exactly one ports.UtxoResolver", name, d.Name.Name)
						}
					}
				case *ast.GenDecl:
					for _, sp := range d.Specs {
						ts, ok := sp.(*ast.TypeSpec)
						if !ok || ts.Name.Name != "OwnResolver" {
							continue
						}
						for _, fld := range ts.Type.(*ast.StructType).Fields.List {
							for _, n := range fld.Names {
								if n.IsExported() {
									t.Errorf("OwnResolver has an exported field %s", n.Name)
								}
							}
						}
					}
				}
			}
		}
	}
	if len(seenMakers) != 2 {
		t.Errorf("makers of an OwnResolver = %v, want OwnProvider and OwnSnapshot", seenMakers)
	}
}
