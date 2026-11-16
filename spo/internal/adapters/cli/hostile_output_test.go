package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/app/airgap"
	apoll "github.com/mochipool/workbench/spo/internal/app/poll"
	"github.com/mochipool/workbench/spo/internal/app/query"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/transfer"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// nastyText is a string a chain, a provider or a file could choose: an escape
// sequence, a C1 control, a right-to-left override, a newline that forges a
// line, a Hangul filler.
const nastyText = "A\x1b[2JB\u009b31mC‮D\nFORGED: lineㅤE"

// noActive fails when s holds a rune a terminal could act on or that disguises
// text, or when the forged line survived.
func noActive(t *testing.T, name, s string) {
	t.Helper()
	for _, r := range s {
		if r == 0x1b || (r >= 0x80 && r <= 0x9f) || r == 0x202e || r == 0x3164 || r == 0x07 {
			t.Errorf("%s: U+%04X survived in %q", name, r, s)
			return
		}
	}
	// Multi-line text a command shows as a block (a poll question, an error
	// message) keeps its line breaks, indented or inside the message; every
	// other field is one line.
	if strings.Contains(s, "\nFORGED") && !strings.Contains(name, "poll") && !strings.Contains(name, "SafeMessage") {
		t.Errorf("%s: the newline forged a line in %q", name, s)
	}
	if !strings.Contains(s, "FORGED") && !strings.Contains(s, "A\\u{1b}") && !strings.Contains(s, `\u{1b}`) {
		// The nastyText text must still be visible, as escapes, unless the path
		// shows hex only (the token name).
		if !strings.Contains(name, "hex only") {
			t.Errorf("%s: the text is not shown at all: %q", name, s)
		}
	}
}

// Every output path that shows a string a chain, a provider, a peer or a file
// chose writes it as escapes (ESC, C1, U+202E, a newline and a filler never
// reach the terminal raw).
//
// spec: ADR 0006 (strings a provider chose are escaped)
func TestHostileTextNeverReachesTheTerminalRaw(t *testing.T) {
	var tid chain.TxID
	cases := map[string]func(w *bytes.Buffer){
		"poll show": func(w *bytes.Buffer) {
			a := &app{d: Deps{Out: w}}
			printPoll(a, apoll.View{TxID: tid, Source: chain.Source(nastyText), Text: nastyText, Options: []string{nastyText, "No"}})
		},
		"address report: name, datum, snapshot, vote": func(w *bytes.Buffer) {
			printAddressReport(w, query.AddressReport{Kind: "payment", Name: nastyText, Address: "addr_test1", Source: "koios", SnapshotDate: nastyText, FromSnapshot: true,
				Utxos:  []query.UtxoLine{{Ref: "ab#0", Assets: []query.AssetLine{{Policy: "p", NameHex: "41", NameText: nastyText, Quantity: 1}}, DatumHash: nastyText, HasDatumHash: true}},
				Assets: []query.AssetTotal{{Policy: "p", NameHex: "41", NameText: nastyText, Fingerprint: nastyText, Quantity: 1}}})
			printAddressReport(w, query.AddressReport{Kind: "stake", Address: "stake_test1", Source: "koios", VoteDelegation: chain.Value(nastyText)})
		},
		"offline info": func(w *bytes.Buffer) {
			printInfo(w, "t.json", airgap.InfoResult{Info: transfer.Info{
				Usable: errors.New(nastyText), Era: nastyText, OnlineCLI: nastyText, OnlineNode: nastyText, OfflineCLI: nastyText, LastAction: nastyText, LastActionDate: nastyText,
				Addresses: []transfer.AddressInfo{{Key: nastyText, Name: nastyText, Type: nastyText, Date: nastyText}},
				Files:     []transfer.FileInfo{{Key: nastyText, Date: nastyText, Size: 1}}}}, nil)
		},
		"offline execute summary": func(w *bytes.Buffer) {
			e := transfer.QueuedEntry{Type: nastyText, Era: nastyText, Date: nastyText, FromName: nastyText, FromAddr: nastyText, ToName: nastyText, ToAddr: nastyText,
				StakeName: nastyText, StakingAddr: nastyText, DelegName: nastyText, DRepName: nastyText, PoolTicker: nastyText, PoolMetaURL: nastyText, PoolMetaHash: nastyText}
			printExecuteSummary(w, ports.ExecuteSummary{Entry: e, Source: chain.Source(nastyText), Warnings: []string{nastyText}, Checked: []string{nastyText}, Unchecked: []string{nastyText}})
		},
		"offline add": func(w *bytes.Buffer) {
			printAdd(w, airgap.AddResult{Name: nastyText, Address: nastyText, Kind: "payment", Source: chain.Source(nastyText), ParamSource: chain.Source(nastyText), Date: nastyText}, "t.json")
		},
		"tx summaries": func(w *bytes.Buffer) {
			s := ports.TxSummary{Account: nastyText, StakeAddr: chain.StakeAddress(nastyText), Source: nastyText, SourceAddr: chain.Address(nastyText), Destination: nastyText, DestAddr: chain.Address(nastyText),
				Amount: nastyText, Message: []string{nastyText}, Unchecked: []string{nastyText}, Sources: []chain.Source{chain.Source(nastyText)}}
			printStakeSummary(w, s)
			printTxSummary(w, s)
		},
		"op cert verdict reasons": func(w *bytes.Buffer) {
			printOpCertVerdict(w, query.OpCertVerdict{Source: chain.Source(nastyText), OnChain: chain.Unknown[uint64](nastyText), Status: query.StatusUnknown, Reasons: []query.Reason{query.Reason(nastyText)}}, query.CheckCurrent)
		},
		"plainText (token registry)": func(w *bytes.Buffer) { w.WriteString(plainText(nastyText, 200)) },
		"SafeMessage (any refusal)":  func(w *bytes.Buffer) { w.WriteString(SafeMessage(errors.New("pool state from koios: " + nastyText))) },
	}
	for name, render := range cases {
		var w bytes.Buffer
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: %v", name, r)
				}
			}()
			render(&w)
		}()
		noActive(t, name, w.String())
	}
}

// A token name with a control, bidirectional or filler character has no text
// form at all: the report shows its hex only (anyone can send such a token to
// an address).
//
// spec: SPO-Cconv-OUT-016
func TestHostileTokenNameIsHexOnly(t *testing.T) {
	var w bytes.Buffer
	printAddressReport(&w, query.AddressReport{Kind: "payment", Address: "addr_test1", Source: "koios",
		Assets: []query.AssetTotal{{Policy: "pp", NameHex: "41", Quantity: 1}}})
	if !strings.Contains(w.String(), "pp.41") || strings.Contains(w.String(), "pp.41 (") {
		t.Errorf("%s", w.String())
	}
}

type hostileCalidus struct{}

func (hostileCalidus) Source() chain.Source { return "fake registrations" }
func (hostileCalidus) CalidusKeys(context.Context, ports.CalidusFilter) ([]ports.CalidusEntry, error) {
	return []ports.CalidusEntry{{PoolBech: nastyText, IDBech: nastyText, PubKeyHex: nastyText, TxHash: nastyText}}, nil
}

// The two read commands whose output is a provider's answer, run end to end:
// pool status (Koios name, ticker, URL, hash) and calidus status.
//
// spec: ADR 0006 (strings a provider chose are escaped)
func TestHostileProviderAnswersInPoolStatusAndCalidusStatus(t *testing.T) {
	f := newStakeFix(t)
	f.pools = fakePools{r: chain.Value(chain.PoolState{Name: nastyText, Ticker: nastyText, MetaURL: nastyText, MetaHash: nastyText, Margin: nastyText, RewardAddress: nastyText})}
	out := f.mustRun(t, "pool", "status", poolHex)
	noActive(t, "pool status", out)

	g := newStakeFix(t)
	withRegistrations(g, &recDeriver{}, hostileCalidus{})
	old := g.deps.Wire
	g.deps.Wire = func(st ports.Store, o WireOptions) (*Env, error) {
		env, err := old(st, o)
		env.CalidusReader = hostileCalidus{}
		return env, err
	}
	noActive(t, "calidus status", g.mustRun(t, "pool", "calidus", "status", "all"))
}
