package cli

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/app/parties"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// approveYesWhy is why approve has no --yes: the decision can only be made
// from the review, and no flag stands in for reading it (SPO-Xparty-INV-016).
const approveYesWhy = "--yes is not accepted: approving a signing request is a decision made from the review you read, answered at a prompt (default No), and then confirmed with the workspace passphrase. No flag answers it"

// escapeUnsafe writes every rune that is not printable, a control or format
// character or a line separator, as \u{hex}, and leaves the rest. It is for
// text the body decoder has already cleaned, as a second line of defence; text
// a peer chose outright goes through safeText.
func escapeUnsafe(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == utf8.RuneError || (r != ' ' && !strconv.IsPrint(r)) {
			fmt.Fprintf(&b, "\\u{%x}", r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func lov(n uint64) string { return lovelaceText(chainLovelace(n)) }

// Limits of the default (folded) display. --full shows everything. The summary
// block is never folded and does not depend on them.
const (
	foldOwnInputs = 8
	foldOutputs   = 10
	foldAssets    = 5
	foldBodyLines = 40
	foldLabels    = 5
	foldMessages  = 3
	foldLineRunes = 240
)

// clip shortens one line of a peer's text for the default display.
func clip(s string, full bool) string {
	if full {
		return s
	}
	r := []rune(s)
	if len(r) <= foldLineRunes {
		return s
	}
	return string(r[:foldLineRunes]) + fmt.Sprintf(" ... (%d more characters; use --full)", len(r)-foldLineRunes)
}

func more(w io.Writer, indent string, n int) {
	fmt.Fprintf(w, "%s... %d more (use --full)\n", indent, n)
}

// netText is the net movement of the signer's own money, with its direction.
func netText(fl party.Flow) string {
	net, dir := fl.NetLovelace, "leaves you"
	if net < 0 {
		net, dir = -net, "arrives to you"
	}
	if fl.NetExcludesInputs {
		return fmt.Sprintf("%s %s, EXCLUDING your own inputs, which were not resolved: value leaving through them is NOT in this number", lov(uint64(net)), dir)
	}
	return fmt.Sprintf("%s %s", lov(uint64(net)), dir)
}

// printReview writes everything the operator reads before a signature: how
// the request arrived, whose money moves (worked out here from this
// workspace's own keys and chain view), the net, the scope parts, the decoded
// body and the metadata. Unless full, long lists, the body and the metadata
// are folded to their first entries: what decides the signature is in the
// summary block printSummary writes after all of this, immediately before the
// question. It returns how many lines of the certificates, votes, withdrawals,
// mint, required signers, treasury and donation it folded or clipped (always 0
// with full): approve asks for --full when it is not 0. The words "inputs not
// checked" are Flow.NotChecked verbatim (SPO-Xparty-PR-003, PR-004).
//
// spec: SPO-Xparty-PR-002, SPO-Xparty-PR-003, SPO-Xparty-PR-004
func printReview(w io.Writer, rv multisig.Review, full bool) (folded int) {
	folded, _ = printReviewSections(w, rv, full)
	return folded
}

// printReviewSections is printReview and also names the authority categories
// (authorityCategories) that lost a line to the fold or the clip, in table
// order, so that a review can say which ones at its end.
func printReviewSections(w io.Writer, rv multisig.Review, full bool) (folded int, sections []string) {
	fmt.Fprintf(w, "Signing request %x\n", rv.RequestID[:])
	fmt.Fprintf(w, "  arrived by    the %s transport\n", rv.Via)
	fmt.Fprintf(w, "  from          %s (an enrolled coordinator)\n", safeText(rv.Coordinator))
	fmt.Fprintf(w, "  asks for      the %s key with hash %x\n", rv.Role, rv.KeyHash[:])
	fmt.Fprintf(w, "  body hash     %x\n", rv.BodyHash[:])
	fmt.Fprintf(w, "  the coordinator says this is for (its claim only; nothing below comes from it): %s\n\n", clip(safeText(rv.ClaimedPurpose), full))

	fl := rv.Flow
	fmt.Fprintln(w, "Whose money moves (worked out here, from your own keys and your own view of the chain)")
	if !fl.Checked {
		fmt.Fprintf(w, "  %s\n", fl.NotChecked)
		if fl.NotCheckedDetail != "" {
			fmt.Fprintf(w, "  what the provider said (not part of what you approve): %s\n", clip(safeText(fl.NotCheckedDetail), full))
		}
	} else {
		fmt.Fprintf(w, "  your own inputs  %d, worth %s\n", len(fl.OwnInputs), lov(fl.OwnInputLovelace))
		for i, in := range fl.OwnInputs {
			if !full && i >= foldOwnInputs {
				more(w, "    ", len(fl.OwnInputs)-i)
				break
			}
			fmt.Fprintf(w, "    %x#%d  %s\n", in.Input.TxID[:], in.Input.Index, lov(in.Lovelace))
			for j, a := range in.Assets {
				if !full && j >= foldAssets {
					more(w, "      ", len(in.Assets)-j)
					break
				}
				fmt.Fprintf(w, "      + %d %x.%x\n", a.Quantity, a.Policy[:], a.Name)
			}
		}
		fmt.Fprintf(w, "  other inputs     %d (not spendable by your keys)\n", fl.ForeignInputs)
	}
	fmt.Fprintf(w, "  outputs\n")
	for i, o := range fl.Outputs {
		if !full && i >= foldOutputs {
			more(w, "    ", len(fl.Outputs)-i)
			break
		}
		who := "NOT yours"
		if o.Own {
			who = "yours"
		}
		fmt.Fprintf(w, "    %s  %s  %s\n", escapeUnsafe(o.Address), lov(o.Lovelace), who)
		if o.Note != "" {
			fmt.Fprintf(w, "      note: %s\n", clip(safeText(o.Note), full))
		}
		for j, a := range o.Assets {
			if !full && j >= foldAssets {
				more(w, "      ", len(o.Assets)-j)
				break
			}
			fmt.Fprintf(w, "      + %d %x.%x\n", a.Quantity, a.Policy[:], a.Name)
		}
	}
	fmt.Fprintf(w, "  withdrawals      %s from your reward accounts, %s from other accounts\n", lov(fl.WithdrawalsOwn), lov(fl.WithdrawalsOther))
	fmt.Fprintf(w, "  refunds          %s to you (all certificates state %s)\n", lov(fl.RefundsOwn), lov(fl.Refunds))
	fmt.Fprintf(w, "  deposits         %s paid by you (all certificates state %s)\n", lov(fl.DepositsOwn), lov(fl.Deposits))
	if fl.UnstatedDeposits > 0 {
		fmt.Fprintf(w, "  %d certificate(s) pay or refund a deposit that is a protocol parameter, not in the body: no amount is shown for it\n", fl.UnstatedDeposits)
	}
	fmt.Fprintf(w, "  value to others  %s (outputs that are not yours)\n", lov(fl.ToOthersLovelace))
	fmt.Fprintf(w, "  fee              %s\n", lov(fl.Fee))
	fmt.Fprintf(w, "  NET              %s  (your inputs + withdrawals + refunds - your outputs - your deposits)\n", netText(fl))
	for i, a := range fl.NetAssets {
		if !full && i >= foldAssets {
			more(w, "  ", len(fl.NetAssets)-i)
			break
		}
		fmt.Fprintf(w, "  net asset        %d %x.%x\n", a.Quantity, a.Policy[:], a.Name)
	}
	if fl.PaymentWitnessElsewhere {
		fmt.Fprintln(w, "  !! "+paymentElsewhereText)
	}
	fmt.Fprintln(w)

	sp := party.ScopePartsOf(rv.Role, rv.View)
	fmt.Fprintf(w, "What the coordinator's scope covers for this request\n  pools named      %s\n", clip(listOrNone(sp.Pools), full))
	fmt.Fprintf(w, "  parts naming no pool (need an unscoped coordinator)  %s\n\n", clip(listOrNone(sp.Unscoped), full))

	// The parts that decide a signature come first, so the fold of the long
	// tail (outputs, inputs, metadata) cannot hide them; and when it still
	// folds or clips any line of them, that is reported to the caller.
	// Text a peer chose (a relay host, a metadata or anchor URL) is quoted
	// here, with the helper the summary uses (SPO-Xparty-PR-002).
	shown := quotedView(rv.View)
	lines, authority := txViewLines(shown, true)
	lines = append(lines, "")
	owner := authorityOwners(shown, authority)
	hit := map[string]bool{}
	for i, l := range lines {
		if !full && i >= foldBodyLines {
			more(w, "  ", len(lines)-i)
			folded += max(authority-i, 0)
			for j := i; j < authority && j < len(owner); j++ {
				hit[owner[j]] = true
			}
			break
		}
		if !full && i < authority && len([]rune(l)) > foldLineRunes {
			folded++
			if i < len(owner) {
				hit[owner[i]] = true
			}
		}
		fmt.Fprintln(w, clip(l, full))
	}
	for _, c := range authorityCategories {
		if hit[c.name] {
			sections = append(sections, c.name)
		}
	}
	if rv.Aux != nil {
		fmt.Fprintf(w, "Metadata  (%d label(s))\n", len(rv.Aux.Labels))
		for i, l := range rv.Aux.Labels {
			if !full && i >= foldLabels {
				more(w, "  ", len(rv.Aux.Labels)-i)
				break
			}
			fmt.Fprintf(w, "  label %d  %s\n", l.Label, clip(escapeUnsafe(l.Value), full))
			for j, m := range l.Messages {
				if !full && j >= foldMessages {
					more(w, "    ", len(l.Messages)-j)
					break
				}
				fmt.Fprintf(w, "    message  %s\n", clip(safeText(m), full))
			}
		}
		fmt.Fprintln(w)
	}
	return folded, sections
}

// authorityCategory is one part of a body that decides a signature and is
// printed before the long tail of the review. The table is the single list:
// the refusal that names what can be folded, the review's closing warning and
// the attribution of a folded line to its part are all read from it, and a
// test fails when a line of the authority region belongs to no row, so a new
// category cannot be added to the display and forgotten here.
type authorityCategory struct {
	name string
	// only is a view that holds this category of v and nothing else.
	only func(v party.TxView) party.TxView
}

// authorityCategories is in the order txViewLines prints them.
var authorityCategories = []authorityCategory{
	{"certificates", func(v party.TxView) party.TxView { return party.TxView{Certificates: v.Certificates} }},
	{"votes", func(v party.TxView) party.TxView { return party.TxView{Votes: v.Votes} }},
	{"withdrawals", func(v party.TxView) party.TxView { return party.TxView{Withdrawals: v.Withdrawals} }},
	{"mint", func(v party.TxView) party.TxView { return party.TxView{Mint: v.Mint} }},
	{"required signers", func(v party.TxView) party.TxView { return party.TxView{RequiredSigners: v.RequiredSigners} }},
	{"treasury", func(v party.TxView) party.TxView { return party.TxView{TreasuryValue: v.TreasuryValue} }},
	{"donation", func(v party.TxView) party.TxView { return party.TxView{Donation: v.Donation} }},
}

// authorityNames is the categories as prose: "a, b and c".
func authorityNames() string {
	var n []string
	for _, c := range authorityCategories {
		n = append(n, c.name)
	}
	return strings.Join(n[:len(n)-1], ", ") + " and " + n[len(n)-1]
}

// authorityCounts is the number of lines of the head (what precedes the first
// category) and of each category, measured by rendering the view with only
// that category, so the counts follow the renderer.
func authorityCounts(v party.TxView) (head int, counts []int) {
	nv := party.TxView{NetworkID: v.NetworkID}
	_, head = txViewLines(nv, true)
	for _, c := range authorityCategories {
		o := c.only(v)
		o.NetworkID = v.NetworkID
		_, n := txViewLines(o, true)
		counts = append(counts, n-head)
	}
	return head, counts
}

// authorityOwners names, for each line of the authority region, the category
// it belongs to ("" for the head).
func authorityOwners(v party.TxView, authority int) []string {
	head, counts := authorityCounts(v)
	owner := make([]string, 0, authority)
	for i := 0; i < head; i++ {
		owner = append(owner, "")
	}
	for i, c := range authorityCategories {
		for j := 0; j < counts[i]; j++ {
			owner = append(owner, c.name)
		}
	}
	return owner
}

// quotedView is v with the text a peer chose and the decoder does not limit
// (relay hosts, the pool metadata URL, anchor URLs) replaced by its quoted
// form, so that the review body shows it as the summary does: one word, with
// no control character, escape sequence, bidirectional override, line
// separator or newline left raw. The input is not changed.
func quotedView(v party.TxView) party.TxView {
	anchor := func(a *party.ViewAnchor) *party.ViewAnchor {
		if a == nil {
			return nil
		}
		c := *a
		c.URL = quoted(c.URL)
		return &c
	}
	v.Certificates = slices.Clone(v.Certificates)
	for i := range v.Certificates {
		c := &v.Certificates[i]
		c.Anchor = anchor(c.Anchor)
		if c.PoolReg != nil {
			r := *c.PoolReg
			r.Relays = slices.Clone(r.Relays)
			for j := range r.Relays {
				r.Relays[j].Host = quoted(r.Relays[j].Host)
			}
			r.MetaURL = quoted(r.MetaURL)
			c.PoolReg = &r
		}
	}
	v.Votes = slices.Clone(v.Votes)
	for i := range v.Votes {
		v.Votes[i].Anchor = anchor(v.Votes[i].Anchor)
	}
	return v
}

const paymentElsewhereText = "THIS BODY SPENDS YOUR OWN PAYMENT UTXOs, and the key you are asked for is not a payment key: this witness does not authorise that. The payment witness must come from elsewhere."

func listOrNone(xs []string) string {
	if len(xs) == 0 {
		return "none"
	}
	return strings.Join(xs, "; ")
}

// requestID resolves the text the operator typed to one request among ALL the
// requests this workspace stores or has received (pending, answered, refused,
// closed): the whole 32-character id, or a prefix of at least 6 characters
// that no other request shares. A prefix that is unique only among the
// pending ones is not enough: an older request that is no longer pending must
// not become the one an approval lands on by a collision the operator cannot
// see.
func requestID(all []party.MessageID, text string) (party.MessageID, error) {
	text = strings.ToLower(strings.TrimSpace(text))
	if len(text) < 6 {
		return party.MessageID{}, errors.New("give at least the first 6 characters of the request id: see spo party requests")
	}
	var hit []party.MessageID
	for _, id := range all {
		if strings.HasPrefix(hex.EncodeToString(id[:]), text) && !slices.Contains(hit, id) {
			hit = append(hit, id)
		}
	}
	switch len(hit) {
	case 0:
		return party.MessageID{}, fmt.Errorf("no request has the id %q: see spo party requests", text)
	case 1:
		return hit[0], nil
	}
	return party.MessageID{}, fmt.Errorf("%q matches %d requests of this workspace (some no longer pending): type more of the id, or all of it", text, len(hit))
}

// allRequestIDs is every request id this workspace knows: the pending ones
// and every request-received event of the security log (answered, refused and
// closed requests are in it).
func (r *partyRun) allRequestIDs(ctx context.Context, sg multisig.Signer) ([]party.MessageID, error) {
	pending, err := sg.Pending(ctx)
	if err != nil {
		return nil, err
	}
	var ids []party.MessageID
	for _, p := range pending {
		ids = append(ids, p.ID)
	}
	evs, err := r.securityEvents(ctx)
	if err != nil {
		return nil, err
	}
	for _, e := range evs {
		if e.Kind != "request-received" {
			continue
		}
		first, _, _ := strings.Cut(e.Detail, " ")
		if b, err := hex.DecodeString(first); err == nil && len(b) == len(party.MessageID{}) {
			ids = append(ids, party.MessageID(b))
		}
	}
	return ids, nil
}

func (r *partyRun) securityEvents(ctx context.Context) ([]parties.Event, error) {
	var evs []parties.Event
	err := r.s.Store.View(ctx, func(rd ports.Reader) error {
		var err error
		evs, err = multisig.Events(rd)
		return err
	})
	return evs, err
}

// reviewCount is how many times a body hash was shown to the operator in this
// workspace (the "request-reviewed" events), the one just recorded included.
func (r *partyRun) reviewCount(ctx context.Context, body [32]byte) (int, error) {
	evs, err := r.securityEvents(ctx)
	if err != nil {
		return 0, err
	}
	n, h := 0, hex.EncodeToString(body[:])
	for _, e := range evs {
		if e.Kind == "request-reviewed" && e.BodyHash == h {
			n++
		}
	}
	return n, nil
}

// signerFor builds the signer role and the id of the request the operator
// named.
func (r *partyRun) signerFor(ctx context.Context, f *signerFlags, idText string) (multisig.Signer, party.MessageID, error) {
	sg, _, err := r.signer(ctx, f.snapshot, r.dirs(f.inbox, f.outbox))
	if err != nil {
		return sg, party.MessageID{}, err
	}
	all, err := r.allRequestIDs(ctx, sg)
	if err != nil {
		return sg, party.MessageID{}, err
	}
	id, err := requestID(all, idText)
	return sg, id, err
}

// signerFlags are the flags every command that builds the signer shares.
type signerFlags struct {
	snapshot, inbox, outbox string
	chain                   chainFlags
	full                    bool // review and approve: show everything, unfolded
}

func (f *signerFlags) addFull(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&f.full, "full", false, "show every input, output and metadata entry, unfolded (the default folds long lists and the metadata to their first entries). The summary block is bounded per category: a category beyond its bound is refused in the block and approve then needs --full")
}

func (f *signerFlags) add(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.snapshot, "own-snapshot", "", "an offline snapshot (a transfer file) that YOU took on this machine, used as this signer's own view of the UTxOs. Never a file a coordinator or any other party sent: refused when it is in the sealed workspace, the party directories, a link, or not yours alone. Without it, light mode uses its own provider and offline mode has none")
	cmd.Flags().StringVar(&f.inbox, "inbox", "", "the inbox directory (default: [party] inbox in spo.toml, else party/inbox in the workspace)")
	cmd.Flags().StringVar(&f.outbox, "outbox", "", "the outbox directory (default: [party] outbox in spo.toml, else party/outbox in the workspace)")
	addChainFlags(cmd, &f.chain, false)
}

var signerNeeds = []Need{CapClock, CapGenesis, CapTxView, CapSigners}

// ---- requests, review, approve, refuse ------------------------------------------------------

func (a *app) partyRequestsCommand() *cobra.Command {
	var f signerFlags
	cmd := &cobra.Command{
		Use:   "requests",
		Short: "List the signing requests waiting for a decision",
		Long: `List the requests that wait for you, with how each arrived (file or network).
Nothing from the body is shown here: read it with spo party review ID. A request
refused automatically, for a reason that depends on what this machine holds, is
not listed: it is in spo party events.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.party(cmd, &f.chain, signerNeeds, func(ctx context.Context, r *partyRun) error {
				sg, _, err := r.signer(ctx, f.snapshot, r.dirs(f.inbox, f.outbox))
				if err != nil {
					return err
				}
				pending, err := sg.Pending(ctx)
				if err != nil {
					return err
				}
				closed, err := sg.Closed(ctx)
				if err != nil {
					return err
				}
				w := a.d.Out
				if len(pending) == 0 {
					fmt.Fprintln(w, "No request is waiting for you.")
				}
				for _, p := range pending {
					fmt.Fprintf(w, "%x  from %s  %s key  collection %.8s slot %d  arrived by %s  expires %s\n", p.ID[:], safeText(p.From), p.Role,
						p.Collection, p.Slot, p.Via, p.Expires.UTC().Format("2006-01-02 15:04 MST"))
				}
				if len(pending) > 0 {
					fmt.Fprintln(w, "Read one with: spo party review ID")
				}
				// Requests the coordinator closed with a notice, or that a rotation
				// closed, are not waiting for you (SPO-Xparty-INV-036).
				if len(closed) > 0 {
					fmt.Fprintln(w, "Closed before you decided, so not waiting for you (the coordinator must ask again if it still wants the signature):")
					for _, c := range closed {
						fmt.Fprintf(w, "  closed (%s)  %x  from %s  %s key  collection %.8s slot %d\n", c.Outcome, c.ID[:], safeText(c.From), c.Role, c.Collection, c.Slot)
					}
				}
				return nil
			})
		},
	}
	f.add(cmd)
	return cmd
}

func (a *app) partyReviewCommand() *cobra.Command {
	var f signerFlags
	cmd := &cobra.Command{
		Use:   "review ID",
		Short: "Show a signing request in full: what the transaction does and whose money moves",
		Long: `Decode the request from its own bytes and show it in full: the flow (your own
inputs, your own outputs, withdrawals, refunds, deposits, the net that leaves
you, the value that goes to others), the scope parts, how the request arrived,
every input, output, certificate and the metadata. What it shows is worked out
here from your own keys and your own view of the chain, never from what the
coordinator says. Nothing is signed. ID is the request id or a prefix of it
that no other request of this workspace shares (answered and refused ones
count), from spo party requests.

The long parts (inputs, outputs, the decoded body, metadata) are folded to
their first entries; --full shows them all. The summary block that ends the
review states what the witness authorises: the net and net assets, the outputs
to others, every certificate, vote, required signer and withdrawal, and every
warning. A category with more items than the block lists is refused there, and
spo party approve then needs --full.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.party(cmd, &f.chain, signerNeeds, func(ctx context.Context, r *partyRun) error {
				sg, id, err := r.signerFor(ctx, &f, args[0])
				if err != nil {
					return err
				}
				rv, err := sg.ReviewRequest(ctx, id)
				if err != nil {
					return reviewErr(err, args[0])
				}
				_, folded := printReviewSections(a.d.Out, rv, f.full)
				n, err := r.reviewCount(ctx, rv.BodyHash)
				if err != nil {
					return err
				}
				cols, _ := geometry(a.term)
				printSummary(a.d.Out, rv, n <= 1, summaryOpts{cols: cols, full: f.full, label: fmt.Sprintf("%.8x", rv.RequestID[:]), owned: sg.Owned})
				// Last, where it cannot scroll away above the summary: what the
				// fold hid, and that approve will not ask until it was read.
				if len(folded) > 0 {
					fmt.Fprintf(a.d.Out, "!! The review above FOLDED lines of: %s. `spo party approve %.8x` refuses to ask until you give --full. Read them whole with: spo party review %.8x --full\n",
						strings.Join(folded, ", "), rv.RequestID[:], rv.RequestID[:])
				}
				fmt.Fprintf(a.d.Out, "To sign: spo party approve %.8x     To decline: spo party refuse %.8x\n", rv.RequestID[:], rv.RequestID[:])
				return nil
			})
		},
	}
	f.add(cmd)
	f.addFull(cmd)
	return cmd
}

// reviewErr says what to do about a request that cannot be reviewed for
// approval.
func reviewErr(err error, id string) error {
	switch {
	case errors.Is(err, multisig.ErrRequestClosed):
		return fmt.Errorf("%w. See: spo party requests", err)
	case errors.Is(err, multisig.ErrCannotReview):
		return fmt.Errorf("%w. You can still decline it: spo party refuse %s", err, id)
	case errors.Is(err, multisig.ErrNotPending), errors.Is(err, multisig.ErrUnknownRequest):
		return fmt.Errorf("%w: see spo party requests", err)
	}
	return mapSignerErr(err)
}

func (a *app) partyApproveCommand() *cobra.Command {
	var f signerFlags
	var yes bool
	cmd := &cobra.Command{
		Use:   "approve ID",
		Short: "Review a signing request again, answer yes or no, and sign it",
		Long: `Show the review of the request again, then ask: sign it? The default is No. No
flag answers that question (there is no --yes), and without a terminal the
command refuses. It also refuses, before printing, when the summary does not fit
the rows of the terminal (enlarge it) or a category exceeds what the summary
lists (use --full). When you answer yes you type the workspace passphrase again,
and only then does the key sign. If anything the review depended on changed
since you read it (the coordinator was revoked, its scope narrowed, your own
UTxOs changed) nothing is signed and you are told to review it again.

The response is queued: carry it with spo party outbox export DIR (file) or
it goes out by spo party connect (tailcat).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if yes {
				return errors.New(approveYesWhy)
			}
			return a.party(cmd, &f.chain, signerNeeds, func(ctx context.Context, r *partyRun) error {
				sg, id, err := r.signerFor(ctx, &f, args[0])
				if err != nil {
					return err
				}
				return a.reviewAndApprove(ctx, r, sg, id, args[0], f.full)
			})
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "not accepted: no flag answers the question")
	cmd.Flags().Lookup("yes").Hidden = true
	f.add(cmd)
	f.addFull(cmd)
	return cmd
}

// reviewAndApprove is the only road to a signature: it reviews, shows the
// review, asks yes or no with default No, and only then makes the Approval
// from that Review and hands it to the signer, whose gate asks for the
// passphrase. There is no other call to Approve in this program (ADR 0005,
// obligation 6).
//
// spec: SPO-Xparty-INV-016, SPO-Xparty-PR-002
func (a *app) reviewAndApprove(ctx context.Context, r *partyRun, sg multisig.Signer, id party.MessageID, label string, full bool) error {
	rv, err := sg.ReviewRequest(ctx, id)
	if err != nil {
		return reviewErr(err, label)
	}
	n, err := r.reviewCount(ctx, rv.BodyHash)
	if err != nil {
		return err
	}
	// The block is laid out for this terminal and checked BEFORE anything is
	// printed: it is never shown with its top scrolled away, and a category it
	// cannot list in full sends the operator through --full.
	cols, rows := geometry(a.term)
	short := fmt.Sprintf("%.8x", rv.RequestID[:])
	sum := buildSummary(rv, n <= 1, summaryOpts{cols: cols, full: full, label: short, owned: sg.Owned,
		promptRows: promptRowsFor(approvePrompt(rv)+" [y/N] ", cols)})
	if err := sum.budgetError(cols, rows, full, short); err != nil {
		return err
	}
	// The review is rendered first and checked: when the default fold hid or
	// clipped any line of the certificates, votes, withdrawals, mint, required
	// signers, treasury or donation, the operator is not asked on a review that
	// did not show them whole.
	var shown strings.Builder
	if folded := printReview(&shown, rv, full); folded > 0 {
		return foldedError(folded, short)
	}
	io.WriteString(a.d.Out, shown.String())
	for _, l := range sum.lines { // last, immediately before the question
		fmt.Fprintln(a.d.Out, l)
	}
	r.gateNote = fmt.Sprintf("request %x, NET %s", rv.RequestID[:4], netText(rv.Flow))
	flushTypedAhead(a.term)
	// The terminal can be resized between the check above and the question:
	// the size is read again immediately before asking, and a block that no
	// longer fits is refused with nothing asked (SPO-Xparty-PR-002).
	atQuestion := geometryOf(a.term)
	if err := sum.stillFits(atQuestion, cols, rv, full, short); err != nil {
		return err
	}
	ok, err := a.askYes(ctx, approvePrompt(rv))
	if err != nil {
		return err
	}
	if !ok {
		fmt.Fprintf(a.d.Out, "Not signed. The request is still waiting; decline it with: spo party refuse %x\n", rv.RequestID[:])
		return nil
	}
	// The operator took time to answer. The size is read again: a terminal that
	// is narrower or shorter than it was at the question may have wrapped or
	// scrolled what the answer was given on, so nothing is signed. A terminal
	// made smaller and back to its size during the question cannot be told
	// from one never touched (SPO-Xparty-PR-002).
	if now := geometryOf(a.term); now.cols < atQuestion.cols || now.rows < atQuestion.rows {
		return fmt.Errorf("the terminal was made smaller while you were answering (%dx%d at the question, %dx%d now), so what you answered on may have wrapped or scrolled. Nothing was signed. Run spo party approve %s again", atQuestion.cols, atQuestion.rows, now.cols, now.rows, short)
	}
	ap, err := rv.Approval()
	if err != nil {
		return err
	}
	if _, err := sg.Approve(ctx, ap); err != nil {
		if errors.Is(err, multisig.ErrReviewStale) {
			return fmt.Errorf("%w\nNothing was signed. Read it again with: spo party review %s", err, label)
		}
		return mapSignerErr(err)
	}
	fmt.Fprintf(a.d.Out, "Signed. The response to %s is queued for the coordinator: spo party outbox export DIR (file), or spo party connect (tailcat).\n", safeText(rv.Coordinator))
	return nil
}

// foldedError is the refusal to ask when the default review folded or clipped
// any line of the sections that decide a signature: the operator is only ever
// asked after seeing them whole, in the review above or with --full.
func foldedError(folded int, short string) error {
	return fmt.Errorf("the default review folded %d line(s) of the %s: read them whole with `spo party review %s --full`, then approve with `spo party approve %s --full`. Nothing was signed", folded, authorityNames(), short, short)
}

func (a *app) partyRefuseCommand() *cobra.Command {
	var f signerFlags
	var reason string
	cmd := &cobra.Command{
		Use:   "refuse ID [--reason TEXT]",
		Short: "Decline a signing request",
		Long: `Decline the request. The coordinator is told only that you declined; the
reason you give is kept in your own log and never sent, because it would let
a coordinator probe this machine. Declining needs no review: it signs nothing.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.party(cmd, &f.chain, signerNeeds, func(ctx context.Context, r *partyRun) error {
				sg, id, err := r.signerFor(ctx, &f, args[0])
				if err != nil {
					return err
				}
				h, err := sg.Refuse(ctx, id)
				if err != nil {
					return reviewErr(err, args[0])
				}
				if reason != "" {
					_ = r.s.Store.Update(ctx, func(w ports.Writer) error {
						return parties.AppendEvent(w, parties.Event{At: r.env.Clock.Now(), Kind: "request-decline-note", Peer: h.Sender.String(),
							Detail: reason})
					})
				}
				fmt.Fprintf(a.d.Out, "Declined request %x. The coordinator is told that you declined, and nothing else.\n", id[:])
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "why, for your own log (never sent)")
	f.add(cmd)
	return cmd
}
