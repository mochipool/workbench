package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/governance"
	dgov "github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// What the two governance-only policy flags give up. Neither is ever set by a
// mode: the operator names it on the command line.
const (
	anchorUnverifiedHelp = "go on although the anchor document was not checked against CIP-100/108/119 (this build has no verifier): " +
		"the hash is recorded as given. A document that does not match its hash or its schema is accepted by the chain " +
		"and may make the vote or proposal unreadable to the voters. The summary says the anchor was not checked"
	anchorUnverifiedNote = "the anchor document was not checked against CIP-100/108/119 (--anchor-unverified); the hash is recorded as given"
	singleSourceGovHelp  = "accept a read that rests on ONE chain source: the deposit a DRep refund is computed from, or the committee state a resignation rests on, " +
		"with no second independent source to corroborate it. A false answer from one provider can cost the deposit. " +
		"The summary says the read rested on a single source"
	allowUnverifiedGovHelp = "go on when the registration of the deposit-return stake address cannot be checked (no reader in this mode, " +
		"or the source does not know the answer). A wrong answer only makes the ledger reject the transaction. The summary lists the check that was skipped"
)

// govOpts says which of the shared flags a governance command offers.
type govOpts struct {
	tx           bool // --message, --yes, chain flags and --transfer-file
	anchor       bool // --anchor-url, --anchor-hash
	unverified   bool // --anchor-unverified
	single       bool // --single-source
	allow        bool // --allow-unverified
	anchorClear  bool // --allow-anchor-clear
	unrestricted bool // --allow-unrestricted (hardware wallets)
	chainOnly    bool // chain flags without a transfer file
	anchorOfWhat string
}

// govFlags are the flags the governance commands share. Nothing here is
// on by default.
type govFlags struct {
	opts  govOpts
	chain chainFlags

	messages         []string
	extra            extraFlags
	yes              bool
	anchorURL        string
	anchorHash       string
	anchorUnverified bool
	singleSource     bool
	allowUnverified  bool
	allowAnchorClear bool
	unrestricted     bool
}

func (f *govFlags) add(cmd *cobra.Command, o govOpts) {
	f.opts = o
	fl := cmd.Flags()
	if o.tx {
		fl.StringArrayVar(&f.messages, "message", nil, "CIP-20 message line, at most 64 bytes (repeatable)")
		fl.BoolVar(&f.yes, "yes", false, "approve without asking (the summary is still printed)")
		f.extra.add(cmd, &f.messages, extraCert)
	}
	if o.anchor {
		what := o.anchorOfWhat
		if what == "" {
			what = "the document"
		}
		fl.StringVar(&f.anchorURL, "anchor-url", "", "URL of the CIP-100 anchor document of "+what+" (https:// or ipfs://, at most 128 characters); needs --anchor-hash where the document cannot be fetched")
		fl.StringVar(&f.anchorHash, "anchor-hash", "", "blake2b-256 hash of the anchor document, 64 hex digits; when the document is fetched its own hash replaces this one")
	}
	if o.anchorClear {
		fl.BoolVar(&f.allowAnchorClear, "allow-anchor-clear", false, "let an update without an anchor replace the anchor the DRep has on chain with none")
	}
	if o.unrestricted {
		fl.BoolVar(&f.unrestricted, "allow-unrestricted", false, unrestrictedHelp)
	}
	if o.unverified {
		fl.BoolVar(&f.anchorUnverified, "anchor-unverified", false, anchorUnverifiedHelp)
	}
	if o.single {
		fl.BoolVar(&f.singleSource, "single-source", false, singleSourceGovHelp)
	}
	if o.allow {
		fl.BoolVar(&f.allowUnverified, "allow-unverified", false, allowUnverifiedGovHelp)
	}
	if o.tx || o.chainOnly {
		addChainFlags(cmd, &f.chain, true)
	}
}

func (f *govFlags) policy() governance.SourcePolicy {
	if f.singleSource {
		return governance.SingleSourceAcknowledged
	}
	return governance.RequireCorroboration
}

// hint adds to a refusal the flag that would let the operator go on, and
// what it gives up. A flag the operator already gave is not suggested.
func (f *govFlags) hint(err error) error {
	if err == nil {
		return nil
	}
	var h string
	switch {
	case errors.Is(err, governance.ErrDeclined):
		return fmt.Errorf("%w: nothing was signed, submitted or queued", err)
	case f.opts.single && !f.singleSource && errors.Is(err, governance.ErrSingleSource):
		h = "pass --single-source to go on with one source: a false answer from one provider can cost the deposit; the summary will say so"
	case f.opts.unverified && !f.anchorUnverified && errors.Is(err, governance.ErrAnchorVerifierMissing):
		h = "pass --anchor-unverified to go on: the anchor document was not checked against CIP-100/108/119; the hash is recorded as given"
	case f.opts.allow && !f.allowUnverified && (errors.Is(err, governance.ErrNoChainReader) || errors.Is(err, governance.ErrUnverified)):
		h = "pass --allow-unverified to go on without that check (an unchecked answer only makes the ledger reject the transaction); the summary lists the check that was skipped"
	case f.opts.anchorClear && !f.allowAnchorClear && errors.Is(err, governance.ErrAnchorWouldBeCleared):
		h = "pass --allow-anchor-clear to replace the anchor with none, or give --anchor-url and --anchor-hash"
	case f.opts.anchor && (errors.Is(err, governance.ErrAnchorNotChecked) || errors.Is(err, dgov.ErrAnchorPair)):
		h = "give both --anchor-url and --anchor-hash: the document cannot be fetched in this mode, so the hash is taken as given"
	case errors.Is(err, governance.ErrOfflineUnsupported):
		h = "this workflow reads the chain: run it in light mode (spo mode set light), not offline"
	default:
		return err
	}
	return &explained{msg: err.Error() + "\n" + h, err: err}
}

// ---- the confirmer ---------------------------------------------------------------------

// govConfirmer is the terminal confirmer of the governance transactions. It
// shows the summary the use case provides, the details the command read from
// the workspace's public files (the DRep id, the anchors, the votes and the
// proposals as files hold them) and the notes of the policy the operator
// acknowledged. The default answer is No.
type govConfirmer struct {
	a       *app
	details []string
	notes   []string
}

func (c govConfirmer) Confirm(ctx context.Context, sum ports.TxSummary) (bool, error) {
	sum.Unchecked = append(append([]string(nil), sum.Unchecked...), c.notes...)
	printStakeSummary(c.a.d.Out, sum)
	printDetails(c.a.d.Out, c.details)
	ans, err := c.a.term.ReadLine(ctx, "Sign and "+routeVerb(sum.Route)+" this transaction? [y/N] ")
	if errors.Is(err, ErrNoTerminal) {
		return false, errors.New("no terminal to ask on; pass --yes to approve without asking")
	}
	if err != nil {
		return false, err
	}
	ans = strings.ToLower(strings.TrimSpace(ans))
	return ans == "y" || ans == "yes", nil
}

func printDetails(w io.Writer, lines []string) {
	if len(lines) == 0 {
		return
	}
	fmt.Fprintln(w, "Details")
	for _, l := range lines {
		fmt.Fprintf(w, "  %s\n", shown(l))
	}
	fmt.Fprintln(w)
}

// govBase is the shared base of the governance transaction use cases.
func (a *app) govBase(s *session, env *Env, f *govFlags, conf govConfirmer) governance.Base {
	p := a.pipeline(s, env, f.yes)
	p.Confirmer = conf
	return governance.Base{
		Store: s.Store, Addresses: env.AddressInspector, Params: env.Params, Tip: env.Tip, Utxos: env.Utxos,
		Pipeline: p, NetworkID: env.NetworkID,
		Files: env.MetadataFiles, Encrypter: env.MsgEncrypter,
	}
}

// govTxNeeds are the needs of every governance transaction.
func govTxNeeds(extra ...Need) []Need { return stakeTxNeeds(extra...) }

// govOutcome is what a governance transaction command reports.
type govOutcome struct {
	kind    string
	account string
	payer   string
	res     governance.Result
	// stored are the artefacts written, by name.
	stored  []ports.Ref
	details []string
	notes   []string
	// extra lines printed last (the ids the proposals will have).
	extra []string
}

func (a *app) govReport(o govOutcome, f *govFlags, env *Env, wo WireOptions) {
	w := a.d.Out
	if o.res.ApprovalSkipped {
		// The summary the use case prepared (attachments, deposit, refund, the
		// payer's address) with the result's figures: the same the interactive
		// confirmation shows.
		sum := o.res.Summary
		sum.Kind, sum.Account, sum.Source = o.kind, o.account, o.payer
		sum.Inputs, sum.Outputs, sum.Fee, sum.TTL = o.res.Inputs, o.res.Outputs, o.res.Fee, o.res.TTL
		sum.Message, sum.Size, sum.TxID, sum.Route = f.messages, o.res.Size, o.res.TxID, routeName(o.res.Queued)
		sum.Sources, sum.SingleSource = o.res.Sources, o.res.SingleSource
		sum.Unchecked = append(append([]string(nil), o.res.Unchecked...), o.notes...)
		if o.res.Deposit != 0 || sum.Deposit == 0 {
			sum.Deposit = o.res.Deposit
		}
		if o.res.Refund != 0 || sum.Refund == 0 {
			sum.Refund = o.res.Refund
		}
		printStakeSummary(w, sum)
		printDetails(w, o.details)
	}
	for _, d := range o.res.Decisions {
		fmt.Fprintf(w, "Decision: %s.\n", shown(d))
	}
	switch {
	case o.res.Submitted:
		fmt.Fprintf(w, "Submitted transaction %s through %s.\n", o.res.TxID, env.Source(CapSubmit))
	case o.res.Queued:
		fmt.Fprintf(w, "Queued transaction %s in %s. Submit it from an online machine.\n", o.res.TxID, wo.TransferFile)
	}
	for _, l := range o.extra {
		fmt.Fprintln(w, shown(l))
	}
	for _, r := range o.stored {
		fmt.Fprintf(w, "Stored %s.\n", artefact(r))
	}
}

// ---- text helpers --------------------------------------------------------------------------

func anchorText(a dgov.Anchor) string {
	if a.IsZero() {
		return "none"
	}
	return fmt.Sprintf("%s (hash %s)", shown(a.URL), a.HashHex())
}

func credText(c dgov.Credential) string {
	if c.Script {
		return fmt.Sprintf("%x (script)", c.Hash[:])
	}
	return fmt.Sprintf("%x", c.Hash[:])
}

// readPublic reads one stored public artefact; it returns nil when it is
// missing, because the details are a courtesy and the use case reports the
// real refusal.
func readPublic(ctx context.Context, st ports.Store, ref ports.Ref) []byte {
	var out []byte
	_ = st.View(ctx, func(r ports.Reader) error {
		b, err := r.Get(ref)
		if err == nil {
			out = b
		}
		return nil
	})
	return out
}

// govGroup is the shape of the nouns that group governance commands.
func govGroup(use, short string, subs ...*cobra.Command) *cobra.Command {
	c := &cobra.Command{Use: use, Short: short}
	c.AddCommand(subs...)
	return c
}
