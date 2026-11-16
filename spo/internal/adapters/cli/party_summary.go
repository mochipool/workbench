package cli

import (
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/platform/textsafe"
)

// The summary block is what a key witness authorises, laid out in SCREEN ROWS
// for the real terminal. Per category it lists up to a fixed number of items;
// when a category has more, the block says so in a line that refuses to
// summarise it, and approve then requires --full, so that bounded never means
// hidden: every item of a category is in the block, or the operator is forced
// through the full display and told so (SPO-Xparty-PR-002, PR-003).
const (
	sumMaxCerts     = 6
	sumMaxVotes     = 4
	sumMaxSigners   = 4
	sumMaxWithdraw  = 4
	sumMaxMint      = 4
	sumMaxNetAssets = 4
	sumMaxOutputs   = 4
	sumMaxOwners    = 4 // per pool registration
	sumMaxRelays    = 3 // per pool registration
	sumMaxLabels    = 8

	// Fallback terminal size when the driver reports none.
	defaultCols, defaultRows = 80, 24
	minCols                  = 44
	// The rows the block may not use: the question itself (which can wrap)
	// and the line the operator typed the command on.
	reservedRows = 4

	addrKeep = 12 // first and last characters of an elided address
)

// sizer is a terminal that reports its size. It is optional: the TUI's
// terminal reports the size of the pane the output is drawn in, a tty reports
// its window, anything else reports nothing and the block is laid out for 80
// by 24.
type sizer interface {
	Size() (cols, rows int, ok bool)
}

// Size is the window of the terminal descriptor, when it is one.
func (t ttyTerminal) Size() (int, int, bool) {
	ws, err := unix.IoctlGetWinsize(t.fd, unix.TIOCGWINSZ)
	if err != nil || ws.Col == 0 || ws.Row == 0 {
		return 0, 0, false
	}
	return int(ws.Col), int(ws.Row), true
}

// geometry is the size the block is laid out for.
func geometry(t Terminal) (cols, rows int) {
	if s, ok := t.(sizer); ok {
		if c, r, ok := s.Size(); ok && c > 0 && r > 0 {
			return c, r
		}
	}
	return defaultCols, defaultRows
}

// summary is a laid-out block: every line fits the width it was built for, so
// len(lines) is the number of screen rows it takes. Overflow names the
// categories it refuses to summarise.
type summary struct {
	lines    []string
	overflow []string
	// reserved is the rows the block may not use (the question as wrapped in
	// the terminal it was laid out for, the answer line and one more).
	reserved int
}

type summaryOpts struct {
	cols  int
	full  bool   // the full review was printed above this block
	label string // the request id prefix a command line names
	// owned is every payment and stake key of this workspace, so a credential
	// is marked against all of them and not only against the key asked for.
	owned party.OwnedKeys
	// promptRows is how many rows the question takes in this terminal; 0 means
	// the usual two.
	promptRows int
}

// promptRowsFor is the screen rows a question takes at cols columns: counted
// conservatively (a wide rune counts two), never less than one.
func promptRowsFor(q string, cols int) int {
	if cols < 1 {
		cols = 1
	}
	return max((textWidth(q)+cols-1)/cols, 1)
}

// quoted is attacker-chosen text in double quotes with nothing that could
// forge a line, a space, a quote or a control character left raw: a URL or a
// host name is one word, whole.
func quoted(s string) string { return textsafe.Quote(s) }

// width is the columns a rune takes, counted conservatively: anything that is
// not ASCII may be two wide.
func width(r rune) int {
	if r < 0x80 {
		return 1
	}
	return 2
}

func textWidth(s string) int {
	n := 0
	for _, r := range s {
		n += width(r)
	}
	return n
}

// layout writes text word-wrapped to cols, the first row after prefix and
// the others indented by cont. A word longer than a row is split, never clipped.
func layout(prefix, cont, text string, cols int) []string {
	var rows []string
	cur := prefix
	curW := textWidth(prefix)
	blank := true // nothing but the prefix on the row
	flush := func() {
		rows = append(rows, cur)
		cur, curW, blank = cont, textWidth(cont), true
	}
	for _, word := range strings.Fields(text) {
		ww := textWidth(word)
		sep := 1
		if blank {
			sep = 0
		}
		if curW+sep+ww <= cols {
			if sep == 1 {
				cur += " "
			}
			cur += word
			curW += sep + ww
			blank = false
			continue
		}
		if !blank {
			flush()
		}
		for textWidth(word) > cols-curW {
			room := cols - curW
			cut, w := 0, 0
			for i, r := range word {
				if w+width(r) > room && i > 0 {
					break
				}
				w += width(r)
				cut = i + len(string(r))
			}
			cur += word[:cut]
			word = word[cut:]
			flush()
		}
		cur += word
		curW += textWidth(word)
		blank = false
	}
	if !blank || len(rows) == 0 {
		rows = append(rows, cur)
	}
	return rows
}

// adaText is an amount to the lovelace, short.
func adaText(n uint64) string { return fmt.Sprintf("%d.%06d ADA", n/1_000_000, n%1_000_000) }

// elide shows the first and last characters of a long text.
func elide(s string) string {
	r := []rune(s)
	if len(r) <= 2*addrKeep+3 {
		return s
	}
	return string(r[:addrKeep]) + "..." + string(r[len(r)-addrKeep:])
}

func sumAsset(policy [28]byte, name []byte) string {
	t := fmt.Sprintf("%x.%x", policy[:], name)
	if len(name) > 0 {
		t += " (name " + safeText(string(name)) + ")"
	}
	return t
}

// rewardKeyHash is the key hash of a stake (reward) address, when it has one.
func rewardKeyHash(account string) ([28]byte, bool) {
	_, data, err := chain.Bech32Decode(account)
	if err != nil || len(data) != 29 || data[0]>>4 != 0xe {
		return [28]byte{}, false
	}
	return [28]byte(data[1:]), true
}

type owner struct {
	key   string
	owned party.OwnedKeys
}

// markHex says whether a bare hex hash is the key this witness is for, another
// payment or stake key of this workspace, or not the operator's at all.
func (o owner) markHex(h string) string {
	if h == o.key {
		return " (this key)"
	}
	if b, err := hex.DecodeString(h); err == nil && len(b) == 28 {
		k := [28]byte(b)
		if o.owned.OwnsStake(k) || o.owned.OwnsPayment(k) {
			return " (another key of yours)"
		}
	}
	return " (not yours)"
}

// mark is markHex for a credential text ("key:<hex>", "drep-key:<hex>",
// "pool:<hex>") or a bare hex hash.
//
// Only a KEY credential can be the operator's: a script credential whose hash
// happens to equal one of the operator's key hashes is not that key, and is
// never marked as theirs.
func (o owner) mark(text string) string {
	if i := strings.LastIndexByte(text, ':'); i >= 0 {
		if strings.Contains(text[:i], "script") {
			return " (not yours)"
		}
		text = text[i+1:]
	}
	return o.markHex(text)
}

// thisKey marks only the key this witness is for: where the unmarked reading
// is the ordinary one (a pool's operator, a cold key this store does not list).
func (o owner) thisKey(h []byte) string {
	if hex.EncodeToString(h) == o.key {
		return " (this key)"
	}
	return ""
}

// credential is a credential text with its mark. The signer's own is cut to
// its first characters: the key line above carries it whole.
func (o owner) credential(c string) string {
	m := o.mark(c)
	if m == " (this key)" {
		if i := strings.LastIndexByte(c, ':'); i >= 0 && len(c)-i-1 > 8 {
			return escapeUnsafe(c[:i+1+8]) + "..." + m
		}
	}
	return escapeUnsafe(c) + m
}

func (o owner) markHash(h [28]byte) string { return o.markHex(hex.EncodeToString(h[:])) }

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// buildSummary lays out what this witness authorises: the request, the net,
// the outputs to others, and one line group per certificate, vote, required
// signer, withdrawal and mint, each category bounded and refusing to summarise
// beyond its bound.
//
// spec: SPO-Xparty-PR-002, SPO-Xparty-PR-003
func buildSummary(rv multisig.Review, firstTime bool, o summaryOpts) summary {
	cols := o.cols
	var s summary
	s.reserved = 2 + max(o.promptRows, 2)
	add := func(prefix, cont, text string) { s.lines = append(s.lines, layout(prefix, cont, text, cols)...) }
	key := hex.EncodeToString(rv.KeyHash[:])
	me := owner{key: key, owned: o.owned}
	v, fl := rv.View, rv.Flow

	// bound lists up to max items of one category; beyond it, a refusal line.
	bounded := func(name string, n, max int, item func(i int)) {
		for i := 0; i < n && i < max; i++ {
			item(i)
		}
		if n <= max {
			return
		}
		s.overflow = append(s.overflow, name)
		how := fmt.Sprintf("run `spo party review %s --full` and read all of them", o.label)
		if o.full {
			how = "all of them are in the full review printed above: read all of them"
		}
		add("!! ", "   ", fmt.Sprintf("%d %s: more than this summary shows (first %d listed, and %d more not shown); %s", n, name, max, n-max, how))
	}

	add("=== SUMMARY  ", "    ", fmt.Sprintf("request %x", rv.RequestID[:]))
	body := fmt.Sprintf("%x", rv.BodyHash[:])
	if cols >= len("body hash ")+64 {
		add("body hash ", "", body)
	} else {
		s.lines = append(s.lines, "body hash "+body[:32], "          "+body[32:])
	}
	first := ""
	if firstTime {
		first = "; first time this body is shown here"
	}
	add("from ", "     ", fmt.Sprintf("%s via %s%s", safeText(rv.Coordinator), rv.Via, first))
	add("key  ", "     ", fmt.Sprintf("%s %s", rv.Role, key))
	add("NET  ", "     ", netShort(fl))

	bounded("net assets", len(fl.NetAssets), sumMaxNetAssets, func(i int) {
		a := fl.NetAssets[i]
		q, dir := a.Quantity, "leaves you"
		if q < 0 {
			q, dir = -q, "arrives to you"
		}
		add("  asset ", "        ", fmt.Sprintf("%d %s %s", q, sumAsset(a.Policy, a.Name), dir))
	})

	// outputs that are not the signer's
	var others []party.FlowOutput
	for _, out := range fl.Outputs {
		if !out.Own {
			others = append(others, out)
		}
	}
	elided := false
	for _, out := range others[:min(len(others), sumMaxOutputs)] {
		if elide(escapeUnsafe(out.Address)) != escapeUnsafe(out.Address) {
			elided = true
		}
	}
	note := ""
	if elided {
		note = " (shortened; the body above has it whole)"
	}
	add("to others  ", "            ", fmt.Sprintf("%s in %d %s%s", adaText(fl.ToOthersLovelace), len(others), plural(len(others), "output", "outputs"), note))
	bounded("outputs to others", len(others), sumMaxOutputs, func(i int) {
		out := others[i]
		tail := ""
		if len(out.Assets) > 0 {
			tail = fmt.Sprintf(" + %d %s", len(out.Assets), plural(len(out.Assets), "asset", "assets"))
		}
		add("  to ", "     ", elide(escapeUnsafe(out.Address))+" "+adaText(out.Lovelace)+tail)
	})
	if v.Donation != nil {
		add("donation  ", "          ", adaText(*v.Donation)+" given to the treasury")
	}
	if v.TreasuryValue != nil {
		add("treasury  ", "          ", adaText(*v.TreasuryValue)+" stated")
	}

	ttl := "ttl none (valid with no upper limit)"
	if v.TTL != nil {
		ttl = fmt.Sprintf("ttl slot %d", *v.TTL)
	}
	add("fee  ", "     ", adaText(v.Fee)+"; "+ttl)
	if rv.Aux != nil {
		var labels []string
		for _, l := range rv.Aux.Labels[:min(len(rv.Aux.Labels), sumMaxLabels)] {
			labels = append(labels, strconv.FormatUint(l.Label, 10))
		}
		list := strings.Join(labels, ", ")
		if n := len(rv.Aux.Labels) - sumMaxLabels; n > 0 {
			list += fmt.Sprintf(", and %d more", n) // only their numbers: the contents are in the review
		}
		add("metadata attached: ", "    ", fmt.Sprintf("%d %s [%s]", len(rv.Aux.Labels), plural(len(rv.Aux.Labels), "label", "labels"), list))
	} else if v.AuxDataHash != nil {
		add("metadata attached: ", "    ", fmt.Sprintf("yes, contents not decoded here (hash %x)", v.AuxDataHash[:]))
	}

	bounded("certificates", len(v.Certificates), sumMaxCerts, func(i int) { addCert(add, bounded, me, i+1, v.Certificates[i]) })
	bounded("votes", len(v.Votes), sumMaxVotes, func(i int) {
		vt := v.Votes[i]
		add(fmt.Sprintf("vote %d  ", i+1), "    ", fmt.Sprintf("%s%s votes %s on action %x#%d", escapeUnsafe(vt.Voter), me.mark(vt.Voter), escapeUnsafe(vt.Vote), vt.ActionTx[:], vt.ActionIx))
		addAnchor(add, vt.Anchor)
	})
	bounded("required signers", len(v.RequiredSigners), sumMaxSigners, func(i int) {
		sg := v.RequiredSigners[i]
		add("must sign  ", "           ", fmt.Sprintf("%x%s", sg[:], me.markHash(sg)))
	})
	bounded("withdrawals", len(v.Withdrawals), sumMaxWithdraw, func(i int) {
		x := v.Withdrawals[i]
		yours := " (not your signing key's account)"
		if h, ok := rewardKeyHash(x.Account); ok {
			yours = me.markHash(h)
		}
		add("withdraw  ", "          ", fmt.Sprintf("%s from %s%s", adaText(x.Lovelace), escapeUnsafe(x.Account), yours))
	})
	// A mint is refused before a review exists (Undisplayable); listed anyway
	// so that a view that holds one is never summarised without it.
	bounded("mint or burn entries", len(v.Mint), sumMaxMint, func(i int) {
		m := v.Mint[i]
		verb, q := "mint", m.Quantity
		if q < 0 {
			verb, q = "burn", -q
		}
		add(verb+"  ", "      ", fmt.Sprintf("%d %s", q, sumAsset(m.Policy, m.Name)))
	})

	if !fl.Checked {
		add("!! ", "   ", "your inputs NOT checked: full text above (\"Whose money moves\")")
	}
	if fl.PaymentWitnessElsewhere {
		add("!! ", "   ", "spends your payment UTxOs; this key does not authorise it (above)")
	}
	if fl.UnstatedDeposits > 0 {
		add("!! ", "   ", fmt.Sprintf("%d deposit or refund %s not in the body (a protocol parameter)", fl.UnstatedDeposits, plural(fl.UnstatedDeposits, "amount is", "amounts are")))
	}
	return s
}

// addAnchor is a certificate's or a vote's anchor: its URL quoted whole and
// its hash whole.
func addAnchor(add func(prefix, cont, text string), a *party.ViewAnchor) {
	if a != nil {
		add("  anchor ", "  ", fmt.Sprintf("%s hash %x", quoted(a.URL), a.Hash[:]))
	}
}

func addCert(add func(prefix, cont, text string), bounded func(string, int, int, func(int)), me owner, n int, c party.ViewCert) {
	var p []string
	if c.Credential != "" {
		p = append(p, "on "+me.credential(c.Credential))
	}
	if c.HasPool && c.PoolReg == nil { // a registration names its pool as the operator, below
		t := "pool " + chain.PoolID(c.Pool).Bech32()
		if c.Kind == party.CertPoolRetirement || c.Kind == party.CertPoolRegistration {
			t += me.thisKey(c.Pool[:])
		}
		p = append(p, t)
	}
	if c.Epoch != nil {
		p = append(p, fmt.Sprintf("retires at epoch %d", *c.Epoch))
	}
	if c.DRep != "" {
		t := "drep " + escapeUnsafe(c.DRep)
		if strings.Contains(c.DRep, ":") {
			t += me.mark(c.DRep)
		}
		p = append(p, t)
	}
	if c.HotCredential != "" {
		p = append(p, "hot key "+escapeUnsafe(c.HotCredential)+me.mark(c.HotCredential))
	}
	switch {
	case c.Deposit != nil:
		verb := "deposit"
		if c.Kind == party.CertStakeDeregistration || c.Kind == party.CertDRepDeregistration {
			verb = "refund"
		}
		p = append(p, verb+" "+adaText(*c.Deposit))
	}
	add(fmt.Sprintf("cert %d  ", n), "    ", escapeUnsafe(c.Kind)+" "+strings.Join(p, "; "))
	addAnchor(add, c.Anchor)
	if r := c.PoolReg; r != nil {
		pre, cont := "  ", "  "
		add(pre, cont, "operator "+chain.PoolID(r.Operator).Bech32()+me.thisKey(r.Operator[:]))
		add(pre, cont, "vrf key "+hex.EncodeToString(r.VRFKeyHash[:]))
		add(pre, cont, fmt.Sprintf("pledge %s; cost %s; margin %d/%d", adaText(r.Pledge), adaText(r.Cost), r.MarginNum, r.MarginDen))
		mark := " (not yours)"
		if h, ok := rewardKeyHash(r.RewardAccount); ok {
			mark = me.markHash(h)
		}
		add(pre, cont, "reward "+escapeUnsafe(r.RewardAccount)+mark)
		bounded(fmt.Sprintf("pool owners of certificate %d", n), len(r.Owners), sumMaxOwners, func(i int) {
			add(pre, cont, fmt.Sprintf("owner %x%s", r.Owners[i][:], me.markHash(r.Owners[i])))
		})
		if len(r.Relays) == 0 {
			add(pre, cont, "relays none")
		}
		bounded(fmt.Sprintf("pool relays of certificate %d", n), len(r.Relays), sumMaxRelays, func(i int) {
			rl := r.Relays[i]
			port := ""
			if rl.HasPort {
				port = fmt.Sprintf(":%d", rl.Port)
			}
			add(pre, cont, fmt.Sprintf("relay %d of %d %s %s%s", i+1, len(r.Relays), escapeUnsafe(rl.Kind), quoted(rl.Host), port))
		})
		if r.HasMeta {
			add(pre, cont, "metadata url "+quoted(r.MetaURL))
			add(pre, cont, "metadata hash "+hex.EncodeToString(r.MetaHash[:]))
		} else {
			add(pre, cont, "no metadata")
		}
	}
}

// netShort is the net in one short phrase.
func netShort(fl party.Flow) string {
	net, dir := fl.NetLovelace, "leaves you"
	if net < 0 {
		net, dir = -net, "arrives to you"
	}
	t := fmt.Sprintf("%s %s", adaText(uint64(net)), dir)
	if fl.NetExcludesInputs {
		t += " (EXCLUDING your inputs, NOT checked)"
	}
	if n := len(fl.NetAssets); n > 0 {
		t += fmt.Sprintf(" + %d net %s", n, plural(n, "asset", "assets"))
	}
	return t
}

// printSummary writes the block and returns it.
func printSummary(w io.Writer, rv multisig.Review, firstTime bool, o summaryOpts) summary {
	s := buildSummary(rv, firstTime, o)
	for _, l := range s.lines {
		fmt.Fprintln(w, l)
	}
	return s
}

// approvePrompt is the question, with the net, the request and the start of
// the body hash in the line the operator answers.
func approvePrompt(rv multisig.Review) string {
	return fmt.Sprintf("NET %s; request %x body %x. Sign this transaction?", netShort(rv.Flow), rv.RequestID[:4], rv.BodyHash[:4])
}

// budgetError is why approve refuses to ask in this terminal, or nil.
func (s summary) budgetError(cols, rows int, full bool, label string) error {
	if cols < minCols {
		return fmt.Errorf("this terminal is %d columns wide: the summary needs at least %d. Enlarge it and run spo party approve %s again", cols, minCols, label)
	}
	if !full && len(s.overflow) > 0 {
		return fmt.Errorf("%s: more than the summary shows. Read all of them with `spo party review %s --full`, then approve with `spo party approve %s --full`", strings.Join(s.overflow, ", "), label, label)
	}
	reserved := s.reserved
	if reserved == 0 {
		reserved = reservedRows
	}
	if need := len(s.lines) + reserved; rows < need {
		fix := fmt.Sprintf("Enlarge the terminal, or use `spo party review %s --full | less` as a pager and approve in a larger terminal", label)
		if full {
			fix = "Enlarge the terminal and approve again (--full is already on)"
		}
		return fmt.Errorf("this request needs a terminal at least %d rows tall; yours has %d (the summary is %d rows, the question and your command line take %d): the top of it would scroll off the screen. %s. Nothing was signed", need, rows, len(s.lines), reserved, fix)
	}
	return nil
}

// size is a terminal's reported size.
type size struct{ cols, rows int }

// geometryOf is geometry as a value.
func geometryOf(t Terminal) size {
	c, r := geometry(t)
	return size{c, r}
}

// stillFits re-checks a block that was printed for printedCols columns
// against the size the terminal has now. A terminal made narrower would wrap
// lines that were laid out to fit, so its row count no longer holds; one made
// shorter would already have scrolled the top of the block away. Both are
// refused with nothing asked.
func (s summary) stillFits(now size, printedCols int, rv multisig.Review, full bool, label string) error {
	if now.cols < printedCols {
		return fmt.Errorf("the terminal was made narrower (%d columns, the summary was laid out for %d) after the summary was printed, so its rows are no longer what was counted. Nothing was signed. Run spo party approve %s again", now.cols, printedCols, label)
	}
	s.reserved = 2 + max(promptRowsFor(approvePrompt(rv)+" [y/N] ", now.cols), 2)
	if err := s.budgetError(now.cols, now.rows, full, label); err != nil {
		return fmt.Errorf("the terminal changed size after the summary was printed: %w", err)
	}
	return nil
}
