package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/party"
)

func chainLovelace(n uint64) chain.Lovelace { return chain.Lovelace(n) }

// printTxView writes the decoded body a signer is asked to approve: every
// input, output, certificate, withdrawal, mint, vote and the fee, in full.
// Nothing in it is secret. It prints what the view holds and nothing is
// summarised away: a part the view cannot show in full is refused by the
// use case before this is called.
func printTxView(w io.Writer, v party.TxView) {
	lines, _ := txViewLines(v, false)
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
	fmt.Fprintln(w)
}

// txViewLines is the body as lines. With authorityFirst (the party review) the
// parts that decide a signature come right after the header: certificates,
// votes, withdrawals, mint, required signers, treasury and donation, then the
// outputs, the fee and validity, the inputs and last the metadata hash; so a
// fold of the long tail never hides them. authority is the number of lines up
// to the end of those parts (the header included).
func txViewLines(v party.TxView, authorityFirst bool) (lines []string, authority int) {
	sec := map[string]*strings.Builder{}
	for _, n := range []string{"head", "inputs", "outputs", "fee", "certs", "withdrawals", "mint", "votes", "signers", "aux", "treasury"} {
		sec[n] = &strings.Builder{}
	}
	w := func(n string) *strings.Builder { return sec[n] }
	fmt.Fprintln(w("head"), "Transaction to sign")
	if v.NetworkID != nil {
		fmt.Fprintf(w("head"), "  network id   %d\n", *v.NetworkID)
	}
	b := w("inputs")
	fmt.Fprintf(b, "  inputs       %d\n", len(v.Inputs))
	for _, in := range v.Inputs {
		fmt.Fprintf(b, "    %x#%d\n", in.TxID[:], in.Index)
	}
	b = w("outputs")
	fmt.Fprintf(b, "  outputs      %d\n", len(v.Outputs))
	for _, o := range v.Outputs {
		fmt.Fprintf(b, "    %s  %s\n", o.Address, lovelaceText(chainLovelace(o.Lovelace)))
		for _, a := range o.Assets {
			fmt.Fprintf(b, "      + %d %x.%x\n", a.Quantity, a.Policy[:], a.Name)
		}
	}
	b = w("fee")
	fmt.Fprintf(b, "  fee          %s\n", lovelaceText(chainLovelace(v.Fee)))
	if v.TTL != nil {
		fmt.Fprintf(b, "  valid until  slot %d\n", *v.TTL)
	}
	if v.ValidFrom != nil {
		fmt.Fprintf(b, "  valid from   slot %d\n", *v.ValidFrom)
	}
	b = w("certs")
	for _, c := range v.Certificates {
		fmt.Fprintf(b, "  certificate  %s", c.Kind)
		if c.Credential != "" {
			fmt.Fprintf(b, "  %s", c.Credential)
		}
		fmt.Fprintln(b)
		if c.HasPool {
			fmt.Fprintf(b, "    pool         %x\n", c.Pool[:])
		}
		if c.DRep != "" {
			fmt.Fprintf(b, "    drep         %s\n", c.DRep)
		}
		if c.HotCredential != "" {
			fmt.Fprintf(b, "    hot key      %s\n", c.HotCredential)
		}
		if c.Deposit != nil {
			fmt.Fprintf(b, "    deposit      %s\n", lovelaceText(chainLovelace(*c.Deposit)))
		}
		if c.Epoch != nil {
			fmt.Fprintf(b, "    retires at   epoch %d\n", *c.Epoch)
		}
		if c.Anchor != nil {
			fmt.Fprintf(b, "    anchor       %s (hash %x)\n", shown(c.Anchor.URL), c.Anchor.Hash[:])
		}
		if r := c.PoolReg; r != nil {
			fmt.Fprintf(b, "    operator     %x\n    vrf key      %x\n    pledge       %s\n    cost         %s\n    margin       %d/%d\n    rewards to   %s\n",
				r.Operator[:], r.VRFKeyHash[:], lovelaceText(chainLovelace(r.Pledge)), lovelaceText(chainLovelace(r.Cost)), r.MarginNum, r.MarginDen, r.RewardAccount)
			for _, o := range r.Owners {
				fmt.Fprintf(b, "    owner        %x\n", o[:])
			}
			for _, rl := range r.Relays {
				port := ""
				if rl.HasPort {
					port = fmt.Sprintf(":%d", rl.Port)
				}
				fmt.Fprintf(b, "    relay        %s %s%s\n", rl.Kind, shown(rl.Host), port)
			}
			if r.HasMeta {
				fmt.Fprintf(b, "    metadata     %s (hash %x)\n", shown(r.MetaURL), r.MetaHash[:])
			}
		}
	}
	b = w("withdrawals")
	for _, x := range v.Withdrawals {
		fmt.Fprintf(b, "  withdrawal   %s  %s\n", x.Account, lovelaceText(chainLovelace(x.Lovelace)))
	}
	b = w("mint")
	for _, m := range v.Mint {
		fmt.Fprintf(b, "  mint         %d %x.%x\n", m.Quantity, m.Policy[:], m.Name)
	}
	b = w("votes")
	for _, vt := range v.Votes {
		fmt.Fprintf(b, "  vote         %s on %x#%d: %s\n", vt.Voter, vt.ActionTx[:], vt.ActionIx, vt.Vote)
		if vt.Anchor != nil && authorityFirst { // a vote anchor is shown in the party review only
			fmt.Fprintf(b, "    anchor       %s (hash %x)\n", shown(vt.Anchor.URL), vt.Anchor.Hash[:])
		}
	}
	b = w("signers")
	for _, s := range v.RequiredSigners {
		fmt.Fprintf(b, "  must sign    %x\n", s[:])
	}
	if v.AuxDataHash != nil {
		fmt.Fprintf(w("aux"), "  metadata     hash %x\n", v.AuxDataHash[:])
	}
	b = w("treasury")
	if v.TreasuryValue != nil {
		fmt.Fprintf(b, "  treasury     %s\n", lovelaceText(chainLovelace(*v.TreasuryValue)))
	}
	if v.Donation != nil {
		fmt.Fprintf(b, "  donation     %s\n", lovelaceText(chainLovelace(*v.Donation)))
	}
	order := []string{"head", "inputs", "outputs", "fee", "certs", "withdrawals", "mint", "votes", "signers", "aux", "treasury"}
	authorityEnd := 0
	if authorityFirst {
		order = []string{"head", "certs", "votes", "withdrawals", "mint", "signers", "treasury", "outputs", "fee", "inputs", "aux"}
		authorityEnd = 7
	}
	var all []string
	for i, n := range order {
		if t := strings.TrimSuffix(sec[n].String(), "\n"); t != "" {
			all = append(all, strings.Split(t, "\n")...)
		}
		if authorityFirst && i == authorityEnd-1 {
			authority = len(all)
		}
	}
	return all, authority
}
