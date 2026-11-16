package cli

import (
	"fmt"
	"io"

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
	fmt.Fprintln(w, "Transaction to sign")
	if v.NetworkID != nil {
		fmt.Fprintf(w, "  network id   %d\n", *v.NetworkID)
	}
	fmt.Fprintf(w, "  inputs       %d\n", len(v.Inputs))
	for _, in := range v.Inputs {
		fmt.Fprintf(w, "    %x#%d\n", in.TxID[:], in.Index)
	}
	fmt.Fprintf(w, "  outputs      %d\n", len(v.Outputs))
	for _, o := range v.Outputs {
		fmt.Fprintf(w, "    %s  %s\n", o.Address, lovelaceText(chainLovelace(o.Lovelace)))
		for _, a := range o.Assets {
			fmt.Fprintf(w, "      + %d %x.%x\n", a.Quantity, a.Policy[:], a.Name)
		}
	}
	fmt.Fprintf(w, "  fee          %s\n", lovelaceText(chainLovelace(v.Fee)))
	if v.TTL != nil {
		fmt.Fprintf(w, "  valid until  slot %d\n", *v.TTL)
	}
	if v.ValidFrom != nil {
		fmt.Fprintf(w, "  valid from   slot %d\n", *v.ValidFrom)
	}
	for _, c := range v.Certificates {
		fmt.Fprintf(w, "  certificate  %s", c.Kind)
		if c.Credential != "" {
			fmt.Fprintf(w, "  %s", c.Credential)
		}
		fmt.Fprintln(w)
		if c.HasPool {
			fmt.Fprintf(w, "    pool         %x\n", c.Pool[:])
		}
		if c.DRep != "" {
			fmt.Fprintf(w, "    drep         %s\n", c.DRep)
		}
		if c.HotCredential != "" {
			fmt.Fprintf(w, "    hot key      %s\n", c.HotCredential)
		}
		if c.Deposit != nil {
			fmt.Fprintf(w, "    deposit      %s\n", lovelaceText(chainLovelace(*c.Deposit)))
		}
		if c.Epoch != nil {
			fmt.Fprintf(w, "    retires at   epoch %d\n", *c.Epoch)
		}
		if c.Anchor != nil {
			fmt.Fprintf(w, "    anchor       %s (hash %x)\n", c.Anchor.URL, c.Anchor.Hash[:])
		}
		if r := c.PoolReg; r != nil {
			fmt.Fprintf(w, "    operator     %x\n    vrf key      %x\n    pledge       %s\n    cost         %s\n    margin       %d/%d\n    rewards to   %s\n",
				r.Operator[:], r.VRFKeyHash[:], lovelaceText(chainLovelace(r.Pledge)), lovelaceText(chainLovelace(r.Cost)), r.MarginNum, r.MarginDen, r.RewardAccount)
			for _, o := range r.Owners {
				fmt.Fprintf(w, "    owner        %x\n", o[:])
			}
			for _, rl := range r.Relays {
				port := ""
				if rl.HasPort {
					port = fmt.Sprintf(":%d", rl.Port)
				}
				fmt.Fprintf(w, "    relay        %s %s%s\n", rl.Kind, rl.Host, port)
			}
			if r.HasMeta {
				fmt.Fprintf(w, "    metadata     %s (hash %x)\n", r.MetaURL, r.MetaHash[:])
			}
		}
	}
	for _, x := range v.Withdrawals {
		fmt.Fprintf(w, "  withdrawal   %s  %s\n", x.Account, lovelaceText(chainLovelace(x.Lovelace)))
	}
	for _, m := range v.Mint {
		fmt.Fprintf(w, "  mint         %d %x.%x\n", m.Quantity, m.Policy[:], m.Name)
	}
	for _, vt := range v.Votes {
		fmt.Fprintf(w, "  vote         %s on %x#%d: %s\n", vt.Voter, vt.ActionTx[:], vt.ActionIx, vt.Vote)
	}
	for _, s := range v.RequiredSigners {
		fmt.Fprintf(w, "  must sign    %x\n", s[:])
	}
	if v.AuxDataHash != nil {
		fmt.Fprintf(w, "  metadata     hash %x\n", v.AuxDataHash[:])
	}
	if v.TreasuryValue != nil {
		fmt.Fprintf(w, "  treasury     %s\n", lovelaceText(chainLovelace(*v.TreasuryValue)))
	}
	if v.Donation != nil {
		fmt.Fprintf(w, "  donation     %s\n", lovelaceText(chainLovelace(*v.Donation)))
	}
	fmt.Fprintln(w)
}
