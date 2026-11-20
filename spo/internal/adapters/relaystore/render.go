package relaystore

import (
	"fmt"
	"io"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
)

// The renderings print names, counts, sizes, version ids, dates and fingerprints:
// what the store's operator sees anyway (ADR 0015 decision 10). They never
// print a credential, an envelope body or a binding statement's bytes.

func renderChecks(w io.Writer, cs []Check) {
	for _, c := range cs {
		fmt.Fprintf(w, "  [%s] %s", c.Verdict, c.Name)
		if c.Detail != "" {
			fmt.Fprintf(w, ": %s", c.Detail)
		}
		fmt.Fprintln(w)
	}
}

func list(w io.Writer, title string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintln(w, title)
	for _, it := range items {
		fmt.Fprintf(w, "  %s\n", it)
	}
}

// RenderInit writes an init-store report.
func RenderInit(w io.Writer, r InitReport) {
	fmt.Fprintf(w, "relay identity %s\n", r.Identity)
	fmt.Fprintln(w, "checks:")
	renderChecks(w, r.Checks)
	if r.AlreadyInitialised {
		fmt.Fprintln(w, "the store was already initialised: nothing of the identity was written")
	} else {
		fmt.Fprintln(w, "the store is initialised")
	}
	list(w, "written:", r.Written)
	list(w, "the store now holds:", r.Left)
	list(w, "notes:", r.Notes)
}

// RenderVerify writes a store verify report: every check, then the
// version-aware tombstone view, the bindings, the mailboxes, and the policy
// statements to compare.
func RenderVerify(w io.Writer, r VerifyReport) {
	fmt.Fprintf(w, "relay identity %s\n", r.Identity)
	fmt.Fprintln(w, "checks:")
	renderChecks(w, r.Checks)
	fmt.Fprintf(w, "tombstones (%d name(s), %d version(s), %d delete marker(s)):\n", r.Tombs.NameCount, r.Tombs.Versions, r.Tombs.DeleteMarkers)
	for _, n := range r.Tombs.Names {
		renderTombName(w, n)
	}
	if more := r.Tombs.NameCount - len(r.Tombs.Names); more > 0 {
		fmt.Fprintf(w, "  and %d more name(s) (store inspect --bucket registry --path registry/tombstones/ --versions lists them)\n", more)
	}
	fmt.Fprintf(w, "bindings (%d):\n", len(r.Bindings))
	for _, b := range r.Bindings {
		fmt.Fprintf(w, "  %s  %d bytes  %s", fp(b.Device), b.Size, b.Verdict)
		if b.Detail != "" {
			fmt.Fprintf(w, " (%s)", b.Detail)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "mailboxes (%d, %d object(s), %d byte(s)):\n", r.Mailbox.RecipientsN, r.Mailbox.Objects, r.Mailbox.Bytes)
	for _, m := range r.Mailbox.Recipients {
		fmt.Fprintf(w, "  %s  %d object(s)  %d entr(y/ies)  %d sender(s)  %d byte(s)  %d duplicate(s)  %d past the bound\n",
			fp(m.Recipient), m.Objects, m.Entries, m.Senders, m.Bytes, m.DuplicatesN, m.OverBoundN)
	}
	if more := r.Mailbox.RecipientsN - len(r.Mailbox.Recipients); more > 0 {
		fmt.Fprintf(w, "  and %d more mailbox(es)\n", more)
	}
	fmt.Fprintln(w, "the statements ADR 0015 requires (compare with the buckets' policy, lifecycle and settings):")
	fmt.Fprint(w, r.Policy)
}

func renderTombName(w io.Writer, n TombName) {
	if n.Foreign {
		fmt.Fprintf(w, "  %s  not a tombstone's name (ignored by the relay), %d entr(y/ies)\n", n.Name, n.Entries)
		return
	}
	fmt.Fprintf(w, "  %s  scope %s  enforced not-before %s\n", n.Name, scopeName(n.Key.Scope), unixText(n.Highest))
	defer func() {
		if more := n.Entries - len(n.Versions); more > 0 {
			fmt.Fprintf(w, "    and %d more entr(y/ies)\n", more)
		}
	}()
	for _, v := range n.Versions {
		fmt.Fprintf(w, "    %s", v.ID)
		if v.Latest {
			fmt.Fprint(w, " (current)")
		}
		switch {
		case v.DeleteMarker:
			fmt.Fprint(w, " delete marker")
		case v.Gone:
			fmt.Fprint(w, " gone since the listing")
		default:
			fmt.Fprintf(w, " not-before %s", unixText(v.NotBefore))
			if v.Unreadable {
				fmt.Fprint(w, " (unreadable: the strictest reading)")
			}
			fmt.Fprintf(w, ", %s", lockText(v.Lock))
		}
		fmt.Fprintln(w)
	}
}

func unixText(t int64) string {
	switch {
	case t == relaybind.NoTombstone:
		return "none"
	case t >= relaybind.MaxTime:
		return "for ever"
	}
	return time.Unix(t, 0).UTC().Format(time.RFC3339)
}
