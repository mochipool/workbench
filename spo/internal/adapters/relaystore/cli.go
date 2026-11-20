package relaystore

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
)

// The exit statuses, those of spo-relay's other commands (SPO-Xmailbox-OUT-101).
const (
	exitOK    = 0
	exitFail  = 1
	exitUsage = 2
)

// Usage is the help of the store commands.
const Usage = `usage:
  spo-relay init-store --config FILE
  spo-relay store verify --config FILE [--probe] [--operator]
  spo-relay store inspect --config FILE --bucket registry|working [--path P] [--versions [--locks]] [--limit N] [--after T]
  spo-relay store repair --config FILE --action A [--action B ...] [--dry-run] [--yes]
  spo-relay migrate-store --config FILE --from-mailbox DIR --from-registry DIR [--no-mailbox] [--yes]

init-store     initialise a NEW relay identity's store: self-tests of both buckets (one
               object stays locked for a day), both markers, the released lease, full rate
               buckets; refuses a store that looks emptied or foreign; never run by serve
store verify   check the buckets, markers, lease, tombstones, bindings, mailbox and rates;
               read only unless --probe; exits 1 when a check fails
store inspect  list one page of one prefix, names decoded, never a body
store repair   make the named repairs (` + "delete-markers, lease, mailbox-duplicates, mailbox-over-bound, mailbox-unparsable, selftest, migration-record" + `),
               after listing them, only those listed; takes the lease, so stop the relay first
migrate-store  copy a stopped directory relay into the buckets: into a new identity the
               self-tests first (one object stays locked for a day), then tombstones, the
               markers last; a run that stops is completed by running it again

repair and migrate-store ask on the terminal before they write, unless --yes.
`

// CLI are the command line's adapters, given by the relay binary.
type CLI struct {
	// Open builds the store's dependencies from the relay's configuration file
	// (its [store] table and key); done releases what it opened.
	Open func(configPath string) (d Deps, done func(), err error)
	// OpenDir opens a stopped directory relay under its stores' locks.
	OpenDir func(mailboxDir, registryDir string) (DirSource, func() error, error)
	// Confirm asks the operator a yes-or-no question on the terminal, never on
	// standard input; nil when there is no terminal.
	Confirm        func(question string) (bool, error)
	Stdout, Stderr io.Writer
}

// IsCommand reports whether name is one of the store commands Main runs.
func IsCommand(name string) bool {
	return name == "init-store" || name == "store" || name == "migrate-store"
}

type actionFlags []RepairAction

func (a *actionFlags) String() string { return fmt.Sprint(*a) }
func (a *actionFlags) Set(v string) error {
	*a = append(*a, RepairAction(v))
	return nil
}

// Main runs one store command; args begin with "init-store", "store" or
// "migrate-store". ctx ends the command (the binary cancels it on SIGINT and
// SIGTERM). It returns the exit status.
func Main(ctx context.Context, args []string, c CLI) int {
	if len(args) == 0 {
		fmt.Fprint(c.Stderr, Usage)
		return exitUsage
	}
	name := args[0]
	rest := args[1:]
	if name == "store" {
		if len(rest) == 0 {
			fmt.Fprint(c.Stderr, Usage)
			return exitUsage
		}
		if rest[0] == "-h" || rest[0] == "--help" || rest[0] == "help" {
			fmt.Fprint(c.Stdout, Usage)
			return exitOK
		}
		name, rest = "store "+rest[0], rest[1:]
	}
	fl := flag.NewFlagSet("spo-relay "+name, flag.ContinueOnError)
	fl.SetOutput(c.Stderr)
	conf := fl.String("config", "", "the relay's configuration file")
	var probe, operator, versions, locks, dry, yes, noMail *bool
	var bucket, path, after, fromM, fromR *string
	var limit *int
	var acts actionFlags
	switch name {
	case "init-store":
	case "store verify":
		probe = fl.Bool("probe", false, "run the checks that write and remove: the self-tests (one object stays locked for a day) and the policy probes")
		operator = fl.Bool("operator", false, "ask for the reads that need the operator's credentials (the client cannot make them; the check says so)")
	case "store inspect":
		bucket = fl.String("bucket", "", "registry or working")
		path = fl.String("path", "", "a prefix below relays/<node key>/")
		versions = fl.Bool("versions", false, "list versions and delete markers (registry bucket)")
		locks = fl.Bool("locks", false, "with --versions: read each version's lock")
		limit = fl.Int("limit", 100, "entries on the page, 1 to 1000")
		after = fl.String("after", "", "where the page starts (printed by the page before)")
	case "store repair":
		fl.Var(&acts, "action", "a repair to make (repeat for several)")
		dry = fl.Bool("dry-run", false, "list what would be done and write nothing")
		yes = fl.Bool("yes", false, "do not ask on the terminal")
	case "migrate-store":
		fromM = fl.String("from-mailbox", "", "the stopped relay's mailbox_dir")
		fromR = fl.String("from-registry", "", "the stopped relay's registry_dir")
		noMail = fl.Bool("no-mailbox", false, "leave the queues in the directory")
		yes = fl.Bool("yes", false, "do not ask on the terminal")
	default:
		fmt.Fprintf(c.Stderr, "spo-relay: unknown command %q\n%s", name, Usage)
		return exitUsage
	}
	if err := fl.Parse(rest); err != nil {
		return exitUsage
	}
	bad := func(why string) int {
		fmt.Fprintf(c.Stderr, "spo-relay %s: %s\n%s", name, why, Usage)
		return exitUsage
	}
	switch {
	case *conf == "" || fl.NArg() != 0:
		return bad("--config FILE is required and nothing else is taken")
	case name == "store inspect" && *bucket == "":
		return bad("--bucket registry|working is required")
	case name == "store repair" && len(acts) == 0:
		return bad("name at least one --action")
	case name == "migrate-store" && (*fromM == "" || *fromR == ""):
		return bad("--from-mailbox and --from-registry are required")
	}
	for _, a := range acts {
		if !strings.Contains(" "+actionList()+",", " "+string(a)+",") {
			return bad(fmt.Sprintf("unknown action %q; the actions are %s", a, actionList()))
		}
	}
	if c.Open == nil {
		fmt.Fprintln(c.Stderr, "spo-relay: this build cannot open an object store")
		return exitFail
	}
	d, done, err := c.Open(*conf)
	if err != nil {
		fmt.Fprintf(c.Stderr, "spo-relay: %v\n", err)
		return exitFail
	}
	defer done()
	fail := func(err error) int {
		fmt.Fprintf(c.Stderr, "spo-relay %s: %v\n", name, err)
		return exitFail
	}
	switch name {
	case "init-store":
		rep, err := InitStore(ctx, d)
		RenderInit(c.Stdout, rep)
		if err != nil {
			return fail(err)
		}
	case "store verify":
		rep, err := Verify(ctx, d, VerifyOptions{Probe: *probe, Operator: *operator})
		RenderVerify(c.Stdout, rep)
		if err != nil {
			return fail(err)
		}
		if rep.Failed() {
			fmt.Fprintln(c.Stderr, "spo-relay store verify: a check failed")
			return exitFail
		}
	case "store inspect":
		page, err := Inspect(ctx, d, InspectOptions{Bucket: *bucket, Path: *path, Versions: *versions, Locks: *locks, Limit: *limit, After: *after})
		if err != nil {
			return fail(err)
		}
		RenderInspect(c.Stdout, page)
	case "store repair":
		plan, err := Repair(ctx, d, RepairOptions{Actions: acts, DryRun: true})
		RenderRepair(c.Stdout, plan)
		if err != nil {
			return fail(err)
		}
		if *dry || len(plan.Steps) == 0 {
			return exitOK
		}
		if code := c.confirm(*yes, fmt.Sprintf("Make the %d repair(s) listed above to the store of relay %s? Each deletes or overwrites what it names. It takes the lease: stop the relay first.", len(plan.Steps), short(plan.Identity))); code != exitOK {
			return code
		}
		// the plan printed and confirmed, and nothing else (changed after the
		// review of work package 9: it planned again here)
		rep, err := Repair(ctx, d, RepairOptions{Actions: acts, Confirmed: plan.Steps})
		RenderRepair(c.Stdout, rep)
		if err != nil {
			return fail(err)
		}
		if rep.Failed() {
			return exitFail
		}
	case "migrate-store":
		if c.OpenDir == nil {
			fmt.Fprintln(c.Stderr, "spo-relay: this build cannot read a directory relay")
			return exitFail
		}
		src, closeDir, err := c.OpenDir(*fromM, *fromR)
		if err != nil {
			return fail(err)
		}
		defer closeDir()
		q := fmt.Sprintf("Copy the directory relay (%s, %s) into the store of relay %s? It writes tombstones locked in %s mode, which cannot be removed before their dates.", *fromM, *fromR, short(fmt.Sprintf("%x", d.NodeKey[:])), modeOf(d))
		if code := c.confirm(*yes, q); code != exitOK {
			return code
		}
		rep, err := Migrate(ctx, d, src, MigrateOptions{NoMailbox: *noMail})
		RenderMigrate(c.Stdout, rep)
		if err != nil {
			return fail(err)
		}
	}
	return exitOK
}

func modeOf(d Deps) string {
	if d.Mode == "" {
		return "COMPLIANCE"
	}
	return string(d.Mode)
}

// errNoTerminal is the refusal to write without a terminal and without --yes.
var errNoTerminal = errors.New("there is no terminal to confirm on; pass --yes to proceed without asking")

func (c CLI) confirm(yes bool, q string) int {
	if yes {
		return exitOK
	}
	if c.Confirm == nil {
		fmt.Fprintf(c.Stderr, "spo-relay: %v\n", errNoTerminal)
		return exitFail
	}
	ok, err := c.Confirm(q)
	switch {
	case err != nil:
		fmt.Fprintf(c.Stderr, "spo-relay: %v; pass --yes to proceed without asking\n", err)
		return exitFail
	case !ok:
		fmt.Fprintln(c.Stderr, "spo-relay: not confirmed; nothing was written")
		return exitFail
	}
	return exitOK
}
