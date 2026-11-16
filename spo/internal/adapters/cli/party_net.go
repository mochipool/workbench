package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Timings of the long-running commands. Variables so that a test can shorten
// them.
var (
	// serveSyncEvery is how often a running server reads the registry to follow
	// enrollments and revocations made by another process.
	serveSyncEvery = 2 * time.Second
	// connectBackoffBase is the first wait after a failed dial; it doubles to
	// connectBackoffMax. The server drops an idle connection after 30 s, and the
	// next Connect dials again with a fresh Hello.
	connectBackoffBase = time.Second
	connectBackoffMax  = 30 * time.Second
	// connectReceiveWindow is how long one pass waits for a frame.
	connectReceiveWindow = 700 * time.Millisecond
	// connectSilentLimit is how many connections in a row may close before
	// sending any frame before the operator is told why that may be.
	connectSilentLimit = 5
)

// needNetwork is met unless the mode is offline: an offline coordinator or
// signer exchanges envelopes by file only (SPO-Xparty-MODE-001).
type needNetwork struct{}

func (needNetwork) missing(e *Env) string {
	if e.Mode == ModeOffline {
		return "tailcat: offline mode has no network transport; exchange envelopes by file (spo party request export, spo party inbox import)"
	}
	return ""
}

// tailcatSettings is [tailcat] of spo.toml.
func (r *partyRun) tailcatSettings() (port uint16, derp string) {
	if t := r.o.Config.Tailcat; t != nil {
		return uint16(t.Port), t.DERPMapURL
	}
	return 0, ""
}

// openLocalSecret opens one of this workspace's own secret records.
func (r *partyRun) openSecret(ctx context.Context, ref ports.Ref) (*secret.Buffer, error) {
	v, err := r.vault()
	if err != nil {
		return nil, err
	}
	return v.Open(ctx, ref)
}

func (a *app) partyServeCommand() *cobra.Command {
	var (
		invites []string
		outbox  string
		cf      chainFlags
	)
	cmd := &cobra.Command{
		Use:   "serve [--invite NAME]... [--outbox DIR]",
		Short: "Coordinator: serve signing requests to signers over tailcat",
		Long: `Listen on the tailcat port, admit only enrolled signers (an empty allow-list is
refused: tailcat would admit everyone), send each connected signer its open
requests and take its responses in, until you stop it. A signer that connects
says Hello; its unanswered requests are sent again with the same message id.
A request for the pool cold key is never sent over tailcat.

The server's node key and pre-shared key are sealed records, so the address is
the same on every start. It is never printed: a signer gets it only inside an
invitation sealed to that signer. --invite NAME writes that invitation, as a
file, into --outbox (default: the party outbox); carry it to the signer, who
reads it with spo party inbox import. Do that once per signer, and again if
the port or relay settings change.

A response that completes a collection does not submit anything: finish it
with spo pool register POOL PAYER. A party revoked while this runs (here, or in
another process) is refused within seconds and its connections are closed.
Needs the identity made with --tailcat. Not available in offline mode.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			needs := append([]Need{CapTxID, needNetwork{}}, signerNeeds...)
			return a.party(cmd, &cf, needs, func(ctx context.Context, r *partyRun) error { return r.serve(ctx, invites, outbox) })
		},
	}
	cmd.Flags().StringArrayVar(&invites, "invite", nil, "write an invitation (the sealed tailcat address) for this enrolled signer (repeatable)")
	cmd.Flags().StringVar(&outbox, "outbox", "", "where invitations are written (default: [party] outbox, else party/outbox in the workspace)")
	addChainFlags(cmd, &cf, false)
	return cmd
}

func (r *partyRun) serve(ctx context.Context, invites []string, outboxDir string) error {
	a := r.a
	tc := r.kit().Tailcat
	if tc.NewServer == nil || tc.NodePublic == nil {
		return errors.New("this build has no tailcat transport")
	}
	l, err := r.kit().Kit.Local(ctx)
	if err != nil {
		return partyIdentityErr(err)
	}
	id := l.Identity()
	l.Destroy()
	if id.Node == nil {
		return errors.New("this identity has no tailcat node key (it was made without --tailcat), so no signer can be told to expect it: a coordinator that serves needs an identity made with: spo party init --tailcat")
	}
	pub, err := r.nodeKey(ctx, false)
	if err != nil {
		return err
	}
	if pub != *id.Node {
		return errors.New("the sealed node key is not the one the identity publishes: refusing to serve")
	}
	co, err := r.coordinator()
	if err != nil {
		return err
	}
	allowed, err := co.AllowList(ctx)
	if err != nil {
		return err
	}
	if len(allowed) == 0 {
		return errors.New("no enrolled signer has a tailcat node key, so nobody could be admitted. tailcat admits every client when its allow-list is empty, so spo refuses to start. Enroll a signer whose identity has a node key (spo party init --tailcat)")
	}
	nodeRef, pskRef := ports.Ref{Name: "local", Kind: ports.TailcatNodeKey}, ports.Ref{Name: "local", Kind: ports.TailcatPSK}
	var have bool
	if err := r.s.Store.View(ctx, func(rd ports.Reader) error {
		var err error
		have, err = rd.Exists(pskRef)
		return err
	}); err != nil {
		return err
	}
	if !have {
		k, err := tc.NewNodeKey() // 32 random bytes: a pre-shared key is one too
		if err != nil {
			return err
		}
		err = r.s.Store.Update(ctx, func(w ports.Writer) error { return w.PutSecret(pskRef, k) })
		k.Destroy()
		if err != nil {
			return err
		}
	}
	nodeKey, err := r.openSecret(ctx, nodeRef)
	if err != nil {
		return err
	}
	psk, err := r.openSecret(ctx, pskRef)
	if err != nil {
		nodeKey.Destroy()
		return err
	}
	port, derp := r.tailcatSettings()
	srv, err := tc.NewServer(TailcatServerConfig{NodeKey: nodeKey, PSK: psk, Allowed: allowed, Port: port, DERPMapURL: derp,
		Admit: func(env []byte, peer party.NodeKey) (party.Fingerprint, error) { return co.Admit(ctx, env, peer) }})
	if err != nil {
		nodeKey.Destroy()
		psk.Destroy()
		return err
	}
	defer srv.Close()
	sctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	err = srv.Start(sctx)
	cancel()
	if err != nil {
		return fmt.Errorf("tailcat did not start: %w", err)
	}
	defer registerLive(srv)()
	w := a.d.Out
	fmt.Fprintf(w, "Serving over tailcat.\n  fingerprint  %s\n  node key     %x\n  admitting    %d signer node key(s)\n", id.Fingerprint(), pub[:], len(allowed))
	fmt.Fprintln(w, "The address is a secret and is not shown: a signer gets it only in an invitation sealed to it.")

	if len(invites) > 0 {
		// Writing an invitation by file hands EVERY envelope waiting in the
		// outbox to the file transport (multisig.Outbox.Flush takes no filter),
		// and a request that went into a file is delivered and is not sent over
		// tailcat. So invitations are written while nothing else waits.
		if pending, err := r.node().Outbox().Pending(ctx); err != nil {
			return err
		} else if len(pending) > 0 {
			return fmt.Errorf("the outbox holds %d envelope(s) that writing an invitation by file would carry away too (requests meant for tailcat would be delivered as files and never sent over it): write the invitations first, with nothing queued (spo party serve --invite NAME), then queue requests; or empty the outbox with spo party outbox export DIR", len(pending))
		}
		d := r.dirs("", outboxDir)
		if err := ensureDir(d.outbox); err != nil {
			return err
		}
		bag, err := r.kit().OpenOutput(d.outbox)
		if err != nil {
			return err
		}
		addr, err := srv.Address()
		if err != nil {
			bag.Close()
			return err
		}
		var text string
		_ = addr.Use(func(b []byte) error { text = string(b); return nil })
		addr.Destroy()
		for _, n := range invites {
			if err := co.SendInvite(ctx, n, party.Invite{Address: text, Node: pub}, bag.Transport()); err != nil {
				bag.Close()
				return fmt.Errorf("invitation for %s: %w", n, err)
			}
			fmt.Fprintf(w, "  invitation for %s written to %s\n", n, d.outbox)
		}
		bag.Close()
	}

	known, err := co.AllowOwners(ctx)
	if err != nil {
		return err
	}
	ob := r.node().Outbox()
	tr := srv.Transport()
	synced := time.Now()
	r.sweepNotices(ctx)
	for ctx.Err() == nil {
		if _, err := ob.Flush(ctx, tr); err != nil && ctx.Err() == nil {
			fmt.Fprintf(a.d.Err, "sending: %v\n", err)
		}
		rctx, cancelR := context.WithTimeout(ctx, 700*time.Millisecond)
		rcv, err := srv.Receive(rctx)
		cancelR()
		if err == nil {
			h, herr := co.Handle(ctx, rcv)
			switch {
			case herr != nil:
				fmt.Fprintf(a.d.Err, "handling an envelope: %v\n", herr)
			case h.Effect == "hello" || h.Effect == "acknowledged":
			default:
				printHandled(w, h)
			}
		}
		if time.Since(synced) > serveSyncEvery {
			synced = time.Now()
			r.syncAllowList(ctx, co, srv, known)
			r.sweepNotices(ctx)
		}
	}
	fmt.Fprintln(w, "Stopped serving.")
	return nil
}

// syncAllowList makes the running server follow the registry: a node key that
// was enrolled since (or by another process) is allowed, one whose party was
// revoked is refused and its connections closed (SPO-Xparty-IF-005).
func (r *partyRun) syncAllowList(ctx context.Context, co multisig.Coordinator, srv TailcatServer, known map[party.NodeKey]party.Fingerprint) {
	now, err := co.AllowOwners(ctx)
	if err != nil {
		return
	}
	followRegistry(srv, known, now, r.a.d.Out)
}

// followRegistry makes srv admit exactly the node keys of now. A key whose
// holder changed (a party revoked and another enrolled with the same node key
// between two syncs) is revoked and then allowed again, so the old holder's
// open connections are closed.
func followRegistry(srv TailcatServer, known, now map[party.NodeKey]party.Fingerprint, out io.Writer) {
	for k, fp := range now {
		old, had := known[k]
		switch {
		case !had:
			srv.Allow(k)
			fmt.Fprintf(out, "now admitting node key %x\n", k[:8])
		case old != fp:
			srv.Revoke(k)
			srv.Allow(k)
			fmt.Fprintf(out, "node key %x now belongs to another party: the old party's connections were closed\n", k[:8])
		}
	}
	for k := range known {
		if _, ok := now[k]; !ok {
			srv.Revoke(k)
			fmt.Fprintf(out, "no longer admitting node key %x: its party was revoked or removed\n", k[:8])
		}
	}
	clear(known)
	for k, fp := range now {
		known[k] = fp
	}
}

func (a *app) partyConnectCommand() *cobra.Command {
	var f signerFlags
	var interactive bool
	cmd := &cobra.Command{
		Use:   "connect COORDINATOR [--interactive]",
		Short: "Signer: stay connected to a coordinator over tailcat and receive its requests",
		Long: `Dial the coordinator named COORDINATOR (an enrolled coordinator whose invitation
you imported), say Hello, send your queued responses and receive its requests
into the same pending list spo party requests shows. The server drops an idle
connection after 30 seconds; this reconnects with a fresh Hello and a backoff
(1 s, doubling to 30 s), until you stop it.

Receiving a request never signs it. Approval is a separate, deliberate step:
spo party review ID and spo party approve ID in another terminal, or
--interactive, which runs the same review and the same prompts (default No,
then the passphrase) in this process as each request arrives.

A request that arrives over tailcat is refused automatically and in silence
unless this signer has a chain view of its own that resolves EVERY input: the
provider of light mode, or --own-snapshot PATH. A network peer must not be able
to make a signer sign blind (SPO-Xparty-PRE-007). A request for the pool cold
key never travels over tailcat. Not available in offline mode.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			needs := append([]Need{needNetwork{}}, signerNeeds...)
			return a.party(cmd, &f.chain, needs, func(ctx context.Context, r *partyRun) error { return r.connect(ctx, args[0], &f, interactive) })
		},
	}
	cmd.Flags().BoolVar(&interactive, "interactive", false, "review and ask for approval here, as each request arrives (the same prompts as spo party approve)")
	f.add(cmd)
	f.addFull(cmd)
	return cmd
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func (r *partyRun) connect(ctx context.Context, coordName string, f *signerFlags, interactive bool) error {
	a := r.a
	tc := r.kit().Tailcat
	if tc.NewClient == nil || tc.NodePublic == nil {
		return errors.New("this build has no tailcat transport")
	}
	coord, err := r.byName(ctx, coordName)
	if err != nil {
		return err
	}
	if !coord.Active() || !coord.HasRole(party.RoleCoordinator) {
		return fmt.Errorf("%s is not an active enrolled coordinator", coordName)
	}
	if coord.Identity.Node == nil {
		return fmt.Errorf("%s has no tailcat node key in the identity you enrolled: it cannot be reached over tailcat", coordName)
	}
	sg, why, err := r.signer(ctx, f.snapshot, r.dirs(f.inbox, f.outbox))
	if err != nil {
		return err
	}
	if _, err := r.nodeKey(ctx, false); err != nil {
		return err
	}
	addr, err := r.openSecret(ctx, ports.Ref{Name: coord.Name, Kind: ports.TailcatAddr})
	if errors.Is(err, ports.ErrNotFound) {
		return fmt.Errorf("there is no invitation from %s: ask its operator for one (spo party serve --invite %s) and import the file with spo party inbox import", coordName, "NAME")
	}
	if err != nil {
		return err
	}
	nodeKey, err := r.openSecret(ctx, ports.Ref{Name: "local", Kind: ports.TailcatNodeKey})
	if err != nil {
		addr.Destroy()
		return err
	}
	port, derp := r.tailcatSettings()
	var hellos atomic.Int64
	client, err := tc.NewClient(TailcatClientConfig{Address: addr, NodeKey: nodeKey, Coordinator: coord.Fingerprint, Port: port, DERPMapURL: derp,
		ExpectServerKey: *coord.Identity.Node,
		// Every new connection makes a Hello, so the count of Hellos is the
		// count of connections the loop below has seen.
		Hello: func(ctx context.Context) ([]byte, error) { hellos.Add(1); return sg.NewHello(ctx, coord.Name) }})
	if err != nil {
		addr.Destroy()
		nodeKey.Destroy()
		return err
	}
	defer client.Close()
	w := a.d.Out
	fmt.Fprintf(w, "Connecting to %s over tailcat. This machine's own chain view: %s.\n", coord.Name, why)
	if !sg.Resolver.IsSet() {
		fmt.Fprintln(a.d.Err, "WARNING: this signer has no chain view of its own, so EVERY request that arrives over tailcat will be refused automatically and in silence (SPO-Xparty-PRE-007): a request from a network must have every input resolved by the signer's own resolver, and there is none. The refusals are in spo party events and nothing is sent back. Give it a view (light mode uses its own provider; or --own-snapshot PATH), or exchange requests by file.")
	}
	ob := r.node().Outbox()
	// The backoff is reset only by a frame received: a connection that is
	// accepted and then closed before it carries anything (a revoked signer,
	// clocks too far apart, the wrong coordinator) is not a working one.
	backoff := connectBackoffBase
	up := false
	var seenHellos int64
	var framesOnConn, silent int
	for ctx.Err() == nil {
		if err := client.Connect(ctx); err != nil {
			up = false
			if ctx.Err() != nil {
				break
			}
			fmt.Fprintf(a.d.Err, "cannot reach %s (%v); trying again in %s\n", coord.Name, err, backoff)
			sleepCtx(ctx, backoff)
			backoff = min(2*backoff, connectBackoffMax)
			continue
		}
		if h := hellos.Load(); h != seenHellos {
			// A new connection began, so the one before it ended.
			if seenHellos != 0 && framesOnConn == 0 {
				silent++
				if silent%connectSilentLimit == 0 {
					fmt.Fprintf(a.d.Err, "%d connections to %s in a row closed before it sent anything. Likely causes: the coordinator revoked this signer (its allow-list no longer has this node key); the two machines' clocks are more than five minutes apart (a Hello outside that window is refused); this is not the coordinator you meant. Backing off to at most %s between connections.\n", silent, coord.Name, connectBackoffMax)
				}
				sleepCtx(ctx, backoff)
				backoff = min(2*backoff, connectBackoffMax)
			}
			seenHellos, framesOnConn = h, 0
		}
		if !up {
			up = true
			fmt.Fprintf(w, "Connected to %s.\n", coord.Name)
		}
		if _, err := ob.Flush(ctx, client.Transport()); err != nil && ctx.Err() == nil {
			fmt.Fprintf(a.d.Err, "sending: %v; reconnecting\n", err)
			client.Disconnect()
			up = false
			sleepCtx(ctx, backoff)
			continue
		}
		rctx, cancel := context.WithTimeout(ctx, connectReceiveWindow)
		rcv, err := client.Receive(rctx)
		cancel()
		if err != nil {
			continue
		}
		framesOnConn++
		backoff, silent = connectBackoffBase, 0
		h, herr := sg.Handle(ctx, rcv)
		switch {
		case herr != nil:
			fmt.Fprintf(a.d.Err, "handling an envelope: %v\n", mapSignerErr(herr))
		case h.Effect == "duplicate":
		default:
			printHandled(w, h)
			if interactive && !h.Refused && h.Effect == "stored" {
				if err := a.reviewAndApprove(ctx, r, sg, h.Request, fmt.Sprintf("%x", h.Request[:4]), f.full); err != nil {
					fmt.Fprintf(a.d.Err, "not approved: %v\n", err)
				}
			}
		}
	}
	fmt.Fprintln(w, "Disconnected.")
	return nil
}
