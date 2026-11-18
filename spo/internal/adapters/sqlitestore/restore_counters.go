package sqlitestore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/unlock"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"

	sqlite "modernc.org/sqlite"
)

// The counter rule of a restore (ADR 0012 decision 9): a restore never lowers an
// operational-certificate counter or a KES counter of the workspace it replaces.
//
// Where the values live. Per pool, keyed by the anchor identity of the pool's
// cold key (the label is only a name): `node.counter` holds the cold issue
// counter, a text envelope {Next, ColdVKey}, Next being the number the next
// operational certificate takes; `kes.counter` holds the number of the newest KES
// key generated and `kes.counter-next` the number the next one must have. All
// three are sealed records of class Sensitive, like every record. An issued
// certificate is stored as `node.opcert` numbered by its KES key and embeds its own
// counter; nothing ties it to the issue counter except the cold key's identity.
//
// What is carried. When the backup does not contain the head of the destination
// (an older or diverged backup, accepted only with AllowOlder), the destination is
// opened read-only and each pool is compared:
//   - the issue counter: when the destination's Next is larger (or the backup has
//     no record for the pool), the destination's record is written into the
//     restore's private copy as it stands;
//   - the KES allocator `kes.counter-next`: when the destination's effective next
//     number is larger, it is written. `kes.counter` (the newest key) is NOT carried:
//     it names a key the restored file does not hold, and a state that says an
//     unconsumed key exists when none does could never be generated out of.
//
// The writes are one ordinary audited write of the copy, with one event per
// counter (both values). They happen before the swap, so nothing is written to the
// destination before it.

// RestoreReport says what a restore did about the counter rule and the
// checkpoint key.
type RestoreReport struct {
	// KeyHash is the hash of the checkpoint key of the restored file (nil: none).
	KeyHash []byte
	// KeyCarried: the backup held no checkpoint key and the replaced workspace's
	// was carried into the restored copy.
	KeyCarried bool
	// KeyReplaced is the hash of the replaced workspace's checkpoint key when the
	// backup holds a different one (the backup's is kept).
	KeyReplaced []byte
	// Carried lists the counters written from the replaced workspace into the
	// restored one.
	Carried []CarriedCounter
	// LowerAccepted: the replaced workspace could not be opened and
	// AcceptLowerCounters let the restore go on without comparing.
	LowerAccepted bool
	// HeadAhead: the replaced workspace's head file was ahead of its file (rolled
	// back, or the head file was rewritten): the counters in the file were carried
	// as a floor, and the true counters may be higher still.
	HeadAhead bool
}

// CarriedCounter is one counter carried forward.
type CarriedCounter struct {
	Pool   string // the pool's label, or its anchor identity
	Kind   string // node.counter or kes.counter-next
	Live   string // the replaced workspace's value
	Backup string // the backup's value, or "absent"
}

// afterCarry, when set, runs after the counters were carried into the private copy
// and before the destination is locked; an error stops the restore there (a test
// sets it to show a crash at that point leaves the destination untouched).
var afterCarry func() error

type issueC struct {
	next uint64
	vkey [32]byte
	raw  []byte
}

type counterSet struct {
	issue map[identity.Ref]issueC
	cur   map[identity.Ref]int
	next  map[identity.Ref]int
	names map[identity.Ref]string
	// kesKeys are the numbers of the KES verification keys each pool holds, with a
	// hash of the key record: a number is "held" only with the same key material.
	kesKeys map[identity.Ref]map[int][32]byte
}

func (c counterSet) poolName(a identity.Ref) string {
	if n, ok := c.names[a]; ok {
		return n
	}
	return a.String()
}

// readCounterSet reads the counters of every pool of an open store.
func readCounterSet(ctx context.Context, s *Store, what string) (counterSet, error) {
	cs := counterSet{issue: map[identity.Ref]issueC{}, cur: map[identity.Ref]int{}, next: map[identity.Ref]int{}, names: map[identity.Ref]string{}, kesKeys: map[identity.Ref]map[int][32]byte{}}
	err := s.View(ctx, func(r ports.Reader) error {
		rl, ok := r.(ports.RecordLister)
		if !ok {
			return errors.New("the store cannot list records")
		}
		refs := func(k ports.Kind) ([]ports.Ref, error) { return rl.Records(k) }
		if ls, err := refs(ports.Label); err == nil {
			for _, ref := range ls {
				if b, err := r.Get(ref); err == nil {
					if l, err := labels.ParseLabel(b); err == nil {
						if _, dup := cs.names[l.Anchor]; !dup {
							cs.names[l.Anchor] = l.Name
						}
					}
				}
			}
		}
		if ks, err := refs(ports.KesVKey); err == nil {
			for _, ref := range ks {
				b, gerr := r.Get(ref)
				if gerr != nil {
					continue // a key record that cannot be read is not "held"
				}
				if cs.kesKeys[ref.Anchor] == nil {
					cs.kesKeys[ref.Anchor] = map[int][32]byte{}
				}
				cs.kesKeys[ref.Anchor][ref.Num] = sha256.Sum256(b)
			}
		}
		for _, k := range []ports.Kind{ports.NodeCounter, ports.KesCounter, ports.KesCounterNext} {
			rs, err := refs(k)
			if err != nil {
				return err
			}
			for _, ref := range rs {
				if ref.Num != 0 {
					continue
				}
				b, err := r.Get(ref)
				if err != nil {
					return err
				}
				switch k {
				case ports.NodeCounter:
					ic, err := pool.ParseIssueCounter(b)
					if err != nil {
						return fmt.Errorf("%w: the %s of %s in the %s cannot be read", ErrCountersUnknown, k, cs.poolName(ref.Anchor), what)
					}
					cs.issue[ref.Anchor] = issueC{next: ic.Next, vkey: ic.ColdVKey, raw: append([]byte(nil), b...)}
				default:
					n, err := pool.ParseCounter(b)
					if err != nil {
						// a KES counter that is not a number is not a state the pool
						// use cases accept either (ErrBadCounter); it cannot be compared
						// and is left as it is
						continue
					}
					if k == ports.KesCounter {
						cs.cur[ref.Anchor] = n
					} else {
						cs.next[ref.Anchor] = n
					}
				}
			}
		}
		return nil
	})
	return cs, err
}

// effNext is the number the next KES key of a pool must have, as the store's
// state machine reads it; ok is false when the pool has no KES counter at all.
func (c counterSet) effNext(a identity.Ref) (int, bool) {
	cur, hc := c.cur[a]
	nxt, hn := c.next[a]
	if !hc && !hn {
		return 0, false
	}
	var cp, np *int
	if hc {
		cp = &cur
	}
	if hn {
		np = &nxt
	}
	return pool.NewKesState(cp, np).NextNumber(), true
}

type carry struct {
	ref  ports.Ref
	data []byte
	note CarriedCounter
}

// planCarry compares the pools of the destination (live) with the backup's and
// returns what to write. It refuses a pool whose counter record names another
// cold key.
func planCarry(live, bak counterSet) ([]carry, error) {
	var out []carry
	anchors := make([]identity.Ref, 0, len(live.issue))
	for a := range live.issue {
		anchors = append(anchors, a)
	}
	sort.Slice(anchors, func(i, j int) bool { return anchors[i].Compare(anchors[j]) < 0 })
	for _, a := range anchors {
		l := live.issue[a]
		b, have := bak.issue[a]
		switch {
		case !have:
			out = append(out, carry{ref: ports.Ref{Anchor: a, Kind: ports.NodeCounter}, data: l.raw,
				note: CarriedCounter{Pool: live.poolName(a), Kind: string(ports.NodeCounter), Live: strconv.FormatUint(l.next, 10), Backup: "absent"}})
		case l.next > b.next:
			if l.vkey != b.vkey {
				return nil, fmt.Errorf("%w: the issue counter of %s names a different cold key in the backup than in the replaced workspace, so it cannot be carried; nothing was replaced", ErrCountersUnknown, live.poolName(a))
			}
			out = append(out, carry{ref: ports.Ref{Anchor: a, Kind: ports.NodeCounter}, data: l.raw,
				note: CarriedCounter{Pool: live.poolName(a), Kind: string(ports.NodeCounter), Live: strconv.FormatUint(l.next, 10), Backup: strconv.FormatUint(b.next, 10)}})
		}
	}
	ka := map[identity.Ref]bool{}
	for a := range live.cur {
		ka[a] = true
	}
	for a := range live.next {
		ka[a] = true
	}
	kanchors := make([]identity.Ref, 0, len(ka))
	for a := range ka {
		kanchors = append(kanchors, a)
	}
	sort.Slice(kanchors, func(i, j int) bool { return kanchors[i].Compare(kanchors[j]) < 0 })
	for _, a := range kanchors {
		ln, _ := live.effNext(a)
		// A KES key generated and not yet used for a certificate sits at number
		// cur == next. When the restored workspace does not hold that key, the next
		// number must move past it: generating at the same number again would make a
		// different key with the same number as the one already exported.
		if cur, ok := live.cur[a]; ok && cur == ln {
			lh, lok := live.kesKeys[a][cur]
			bh, bok := bak.kesKeys[a][cur]
			if !(lok && bok && lh == bh) { // the same number is not the same key
				ln = cur + 1
			}
		}
		bn, bhave := bak.effNext(a)
		if bhave && ln <= bn {
			continue
		}
		bs := "absent"
		if bhave {
			bs = strconv.Itoa(bn)
		}
		out = append(out, carry{ref: ports.Ref{Anchor: a, Kind: ports.KesCounterNext}, data: pool.FormatCounter(ln),
			note: CarriedCounter{Pool: live.poolName(a), Kind: string(ports.KesCounterNext), Live: strconv.Itoa(ln), Backup: bs}})
	}
	return out, nil
}

// counterPlan is what the counter rule decided before the swap.
type counterPlan struct {
	destHead      *Head // the head of the destination when its counters were read
	report        RestoreReport
	carried       bool // the private copy was written
	ws            []byte
	head          Head // the private copy's own head after the carry
	refusalNeeded error
}

// prepareCounters applies the counter rule to the private copy tmpPath of a
// backup about to replace dest, whenever dest exists and can be opened, whatever
// its workspace id (a pool has the same anchor in every workspace that holds it).
// It returns nil when there is nothing for the rule to do and the ordinary checks
// (checkReplace) decide: a destination that is not a workspace, another
// workspace without the operator's say, an older backup without AllowOlder whose
// destination cannot be opened.
//
// There is no "the backup contains the destination's head, so it cannot lower
// anything" shortcut: `pool opcert issue --counter N` writes N+1 whatever the
// stored counter was, and `workspace import` can replace a counter, so a chain
// that contains the head can still hold a lower counter.
func prepareCounters(ctx context.Context, dest, tmpPath string, cred credential, o RestoreOptions) (*counterPlan, error) {
	dws, _, ierr := inspectFile(ctx, dest)
	bws, _, err := inspectFile(ctx, tmpPath)
	if err != nil {
		return nil, err
	}
	// Every "return nil, nil" below is for a destination that the ordinary checks
	// (checkReplace, under the lock, before anything is replaced) refuse anyway, and
	// is justified at the line. No other path leaves a destination without a plan.
	if ierr != nil {
		if !isStructural(ierr) {
			return nil, fmt.Errorf("the workspace to be replaced could not be read: %w", ierr)
		}
		if !o.AllowOtherWorkspace {
			// the destination is not a workspace and the operator did not say to
			// replace it: checkReplace refuses (ErrOtherWorkspace), replacing nothing
			return nil, nil
		}
		return damagedCounters(ctx, tmpPath, cred, o, "the file to be replaced does not parse as a workspace")
	}
	same := bytes.Equal(dws, bws)
	if !same && !o.AllowOtherWorkspace {
		// another workspace without the operator's say: checkReplace refuses
		// (ErrOtherWorkspace), replacing nothing
		return nil, nil
	}
	st, headAhead, how, oerr := openDestinationReadOnly(ctx, dest, cred, o)
	switch how {
	case openOK:
	case openStructural:
		return damagedCounters(ctx, tmpPath, cred, o, oerr.Error())
	default: // a credential problem, a busy file, an I/O error, a refused factor
		return nil, oerr
	}
	defer st.Close()
	if headAhead && !o.AcceptLowerCounters {
		return nil, fmt.Errorf("%w (%s). The file itself unlocked and its counters can be carried as a floor, but the head file says the workspace was further along, so its true counters may be higher than the file's. Nothing was replaced. --accept-lower-counters goes on anyway: the counters in the file are carried, a warning is printed and an audit event recorded, and you must check the counter of every pool on chain before issuing an operational certificate", ErrCountersUnknown, headAheadWhy)
	}
	liveHead := st.head
	live, err := readCounterSet(ctx, st, "workspace to be replaced")
	if err != nil {
		return nil, err
	}
	bst, err := open(tmpPath, cred, false, OpenOptions{})
	if err != nil {
		return nil, fmt.Errorf("the backup copy cannot be opened to compare counters: %w", err)
	}
	closed := false
	defer func() {
		if !closed {
			bst.Close()
		}
	}()
	bak, err := readCounterSet(ctx, bst, "backup")
	if err != nil {
		return nil, err
	}
	carries, err := planCarry(live, bak)
	if err != nil {
		return nil, err
	}
	// the checkpoint key record: carried when the backup holds none, reported when
	// the backup holds another (the backup's is kept: it is what that file was
	// sealed with)
	liveCK, err := readCheckpointKey(ctx, st)
	if err != nil {
		return nil, fmt.Errorf("the checkpoint key of the workspace to be replaced could not be read: %w", err)
	}
	bakCK, err := readCheckpointKey(ctx, bst)
	if err != nil {
		return nil, fmt.Errorf("the checkpoint key of the backup could not be read: %w", err)
	}
	// the destination's head is always recorded, so that the swap can see that it
	// moved on since its counters were read
	plan := &counterPlan{destHead: &liveHead}
	var ckCarry []byte
	var ckDiffers [][]any
	switch {
	case liveCK != nil && bakCK == nil:
		ckCarry = liveCK
		plan.report.KeyCarried = true
		plan.report.KeyHash = checkpointKeyHash(liveCK)
	case liveCK != nil && bakCK != nil:
		lh, bh := checkpointKeyHash(liveCK), checkpointKeyHash(bakCK)
		if !bytes.Equal(lh, bh) {
			plan.report.KeyReplaced = lh
			ckDiffers = [][]any{keyEvent("checkpoint-key-differs", bh, lh)}
		}
	}
	if len(carries) > 0 || ckCarry != nil {
		extra := make([][]any, 0, len(carries)+1)
		for _, c := range carries {
			extra = append(extra, []any{"counter-carried", c.note.Kind, c.note.Pool, c.note.Live, c.note.Backup, "carried forward from the replaced workspace"})
			plan.report.Carried = append(plan.report.Carried, c.note)
		}
		if ckCarry != nil {
			extra = append(extra, keyEvent("checkpoint-key-carried", checkpointKeyHash(ckCarry)))
		}
		if err := bst.updateExtra(ctx, func(w ports.Writer) error {
			for _, c := range carries {
				if err := w.Put(c.ref, c.data); err != nil {
					return err
				}
			}
			if ckCarry != nil {
				return putCheckpointKey(ctx, w, ckCarry)
			}
			return nil
		}, extra); err != nil {
			return nil, fmt.Errorf("the counters and the checkpoint key could not be carried into the restored copy: %w", err)
		}
		plan.carried = true
	}
	if ckDiffers != nil {
		if err := bst.auditNote(ctx, ckDiffers); err != nil {
			return nil, err
		}
		plan.carried = true
	}
	if headAhead {
		plan.report.HeadAhead = true
		if err := bst.auditNote(ctx, [][]any{{"counters-floor", "the head file of the replaced workspace was ahead of its file, so the counters carried are a floor and the true counters may be higher; check every pool's counter on chain before issuing an operational certificate"}}); err != nil {
			return nil, err
		}
		plan.carried = true
	}
	if err := settleCopy(ctx, bst, tmpPath); err != nil {
		return nil, err
	}
	closed = true
	return plan, nil
}

const headAheadWhy = "the workspace file is older than its head file, or the head file does not match it: it was rolled back, or the head file was rewritten"

// settleCopy folds the write-ahead log of the private copy into the file, closes
// the store and removes the side files of the copy (its head file and lock).
func settleCopy(ctx context.Context, s *Store, tmpPath string) error {
	var busy, frames, done int
	if err := s.db.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &frames, &done); err != nil || busy != 0 {
		s.Close()
		return fmt.Errorf("the restored copy could not be checkpointed (%v)", err)
	}
	if err := s.Close(); err != nil {
		return err
	}
	os.Remove(tmpPath + "-wal")
	os.Remove(tmpPath + "-shm")
	os.Remove(headPath(tmpPath))
	os.Remove(headPath(tmpPath) + ".lock")
	return nil
}

// damagedCounters is the counter rule for a destination whose counters cannot
// be read because the file itself is unusable: it does not parse as a workspace,
// fails its verification, or is older than its head file (the counters of the
// recorded state are not in it). The restore refuses, unless AcceptLowerCounters
// says to go on, in which case the copy gets an audit event that says nothing
// was compared. A credential problem, a busy file and an I/O error never get here.
func damagedCounters(ctx context.Context, tmpPath string, cred credential, o RestoreOptions, why string) (*counterPlan, error) {
	if !o.AcceptLowerCounters {
		return nil, fmt.Errorf("%w (%s). Restoring over it could lower an operational certificate counter or a KES counter, and an operational certificate issued with a lower counter is rejected by the chain or, worse, can reuse a counter; nothing was replaced. If that workspace is really lost, --accept-lower-counters goes on anyway: the restore then prints a warning and records an audit event, and you must check the counter of every pool on chain before issuing an operational certificate", ErrCountersUnknown, why)
	}
	bst, err := open(tmpPath, cred, false, OpenOptions{})
	if err != nil {
		return nil, fmt.Errorf("the backup copy cannot be opened to record the warning: %w", err)
	}
	if err := bst.auditNote(ctx, [][]any{{"counters-not-carried", "the replaced workspace could not be read, so its operational certificate and KES counters were not compared; check every pool's counter on chain before issuing an operational certificate"}}); err != nil {
		bst.Close()
		return nil, err
	}
	if err := settleCopy(ctx, bst, tmpPath); err != nil {
		return nil, err
	}
	return &counterPlan{report: RestoreReport{LowerAccepted: true}, carried: true}, nil
}

type openHow int

const (
	openOK openHow = iota
	// openNeedsCredential: the credential presented for the backup does not open
	// the destination and its own recovery material was not offered or did not
	// open it. A credential problem; --accept-lower-counters never applies.
	openNeedsCredential
	// openStructural: the file does not parse as a workspace or fails verification.
	openStructural
	// openOther: a busy file, an I/O error, a factor that was refused: returned as
	// it is, and never satisfies --accept-lower-counters.
	openOther
)

// ErrCountersNeedCredential: the workspace a restore would replace cannot be
// opened with the credential presented for the backup, so its counters cannot be
// compared. It is a credential problem, never "damaged": --accept-lower-counters
// does not apply.
var ErrCountersNeedCredential = errors.New("sqlitestore: the counters of the workspace to be replaced cannot be compared")

func needCredential(detail string, cause error) error {
	return needCredentialErr(detail, cause, false)
}

const (
	needRecoveryAdvice = "Present that workspace's own recovery key (--recovery-key-in-fd N, or answer the prompt; under hardware also --current-recovery-device and --recovery-pin-fd). If its credentials are lost, move workspace.spo aside and restore into the empty directory: nothing can then be compared, so check every pool's counter on chain before issuing an operational certificate; nothing was replaced"
	// A strict workspace has no recovery path, so it cannot be told to present one.
	needStrictAdvice = "The workspace to be replaced is strict: it has no recovery path, so it can be opened only with one of its own enrolled authenticators, and the one presented for the backup is not one of them. Present an authenticator that is enrolled in both (--fido2-device), if there is one. If none is left, the workspace cannot be compared: move workspace.spo aside, restore into the empty directory and check every pool's counter on chain before issuing an operational certificate; nothing was replaced"
)

func needCredentialErr(detail string, cause error, strict bool) error {
	advice := needRecoveryAdvice
	if strict {
		advice = needStrictAdvice
	}
	if cause != nil {
		return fmt.Errorf("%w: %s. %s: %w", ErrCountersNeedCredential, detail, advice, cause)
	}
	return fmt.Errorf("%w: %s. %s", ErrCountersNeedCredential, detail, advice)
}

// isStructural reports whether err says the file itself is unusable: not a
// database, corrupt, or failing verification. A busy file, a permission or I/O
// error and a wrong credential are not structural.
func isStructural(err error) bool {
	var ve *VerifyError
	if errors.Is(err, ErrCorrupt) || errors.As(err, &ve) {
		return true
	}
	var se *sqlite.Error
	if errors.As(err, &se) {
		switch se.Code() & 0xff {
		case 26, 11: // SQLITE_NOTADB, SQLITE_CORRUPT
			return true
		}
	}
	m := err.Error()
	return strings.Contains(m, "no such table") || strings.Contains(m, "file is not a database") || strings.Contains(m, "malformed")
}

// openDest opens the destination read-only. A file older than its head file (or
// whose head file does not match it) is read as it is, with headAhead set, when
// the credential unlocked it and only that check failed; when a restore sidecar
// that names the file's own head explains it (a restore that died past the swap,
// whose carried counters are in the file) headAhead is false.
func openDest(dest string, cred credential) (st *Store, headAhead bool, err error) {
	st, err = open(dest, cred, true, OpenOptions{})
	if err == nil {
		return st, false, nil
	}
	if errors.Is(err, ErrRolledBack) || errors.Is(err, ErrHeadMismatch) {
		explained := false
		if ws, own, ierr := inspectFile(context.Background(), dest); ierr == nil {
			_, explained = adoptSidecar(dest, ws, own)
		}
		st, err = open(dest, cred, true, OpenOptions{AcceptRollback: true})
		return st, !explained, err
	}
	return nil, false, err
}

// openDestinationReadOnly opens the destination read-only with the credential
// presented for the backup and, when that credential does not open it (its slots
// changed since the backup), with the recovery material of the current workspace
// that --allow-weaker-policy also takes (CurrentRecovery), asked for only then.
func openDestinationReadOnly(ctx context.Context, dest string, cred credential, o RestoreOptions) (*Store, bool, openHow, error) {
	classify := func(err error) (openHow, error) {
		if isStructural(err) {
			return openStructural, fmt.Errorf("the file to be replaced fails to open as a workspace (%v)", err)
		}
		return openOther, err
	}
	st, ahead, err := openDest(dest, cred)
	if err == nil {
		return st, ahead, openOK, nil
	}
	if !wrongCredential(err) {
		how, e := classify(err)
		return nil, false, how, e
	}
	pol, _, derr := Describe(dest)
	if derr == nil && pol == unlock.Strict {
		// no recovery path exists to present, whatever CurrentRecovery holds
		return nil, false, openNeedsCredential, needCredentialErr("the credential presented for the backup does not open the workspace to be replaced (its key slots changed since the backup)", nil, true)
	}
	in := o.CurrentRecovery
	if in == nil || (in.Recovery == nil && in.Source == nil) {
		return nil, false, openNeedsCredential, needCredential("the credential presented for the backup does not open the workspace to be replaced (its key slots changed since the backup)", nil)
	}
	if derr != nil {
		how, e := classify(derr)
		return nil, false, how, e
	}
	if pol == "standard" {
		rk, rerr := in.Recovery(ctx)
		if rerr != nil {
			return nil, false, openNeedsCredential, needCredential("the recovery key of the workspace to be replaced could not be read", rerr)
		}
		defer rk.Destroy()
		st, ahead, err = openDest(dest, credential{kind: seal.SlotRecovery, buf: rk})
	} else {
		if in.Source == nil {
			return nil, false, openNeedsCredential, needCredential("there is no factor source to present the recovery authenticator of the workspace to be replaced", nil)
		}
		st, ahead, err = openDest(dest, credential{kind: credFactors, factors: in})
	}
	if err != nil {
		if wrongCredential(err) {
			return nil, false, openNeedsCredential, needCredential("the recovery material presented does not open the workspace to be replaced", nil)
		}
		how, e := classify(err)
		return nil, false, how, e
	}
	return st, ahead, openOK, nil
}

func wrongCredential(err error) bool {
	return errors.Is(err, ErrWrongCredential) || errors.Is(err, ErrNoFactorSlot)
}

// auditNote appends an audit row of event(s) that change no record.
func (s *Store) auditNote(ctx context.Context, events [][]any) error {
	_, err := s.withWriteTx(ctx, func(q dbq) (*Head, error) {
		set, err := slotSetHash(ctx, q)
		if err != nil {
			return nil, err
		}
		prev, err := chainHead(ctx, q)
		if err != nil {
			return nil, err
		}
		return appendAudit(ctx, q, s.ws, s.keys, auditSlots, s.now().Unix(), prev, events, nil, set)
	}, nil)
	return err
}
