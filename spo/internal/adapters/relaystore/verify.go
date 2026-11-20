package relaystore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objregistry"
	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
)

// VerifyOptions choose what verify may do beyond reading.
type VerifyOptions struct {
	// Probe runs the checks that write: the self-test of both buckets with the
	// retention part (which leaves one object in the registry bucket's
	// selftest/, locked for a day), the default-retention probe, and the
	// probes of the simple-delete denies on names under selftest/ that the
	// policy's patterns match. Each removes what it wrote where the store lets
	// it.
	Probe bool
	// Operator asks for the reads that need the operator's own credentials
	// (bucket policy, lifecycle, encryption, default retention). The client
	// cannot make them: the check says which calls are missing.
	Operator bool
	// MaxVersions bounds the tombstone versions read
	// (relayregistry.MaxTombstoneVersions by default); MaxObjects the mailbox
	// objects (objmailbox.MaxObjects by default).
	MaxVersions, MaxObjects int
}

// BindingView is one stored binding as a load would see it.
type BindingView struct {
	Device  party.Fingerprint
	Size    int64
	Verdict string
	Detail  string
}

// VerifyReport is what store verify found.
type VerifyReport struct {
	Identity string
	Checks   []Check
	State    StoreState
	Tombs    TombView
	Bindings []BindingView
	Mailbox  MailboxView
	// Policy is the reference block of statements to compare with the buckets.
	Policy string
}

// Failed reports whether any check failed: store verify then exits non-zero.
func (r VerifyReport) Failed() bool { return failed(r.Checks) }

func (r *VerifyReport) add(name string, v Verdict, format string, a ...any) {
	r.Checks = append(r.Checks, Check{name, v, fmt.Sprintf(format, a...)})
}

// Verify checks one identity's store as ADR 0015 decision 2 and work package 9
// describe: the bucket properties the relay's role can observe, the markers,
// the lease, the version-aware tombstone view, the bindings, the mailbox and
// the rate object. Without Probe it only reads. It does not take the lease.
// A check that the relay's role cannot make says so (NotVerifiable), and the
// report carries the statements to compare.
func Verify(ctx context.Context, d Deps, o VerifyOptions) (VerifyReport, error) {
	s, err := newSession(d)
	if err != nil {
		return VerifyReport{}, err
	}
	rep := VerifyReport{Identity: s.nodeHex, Policy: PolicyStatements(s.nodeHex)}
	s.verifyBuckets(ctx, o, &rep)
	if rep.State, err = s.readState(ctx); err != nil {
		return rep, err
	}
	s.verifyMarkers(&rep)
	s.verifyLease(&rep)
	if err := s.verifyRecord(ctx, &rep); err != nil {
		return rep, err
	}
	maxV := o.MaxVersions
	if maxV <= 0 {
		maxV = relayregistry.MaxTombstoneVersions
	}
	// the bindings first, so the scan keeps only the names that apply to them
	bl, err := s.listBindings(ctx)
	if err != nil {
		return rep, err
	}
	tc := newTombChecks(s)
	tv, err := s.scanTombstones(ctx, scanOpts{maxVersions: maxV, want: bl.want, version: tc.version, name: tc.name})
	if err != nil {
		if !errors.Is(err, s3client.ErrListLimit) && !errors.Is(err, s3client.ErrBadListing) {
			return rep, err
		}
		rep.add("tombstones: listing", Failure, "%v", err)
	} else {
		rep.add("tombstones: listing", OK, "%d name(s), %d version(s), %d delete marker(s)", tv.NameCount, tv.Versions, tv.DeleteMarkers)
	}
	rep.Tombs = tv
	tc.report(&rep)
	s.verifyBindings(bl, &rep)
	ms, err := s.scanMailbox(ctx, o.MaxObjects, 0)
	if err != nil {
		if !errors.Is(err, s3client.ErrListLimit) && !errors.Is(err, s3client.ErrBadListing) {
			return rep, err
		}
		rep.add("mailbox: bounds", Failure, "%v; the relay refuses to start", err)
	}
	rep.Mailbox = ms.view
	verifyMailbox(&rep)
	s.verifyRates(ctx, &rep)
	if o.Operator {
		rep.add("operator reads: bucket policy, lifecycle, encryption, default retention", NotVerifiable, "%s", missingClientCalls)
	}
	return rep, nil
}

func (s *session) verifyBuckets(ctx context.Context, o VerifyOptions, rep *VerifyReport) {
	rctx, cancel := context.WithTimeout(ctx, s.reqMax)
	st, err := s.rc.Versioning(rctx)
	cancel()
	switch {
	case err != nil:
		rep.add("registry bucket: versioning on", Failure, "%v", err)
	case st != "Enabled":
		rep.add("registry bucket: versioning on", Failure, "the bucket reports versioning %q; tombstones are read from versions", st)
	default:
		rep.add("registry bucket: versioning on", OK, "Enabled")
	}
	rctx, cancel = context.WithTimeout(ctx, s.reqMax)
	st, err = s.wc.Versioning(rctx)
	cancel()
	switch {
	case err != nil:
		rep.add("working bucket: versioning never enabled", Failure, "%v", err)
	case st != "":
		rep.add("working bucket: versioning never enabled", Failure, "the bucket reports versioning %q: an acknowledged envelope stays as a noncurrent version (SPO-Xobjstore-PRE-005); use a bucket whose versioning was never enabled", st)
	default:
		rep.add("working bucket: versioning never enabled", OK, "no versioning status")
	}
	rctx, cancel = context.WithTimeout(ctx, s.reqMax)
	on, err := s.rc.ObjectLockEnabled(rctx)
	cancel()
	switch {
	case err != nil:
		rep.add("registry bucket: Object Lock enabled", Failure, "%v", err)
	case !on:
		rep.add("registry bucket: Object Lock enabled", Failure, "Object Lock is not enabled: tombstone versions cannot be locked")
	default:
		rep.add("registry bucket: Object Lock enabled", OK, "Enabled")
	}
	const noRole = "not verifiable from the relay's role; compare the policy with the reference statements"
	if !o.Probe {
		rep.add("registry bucket: no default retention", NotVerifiable, "a probe writes an object; run with --probe")
		rep.add("registry bucket: a simple delete of a tombstone is refused", NotVerifiable, "the self-test probes it; run with --probe")
		rep.add("registry bucket: a simple delete of the marker is refused", NotVerifiable, "a probe of a name under selftest/ that relays/*/marker matches; run with --probe")
		rep.add("working bucket: a simple delete of the lease is refused", NotVerifiable, "a probe of a name under selftest/ that relays/*/lease matches; run with --probe")
	} else {
		cs := s.selfTests(ctx, true)
		rep.Checks = append(rep.Checks, cs...)
		deny := Check{"registry bucket: a simple delete of a tombstone is refused", OK, "a simple delete of registry/tombstones/selftest-<16 hex> was refused for the relay's role; that the deny holds for every principal is " + noRole}
		for _, c := range cs {
			if c.Name == "registry bucket self-test" && c.Verdict == Failure {
				deny.Verdict, deny.Detail = NotVerifiable, "the self-test failed before or at the probe: "+c.Detail
				if strings.Contains(c.Detail, s3client.PropDenySimpleDelete) {
					deny.Verdict = Failure
				}
			}
		}
		rep.Checks = append(rep.Checks, deny, s.probeMarkerDeny(ctx), s.probeLeaseDeny(ctx))
	}
	rep.add("registry bucket: no governance bypass", NotVerifiable, "the client sends no bypass header; %s", noRole)
	rep.add("registry bucket: no retention longer than 182 days on a tombstone, 366 on the marker", NotVerifiable, "a probe would leave an object locked for half a year if the deny were missing; %s", noRole)
	rep.add("registry bucket: no legal hold", NotVerifiable, "the client cannot set a legal hold; %s", noRole)
	rep.add("both buckets: requests without TLS and puts without a condition denied", NotVerifiable, "the client sends neither (it refuses http and has no unconditional put); %s", noRole)
}

// probeMarkerDeny makes a simple delete of <prefix>selftest/<16 hex>/marker,
// a name relays/*/marker matches (in a policy '*' spans '/'). Refused: the
// relay's role cannot add a delete marker over the marker. Applied: the delete
// marker it made is removed by its version id (the role may delete versions
// under selftest/), and the check fails.
func (s *session) probeMarkerDeny(ctx context.Context) Check {
	const name = "registry bucket: a simple delete of the marker is refused"
	tag, err := s.randHex(8)
	if err != nil {
		return Check{name, NotVerifiable, err.Error()}
	}
	key := s.prefix + pathSelftest + tag + "/marker"
	rctx, cancel, _ := s.rq(ctx)
	res, err := s.rc.Delete(rctx, key)
	cancel()
	if errors.Is(err, s3client.ErrAccessDenied) && !errors.Is(err, s3client.ErrOutcomeUnknown) {
		return Check{name, OK, "a simple delete of a name that relays/*/marker matches was refused for the relay's role; that the deny holds for every principal is not verifiable from the role"}
	}
	s.removeVersions(ctx, s.rc, key, res.VersionID)
	return Check{name, Failure, fmt.Sprintf("a simple delete of %s was not refused (%v): without the deny a simple delete adds a delete marker over the marker; add the statement DenySimpleDeleteOfTombstonesAndMarker", strings.TrimPrefix(key, s.prefix), err)}
}

// probeLeaseDeny makes a simple delete of <prefix>selftest/<16 hex>/lease in
// the working bucket, where the role may delete objects of its prefix: only a
// deny matching relays/*/lease refuses it. The name holds nothing, so an
// applied delete leaves nothing.
func (s *session) probeLeaseDeny(ctx context.Context) Check {
	const name = "working bucket: a simple delete of the lease is refused"
	tag, err := s.randHex(8)
	if err != nil {
		return Check{name, NotVerifiable, err.Error()}
	}
	key := s.prefix + pathSelftest + tag + "/lease"
	rctx, cancel, _ := s.rq(ctx)
	_, err = s.wc.Delete(rctx, key)
	cancel()
	if errors.Is(err, s3client.ErrAccessDenied) && !errors.Is(err, s3client.ErrOutcomeUnknown) {
		return Check{name, OK, "a simple delete of a name that relays/*/lease matches was refused, where the role may delete: the deny is in force"}
	}
	return Check{name, Failure, fmt.Sprintf("a simple delete of %s was not refused (%v): add the statement DenyLeaseDelete (relays/*/lease)", strings.TrimPrefix(key, s.prefix), err)}
}

// removeVersions deletes, by version id, the given version and every delete
// marker listed under key (a probe's leftovers).
func (s *session) removeVersions(ctx context.Context, c *s3client.Client, key, vid string) {
	if vid != "" {
		if rctx, cancel, err := s.rq(ctx); err == nil {
			_, _ = c.DeleteVersion(rctx, key, vid)
			cancel()
		}
	}
	vs, err := s.listVersions(ctx, c, key, 16)
	if err != nil {
		return
	}
	for _, v := range vs {
		if v.Key == key && v.DeleteMarker {
			if rctx, cancel, err := s.rq(ctx); err == nil {
				_, _ = c.DeleteVersion(rctx, key, v.VersionID)
				cancel()
			}
		}
	}
}

func (s *session) verifyMarkers(rep *VerifyReport) {
	st := rep.State
	mv := st.Registry
	switch {
	case mv.Ours:
		v, why := OK, fmt.Sprintf("version %s, %s; %d version(s), %d delete marker(s)", mv.Newest.ID, lockText(mv.Newest.Lock), len(mv.Versions)-mv.DeleteMarkers, mv.DeleteMarkers)
		lock := mv.Newest.Lock
		switch {
		case lock == nil:
			v, why = Failure, "the identity's newest marker version is not locked: "+why
		case s.mode == s3client.Compliance && lock.Mode != s3client.Compliance:
			v, why = Failure, "the identity's newest marker version is locked in "+string(lock.Mode)+" mode in a compliance deployment: "+why
		case mv.OverOther > 0:
			// changed after the review of work package 9: a failure, not a warning
			v, why = Failure, fmt.Sprintf("%d version(s) newer than the identity's marker are not its marker (%d naming another identity, %d not markers): the relay finds its marker under them, but someone wrote them with the role or the operator's rights; find who (store inspect --bucket registry --path marker --versions), and the relay's next renewal writes on top: %s", mv.OverOther, mv.Other, mv.Junk, why)
		case mv.OverDeleteMarkers > 0:
			v, why = Failure, fmt.Sprintf("%d delete marker(s) over the identity's marker: a simple delete of the marker was made (is DenySimpleDeleteOfTombstonesAndMarker in the policy?); the relay reads versions and still finds it; store repair --action delete-markers removes them: %s", mv.OverDeleteMarkers, why)
		case lock.Until.Sub(s.now()) < objregistry.MarkerRenewBefore:
			v, why = Warning, "the lock ends within 30 days; the relay's sweep writes a new version: "+why
		case mv.DeleteMarkers > 0:
			v, why = Warning, "delete markers under the marker hide nothing from the relay; the relay's sweep or store repair --action delete-markers removes them: "+why
		}
		rep.add("registry bucket: marker", v, "%s", why)
	case mv.Other > 0:
		rep.add("registry bucket: marker", Failure, "the marker names another relay identity: this is not this identity's prefix or bucket")
	case st.HasState() || st.Working == MarkerOurs:
		rep.add("registry bucket: marker", Failure, "missing while the identity holds state: the relay refuses to start (the store looks emptied); do not run init-store over it")
	default:
		rep.add("registry bucket: marker", Warning, "missing, and the identity holds nothing: a new store; run init-store")
	}
	switch st.Working {
	case MarkerOurs:
		rep.add("working bucket: marker", OK, "names this identity")
	case MarkerOther:
		rep.add("working bucket: marker", Failure, "the marker names another relay identity")
	case MarkerNotOurs:
		rep.add("working bucket: marker", Failure, "the object at the marker's name is not a marker: the relay refuses to start")
	default:
		if st.HasState() || mv.Ours {
			rep.add("working bucket: marker", Failure, "missing while the identity holds state or its registry marker: the relay refuses to start (the store looks emptied)")
		} else {
			rep.add("working bucket: marker", Warning, "missing, and the identity holds nothing: a new store; run init-store")
		}
	}
}

func (s *session) verifyLease(rep *VerifyReport) {
	lv := rep.State.Lease
	switch lv.State {
	case "absent":
		rep.add("lease", Warning, "absent: it is treated as lapsed, so the next start waits the take-after time and the drain; init-store writes it for a new store")
	case "unreadable":
		rep.add("lease", Failure, "unreadable (%s): the relay refuses to start; check that no relay of this identity runs, then: spo-relay store repair --action lease", lv.Cause)
	case "foreign":
		rep.add("lease", Failure, "it names another relay identity (%s): the relay refuses to start; spo-relay store repair --action lease", lv.Cause)
	default:
		r := lv.Record
		age := "an age the store does not report"
		if lv.Age > 0 {
			age = lv.Age.Truncate(time.Second).String()
		}
		detail := fmt.Sprintf("%s by holder %s, generation %d, counter %d, duration %v, margin %v, written %s ago", r.State, r.Holder, r.Generation, r.Counter, r.Duration, r.Margin, age)
		if r.State == "held" && lv.Age > r.Duration+r.Margin {
			detail += "; not renewed for longer than its take-after time: the holder has stopped, and the next taker drains"
		}
		rep.add("lease", OK, "%s", detail)
	}
}

// finding is one class of finding: how many, and the first maxListedKeys.
type finding struct {
	n     int
	items []string
}

func (f *finding) add(s string) {
	if f.n++; len(f.items) < maxListedKeys {
		f.items = append(f.items, s)
	}
}

// tombChecks are the tombstone checks, folded version by version as the scan
// reads them (scanOpts.version, scanOpts.name): counts and the first keys of
// each class, never the listing (changed after the review of work package 9).
type tombChecks struct {
	now                                   int64
	mode                                  s3client.Mode
	unlocked, wrongMode, short, long      finding
	unreadable, markers, foreign, current finding
	stale, gone                           finding
	dms                                   int // delete markers of the name being read
}

func newTombChecks(s *session) *tombChecks { return &tombChecks{now: s.now().Unix(), mode: s.mode} }

func (c *tombChecks) version(n *TombName, v TombVersion) {
	if n.Foreign {
		return
	}
	id := n.Name + "@" + v.ID
	switch {
	case v.DeleteMarker:
		c.dms++
		return
	case v.Gone:
		c.gone.add(id)
		return
	case v.Unreadable:
		c.unreadable.add(fmt.Sprintf("%s (enforced at the strictest reading: %s)", id, unixText(v.NotBefore)))
	}
	// every check below reads the lock through a nil check of its own: store
	// content never makes the tool panic (changed after the review of work
	// package 9, whose mutants of these lines panicked)
	l := v.Lock
	if l == nil {
		c.unlocked.add(id)
	}
	if l != nil && c.mode == s3client.Compliance && l.Mode != s3client.Compliance {
		c.wrongMode.add(id + " (" + string(l.Mode) + ")")
	}
	// a lock that ends before the tombstone's life does: whoever can write
	// one (the relay's role can) can delete it by its id once it ends, and the
	// revocation with it (changed after the review of work package 9: a
	// failure while the life has not ended; it was a warning)
	if need := objregistry.TombstoneLockNeed(v.NotBefore); l != nil && !v.Unreadable && need > c.now && l.Until.Unix() < need {
		c.short.add(fmt.Sprintf("%s (locked until %s, needs %s)", id, unixText(l.Until.Unix()), unixText(need)))
	}
	if l != nil && l.Until.Unix() > c.now+objregistry.MaxLockAhead {
		c.long.add(fmt.Sprintf("%s (locked until %s)", id, unixText(l.Until.Unix())))
	}
}

func (c *tombChecks) name(n *TombName) {
	dms := c.dms
	c.dms = 0
	if n.Foreign {
		c.foreign.add(n.Name)
		return
	}
	if dms > 0 {
		c.markers.add(fmt.Sprintf("%s (%d)", n.Name, dms))
	}
	if n.CurrentLower {
		c.current.add(n.Name)
	}
	if n.Stale {
		c.stale.add(n.Name)
	}
}

func (c *tombChecks) report(rep *VerifyReport) {
	verdict := func(name string, f finding, bad Verdict, what, fine string) {
		if f.n == 0 {
			rep.add(name, OK, "%s", fine)
			return
		}
		more := ""
		if f.n > len(f.items) {
			more = fmt.Sprintf(" and %d more", f.n-len(f.items))
		}
		rep.add(name, bad, "%d: %s%s; %s", f.n, strings.Join(f.items, ", "), more, what)
	}
	verdict("tombstones: every version locked", c.unlocked, Failure, "an unlocked version can be deleted by its version id, which removes what it revokes; the relay writes none", "every object version is locked")
	verdict("tombstones: every version locked in the deployment's mode", c.wrongMode, Failure, "a governance lock can be removed by whoever is granted the bypass (ADR 0015 decision 10)", "every lock is in the deployment's mode or compliance")
	verdict("tombstones: locks cover their tombstones", c.short, Failure, "a lock that ends before the tombstone's life lets whoever wrote it (the relay's role can) delete the version by its id then, and the revocation with it; the relay writes none; the relay's next revoke of the scope, or migrate-store, writes its own version locked for the life", "every lock covers its tombstone's life")
	verdict("tombstones: no lock longer than a revoke needs", c.long, Warning, "one longer than a verified revoke needs is not the relay's (the 182-day deny should stop it)", "none")
	verdict("tombstones: unreadable versions", c.unreadable, Warning, "each revokes its scope until its lock ends (SPO-Xobjstore-PRE-809); none is the relay's", "every version is a tombstone")
	verdict("tombstones: delete markers", c.markers, Warning, "they hide nothing from the relay, which reads versions; their presence means a simple delete was made (is the deny in the policy?); store repair --action delete-markers removes them", "none")
	verdict("tombstones: foreign objects", c.foreign, Warning, "objects whose name is not a tombstone's are ignored by the relay and count against the version ceiling", "none")
	verdict("tombstones: current versions", c.current, Warning, "a version lower than an older one was written on top; the highest is enforced", "every current version holds the name's highest value")
	verdict("tombstones: listing agrees with the objects", c.stale, Failure, "the listing's latest version is not what the store serves: the relay refuses to start; run verify again", "yes")
	if c.gone.n > 0 {
		rep.add("tombstones: versions gone since the listing", Warning, "%d: %s", c.gone.n, strings.Join(c.gone.items, ", "))
	}
}

// bindingList is the bindings under registry/bindings/, verified as a load
// verifies them before the tombstones are known, and the tombstone names
// that apply to them (a scan keeps only those). At most
// mailbox.MaxBoundDevices bindings, each at most a record's size, are held.
type bindingList struct {
	views   []BindingView
	checked []checkedBinding
	bad     finding
	over    bool // past mailbox.MaxBoundDevices: the relay refuses to start
	want    map[relayregistry.TombKey]bool
}

func (s *session) listBindings(ctx context.Context) (bindingList, error) {
	pol := coreOf(s.d).Policy
	now := s.now().Unix()
	bl := bindingList{want: map[relayregistry.TombKey]bool{}}
	prefix := s.prefix + pathBindings
	err := s.listObjects(ctx, s.rc, prefix, mailbox.MaxBoundDevices, func(o objInfo) error {
		name := strings.TrimPrefix(o.Key, prefix)
		d, ok := parseDevice(name)
		if !ok {
			bl.bad.add(name)
			return nil
		}
		bv := BindingView{Device: d, Size: o.Size}
		if o.Size > int64(maxRecordBytes) {
			bl.views = append(bl.views, bv)
			bl.checked = append(bl.checked, checkedBinding{verdict: bindUnverified, cause: errors.New("larger than a record")})
			return nil
		}
		rctx, cancel, err := s.rq(ctx)
		if err != nil {
			return err
		}
		got, err := s.rc.Get(rctx, s3client.GetInput{Key: o.Key, MaxBytes: int64(maxRecordBytes)})
		cancel()
		switch {
		case errors.Is(err, s3client.ErrNotFound):
			return nil
		case errors.Is(err, s3client.ErrTooLarge):
			bl.views = append(bl.views, bv)
			bl.checked = append(bl.checked, checkedBinding{verdict: bindUnverified, cause: errors.New("larger than a record")})
			return nil
		case err != nil:
			return fmt.Errorf("the binding %s cannot be read: %w", name, err)
		}
		c := checkBinding(d, got.Body, now, pol)
		for _, k := range c.names(d) {
			bl.want[k] = true
		}
		bl.views = append(bl.views, bv)
		bl.checked = append(bl.checked, c)
		return nil
	})
	switch {
	case errors.Is(err, s3client.ErrListLimit):
		bl.over = true
		return bl, nil
	case err != nil:
		return bl, err
	}
	return bl, nil
}

// verifyBindings admits each listed binding against the tombstone view.
func (s *session) verifyBindings(bl bindingList, rep *VerifyReport) {
	pol := coreOf(s.d).Policy
	now := s.now().Unix()
	tombs := rep.Tombs.tombsOf()
	var below, aside finding
	for i, c := range bl.checked {
		bv := bl.views[i]
		v, cause := c.admit(bv.Device, now, pol, tombs)
		bv.Verdict = v.String()
		if cause != nil {
			bv.Detail = cause.Error()
		}
		switch v {
		case bindRevoked:
			below.add(fp(bv.Device))
		case bindUnverified:
			aside.add(fp(bv.Device))
		}
		rep.Bindings = append(rep.Bindings, bv)
	}
	switch {
	case bl.over:
		rep.add("bindings", Failure, "more than %d bindings: the relay refuses to start", mailbox.MaxBoundDevices)
	case bl.bad.n > 0:
		rep.add("bindings", Failure, "%d name(s) under registry/bindings/ are not a device's: %s; the relay refuses to start", bl.bad.n, strings.Join(bl.bad.items, ", "))
	case below.n+aside.n > 0:
		rep.add("bindings", Warning, "%d below a tombstone (%s), %d failing verification (%s): the load drops the first and leaves the second unloaded", below.n, strings.Join(below.items, ", "), aside.n, strings.Join(aside.items, ", "))
	default:
		rep.add("bindings", OK, "%d binding(s); every one verifies against the tombstone view", len(rep.Bindings))
	}
}

func verifyMailbox(rep *VerifyReport) {
	m := rep.Mailbox
	switch {
	case m.UnparsableN+m.BadSizeN > 0:
		rep.add("mailbox: every key parses", Failure, "%d key(s) that are not entry keys (%s) and %d of a size outside 1 B to 1 MiB (%s): the relay refuses to start; store repair --action mailbox-unparsable deletes them", m.UnparsableN, strings.Join(m.Unparsable, ", "), m.BadSizeN, strings.Join(m.BadSize, ", "))
	default:
		rep.add("mailbox: every key parses", OK, "%d object(s), %d byte(s), %d mailbox(es)", m.Objects, m.Bytes, m.RecipientsN)
	}
	if m.TooManyN > 0 {
		rep.add("mailbox: bounds", Failure, "%d mailbox(es) hold more than 512 objects: the relay refuses to start", m.TooManyN)
	}
	var doomed finding
	for _, r := range m.Recipients {
		if r.DuplicatesN+r.OverBoundN > 0 {
			doomed.add(fmt.Sprintf("%s: %d later duplicate(s), %d past the 256 entries", short(fp(r.Recipient)), r.DuplicatesN, r.OverBoundN))
		}
	}
	if doomed.n > 0 {
		rep.add("mailbox: entries a load dooms", Warning, "%s; the relay counts them, lists none and its sweep deletes them; store repair --action mailbox-duplicates or mailbox-over-bound deletes them now", strings.Join(doomed.items, "; "))
	} else {
		rep.add("mailbox: entries a load dooms", OK, "none")
	}
}

// verifyRecord reports a migration record: a failure, whether it is the
// leftover of a completed migration (repair --action migration-record) or a
// migration in progress (migrate-store again); a relay does not read it, but
// it says that the store's state was not finished, and no other writer makes
// one.
func (s *session) verifyRecord(ctx context.Context, rep *VerifyReport) error {
	const name = "migration record"
	record, err := s.hasMigrationRecord(ctx)
	switch {
	case errors.Is(err, ErrForeign):
		rep.add(name, Failure, "%v; it is not this tool's: find who wrote it (store inspect --bucket working --path migration)", err)
	case err != nil:
		return err
	case !record:
		rep.add(name, OK, "none")
	case rep.State.Initialised() && rep.State.Lease.State == "record":
		rep.add(name, Failure, "%s is left by a migration whose markers and lease are written; delete it: spo-relay store repair --action migration-record", migrationPath)
	default:
		rep.add(name, Failure, "%s is there and the markers are not both written: a migration is incomplete (or the record was planted); run spo-relay migrate-store again, which refuses a store that is not its own interrupted migration", migrationPath)
	}
	return nil
}

func (s *session) verifyRates(ctx context.Context, rep *VerifyReport) {
	rctx, cancel, err := s.rq(ctx)
	if err != nil {
		rep.add("rates", NotVerifiable, "%v", err)
		return
	}
	got, err := s.wc.Get(rctx, s3client.GetInput{Key: s.prefix + pathRates, MaxBytes: int64(ratesBytes)})
	cancel()
	switch {
	case errors.Is(err, s3client.ErrNotFound):
		rep.add("rates", Warning, "missing: the relay starts with empty rate buckets (no new bindings and no recorded revokes of nothing until they refill)")
	case errors.Is(err, s3client.ErrTooLarge):
		rep.add("rates", Warning, "larger than a rate object: the relay starts with empty buckets")
	case err != nil:
		rep.add("rates", Failure, "the rate object cannot be read: %v", err)
	default:
		if r, derr := objregistry.DecodeRates(got.Body); derr != nil {
			rep.add("rates", Warning, "unreadable (%v): the relay starts with empty buckets", derr)
		} else {
			rep.add("rates", OK, "new bindings %d unit(s) at %s, revokes %d unit(s) at %s", r.NewBindings.Units, unixText(r.NewBindings.At), r.Revokes.Units, unixText(r.Revokes.At))
		}
	}
}

func coreOf(d Deps) relayregistry.Config {
	if d.Core.MaxBoundDevices == 0 {
		return relayregistry.DefaultConfig()
	}
	return d.Core
}
