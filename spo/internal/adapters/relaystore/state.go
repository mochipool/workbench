package relaystore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objlease"
	"github.com/mochipool/workbench/spo/internal/adapters/objregistry"
	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
)

// MarkerVersion is one entry of the registry marker's version listing.
type MarkerVersion struct {
	ID           string
	DeleteMarker bool
	Latest       bool
	// Kind is "this identity", "another identity" or "not a marker" for an
	// object version.
	Kind string
	Lock *s3client.Retention
}

// MarkerView is what the registry bucket's marker listing shows.
type MarkerView struct {
	Versions []MarkerVersion
	// Ours is true when an object version names this identity; Newest is the
	// newest such version.
	Ours   bool
	Newest *MarkerVersion
	// Other and Junk count object versions naming another identity and object
	// versions that are not markers.
	Other, Junk int
	// DeleteMarkers counts delete markers; CurrentDeleted is true when the
	// current entry is one.
	DeleteMarkers  int
	CurrentDeleted bool
	// Over counts the entries newer than Newest: delete markers and object
	// versions that are not this identity's marker. The relay's load still
	// finds its marker under them (it reads versions); store verify fails them
	// (changed after the review of work package 9).
	OverDeleteMarkers, OverOther int
}

// WorkingMarker is the working bucket's marker: "absent", "this identity",
// "another identity" or "not a marker".
type WorkingMarker string

// The states of the working marker.
const (
	MarkerAbsent  WorkingMarker = "absent"
	MarkerOurs    WorkingMarker = "this identity"
	MarkerOther   WorkingMarker = "another identity"
	MarkerNotOurs WorkingMarker = "not a marker"
)

// LeaseView is what the lease object holds.
type LeaseView struct {
	// State is "absent", "record", "unreadable" or "foreign".
	State  string
	Record objlease.Record
	ETag   string
	// Age is how long ago the store says the object was last written (zero
	// when the store does not say).
	Age   time.Duration
	Cause string
}

// StoreState is what an identity's prefix holds, read without a write.
type StoreState struct {
	Registry MarkerView
	Working  WorkingMarker
	// RegistryState: the registry bucket holds a version or a delete marker
	// under registry/ (the self-test's probe name excepted). WorkingState: the
	// working bucket holds an object under registry/ or mailbox/.
	RegistryState, WorkingState bool
	Lease                       LeaseView
}

// HasState reports whether either bucket holds state of the identity.
func (st StoreState) HasState() bool { return st.RegistryState || st.WorkingState }

// Initialised reports both markers present and naming this identity.
func (st StoreState) Initialised() bool { return st.Registry.Ours && st.Working == MarkerOurs }

// refusal is why init-store or migrate-store must not write markers on this
// store, or nil.
func (st StoreState) refusal() error {
	switch {
	case st.Registry.Other > 0 && !st.Registry.Ours:
		return fmt.Errorf("%w: the registry bucket's marker names another relay identity", ErrForeign)
	case st.Working == MarkerOther:
		return fmt.Errorf("%w: the working bucket's marker names another relay identity", ErrForeign)
	case st.Working == MarkerNotOurs:
		return fmt.Errorf("%w: the working bucket holds an object at the marker's name that is not a marker", ErrForeign)
	case st.Lease.State == "foreign" || st.Lease.State == "unreadable":
		return fmt.Errorf("%w (%s); check that no relay of this identity runs, then run: spo-relay store repair --action lease", ErrLeaseUnreadable, st.Lease.Cause)
	case !st.Registry.Ours && (st.RegistryState || st.Working == MarkerOurs || st.WorkingState):
		return fmt.Errorf("%w: the registry bucket has no marker of this identity, and the store holds its state or its working marker; its tombstones may be lost. See docs/how-to/initialise-and-migrate-a-relay-store.md", ErrEmptied)
	case st.Registry.Ours && st.Working != MarkerOurs && st.WorkingState:
		return fmt.Errorf("%w: the working bucket has no marker of this identity and holds its state", ErrEmptied)
	}
	return nil
}

// readState reads the markers, whether there is state, and the lease.
func (s *session) readState(ctx context.Context) (StoreState, error) {
	var st StoreState
	var err error
	if st.Registry, err = s.readRegistryMarker(ctx); err != nil {
		return st, err
	}
	if st.Working, err = s.readWorkingMarker(ctx); err != nil {
		return st, err
	}
	rctx, cancel, err := s.rq(ctx)
	if err != nil {
		return st, err
	}
	p, err := s.rc.ListVersions(rctx, s3client.VersionsInput{Prefix: s.prefix + "registry/", MaxKeys: 16})
	cancel()
	if err != nil {
		return st, fmt.Errorf("the registry bucket's listing: %w", err)
	}
	for _, v := range p.Versions {
		if !objregistry.IsProbeName(strings.TrimPrefix(v.Key, s.prefix+pathTombstones)) {
			st.RegistryState = true
		}
	}
	st.RegistryState = st.RegistryState || p.Truncated
	for _, sub := range []string{"registry/", pathMailbox} {
		rctx, cancel, err := s.rq(ctx)
		if err != nil {
			return st, err
		}
		page, err := s.wc.List(rctx, s3client.ListInput{Prefix: s.prefix + sub, MaxKeys: 1})
		cancel()
		if err != nil {
			return st, fmt.Errorf("the working bucket's listing: %w", err)
		}
		st.WorkingState = st.WorkingState || len(page.Objects) > 0
	}
	st.Lease, err = s.readLease(ctx)
	return st, err
}

func (s *session) readRegistryMarker(ctx context.Context) (MarkerView, error) {
	var mv MarkerView
	key := s.prefix + pathMarker
	vs, err := s.listVersions(ctx, s.rc, key, objregistry.MaxMarkerEntries)
	if err != nil {
		return mv, fmt.Errorf("the marker's version listing: %w", err)
	}
	for _, v := range vs {
		if v.Key != key {
			continue
		}
		e := MarkerVersion{ID: v.VersionID, DeleteMarker: v.DeleteMarker, Latest: v.IsLatest}
		if v.DeleteMarker {
			mv.DeleteMarkers++
			mv.CurrentDeleted = mv.CurrentDeleted || v.IsLatest
			if !mv.Ours {
				mv.OverDeleteMarkers++
			}
			mv.Versions = append(mv.Versions, e)
			continue
		}
		if mv.Ours {
			// below the identity's newest, which decides: not read
			e.Kind = "older than the identity's newest (not read)"
			mv.Versions = append(mv.Versions, e)
			continue
		}
		rctx, cancel, err := s.rq(ctx)
		if err != nil {
			return mv, err
		}
		got, gerr := s.rc.Get(rctx, s3client.GetInput{Key: key, VersionID: v.VersionID, MaxBytes: int64(markerBytes)})
		cancel()
		switch {
		case errors.Is(gerr, s3client.ErrTooLarge):
			e.Kind, mv.Junk = "not a marker", mv.Junk+1
			e.Lock = s.headLock(ctx, s.rc, key, v.VersionID)
		case gerr != nil:
			return mv, fmt.Errorf("the marker's version %s cannot be read: %w", v.VersionID, gerr)
		default:
			e.Lock = got.Info.Retention
			switch node, derr := decodeMarker(got.Body); {
			case derr != nil:
				e.Kind, mv.Junk = "not a marker", mv.Junk+1
			case node != s.node:
				e.Kind, mv.Other = "another identity", mv.Other+1
			default:
				e.Kind = "this identity"
				mv.Ours = true
				c := e
				mv.Newest = &c
			}
		}
		if e.Kind != "this identity" {
			mv.OverOther++
		}
		mv.Versions = append(mv.Versions, e)
	}
	return mv, nil
}

// markerLocked reports the identity's newest marker version locked in the
// deployment's mode or compliance until after now: the positive evidence
// that the registry bucket is the identity's (a role holder cannot delete
// it, and an emptied bucket does not have it).
func (s *session) markerLocked(mv MarkerView) bool {
	n := mv.Newest
	return mv.Ours && n != nil && n.Lock != nil && (n.Lock.Mode == s.mode || n.Lock.Mode == s3client.Compliance) && n.Lock.Until.After(s.now())
}

// headLock is a version's lock as a head reports it (nil when it cannot).
func (s *session) headLock(ctx context.Context, c *s3client.Client, key, id string) *s3client.Retention {
	rctx, cancel, err := s.rq(ctx)
	if err != nil {
		return nil
	}
	defer cancel()
	info, err := c.Head(rctx, key, id)
	if err != nil {
		return nil
	}
	return info.Retention
}

func (s *session) readWorkingMarker(ctx context.Context) (WorkingMarker, error) {
	rctx, cancel, err := s.rq(ctx)
	if err != nil {
		return "", err
	}
	got, err := s.wc.Get(rctx, s3client.GetInput{Key: s.prefix + pathMarker, MaxBytes: int64(markerBytes)})
	cancel()
	switch {
	case errors.Is(err, s3client.ErrNotFound):
		return MarkerAbsent, nil
	case errors.Is(err, s3client.ErrTooLarge):
		return MarkerNotOurs, nil
	case err != nil:
		return "", fmt.Errorf("the working bucket's marker cannot be read: %w", err)
	}
	node, err := decodeMarker(got.Body)
	switch {
	case err != nil:
		return MarkerNotOurs, nil
	case node != s.node:
		return MarkerOther, nil
	}
	return MarkerOurs, nil
}

func (s *session) readLease(ctx context.Context) (LeaseView, error) {
	rctx, cancel, err := s.rq(ctx)
	if err != nil {
		return LeaseView{}, err
	}
	got, err := s.wc.Get(rctx, s3client.GetInput{Key: objlease.Key(s.nodeHex), MaxBytes: objlease.MaxRecordBytes})
	cancel()
	switch {
	case errors.Is(err, s3client.ErrNotFound):
		return LeaseView{State: "absent"}, nil
	case errors.Is(err, s3client.ErrTooLarge):
		return LeaseView{State: "unreadable", Cause: fmt.Sprintf("larger than %d bytes", objlease.MaxRecordBytes)}, nil
	case err != nil:
		return LeaseView{}, fmt.Errorf("the lease object cannot be read: %w", err)
	}
	lv := LeaseView{ETag: got.Info.ETag}
	if !got.Info.LastModified.IsZero() {
		lv.Age = s.now().Sub(got.Info.LastModified)
	}
	rec, err := objlease.Decode(got.Body)
	switch {
	case err != nil:
		lv.State, lv.Cause = "unreadable", err.Error()
	case rec.Node != s.nodeHex:
		lv.State, lv.Cause, lv.Record = "foreign", "it names the node key "+rec.Node, rec
	default:
		lv.State, lv.Record = "record", rec
	}
	return lv, nil
}

// listVersions reads the version listing under prefix page by page, each page
// under its own request context, at most limit entries (ErrListLimit past it),
// with the client's checks on each page and across pages.
func (s *session) listVersions(ctx context.Context, c *s3client.Client, prefix string, limit int) ([]s3client.Version, error) {
	var out []s3client.Version
	err := s.eachVersion(ctx, c, prefix, limit, func(v s3client.Version) bool {
		out = append(out, v)
		return true
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// eachVersion reads the version listing under prefix page by page and gives
// each entry to each, in order, holding one page: past limit entries it
// returns ErrListLimit (each has had the first limit), and it stops without
// an error when each returns false.
func (s *session) eachVersion(ctx context.Context, c *s3client.Client, prefix string, limit int, each func(s3client.Version) bool) error {
	var km, vm, last string
	n := 0
	for {
		rctx, cancel, err := s.rq(ctx)
		if err != nil {
			return err
		}
		p, err := c.ListVersions(rctx, s3client.VersionsInput{Prefix: prefix, KeyMarker: km, VersionIDMarker: vm})
		cancel()
		if err != nil {
			return err
		}
		for _, v := range p.Versions {
			if v.Key < last {
				return fmt.Errorf("%w: the listing goes back in key order", s3client.ErrBadListing)
			}
			last = v.Key
			if n++; n > limit {
				return fmt.Errorf("%w (%d) under %s", s3client.ErrListLimit, limit, prefix)
			}
			if !each(v) {
				return nil
			}
		}
		if !p.Truncated {
			return nil
		}
		if p.NextKeyMarker == km && p.NextVersionIDMarker == vm {
			return fmt.Errorf("%w: the markers do not advance", s3client.ErrBadListing)
		}
		km, vm = p.NextKeyMarker, p.NextVersionIDMarker
	}
}

// listObjects reads a listing under prefix page by page, at most limit objects.
func (s *session) listObjects(ctx context.Context, c *s3client.Client, prefix string, limit int, each func(s3client.ObjectInfo) error) error {
	token, last, n := "", "", 0
	for {
		rctx, cancel, err := s.rq(ctx)
		if err != nil {
			return err
		}
		p, err := c.List(rctx, s3client.ListInput{Prefix: prefix, ContinuationToken: token})
		cancel()
		if err != nil {
			return err
		}
		for _, o := range p.Objects {
			if o.Key <= last {
				return fmt.Errorf("%w: a page repeats or reorders keys", s3client.ErrBadListing)
			}
			last = o.Key
			if n++; n > limit {
				return fmt.Errorf("%w (%d) under %s", s3client.ErrListLimit, limit, prefix)
			}
			if err := each(o); err != nil {
				return err
			}
		}
		if !p.Truncated {
			return nil
		}
		if p.NextToken == token {
			return fmt.Errorf("%w: the continuation does not advance", s3client.ErrBadListing)
		}
		token = p.NextToken
	}
}
