package relaystore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/mochipool/workbench/spo/internal/adapters/objregistry"
	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
)

// readConcurrency is how many version reads a scan has in flight.
const readConcurrency = 8

// maxListedNames bounds the tombstone names a view keeps for its report (each
// with at most maxListedKeys versions); the rest are counted.
const maxListedNames = 64

// TombVersion is one entry of a tombstone name's version listing.
type TombVersion struct {
	ID           string
	DeleteMarker bool
	Latest       bool
	// NotBefore is the value the version holds; for an unreadable one the
	// strictest reading the relay enforces (the end of its lock, or for ever).
	NotBefore  int64
	Unreadable bool
	// Gone: listed, then answered 404 (deleted by its id since the listing).
	Gone bool
	Lock *s3client.Retention
}

// TombName is the version-aware view of one name under registry/tombstones/.
type TombName struct {
	Name string
	Key  relayregistry.TombKey
	// Foreign: the name is not a tombstone's; the relay ignores it.
	Foreign bool
	// Versions are the first maxListedKeys entries, newest first, as listed;
	// Entries counts them all (object versions and delete markers).
	Versions []TombVersion
	Entries  int
	// Highest is the highest not-before of the versions that exist
	// (relaybind.NoTombstone when none): what the relay enforces.
	Highest int64
	// CurrentLower: the current version holds less than an older one.
	CurrentLower bool
	// Stale: the listing's latest entry is not what the store serves as current.
	Stale bool
}

// TombView is the version-aware view of the identity's tombstones, kept
// bounded (changed after the review of work package 9): the counts of the
// whole listing, the first maxListedNames names for the report, and for the
// names a caller asked for (scanOpts.want) what it decides by.
type TombView struct {
	Names                                       []TombName
	NameCount, Versions, DeleteMarkers, Foreign int
	sums                                        map[relayregistry.TombKey]tombSum
}

// tombSum is what a scan keeps of a wanted name: the highest not-before
// enforced (unreadable versions at their strictest reading) and the highest
// not-before held by a readable version locked for its life
// (objregistry.LocksFor), each relaybind.NoTombstone when none.
type tombSum struct{ highest, covered int64 }

// Max is the highest not-before enforced for k (relaybind.NoTombstone when
// none): from the wanted names, else from the names kept for the report.
func (v TombView) Max(k relayregistry.TombKey) int64 {
	if s, ok := v.sums[k]; ok {
		return s.highest
	}
	for _, n := range v.Names {
		if !n.Foreign && n.Key == k {
			return n.Highest
		}
	}
	return relaybind.NoTombstone
}

// covered is the highest not-before of a wanted name that a version locked
// for its life holds.
func (v TombView) covered(k relayregistry.TombKey) int64 {
	if s, ok := v.sums[k]; ok {
		return s.covered
	}
	return relaybind.NoTombstone
}

// tombsOf is the three scopes' maxima for a binding, from the wanted names.
func (v TombView) tombsOf() func(relaybind.KeyHash, party.Fingerprint) relaybind.Tombstones {
	return func(k relaybind.KeyHash, d party.Fingerprint) relaybind.Tombstones {
		return relaybind.Tombstones{
			Pair:   v.Max(relayregistry.TombKey{Scope: relaybind.ScopePair, Key: k, Device: d}),
			All:    v.Max(relayregistry.TombKey{Scope: relaybind.ScopeAll, Key: k}),
			Device: v.Max(relayregistry.TombKey{Scope: relaybind.ScopeDevice, Device: d}),
		}
	}
}

func strictest(r *s3client.Retention) int64 {
	if r == nil || r.Until.IsZero() {
		return relaybind.MaxTime
	}
	return min(max(r.Until.Unix(), 0), relaybind.MaxTime)
}

// scanOpts choose what a scan keeps and whom it tells.
type scanOpts struct {
	// maxVersions bounds the object versions and, apart, the delete markers.
	maxVersions int
	// want are the names whose sums are kept (TombView.Max, covered).
	want map[relayregistry.TombKey]bool
	// version is told every entry of a tombstone name as it is read, name the
	// name once all its entries are; either may be nil.
	version func(n *TombName, v TombVersion)
	name    func(n *TombName)
}

// nameAgg is the name being folded.
type nameAgg struct {
	n             TombName
	current       bool  // the current entry was an object version
	curNB, others int64 // its value; the highest of the others
	covered       int64
}

// scanTombstones reads the version listing of registry/tombstones/ page by
// page and reads every object version, as the relay's load does: per name the
// current version without a version id (which must be the listing's latest)
// and every other object version by its id. It holds one page and one name's
// sums at a time, never the listing: each entry is folded into its name as it
// is read (changed after the review of work package 9). At most maxVersions
// object versions and as many delete markers are read (ErrListLimit past
// either). The self-test's probe name is skipped.
func (s *session) scanTombstones(ctx context.Context, o scanOpts) (TombView, error) {
	tv := TombView{sums: map[relayregistry.TombKey]tombSum{}}
	prefix := s.prefix + pathTombstones
	var km, vm, last, kept string
	var agg *nameAgg
	finish := func() {
		if agg == nil {
			return
		}
		n := &agg.n
		n.CurrentLower = agg.current && agg.curNB < agg.others
		tv.NameCount++
		if n.Foreign {
			tv.Foreign++
		} else if o.want[n.Key] {
			tv.sums[n.Key] = tombSum{highest: n.Highest, covered: agg.covered}
		}
		if o.name != nil {
			o.name(n)
		}
		if len(tv.Names) < maxListedNames {
			tv.Names = append(tv.Names, *n)
		}
		agg = nil
	}
	for {
		rctx, cancel, err := s.rq(ctx)
		if err != nil {
			return tv, err
		}
		p, err := s.rc.ListVersions(rctx, s3client.VersionsInput{Prefix: prefix, KeyMarker: km, VersionIDMarker: vm})
		cancel()
		if err != nil {
			return tv, fmt.Errorf("the tombstone listing: %w", err)
		}
		var page []s3client.Version
		var first []bool
		for _, v := range p.Versions {
			if v.Key < last {
				return tv, fmt.Errorf("%w: the tombstone listing goes back in key order", s3client.ErrBadListing)
			}
			last = v.Key
			if objregistry.IsProbeName(strings.TrimPrefix(v.Key, prefix)) {
				continue
			}
			if v.DeleteMarker {
				if tv.DeleteMarkers++; tv.DeleteMarkers > o.maxVersions {
					return tv, fmt.Errorf("%w: more than %d delete markers under registry/tombstones/; the relay refuses to start", s3client.ErrListLimit, o.maxVersions)
				}
			} else if tv.Versions++; tv.Versions > o.maxVersions {
				return tv, fmt.Errorf("%w: more than %d tombstone versions; the relay refuses to start (relayregistry.MaxTombstoneVersions)", s3client.ErrListLimit, o.maxVersions)
			}
			// the first entry of a name, on this page or on an earlier one
			first = append(first, v.Key != kept)
			page = append(page, v)
			kept = v.Key
		}
		read, stale, err := s.readPage(ctx, prefix, page, first)
		if err != nil {
			return tv, err
		}
		for i, v := range page {
			if first[i] {
				finish()
				name := strings.TrimPrefix(v.Key, prefix)
				k, ok := parseTombName(name)
				agg = &nameAgg{n: TombName{Name: name, Key: k, Foreign: !ok, Highest: relaybind.NoTombstone},
					curNB: relaybind.NoTombstone, others: relaybind.NoTombstone, covered: relaybind.NoTombstone}
			}
			s.fold(agg, read[i], first[i], stale[i], o)
		}
		if !p.Truncated {
			break
		}
		if p.NextKeyMarker == km && p.NextVersionIDMarker == vm {
			return tv, fmt.Errorf("%w: the tombstone listing's markers do not advance", s3client.ErrBadListing)
		}
		km, vm = p.NextKeyMarker, p.NextVersionIDMarker
	}
	finish()
	return tv, nil
}

// fold adds one read entry to its name.
func (s *session) fold(a *nameAgg, v TombVersion, first, stale bool, o scanOpts) {
	n := &a.n
	n.Entries++
	n.Stale = n.Stale || stale
	if len(n.Versions) < maxListedKeys {
		n.Versions = append(n.Versions, v)
	}
	if !v.DeleteMarker && !v.Gone {
		n.Highest = max(n.Highest, v.NotBefore)
		if first {
			a.current, a.curNB = true, v.NotBefore
		} else {
			a.others = max(a.others, v.NotBefore)
		}
		if !v.Unreadable && objregistry.LocksFor(v.NotBefore, v.Lock, s.mode) {
			a.covered = max(a.covered, v.NotBefore)
		}
	}
	if o.version != nil {
		o.version(n, v)
	}
}

// readPage reads the entries of one listing page, at most readConcurrency at
// once: the first entry of a name (first) as the current version, every other
// object version by its id; delete markers that are not first are not read.
func (s *session) readPage(ctx context.Context, prefix string, page []s3client.Version, first []bool) ([]TombVersion, []bool, error) {
	out := make([]TombVersion, len(page))
	stale := make([]bool, len(page))
	errs := make([]error, len(page))
	var wg sync.WaitGroup
	sem := make(chan struct{}, readConcurrency)
	for i, v := range page {
		out[i] = TombVersion{ID: v.VersionID, DeleteMarker: v.DeleteMarker, Latest: v.IsLatest, NotBefore: -1}
		if !first[i] && v.DeleteMarker {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			errs[i] = s.readVersion(ctx, v.Key, v, &out[i], first[i], &stale[i])
		}()
	}
	wg.Wait()
	return out, stale, errors.Join(errs...)
}

// readVersion reads one listed entry: the current version (no version id) for
// the first entry of a name, else the version by its id.
func (s *session) readVersion(ctx context.Context, key string, lv s3client.Version, out *TombVersion, current bool, stale *bool) error {
	id := lv.VersionID
	if current {
		id = ""
	}
	rctx, cancel, err := s.rq(ctx)
	if err != nil {
		return err
	}
	got, gerr := s.rc.Get(rctx, s3client.GetInput{Key: key, VersionID: id, MaxBytes: int64(tombBytes)})
	cancel()
	var se *s3client.StatusError
	switch {
	case current && errors.Is(gerr, s3client.ErrNotFound):
		if !(lv.DeleteMarker && errors.As(gerr, &se) && se.DeleteMarker) {
			*stale = true
		}
		return nil
	case current && lv.DeleteMarker && gerr == nil:
		*stale = true
		return nil
	case errors.Is(gerr, s3client.ErrNotFound):
		out.Gone = true
		return nil
	case errors.Is(gerr, s3client.ErrTooLarge):
		out.Unreadable = true
		out.Lock = s.headLock(ctx, s.rc, key, lv.VersionID)
		out.NotBefore = strictest(out.Lock)
		return nil
	case gerr != nil:
		return fmt.Errorf("the tombstone %s version %q cannot be read: %w", key, lv.VersionID, gerr)
	}
	if current && got.Info.VersionID != lv.VersionID {
		*stale = true
	}
	out.Lock = got.Info.Retention
	if nb, err := decodeTomb(got.Body); err != nil {
		out.Unreadable, out.NotBefore = true, strictest(out.Lock)
	} else {
		out.NotBefore = nb
	}
	return nil
}
