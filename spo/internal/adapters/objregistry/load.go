package objregistry

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

func corrupt(format string, a ...any) error {
	return fmt.Errorf("%w: %s", relayport.ErrRegistryCorrupt, fmt.Sprintf(format, a...))
}

// load rebuilds memory from the store, in the order of ADR 0015: the markers,
// the tombstones (before the bindings, so every binding is checked against
// them), the bindings, the rate buckets. Only after every check has passed are
// the bindings it dropped deleted.
func (s *Registry) load(ctx context.Context, init bool) error {
	now, err := s.now()
	if err != nil {
		return err
	}
	if _, ok := s.lease.Until(); !ok {
		return fmt.Errorf("%w: the registry is loaded only under a held lease", relayport.ErrAuthorityLost)
	}
	if err := s.loadMarkers(ctx, now, init); err != nil {
		return err
	}
	if err := s.loadTombstones(ctx, now); err != nil {
		return err
	}
	drops, err := s.loadBindings(ctx, now)
	if err != nil {
		return err
	}
	if err := s.loadRates(ctx, now); err != nil {
		return err
	}
	for _, d := range drops {
		rctx, cancel, err := s.reqCtx(ctx)
		if err != nil {
			return err
		}
		_, err = s.rc.Delete(rctx, bindingKey(s.prefix, d))
		cancel()
		if err != nil {
			s.note("binding %s was dropped but could not be deleted from the store (%v); it is not served", deviceName(d), err)
			continue
		}
		s.bindObj(d).etag = ""
	}
	return nil
}

// ---- markers ----

func (s *Registry) loadMarkers(ctx context.Context, now int64, init bool) error {
	regOK, err := s.registryMarker(ctx)
	if err != nil {
		return err
	}
	workOK, err := s.workingMarker(ctx)
	if err != nil {
		return err
	}
	if regOK && workOK {
		return nil
	}
	regEmpty, err := s.registryEmpty(ctx)
	if err != nil {
		return err
	}
	workEmpty, err := s.workingEmpty(ctx)
	if err != nil {
		return err
	}
	if init {
		// the registry marker first, and only for an identity that neither bucket
		// knows: a registry bucket emptied under a working bucket that still names
		// the identity is never marked again (its tombstones would be forgotten).
		// The working marker follows the registry's, so an init that stopped
		// between the two is finished by the next one.
		if !regOK && regEmpty && !workOK && workEmpty {
			if err := s.writeRegistryMarker(ctx, now); err != nil {
				return err
			}
			regOK, s.created = true, true
		}
		if regOK && !workOK && workEmpty {
			if _, err := s.writeObject(ctx, s.wc, s.prefix+markerPath, encodeMarker(s.node), nil); err != nil {
				return err
			}
			workOK = true
		}
		if regOK && workOK {
			return nil
		}
	}
	if !regOK && !workOK && regEmpty && workEmpty {
		return ErrStoreNew
	}
	var missing []string
	if !regOK {
		missing = append(missing, "the registry bucket")
	}
	if !workOK {
		missing = append(missing, "the working bucket")
	}
	return fmt.Errorf("%w: %s holds no marker of this relay while the identity has state or a marker in the store; refusing to start on a store that may have forgotten its tombstones (see spo-relay store inspect)", ErrStoreEmptied, strings.Join(missing, " and "))
}

// registryMarker finds the identity's marker in the registry bucket by a
// version listing, so that a delete marker over it hides nothing: present
// when an object version's bytes name this identity. The listing is bounded
// by MaxMarkerEntries entries (delete markers included) and
// MaxMarkerVersions object versions; past either the start is refused. A
// version that is not a marker, or names another identity, does not refuse
// the start when this identity's marker is there too (a holder of the role can
// write one, locked, on top): it is noted. Without this identity's marker, a
// version naming another identity is a wrong prefix or bucket
// (ErrStoreEmptied). It records the ETag of the current entry when it is an
// object version (so that a renewal is conditional on it), the newest
// identity version's id and retention, and every other entry, for the
// renewal and the pruning (SPO-Xobjstore-OUT-805).
func (s *Registry) registryMarker(ctx context.Context) (bool, error) {
	key := s.prefix + markerPath
	var entries []s3client.Version
	km, vm := "", ""
	for {
		rctx, cancel, err := s.reqCtx(ctx)
		if err != nil {
			return false, err
		}
		p, err := s.rc.ListVersions(rctx, s3client.VersionsInput{Prefix: key, KeyMarker: km, VersionIDMarker: vm, MaxKeys: s.pageKeys})
		cancel()
		if err != nil {
			return false, fmt.Errorf("the marker's version listing: %w", err)
		}
		for _, v := range p.Versions {
			if v.Key != key {
				continue
			}
			if len(entries) >= s.markerEntries {
				return false, corrupt("the marker has more than %d versions and delete markers; see spo-relay store inspect", s.markerEntries)
			}
			entries = append(entries, v)
		}
		if !p.Truncated {
			break
		}
		if p.NextKeyMarker == km && p.NextVersionIDMarker == vm {
			return false, fmt.Errorf("%w: the marker's listing does not advance", s3client.ErrBadListing)
		}
		km, vm = p.NextKeyMarker, p.NextVersionIDMarker
	}
	objects, other, junk, found := 0, 0, 0, false
	for i, v := range entries {
		if i == 0 {
			s.marker.latest = v.VersionID
			if !v.DeleteMarker {
				s.marker.etag = v.ETag
			}
		}
		if v.DeleteMarker {
			s.marker.old = append(s.marker.old, markerVer{id: v.VersionID, deleteMarker: true})
			continue
		}
		if objects++; objects > MaxMarkerVersions {
			return false, corrupt("the marker has more than %d versions", MaxMarkerVersions)
		}
		if found {
			info, err := s.head(ctx, s.rc, key, v.VersionID)
			if err != nil {
				return false, fmt.Errorf("the marker's version %s cannot be read: %w", v.VersionID, err)
			}
			s.marker.old = append(s.marker.old, markerVer{id: v.VersionID, until: untilOf(info.Retention)})
			continue
		}
		got, err := s.get(ctx, s.rc, s3client.GetInput{Key: key, VersionID: v.VersionID, MaxBytes: int64(markerBytes)})
		var node [32]byte
		bad := errors.Is(err, s3client.ErrTooLarge)
		switch {
		case bad:
		case err != nil:
			return false, fmt.Errorf("the marker's version %s cannot be read: %w", v.VersionID, err)
		default:
			var derr error
			node, derr = decodeMarker(got.Body)
			bad = derr != nil
		}
		if bad || node != s.node {
			if bad {
				junk++
			} else {
				other++
			}
			s.marker.old = append(s.marker.old, markerVer{id: v.VersionID, until: untilOf(got.Info.Retention)})
			continue
		}
		found = true
		s.marker.id = v.VersionID
		if got.Info.Retention != nil {
			s.marker.until = got.Info.Retention.Until
		}
	}
	switch {
	case !found && other > 0:
		return false, fmt.Errorf("%w: the registry bucket's marker names another relay identity", ErrStoreEmptied)
	case found && other+junk > 0:
		s.note("WARNING: the registry bucket's marker has %d version(s) naming another identity and %d that are not markers, besides this relay's; they are ignored (see spo-relay store inspect)", other, junk)
	}
	return found, nil
}

func (s *Registry) workingMarker(ctx context.Context) (bool, error) {
	got, err := s.get(ctx, s.wc, s3client.GetInput{Key: s.prefix + markerPath, MaxBytes: int64(markerBytes)})
	switch {
	case errors.Is(err, s3client.ErrNotFound):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("the working bucket's marker cannot be read: %w", err)
	}
	node, err := decodeMarker(got.Body)
	if err != nil {
		return false, corrupt("the working bucket's marker: %v", err)
	}
	if node != s.node {
		return false, fmt.Errorf("%w: the working bucket's marker names another relay identity", ErrStoreEmptied)
	}
	return true, nil
}

// registryEmpty reports whether the registry bucket holds nothing of the
// identity under registry/ (no version and no delete marker), the self-test's
// probe of the deny excepted.
func (s *Registry) registryEmpty(ctx context.Context) (bool, error) {
	rctx, cancel, err := s.reqCtx(ctx)
	if err != nil {
		return false, err
	}
	defer cancel()
	p, err := s.rc.ListVersions(rctx, s3client.VersionsInput{Prefix: s.prefix + "registry/", MaxKeys: 16})
	if err != nil {
		return false, err
	}
	if p.Truncated {
		return false, nil
	}
	for _, v := range p.Versions {
		if !selftestRE.MatchString(strings.TrimPrefix(v.Key, s.prefix+tombstonesPath)) {
			return false, nil
		}
	}
	return true, nil
}

// workingEmpty reports whether the working bucket holds nothing of the
// identity under registry/ and mailbox/ (the lease and the self-test's
// objects are not state).
func (s *Registry) workingEmpty(ctx context.Context) (bool, error) {
	for _, p := range []string{"registry/", "mailbox/"} {
		rctx, cancel, err := s.reqCtx(ctx)
		if err != nil {
			return false, err
		}
		page, err := s.wc.List(rctx, s3client.ListInput{Prefix: s.prefix + p, MaxKeys: 1})
		cancel()
		if err != nil {
			return false, err
		}
		if len(page.Objects) > 0 {
			return false, nil
		}
	}
	return true, nil
}

func (s *Registry) writeRegistryMarker(ctx context.Context, now int64) error {
	until := time.Unix(now, 0).Add(MarkerRetention).UTC().Truncate(time.Second)
	res, err := s.writeObject(ctx, s.rc, s.prefix+markerPath, encodeMarker(s.node), &s3client.Retention{Mode: s.mode, Until: until})
	if err != nil {
		return err
	}
	s.marker.etag, s.marker.until, s.marker.id, s.marker.latest = res.ETag, until, res.VersionID, res.VersionID
	return nil
}

// writeObject creates an object (create-only); an unknown outcome is an
// error, and a conflict the read-back does not explain ends the writer.
func (s *Registry) writeObject(ctx context.Context, c *s3client.Client, key string, body []byte, ret *s3client.Retention) (s3client.PutResult, error) {
	var o obj
	res, r, err := s.putObject(ctx, c, s3client.PutInput{Key: key, Body: body, Retention: ret, Checksum: true}, &o)
	switch r {
	case done:
		return res, nil
	case conflicted:
		return s3client.PutResult{}, s.loseAuthority(err)
	}
	if err == nil {
		err = fmt.Errorf("%w: %s", relayport.ErrOutcomeUnknown, key)
	}
	return s3client.PutResult{}, err
}

// ---- tombstones ----

// listed is one entry of the tombstone version listing that the writer has
// not seen: an object version or a delete marker of one scope key. badSize
// marks an object version whose listed size is not a tombstone's.
type listed struct {
	key     relayregistry.TombKey
	id      string
	etag    string
	latest  bool
	marker  bool
	badSize bool
}

// scan is where a pass over the tombstone version listing stands, and what it
// counted so far: the markers to resume from, the last key and the version
// ids seen under it (a listing that goes back or repeats is refused), and the
// object versions, delete markers and foreign objects of the pass.
type scan struct {
	km, vm, lastKey            string
	sameKey                    map[string]bool
	versions, markers, foreign int
}

func (c scan) clone() scan {
	m := make(map[string]bool, len(c.sameKey))
	for k, v := range c.sameKey {
		m[k] = v
	}
	c.sameKey = m
	return c
}

// scanPages reads the version listing under registry/tombstones/ from where
// sc stands, at most pages pages (0: to the end), each under its own request
// context, and gives each page's entries the writer has not seen to each; it
// reports whether the listing ended. It refuses (fail closed) more object
// versions than the ceiling and as many delete markers in one pass, and a
// listing that goes back or repeats. An object whose name is not a tombstone
// names no scope: it is counted (scan.foreign, and against the ceiling) and
// ignored (SPO-Xobjstore-PRE-809). The names of the self-test's probe are
// skipped. A pass resumed from a version the store no longer has resumes
// after its key.
func (s *Registry) scanPages(ctx context.Context, sc *scan, pages int, each func([]listed) error) (bool, error) {
	prefix := s.prefix + tombstonesPath
	for n := 0; pages == 0 || n < pages; n++ {
		in := s3client.VersionsInput{Prefix: prefix, KeyMarker: sc.km, VersionIDMarker: sc.vm, MaxKeys: s.pageKeys}
		p, err := s.listVersions(ctx, in)
		var se *s3client.StatusError
		if err != nil && sc.vm != "" && errors.As(err, &se) && se.Status == 400 {
			in.VersionIDMarker = ""
			p, err = s.listVersions(ctx, in)
		}
		if err != nil {
			return false, fmt.Errorf("the tombstone listing: %w", err)
		}
		var out []listed
		for _, v := range p.Versions {
			if v.Key < sc.lastKey {
				return false, fmt.Errorf("%w: the tombstone listing goes back in key order", s3client.ErrBadListing)
			}
			if v.Key != sc.lastKey {
				sc.lastKey, sc.sameKey = v.Key, map[string]bool{}
			}
			if sc.sameKey[v.VersionID] {
				return false, fmt.Errorf("%w: a tombstone version listed twice", s3client.ErrBadListing)
			}
			sc.sameKey[v.VersionID] = true
			name := strings.TrimPrefix(v.Key, prefix)
			if selftestRE.MatchString(name) {
				continue
			}
			if v.DeleteMarker {
				if sc.markers++; sc.markers > s.maxVersions {
					return false, corrupt("the tombstone listing holds more than %d delete markers", s.maxVersions)
				}
			} else if sc.versions++; sc.versions > s.maxVersions {
				return false, fmt.Errorf("%w: %w: the store holds more than %d tombstone versions; see spo-relay store inspect", relayport.ErrRegistryCorrupt, relayregistry.ErrTombstoneVersions, s.maxVersions)
			}
			k, err := parseTombName(name)
			if err != nil {
				if !v.DeleteMarker {
					sc.foreign++
				}
				continue
			}
			if t := s.tombs[k]; t != nil {
				if _, seen := t.ids[v.VersionID]; seen {
					continue
				}
			}
			out = append(out, listed{key: k, id: v.VersionID, etag: v.ETag, latest: v.IsLatest, marker: v.DeleteMarker,
				badSize: !v.DeleteMarker && v.Size != int64(tombBytes)})
		}
		if err := each(out); err != nil {
			return false, err
		}
		if !p.Truncated {
			return true, nil
		}
		if p.NextKeyMarker == sc.km && p.NextVersionIDMarker == sc.vm {
			return false, fmt.Errorf("%w: the tombstone listing's markers do not advance", s3client.ErrBadListing)
		}
		sc.km, sc.vm = p.NextKeyMarker, p.NextVersionIDMarker
	}
	return false, nil
}

func (s *Registry) listVersions(ctx context.Context, in s3client.VersionsInput) (s3client.VersionPage, error) {
	rctx, cancel, err := s.reqCtx(ctx)
	if err != nil {
		return s3client.VersionPage{}, err
	}
	defer cancel()
	return s.rc.ListVersions(rctx, in)
}

// strictest is the not-before a version the relay cannot read is enforced
// at (SPO-Xobjstore-PRE-809): the end of its lock, which revokes every binding
// of its scope presented before then; MaxTime when the store reports no lock.
func strictest(r *s3client.Retention) int64 {
	if r == nil || r.Until.IsZero() {
		return relaybind.MaxTime
	}
	return min(max(r.Until.Unix(), 0), relaybind.MaxTime)
}

// readJob is one read of a tombstone name: its current version (id "") or one
// version by id; badSize reads only the head (the listed size is not a
// tombstone's).
type readJob struct {
	key     relayregistry.TombKey
	id      string
	badSize bool
}

// readRes is what a read found: the not-before (at the strictest reading when
// unreadable), what the store said of the version, absent (a 404 of a current
// version; deleteMarker when a delete marker is current), gone (a version by
// id that is no longer listed), or an error.
type readRes struct {
	nb                                     int64
	info                                   s3client.ObjectInfo
	unreadable, absent, deleteMarker, gone bool
	err                                    error
}

// readAll runs the reads with at most s.concurrency in flight, each under its
// own request context (so under the lease), and stops at the first error, or
// when ctx ends, which it returns.
func (s *Registry) readAll(ctx context.Context, jobs []readJob) ([]readRes, error) {
	out := make([]readRes, len(jobs))
	if len(jobs) == 0 {
		return out, nil
	}
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var mu sync.Mutex
	var first error
	next := make(chan int)
	var wg sync.WaitGroup
	for range min(s.concurrency, len(jobs)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				if s.hooks.inFlight != nil {
					s.hooks.inFlight(1)
				}
				r := s.readOne(wctx, jobs[i])
				if s.hooks.inFlight != nil {
					s.hooks.inFlight(-1)
				}
				out[i] = r
				if r.err != nil {
					mu.Lock()
					if first == nil {
						first = r.err
					}
					mu.Unlock()
					cancel()
				}
			}
		}()
	}
feed:
	for i := range jobs {
		select {
		case next <- i:
		case <-wctx.Done():
			break feed
		}
	}
	close(next)
	wg.Wait()
	if first == nil {
		first = ctx.Err()
	}
	return out, first
}

// readOne reads one job. A version listed by id that the store answers 404 for
// is never skipped (SPO-Xobjstore-PRE-809): the name's versions are listed
// again; one no longer listed is gone (deleted by its id since the listing);
// one still listed is read again, and a second 404 is enforced at the
// strictest reading with no lock known (MaxTime).
func (s *Registry) readOne(ctx context.Context, j readJob) readRes {
	key := tombKey(s.prefix, j.key)
	if j.id != "" && s.hooks.beforeVersionGet != nil {
		s.hooks.beforeVersionGet(key, j.id)
	}
	r := s.readTomb(ctx, key, j.id, j.badSize)
	if j.id == "" || !r.absent {
		return r
	}
	listed, err := s.stillListed(ctx, key, j.id)
	switch {
	case err != nil:
		return readRes{err: err}
	case !listed:
		return readRes{gone: true}
	}
	r = s.readTomb(ctx, key, j.id, j.badSize)
	if r.absent {
		return readRes{nb: relaybind.MaxTime, unreadable: true}
	}
	return r
}

// readTomb reads one version (or the current one, id "") of a tombstone. A
// body that is not a tombstone is unreadable and read at the strictest
// reading, with the lock the store reports for it (a head when the body is
// too large or its listed size is wrong, so no body is read).
func (s *Registry) readTomb(ctx context.Context, key, id string, badSize bool) readRes {
	fromHead := func() readRes {
		info, err := s.head(ctx, s.rc, key, id)
		var se *s3client.StatusError
		switch {
		case errors.Is(err, s3client.ErrNotFound):
			return readRes{absent: true, deleteMarker: errors.As(err, &se) && se.DeleteMarker}
		case err != nil:
			return readRes{err: fmt.Errorf("the tombstone %s version %q cannot be read: %w", key, id, err)}
		}
		return readRes{nb: strictest(info.Retention), info: info, unreadable: true}
	}
	if badSize {
		return fromHead()
	}
	got, err := s.get(ctx, s.rc, s3client.GetInput{Key: key, VersionID: id, MaxBytes: int64(tombBytes)})
	var se *s3client.StatusError
	switch {
	case errors.Is(err, s3client.ErrNotFound):
		return readRes{absent: true, deleteMarker: errors.As(err, &se) && se.DeleteMarker}
	case errors.Is(err, s3client.ErrTooLarge):
		return fromHead()
	case err != nil:
		return readRes{err: fmt.Errorf("the tombstone %s version %q cannot be read: %w", key, id, err)}
	}
	nb, err := decodeTomb(got.Body)
	if err != nil {
		return readRes{nb: strictest(got.Info.Retention), info: got.Info, unreadable: true}
	}
	return readRes{nb: nb, info: got.Info}
}

// stillListed reports whether version id of key is in a listing of the name's
// versions read now, at most four pages; a name with more fails closed (true).
func (s *Registry) stillListed(ctx context.Context, key, id string) (bool, error) {
	km, vm := "", ""
	for range 4 {
		p, err := s.listVersions(ctx, s3client.VersionsInput{Prefix: key, KeyMarker: km, VersionIDMarker: vm, MaxKeys: s.pageKeys})
		if err != nil {
			return false, fmt.Errorf("the listing of %s: %w", key, err)
		}
		for _, v := range p.Versions {
			if v.Key == key && v.VersionID == id {
				return true, nil
			}
		}
		if !p.Truncated || (p.NextKeyMarker == km && p.NextVersionIDMarker == vm) {
			return false, nil
		}
		km, vm = p.NextKeyMarker, p.NextVersionIDMarker
	}
	return true, nil
}

// tombCounts counts what the load of tombstones notes.
type tombCounts struct {
	missing, unreadable, lowerOnTop, future int
}

// loadTombstones lists the versions page by page and loads every version as
// soon as its name's versions are all listed (the maximum per scope key wins,
// the core counts versions against its ceiling). For each name the current
// version is read without a version id: the listing must show it as the
// latest, or the listing is stale and the start is refused, so a listing that
// missed a raise never loads the lower value (SPO-Xobjstore-PRE-803). The
// reads of one page run concurrently (LoadConcurrency).
func (s *Registry) loadTombstones(ctx context.Context, now int64) error {
	var sc scan
	var carry []listed
	var tc tombCounts
	_, err := s.scanPages(ctx, &sc, 0, func(page []listed) error {
		carry = append(carry, page...)
		if len(carry) == 0 {
			return nil
		}
		last := carry[len(carry)-1].key
		cut := len(carry)
		for cut > 0 && carry[cut-1].key == last {
			cut--
		}
		if cut == 0 {
			return nil
		}
		if err := s.loadGroups(ctx, carry[:cut], now, &tc); err != nil {
			return err
		}
		carry = append([]listed(nil), carry[cut:]...)
		return nil
	})
	if err != nil {
		return err
	}
	if err := s.loadGroups(ctx, carry, now, &tc); err != nil {
		return err
	}
	for _, c := range []struct {
		n    int
		what string
	}{
		{tc.missing, "%d listed tombstone version(s) were gone when read (deleted by version id since the listing)"},
		{tc.unreadable, "WARNING: %d tombstone version(s) could not be read; each is enforced at the strictest reading (its scope revoked until its lock ends; see spo-relay store inspect)"},
		{tc.lowerOnTop, "WARNING: %d tombstone name(s) have a current version lower than an older one (a version written over a tombstone); the highest is enforced"},
		{tc.future, "WARNING: %d tombstone version(s) have a not-before ahead of the clock; each is enforced as it is (a lock cannot be shortened; its scope stays revoked until the not-before plus the maximum lifetime)"},
		{sc.foreign, "WARNING: %d object(s) under registry/tombstones/ are not tombstones; they name no scope and are ignored (see spo-relay store inspect)"},
	} {
		if c.n > 0 {
			s.note(c.what, c.n)
		}
	}
	if n, cfg := s.core.Stats(0).Tombstones, s.core.Config(); n > cfg.MaxTombstones+cfg.TombstoneHeadroom() {
		s.note("the store holds %d tombstones, more than the configured bound of %d and its headroom; new tombstones are refused (revokes of nothing) or unrecorded (revokes of bound devices) until some expire", n, cfg.MaxTombstones)
	}
	return nil
}

// loadGroups reads and loads the listed entries, which hold whole names.
func (s *Registry) loadGroups(ctx context.Context, entries []listed, now int64, tc *tombCounts) error {
	if len(entries) == 0 {
		return nil
	}
	jobs := make([]readJob, 0, len(entries))
	idx := make([]int, len(entries))
	for i, v := range entries {
		switch {
		case i == 0 || entries[i-1].key != v.key:
			jobs = append(jobs, readJob{key: v.key, badSize: v.badSize})
		case v.marker:
			idx[i] = -1
			continue
		default:
			jobs = append(jobs, readJob{key: v.key, id: v.id, badSize: v.badSize})
		}
		idx[i] = len(jobs) - 1
	}
	res, err := s.readAll(ctx, jobs)
	if err != nil {
		return err
	}
	for i := 0; i < len(entries); {
		j := i + 1
		for j < len(entries) && entries[j].key == entries[i].key {
			j++
		}
		group, k := entries[i:j], entries[i].key
		first := i
		i = j
		latest := group[0]
		if !latest.latest {
			return fmt.Errorf("%w: %s: the first version listed is not the latest", s3client.ErrBadListing, tombName(k))
		}
		t := s.tombObj(k)
		t.latestVID = latest.id
		cur := res[idx[first]]
		switch {
		case cur.absent:
			if !cur.deleteMarker || !latest.marker {
				return fmt.Errorf("%w: %s: the listing shows a version the store does not serve as current", ErrStaleListing, tombName(k))
			}
		case latest.marker || cur.info.VersionID != latest.id:
			return fmt.Errorf("%w: %s: the current version is %q, the listing's latest is %q", ErrStaleListing, tombName(k), cur.info.VersionID, latest.id)
		default:
			t.etag = cur.info.ETag
		}
		top := relaybind.NoTombstone
		for n, v := range group {
			if v.marker {
				t.ids[v.id] = ver{nb: -1}
				continue
			}
			r := cur
			if n > 0 {
				r = res[idx[first+n]]
				if r.gone {
					tc.missing++ // deleted by its id since the listing: it no longer protects anything
					continue
				}
				top = max(top, r.nb)
			}
			if r.unreadable {
				tc.unreadable++
			} else if r.nb > now+relaybind.SkewSeconds+int64(RetentionMargin/time.Second) {
				tc.future++
			}
			if err := s.core.LoadTombstoneVersion(k, r.nb); err != nil {
				return fmt.Errorf("%w: %s version %s: %w", relayport.ErrRegistryCorrupt, tombName(k), v.id, err)
			}
			t.ids[v.id] = ver{nb: r.nb, until: untilOf(r.info.Retention)}
			s.nversions++
		}
		if !latest.marker && cur.nb < top {
			tc.lowerOnTop++
		}
	}
	return nil
}

// readNew reads the versions a refresh listed and the writer has not seen;
// it returns them and how many could not be read (enforced at the strictest
// reading).
func (s *Registry) readNew(ctx context.Context, sc []listed) ([]tombVal, int, error) {
	var jobs []readJob
	for _, v := range sc {
		if !v.marker {
			jobs = append(jobs, readJob{key: v.key, id: v.id, badSize: v.badSize})
		}
	}
	res, err := s.readAll(ctx, jobs)
	if err != nil {
		return nil, 0, err
	}
	var out []tombVal
	unreadable := 0
	for i, r := range res {
		if r.gone {
			continue
		}
		if r.unreadable {
			unreadable++
		}
		out = append(out, tombVal{key: jobs[i].key, id: jobs[i].id, nb: r.nb, until: untilOf(r.info.Retention)})
	}
	return out, unreadable, nil
}

type tombVal struct {
	key       relayregistry.TombKey
	id        string
	nb, until int64
}

// adopt records what a refresh read: each new version, and a new current
// version of a name (an unseen latest entry is newer than every version the
// writer knows, because versions are only appended), so that the next raise
// is conditional on it. A latest entry the writer has seen (a stale listing)
// changes nothing.
func (s *Registry) adopt(sc []listed, values []tombVal) {
	for _, v := range values {
		t := s.tombObj(v.key)
		if _, seen := t.ids[v.id]; !seen {
			s.nversions++
		}
		t.ids[v.id] = ver{nb: v.nb, until: v.until}
	}
	for _, v := range sc {
		t := s.tombObj(v.key)
		if v.marker {
			t.ids[v.id] = ver{nb: -1}
		}
		if !v.latest || t.unsure {
			continue
		}
		if v.marker {
			t.etag, t.latestVID = "", v.id
		} else if _, ok := t.ids[v.id]; ok {
			t.etag, t.latestVID = v.etag, v.id
		}
	}
}

// namesOf are the three tombstone names that apply to a binding of device d
// under the wallet key k.
func namesOf(k relaybind.KeyHash, d party.Fingerprint) []relayregistry.TombKey {
	return []relayregistry.TombKey{
		{Scope: relaybind.ScopePair, Key: k, Device: d},
		{Scope: relaybind.ScopeAll, Key: k},
		{Scope: relaybind.ScopeDevice, Device: d},
	}
}

// checkNames reads the current version of each name in ks that the writer
// does not know (SPO-Xobjstore-PRE-803): a name that exists there (or whose
// current version is a delete marker) was hidden by the listing. Its versions
// are then listed and read (or, when that listing hides it too, its current
// version stands for it), recorded, and returned for the caller to load or
// merge, with how many names were hidden. A name that answers 404 does not
// exist. It costs one GET per unknown name, and more only for a hidden one.
func (s *Registry) checkNames(ctx context.Context, ks []relayregistry.TombKey) ([]relayregistry.TombstoneValue, int, error) {
	var jobs []readJob
	seen := map[relayregistry.TombKey]bool{}
	for _, k := range ks {
		if s.tombs[k] == nil && !seen[k] {
			seen[k] = true
			jobs = append(jobs, readJob{key: k})
		}
	}
	res, err := s.readAll(ctx, jobs)
	if err != nil {
		return nil, 0, err
	}
	var out []relayregistry.TombstoneValue
	hidden := 0
	for i, r := range res {
		if r.absent && !r.deleteMarker {
			continue
		}
		hidden++
		k := jobs[i].key
		vs, err := s.readName(ctx, k)
		if err != nil {
			return nil, 0, err
		}
		if len(vs) == 0 && !r.absent {
			t := s.tombObj(k)
			s.recordTomb(t, r.info.ETag, r.info.VersionID, r.nb, untilOf(r.info.Retention))
			vs = []int64{r.nb}
		}
		for _, nb := range vs {
			out = append(out, relayregistry.TombstoneValue{Key: k, NotBefore: nb})
		}
	}
	return out, hidden, nil
}

// readName lists and reads every version of one tombstone name and records
// them; it returns their not-before values.
func (s *Registry) readName(ctx context.Context, k relayregistry.TombKey) ([]int64, error) {
	key := tombKey(s.prefix, k)
	var entries []s3client.Version
	km, vm := "", ""
	for {
		p, err := s.listVersions(ctx, s3client.VersionsInput{Prefix: key, KeyMarker: km, VersionIDMarker: vm, MaxKeys: s.pageKeys})
		if err != nil {
			return nil, fmt.Errorf("the listing of %s: %w", key, err)
		}
		for _, v := range p.Versions {
			if v.Key == key {
				if len(entries) >= s.maxVersions {
					return nil, fmt.Errorf("%w: %w: %s", relayport.ErrRegistryCorrupt, relayregistry.ErrTombstoneVersions, tombName(k))
				}
				entries = append(entries, v)
			}
		}
		if !p.Truncated || (p.NextKeyMarker == km && p.NextVersionIDMarker == vm) {
			break
		}
		km, vm = p.NextKeyMarker, p.NextVersionIDMarker
	}
	var jobs []readJob
	for _, v := range entries {
		if !v.DeleteMarker {
			jobs = append(jobs, readJob{key: k, id: v.VersionID, badSize: v.Size != int64(tombBytes)})
		}
	}
	res, err := s.readAll(ctx, jobs)
	if err != nil {
		return nil, err
	}
	t := s.tombObj(k)
	var out []int64
	for i, r := range res {
		if r.gone {
			continue
		}
		s.recordTomb(t, t.etag, jobs[i].id, r.nb, untilOf(r.info.Retention))
		out = append(out, r.nb)
	}
	t.etag, t.latestVID = "", ""
	for i, v := range entries {
		if v.DeleteMarker {
			t.ids[v.VersionID] = ver{nb: -1}
		}
		if i == 0 {
			t.latestVID = v.VersionID
			if !v.DeleteMarker {
				t.etag = v.ETag
			}
		}
	}
	return out, nil
}

// ---- bindings ----

type loadCounts struct {
	expired, lifetime, revoked, notAllowed, notYet, aside int
	lastAuth                                              int64
}

// candidate is a stored binding that verified, waiting for the tombstone check.
type candidate struct {
	d    party.Fingerprint
	vb   relaybind.VerifiedBinding
	st   storedRecord
	pres relayregistry.Presented
	at   int64
}

// loadBindings lists registry/bindings/ page by page, reads each object
// (bounded by the record size) and verifies it again with relaybind; then
// reads the tombstone names that apply to the verified ones and that the
// listing did not show (checkNames: a listing that hid a name is caught), and
// checks each against the tombstones. It returns the devices whose binding is
// dropped (expired, over this relay's lifetime, revoked, not allowed), to be
// deleted once every check has passed. A binding that fails verification is
// left in place and not loaded; its ETag is kept so that the device's next
// registration overwrites it.
func (s *Registry) loadBindings(ctx context.Context, now int64) ([]party.Fingerprint, error) {
	prefix := s.prefix + bindingsPath
	var drops []party.Fingerprint
	var cands []candidate
	var lc loadCounts
	token, last, n := "", "", 0
	for {
		rctx, cancel, err := s.reqCtx(ctx)
		if err != nil {
			return nil, err
		}
		p, err := s.rc.List(rctx, s3client.ListInput{Prefix: prefix, ContinuationToken: token})
		cancel()
		if err != nil {
			return nil, fmt.Errorf("the binding listing: %w", err)
		}
		for _, o := range p.Objects {
			if o.Key <= last {
				return nil, fmt.Errorf("%w: the binding listing repeats or reorders keys", s3client.ErrBadListing)
			}
			last = o.Key
			if n++; n > mailbox.MaxBoundDevices {
				return nil, corrupt("the store holds more than %d bindings", mailbox.MaxBoundDevices)
			}
			d, err := parseDeviceName(strings.TrimPrefix(o.Key, prefix))
			if err != nil {
				return nil, corrupt("%s%v", bindingsPath, err)
			}
			if o.Size > int64(maxRecordBytes) {
				s.bindObj(d).etag = o.ETag
				lc.aside++
				s.note("binding %s is %d bytes, larger than a record; it is left in place and not loaded", deviceName(d), o.Size)
				continue
			}
			got, err := s.get(ctx, s.rc, s3client.GetInput{Key: o.Key, MaxBytes: int64(maxRecordBytes)})
			switch {
			case errors.Is(err, s3client.ErrNotFound):
				continue // gone since the listing
			case err != nil:
				return nil, fmt.Errorf("the binding %s cannot be read: %w", deviceName(d), err)
			}
			s.bindObj(d).etag = got.Info.ETag
			c, drop, ok := s.verifyStored(d, got.Body, now, &lc)
			switch {
			case drop:
				drops = append(drops, d)
			case ok:
				cands = append(cands, c)
			}
		}
		if !p.Truncated {
			break
		}
		if p.NextToken == token {
			return nil, fmt.Errorf("%w: the binding listing's continuation does not advance", s3client.ErrBadListing)
		}
		token = p.NextToken
	}
	var names []relayregistry.TombKey
	for _, c := range cands {
		names = append(names, namesOf(c.vb.Key(), c.d)...)
	}
	vs, hidden, err := s.checkNames(ctx, names)
	if err != nil {
		return nil, err
	}
	if hidden > 0 {
		s.note("WARNING: %d tombstone name(s) that apply to stored bindings were missing from the listing and were read directly; they are enforced", hidden)
	}
	for _, v := range vs {
		if err := s.core.LoadTombstoneVersion(v.Key, v.NotBefore); err != nil {
			return nil, fmt.Errorf("%w: %s: %w", relayport.ErrRegistryCorrupt, tombName(v.Key), err)
		}
	}
	for _, c := range cands {
		drop, err := s.admitStored(c, now, &lc)
		if err != nil {
			return nil, err
		}
		if drop {
			drops = append(drops, c.d)
		}
	}
	for _, c := range []struct {
		n    int
		what string
	}{
		{lc.expired, "dropped %d expired binding(s)"},
		{lc.lifetime, "dropped %d binding(s) whose lifetime is over this relay's maximum lifetime; the devices present new ones"},
		{lc.revoked, "dropped %d binding(s) revoked by a tombstone"},
		{lc.notAllowed, "dropped %d binding(s) naming a wallet key that is not on the allow-list"},
		{lc.notYet, "%d binding(s) are not valid yet by the clock; they are kept and not served until the clock reaches them"},
	} {
		if c.n > 0 {
			s.note(c.what, c.n)
		}
	}
	if lc.lastAuth > 0 && now < lc.lastAuth-s.core.Config().Policy.Skew {
		s.note("WARNING: the clock appears to be behind: now is %d, and a binding authenticated at %d", now, lc.lastAuth)
	}
	if n := s.core.Len(); n > s.core.Config().MaxBoundDevices {
		s.note("the store holds %d bindings, more than max_bound_devices (%d); all are loaded and new bindings evict until it is under the cap", n, s.core.Config().MaxBoundDevices)
	}
	return drops, nil
}

// verifyStored verifies one stored binding again from its bytes, as the
// directory store does: drop reports a binding to delete, ok one to check
// against the tombstones.
func (s *Registry) verifyStored(d party.Fingerprint, data []byte, now int64, lc *loadCounts) (c candidate, drop, ok bool) {
	aside := func(cause error) (candidate, bool, bool) {
		lc.aside++
		s.note("binding %s failed verification (%v); it is left in place and not loaded, and the device's next registration replaces it", deviceName(d), cause)
		return candidate{}, false, false
	}
	st, err := decodeRecord(data)
	if err != nil {
		return aside(err)
	}
	stmt, err := relaybind.ParseStatement(st.sign1)
	if err != nil {
		return aside(err)
	}
	vkey, err := relaybind.ParseCOSEKey(st.coseKey)
	if err != nil {
		return aside(err)
	}
	cfg := s.core.Config()
	at := now
	vb, err := relaybind.VerifyBinding(stmt, vkey, d, at, cfg.Policy)
	if errors.Is(err, relaybind.ErrNotYetValid) {
		if b, perr := relaybind.ParseBinding(stmt.Payload()); perr == nil {
			at = b.From
			vb, err = relaybind.VerifyBinding(stmt, vkey, d, at, cfg.Policy)
		}
	}
	switch {
	case errors.Is(err, relaybind.ErrExpired):
		lc.expired++
		return candidate{}, true, false
	case errors.Is(err, relaybind.ErrLifetimePolicy):
		lc.lifetime++
		return candidate{}, true, false
	case errors.Is(err, relaybind.ErrNotYetValid):
		lc.notYet++
		return candidate{}, false, false
	case err != nil:
		return aside(err)
	}
	pres, err := relayregistry.NewPresented(vb, st.sign1, st.coseKey)
	if err != nil {
		return aside(err)
	}
	return candidate{d: d, vb: vb, st: st, pres: pres, at: at}, false, true
}

// admitStored checks a verified stored binding against the tombstones and the
// allow-list and loads it; drop reports a binding to delete.
func (s *Registry) admitStored(c candidate, now int64, lc *loadCounts) (drop bool, err error) {
	cfg := s.core.Config()
	vb, d, st := c.vb, c.d, c.st
	if err := relaybind.Admit(vb, s.core.Tombstones(vb.Key(), d), c.at, cfg.Policy); err != nil {
		if errors.Is(err, relaybind.ErrRevoked) {
			lc.revoked++
			return true, nil
		}
		lc.aside++
		s.note("binding %s failed verification (%v); it is left in place and not loaded, and the device's next registration replaces it", deviceName(d), err)
		return false, nil
	}
	if !s.core.Allowed(vb.Key()) {
		lc.notAllowed++
		return true, nil
	}
	if c.at != now {
		lc.notYet++
	}
	lc.lastAuth = max(lc.lastAuth, st.lastAuth)
	rec := relayregistry.Record{
		Device: d, Key: vb.Key(), Binding: vb.Binding(), StatementID: vb.StatementID(), FullHash: vb.FullHash(),
		Sign1: c.pres.Sign1(), COSEKey: c.pres.COSEKey(), LastAuth: min(st.lastAuth, now), Senders: st.senders,
	}
	if !st.sendersOK {
		s.note("binding %s: expected-sender list dropped (not strictly ascending); its senders are strangers until it logs in", deviceName(d))
	}
	return false, s.core.LoadBinding(rec)
}

// ---- rates ----

// loadRates restores the two rate buckets from the working bucket's
// registry/rates (relayregistry.Core.RestoreRates, which can only take tokens
// away). A missing or unreadable object restores EMPTY buckets, never full
// ones: a store whose rate object an operator deleted or damaged gives no
// extra tokens. Only a new identity (InitIdentity wrote its marker in this
// Open) with no rate object stores full ones.
func (s *Registry) loadRates(ctx context.Context, now int64) error {
	key := s.prefix + ratesPath
	empty := func(why string) error {
		s.note("the rate object %s; both rate buckets start empty", why)
		z := relayregistry.RateState{Units: 0, At: now}
		return s.core.RestoreRates(relayregistry.RateSnapshot{NewBindings: z, Revokes: z}, now)
	}
	got, err := s.get(ctx, s.wc, s3client.GetInput{Key: key, MaxBytes: int64(ratesBytes)})
	switch {
	case errors.Is(err, s3client.ErrNotFound) && s.created:
		res, err := s.writeObject(ctx, s.wc, key, encodeRates(s.core.Rates(now)), nil)
		if err != nil {
			return err
		}
		s.rates.etag = res.ETag
		return nil
	case errors.Is(err, s3client.ErrNotFound):
		return empty("is missing")
	case errors.Is(err, s3client.ErrTooLarge):
		info, herr := s.head(ctx, s.wc, key, "")
		if herr != nil {
			return fmt.Errorf("the rate object cannot be read: %w", herr)
		}
		s.rates.etag = info.ETag
		return empty("is larger than a rate object")
	case err != nil:
		return fmt.Errorf("the rate object cannot be read: %w", err)
	}
	s.rates.etag = got.Info.ETag
	snap, err := decodeRates(got.Body)
	if err != nil {
		return empty(fmt.Sprintf("is unreadable (%v)", err))
	}
	if err := s.core.RestoreRates(snap, now); err != nil {
		return empty(fmt.Sprintf("is out of range (%v)", err))
	}
	return nil
}
