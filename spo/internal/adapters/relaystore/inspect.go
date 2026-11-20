package relaystore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objregistry"
	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
)

// InspectOptions name one page of one prefix.
type InspectOptions struct {
	// Bucket is "registry" or "working".
	Bucket string
	// Path is below the identity's prefix ("registry/tombstones/",
	// "mailbox/<recipient>/", "" for all of it).
	Path string
	// Versions lists versions and delete markers (registry bucket only);
	// Locks then heads each version listed for its lock (one request each).
	Versions, Locks bool
	// Limit is the page size, 1 to 1000 (100 when zero).
	Limit int
	// After is the Next of the page before.
	After string
}

// InspectEntry is one listed object or version, its name decoded. It holds no
// body.
type InspectEntry struct {
	Key          string // below the prefix
	Kind         string
	Detail       string
	Size         int64
	VersionID    string
	Latest       bool
	DeleteMarker bool
	Lock         *s3client.Retention
	LastModified time.Time
}

// InspectPage is one page and where the next starts ("" at the end).
type InspectPage struct {
	Bucket  string
	Entries []InspectEntry
	Next    string
}

// Inspect lists one page of one prefix of the identity, in human-readable form:
// tombstone names as their scope, wallet key hash and device; mailbox keys as
// recipient, arrival, id, sender and nonce; sizes; version ids; lock ends
// (Locks). It reads no body and writes nothing.
func Inspect(ctx context.Context, d Deps, o InspectOptions) (InspectPage, error) {
	s, err := newSession(d)
	if err != nil {
		return InspectPage{}, err
	}
	limit := o.Limit
	switch {
	case limit == 0:
		limit = 100
	case limit < 1 || limit > s3client.MaxKeysPerPage:
		return InspectPage{}, fmt.Errorf("a page is 1 to %d entries", s3client.MaxKeysPerPage)
	}
	if o.Path != "" && (strings.HasPrefix(o.Path, "/") || !s3client.ValidKey(strings.TrimSuffix(o.Path, "/"))) {
		return InspectPage{}, fmt.Errorf("the path %q is not a key prefix below the identity's prefix", o.Path)
	}
	var c *s3client.Client
	switch o.Bucket {
	case "registry":
		c = s.rc
	case "working":
		c = s.wc
		if o.Versions {
			return InspectPage{}, errors.New("the working bucket is unversioned: list it without --versions")
		}
	default:
		return InspectPage{}, fmt.Errorf("the bucket is registry or working, not %q", o.Bucket)
	}
	prefix := s.prefix + o.Path
	page := InspectPage{Bucket: o.Bucket}
	rctx, cancel, _ := s.rq(ctx)
	defer cancel()
	if !o.Versions {
		p, err := c.List(rctx, s3client.ListInput{Prefix: prefix, ContinuationToken: o.After, MaxKeys: limit})
		if err != nil {
			return page, err
		}
		for _, ob := range p.Objects {
			e := InspectEntry{Key: strings.TrimPrefix(ob.Key, s.prefix), Size: ob.Size, LastModified: ob.LastModified}
			e.Kind, e.Detail = s.describe(e.Key)
			page.Entries = append(page.Entries, e)
		}
		if p.Truncated {
			page.Next = p.NextToken
		}
		return page, nil
	}
	km, vm, _ := strings.Cut(o.After, " ")
	p, err := c.ListVersions(rctx, s3client.VersionsInput{Prefix: prefix, KeyMarker: km, VersionIDMarker: vm, MaxKeys: limit})
	if err != nil {
		return page, err
	}
	for _, v := range p.Versions {
		e := InspectEntry{Key: strings.TrimPrefix(v.Key, s.prefix), Size: v.Size, VersionID: v.VersionID, Latest: v.IsLatest, DeleteMarker: v.DeleteMarker, LastModified: v.LastModified}
		e.Kind, e.Detail = s.describe(e.Key)
		if o.Locks && !v.DeleteMarker {
			e.Lock = s.headLock(ctx, c, v.Key, v.VersionID)
		}
		page.Entries = append(page.Entries, e)
	}
	if p.Truncated {
		page.Next = p.NextKeyMarker + " " + p.NextVersionIDMarker
	}
	return page, nil
}

// describe decodes a name below the prefix.
func (s *session) describe(rel string) (kind, detail string) {
	switch {
	case rel == pathMarker:
		return "marker", ""
	case rel == pathLease:
		return "lease", ""
	case rel == pathRates:
		return "rates", ""
	case strings.HasPrefix(rel, pathSelftest):
		return "self-test object", ""
	case strings.HasPrefix(rel, pathBindings):
		if d, ok := parseDevice(strings.TrimPrefix(rel, pathBindings)); ok {
			return "binding", "device " + fp(d)
		}
		return "unknown", "not a binding's name"
	case strings.HasPrefix(rel, pathTombstones):
		name := strings.TrimPrefix(rel, pathTombstones)
		if objregistry.IsProbeName(name) {
			return "self-test probe", ""
		}
		k, ok := parseTombName(name)
		if !ok {
			return "unknown", "not a tombstone's name (the relay ignores it)"
		}
		switch k.Scope {
		case relaybind.ScopePair:
			return "tombstone", fmt.Sprintf("scope pair, wallet key %x, device %s", k.Key[:], fp(k.Device))
		case relaybind.ScopeAll:
			return "tombstone", fmt.Sprintf("scope all, wallet key %x", k.Key[:])
		}
		return "tombstone", "scope device, device " + fp(k.Device)
	case strings.HasPrefix(rel, pathMailbox):
		m, err := parseEntry(s.prefix+pathMailbox, s.prefix+rel)
		if err != nil {
			return "unknown", "not a mailbox entry's key"
		}
		return "mailbox entry", fmt.Sprintf("recipient %s, arrival %s, id %s, sender %s, nonce %016x", fp(m.Recipient), unixText(m.Arrival), m.Mid, fp(m.Sender), m.Nonce)
	case rel == migrationPath:
		return "migration record", "left by migrate-store; see store verify"
	}
	return "unknown", ""
}

// RenderInspect writes one page.
func RenderInspect(w io.Writer, p InspectPage) {
	for _, e := range p.Entries {
		fmt.Fprintf(w, "%s  %s", e.Key, e.Kind)
		if e.Detail != "" {
			fmt.Fprintf(w, " (%s)", e.Detail)
		}
		if e.VersionID != "" {
			fmt.Fprintf(w, "  version %s", e.VersionID)
			if e.Latest {
				fmt.Fprint(w, " (current)")
			}
		}
		if e.DeleteMarker {
			fmt.Fprint(w, "  delete marker")
		} else {
			fmt.Fprintf(w, "  %d bytes", e.Size)
		}
		if e.Lock != nil {
			fmt.Fprintf(w, "  %s", lockText(e.Lock))
		}
		fmt.Fprintln(w)
	}
	if p.Next != "" {
		fmt.Fprintf(w, "more: --after %q\n", p.Next)
	} else {
		fmt.Fprintln(w, "end of the listing")
	}
}
