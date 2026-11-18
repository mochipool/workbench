package ports

import (
	"context"
	"errors"
	"io"
	"strings"
)

// The object ports of a backup sink (ADR 0012 decisions 4, 5 and 9). They are
// split by capability (ADR 0008): an adapter implements the ports it can honour
// and there is no combined store. Names are slash-separated relative paths such
// as backups/<workspace>/<file>; an adapter refuses any other shape.

// ErrObjectExists is returned by ObjectWriter.Put when the name is taken by an
// object with different bytes. Nothing was changed.
var ErrObjectExists = errors.New("an object with that name already exists with different content")

// ErrObjectNotFound is returned by ObjectReader.Get for a name that is absent.
var ErrObjectNotFound = errors.New("no such object")

// ObjectWriter creates objects. Put is create-if-absent: when the name exists
// with identical bytes it succeeds and changes nothing; when it exists with
// different bytes it returns ErrObjectExists. There is no overwrite and no
// delete. size is the length of r.
type ObjectWriter interface {
	Put(ctx context.Context, name string, r io.Reader, size int64) error
}

// ObjectReader reads objects by name.
type ObjectReader interface {
	Get(ctx context.Context, name string) (io.ReadCloser, error)
	Has(ctx context.Context, name string) (bool, error)
}

// ErrRangeNotSatisfiable is returned by ObjectRangeReader.GetRange when the
// offset is at or beyond the end of the object (an HTTP 416).
var ErrRangeNotSatisfiable = errors.New("the offset is beyond the end of the object")

// ObjectRangeReader reads an object from an offset to its end, to resume an
// interrupted download. It is its own capability: an adapter that cannot seek
// does not implement it.
type ObjectRangeReader interface {
	GetRange(ctx context.Context, name string, offset int64) (io.ReadCloser, error)
}

// ObjectInfo is one entry of a listing.
type ObjectInfo struct {
	Name string
	Size int64
}

// ObjectLister lists the names that start with prefix.
type ObjectLister interface {
	List(ctx context.Context, prefix string) ([]ObjectInfo, error)
}

// SinkKind says what a sink is.
type SinkKind string

const (
	SinkDir SinkKind = "dir"
	SinkS3  SinkKind = "s3"
)

// SinkProperties is what a sink reports about itself. An adapter only reports;
// the use case decides from the report.
type SinkProperties struct {
	Kind SinkKind
	// Versioning is true when object versions are kept (S3 bucket versioning).
	Versioning bool
	// ObjectLockMode is the default retention mode of the bucket: "COMPLIANCE",
	// "GOVERNANCE" or "" when Object Lock is off or has no default rule.
	ObjectLockMode string
	// ObjectLockDefaultRetention is true when the bucket has a default retention
	// rule (a number of days or years).
	ObjectLockDefaultRetention bool
	// ShortLivedCredentials is true when the credentials the adapter uses expire
	// and carry a session token.
	ShortLivedCredentials bool
}

// SinkProbe reports the properties of a sink.
type SinkProbe interface {
	Check(ctx context.Context) (SinkProperties, error)
}

// ValidObjectName reports whether name is a relative, slash-separated name with
// no empty, "." or ".." component, no backslash and no control character. Every
// adapter applies it before it touches storage.
func ValidObjectName(name string) error {
	if name == "" || len(name) > 1024 {
		return errors.New("object name is empty or too long")
	}
	if name[0] == '/' {
		return errors.New("object name is absolute")
	}
	for _, c := range name {
		if c < 0x20 || c == 0x7f || c == '\\' {
			return errors.New("object name has a control character or a backslash")
		}
	}
	for _, part := range strings.Split(name, "/") {
		switch part {
		case "", ".", "..":
			return errors.New("object name has an empty, \".\" or \"..\" component")
		}
	}
	return nil
}
