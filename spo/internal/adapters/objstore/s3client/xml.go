package s3client

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"time"
)

// The XML a store sends is decoded token by token under fixed bounds: the
// body is already within its byte bound; the nesting is at most maxDepth; the
// elements are at most maxElems; the text of one element is at most maxText
// bytes. The decoder is strict, has no entity map (only the five predefined
// entities and character references decode; any other is an error, so nothing
// expands) and no charset reader (a declared encoding other than UTF-8 is an
// error); a document type or any directive is refused. Only local names are
// compared: the S3 namespace is not checked.
const (
	maxDepth = 6
	maxText  = 2048
)

type xmlEvent struct {
	start, end bool
	path       []string // local names from the root, the current element last
	text       string   // the element's text, on end
}

// walkXML calls f for each start and end of an element below the root, the
// end carrying the element's text. The root's local name must be root.
func walkXML(body []byte, root string, maxElems int, f func(xmlEvent) error) error {
	d := xml.NewDecoder(bytes.NewReader(body))
	d.Strict = true
	d.Entity = nil
	d.CharsetReader = nil
	var path []string
	var text []byte
	elems := 0
	sawRoot := false
	for {
		tok, err := d.RawToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: XML: %v", ErrBadResponse, err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			elems++
			if elems > maxElems {
				return fmt.Errorf("%w: XML has more than %d elements", ErrBadResponse, maxElems)
			}
			if len(path) == 0 {
				if sawRoot || t.Name.Local != root {
					return fmt.Errorf("%w: XML root is not %s", ErrBadResponse, root)
				}
				sawRoot = true
			}
			if len(path) >= maxDepth {
				return fmt.Errorf("%w: XML nested deeper than %d", ErrBadResponse, maxDepth)
			}
			path = append(path, t.Name.Local)
			text = text[:0]
			if len(path) > 1 {
				if err := f(xmlEvent{start: true, path: path}); err != nil {
					return err
				}
			}
		case xml.EndElement:
			if len(path) == 0 || path[len(path)-1] != t.Name.Local {
				return fmt.Errorf("%w: XML end tag does not match", ErrBadResponse)
			}
			if len(path) > 1 {
				if err := f(xmlEvent{end: true, path: path, text: string(text)}); err != nil {
					return err
				}
			}
			path = path[:len(path)-1]
			text = text[:0]
		case xml.CharData:
			if len(path) == 0 {
				if len(bytes.TrimSpace(t)) != 0 {
					return fmt.Errorf("%w: XML text outside the root", ErrBadResponse)
				}
				continue
			}
			if len(text)+len(t) > maxText {
				return fmt.Errorf("%w: XML text longer than %d bytes", ErrBadResponse, maxText)
			}
			text = append(text, t...)
		case xml.ProcInst:
			if t.Target != "xml" || sawRoot {
				return fmt.Errorf("%w: XML processing instruction", ErrBadResponse)
			}
		case xml.Directive:
			return fmt.Errorf("%w: XML directive (a document type is never accepted)", ErrBadResponse)
		case xml.Comment:
		}
	}
	if !sawRoot || len(path) != 0 {
		return fmt.Errorf("%w: XML document incomplete", ErrBadResponse)
	}
	return nil
}

// RawToken does not translate entities in attribute values or check that end
// tags match; walkXML checks the tags itself, and CharData from RawToken still
// has the predefined entities and character references decoded in strict mode.

// errorCode reads the Code of an S3 error document; "" when there is none that
// passes the checks (letters and digits, at most 64).
func errorCode(body []byte) string {
	code := ""
	err := walkXML(body, "Error", 64, func(e xmlEvent) error {
		if e.end && len(e.path) == 2 && e.path[1] == "Code" {
			code = e.text
		}
		return nil
	})
	if err != nil || len(code) > 64 {
		return ""
	}
	for i := 0; i < len(code); i++ {
		ch := code[i]
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9') {
			return ""
		}
	}
	return code
}

// ObjectInfo is what a listing, a head or a get says of one object.
type ObjectInfo struct {
	Key          string
	Size         int64
	ETag         string
	VersionID    string // empty in an unversioned listing
	LastModified time.Time
	// Retention, from a head or a get: the Object Lock mode and date of this version.
	Retention *Retention
	// ChecksumSHA256 is the base64 checksum the store reported, if any.
	ChecksumSHA256 string
}

// Version is one entry of a version listing: an object version or a delete marker.
type Version struct {
	Key          string
	VersionID    string
	IsLatest     bool
	DeleteMarker bool
	Size         int64 // 0 for a delete marker
	ETag         string
	LastModified time.Time
}

// ListPage is one page of a listing.
type ListPage struct {
	Objects   []ObjectInfo
	Truncated bool
	NextToken string
}

// VersionPage is one page of a version listing.
type VersionPage struct {
	Versions            []Version
	Truncated           bool
	NextKeyMarker       string
	NextVersionIDMarker string
}

func parseBool(s string) (bool, error) {
	switch s {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("%w: not a boolean", ErrBadResponse)
}

func parseSize(s string) (int64, error) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 || len(s) > 19 || (len(s) > 1 && s[0] == '0') {
		return 0, fmt.Errorf("%w: not a size", ErrBadResponse)
	}
	return n, nil
}

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: not a time", ErrBadResponse)
	}
	return t, nil
}

func checkETag(s string) error {
	if !validETag(s) {
		return fmt.Errorf("%w: not an ETag", ErrBadResponse)
	}
	return nil
}

// validETag accepts a quoted or bare token of printable ASCII, at most 128 bytes.
func validETag(s string) bool { return printable(s, 128) }

// parseListPage decodes a ListObjectsV2 page of at most maxKeys entries.
func parseListPage(body []byte, maxKeys int) (ListPage, error) {
	var p ListPage
	var cur *ObjectInfo
	var seen map[string]bool
	err := walkXML(body, "ListBucketResult", 16*maxKeys+64, func(e xmlEvent) error {
		switch {
		case len(e.path) == 2 && e.path[1] == "Contents":
			if e.start {
				if len(p.Objects) >= maxKeys {
					return fmt.Errorf("%w: more entries than max-keys", ErrBadListing)
				}
				cur, seen = &ObjectInfo{}, map[string]bool{}
				return nil
			}
			if !seen["Key"] || !seen["Size"] {
				return fmt.Errorf("%w: an entry without a key or a size", ErrBadResponse)
			}
			p.Objects = append(p.Objects, *cur)
			cur = nil
		case e.end && len(e.path) == 3 && e.path[1] == "Contents":
			if seen[e.path[2]] {
				return fmt.Errorf("%w: %s twice in one entry", ErrBadResponse, e.path[2])
			}
			seen[e.path[2]] = true
			var err error
			switch e.path[2] {
			case "Key":
				cur.Key = e.text
			case "Size":
				cur.Size, err = parseSize(e.text)
			case "ETag":
				cur.ETag, err = e.text, checkETag(e.text)
			case "LastModified":
				cur.LastModified, err = parseTime(e.text)
			}
			return err
		case e.end && len(e.path) == 2:
			var err error
			switch e.path[1] {
			case "IsTruncated":
				p.Truncated, err = parseBool(e.text)
			case "NextContinuationToken":
				if !printable(e.text, 1024) {
					return fmt.Errorf("%w: not a continuation token", ErrBadResponse)
				}
				p.NextToken = e.text
			}
			return err
		}
		return nil
	})
	return p, err
}

// parseVersionPage decodes a ListObjectVersions page of at most maxKeys entries.
func parseVersionPage(body []byte, maxKeys int) (VersionPage, error) {
	var p VersionPage
	var cur *Version
	var seen map[string]bool
	err := walkXML(body, "ListVersionsResult", 16*maxKeys+64, func(e xmlEvent) error {
		switch {
		case len(e.path) == 2 && (e.path[1] == "Version" || e.path[1] == "DeleteMarker"):
			if e.start {
				if len(p.Versions) >= maxKeys {
					return fmt.Errorf("%w: more entries than max-keys", ErrBadListing)
				}
				cur, seen = &Version{DeleteMarker: e.path[1] == "DeleteMarker"}, map[string]bool{}
				return nil
			}
			if !seen["Key"] || !seen["VersionId"] || (!cur.DeleteMarker && !seen["Size"]) {
				return fmt.Errorf("%w: a version without a key, a version id or a size", ErrBadResponse)
			}
			p.Versions = append(p.Versions, *cur)
			cur = nil
		case e.end && len(e.path) == 3 && (e.path[1] == "Version" || e.path[1] == "DeleteMarker"):
			if seen[e.path[2]] {
				return fmt.Errorf("%w: %s twice in one entry", ErrBadResponse, e.path[2])
			}
			seen[e.path[2]] = true
			var err error
			switch e.path[2] {
			case "Key":
				cur.Key = e.text
			case "VersionId":
				if !printable(e.text, 1024) {
					return fmt.Errorf("%w: not a version id", ErrBadResponse)
				}
				cur.VersionID = e.text
			case "IsLatest":
				cur.IsLatest, err = parseBool(e.text)
			case "Size":
				if cur.DeleteMarker {
					return fmt.Errorf("%w: a delete marker with a size", ErrBadResponse)
				}
				cur.Size, err = parseSize(e.text)
			case "ETag":
				cur.ETag, err = e.text, checkETag(e.text)
			case "LastModified":
				cur.LastModified, err = parseTime(e.text)
			}
			return err
		case e.end && len(e.path) == 2:
			var err error
			switch e.path[1] {
			case "IsTruncated":
				p.Truncated, err = parseBool(e.text)
			case "NextKeyMarker":
				p.NextKeyMarker = e.text
			case "NextVersionIdMarker":
				if e.text != "" && !printable(e.text, 1024) {
					return fmt.Errorf("%w: not a version id marker", ErrBadResponse)
				}
				p.NextVersionIDMarker = e.text
			}
			return err
		}
		return nil
	})
	return p, err
}

// parseVersioning reads the Status of a GetBucketVersioning answer ("" when absent).
func parseVersioning(body []byte) (string, error) {
	st := ""
	err := walkXML(body, "VersioningConfiguration", 16, func(e xmlEvent) error {
		if e.end && len(e.path) == 2 && e.path[1] == "Status" {
			st = e.text
		}
		return nil
	})
	return st, err
}

// parseObjectLock reads whether ObjectLockEnabled is Enabled.
func parseObjectLock(body []byte) (bool, error) {
	on := false
	err := walkXML(body, "ObjectLockConfiguration", 32, func(e xmlEvent) error {
		if e.end && len(e.path) == 2 && e.path[1] == "ObjectLockEnabled" {
			on = e.text == "Enabled"
		}
		return nil
	})
	return on, err
}
