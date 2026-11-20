package s3client

import (
	"errors"
	"fmt"
	"net/http"
)

// The typed outcomes. A refused request is a *StatusError, which matches the
// sentinel of its status with errors.Is; the others are returned as they are or
// joined with their cause.
var (
	// ErrPreconditionFailed is a 412: an If-None-Match: * over an object that
	// exists, or an If-Match whose ETag is not the current one.
	ErrPreconditionFailed = errors.New("the store refused a conditional write: precondition failed (412)")
	// ErrConflict is a 409: a conditional write raced another one.
	ErrConflict = errors.New("the store refused a conditional write: conflict (409)")
	// ErrNotFound is a 404: no such object or version, or If-Match on an object
	// that is gone or whose current version is a delete marker.
	ErrNotFound = errors.New("the store has no such object (404)")
	// ErrAccessDenied is a 403 that is not about the clock: a policy deny, or a
	// delete that Object Lock retention refuses.
	ErrAccessDenied = errors.New("the store denied the request (403)")
	// ErrClockSkew is the store saying the request time is too far from its own
	// (RequestTimeTooSkewed): this machine's clock or the store's is wrong.
	ErrClockSkew = errors.New("the store says this machine's clock is too far from its own (RequestTimeTooSkewed)")
	// ErrBadDigest is the store refusing a body whose checksum is not the one
	// sent: bytes damaged on the way.
	ErrBadDigest = errors.New("the store refused the body: its checksum is not the one sent (damaged on the way)")
	// ErrRedirect is a 3xx: redirects are never followed, so credentials never
	// go to another host.
	ErrRedirect = errors.New("the store answered with a redirect, which is not followed")
	// ErrStatus is any other refusal.
	ErrStatus = errors.New("the store refused the request")

	// ErrOutcomeUnknown is joined to the error of a write whose request may have
	// been applied: no answer came (a lost response, a deadline, a reset). Read
	// the object back before deciding.
	ErrOutcomeUnknown = errors.New("the write may or may not have been applied: no answer was received")
	// ErrNoDeadline is returned for a context without a deadline: every request
	// must have one.
	ErrNoDeadline = errors.New("the request has no deadline: every store request must carry one")
	// ErrUnconditional is returned for a put with neither If-None-Match nor
	// If-Match, or with both: this client makes no unconditional write.
	ErrUnconditional = errors.New("a put must be either create-only (If-None-Match: *) or an overwrite of one ETag (If-Match), exactly one of them")
	// ErrInvalidKey is returned for an object key outside the client's alphabet.
	ErrInvalidKey = errors.New("the object key is not valid: 1 to 1024 bytes of letters, digits, '.', '_', '-' and '/', no empty, '.' or '..' segment")
	// ErrInvalidInput is returned for any other malformed input.
	ErrInvalidInput = errors.New("invalid input")

	// ErrTooLarge is returned when a response is, or claims to be, larger than
	// the bound of the request.
	ErrTooLarge = errors.New("the store's response is larger than the bound of the request: refused")
	// ErrTruncated is returned when a response body ends before its stated length.
	ErrTruncated = errors.New("the store's response ended before its stated length")
	// ErrBadResponse is returned for a malformed response: a header value or an
	// XML document that does not pass the strict checks.
	ErrBadResponse = errors.New("the store's response is malformed")
	// ErrBadListing is returned for a listing that is inconsistent: keys out of
	// order or repeated, a key outside the prefix, a truncated page without a
	// continuation or without entries.
	ErrBadListing = errors.New("the store's listing is inconsistent")
	// ErrListLimit is returned when a listing holds more entries than the caller's bound.
	ErrListLimit = errors.New("the listing holds more entries than the bound")
	// ErrChecksumMismatch is returned when the store reports a SHA-256 checksum
	// other than the one of the bytes sent or received.
	ErrChecksumMismatch = errors.New("the store reports a checksum other than the one of the bytes")

	// ErrStaticCredentials is returned for credentials without a session token or an expiry.
	ErrStaticCredentials = errors.New("the store credentials are not short-lived: a session token and an expiry are required (use web identity, IRSA or Workload Identity)")
	// ErrCredentialsExpired is returned for credentials whose expiry has passed.
	ErrCredentialsExpired = errors.New("the store credentials have expired")
	// ErrCredentialsTooLong is returned for credentials that expire more than MaxCredentialLife ahead.
	ErrCredentialsTooLong = errors.New("the store credentials expire more than 12 hours ahead, which is not short-lived")
	// ErrInsecureEndpoint is returned for an endpoint that is not https (plain
	// http is allowed only to a loopback address with the test opt-in).
	ErrInsecureEndpoint = errors.New("the store endpoint is not https")
)

// StatusError is a request the store answered with a status other than
// success. It carries no header, no body beyond the error code and nothing of
// the credentials.
type StatusError struct {
	Op     string // put, get, head, delete, list, list-versions, bucket
	Key    string // the object key, empty for a bucket request
	Status int
	Code   string // the S3 error code, when the body gave one that passes the checks
	// DeleteMarker is true when the store said the key's current version (or the
	// version asked for) is a delete marker (x-amz-delete-marker: true).
	DeleteMarker bool
	// Attempts is the number of attempts made, this one included.
	Attempts int
	// Uncertain is true when an earlier attempt of this write had no answer, so
	// this refusal may be caused by that attempt having been applied (a 412 to a
	// retried create whose first try landed). Read the object back to tell.
	Uncertain bool
}

func (e *StatusError) Error() string {
	s := fmt.Sprintf("s3 %s", e.Op)
	if e.Key != "" {
		s += " " + e.Key
	}
	s += fmt.Sprintf(": %d %s", e.Status, http.StatusText(e.Status))
	if e.Code != "" {
		s += " (" + e.Code + ")"
	}
	if e.Attempts > 1 {
		s += fmt.Sprintf(" after %d attempts", e.Attempts)
	}
	return s
}

// Is matches the sentinel of the status.
func (e *StatusError) Is(target error) bool {
	switch target {
	case ErrStatus:
		return true
	case ErrPreconditionFailed:
		return e.Status == http.StatusPreconditionFailed
	case ErrConflict:
		return e.Status == http.StatusConflict
	case ErrNotFound:
		return e.Status == http.StatusNotFound
	case ErrClockSkew:
		return e.Status == http.StatusForbidden && e.Code == "RequestTimeTooSkewed"
	case ErrAccessDenied:
		return e.Status == http.StatusForbidden && e.Code != "RequestTimeTooSkewed"
	case ErrBadDigest:
		return e.Status == http.StatusBadRequest && (e.Code == "BadDigest" || e.Code == "InvalidDigest" || e.Code == "XAmzContentChecksumMismatch" || e.Code == "XAmzContentSHA256Mismatch")
	case ErrRedirect:
		return e.Status >= 300 && e.Status < 400
	}
	return false
}
