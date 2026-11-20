package s3client

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"
)

// SelfTestOptions are the inputs of the start-up self-test.
type SelfTestOptions struct {
	// Prefix is the identity's prefix ("relays/<key>/"); the test objects are
	// <Prefix>selftest/<16 hex>.
	Prefix string
	// Registry adds the checks of the registry bucket (versioning, Object Lock,
	// retention) and puts every test object with a one-day retention in Mode.
	Registry bool
	Mode     Mode
	// Now is the clock for the retention date (default time.Now); Rand the
	// source of the object name (default crypto/rand).
	Now  func() time.Time
	Rand io.Reader
}

// SelfTestError names the property a store failed.
type SelfTestError struct {
	Property string
	Err      error
}

func (e *SelfTestError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("the store fails the self-test: %s: %v", e.Property, e.Err)
	}
	return "the store fails the self-test: " + e.Property
}

func (e *SelfTestError) Unwrap() error { return e.Err }

// The properties of ADR 0015 decision 2, "What the store must offer, checked at
// every start". Their text is what SelfTestError.Property holds.
const (
	PropCreateOnly     = "a create with If-None-Match: * over an existing object answers 412"
	PropWrongIfMatch   = "an overwrite with a wrong If-Match answers 412"
	PropDistinctETags  = "two writes of different bytes give two different ETags"
	PropReadAfterWrite = "a written object is read back at once"
	PropListAfterWrite = "a written object is listed at once"
	PropVersioning     = "the bucket reports versioning on"
	PropObjectLock     = "the bucket reports Object Lock enabled"
	PropRetention      = "a create with a retain-until date and mode reads back with that date and mode"
	PropLockedDelete   = "a delete of a locked version by its version id is refused"
	PropVersionListed  = "a version listing shows the locked version"
	PropCleanup        = "a test object of the working bucket is deleted"
)

// SelfTest runs the start-up checks of ADR 0015 decision 2 against the
// client's bucket, one request at a time. It cannot show that of two racing
// conditional writes exactly one wins, nor read the bucket policy or the
// lifecycle rules (decision 2, "What the self-test cannot show"). In the
// working bucket it deletes its object; in the registry bucket the object
// keeps its one-day retention and is left for the sweep.
func SelfTest(ctx context.Context, c *Client, o SelfTestOptions) error {
	if !validPrefix(o.Prefix) {
		return ErrInvalidKey
	}
	now, rnd := o.Now, o.Rand
	if now == nil {
		now = time.Now
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	var id [8]byte
	if _, err := io.ReadFull(rnd, id[:]); err != nil {
		return err
	}
	key := o.Prefix + "selftest/" + hex.EncodeToString(id[:])
	var ret *Retention
	if o.Registry {
		if o.Mode != Compliance && o.Mode != Governance {
			return fmt.Errorf("%w: the registry self-test needs a retention mode", ErrInvalidInput)
		}
		st, err := c.Versioning(ctx)
		if err != nil {
			return &SelfTestError{PropVersioning, err}
		}
		if st != "Enabled" {
			return &SelfTestError{Property: PropVersioning}
		}
		on, err := c.ObjectLockEnabled(ctx)
		if err != nil {
			return &SelfTestError{PropObjectLock, err}
		}
		if !on {
			return &SelfTestError{Property: PropObjectLock}
		}
		ret = &Retention{Mode: o.Mode, Until: now().Add(24 * time.Hour).UTC().Truncate(time.Second)}
	}
	a := []byte("spo selftest a " + key)
	b := []byte("spo selftest b " + key)
	first, err := c.Put(ctx, PutInput{Key: key, Body: a, IfNoneMatch: true, Retention: ret, Checksum: true})
	if err != nil {
		return &SelfTestError{PropCreateOnly, fmt.Errorf("the first create failed: %w", err)}
	}
	if _, err := c.Put(ctx, PutInput{Key: key, Body: b, IfNoneMatch: true, Retention: ret, Checksum: true}); !errors.Is(err, ErrPreconditionFailed) {
		return &SelfTestError{PropCreateOnly, err}
	}
	wrong := `"00000000000000000000000000000000"`
	if wrong == first.ETag {
		wrong = `"11111111111111111111111111111111"`
	}
	if _, err := c.Put(ctx, PutInput{Key: key, Body: b, IfMatch: wrong, Retention: ret, Checksum: true}); !errors.Is(err, ErrPreconditionFailed) {
		return &SelfTestError{PropWrongIfMatch, err}
	}
	second, err := c.Put(ctx, PutInput{Key: key, Body: b, IfMatch: first.ETag, Retention: ret, Checksum: true})
	if err != nil {
		return &SelfTestError{PropDistinctETags, fmt.Errorf("the overwrite with the right If-Match failed: %w", err)}
	}
	if second.ETag == first.ETag {
		return &SelfTestError{Property: PropDistinctETags}
	}
	got, err := c.Get(ctx, GetInput{Key: key, MaxBytes: int64(len(b)) + 1})
	if err != nil {
		return &SelfTestError{PropReadAfterWrite, err}
	}
	if string(got.Body) != string(b) || got.Info.ETag != second.ETag {
		return &SelfTestError{Property: PropReadAfterWrite}
	}
	list, err := c.ListAll(ctx, key, 4)
	if err != nil {
		return &SelfTestError{PropListAfterWrite, err}
	}
	if len(list) != 1 || list[0].Key != key || list[0].Size != int64(len(b)) {
		return &SelfTestError{Property: PropListAfterWrite}
	}
	if !o.Registry {
		if _, err := c.Delete(ctx, key); err != nil {
			return &SelfTestError{PropCleanup, err}
		}
		return nil
	}
	h, err := c.Head(ctx, key, second.VersionID)
	if err != nil {
		return &SelfTestError{PropRetention, err}
	}
	if second.VersionID == "" || h.Retention == nil || h.Retention.Mode != ret.Mode || !h.Retention.Until.Equal(ret.Until) {
		return &SelfTestError{Property: PropRetention}
	}
	if _, err := c.DeleteVersion(ctx, key, second.VersionID); err == nil {
		return &SelfTestError{Property: PropLockedDelete}
	} else if !errors.Is(err, ErrAccessDenied) {
		return &SelfTestError{PropLockedDelete, err}
	}
	vs, err := c.ListAllVersions(ctx, key, 16)
	if err != nil {
		return &SelfTestError{PropVersionListed, err}
	}
	for _, v := range vs {
		if v.Key == key && v.VersionID == second.VersionID && !v.DeleteMarker {
			return nil
		}
	}
	return &SelfTestError{Property: PropVersionListed}
}
