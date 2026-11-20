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

// SelfTestOptions are the inputs of the self-test.
type SelfTestOptions struct {
	// Prefix is the identity's prefix ("relays/<key>/"); the test objects are
	// <Prefix>selftest/<16 hex> (and <16 hex>-r for the retention checks), and
	// the policy check uses <Prefix>registry/tombstones/selftest-<16 hex>.
	Prefix string
	// Registry adds the checks of the registry bucket: versioning on, Object
	// Lock enabled, and the policy's deny of a simple delete in the tombstone
	// namespace. Without it the bucket must report versioning never enabled.
	Registry bool
	// Retention (registry only) adds the checks that leave an object behind: a
	// create with a one-day retention in Mode, read back with that mode and date,
	// a delete of it by version id refused, the version listed. The object stays
	// locked for a day and is left for the sweep, so these checks run at
	// init-store and store verify, not at every start: a crash loop would
	// otherwise pile up objects nobody can delete for a day.
	Retention bool
	Mode      Mode
	// Now is the clock for the retention date (default time.Now); Rand the
	// source of the object names (default crypto/rand).
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

// The properties of ADR 0015 decision 2, "What the store must offer", and the
// checks added to it. Their text is what SelfTestError.Property holds.
const (
	PropBucket           = "the bucket exists (its versioning status can be read)"
	PropUnversioned      = "the working bucket reports versioning never enabled"
	PropCreateOnly       = "a create with If-None-Match: * over an existing object answers 412"
	PropWrongIfMatch     = "an overwrite with a wrong If-Match answers 412"
	PropDistinctETags    = "two writes of different bytes give two different ETags"
	PropReadAfterWrite   = "a written object is read back at once"
	PropListAfterWrite   = "a written object is listed at once"
	PropVersioning       = "the bucket reports versioning on"
	PropObjectLock       = "the bucket reports Object Lock enabled"
	PropDenySimpleDelete = "a simple delete in the tombstone namespace is refused by the bucket policy"
	PropRetention        = "a create with a retain-until date and mode reads back with that date and mode"
	PropLockedDelete     = "a delete of a locked version by its version id is refused"
	PropVersionListed    = "a version listing shows the locked version"
	PropCleanup          = "a test object is deleted (by name in the working bucket, by version id in the registry bucket)"
)

// SelfTest runs the checks of ADR 0015 decision 2 against the client's bucket,
// one request at a time, and removes what it wrote (on a failure too, as far
// as the store lets it), except the retention object of Retention.
//
// What it cannot show (decision 2, "What the self-test cannot show", and
// SPO-Xobjstore-PRE-005): that of two racing conditional writes exactly one
// wins; the lifecycle rules; the policy's deny on the marker (testing it would
// hide the real marker if the deny were missing) and on an unconditional put
// (the client has none); that a retention is compliance and not governance
// beyond the mode the store reports; that a refused delete by version id is
// refused by the lock and not by a policy (it can show only that the same role
// may delete an unlocked self-test version by id, which it does first).
func SelfTest(ctx context.Context, c *Client, o SelfTestOptions) error {
	if !validPrefix(o.Prefix) {
		return ErrInvalidKey
	}
	if o.Retention && (!o.Registry || (o.Mode != Compliance && o.Mode != Governance)) {
		return fmt.Errorf("%w: the retention checks need the registry bucket and a retention mode", ErrInvalidInput)
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
	tag := hex.EncodeToString(id[:])
	key := o.Prefix + "selftest/" + tag

	st, err := c.Versioning(ctx)
	if err != nil {
		return &SelfTestError{PropBucket, err}
	}
	if !o.Registry && st != "" {
		return &SelfTestError{PropUnversioned, fmt.Errorf("the bucket reports versioning %q", st)}
	}
	if o.Registry {
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
		if err := denySimpleDelete(ctx, c, o.Prefix+"registry/tombstones/selftest-"+tag); err != nil {
			return err
		}
	}

	var vids []string // versions this run created, for the registry cleanup
	err = conditionalChecks(ctx, c, key, &vids)
	if err != nil {
		removeAll(ctx, c, key, o.Registry, vids)
		return err
	}
	if err := remove(ctx, c, key, o.Registry, vids); err != nil {
		return &SelfTestError{PropCleanup, err}
	}
	if !o.Retention {
		return nil
	}
	return retentionChecks(ctx, c, key+"-r", &Retention{Mode: o.Mode, Until: now().Add(24 * time.Hour).UTC().Truncate(time.Second)})
}

// denySimpleDelete checks that a simple delete under registry/tombstones/ is
// refused. The name parses as no tombstone. Without the deny the delete adds a
// delete marker, which is removed again by its version id (the role may delete
// versions there) before the failure is reported.
func denySimpleDelete(ctx context.Context, c *Client, key string) error {
	_, err := c.Delete(ctx, key)
	if errors.Is(err, ErrAccessDenied) && !errors.Is(err, ErrOutcomeUnknown) {
		return nil
	}
	if vs, lerr := c.ListAllVersions(ctx, key, 16); lerr == nil {
		for _, v := range vs {
			if v.Key == key {
				_, _ = c.DeleteVersion(ctx, key, v.VersionID)
			}
		}
	}
	return &SelfTestError{PropDenySimpleDelete, err}
}

func conditionalChecks(ctx context.Context, c *Client, key string, vids *[]string) error {
	a := []byte("spo selftest a " + key)
	b := []byte("spo selftest b " + key)
	first, err := c.Put(ctx, PutInput{Key: key, Body: a, IfNoneMatch: true, Checksum: true})
	if err != nil {
		return &SelfTestError{PropCreateOnly, fmt.Errorf("the first create failed: %w", err)}
	}
	*vids = append(*vids, first.VersionID)
	if _, err := c.Put(ctx, PutInput{Key: key, Body: b, IfNoneMatch: true, Checksum: true}); !errors.Is(err, ErrPreconditionFailed) || errors.Is(err, ErrOutcomeUnknown) {
		return &SelfTestError{PropCreateOnly, err}
	}
	wrong := `"00000000000000000000000000000000"`
	if wrong == first.ETag {
		wrong = `"11111111111111111111111111111111"`
	}
	if _, err := c.Put(ctx, PutInput{Key: key, Body: b, IfMatch: wrong, Checksum: true}); !errors.Is(err, ErrPreconditionFailed) || errors.Is(err, ErrOutcomeUnknown) {
		return &SelfTestError{PropWrongIfMatch, err}
	}
	second, err := c.Put(ctx, PutInput{Key: key, Body: b, IfMatch: first.ETag, Checksum: true})
	if err != nil {
		return &SelfTestError{PropDistinctETags, fmt.Errorf("the overwrite with the right If-Match failed: %w", err)}
	}
	*vids = append(*vids, second.VersionID)
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
	return nil
}

// remove deletes the test object: by name in the working bucket, each version
// this run created by its id in the registry bucket (no delete marker is left).
func remove(ctx context.Context, c *Client, key string, registry bool, vids []string) error {
	if !registry {
		_, err := c.Delete(ctx, key)
		return err
	}
	for _, v := range vids {
		if v == "" {
			return fmt.Errorf("%w: a put in the registry bucket gave no version id", ErrBadResponse)
		}
		if _, err := c.DeleteVersion(ctx, key, v); err != nil {
			return err
		}
	}
	return nil
}

// removeAll is the cleanup of a failed run, best effort: in the registry
// bucket it also deletes the versions a listing shows, which covers a put whose
// outcome was unknown.
func removeAll(ctx context.Context, c *Client, key string, registry bool, vids []string) {
	_ = remove(ctx, c, key, registry, vids)
	if !registry {
		return
	}
	if vs, err := c.ListAllVersions(ctx, key, 16); err == nil {
		for _, v := range vs {
			if v.Key == key {
				_, _ = c.DeleteVersion(ctx, key, v.VersionID)
			}
		}
	}
}

// retentionChecks leaves one locked object behind. The retention is read back
// by a GET, not a HEAD, so that a refusal carries its code (a skewed clock is
// ErrClockSkew, not ErrAccessDenied).
func retentionChecks(ctx context.Context, c *Client, key string, ret *Retention) error {
	body := []byte("spo selftest retention " + key)
	p, err := c.Put(ctx, PutInput{Key: key, Body: body, IfNoneMatch: true, Retention: ret, Checksum: true})
	if err != nil {
		return &SelfTestError{PropRetention, fmt.Errorf("the create with a retention failed: %w", err)}
	}
	if p.VersionID == "" {
		return &SelfTestError{PropRetention, fmt.Errorf("%w: the create gave no version id", ErrBadResponse)}
	}
	got, err := c.Get(ctx, GetInput{Key: key, VersionID: p.VersionID, MaxBytes: int64(len(body)) + 1})
	if err != nil {
		return &SelfTestError{PropRetention, err}
	}
	if r := got.Info.Retention; r == nil || r.Mode != ret.Mode || !r.Until.Equal(ret.Until) {
		return &SelfTestError{Property: PropRetention}
	}
	if _, err := c.DeleteVersion(ctx, key, p.VersionID); err == nil {
		return &SelfTestError{Property: PropLockedDelete}
	} else if !errors.Is(err, ErrAccessDenied) {
		return &SelfTestError{PropLockedDelete, err}
	}
	vs, err := c.ListAllVersions(ctx, key, 16)
	if err != nil {
		return &SelfTestError{PropVersionListed, err}
	}
	for _, v := range vs {
		if v.Key == key && v.VersionID == p.VersionID && !v.DeleteMarker {
			return nil
		}
	}
	return &SelfTestError{Property: PropVersionListed}
}
