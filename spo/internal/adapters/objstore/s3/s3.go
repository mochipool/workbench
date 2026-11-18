// Package s3 is a backup sink on an S3 bucket, through the AWS SDK for Go v2
// (ADR 0012 decisions 4, 5 and 9). It is the only package that imports the AWS
// modules.
//
// Credentials come only from the SDK's default chain (environment, shared
// configuration, SSO, web identity, container and instance roles). The adapter
// refuses credentials that are not short-lived: static access keys are not
// accepted. The endpoint is overridden only through the SDK's own
// configuration (AWS_ENDPOINT_URL, AWS_ENDPOINT_URL_S3, the shared config
// file). Nothing here prints or logs a credential.
//
// Construction makes no network call: credentials are fetched on first use.
package s3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// ErrStaticCredentials is returned for credentials that do not expire or have
// no session token.
var ErrStaticCredentials = errors.New("the AWS credentials are not short-lived: static access keys, in a file or an environment variable, are not accepted for a backup bucket. Use AWS SSO (IAM Identity Center), IAM Roles Anywhere, IRSA or GKE-style Workload Identity federation so that the credentials expire")

// ErrCredentialsExpired is returned when the credentials have expired.
var ErrCredentialsExpired = errors.New("the AWS credentials have expired or were rejected as expired: re-authenticate (for example run aws sso login, or start a new role session) and run the command again")

// ErrCredentialsTooLong is returned for credentials that expire more than
// MaxCredentialLife ahead: a provider can assert any expiry, and a far-future
// one is no more short-lived than a static key.
var ErrCredentialsTooLong = errors.New("the AWS credentials expire more than 12 hours ahead, which is not short-lived: use credentials that expire within 12 hours (AWS SSO, IAM Roles Anywhere, IRSA or Workload Identity give such sessions)")

// ErrInsecureEndpoint is returned for an endpoint that is not https.
var ErrInsecureEndpoint = errors.New("the S3 endpoint is not https: a backup is not sent to a plain-http endpoint (check AWS_ENDPOINT_URL, AWS_ENDPOINT_URL_S3 and the shared AWS configuration)")

// ErrTooSlow is returned when a transfer exceeds the total deadline derived from
// its size.
var ErrTooSlow = errors.New("the transfer is too slow: it did not finish within the total deadline for its size")

// ErrStalled is returned when a transfer moves no data for the stall timeout.
var ErrStalled = errors.New("the transfer stalled: no data moved within the time limit")

// The limits: the SDK's standard retryer makes at most MaxAttempts attempts of
// a request; a transfer that moves no data for DefaultStallTimeout is abandoned
// (a transfer that keeps moving is not limited, it can be a gigabyte); a call
// that moves no object body is limited to twice that.
const (
	MaxAttempts         = 3
	MaxCredentialLife   = 12 * time.Hour
	DefaultMinRate      = 64 << 10 // bytes per second; with the allowance, the total deadline of a transfer
	DefaultAllowance    = time.Minute
	DefaultStallTimeout = time.Minute
	dialTimeout         = 10 * time.Second
)

// Store is a bucket (and key prefix) used as a sink. It implements
// ports.ObjectWriter, ObjectReader, ObjectLister and SinkProbe.
type Store struct {
	c      *awss3.Client
	bucket string
	prefix string
	creds  aws.CredentialsProvider
	stall  time.Duration
	rate   int64
	allow  time.Duration
}

var (
	_ ports.ObjectWriter      = (*Store)(nil)
	_ ports.ObjectReader      = (*Store)(nil)
	_ ports.ObjectLister      = (*Store)(nil)
	_ ports.ObjectRangeReader = (*Store)(nil)
	_ ports.SinkProbe         = (*Store)(nil)
)

type options struct {
	cfg      *aws.Config
	attempts int
	stall    time.Duration
	rate     int64
	allow    time.Duration
}

// WithTransferLimits sets the minimum rate (bytes per second) and the fixed
// allowance that give a transfer its total deadline: allowance + size/rate.
func WithTransferLimits(minRate int64, allowance time.Duration) Option {
	return func(o *options) { o.rate, o.allow = minRate, allowance }
}

// WithMaxAttempts sets the attempts of the standard retryer (default MaxAttempts).
func WithMaxAttempts(n int) Option { return func(o *options) { o.attempts = n } }

// WithStallTimeout sets how long a transfer may move no data (default DefaultStallTimeout).
func WithStallTimeout(d time.Duration) Option { return func(o *options) { o.stall = d } }

// Option changes how New builds the client.
type Option func(*options)

// WithAWSConfig replaces the default configuration chain. It is for tests,
// which inject a provider and a local endpoint; the commands never use it.
func WithAWSConfig(cfg aws.Config) Option { return func(o *options) { o.cfg = &cfg } }

// requireShortLived passes only credentials that expire and carry a session token.
type requireShortLived struct{ inner aws.CredentialsProvider }

func (p requireShortLived) Retrieve(ctx context.Context) (aws.Credentials, error) {
	c, err := p.inner.Retrieve(ctx)
	if err != nil {
		return aws.Credentials{}, err
	}
	if !c.CanExpire || c.SessionToken == "" {
		return aws.Credentials{}, ErrStaticCredentials
	}
	if time.Until(c.Expires) > MaxCredentialLife {
		return aws.Credentials{}, ErrCredentialsTooLong
	}
	return c, nil
}

// New builds a sink for bucket and the key prefix (which may be empty). It does
// not contact AWS.
func New(ctx context.Context, bucket, prefix string, opts ...Option) (*Store, error) {
	if bucket == "" {
		return nil, errors.New("the S3 bucket name is empty")
	}
	o := options{attempts: MaxAttempts, stall: DefaultStallTimeout, rate: DefaultMinRate, allow: DefaultAllowance}
	for _, f := range opts {
		f(&o)
	}
	var cfg aws.Config
	if o.cfg != nil {
		cfg = *o.cfg
	} else {
		var err error
		if cfg, err = config.LoadDefaultConfig(ctx); err != nil {
			return nil, fmt.Errorf("cannot load the AWS configuration: %w", err)
		}
	}
	if cfg.Region == "" {
		return nil, errors.New("no AWS region is configured: set AWS_REGION or a region in the shared AWS configuration")
	}
	if cfg.Credentials == nil {
		return nil, errors.New("no AWS credentials provider is configured")
	}
	if cfg.HTTPClient == nil {
		stall := o.stall
		cfg.HTTPClient = awshttp.NewBuildableClient().
			WithDialerOptions(func(d *net.Dialer) { d.Timeout = dialTimeout }).
			WithTransportOptions(func(tr *http.Transport) {
				tr.TLSHandshakeTimeout = dialTimeout
				tr.ResponseHeaderTimeout = stall
			})
	}
	creds := aws.NewCredentialsCache(requireShortLived{cfg.Credentials})
	cfg.Credentials = creds
	prefix = strings.Trim(prefix, "/")
	if prefix != "" {
		prefix += "/"
	}
	oa := o
	c := awss3.NewFromConfig(cfg, func(o *awss3.Options) {
		// The checksum is sent explicitly (SHA-256 of the file); nothing else is
		// added to the request or demanded of the response.
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
		o.RetryMaxAttempts = oa.attempts
		if cfg.BaseEndpoint != nil {
			o.UsePathStyle = true // a custom endpoint is usually not a virtual-hosted name
		}
	})
	if ep := c.Options().BaseEndpoint; ep != nil {
		if u, err := url.Parse(*ep); err != nil || u.Scheme != "https" {
			return nil, ErrInsecureEndpoint
		}
	}
	return &Store{c: c, bucket: bucket, prefix: prefix, creds: creds, stall: o.stall, rate: o.rate, allow: o.allow}, nil
}

// limit is the total deadline of a transfer of size bytes.
func (s *Store) limit(size int64) time.Duration {
	return s.allow + time.Duration(size)*time.Second/time.Duration(s.rate)
}

func (s *Store) key(name string) (string, error) {
	if err := ports.ValidObjectName(name); err != nil {
		return "", err
	}
	return s.prefix + name, nil
}

// watch cancels a context when no data has moved for d.
type watch struct {
	cancel context.CancelCauseFunc
	t      *time.Timer
	d      time.Duration
	dl     *time.Timer // the total deadline of the transfer, when its size is known
}

// deadline bounds the whole transfer, however steadily it moves.
func (w *watch) deadline(d time.Duration) {
	if w.dl != nil {
		w.dl.Stop()
	}
	w.dl = time.AfterFunc(d, func() { w.cancel(ErrTooSlow) })
}

func newWatch(ctx context.Context, d time.Duration) (context.Context, *watch) {
	ctx, cancel := context.WithCancelCause(ctx)
	w := &watch{cancel: cancel, d: d}
	w.t = time.AfterFunc(d, func() { cancel(ErrStalled) })
	return ctx, w
}

func (w *watch) touch() { w.t.Reset(w.d) }
func (w *watch) stop() {
	w.t.Stop()
	if w.dl != nil {
		w.dl.Stop()
	}
	w.cancel(context.Canceled)
}

// touchBody keeps a body seekable and reports every read as progress.
type touchBody struct {
	io.ReadSeeker
	w *watch
}

func (b touchBody) Read(p []byte) (int, error) { b.w.touch(); return b.ReadSeeker.Read(p) }

// touchReadCloser reports reads as progress and stops the watch on Close.
type touchReadCloser struct {
	rc  io.ReadCloser
	w   *watch
	ctx context.Context
}

func (r *touchReadCloser) Read(p []byte) (int, error) {
	r.w.touch()
	n, err := r.rc.Read(p)
	if err != nil && err != io.EOF {
		if cause := context.Cause(r.ctx); errors.Is(cause, ErrStalled) || errors.Is(cause, ErrTooSlow) {
			err = cause
		}
	}
	return n, err
}
func (r *touchReadCloser) Close() error { r.w.stop(); return r.rc.Close() }

// wrap names an expired credential or a stall in the error of a call.
func (s *Store) wrap(ctx context.Context, err error) error {
	if err == nil || errors.Is(err, ErrStaticCredentials) || errors.Is(err, ErrCredentialsTooLong) || errors.Is(err, ports.ErrObjectExists) || errors.Is(err, ports.ErrObjectNotFound) {
		return err
	}
	if errors.Is(context.Cause(ctx), ErrStalled) {
		return fmt.Errorf("%w (%s)", ErrStalled, s.stall)
	}
	if errors.Is(context.Cause(ctx), ErrTooSlow) {
		return ErrTooSlow
	}
	switch codeOf(err) {
	case "ExpiredToken", "ExpiredTokenException", "TokenRefreshRequired", "RequestExpired":
		return fmt.Errorf("%w (%s)", ErrCredentialsExpired, codeOf(err))
	}
	if strings.Contains(strings.ToLower(err.Error()), "expired") && (strings.Contains(strings.ToLower(err.Error()), "token") || strings.Contains(strings.ToLower(err.Error()), "sso") || strings.Contains(strings.ToLower(err.Error()), "credential")) {
		return fmt.Errorf("%w (%v)", ErrCredentialsExpired, err)
	}
	return err
}

func statusOf(err error) int {
	var re *awshttp.ResponseError
	if errors.As(err, &re) {
		return re.HTTPStatusCode()
	}
	return 0
}

func codeOf(err error) string {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode()
	}
	return ""
}

// Put creates the object name with If-None-Match: *. See ports.ObjectWriter.
// On a 412 or 409 it compares the SHA-256 of the existing object with the
// body: equal is success, different is ports.ErrObjectExists. A body that is
// not an io.ReadSeeker is held in memory.
func (s *Store) Put(ctx context.Context, name string, r io.Reader, size int64) error {
	key, err := s.key(name)
	if err != nil {
		return err
	}
	body, ok := r.(io.ReadSeeker)
	if !ok {
		b, err := io.ReadAll(io.LimitReader(r, size+1))
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	if _, err := body.Seek(0, io.SeekStart); err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(body, size+1))
	if err != nil {
		return err
	}
	if n != size {
		return fmt.Errorf("the reader gave %d bytes where %d were declared", n, size)
	}
	sum := h.Sum(nil)
	if _, err := body.Seek(0, io.SeekStart); err != nil {
		return err
	}
	pctx, w := newWatch(ctx, s.stall)
	defer w.stop()
	w.deadline(s.limit(size))
	_, err = s.c.PutObject(pctx, &awss3.PutObjectInput{
		Bucket:         aws.String(s.bucket),
		Key:            aws.String(key),
		Body:           touchBody{body, w},
		ContentLength:  aws.Int64(size),
		IfNoneMatch:    aws.String("*"),
		ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(sum)),
	})
	if err == nil {
		return nil
	}
	if st := statusOf(err); st == http.StatusPreconditionFailed || st == http.StatusConflict {
		return s.wrap(ctx, s.sameAsExisting(ctx, name, size, sum))
	}
	return fmt.Errorf("put %s: %w", name, s.wrap(pctx, err))
}

func (s *Store) sameAsExisting(ctx context.Context, name string, size int64, sum []byte) error {
	rc, err := s.get(ctx, name, "")
	if err != nil {
		return fmt.Errorf("the object exists but cannot be read back to compare: %w", err)
	}
	defer rc.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(rc, size+1))
	if err != nil {
		return fmt.Errorf("the object exists but cannot be read back to compare: %w", err)
	}
	if n != size || !bytes.Equal(h.Sum(nil), sum) {
		return ports.ErrObjectExists
	}
	return nil
}

// Get opens the object name.
func (s *Store) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	return s.get(ctx, name, "")
}

// GetRange opens the object name from offset to its end (an HTTP Range
// request). An offset at or beyond the end is ports.ErrRangeNotSatisfiable.
func (s *Store) GetRange(ctx context.Context, name string, offset int64) (io.ReadCloser, error) {
	if offset < 0 {
		return nil, errors.New("negative offset")
	}
	return s.get(ctx, name, fmt.Sprintf("bytes=%d-", offset))
}

func (s *Store) get(ctx context.Context, name, rng string) (io.ReadCloser, error) {
	key, err := s.key(name)
	if err != nil {
		return nil, err
	}
	in := &awss3.GetObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)}
	if rng != "" {
		in.Range = aws.String(rng)
	}
	wctx, w := newWatch(ctx, s.stall)
	out, err := s.c.GetObject(wctx, in)
	if err != nil {
		cerr := s.wrap(wctx, err)
		w.stop()
		var nsk *types.NoSuchKey
		switch {
		case errors.As(err, &nsk) || codeOf(err) == "NoSuchKey":
			return nil, ports.ErrObjectNotFound
		case rng != "" && (statusOf(err) == http.StatusRequestedRangeNotSatisfiable || codeOf(err) == "InvalidRange"):
			return nil, ports.ErrRangeNotSatisfiable
		}
		return nil, fmt.Errorf("get %s: %w", name, cerr)
	}
	if out.ContentLength != nil {
		w.deadline(s.limit(*out.ContentLength))
	}
	return &touchReadCloser{rc: out.Body, w: w, ctx: wctx}, nil
}

// Has reports whether the object name exists.
func (s *Store) Has(ctx context.Context, name string) (bool, error) {
	key, err := s.key(name)
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*s.stall)
	defer cancel()
	_, err = s.c.HeadObject(ctx, &awss3.HeadObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
	if err == nil {
		return true, nil
	}
	var nf *types.NotFound
	if errors.As(err, &nf) || statusOf(err) == http.StatusNotFound {
		return false, nil
	}
	return false, fmt.Errorf("head %s: %w", name, s.wrap(ctx, err))
}

// List returns the objects whose names start with prefix, in key order.
func (s *Store) List(ctx context.Context, prefix string) ([]ports.ObjectInfo, error) {
	if t := strings.TrimSuffix(prefix, "/"); t != "" {
		if err := ports.ValidObjectName(t); err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*s.stall)
	defer cancel()
	var out []ports.ObjectInfo
	p := awss3.NewListObjectsV2Paginator(s.c, &awss3.ListObjectsV2Input{Bucket: aws.String(s.bucket), Prefix: aws.String(s.prefix + prefix)})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", prefix, s.wrap(ctx, err))
		}
		for _, o := range page.Contents {
			if o.Key == nil || !strings.HasPrefix(*o.Key, s.prefix) {
				continue
			}
			out = append(out, ports.ObjectInfo{Name: strings.TrimPrefix(*o.Key, s.prefix), Size: aws.ToInt64(o.Size)})
		}
	}
	return out, nil
}

// Check reports what the bucket and the credentials are. Credentials that are
// not short-lived are reported as such without any request to the bucket.
func (s *Store) Check(ctx context.Context) (ports.SinkProperties, error) {
	props := ports.SinkProperties{Kind: ports.SinkS3}
	ctx, cancel := context.WithTimeout(ctx, 4*s.stall)
	defer cancel()
	if _, err := s.creds.Retrieve(ctx); err != nil {
		if errors.Is(err, ErrStaticCredentials) || errors.Is(err, ErrCredentialsTooLong) {
			return props, nil
		}
		return props, fmt.Errorf("cannot get AWS credentials: %w", s.wrap(ctx, err))
	}
	props.ShortLivedCredentials = true
	v, err := s.c.GetBucketVersioning(ctx, &awss3.GetBucketVersioningInput{Bucket: aws.String(s.bucket)})
	if err != nil {
		return props, fmt.Errorf("cannot read the bucket's versioning: %w", s.wrap(ctx, err))
	}
	props.Versioning = v.Status == types.BucketVersioningStatusEnabled
	l, err := s.c.GetObjectLockConfiguration(ctx, &awss3.GetObjectLockConfigurationInput{Bucket: aws.String(s.bucket)})
	if err != nil {
		if codeOf(err) == "ObjectLockConfigurationNotFoundError" {
			return props, nil // Object Lock is not enabled
		}
		return props, fmt.Errorf("cannot read the bucket's Object Lock configuration: %w", s.wrap(ctx, err))
	}
	if lc := l.ObjectLockConfiguration; lc != nil && lc.ObjectLockEnabled == types.ObjectLockEnabledEnabled && lc.Rule != nil && lc.Rule.DefaultRetention != nil {
		d := lc.Rule.DefaultRetention
		props.ObjectLockMode = string(d.Mode)
		props.ObjectLockDefaultRetention = aws.ToInt32(d.Days) > 0 || aws.ToInt32(d.Years) > 0
	}
	return props, nil
}
