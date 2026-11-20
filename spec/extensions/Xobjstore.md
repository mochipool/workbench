+++
id = "Xobjstore"
kind = "extension"
title = "The narrow S3 client of the relay's object store, and its in-process stand-in"
status = "draft"
contexts = ["pool-operations"]
use_cases = []
depends_on = ["Xmailbox"]
+++

# Xobjstore: the narrow S3 client and the S3 stand-in

This spec is not upstream behaviour. It specifies work packages 2 and 3 of [ADR 0015](../../docs/explanation/adr/0015-stateless-relay.md): an S3 client that the relay binary may link (`spo/internal/adapters/objstore/s3client`), the Signature Version 4 it shares with the unlock backends (`spo/internal/platform/sigv4`), and an in-process S3 stand-in for tests (`spo/test/s3stand`), honest and hostile. The lease, the mailbox adapter and the registry adapter that use the client are later packages. No real object store was contacted to write or test it.

Terms: a **conditional put** carries `If-None-Match: *` (create only) or `If-Match: <ETag>` (overwrite of exactly that ETag). A **typed outcome** is an error that `errors.Is` matches against one sentinel per status. The **stand-in** is the test server; its **honest mode** is what S3 is documented to do, its **hostile modes** are faults switched on per test.

## Interface

- **SPO-Xobjstore-IF-001** `Client.Put` makes only conditional puts: exactly one of `IfNoneMatch` and `IfMatch` is set, otherwise `ErrUnconditional` before any request. There is no unconditional put, because both buckets' policies deny one (ADR 0015 decision 3) and every write of decisions 2 and 5 is conditional. A key is 1 to 1024 bytes of letters, digits, `.`, `_`, `-` and `/` with no empty, `.` or `..` segment (`ErrInvalidKey`); the body is held whole, at most 4 MiB.
- **SPO-Xobjstore-IF-002** A refused request is a `*StatusError` with the operation, the key, the status, the S3 error code, the number of attempts and the delete-marker flag. `errors.Is` matches 412 to `ErrPreconditionFailed`, 409 to `ErrConflict`, 404 to `ErrNotFound`, 403 `RequestTimeTooSkewed` to `ErrClockSkew`, any other 403 to `ErrAccessDenied` (a policy deny or a delete that retention refuses), 400 `BadDigest` and its kin to `ErrBadDigest`, a 3xx to `ErrRedirect`, and every refusal to `ErrStatus`; no status matches another's sentinel.
- **SPO-Xobjstore-IF-003** `SameAsCurrent(key, body)` reads the current version back, bounded by the length of `body`, and reports whether its bytes are `body`: equal bytes after a precondition failure mean the writer's own earlier attempt landed. A `StatusError` carries `Uncertain` when an earlier attempt of the same write had no answer, so the caller knows a read-back is needed before applying the exit rule.
- **SPO-Xobjstore-IF-004** `Get` reads an object (or one version) whole, with a bound of 1 byte to 16 MiB that the caller states; `Head` reports size, ETag, version id, retention mode and date; `Delete` removes by name (in a versioned bucket it adds a delete marker and reports it); `DeleteVersion` removes one version by id. Deletes are idempotent.
- **SPO-Xobjstore-IF-005** `List` reads one ListObjectsV2 page under a prefix with keys, sizes, ETags and the continuation token; `ListAll` reads every page within a stated bound on the number of objects (`ErrListLimit` above it).
- **SPO-Xobjstore-IF-006** `ListVersions` reads one ListObjectVersions page with object versions and delete markers told apart (`DeleteMarker`), with their version ids, newest first per key, and the key and version-id markers; `ListAllVersions` reads every page within a stated bound.
- **SPO-Xobjstore-IF-007** A put may carry an Object Lock retention (`COMPLIANCE` or `GOVERNANCE`, a retain-until date in whole seconds) and a SHA-256 checksum (`x-amz-checksum-sha256` with `x-amz-sdk-checksum-algorithm: SHA256`); a retention always carries the checksum. A put whose answer echoes another checksum, and a get whose reported checksum is not that of the bytes, fail with `ErrChecksumMismatch`.
- **SPO-Xobjstore-IF-008** `Versioning` and `ObjectLockEnabled` read the bucket's state (a missing Object Lock configuration is "not enabled"). `SelfTest` runs the start-up checks of ADR 0015 decision 2 one request at a time: in every bucket, a create over an existing object is 412, an overwrite with a wrong `If-Match` is 412, two writes of different bytes give different ETags, a written object is read back and listed at once, and the working bucket's test object is deleted; in the registry bucket also versioning on, Object Lock enabled, a one-day retention read back with its mode and date, a delete of that version by id refused, and the version listed. Every registry test object carries the retention and is left for the sweep.
- **SPO-Xobjstore-IF-009** Credentials come from a `Provider` the caller supplies (`Retrieve(ctx) (Credentials, error)`): an access key id, a secret, a session token and an expiry. `StaticProvider` returns one fixed set and is for tests. Web identity is a later package.
- **SPO-Xobjstore-IF-010** Signature Version 4 is `platform/sigv4.Sign`, which takes the secret through a lending function and imports no secret buffer type. The unlock backends (`adapters/vaultkms`) lend it their guarded buffer; the S3 client lends a copy it wipes. The published vectors (get-vanilla, IAM ListUsers, the signing-key derivation, and the S3 GET Object and ListObjects examples) hold for it.

## Modes

- **SPO-Xobjstore-MODE-001** Path-style addressing puts the bucket in the path (`https://host/bucket/key`); virtual-host addressing puts it in the first label of the host (`https://bucket.host/key`), and a bucket name with a dot needs path style over TLS. Both are signed with the host they are sent to.

## Outputs

- **SPO-Xobjstore-OUT-001** A store that fails the self-test is refused with a `*SelfTestError` whose `Property` is the property's sentence and whose message names it.

## Preconditions and failures

- **SPO-Xobjstore-PRE-001** Every request needs a context deadline (`ErrNoDeadline` otherwise). Retries are made only for requests that are idempotent (get, head, delete, listings, bucket reads) or conditional (every put), only after a transport failure or a 500, 502, 503, 504 or 429, at most `MaxAttempts` (3 by default) with a doubling wait, and never when the wait would leave less than the wait again before the deadline. A 4xx and a 3xx are never retried.
- **SPO-Xobjstore-PRE-002** A write that got no answer (a lost response, a reset, the deadline) fails with `ErrOutcomeUnknown` joined to its cause, so the caller reads it back; a read that got no answer does not.

## Security

- **SPO-Xobjstore-SEC-001** Only short-lived credentials are used: a set without a session token or an expiry is `ErrStaticCredentials`, one past its expiry `ErrCredentialsExpired`, one that expires more than 12 hours ahead `ErrCredentialsTooLong`, all before any request. A set is cached until five minutes before its expiry. No credential appears in an error, and the `Credentials` type prints as redacted under every verb.
- **SPO-Xobjstore-SEC-002** The endpoint must be `https`; plain `http` is accepted only to a loopback IP literal with the explicit test opt-in. TLS 1.2 is the minimum, no proxy is used, and no redirect is followed, so no credential goes to another host.
- **SPO-Xobjstore-SEC-003** Every response is read within a stated bound: a success body within the request's bound (a get's, 4 MiB for a listing page by default, 8 KiB for an error document), checked against `Content-Length` before any byte is read and against the bytes read after; a body shorter than its length is `ErrTruncated`; the header block is at most 32 KiB; transparent decompression is off. Header values that are used (ETag, version id, retention, checksum) are checked before use.
- **SPO-Xobjstore-SEC-004** XML is decoded strictly, token by token, with no entity map (only the predefined entities and character references decode, nothing expands), no charset reader, no document type or other directive, no processing instruction other than the declaration, one root of the expected name, nesting at most 6, element text at most 2048 bytes, and at most 16 elements per entry asked for. Sizes are decimal without a sign or a leading zero; a delete marker has no size; an entry lacks no required field and repeats none.
- **SPO-Xobjstore-SEC-005** A listing is checked: every key is in the alphabet and under the prefix, keys strictly increase within and across pages (versions: keys do not go back and no key and version id repeats), no page has more entries than asked, a truncated page has a continuation and at least one entry, and the continuation advances. A listing that fails is `ErrBadListing`.

## Invariants

- **SPO-Xobjstore-INV-001** The client and `platform/sigv4` link nothing the relay binary may not (SPO-Xmailbox-SEC-078: no `internal/ports`, no `platform/secret`, no AWS SDK) and nothing relay-banned (SPO-Xmailbox-SEC-009). The key agreement, key derivation and AEAD packages are reached only below the standard library's TLS stack (`crypto/tls`, `crypto/x509`), the store connection's transport, as the tunnel's are below the tunnel adapter. Their direct imports are exact allow-lists.
- **SPO-Xobjstore-INV-002** The stand-in is never in a release binary: `cmd/spo` and `cmd/spo-relay` do not contain it, and only `_test.go` files and packages under `spo/test/` import it.
- **SPO-Xobjstore-INV-003** The stand-in's honest mode does what S3 is documented to do for what ADR 0015 relies on: strong read-after-write and listing; 412 for `If-None-Match: *` over a live object and for `If-Match` with another ETag; 404 for `If-Match` on a missing object or a current delete marker; versioned buckets (a put adds a version, a simple delete adds a marker, a delete by version id removes that version) and unversioned ones; Object Lock in compliance and governance mode (a delete by version id refused until the date, governance bypass only with the right and the header, a simple delete still adds a marker); the bucket-policy denies of a simple delete on the tombstones and the marker and of a put without a condition, and a principal limited to its prefix; ETag = MD5 of the body; SHA-256 checksum refusal; Signature Version 4 verified by a second implementation that shares no code with `platform/sigv4`, with a 15-minute skew limit; paged listings and version listings. Each property states its source (documentation or memory) where it is implemented.
- **SPO-Xobjstore-INV-004** The stand-in's hostile modes, each switchable per test by operation, key prefix and count: a lost response after a commit, a write applied after the client's deadline or twice, 412, 404, 409 or any status at will, a stale listing, a listing that omits or repeats keys, truncated, falsely sized and oversized bodies, hostile XML, a wrong ETag, a damaged body accepted with the client's checksum, a body damaged on the way, a stall before the headers or in the body, a slow body, a redirect, a clock that disagrees; and, as a foreign principal or the store's operator, a delete marker over a locked version, a lower version on top, an older version restored as current and a rollback (refused for a compliance-locked version). A recorder keeps every request with its conditions, retention and checksum headers, principal and status, and lists the unconditional puts.

## Not covered

- Web identity (IRSA, Workload Identity) credentials, the lease, the mailbox and registry adapters, the version ceiling and the 60-second tombstone re-read: later work packages of ADR 0015.
- The backup sink (`adapters/objstore/s3`) still uses the AWS SDK; moving it onto this client is deferred.
- That a real store behaves as the stand-in's honest mode says; ADR 0015, "What only real infrastructure can show".
