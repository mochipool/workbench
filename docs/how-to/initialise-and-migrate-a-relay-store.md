# Initialise, verify, repair and migrate a relay store

This page sets up the object store of one relay identity and keeps it healthy. The store is two buckets, as [ADR 0015](../explanation/adr/0015-stateless-relay.md) decision 3 describes: a **registry bucket** (versioned, with Object Lock) for the marker, the bindings and the revocation tombstones, and a **working bucket** (never versioned) for the marker, the lease, the rate object and the mailbox. Each identity uses the prefix `relays/<node key>/` in both.

The commands are part of `spo-relay`. They read the relay's configuration (its `[store]` table and its key file) with `--config`. They use the relay's own role. They never print a credential or the content of an envelope.

> **Not run against a real store.** The commands are tested against an in-process S3 stand-in only. Check the bucket settings below on your store by hand.

## Before you start

Create both buckets and apply the settings in "The bucket settings" below. Use one role per relay identity, limited to its prefix. Write the `[store]` table into the relay's configuration (see [Run a relay](./run-a-relay.md)).

Stop every relay of the identity before you repair or migrate. The tools take the identity's lease. A relay that holds and renews the lease is never pushed aside: the tool waits about 75 seconds, then refuses.

## Initialise a new relay

Run this once, for a new relay identity only:

```sh
spo-relay init-store --config /etc/spo-relay/relay.toml
```

It does this, in order:

1. It reads both buckets. It refuses a store that holds state without a marker (an emptied or rolled-back store), a marker of another identity, a lease object it cannot read, or a migration record (see "Migrate a directory relay"). It writes nothing then.
2. It runs the self-test of both buckets, with the retention part. One test object stays in the registry bucket, `selftest/<16 hex>-r`, locked for one day. The relay's sweep deletes it once the lock has ended.
3. It checks that the registry bucket has no default retention.
4. It writes the lease record (released), then both markers (the registry marker locked for one year) and full rate buckets.

It prints what it wrote and what the store holds. Running it again on an initialised store writes nothing new and skips the retention part of the self-test, so it leaves no new locked object; the report says so. If it stops part way, run it again.

`spo-relay serve` never initialises a store. It refuses one that was never initialised.

## Verify a store

```sh
spo-relay store verify --config /etc/spo-relay/relay.toml
spo-relay store verify --config /etc/spo-relay/relay.toml --probe
```

Without `--probe` it only reads. With `--probe` it also runs the checks that write and then remove what they wrote: the self-tests (one more object stays locked for a day), the default-retention probe, and simple deletes of names under `selftest/` that the policy's patterns cover.

Each check ends with a verdict:

* **ok**: the property holds.
* **warning**: the relay still starts and enforces everything (for example, delete markers over a tombstone).
* **FAILURE**: the relay refuses to start, or a protection the design depends on is missing. The command exits 1.
* **not verifiable**: the relay's role cannot see it. Compare the policy by hand with the statements the report prints.

The relay's role cannot see the governance-bypass deny, the 182-day and 366-day retention denies, the legal-hold deny, the TLS and conditional-put denies, or the lifecycle rule. `--operator` says so: the store client has no call to read a bucket policy, a lifecycle, an encryption setting or a default retention rule.

Some checks fail although the relay would still start, because they show that someone with write rights changed the store:

* a tombstone version locked for less than the tombstone's life. The relay's role can write such a version. Whoever wrote it can delete it by its id once the short lock ends, and the revocation goes with it. The relay's next revoke of that scope, and `migrate-store`, write their own version locked for the full life;
* a delete marker, or a version that is not this identity's marker, newer than the identity's marker;
* a migration record left in the working bucket.

## Look at one prefix

```sh
spo-relay store inspect --config FILE --bucket registry --path registry/tombstones/ --versions --locks
spo-relay store inspect --config FILE --bucket working --path mailbox/ --limit 50
```

It prints one page, at most 1000 entries. Names are decoded: a tombstone's scope, wallet key and device; a mailbox entry's recipient, arrival, id and sender. It prints sizes, version ids and lock ends. It never prints a body. To see the next page, pass the `--after` value it prints.

## Repair a store

Name each repair. None runs unless named:

| Action | What it does |
| --- | --- |
| `delete-markers` | Deletes the delete markers over tombstones and over the marker, by version id. |
| `lease` | Overwrites a lease object that cannot be read, or that names another relay, with a released record. It first watches the object unchanged for 55 seconds. It never deletes the lease. |
| `mailbox-duplicates` | Deletes later copies of one sender's message, which the relay would not serve. |
| `mailbox-over-bound` | Deletes objects past the 256 entries of a mailbox. |
| `mailbox-unparsable` | Deletes objects under `mailbox/` whose name or size is not an entry's. The relay refuses to start while they are there. |
| `selftest` | Deletes the self-test's objects whose lock has ended, at most 1000 a run. |
| `migration-record` | Deletes the migration record a completed migration left. It does so only when both markers and the lease record are there. |

```sh
spo-relay store repair --config FILE --action delete-markers --action selftest --dry-run
spo-relay store repair --config FILE --action delete-markers --action selftest
```

It first lists every step, at most 10 000 a run; if there are more it says to run it again. `--dry-run` stops there. Otherwise it asks on the terminal before it writes; `--yes` skips the question. It then makes only the steps it listed. It takes the lease and scans the store again under the lease, and it skips a listed step that the new scan no longer finds in the same class (for example a duplicate whose earlier copy is gone, so the relay would now serve it). A step that only the new scan finds is not made; run repair again to see it. Repair never deletes a locked version, never writes a tombstone, and never deletes a binding, a tombstone or a marker version.

## Migrate a directory relay

Stop the relay. Then:

```sh
spo-relay migrate-store --config /etc/spo-relay/relay.toml \
  --from-mailbox /var/lib/spo-relay/mailbox --from-registry /var/lib/spo-relay/registry
```

Use the relay's old `mailbox_dir` and `registry_dir`. The configuration is the new one, with `[store]`. The key must be the same key, so that devices keep their pin.

Run `spo-relay store verify --probe` on the new buckets first. Into a new identity the migration also runs the self-test of both buckets (with the retention part) and the default-retention probe before its first write, and stops if either fails.

It takes the directory stores' own locks, so it refuses while the old relay runs. It never changes the directories. It writes in this order:

1. into a new identity, a migration record, `migration` in the working bucket;
2. every tombstone, each as a version locked for the tombstone's full life, then a read back that checks every one is there and locked so. A version already in the store counts only if it is locked for its full life. If the store holds a higher value under a shorter lock, the migration writes that higher value with a full lock;
3. the bindings (one below a tombstone, or expired, is skipped and listed);
4. the mailbox entries, in the same order, with the same bytes;
5. an empty rate object;
6. the markers and the lease, then it deletes the migration record.

If it stops part way, the relay refuses the store until the markers are written. Run the command again: it skips what is already there. If something could not be carried, it says what and exits 1, and it writes no marker. `--no-mailbox` leaves the queues behind; senders put pending mail again.

The migration record does not prove anything on its own: anyone who can write the working bucket can create one. A second run accepts a store without markers only when it looks like an interrupted migration: no lease object, no working marker, and either no registry marker or the identity's registry marker locked until a future date. A store with a working marker or a lease object but no registry marker is refused as emptied, record or not. A store with a lease object but without both markers is what an interrupted `init-store` leaves: run `init-store` again first, then migrate into the initialised identity.

If the migration cannot delete its record at the end, it exits 1 and says so. The store is complete and the relay may start. Delete the record with `spo-relay store repair --action migration-record`.

Keep the directories until the relay has run on the object store for a while.

## The bucket settings

`spo-relay store verify` prints these statements too, with the identity's node key filled in. Replace `REGISTRY`, `WORKING`, `ROLE_ARN` and `NODEKEY`.

```text
Registry bucket (versioning Enabled; Object Lock enabled with NO default retention rule):
  {"Sid": "DenySimpleDeleteOfTombstonesAndMarker", "Effect": "Deny", "Principal": "*",
   "Action": "s3:DeleteObject",
   "Resource": ["arn:aws:s3:::REGISTRY/relays/*/registry/tombstones/*", "arn:aws:s3:::REGISTRY/relays/*/marker"]}
  {"Sid": "DenyGovernanceBypass", "Effect": "Deny", "Principal": "*",
   "Action": "s3:BypassGovernanceRetention", "Resource": "arn:aws:s3:::REGISTRY/*"}
  {"Sid": "DenyLongTombstoneLocks", "Effect": "Deny", "Principal": {"AWS": "ROLE_ARN"},
   "Action": "s3:PutObjectRetention", "Resource": "arn:aws:s3:::REGISTRY/relays/*/registry/tombstones/*",
   "Condition": {"NumericGreaterThan": {"s3:object-lock-remaining-retention-days": "182"}}}
  {"Sid": "DenyLongMarkerLocks", "Effect": "Deny", "Principal": {"AWS": "ROLE_ARN"},
   "Action": "s3:PutObjectRetention", "Resource": "arn:aws:s3:::REGISTRY/relays/*/marker",
   "Condition": {"NumericGreaterThan": {"s3:object-lock-remaining-retention-days": "366"}}}
  {"Sid": "DenyLegalHold", "Effect": "Deny", "Principal": {"AWS": "ROLE_ARN"},
   "Action": "s3:PutObjectLegalHold", "Resource": "arn:aws:s3:::REGISTRY/*"}
  {"Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
   "Resource": ["arn:aws:s3:::REGISTRY", "arn:aws:s3:::REGISTRY/*"],
   "Condition": {"Bool": {"aws:SecureTransport": "false"}}}
  {"Sid": "DenyUnconditionalPut", "Effect": "Deny", "Principal": "*", "Action": "s3:PutObject",
   "Resource": "arn:aws:s3:::REGISTRY/*",
   "Condition": {"Null": {"s3:if-none-match": "true", "s3:if-match": "true"}}}
Registry bucket lifecycle (one rule per identity; no rule touches registry/tombstones/ or marker):
  {"ID": "spo-relay-NODEKEY-bindings", "Status": "Enabled",
   "Filter": {"Prefix": "relays/NODEKEY/registry/bindings/"},
   "NoncurrentVersionExpiration": {"NoncurrentDays": 1},
   "Expiration": {"ExpiredObjectDeleteMarker": true}}
Working bucket (versioning never enabled; no lifecycle rule needed):
  {"Sid": "DenyLeaseDelete", "Effect": "Deny", "Principal": "*",
   "Action": "s3:DeleteObject", "Resource": "arn:aws:s3:::WORKING/relays/*/lease"}
  {"Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
   "Resource": ["arn:aws:s3:::WORKING", "arn:aws:s3:::WORKING/*"],
   "Condition": {"Bool": {"aws:SecureTransport": "false"}}}
  {"Sid": "DenyUnconditionalPut", "Effect": "Deny", "Principal": "*", "Action": "s3:PutObject",
   "Resource": "arn:aws:s3:::WORKING/*",
   "Condition": {"Null": {"s3:if-none-match": "true", "s3:if-match": "true"}}}
```

The role's own rights are in ADR 0015 decision 3, "Bucket policy". In a policy, `*` in a resource matches `/` too, so `relays/*/marker` covers every identity's marker.

> **None of these statements was checked against AWS.** They are written from memory and tested only against the in-process stand-in. Test each one on your store before you rely on it. In particular, these are not checked:
>
> * whether `s3:object-lock-remaining-retention-days` is evaluated for a `PutObject` that carries lock headers. The statements above deny long locks on `s3:PutObjectRetention` only, so a put may set any date;
> * the exact condition keys of the conditional-put deny (`s3:if-none-match`, `s3:if-match` in a `Null` condition);
> * that a lifecycle filter cannot hold a wildcard (hence one rule per identity);
> * that `*` in a resource matches `/`.
>
> The tools assume the worst of the first point: the relay's role can write a tombstone version with a short lock. `store verify` fails such a version, and `migrate-store` and the relay's revoke never count one as stored.

## Exit statuses

0 success; 1 a refusal, a failed check, a failed repair step, an incomplete migration or a declined question; 2 a usage error.
