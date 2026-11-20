# ADR 0015: A relay whose pods hold no state

Status: accepted by the owner, 2026-11-19, as revised after the adversarial review of the same day ("Changes after the review" below). The owner decided the store, the sharing of storage, the key source, the shared tombstone set, option C, the Object Lock mode and the reading of the relay key ("Decided by the owner" below). No question is open. Nothing here is built except what work package 1 is building now. It amends [ADR 0013](./0013-tailnet-relay-and-mailbox.md) (the relay and its mailbox store) and [ADR 0014](./0014-wallet-key-identity-for-the-relay.md) (the durable registry, decision 7) in where their state is stored; the protocol, the session rules and the bounds are unchanged. It builds on [ADR 0012](./0012-server-backup-and-deployment.md) (decisions 4 and 9: an object store with short-lived federated credentials; stage 6, Kubernetes) and [ADR 0008](./0008-capability-typed-ports.md) (narrow ports). It replaces the shape of the first Kubernetes deployment in `deploy/kubernetes/relay/` (uncommitted) and in [Run a relay on Kubernetes](../../how-to/run-a-relay-on-kubernetes.md).

Each outside fact is marked: **(source)** read in this repository or in the Go module cache (`tailscale/tailcat@v0.7.0`, `tailscale.com@v1.103.0-pre…`, the versions in `spo/go.mod`); **(doc)** public documentation, with its address; **(review)** stated by the review and not checked again here; **(memory)** none of these, to be checked. "Not confirmed" facts are listed again at the end.

## Changes after the review, 2026-11-19

What moved after the adversarial review (blockers B, major findings M, minor findings m). Each is marked "*Changed after the review (id).*" where it is decided.

* **B1, delete markers (decisions 2, 3, 10).** A simple DELETE in a versioned bucket adds a delete marker that hides a locked version from a plain listing. The bucket policy denies simple `s3:DeleteObject` on the tombstones and the marker; the sweep deletes by version id; tombstones and the marker are loaded from a version listing that ignores delete markers.
* **B2, the lease body (decision 5).** The lease carries a renewal counter, so every renewal changes the bytes; "unchanged" means the same ETag and the same counter.
* **M1, the lease does not fence (decision 5).** Every store request has a deadline at the holder's lease end and no retry past it; the taker waits a drain period; the tombstone prefix is re-listed every 60 s; each stale-write case is stated with what closes it.
* **M2, the exit rule (decisions 2, 5).** 404 and 409 on a conditional write end the writer as 412 does; the cost of a spurious exit and its metric are stated.
* **M3, tombstone names (decisions 2, 3; the registry core).** One name per scope, as the directory store has it; a raise is an `If-Match` overwrite that makes a new locked version; the load takes the highest not-before across versions; a delete that retention refuses never fails a revoke.
* **M4, the region pin (decision 7, work package 1).** A region id does not give a stable address. The object-store mode requires a full `[derp_region]` and compares the encoded region.
* **M5, versioning and the mailbox (decision 3).** The mailbox, the lease and the rate state move to a second, unversioned bucket of the same operator.
* **M6, what "S3-compatible" means (decision 2).** A short allow-list of products with what was verified for each; the limits of the start-up self-test; the permissions the checks need.
* **M7, the rollout (decision 13).** Kubernetes does not promise to replace a standby first. Accepted: the active pod may go first.
* **M8, work packages (decision 12).** Added: migration from a directory store, a store tool, metrics, a request-cost guard and the registry core changes.
* **Minor findings (m1 to m8).** The put path holds the body and the port text is amended (m1); the crash gap between a revoke and the mailbox removal is recorded (m2); the rate object is written with `If-Match` (m3); the fail-over figures are worst cases, not "about a minute" (m4); the margin between the old tunnel and the taker (m5); what a partial rollback can still do (m6); the warm standby is optional and measured first (m7); the reading of "the server can decrypt nothing" is an open question (m8).

## Changes after the review of the store client, 2026-11-19

Found while the client of work package 2 was reviewed and fixed (spec [Xobjstore](../../../spec/extensions/Xobjstore.md)). They amend decisions 2 and 3.

* **The working bucket's role also needs `s3:GetBucketVersioning`.** The start-up self-test refuses a working bucket whose versioning was ever enabled, because an acknowledged envelope must be removed, not kept as a noncurrent version (SPO-Xobjstore-PRE-005).
* **The retention part of the self-test does not run at every start.** It leaves a locked object behind, so a crash loop would fill the registry bucket with objects nobody can delete. It runs at `init-store` and `store verify`; the start-up run checks the rest and removes what it wrote.
* **The registry bucket has no default retention.** With one, the start-up self-test could not remove its own objects and fails. Retention is set per object, by the relay, on tombstones and the marker only.
* **A write whose outcome is unknown is read back, and a read-back that does not show it is a conflict, not an absence.** The store may still apply a request for as long as its signature is valid (15 minutes). The writer then exits by the rule of decision 5; it never writes other content in its place.

## Changes after the review of work package 8, 2026-11-20

Found by the security review of the registry adapter (`adapters/objregistry`; spec [Xobjstore](../../../spec/extensions/Xobjstore.md), IF-804 to PRE-810). They amend decisions 2, 3 and 10; each place is marked "*Changed after the review of work package 8.*"

* **Superseded tombstone versions are deleted (decision 3, "A ceiling on versions").** The earlier arithmetic assumed versions go away; nothing deleted a version of a live name, so one name raised once a minute passed the ceiling in about a year and the relay could not start again. `Sweep` now deletes, by version id, every version but a name's highest and its current once its lock has ended, and the core budgets the raises of one name that invalidate nothing (4 in 24 hours). The worst case from the caps is 667 660 versions.
* **The marker keeps at most two versions (decision 2).** A new locked version every 30 days with none deleted reached the bound of 64 in about five years. The marker is renewed when 30 days of its lock are left and the older versions are deleted when their lock ends; delete markers are bounded apart.
* **No lock longer than a verified revoke needs (decision 10).** The relay refuses to write one. The bucket policy adds two denies for the role, checked by `store verify`. A holder of the role can still write locked versions; what that costs is stated in decision 10.
* **A version the relay cannot read costs its scope, not the start (decision 3).** It is enforced at the strictest reading; an object that is not a tombstone is ignored. A listed version that answers 404 is never skipped.
* **A listing that hides a whole name is caught for the bindings it matters to (decision 3).** The three names of every stored binding and of every fresh registration are read directly when the listing did not show them.
* **The refresh and the load are bounded (decision 3).** A refresh reads at most 8 listing pages and resumes; a load reads 32 versions at once, under the lease.
* **Smaller fixes.** A conflict on the rate object is adopted, not the end of the writer; equal bytes read back count only when locked; a registration waits while a delete of its device is unconfirmed; a tombstone write that met a conflict is enforced before the writer ends and is not reported recorded.

## Changes after the review of the object-store lease, 2026-11-20

The review of work package 6 found no break of the rule that two processes never both hold the lease within its stated assumptions, but these. They amend decisions 3 and 5 (spec [Xobjstore](../../../spec/extensions/Xobjstore.md), "The object-store lease"; [Xmailbox](../../../spec/extensions/Xmailbox.md) IF-031, IF-034, INV-045).

* **H1, a deleted lease object.** An absent object was taken at once, so a deletion under a live holder gave two holders until the holder's next renewal. Now an absent object is lapsed (the full wait and the drain); `init-store` writes a released record (`objlease.Init`) so a start never meets absence on a healthy store; the refusal of an unreadable object says to overwrite it with a released record with the store tool, never to remove it; the working bucket's policy denies `s3:DeleteObject` on `relays/*/lease` (decision 3), and `store verify` checks it.
* **M1, the drain.** A take answered after 6 s was lost at the end of the drain, and a failed renewal after it left the relay's renewal period sized from the time left. Now the taker renews during the drain every quarter of the term, the configuration requires a request timeout of at most half the term, and the relay reads the term from the lease (`relayport.LeaseTerm`).
* **M2, the clock-rate bound.** The tolerated ratio of two clock rates is (D+M)/(D−M); a margin of 0 was accepted. The margin is now at least a third of the duration, in the configuration and in a record (ratio at least 2).
* **M3, the retries.** One slow renewal and one refusal ended the relay. Renewals are now scheduled from the sending of the one before and retried until the lease end less the guard less a minimum request time (500 ms), each deadline shrunk to fit.
* **M4, a failed start.** It released the lease without the rule of a planned stop. It now lets the lease lapse when a store's open failed, a call went unanswered, an operation is unconfirmed or the statistics cannot be read. A rate save of unknown outcome at a planned stop was already counted unanswered; a test now shows it.
* **L1 to L5.** A holder whose two clocks stopped, and bytes already handed to the kernel, are listed under "The lease does not fence"; a renewal of unknown outcome whose read-back shows the holder's previous record is sent again with the same bytes; a lease clock without a monotonic reading needs an explicit wall clock; the relay's declared loss reaches the lease (`relayport.LeaseLoser`); a record's duration is honoured up to 5 minutes, and a longer one is logged when it exceeds the waiter's own.

## Changes after the review of the object-store mailbox, 2026-11-20

The review of work package 7 found that about 150 ms of `SlowDown` answers on one put ended the writer, and that keys could be used twice. They amend decision 5, "The exit rule", for mailbox puts only (spec [Xobjstore](../../../spec/extensions/Xobjstore.md) OUT-702, OUT-704, OUT-706, OUT-707, INV-702).

* **A put that is not confirmed is held, not a loss of authority.** A mailbox entry's key names its sender and the hash of its bytes and is used by one put only, so "nothing under the key" after a 5xx says nothing about another writer. The put sends the identical create-only PUT again (same key, same bytes, at most 6, within one request timeout); a later conflict that reads back as its bytes is success. When it stays unconfirmed, its key is held: counted in every quota and in the arrival mark, listed nowhere, deleted by every sweep and freed only by a deletion confirmed 30 minutes after its last PUT (the 15 minutes of a signature plus a store clock at most 15 minutes behind). The caller is told `ErrOutcomeUnknown`, which the relay counts as unanswered, so a planned stop lets the lease lapse. At most 32 held keys a mailbox and 256 in all; at a bound a put is answered `busy`. Other bytes under the key, and the lease's own end, still end the writer. The exit rule for every other conditional write is unchanged.
* **Keys carry a nonce.** Each put draws 64 random bits for its key, so a DELETE or a PUT the store applies late reaches only its own object, also after a restart; the arrival of a mailbox never goes back, after an ack or with a clock stepped back.
* **A late write past a mailbox bound does not stop the start.** Entries past the 256 of a mailbox are doomed at load; the count of mailboxes is no longer a reason to refuse it; only the bounds of what the index allocates (512 objects a mailbox, 524 288 in all) are.
* **Close drains.** The mailbox's `Close` returns once its requests in flight have ended, and nothing is sent after it or after a known loss; the host calls it before it releases the lease.

## Context

The first Kubernetes deployment of `spo-relay` is one StatefulSet per relay with one replica, a PersistentVolumeClaim that holds the mailbox directory and the binding registry directory, and the relay key copied from a Secret by an init container (`deploy/kubernetes/relay/base/instance/statefulset.yaml`). The pod holds state: lose the claim and the queues and the revoke tombstones are gone.

**Owner direction, 2026-11-19.** "Kubernetes should be stateless, ideally. If we design correctly, CQRS, hexagonal architecture, etc. then this should be possible." On several pods: "Research for 3 and come up with the most feasible solution."

**Earlier binding requirements.** The server has no way to decrypt anything by itself. No insecure mechanism. Standard, well-adopted processes. "Anyone can run the relay, and in-fact there can be multiple relays (re: kubernetes HA)." The application works as a full Kubernetes deployment and as a simple local deployment. No static cloud keys: short-lived federated credentials such as IRSA or Workload Identity (ADR 0012 decision 4).

**What makes this possible.** The relay is already hexagonal. `app/relayhost.Start` takes the stores as functions (`Deps.OpenMailbox`, `Deps.OpenRegistry`), and the session (`app/relay`) sees only the narrow ports of `ports/relayport`: `MailboxWriter`, `MailboxReader`, `MailboxAcker`, `MailboxRetractor`, `MailboxRevoker`, `MailboxExpirer`, `MailboxUsageReader` (`relayport/mailbox.go`) and `RegistryReader`, `Registrar`, `Revoker`, `ExpectedSenderReader`, `ExpectedSenderWriter`, `RegistryExpirer`, `RegistryStats` (`relayport/registry.go`). Each has a contract suite (`relayporttest.RunMailboxStore`; the registry suite in `relayporttest/registry.go`) with a `Reopen` hook for restarts. A new adapter behind the same ports changes no line of the session.

**What makes it harder than it looks.** Both directory adapters keep their working state in memory and treat the disk as its durable copy, assuming one process per directory:

* `adapters/mailboxstore.Store` holds every quota counter (`rcptEntries`, `rcptBytes`, `pairEntries`, `pairBytes`, `senderBytes`, `globalBytes`) and the puts in flight (`pending`, `pendN`, `revoked`) in memory, rebuilt from the names at `Open`, under an exclusive `flock` (`ErrLocked`).
* `adapters/bindingstore.Store` holds the whole registry in a `relayregistry.Core`, rebuilt at `Open`. A change is a plan of storage operations that the `Core` decides over the whole state (`relayregistry.Op`, `Plan`), carried out under one writer lock (`wmu`). Its package comment says the rate bucket and the counters are not durable and that a full rollback of the directory is not detected.
* The `Core`'s decisions are relay-wide: the registry cap with eviction of the least recently authenticated binding, the tombstone table with its share and headroom, the new-binding cap (`Core.rate`) and the cap on revokes that invalidate nothing (`Core.revRate`).

So the stores are not "a database the pods share". They are a single-writer state machine with a durable record of its effects. That decides most of what follows.

## Decided by the owner, 2026-11-19

1. **The store.** An S3-compatible object store with conditional writes is the default for a cluster. The directory adapters stay for a local deployment. No second external adapter is designed now (decision 2 says what would justify one).
2. **Sharing.** Relays run by one operator may share storage. Each relay identity has its own prefix and its own state, so one relay's objects are never read as another's (decision 3 gives the layout and the policy). *Changed after the review (M5):* the storage is two buckets per operator, one for what must not be lost and one for working state; every identity of the operator uses both.
3. **Several pods.** Option A of decision 5: one active pod per identity by a lease, and two or more identities per operator.
4. **The key source.** KMS-wrapped as the target (source 2 of decision 6); the mounted Secret (source 1) is built first.
5. **A shared tombstone set** across one operator's identities: yes, as a stage after stage 2 (decision 3).
6. **The operator-key design** (option C of decision 5): not now.

7. **The Object Lock mode.** Compliance mode for tombstones and the marker (decision 10). Governance is for test deployments only. Decided after the review, on its recommendation.
8. **The reading of "the server can decrypt nothing by itself".** Confirmed: the relay key is an identity key, not a mail key, so a pod that unwraps it with its own role (key source 2) does not contradict the requirement (decision 6).

## Terms

* **Relay identity**: the relay's tailcat node private key and pre-shared key (`relayconf.Key`); its public node key, which devices pin; and its address, which carries both public keys, the pre-shared key and the DERP region (decision 5, "What an endpoint is").
* **Store**: where a relay's durable state lives. The **directory store** is today's two adapters; the **object store** is two S3-compatible buckets and one key prefix in each.
* **Registry bucket**: the versioned bucket with Object Lock that holds the marker, the bindings and the tombstones. **Working bucket**: the unversioned bucket that holds the lease, the rate state and the mailbox.
* **Writer**: the one process that may change a relay identity's store. **Lease**: an object in the store that names the writer and lapses unless renewed.
* **Stateless pod**: a pod with no volume whose loss loses data. A memory `emptyDir` for scratch is allowed; nothing in it must survive the pod.

## Decision

### 1. Inventory of the state the relay holds today

Every item below was found in the code named. "If lost" says what a pod's death costs when the item was only in that pod.

**Durable and authoritative.**

| State | Where it lives now | Port that owns it | If lost |
| --- | --- | --- | --- |
| Queued envelopes by recipient device, named by arrival, mid and sender (SPO-Xmailbox-OUT-012) | `mailboxstore`, files under `mailbox/` | `MailboxWriter`, `MailboxReader`, `MailboxAcker`, `MailboxRetractor`, `MailboxRevoker`, `MailboxExpirer` | Mail waiting for an offline device is dropped; senders' outboxes put it again while the request is live (ADR 0013, "Retention and expiry"). Not a security loss. |
| Bindings: the verified statement bytes, the last authentication (at `relayregistry.PersistGranularity`), the expected-sender list of the latest login | `bindingstore`, `bindings/` | `Registrar`, `RegistryReader`, `ExpectedSenderWriter`, `ExpectedSenderReader` | Every put to an offline device is `unbound` until it logs in again; store-and-forward fails for offline recipients (ADR 0014 decision 7, "The registry is durable"). |
| Tombstones of the three scopes, one file per scope key holding the maximum not-before (`bindingstore/names.go`: `p-<K>-<device>`, `a-<K>`, `d-<device>`; a raise is one rename over the name) | `bindingstore`, `tombstones/` | `Revoker`, `RegistryReader.Tombstones`, `RegistryExpirer` | **Security loss.** ADR 0014 decision 7: "Losing tombstones alone would also re-open revoked bindings until they expire" (up to 180 days), until the client's re-sent revoke arrives (decision 8 there). This is why the registry is durable at all. |
| Arrival order inside a mailbox (strictly increasing, OUT-022) | the names | `MailboxWriter`, `MailboxReader.List` | Rebuilt from the names. |

**Durable but derivable** (rebuilt from the above at `Open`).

| State | Where | If lost |
| --- | --- | --- |
| Quota counters per recipient, pair, sender and in all | `mailboxstore.Store` | Rebuilt exactly from names and sizes. |
| The registry's indexes (`Core.dev`, `byKey`, `pair`, `all`, `dtomb`, `tombDays`) and statistics | `relayregistry.Core` | Rebuilt by `bindingstore.Open`, which verifies every stored binding again. |
| Puts in flight and their reservations | `mailboxstore.Store` | Gone with their connections; nothing was committed. |

**Soft state** (in memory only, by design).

| State | Where | Owner | What a restart costs |
| --- | --- | --- | --- |
| New-binding cap, 60 an hour plus a burst of 10 | `Core.rate` | registry | Starts full: one extra burst per restart. |
| Cap on revokes that invalidate nothing, 60 an hour plus 10 | `Core.revRate` | registry | Starts full: one extra burst per restart. |
| Connection counts and minute windows: `live`, `unauth`, `perKey`, `recent`, `puts`, `inflight`, `perDevice`, `perWallet`, `rejects` | `relay.Server` (`app/relay/server.go`) | session | Every connection ends with the pod, so counts restart right at zero; windows restart empty. |
| Stranger book: the class of each queued entry; per-key bytes in flight | `relay.book` (`app/relay/strangers.go`, SPO-Xmailbox-OUT-056, INV-037) | session | Rebuilt at the first admission per recipient, counting every entry as a stranger's: errs toward refusing strangers. |
| Long-poll waiters | `relay.notifier` (`app/relay/notify.go`, INV-014) | session | End with their connections; clients fetch again. |
| Devices connected, for the eviction guard | `relay.Guard.conn` (`app/relay/guard.go`) | session, read by the registry | Empty after a restart: an idle device with an empty queue may be evicted before it reconnects, as after a restart today. |
| De-duplication over several relays | `mailbox.Multi` (`adapters/mailbox/multi.go`) | client | Not the relay's. |

**Identity and configuration.**

| State | Where now | Note |
| --- | --- | --- |
| Node private key and pre-shared key | key file, `relayconfig.LoadKey`: 156 bytes, a regular file of the effective user with no group or other bit; in the cluster a Secret copied by an init container | Configuration, but it must come from somewhere when there is no volume (decision 6). |
| The DERP region in the address | chosen again at **every start**: `stream.Listener.build` passes `Region: l.region`, which is nil from `cmd/spo-relay`, and no `RegionID`; tailcat then picks "the nearest region … based on latency at Start" (source: `tailcat.Server.RegionID` doc comment) | A pod that restarts or is rescheduled may get another region and so another address; devices holding the old address cannot reach it. A rebuild after `SetAllowed` calls `build` again, and `Listener.install` then fails the listener if the address changed ("the pinned relay address no longer works") (source). Decision 7 makes the pin a first-stage requirement. |
| Device list (`[[device]]`) and allow-list (`[[wallet]]`) | configuration (`relayconf.Config`) | A ConfigMap. How changes roll out: decision 9. |
| The tunnel engine's state | memory: tailcat runs on `ipn/store/mem` (source: tailcat imports it; `stream.ListenerConfig` "holds no state directory") | Nothing to keep. |

**Conclusion.** Three things must leave the pod: the queues, the bindings and the tombstones. Only the tombstones' loss is a security loss. Everything else is rebuilt from those three or is soft by design.

### 2. Target shape: no volume, durable state in an object store

**Decided (owner).** The pods have no PersistentVolumeClaim. The three durable items live in an S3-compatible object store, behind the existing ports, as a second pair of adapters beside the directory adapters. The in-memory parts stay in the process as they are: the counters, the `relayregistry.Core`, the stranger book, the notifier. The store is the durable copy and the process is its one writer (decision 5 makes that true as far as a lease can).

**Why this store, for this workload.** At the defaults: at most 1024 bound devices, 256 entries and 4 MiB per queue, 4 GiB in all, envelopes of at most 1 MiB, bindings of about 3 KiB, tombstones of 15 bytes. The operations are create, read, list one recipient's queue, delete by name, and a few conditional overwrites. Every one is a single object under one writer, which an object store does well. The owner already uses S3 with federated credentials (ADR 0012 stage 1, `adapters/objstore/s3`, which refuses credentials that do not expire and endpoints that are not https (source)). AWS S3 supports `If-None-Match: *` and `If-Match: <etag>` on PutObject in general-purpose buckets, the first conditional write to finish wins and the others get 412 (doc: <https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html>, <https://aws.amazon.com/about-aws/whats-new/2024/11/amazon-s3-functionality-conditional-writes>), and a bucket policy can require the headers (doc: <https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes-enforce.html>). The rejected candidates: PostgreSQL (a stateful service to run; its transactions are not needed with one writer), Redis-like stores (durability by AOF policy, data set in memory, a failover can lose tombstones), etcd or Kubernetes API objects (the control plane's store for 4 GiB of user data; an API token and write rights for the relay; a 1 MiB ConfigMap limit below an envelope with overhead (memory); no use to a local deployment).

**What would justify a second external adapter later.** A second adapter is worth building only when a deployment needs what an object store under one writer cannot give: several processes changing one relay identity's state at the same moment, with the registry's relay-wide caps decided across them in one transaction. That arises only if a later record wants several active writers per identity (option C of decision 5, or a registry shared between identities that is written by all of them). Then PostgreSQL is the candidate: row locks and transactions for `Register` and `Revoke`, and `LISTEN`/`NOTIFY` for wake-up. A store that lacks conditional writes, strong listing or per-object retention is not a reason for a second adapter; it is a store this one refuses (below).

**Atomicity, operation by operation.** "Memory" is the writer's in-process state. It is authoritative because nothing else writes, and it changes only after the store confirmed the write, as `bindingstore` does today ("applied to the Core only after it is on storage"). **A conflict** is a conditional write answered 412, 404 or 409. *Changed after the review (M2):* every conflict that a read-back does not explain ends the writer (decision 5, "The exit rule"); 412 alone was not enough, because `If-Match` on an object that is gone answers 404 and a race between conditional writes can answer 409 (doc: the conditional-writes page above).

| Operation | Needs | How, with one writer | Lost response or retry | A second writer (decision 5 bounds it; this is what is left) |
| --- | --- | --- | --- | --- |
| `Register` (admit, lifetime, allow-list, same statement, older binding, devices per key, cost, cap with eviction) | Decision and writes serialised against every registry writer: the caps are relay-wide | The `Core` decides under the writer lock as now. The plan's operations go out one at a time, in plan order: victims' binding objects deleted, then the newcomer's object written with `If-Match` on the ETag the writer holds, or `If-None-Match: *` for a device that has none. | A conflict on a retried write is read back: equal bytes is success (the method `objstore/s3.Store.Put` already uses (source)). DELETE is idempotent. A crash between steps leaves fewer bindings, never more than the cap. | An unexplained conflict means someone else wrote or removed the object. The writer stops serving and exits; it never writes over another writer's change. |
| `Revoke` (always record; delete only what it invalidates; table share, headroom, rate cap) | The tombstone durable before the bindings it invalidates go; the maximum not-before never lowered | *Changed after the review (M3).* One object per scope key, named as the directory store names it, holding the not-before. A new tombstone is created with `If-None-Match: *`; a raise overwrites it with `If-Match` on the ETag the writer holds. Each write carries an Object Lock retention, so every version stays (decision 10). The load takes the highest not-before across every version (decision 3). Then the invalidated binding objects are deleted. | The same bytes read back is success. A crash between leaves bindings that the next load drops, because tombstones load first (as now). | A writer that lowers the current version lowers nothing: the older, higher version is locked and the load reads it. |
| `SetExpectedSenders`, last authentication | Replace one device's record | Overwrite the device's binding object with `If-Match`; the last authentication at `PersistGranularity`, as now. | As `Register`. | As `Register`. |
| Registry `Sweep`, room for a tombstone | Delete exact objects; never a live tombstone | Bindings: DELETE by name. Tombstones: *changed after the review (B1, M3)*, DELETE of each version by its version id, which retention refuses until it ends. A delete that retention refuses is not an error of the revoke or the sweep (decision 3, "The registry core"). | Idempotent. | Exact names and versions only. |
| `MailboxWriter.Put` (duplicate, busy, quota, increasing arrival, hash) | Decision and reservation under one lock; nothing visible before the hash is checked | Decision and reservation in memory under the store's mutex, as now. *Changed after the review (m1):* the body is held in memory until `ReadRawFrame` has checked the hash, then one PUT with `If-None-Match: *` at the OUT-012 name, with an `x-amz-checksum-sha256` the store checks, so bytes damaged on the way are refused. The bytes held are bounded (below). | A conflict with equal bytes read back is success. | Two writers can give two entries one arrival second; OUT-022's "strictly later" can break during the overlap (residual). |
| `Remove` (ack), `Retract`, `RemoveMailbox`, mailbox `Sweep` | Delete exact entries; a put in flight to a removed mailbox fails | DELETE by name from the memory index; the in-flight check stays in memory. The working bucket is unversioned, so the bytes go at once (decision 3). | Idempotent. | Exact names only. |
| Quota (queue, pair, sender, global) | Exact including puts in flight | Memory, rebuilt from one listing at start. No counter object. | Not a write. | Each writer counts only its own puts: the global quota can be passed during an overlap (residual). |
| Rate state | Keep the two buckets across restarts | *Changed after the review (m3):* one object, `registry/rates`, overwritten with `If-Match` at most once a minute and at shutdown. | A conflict read back with equal bytes is success. | As `Register`. |

**Holding a put's body (m1).** *Changed after the review (m1).* `relayport.MailboxWriter.Put` says "The body is streamed, never held whole". The object adapter cannot keep that. The mid is the Blake2b-256 of the envelope (SPO-Xmailbox-OUT-001), and the checksums an S3 store verifies are CRC and SHA families (doc: <https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html>), so the store cannot refuse a body whose mid is wrong. A stream that holds back its last chunk until the hash is known, and aborts the upload when it is wrong, would work if every allowed store discards a PUT whose body ends short; that is a property of each product, not checked. Decided: the port text is amended to "streamed, or held whole up to `mailbox.MaxEnvelopeBytes` by an adapter whose store cannot refuse wrong bytes"; the object adapter holds the body, at most 64 bodies (64 MiB) for the whole store; a put that finds no room waits for one within its own deadline and otherwise fails as a store failure does, and the sender's outbox puts it again. The streamed variant is a later option if memory matters. The Xmailbox requirement that states the port text changes with it (work package 15).

**What "S3-compatible" means here.** *Changed after the review (M6).* A product is allowed only when it is on this list and passes the self-test below. Anything else is unsupported until its self-test passes and the assumptions of the hostile suite (work package 3) are confirmed for it in its documentation.

| Product | Conditional `If-None-Match: *` and `If-Match` on PUT | Per-object retention (Object Lock API) | Strong listing after a write | Status |
| --- | --- | --- | --- | --- |
| AWS S3, general-purpose buckets | Yes (doc above) | Yes, governance and compliance (doc: <https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html>) | Yes (doc: <https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html#ConsistencyModel>) | Allowed, both buckets. Verified from documentation. |
| MinIO | Yes (doc: <https://docs.min.io/aistor/developers/s3-api-compatibility/>) | Documented (memory) | Documented (memory) | Allowed after its self-test passes; retention and listing to confirm in documentation. |
| Ceph RGW | Not checked (review) | Documented since Octopus (memory) | Not checked | Unsupported until confirmed. |
| Cloudflare R2 | Yes (doc: <https://developers.cloudflare.com/r2/api/s3/conditional-operations/>) | Not confirmed: its bucket locks are rules for a bucket or a prefix, set through its own API (doc: <https://developers.cloudflare.com/r2/buckets/bucket-locks/>), not a per-object retention | Not checked | Working bucket only, after its self-test. Not for the registry bucket. |
| Backblaze B2 (S3 API) | Reported to reject `If-None-Match` on PUT (review) | Not checked | Not checked | Unsupported. |
| Google Cloud Storage | Its own precondition headers (`x-goog-if-generation-match`), not these (review) | Its own retention model | Yes (memory) | Unsupported by this adapter. A native adapter would be a second adapter. |

**What the store must offer, checked at every start.** In its own prefix of each bucket the adapter checks: a create with `If-None-Match: *` over an existing object answers 412; an overwrite with a wrong `If-Match` answers 412; two writes of different bytes give two different ETags (the lease depends on it, decision 5); a written object is listed and read back at once. In the registry bucket it also checks: the bucket reports versioning on and Object Lock enabled; a create with a retain-until date of one day and the chosen mode reads back with that date and mode; a delete of that version by its version id is refused; a version listing shows it. Self-test objects in the registry bucket carry a one-day retention and are deleted by version by the next sweep after it ends. A store that fails any check is refused, with the property named.

*Changed after the review (M6).* **What the self-test cannot show.** It sends one request at a time. It cannot show that, of two conditional writes racing on one name, exactly one wins; that is taken from the product's documentation, which is why the list above exists. Nor can it read the bucket policy or the lifecycle rules with the relay's narrow role.

**Permissions the checks need.** The relay's role is granted the bucket-level reads its start needs: `s3:GetBucketVersioning` and `s3:GetBucketObjectLockConfiguration` on the registry bucket, and `s3:ListBucket` and `s3:ListBucketVersions` limited by `s3:prefix` to its own prefix. The checks that need more (the bucket policy, the lifecycle rules, the default retention, encryption) run in `spo-relay store verify`, which the operator runs with the operator's own credentials, and once in `init-store` (work package 9).

**An empty store is a full rollback.** A new prefix, an emptied one or a wrong bucket forgets every tombstone. Each prefix therefore carries a marker object, written by `spo-relay init-store` for a new relay, or by `migrate-store` as its last step (work package 9). In the registry bucket the marker has a retention of one year that the relay extends every 30 days. *Changed after the review of work package 8:* the relay cannot extend a retention in place (its client has no `PutObjectRetention`), so it writes a new locked version when 30 days of the newest's lock are left (about every 335 days) and deletes the older versions by id when their lock ends; at most two object versions of the marker are kept, and delete markers over it are deleted by `Sweep` and bounded apart (4096 entries), so a store that lacks the deny on simple deletes cannot make a cheap refusal of the start. The relay refuses to start on a prefix whose marker is missing in either bucket ("the store looks new or emptied: run init-store only for a new relay"), so an empty store is never taken for a working one by accident. *Changed after the review (B1):* the marker is found by a version listing, so a delete marker over it does not hide it.

### 3. Storage for the relays of one operator

**Decided (owner): one operator's relays may share storage, each identity under its own prefix with its own state.**

*Changed after the review (M5).* **Two buckets, not one.** With versioning on for the whole bucket, every ack, retract and sweep of the mailbox leaves a delete marker and a noncurrent version, and every lease renewal leaves a version. Two ways were weighed:

* *Lifecycle rules in one bucket:* expire noncurrent versions under `mailbox/` after a day, remove expired delete markers (`ExpiredObjectDeleteMarker`), and a rule for binding versions. The lifecycle runs about once a day (memory), so a busy relay carries up to a day of delete markers and old versions; listings walk past the markers, which slows the start-up listing of the mailbox; an acknowledged envelope's sealed bytes outlive the ack by up to a day; and the bucket that must stay locked takes the most frequent writes.
* *A second, unversioned bucket for working state:* the mailbox, the lease and the rate object live there. A delete removes the bytes. No delete markers, no noncurrent versions, no lifecycle rule for them. The locked bucket takes only rare writes.

**Decided: the second bucket.** Its costs are a second bucket, a second policy and a second self-test per operator. The lease guards both buckets equally well, because it does not fence (decision 5) and does not need to live beside any one object. A product that lacks per-object retention, such as R2 today, can serve the working bucket.

**Layout.** In both buckets, `relays/<relay node public key, 64 hex>/` per identity.

| Bucket | Objects under the prefix |
| --- | --- |
| Registry (versioning on, Object Lock enabled) | `marker`; `registry/bindings/<device 40 hex>`; `registry/tombstones/p-<K 56 hex>-<device 40 hex>`, `a-<K 56 hex>`, `d-<device 40 hex>` (one object per scope key, as `bindingstore/names.go`, body `SPORT1\n` and the not-before, 15 bytes); `selftest/<16 hex>` |
| Working (unversioned) | `marker`; `lease`; `registry/rates`; `mailbox/<recipient 40 hex>/<arrival 20 digits>-<mid 64 hex>-<sender 40 hex>` (the OUT-012 names); `selftest/<16 hex>` |

The prefix is the identity's public key, so the relay derives it from its own key and cannot be pointed at another identity's objects by a configuration typo; the lease also names the key (decision 5), and a mismatch refuses the start.

**Bucket policy.** One IAM role (or workload identity) per relay identity, its rights limited to `relays/<its key>/` in both buckets.

* Registry bucket, the role: `GetObject`, `GetObjectVersion`, `GetObjectRetention`, `PutObject`, `PutObjectRetention`; `DeleteObject` on `registry/bindings/*` only; `DeleteObjectVersion` on `registry/tombstones/*`, `marker` and `selftest/*`; `ListBucket` and `ListBucketVersions` with `s3:prefix` limited to its own prefix; the two bucket-level reads of decision 2.
* Working bucket, the role: `GetObject`, `PutObject`, `DeleteObject`, `ListBucket` with `s3:prefix` limited to its own prefix.
* *Changed after the review (B1).* Explicit denials in the registry bucket's policy, for every principal: `s3:DeleteObject` (the simple delete, which only adds a delete marker) on `relays/*/registry/tombstones/*` and `relays/*/marker`; `s3:BypassGovernanceRetention` on the whole bucket.
* *Changed after the review of work package 8.* Two more denials for the relay's role in the registry bucket, both documented by AWS for Object Lock (doc: <https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-managing.html>, "Setting limits on retention periods"): `s3:PutObjectRetention` when `s3:object-lock-remaining-retention-days` is greater than 182 on `relays/*/registry/tombstones/*` (a tombstone needs at most 180 days, twice the skew and an hour), and greater than 366 on `relays/*/marker` (the marker's year); and `s3:PutObjectLegalHold` on the whole bucket (a legal hold has no end and would stop the deletes of decision 3). `spo-relay store verify` (work package 9) checks that both are present. The relay itself refuses to write a tombstone lock longer than that (SPO-Xobjstore-PRE-808).
* *Changed in the review of work package 6, 2026-11-20.* An explicit denial in the working bucket's policy, for every principal: `s3:DeleteObject` on `relays/*/lease`. The lease is only ever overwritten with `If-Match` (a release, or the store tool's released record); a deleted lease object is treated as lapsed by a waiter, but a deny keeps the holder and the waiter from ever meeting that case. `spo-relay store verify` checks that the deny is in the policy.
* Both buckets deny requests without TLS (`aws:SecureTransport`) and PutObject without a conditional header (`s3:if-none-match` or `s3:if-match`; doc above).
* Lifecycle, registry bucket: noncurrent versions under `relays/*/registry/bindings/` expire after one day, and expired delete markers there are removed. No rule touches `registry/tombstones/` or `marker`. Working bucket: none needed.
* The ADR 0012 backup sink uses another bucket and another role.

**Tombstones are read from versions.** *Changed after the review (B1, M3).* The load lists the versions under `registry/tombstones/`, ignores delete markers, reads each version (one GET by version id) and takes, per scope key, the highest not-before of any version that exists. A tombstone version that exists counts whether or not it is current. A delete marker therefore hides nothing, a new lower version lowers nothing, and only a delete of a version by its id, which retention refuses (decision 10), can remove one. The stand-in of work package 3 covers a simple delete over a tombstone, a delete marker made by someone else, and a lower version written on top.

**A ceiling on versions.** *Changed after the review (M3).* A raise makes a version, so the load bounds versions, not names. Raises are rate limited by the existing rules: a raise that invalidates nothing draws on the revoke cap (`PlanRevoke`, `have && !invalidating`), and one that invalidates needs a binding that the new-binding cap admitted. At both caps' full rates (60 an hour each plus bursts) over a tombstone's life (180 days plus the skew) that is at most about 530 thousand versions. The ceiling is 1 048 576 versions (`relayobj.MaxTombstoneVersions`, proposed); above it the start is refused, as for an unreadable tombstone (fail closed), with a pointer to `spo-relay store inspect`. A metric reports the count, so an operator sees a flood long before the ceiling. The `Core` keeps counting names toward its table bound, as now.

*Changed after the review of work package 8.* The figure above was wrong: it assumed that versions go away, and nothing deleted the versions of a name that stays live. A peer raising one name once a minute (each raise draws only on the revoke cap) passed the ceiling in about a year, and locked versions cannot be removed, so the identity could never start again. Now:

* `Sweep` deletes, by version id, every version of a live name but its highest and its current one once its lock has ended (SPO-Xobjstore-OUT-806). Retention is set once, at the write; a superseded version keeps the date it was written with, and the highest is locked at least as long as any lower one the relay wrote.
* The core budgets the raises of one name that invalidate nothing: 4 in any 24 hours (`relayregistry.MaxRaisesPerName`, `ErrNameRaiseRate`, the `limit` outcome; SPO-Xobjstore-PRE-806). A revoke that invalidates a binding is never refused for it. One name gains at most 733 such versions in a lock's life.
* The arithmetic, from the core's constants (`TestTheWorstCaseVersionCountFitsTheCeiling`): a version is locked until at most its write time plus 180 days, twice the skew and a second, and deleted within two days after (a sweep at least daily, a refused delete tried again an hour later): a window of 4369 hours. In it the relay writes at most 262 150 versions that invalidate nothing (60 an hour and the burst of 10) and 266 246 that invalidate (each needs a binding admitted by the new-binding cap, 60 an hour and 10, or held at the start, at most 4096). Past the window at most two versions of each name stay, at most 139 264 for the hard table of 69 632 names. The total is at most **667 660**. The ceiling of 1 048 576 is more than half again as much, so the relay's own writes never reach it; only versions written by someone else (a holder of the role, decision 10) can.
* At that worst case a refresh reads at most 8 listing pages and resumes where the last stopped, so a pass takes 84 refreshes (a late write is seen within 84 minutes instead of 60 s); a load is 668 listing pages and as many gets, 32 at once, about 11 minutes at 30 ms a request (not measured), during which the host's keeper renews the lease; memory for the version ids is about 52 MiB (measured: 81 bytes each).

**Tombstones are re-read while serving.** *Changed after the review (M1).* Every 60 s the writer lists the versions of `registry/tombstones/` again, reads only the version ids it has not seen, and merges them into its `Core` (`LoadTombstone`: the maximum wins). This catches a tombstone that a stale writer's late request wrote after this writer loaded (decision 5, "Writes that arrive late"). The cost is one listing a minute and one GET per new version. *Changed after the review of work package 8:* a refresh reads at most 8 pages (8000 entries) of the listing and the next one resumes there, because the host bounds each refresh by the 10 s request timeout and three failed refreshes end the writer; below 8000 entries nothing changes, at the worst case a pass takes 84 refreshes. A version the relay cannot read is merged at the strictest reading, not an error (decision 10).

**The registry core.** *Changed after the review (M3).* `relayregistry.PlanRevoke` makes room for a new tombstone by dropping expired ones first (`limitedRoom`, `headroomRoom`, `expiredTombstones`); `PlanSweep` drops them too. In the object store such a drop is a delete of every version of the name, which retention refuses when the store's clock is behind the relay's. A refused drop must not fail the revoke: today `execute` would stop at the failed drop, before the tombstone and before the binding deletes, and the revoked binding would stay live. The change, in the `Core` and in both adapters:

* A drop is planned in its own plan, before the revoke's plan. The adapter carries it out; a drop that storage refuses is reported to the `Core` (`Core.Hold(tomb, until)`, name proposed), which excludes that tombstone from the expired set until `until` (one hour, then tried again) and keeps it loaded.
* The revoke is then planned with the room that is really there. When there is none, an invalidating revoke takes the existing path of SPO-Xmailbox-PRE-049: the bindings are deleted, no tombstone is recorded, the result carries `ErrTombstoneUnrecorded` and `TombstoneUnrecorded` (`PlanRevoke`, the `invalidating` case of a new tombstone, checked in `relayregistry/plans.go`). A revoke that invalidates nothing is refused with `ErrTombstoneFull`, as now (PRE-048).
* A refused drop in a sweep is skipped and counted; the sweep goes on.
* The directory adapter never sees a refusal, so its behaviour does not change.

Spec ids that change (amended in place with a note, none renumbered): SPO-Xmailbox-PRE-040 and OUT-079 (a drop that storage refuses is not made, and is no failure), PRE-049 (the unrecorded path also when the drops it needed were refused), PRE-052 (the object store bounds tombstone versions, the directory store names), OUT-063 and OUT-070 (the maximum is taken across versions in the object store). New ids cover the object-store adapters (work package 15).

**A registry shared between identities, for tombstones only.** Bindings and the caps belong to one relay (a device logs in to each relay with that relay's key in the signed bytes), so sharing them would couple relays that ADR 0013 made independent and would need several writers. Tombstones are different: a revoke names no relay, and the maximum of several writers' values is the right merge, so several writers can add to one set. **Decided (owner): yes, as a stage after stage 2.** Each identity of one operator also writes its tombstones to `operator/tombstones/` in the registry bucket (same names, same retention) and merges that prefix into its `Core` every 60 s (maximum not-before wins), so a revoke recorded by any one is enforced by all within a minute even when the client could not reach the others. In that prefix a conflict is expected (another identity raised the same name): the writer reads the current value and raises again only if its own is higher; it does not exit. Every identity's role may write `operator/tombstones/*`. It is a defence in depth: clients send revokes to every relay already (ADR 0014 decision 8, `mailbox.SendRevokesTo`).

### 4. Commands and queries: where CQRS earns its place

**Commands** must be linearised:

| Commands | Linearised over |
| --- | --- |
| `Register`, `Revoke`, `SetExpectedSenders`, registry `Sweep` | The whole registry of one identity (relay-wide caps): one writer lock, as `bindingstore.Store.wmu` now. |
| `Put`, `Remove`, `Retract`, `RemoveMailbox`, mailbox `Sweep` | Per recipient for arrival and queue bounds; per identity for the global quota and per-sender totals: the store's mutex, as `mailboxstore.Store.mu` now. |

**Queries** (`Lookup`, `Devices`, `Tombstones`, `ExpectedSenders`, `Stats`, `List`, `Usage`; `Open` reads the object) are answered from the writer's memory.

**The split that pays is the one already there**: commands write through to the store, queries read memory. The read model is never stale with respect to this writer's own writes, because the reader is the writer.

**Where a stale read model would be a security hole.** A revoked binding still admitted (`session.lookup` and `session.recheck` ask the registry at every request, after every wake and before anything is sent: SPO-Xmailbox-SEC-025); a tombstone not yet visible (`Register` runs `relaybind.Admit` against stored tombstones); the relay-wide caps counted against a stale view; and the re-check after a stored put (`session.store`). This record allows **no stale read view of this writer's own writes, at any staleness.** Read-your-writes holds because memory changes only after the store confirmed the write. *Changed after the review (M1):* a write by an earlier writer that lands after this writer loaded is the one exception; it is seen within 60 s by the tombstone re-read (decision 3) and is stated as a residual in decision 5.

**No event sourcing.** The `Core` already plans its operations in a safe order; nothing consumes a history; an event log would add compaction and replay and buy nothing.

### 5. Serving a relay from more than one pod

#### What an endpoint is (source unless marked)

* **The address** is `"tc"` plus base64url of a CBOR `ConnInfo`: the server's node public key, its disco public key (path discovery; derived from the node key by `discoPrivateForNode`), the WireGuard pre-shared key, and either a full DERP region or a region id (`tailcat.ConnInfo`, `tailcat.Addr`). "At most 1 region may be provided" (comment dated 2023-09-22).
* **What a server's address holds.** *Changed after the review (M4).* A server always puts the **full region** in its address: `Server.TailcatAddr` "embeds the full DERP region", and `locoBackend.tailcatAddr` copies the region it started with, every node of it, while `ConnInfo.Addr` zeroes the region's id, code and name before encoding (`tailcat.go`). With `RegionID` set, `startLocked` fetches the map and takes `dm.Regions[RegionID]` as it is that day. So a region id fixes which region, not the address: a change of the provider's map (a node added, a host name or address changed) changes the address.
* **The server** takes `Key`, `PresharedKey`, `Region` (a full region, no map fetch), `RegionID` (a region of the map; "If zero, the nearest region is picked based on latency at Start"), `DERPMapURL` (default `https://tailcat.dev/derpmap.json`) and `AllowedClients` (`tailcat.Server`). The adapter sets `Region` from `ListenerConfig.Region`, which the relay leaves nil, and never sets `RegionID` (`stream.Listener.build`).
* **What a device pins.** `spo party relay add` stores the relay's node key in a public record and the address sealed (ADR 0014 work package 10, `app/relayself` relay list). The client compares the Challenge's relay key with the pinned key before it signs anything (ADR 0013 decision 3; `mailbox.Client`), and the signed array of version 2 contains the relay node key (`["spo/mailbox-auth/v2", 2, relay node key, client node key, nonce, relay time, fingerprint, binding hash, senders hash]`, ADR 0014 decision 7). The dialer is built for one key (`relayport.StreamDialer` comment).
* **Two connections of one node key at a DERP server.** The server keeps all connections of a key in a `dupClientSet`. "If only the last is sending traffic, that last one is the active connection and it gets traffic. Otherwise, in the case of a cloned node key, the whole set of dups doesn't receive data frames" (`tailscale.com/derp/derpserver`, `clientSet` and `dupClientSet` comments, `pickActiveClient`). So two live engines with one key make the identity unreachable, and a standby that connects to DERP with the active pod's key can take its traffic. Behaviour of a DERP server of another version is not confirmed.
* **Hand-over of a listener.** There is none: the engine, its WireGuard sessions and its netstack are in the process. A new engine with the same key and pre-shared key and the same full region has the same address (the adapter's rebuild relies on that: `Listener.install`). Clients reconnect to it.

#### The options

**A. One active pod per identity, a lease in the object store.** The pod that wins the lease (a conditional write) loads the store, starts the tunnel and serves. A second pod per identity may wait as a warm standby (stage 4, optional): with its configuration checked, its store client and credentials ready, but **no tunnel**, because a standby that connected to DERP with the same key would split the key's traffic (above). On a lapse it takes the lease, loads and starts. No protocol change. One identity has a pause on fail-over, so availability across a pod's loss needs **several identities** (the device's list).

**B. Several pods on one node key.** Impossible without a protocol change: two live engines with one key disable the key at DERP (source above), and a client's WireGuard session is with one engine. A single pod that terminates the tunnel and forwards to workers is a single point again, and the work behind it does not need more than one process. **Rejected.**

**C. Per-pod short-lived node keys certified by a relay operator key that devices pin.** What it would change:

* `domain/mailbox`: a version 3 Challenge carrying a certificate (operator Ed25519 key over `["spo/relay-pod/v1", pod node key, pod disco key, region, not-after]`), and a version 3 signed array that holds the operator key and the certificate hash beside the pod node key. Version 2 relays can keep working: the version range is in the Challenge and the version is in the signed bytes (ADR 0014 decision 7, "Downgrade"), so a client can speak 2 to a relay entry that pins a node key and 3 to one that pins an operator key.
* The client pin and `party relay add`: an entry pins the operator key instead of a node key, and the client must check the certificate before it signs.
* The address: a pod's address carries its own node key, pre-shared key and region, so the device cannot hold it fixed. It needs a way to learn the current pods' addresses, sealed for the device's pre-shared key, from somewhere it can reach: a new channel.
* Revocation of a pod key: short certificate lifetimes (hours) and a list in the same channel.
* The state: the pods of one relay become several writers of one registry, which needs a transactional store (decision 2's PostgreSQL case).

It is the only option with one relay name that survives a pod's loss without a pause, at the cost of new signed formats, a discovery channel and a multi-writer store. **Decided (owner): not now.**

**D. A signed relay-set document.** The operator signs a list of identities, devices pin the operator's key and fill their list of up to 8 relays (`mailbox.MaxRelays`) from it. The document only distributes identities; each identity is still served by A. It adds a new trust root and a channel to fetch the document, and saves the operator one `party relay add` per identity per device. Not needed to serve several pods; a later convenience.

#### The choice: A, with at least two identities per operator

On the criteria in the order given:

| Criterion | A, two or more identities | B | C | D |
| --- | --- | --- | --- | --- |
| What a client verifies before it signs is not weakened | Unchanged: pinned node key, same signed array | — | New certificate path before signing; more to get wrong | Adds trust in an operator key for which relays to use |
| No single pod is a point of failure | Yes: a send is delivered when **one** relay stored it (`mailbox.Multi`), and each identity runs on its own pod | No | Yes | As A |
| Least protocol change | None | Large | Version 3, discovery channel | New document and channel |
| Least new cryptography | None; the lease is a conditional write | — | New certificate format | New signed document |
| Buildable and testable in process | Yes: the lease and stores over an S3 stand-in, the relays over `fakenet` as `test/multiparty` does now | — | Large new surface | Moderate |

**Chosen: A.** Each relay identity is one active pod by the lease. An operator who wants no single point runs at least two identities (on different nodes; ideally in different zones or clusters) and every device lists all of them, which ADR 0013 and ADR 0014 already support. A warm standby per identity is optional (stage 4) and is added only if the measurement of stage 2 shows it is worth it. *Changed after the review (m7):* with two or more identities a standby buys only a shorter pause on one of them; a node loss is the case where it may matter (below).

#### What the lease is

*Changed after the review (B2, M1).*

* **The object.** `relays/<key>/lease` in the working bucket. Its body holds the relay's node public key, a random holder id made at process start, a generation number (raised at each take), a **renewal counter** (raised at each renewal), the duration and a state (`held` or `released`). Every write changes the counter, so every write changes the bytes.
* **Writes.** A take or a renewal is a PUT with `If-Match` on the ETag the writer last saw (`If-None-Match: *` the first time). Only one conditional write can win (doc above). The self-test requires two writes of different bytes to give different ETags (decision 2); the stand-in uses ETag = MD5 of the body, as AWS does for a plain single-part PUT (memory), so a lease that renewed with identical bytes would keep its ETag and the test would catch it.
* **Defaults.** Duration 30 s, margin 10 s, a renewal every quarter of the holder's term (5 s, counted from the sending of the one before; a failed one is retried after 250 ms, doubling to 2 s, until the lease end less the guard of 2.5 s less a minimum request time of 500 ms; changed when work packages 5 and 6 were reviewed, because at every 10 s one failed renewal ended the relay, and later one slow renewal and one refusal did), a poll by a waiting pod every 5 s, a request deadline of at most 10 s, a drain period of 15 s.
* **Judged on the local monotonic clock.** The holder's lease ends at the moment it **sent** its last renewal that was confirmed, plus the duration minus the margin (20 s at the defaults). A waiting pod reads the lease every 5 s; it takes a held lease only when it has read the same ETag and the same counter for the duration plus the margin (40 s) on its own monotonic clock, counted from the first read that showed them. That first read came after the holder's write, so the taker acts at least 20 s after the holder's lease ended. No synchronised clocks are needed, only clocks whose rates are close. A released lease is taken at once. This is the scheme of Kubernetes' leader-election Leases (memory), with the bucket in place of the API server.
* **Request deadlines.** Every store request of the holder, of every kind, has a deadline at the earlier of 10 s and the holder's lease end, and the client does not retry past it. The holder checks its lease before each request. When the lease end passes without a confirmed renewal, it closes the tunnel (`Tunnel.CloseWithin`, bounded by the margin, 10 s), sends nothing more and exits (status 3 if the tunnel did not stop, as now).
* **The drain period.** A taker of a lapsed lease waits the drain period (15 s, longer than the 10 s bound on a request) after its take succeeded, and only then lists and loads. A taker of a released lease does not wait: the holder writes `released` only after every request it sent has been answered, and lets the lease lapse instead when one timed out.
* **The start order.** Lease, then (drain), then load, then tunnel. The tunnel never starts before the lease is held.
* *Changed in the review of work package 6, 2026-11-20.* **An absent object is lapsed.** `init-store` writes the lease object once, released (`objlease.Init`), so an ordinary start never meets an absent object. A waiter that finds none waits the duration plus the margin, read after read, then creates it with `If-None-Match: *` and drains, as for a lapsed lease. **The margin is at least a third of the duration**, in the configuration and in a record, so the take-after time is at least twice the term. **The holder renews during the drain**, every quarter of the term (lease writes are not state writes), so a take answered slowly is not lost at the end of the drain. **A record's duration is honoured up to 5 minutes**; a longer one makes the record unreadable.

**The lease does not fence.** S3 cannot make a write conditional on another object, so nothing stops a request that the old holder sent in time from being applied by the store later. What the rules above give is a margin: the old holder's last request was sent at least 20 s before the taker took the lease, every such request had ended on the client's side by then, and the taker waits 15 s more before it reads. A request applied by the store more than 35 s after the client gave up on it is the residual. Its effects, case by case:

| Late write by the old holder | What happens | What closes it |
| --- | --- | --- |
| A tombstone, then the deletion of the binding it invalidates (a revoke) | The taker loaded before the tombstone; the binding object is gone, but the taker's memory still holds the binding and serves it. | The tombstone re-read finds the tombstone within 60 s and the `Core` stops serving the binding (`Core.serves` checks the tombstones). Independently, the client re-sends every pending revoke on every connection until the revoked binding's `until`, whether or not a relay answered `recorded`: `adapters/mailbox/revoke.go`, `Client.sendRevokes` ("recorded and refused both leave the revoke pending"; at most `MaxRevokesPerConn`, 8, per connection, the least recently sent first; SPO-Xmailbox-OUT-090) (source). |
| A tombstone alone (the deletes did not land) | As above, without the binding gone. | The same two. |
| A mailbox entry created | The entry is in the store and not in the taker's index: it is not listed, and the quotas undercount it. | The next load picks it up. The sender's outbox puts it again when it had no answer. Not a security loss. *Changed after the review of the mailbox (2026-11-20):* the old holder counted such a key as held while it served, and its key carries a nonce no taker draws, so a late request of the old holder never reaches a taker's entry. |
| A binding created or overwritten | The store holds a binding the taker's memory lacks or holds older. | The next load verifies it again against every tombstone version, so it cannot bring back a revoked binding. The taker's own next write of that device answers a conflict and ends the taker (the exit rule), and the next load is right. |
| A binding deleted (an eviction, an expiry) | The taker serves a binding whose object is gone. | Not a security loss (a revoke's delete is the first row). The taker's next write of that device answers 404 and ends it. |
| A lease write | Only `If-Match` writes exist, so a late renewal on the old ETag fails once the taker wrote. | Nothing to close. |
| *Added in the review of work package 6.* A state write sent by a holder whose two clocks both stopped, after it woke | It believes it holds and sends writes until its next renewal is refused: at most one keeper period (5 s) plus the request's latency (10 s at most). | The same as the rows above for the kind of write; the conditional renewal ends it. No check of its own clocks can see this pause. |
| *Added in the review of work package 6.* Bytes the holder handed to the kernel before its end | They may leave the host after the end, and the store applies them as a request sent before the end. | The drain, as for any late request. |

**A paused process.** The holder decides by its monotonic clock. A process whose clock does not advance while it is paused (a suspended VM, depending on the hypervisor; a suspended host) can wake believing its lease is still good and send requests after the taker took over. The holder also checks the wall clock against its last confirmed renewal and stops when either clock says the lease is over; a pause that stops both clocks is the residual, bounded by the conditional writes, the tombstone re-read and the client's re-sent revokes above.

**The exit rule.** *Changed after the review (M2).* A conditional write answered 412, 404 or 409 that a read-back does not explain (equal bytes is success) ends the writer: it stops serving, closes the tunnel and exits without releasing the lease, because it cannot tell whether the lease it holds is still the one it wrote. A spurious exit (a store fault, a delete marker added by an administrator over a tombstone) costs one identity an outage of about one lease period plus the drain and the load, as an unplanned fail-over does. The metric `store_conflict_exits` (by status and object kind) makes a repeated one visible; `spo-relay store inspect` shows its cause.

**Old tunnel versus taker.** *Changed after the review (m5).* The holder starts closing its tunnel at its lease end and the close is bounded by the margin, so its engine is gone at least 10 s before the taker even takes the lease, and at least 25 s before the taker starts its tunnel (the drain and the load come between). A teardown that is stuck is ended by the process exit (status 3): the engine is in the process. If the process cannot exit, the key may be live twice at DERP and the identity is unreachable until it is gone; that is a loss of availability, not of safety, because the old holder sends no store request after its lease end.

#### Fail-over a user sees

*Changed after the review (m4).* From the defaults above and the code's timeouts; none of it is measured.

* *Planned (rollout, drain).* The active pod gets SIGTERM, ends its sessions and closes the tunnel within 20 s (`relayhost.DefaultTeardown`), waits for its requests, writes the lease released and exits. The next pod takes the released lease at once (a standby within its 5 s poll; otherwise when it has started), lists the store (seconds at small sizes, up to about a minute at a full store of 262 thousand entries) and starts the tunnel; the region is in the configuration, so there is no region probe. Gap for that identity: the teardown, the start of the next pod, the load and the tunnel start.
* *Unplanned, the lease alone (changed in the review of work package 6, 2026-11-20).* From the holder's last confirmed renewal: the waiter's first read that shows it within one poll (5 s) and one read (10 s at most), the take-after time (40 s), the take (10 s at most), the drain (15 s, renewing) and the drain's last renewal (10 s at most): 90 s in the worst case, about 57 s in the usual one. An absent lease object costs the same. The holder itself stops serving 17.5 s after its last confirmed renewal was sent (its term less the guard).
* *Unplanned, with a standby (stage 4).* Worst case: the lease period and the margin (40 s) plus one poll (5 s), the drain (15 s), the load (up to about 60 s), the tunnel start (up to about 60 s when DERP is slow to answer (review)) and the device's backoff for that relay (up to 2 minutes, below): about five minutes in the worst case, much less in the usual one.
* *Unplanned, one pod per identity (stages 1 to 3).* A crashed container restarted in place is a new process with a new holder id, so it waits out its own predecessor's lease (40 s) before the drain and the load. A pod lost with its node waits first for Kubernetes to notice the node and move the pod, which with the default tolerations takes about five minutes (memory), and then for the lease to lapse.
* *What a device sees.* Sends go on through the other identity at once ("delivered when one stored it"). The failed identity's member of `mailbox.Multi` is paused with its own backoff, 1 s growing to 2 minutes (`defaultMultiBackMn`, `defaultMultiBackMx`), so its fetches resume within two minutes after the identity is back. Mail queued only at the failed identity waits for it; the store keeps it, so nothing is lost.

#### Stages

*Changed after the review (m7).* The warm standby moved from a required stage to an optional one, after measurement.

* **Stage 1: stateless pods, current protocol.** No volume; the object store; the full region in the configuration; the key without an init container; one writer by the lease; health and metrics; the configuration rolled out by restart; migration from a directory store.
* **Stage 2: two or more identities per operator.** Their placement on different nodes and zones, the multi-relay test, and the measurement of the fail-over gaps on real infrastructure.
* **Stage 3: the shared operator tombstone set** (decided, decision 3).
* **Stage 4, optional: a warm standby per identity.** Built only if stage 2's measurement of a node loss shows the gap matters with two or more identities.
* **Not staged:** C and D.

### 6. The relay key when there is no volume

The relay key is not a decryption key for mail: envelopes are sealed to device X25519 keys (ADR 0005) and the relay holds none. It is the tunnel's static WireGuard key and pre-shared key. Whoever holds it can pose as the relay, see the relay's metadata and drop or delay mail, and opens nothing. This record reads "the server cannot decrypt anything" as holding for every source below; the owner is asked to confirm that reading ("Open questions for the owner", m8).

**Who can read it, per source.** In a cluster, each of these is equivalent to holding the key whatever the source: creating a pod in the namespace that mounts the Secret or uses the relay's service account; `pods/exec` or `pods/attach` on the relay pod; `pods/ephemeralcontainers` on it (which the SIGHUP reload of the first how-to needs); and the node's root. With a Secret, also `get`, `list` or `watch` on Secrets in the namespace, and whoever reads etcd or its backups unless Secrets are encrypted at rest.

| Source | Readers beyond the list above | Work |
| --- | --- | --- |
| 1. A Secret mounted as a file, read directly | Secret readers (`get`, `list`, `watch`), etcd and its backups | `relayconfig.LoadKey` accepts, besides today's form, a regular file owned by root, with no write bit, readable by group only when the group is the process's, in a directory owned by root: the shape kubelet gives a Secret volume with `fsGroup`. The init container goes. |
| 2. The key file encrypted by a cloud KMS (encryption context: the relay's public node key), the ciphertext in the store or the ConfigMap, unwrapped at start with workload identity, kept in memory only | Principals the KMS key policy lets decrypt, which is only the relay's role | A KMS client in the relay (the AWS SDK's, confined like the S3 one; `vaultkms/sigv4.go` cannot be reused, decision 11). |

**Decided (owner): source 2 as the target, source 1 built first.** Source 1 is acceptable where Secret readers are only the operators. The namespace should grant `pods/exec`, `pods/attach`, `pods/ephemeralcontainers` and pod creation to no one but the operators, whatever the source, and the reload needs none of them (decision 9).

### 7. The fixed address: a full DERP region (stage 1, before any cluster use)

A disposable pod restarts and moves, and the region is picked again at every start (decision 1), so the address must not depend on where the pod runs or on what a map says that day.

*Changed after the review (M4).* **Decided.** A table `[derp_region]` (a full region: id, code, nodes with host names, addresses and ports) is **required** when the store is an object store. The adapter sets `tailcat.Server.Region` from it and no map is fetched. At start the relay decodes its own address and compares the encoded region in it, byte for byte, with the encoding of the configured region, and refuses a mismatch; a rebuild cannot change it. A key `derp_region_id` (a region of the map) stays allowed on a host only, with the warning that the address changes when the provider's map changes; it is not the cluster default and the deployment checks refuse it in a cluster `relay.toml`. The earlier text, which offered the region id for the public DERP and called it a pin, was wrong: an id fixes the region, not the address (decision 5).

**The DERP map is trusted through TLS to a third party** (`https://tailcat.dev/derpmap.json` by default (source)) only when a region id is used. With a full `[derp_region]` the relay fetches no map at all and that trust is gone; the cost is that a change of the provider's DERP host names must be copied into the configuration, and devices then need the new address (a `party relay add` again). `spo-relay check-config` prints the region the configuration encodes, so the operator can compare it with a current map before a change.

### 8. Wake-up and long-poll without shared memory

Under option A the put and the fetch of one identity run in one process. The in-process `notifier` stays as it is (`session.store` calls `srv.notes.wake` after a stored put). Nothing is shared between pods, so nothing more is needed. For the record: polling a store with a 2 s bound for 1024 parked fetches would be about 500 listings a second, some 44 million a day, of the order of 200 USD a day at a list price of about 0.005 USD per thousand (memory, order of magnitude); store notifications add a queue service. Neither is needed.

### 9. Configuration changes

With disposable pods every restart is unplanned, and today a configuration edit other than the device list is refused at SIGHUP but takes effect silently at the next restart. Decided:

* **Every change is a rollout.** The ConfigMap is made by a kustomize `configMapGenerator` with its hash suffix, so any edit, the device list included, changes the pod template and rolls the Deployment. A running pod never meets a changed file. No SIGHUP and no ephemeral container are needed in the cluster.
* **What is in force is visible.** The relay logs the Blake2b-256 of its configuration file at start (`config=<16 hex>`), writes it into the health file, and `spo-relay check-config` prints the same hash, so the operator can compare.
* **On a host** SIGHUP stays as it is (device list only, everything else refused). The relay also re-reads the file at start and logs its hash, so a later restart picking up a refused edit is seen in the log.

### 10. Threats added by an external store

**The store's operator sees what the relay sees**: fingerprints, arrival times and hashes in the names (OUT-012); sizes; wallet key hashes, devices and expected-sender lists in the binding objects; sealed envelope bodies. Nothing in the buckets opens an envelope.

| Action by the store's operator | Effect | Defence |
| --- | --- | --- |
| Withhold or delete envelopes | Mail lost | Outbox re-puts; other identities. As a hostile relay (ADR 0014 threat table). |
| Replay an old envelope | Delivered again | The recipient's replay log and expiry (ADR 0005 steps 5 and 7). |
| Roll back bindings | Older bindings return | Harmless: the device presents its current binding; an older one is refused; every binding is checked against every tombstone version at load. |
| **Hide, roll back, delete or empty tombstones** | **A revoked binding is accepted again for up to 180 days** (ADR 0014 decision 7: the reason the registry is durable) | Locked tombstone versions read from a version listing (decision 3); the deny on simple deletes; the marker; the client re-sends pending revokes until the revoked binding's end (ADR 0014 decision 8). What each mode leaves: below. |
| Add fake tombstones or entries | A fake tombstone refuses the bindings it names (denial of service); a fake entry is refused by its recipient | The bucket policy: only the identity's role writes. A tombstone carries no signature today. |

**Locked tombstones.** *Changed after the review (B1, M3).* Each tombstone version is written with an Object Lock retain-until date of its not-before plus the maximum binding lifetime plus the skew, which is when `relaybind.TombstoneExpired`, with the `Core`'s skew margin, lets the sweep drop it (SPO-Xmailbox-OUT-079). A raise is a new version with its own later date; the older version keeps its earlier one (doc: "Different versions of a single object can have different retention modes and periods"). Retention protects a version, not a name: "Retention periods and legal holds don't prevent new versions of the object from being created, or delete markers to be added on top of the object" (doc: <https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html>). That is why the load reads versions and ignores delete markers.

**Governance or compliance.** *Changed after the review (the Object Lock mode).* The owner accepted governance mode on the earlier recommendation. The review shows that it does not stop an account administrator, and the documentation agrees:

* *Governance:* a version can be deleted early by a principal with `s3:BypassGovernanceRetention` who sends the bypass header (doc above). The bucket policy denies that permission to everyone, but an account administrator can change the policy and grant it to himself. So governance stops the relay's role and anyone without IAM rights over the bucket; it does not stop the account's administrators, or whoever takes over an administrator's credentials. Its benefit is that a mistake can be undone.
* *Compliance:* "a protected object version can't be overwritten or deleted by any user, including the root user", the retention cannot be shortened, and the only way to remove it early is to delete the account (doc above). Its costs: a mistaken retention date cannot be undone, and fake tombstones written with a stolen role stay until their date. Both are bounded here: a not-before is at most the relay's time plus the skew (`VerifyRevoke`, `ErrRevokeFuture`), so no retention runs past about 180 days and a day; the objects are 15 bytes; and a fake tombstone is a denial of service that a stolen role could cause anyway.

*Changed after the review of work package 8.* The bound above holds only for what the relay writes from verified revokes, and only while its clock is right. Now: the relay refuses to write a tombstone lock that ends more than 180 days, twice the skew and an hour after its clock (SPO-Xobjstore-PRE-808), and a clock far ahead cannot write at all, because the store refuses a request signed more than 15 minutes from its own clock (memory). The policy denies of decision 3 stop the role from writing a longer retention or a legal hold. What a holder of the relay's role can still do, stated plainly: write locked versions of its own choosing, up to 182 days of lock each. A version whose body is not a tombstone, or whose not-before is far ahead, no longer refuses the start; it revokes the one scope its name names until its lock ends (SPO-Xobjstore-PRE-809), so the cost is that scope (a denial of service the role could cause anyway). An object under the tombstones whose name is not a tombstone is ignored. A junk version over the marker is ignored while the relay's marker is under it. What still refuses every start: more than 1 048 576 versions under the tombstones (about 5 dollars of requests at AWS's price for writes), or more than 4096 entries of the marker's listing, written by that holder; in compliance mode they cannot be removed before their dates (at most 182 days with the deny, or the account's maximum without it), and the recovery is a new identity (a new prefix: `init-store` with a new node key, and every device registers again).

**Recommended: compliance mode** for tombstones and the marker in the registry bucket, because the threat it answers is the one this record exists for (the loss of tombstones re-opens revoked bindings), and the person most able to cause that loss is whoever controls the account. Governance only for a test deployment. The choice is the one open owner question. With either mode the version-aware load means that delete markers and lower versions remove nothing, and an administrator who edits the policy can still delete versions only in governance mode.

**What a partial rollback can still do.** *Changed after the review (m6).* The marker catches an empty or wrong prefix only. With the version-aware load, an operator who hides or overwrites some tombstones achieves nothing. In compliance mode no tombstone version can be removed before its date, so no partial rollback of tombstones is possible at all. In governance mode a principal who obtained the bypass can delete chosen versions, and the relay cannot tell: those revokes are lost until the clients re-send them. A rollback of bindings returns older bindings, which the tombstones still refuse. A rollback or loss in the working bucket loses or replays mail and lease state, as a hostile relay can.

**A signed monotonic head of the registry** is not adopted: a stateless pod remembers no earlier head to compare with, and anchoring one elsewhere needs another store or a protocol change. Locked tombstone versions and the marker close the case that matters at the store.

**Credentials.** Workload identity only (IRSA or EKS Pod Identity, Workload Identity Federation on Google Cloud, a web-identity role for an S3-compatible store that supports it). The adapter refuses credentials that do not expire or live more than 12 hours, as `objstore/s3.requireShortLived` does (source). Anyone who can create a pod with the relay's service account gets the role too, so pod creation in the namespace is an operator right.

**Encryption at rest** (SSE-KMS with a key only the identity's role may use) protects against a reader of the buckets' disks or copies without the role. It does not hide names from the buckets' operator; keyed names would, and are deferred. With SSE-KMS the ETag is not the MD5 of the body (memory); the lease does not depend on that, because "unchanged" also compares the counter, and the self-test checks that different bytes give different ETags.

**A crash between a revoke and the mailbox removal.** *Changed after the review (m2).* The session drops a revoked device's queued mail after `Revoke` returns (session obligation 14, SEC-069). A crash in between leaves that mail in the store; the next load sees the tombstone, drops the binding, and keeps the queue, as it keeps the queue of any lapsed binding. The directory store has the same gap. The mail is sealed to the revoked device's keys and can be fetched only by a device that logs in again with a binding the tombstone does not refuse. Recorded, not reconciled: a reconcile at load cannot tell a revoked device's queue from a lapsed one's except for the device scope, and purging on that alone would be a new rule for one scope.

### 11. Harder than expected

* **The S3 code cannot be linked into the relay as it is.** `adapters/objstore/s3` implements `ports.ObjectWriter` and its family and imports `internal/ports`; SPO-Xmailbox-IF-001 keeps the relay ports in `relayport` "so that the relay's code does not link what `internal/ports` links". The client part (credential rule, https rule, timeouts, conditional create) must move to a package that imports no `internal/ports`.
* **The existing S3 client is create-only.** `objstore/s3.Store.Put` sends only `If-None-Match: *`. The relay also needs `If-Match` overwrite, delete by name and by version id, prefix listing with sizes, version listing, retention headers, a SHA-256 checksum header, per-request deadlines and the classification of 404, 409 and 412.
* **The hand-written SigV4 cannot be reused.** `adapters/vaultkms/sigv4.go` takes its secret as a `*secret.Buffer` and imports `platform/secret`, which ADR 0013's architecture test forbids in the relay. Key source 2 uses the AWS SDK's KMS client (`service/kms` is not in `spo/go.mod` today (source), so it changes the vendored set and the Nix `vendorHash`).
* **The region is picked at every start and is not wired.** `stream.ListenerConfig` has `Region` but no `RegionID`; `relayhost.TunnelSpec`, `relayconf.Config` and `cmd/spo-relay.listenerConfig` have neither; `Listener.install` fails the listener when a rebuild yields another address. A region id does not give a stable address (decision 5).
* **The stores are directories in the types.** `relayhost.Deps.OpenMailbox` and `OpenRegistry` take a directory string; `relayconf.Config.MailboxDir` and `RegistryDir` are required absolute paths, compared by `SameExceptDevices`.
* **The start order.** `relayhost.Start` opens the stores, the server, then the tunnel; the lease must come before the load and the tunnel, and its loss must end `Relay.Run` as a stuck teardown does now.
* **The put path streams to a temporary file** (`mailboxstore`, `stepTmpCreated` to `stepLinked`). With the object store the body waits in memory until the hash is checked, and the port text changes (decision 2).
* **A refused drop fails a revoke today.** `bindingstore.Store.execute` stops at the first failed operation, and a revoke's plan puts its drops before its tombstone (decision 3, "The registry core").
* **A full listing at start**: up to about 262 thousand mailbox objects, a few thousand bindings, and one GET per tombstone version, before serving.
* **No tunnel-up signal is exported.** `stream.Listener.Stats` counts accepts; whether tailcat reports the DERP home connection's state was not found. Health must mean "tunnel up and store reachable" (decision 13), so the adapter must expose one.

### 12. Work packages

*Changed after the review (M8).* Re-numbered. Each is built test first, ends with a mutation pass and runs in the container with no network, as the earlier packages did.

**Stage 1: stateless pods, current protocol.**

1. **Full region in the configuration.** `[derp_region]` in `relayconf`, `TunnelSpec`, `cmd/spo-relay` and `ListenerConfig.Region`; `derp_region_id` for a host only; the start compares the encoded region of its address with the configured one. *Done when:* over the in-process tunnel harness, two starts with one `[derp_region]` give byte-equal addresses, also when the map stand-in serves a changed region in between (no map is fetched); a start whose address encodes another region is refused; an object-store configuration without `[derp_region]` is refused; with `derp_region_id`, a changed map gives a changed address and the warning is logged. Comes before any cluster use. (Being built now with this correction.)
2. **A narrow S3 client without `internal/ports`**, used by the backup sink and the relay: `If-Match`, delete by name and by version id, listing with sizes, version listing, retention headers, the SHA-256 checksum header, per-request deadlines with no retry past them, 404, 409 and 412 told apart, the start-up self-test of decision 2. *Done when:* the backup sink's tests pass unchanged; `go list -deps ./cmd/spo-relay` holds no `internal/ports`, `platform/secret`, `age` or `sqlitestore`, and the architecture test says so.
3. **An in-process S3 stand-in, honest and hostile.** Versioning, delete markers, retention and a bucket-policy emulation; ETag = MD5 of the body. Hostile modes: lost response after commit, conflict storm (412, 404, 409), stale listing, rolled-back object, withheld object, replayed old version, a lower version written over a tombstone, a delete marker over a tombstone or the marker, a simple delete under the deny, a delete by version under retention, a request applied after its client gave up, slow body, a second writer. *Done when:* the honest stand-in passes the self-test and each mode that breaks a required property fails it.
4. **Registry core changes** (decision 3, "The registry core"). Drops planned on their own; `Core.Hold` for a refused drop; the unrecorded path when no room is left; refused sweep drops skipped and counted; export and load of the two rate buckets; the version ceiling as a constant. *Done when:* the registry suite passes over the in-memory registry and `bindingstore` unchanged otherwise; with a stand-in that refuses every drop, an invalidating revoke at a full table deletes its bindings and returns `ErrTombstoneUnrecorded`, and one that invalidates nothing returns `ErrTombstoneFull`; the spec ids of decision 3 are amended.
5. **Ports.** `relayport.Lease` (acquire, renew, release, a channel closed on loss, the lease end for request deadlines) with a contract suite; a typed store specification; `relayhost.Deps` takes it; the directory lease is the existing `flock`; the `MailboxWriter.Put` text amended (decision 2). *Done when:* the directory adapters pass the lease suite and are otherwise unchanged.
6. **The object-store lease.** *Done when:* under the stand-in with paused and slow holders, stepped wall clocks and requests applied late, two holders never both hold it; a renewal always changes the ETag and the counter; a holder that cannot renew sends no request after its lease end and stops within the duration; a taker of a lapsed lease waits the drain period before it lists; a released lease is taken at once; a lease of another node key refuses the start.
7. **The object-store mailbox adapter.** *Done when:* `relayporttest.RunMailboxStore` passes with `Reopen`; the hostile suite shows read-back on a lost response, exit on an unexplained conflict, refusal of a damaged body by the checksum, the bound of 64 held bodies, and that a crash at every step leaves what the directory store would.
8. **The object-store registry adapter**, over the same `Core`: one name per scope key, raises with `If-Match`, retention on every version, the version-aware load and its ceiling, the 60 s re-read, the marker in both buckets, the rate object with `If-Match`. *Done when:* the registry suite passes with `Reopen`; a rollback of binding objects leaves every revoked binding refused; a delete marker or a lower version over a tombstone changes nothing at load; a simple delete of a tombstone is refused by the policy emulation and a delete by version under retention by the stand-in; a tombstone written late by a second writer is enforced within 60 s; an empty prefix refuses the start.
9. **Store tools.** `spo-relay init-store` (both markers, the bucket checks with the operator's credentials); `spo-relay migrate-store --from <directories>` (offline, under the directory lock: every tombstone with its retention, every binding, optionally the queues; verified by reading the version-aware view back and comparing, per scope key, the maximum not-before and the counts; the markers written last, so a relay never starts on a half-copied prefix); `spo-relay store inspect`, `verify` and `repair` (the version-aware tombstone view per scope key: maximum, versions, retention, delete markers; every name checked; repair removes delete markers over tombstones and the marker and never deletes a tombstone version). *Done when:* a migrated directory store, loaded by the object adapter, refuses every binding the directory store refused, over a fixture with tombstones of all three scopes; a migration interrupted at each step leaves a prefix the relay refuses; repair over the hostile modes of package 3 restores the view without deleting a version.
10. **Assembly and configuration.** `[store]` (two buckets), key source 1, the start order (lease, drain, load, tunnel), the end of `Run` on a lost lease or an exit-rule conflict, `check-config` running the self-test and printing the configuration hash and the encoded region. *Done when:* the `relayhost` end-to-end test runs over both store kinds; a lost lease stops serving within the bound.
11. **Health and metrics** (decision 13). *Done when:* each state is reported; a stalled loop fails liveness; a lost lease or a tunnel that is down fails readiness; the metrics (requests by kind; 412, 404 and 409 by object kind; exit-rule exits; lease state, generation and renewal age; load time; tombstone versions; held bodies) are in the health file and in one log line a minute, and `spo-relay health --metrics` prints them.
12. **A request-cost guard.** A configured ceiling on store requests an hour (default from the defaults' worst case, to be set from package 11's figures). Above 80 % it logs; above the ceiling it answers new puts as a store failure and slows the sweep, never the lease, the tombstone re-read or a revoke. *Done when:* a flood of puts over the stand-in stays under the ceiling and every revoke is still recorded.
13. **Manifests and checks** (decision 13). *Done when:* `spo/test/deploy` enforces each new rule and `TestEveryCheckBites` breaks each one.
14. **Key source 2** (KMS-wrapped key). *Done when:* the relay starts with no Secret, a wrong encryption context refuses the unwrap, and the key never reaches a file or the log.
15. **Documents and specification.** Both how-tos; new requirements in [Xmailbox](../../../spec/extensions/Xmailbox.md) for the object-store adapters, the lease, the marker, the full region, health, metrics and the tools (new ids, none renumbered); the amended ids of decision 3 and the port text of decision 2; the handoff. *Done when:* `nix flake check` passes.

**Stage 2: two or more identities per operator.**

16. **Manifests for two identities**: anti-affinity between identities across nodes and zones, the overlay for two identities, two prefixes and two roles. *Done when:* the checks require them.
17. **The multi-relay test.** `test/multiparty` over two identities on `fakenet`: kill one identity's pod mid-exchange; sends are delivered through the other; the replacement waits out the lease and the drain, then serves the killed identity's queue; nothing is lost. *Done when:* it passes under the race detector with the leak check.

**Stage 3: the shared operator tombstone set.**

18. **`operator/tombstones/`** (decision 3). *Done when:* a revoke recorded at one identity is enforced by the other within 60 s with the client cut off from the second; a conflict in the shared prefix re-reads and does not exit.

**Stage 4, optional: a warm standby per identity.** Only if stage 2's measurement asks for it.

19. **Standby mode.** A pod that does not hold the lease checks its configuration and credentials, keeps its store client ready, starts no tunnel, and reports `standby`. *Done when:* in process, the standby never starts an engine while the lease is held, and takes over within the lease duration plus the margin, a poll, the drain and the load after the active one is killed; a planned stop hands over at once.
20. **Manifests for two pods per identity** (`replicas: 2`, `maxSurge: 0`, `maxUnavailable: 1`, anti-affinity between the two pods of an identity, a disruption budget per identity). *Done when:* the checks require them.

**What only real infrastructure can show** (no stand-in proves these):

* For each product on the allow-list: that it answers 412 for `If-Match` and `If-None-Match: *`, that exactly one of two racing conditional writes wins, that it honours retain-until dates per version, refuses a delete by version under retention, keeps a version under a delete marker, gives different ETags for different bytes, and lists strongly after a write.
* That a full `[derp_region]` gives the same address on another node or zone, and devices reach it (the handoff's manual row 37 is the open form of this).
* That a standby without a tunnel does not disturb the active pod at DERP, and what the DERP server in use does with two connections of one key (to observe once; the design avoids it).
* The start time with a full store, the fail-over gaps planned and unplanned (a node loss included), memory at the defaults, and the daily request cost.
* How late a store applies a request whose client gave up (the drain period's assumption).
* That the IRSA webhook injects its projected token with `automountServiceAccountToken: false`; the network-policy entries for the store, STS and, on GKE, the metadata server.

### 13. Kubernetes consequences

**Per relay identity:**

* A **Deployment** with no claim, `replicas: 1`, `strategy: Recreate`. The lease, not the workload kind, is the at-most-one guarantee.
* *Changed after the review (M7).* **Stage 4 only:** `replicas: 2`, `RollingUpdate` with `maxSurge: 0` and `maxUnavailable: 1`. The earlier text said this replaces the standby first. Kubernetes does not promise that: the ReplicaSet controller picks which old pod to delete by its own ranking (memory: unready before ready, then the `controller.kubernetes.io/pod-deletion-cost` annotation, then the younger pod). Steering it would need the active pod to set its own deletion cost through the API, which needs an API token and patch rights on pods, which this record refuses (decision 2's reasons for not using the API). Making the standby unready would steer it but stalls the rollout (the new standby is unready too, so the active one can never go). Accepted: the active pod may go first. Its release is planned and quick (decision 5), and a rollout may then cost an identity two planned hand-overs instead of one.
* **No init container.** Source 1 mounts the Secret read-only into the relay container; source 2 mounts nothing.
* **Volumes**: the hash-suffixed ConfigMap, the Secret (source 1), a memory `emptyDir` for `/tmp` and `/run/spo-relay` (the health file). Read-only root, user 10001, no capability, `seccompProfile: RuntimeDefault`, no host namespaces, no service links: unchanged.
* **Service account**: annotated for workload identity; `automountServiceAccountToken: false` stays.
* **Probes.** The run loop writes `/run/spo-relay/health` every 5 s, atomically: the state (`starting`, `waiting`, `draining`, `loading`, `serving`, `stopping`; `standby` in stage 4), the lease generation and counter, the configuration hash, the metrics and the time. It writes only after a confirmed lease renewal (store reachable) and, when serving, only while the tunnel adapter reports its engine up and no stuck teardown. `spo-relay health --live` succeeds when the file is younger than 30 s; `--ready` when it is younger than 15 s and the state is `serving` (stage 4: `serving` or `standby`). `exec` probes only: no port on the pod network, so no scrape endpoint either; a metrics port is deferred. A `startupProbe` covers the lease wait, the drain and the load. A file was chosen over an abstract Unix socket because it works on every host and is easy to test.
* **Disruption budget.** The one budget over all relays (`maxUnavailable: 1`) stays; with a real readiness signal it now protects a serving relay, not only a running process. Stage 4 adds one per identity with `minAvailable: 1`, which allows the standby to be drained and blocks draining both pods of an identity at once.
* **Network policy.** Default-deny and DNS unchanged; no ingress rule. Egress needed: DNS, and TCP 443 and UDP 3478 to public addresses for DERP and STUN; with a full `[derp_region]` there is no map fetch. The store adds its destinations. On AWS use an S3 **gateway** endpoint: its traffic goes to S3's public address ranges, which the existing public-443 rule already allows, so no private range opens (memory: that gateway endpoints route by prefix list to public ranges). An **interface** endpoint has private addresses; name exactly those addresses as `/32` `ipBlock` entries, never a private range. STS is public 443. On GKE, Workload Identity needs 169.254.169.254 port 80 (memory), allowed on GKE only. Standard NetworkPolicy cannot name hosts; a plugin's FQDN policy may narrow 443 further and is optional.

**What of `deploy/kubernetes/relay/` survives**: the kustomize layout (`base/shared`, `base/instance`, `overlays/example`), the namespace with the `restricted` Pod Security Standard, the service account (annotated), the network policies (amended), the shared disruption budget, the ConfigMap (now hash-suffixed), the `Containerfile`, the security context, the anti-affinity and the 45 s grace period. Gone: the StatefulSet and its claim, the init container and its busybox image, `fsGroupChangePolicy`, the 10 GiB request, the SIGHUP-by-debug-container procedure and the how-to's "Backup of the volume". `spo/test/deploy` changes with them: no claim and no init container; probes required instead of forbidden; `[store]` and `[derp_region]` required in every cluster `relay.toml` and `derp_region_id` refused there; no static cloud key; one prefix and one role per identity.

## Threat model (additions only)

| Threat | Mitigation | Residual |
| --- | --- | --- |
| Store operator reads the buckets | Envelopes sealed; SSE-KMS against readers without the role | The relay's metadata. |
| Store operator hides, rolls back, deletes or empties tombstones | Locked versions read from a version listing; the deny on simple deletes; the marker; clients re-send revokes | Compliance mode: none before a version's date. Governance mode: an account administrator can grant himself the bypass and delete versions. A product without per-object retention is refused for the registry bucket. |
| Store operator withholds, deletes or replays envelopes | Outbox re-puts; other identities; replay log | Delay and loss, as with a hostile relay. |
| Fake objects written into a bucket | Only the identity's role writes its prefix | Denial of service by whoever can write the bucket; in compliance mode fake tombstones stay until their date (at most about 180 days). |
| Two writers on one prefix | The lease; request deadlines at the lease end; the drain period; conditional writes; the exit rule on 412, 404 and 409; the 60 s tombstone re-read; prefix and lease bound to the node key | A request the store applies more than 35 s after its client gave up; a pause that stops both of the old holder's clocks; arrival order and global quota during an overlap. Closed for revokes within 60 s by the re-read and by the clients' re-sent revokes. |
| A standby that connects to DERP with the active key | The standby starts no tunnel; the old holder's engine is closed before the taker takes | A process that cannot exit keeps the key live twice: availability, not safety. |
| Relay key read from the cluster | Source 2; namespace rights for exec, attach, ephemeral containers and pod creation kept to operators | Whoever holds it can pose as the relay; it still opens nothing. |
| Static cloud credentials | Refused by the adapter | A short-lived token is usable by whoever runs code in the pod. |
| Frequent restarts | Stored rate buckets; conservative stranger rebuild | One burst of the two registry caps if the stored state is lost. |
| A silent configuration change at a restart | Every change is a rollout; the hash in the log and the health file | None on a cluster. |
| Request-cost exhaustion | The request-cost guard; the existing per-connection bounds | Puts refused above the ceiling. |

## What changes in the packages already built

| Package | Keep | Change | Remove |
| --- | --- | --- | --- |
| `ports/relayport` | Every port and suite | Add `Lease` and its suite; the `MailboxWriter.Put` text on holding a body | Nothing |
| `app/relay` | Everything | Nothing | Nothing |
| `app/relayhost` | Agreement checks, teardown bound, reload on a host | Store specification, lease first, drain, lost lease or conflict ends `Run`, health file and metrics, `TunnelSpec` region; standby mode in stage 4 | Nothing |
| `domain/relayconf` | Everything | `[store]`, `[derp_region]` and `derp_region_id`, key source | Directories as unconditional requirements |
| `domain/relayregistry` | The `Core` and its plans | Drops planned on their own, `Core.Hold`, export and load of the two rate buckets | Nothing |
| `adapters/mailboxstore`, `adapters/bindingstore` | Everything (the local deployment) | `Lease` by their `flock`; `bindingstore` runs the drops of a revoke on their own | Nothing |
| `adapters/relayconfig` | The file rules | Secret-shaped key file; configuration hash | Nothing |
| `adapters/objstore/s3` | Its behaviour | Built on the moved client | Nothing |
| `adapters/tailcat/stream` | Everything | The configured full region; an engine-up signal | Nothing |
| `cmd/spo-relay` | The shape | Region, store kinds, `health`, `init-store`, `migrate-store`, `store inspect`, `verify`, `repair` | Nothing |
| New: `adapters/relayobj` (name proposed) | | Object-store mailbox, registry and lease | |
| `deploy/kubernetes/relay/` | Decision 13 | Decision 13 | StatefulSet, claim, init container |

## Open questions for the owner

None. Both questions below were answered on 2026-11-19 with the recommendation ("Decided by the owner", items 7 and 8). They are kept for the reasoning.

1. **Object Lock mode for tombstones and the marker.** The owner accepted governance mode on the earlier recommendation. The review, and AWS's documentation, show that governance does not stop an account administrator, who can grant himself the bypass. **Recommended: compliance mode**, whose costs here are bounded (at most about 180 days and a day, 15-byte objects) and whose protection covers the case this record exists for (decision 10). Governance for test deployments only.
2. **The reading of "the server can decrypt nothing by itself".** This record reads it as: the relay key is an identity key (the tunnel's WireGuard key and pre-shared key), not a mail key, so a pod that unwraps it with its own role (key source 2) does not contradict the requirement; nothing the relay holds opens an envelope (decision 6). **Recommended: confirm this reading.** If the owner reads the requirement as covering the relay's own identity too, key source 2 does not meet it and only an operator-held key (unwrapped by a person at each start) would, which a disposable pod cannot have.

## Deferred

* Option C, option D, and anything with several writers on one identity's state; the PostgreSQL adapter that would come with it.
* A streamed put to the object store (decision 2, m1).
* A metrics port on the pod network.
* A signed monotonic registry head anchored outside the store.
* Keyed object names that hide fingerprints from the store's operator.
* A key read by the relay from an external secret store other than KMS.
* Reconciling, at load, the queue of a device revoked just before a crash (decision 10, m2).

## What is not confirmed

* For MinIO and Ceph RGW: per-object retention, strong listing and conditional writes as the allow-list needs them; for R2, any per-object retention; for B2, the reported refusal of `If-None-Match`.
* That exactly one of two racing conditional writes wins on any product other than AWS S3.
* How late a store may apply a request whose client gave up (the 15 s drain period assumes not later than 35 s in all).
* That the ETag of an SSE-KMS object differs for different bytes (the self-test checks it on each start).
* Which pod a ReplicaSet deletes first when scaling down (from memory; the design no longer depends on it).
* The DERP behaviour with duplicate keys in versions other than the module cache's `tailscale.com`.
* That a full `[derp_region]` gives the same address on another node, and that devices reach it.
* That the IRSA webhook injects its token with automount off; the GKE metadata address; that an S3 gateway endpoint uses public ranges; how long Kubernetes takes to move a pod off a lost node with the default tolerations.
* That the Kubernetes Lease protocol is the model the bucket lease follows (from memory; the design does not depend on it).
* The start time with a full store, the tunnel start time, the fail-over gaps, memory, and the request cost (the price in decision 8 is an order of magnitude from memory).
* Whether tailcat exposes the state of its DERP home connection for the health signal.
* How often a store's lifecycle rules run (the registry bucket's binding rule depends on it only for cost).
