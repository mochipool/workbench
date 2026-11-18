# ADR 0013: Tailnet relay and mailbox for sealed envelopes

Status: proposed, 2026-11-18. Revised after an independent review against the code. It details stage 4 of [ADR 0012](./0012-server-backup-and-deployment.md) decision 13 ("the server as a relay for envelopes and the mailbox only") and amends the parts of ADR 0012 decisions 2, 5, 7, 8, 11 and 13 that this record names in "What this changes in ADR 0012". It builds on [ADR 0005](./0005-party-envelope-and-signing-policy.md) (envelope, transport kind, cold-key rule) and [ADR 0010](./0010-object-identity.md) (objects are named by hash). Nothing here is built. Where the text says "confirm", the fact was not established from the repository and is listed again in "What is not confirmed".

## Context

Parties who sign together are rarely in the same place and rarely online at the same time. Today there are two ways to move a signing request or a witness between machines:

* **A carried file.** The operator moves the sealed envelope by hand (`adapters/filebag`, `adapters/transferfile`). It needs no network. It is the only way a pool cold key signs (ADR 0005, "Which keys may sign remotely").
* **A direct tailcat connection.** One side runs a listener (`adapters/tailcat` `Server`), the other dials it (`Client`). Both must be online at once. The listener sends only to a peer that is connected right now (`Server.Send` returns `ports.ErrNoRoute` otherwise), and a `Client` sends only to the one coordinator it was built for.

The first is slow and manual. The second fails whenever the two operators are not online together. ADR 0012 names the missing piece: a server that holds sealed envelopes until the recipient connects. This record designs it.

**What stage 4 is.** A small process, reachable only through tailcat, that accepts sealed envelopes from enrolled parties, keeps them for a bounded time, hands them to the addressed party when that party connects, and forgets them when the party acknowledges. It is its own binary, `cmd/spo-relay` (decision 1). It stores no keys that can open an envelope, and it never opens one.

**What stage 4 is not.**

* It is not the object store, the head log or the devices document. Those are stage 5 and stay blocked on the formal model.
* It is not an authority. Who may ask whom to sign what stays decided by each client's own party registry (ADR 0005). The server's list of parties only decides who may use the mailbox.
* It does not carry cold-key signing. A pool cold key is never signed over a network transport (ADR 0005, D8, ADR 0012 decision 8). The carried file stays the only path.
* It is not a public service. It has no public listener, no HTTP endpoint and no TLS certificate.
* It does not fan a demand out to an operator's several devices. Each device is its own party (decision 2). Fan-out comes at stage 5.
* It does not make operations unattended. Authenticating to the server needs the party's identity key, which lives in the unlocked workspace (see "Authentication").

**Owner direction this record follows.** Tailscale or tailcat is the primary connectivity. Every device dials out. The server cannot decrypt ("The server should not have any way to actually decrypt the files on its own"). Direct device-to-device connection is an optimisation that the application cannot tell from the mailbox path; stage 4 defers it. The interim access list comes from the server's configuration.

**Concerns of `docs/development/go-reference-implementation-concerns.md` this record addresses.**

| Concern | Here |
| --- | --- |
| T2, fail-open authorisation | Addressed. The tunnel allow-list is exactly the node keys of the access list; the relay refuses to start with an empty list (decision 3, work package 3). |
| T3, tunnel identity is not application identity | Addressed. A signed challenge by the party key authenticates each connection, and the envelopes inside stay signed end to end (decision 3). |
| T4, addresses are not confidential enough | Addressed for the relay. The relay address reaches clients through the enrolment ceremony; authorisation never depends on it (decision 7, "Relay address and key lifecycle"). |
| T5, public DERP relays have no SLA | Not solved. Store-and-forward tolerates an outage within the retention window, and the relay may use a self-hosted map through the existing `DERPMapURL` setting. Unmeasured; see "What is not confirmed". |
| T7, exposure | Addressed for the relay: bounds table, checks before allocation, no public listener. |

T1 (upstream stability) is handled by keeping the stream ports small. T6 (enrolment ceremony) is reused, not changed.

## Terms

* **Envelope**: the ADR 0005 unit: an `age` ciphertext sealed to one recipient's X25519 key, containing a signature by the sender and a signed payload with the recipient's fingerprint, a message id, creation and expiry times and the body. At most `party.MaxEnvelopeBytes` (1 MiB).
* **Party identity**: an Ed25519 signing key and an X25519 encryption key. Its **fingerprint** is `party.FingerprintOf(ed, x)`, 20 bytes. In the code one enrolled machine is one party identity (`party.Identity`). Each device of an operator is its own party for stage 4.
* **Node key**: the tailcat (WireGuard) public key of a machine. `party.NodeKey`, 32 bytes.
* **Mailbox**: the server's set of stored envelopes for one recipient fingerprint.
* **Envelope hash**: Blake2b-256 of the envelope bytes. It is the same function that names layout objects (SPO-Xlayout-OUT-001). It is called `mid` below ("mailbox id") to keep it apart from the message id inside the seal, which the server cannot see.
* **Relay**: this server process, `spo-relay`. It is not one of tailcat's "DERP relays". Those are Tailscale's public packet relays that carry WireGuard ciphertext when two nodes cannot connect directly. This record always says "DERP relay" for those and "the relay" for the mailbox server.
* **Interim access list**: the server's configuration list of parties that may use it (ADR 0012 R1). The devices document replaces it at stage 5.

## Decision

### 1. Architecture

```
  operator A, device 1                 operator A, device 2
  spo (unlocked workspace)             spo (unlocked workspace)
  own party, own mailbox               own party, own mailbox
        |  dials out                         |  dials out
        |  tailcat stream                    |  tailcat stream
        v                                    v
   +----------------------------------------------------+
   |  tailcat tunnel (WireGuard, DERP relays carry only |
   |  ciphertext; only allow-listed node keys connect)  |
   +-------------------------+--------------------------+
                             |  accepts, never dials
                             v
                 relay: spo-relay (own binary)
                 - access list (signed identity documents)
                 - mailbox store (sealed envelopes by mid)
                 - no identity key, no workspace, no age

  operator B, device 1  --dials out-->  (same relay)
```

**The relay is its own binary.** `cmd/spo-relay` is a separate `main`, not a second mode of `spo`. An architecture test runs `go list -deps` on it and fails if the result contains `filippo.io/age`, `adapters/sqlitestore`, `adapters/envelope`, `platform/secret` (and so memguard) or `domain/unlock`. `domain/custody` is not on the list: `domain/party` imports it, it is pure data and rules about key roles and signing capability with no key material and no I/O, and the relay needs `domain/party`. That is a proof by the build graph that the relay cannot open an envelope, which a flag inside the one binary could not give. **Trade-off, owner-visible:** it costs the "one binary" goal of ADR 0009 (one command tree). `spo` still has a single tree. The relay is the one extra artefact, and it is also the one that runs on a host the operators may not control. This is a decision, not a question, but the owner should know it.

**Who dials whom.** Every client dials out to the relay. The relay only accepts. A device never accepts a connection for the mailbox. This is the existing coordinator pattern turned around: the always-on side is the listener, and in tailcat a listener is a virtual one inside the tunnel (`ts.Listen` with `ServedTCPPorts`), not an operating-system port. That reading of tailcat is taken from `adapters/tailcat/server.go` and is **to confirm** on a real run: that the relay host needs no open inbound port at all, only outbound access to the DERP relays and STUN.

**Near-real-time delivery without a direct path.** A `Fetch` may wait up to 20 seconds on the relay and is answered the moment an entry arrives. A client that is connected and polling therefore receives a request within a moment of the put. `--transport tailcat` (the existing direct path) stays available as wiring. A router that sends direct when both parties are online and falls back to the mailbox is deferred past stage 4.

**Components.**

| Component | Where | Does |
| --- | --- | --- |
| Relay session logic | `app/relay` (new) | Challenge, authentication, put, fetch, ack, quotas. Pure over ports. |
| Mailbox store | `adapters/mailboxstore` (new) | Its own type. Wraps the `objstore/dir` write path and adds `Remove` (decision 7). |
| Access list | `adapters/relayconfig` (new) | Reads the server configuration: signed identity documents. |
| Stream listener and dialer | `adapters/tailcat` (extended) | Gives the relay and the clients an authenticated byte stream and the peer's node key. |
| Mailbox client | `adapters/mailbox` (new) | Implements `ports.EnvelopeSender`, `ports.EnvelopeReceiver` and `ports.EnvelopeAcker` over the wire protocol. |
| Domain types | `domain/mailbox` (new) | Limits, `Hash`, message types, status codes, canonical CBOR shapes, `AuthBytes`. |
| Relay main | `cmd/spo-relay` (new) | Wires the above. Opens no store. |

**What the tunnel identity gives, and what it must not be trusted for.**

| Gives | Must not be trusted for |
| --- | --- |
| Only an allow-listed node key can open a tunnel to the relay (`AllowedClients`, never empty: concern T2). | Who the operator is. A node key proves possession of a WireGuard key (concern T3). |
| The peer's node key for each connection (`Server.PeerEnv`, already used by `adapters/tailcat`). | Authority to act for a party. A stolen device has its node key. |
| Confidentiality and forward secrecy in transit; the DERP relays see ciphertext. Both WireGuard static keys are authenticated by the tunnel handshake. | Revocation. tailcat cannot remove a key from its allow-list while it runs (ADR 0005); the relay refuses a revoked node key itself and closes its connections. |
| Possession of the pre-shared key in the address, one more barrier. | Secrecy of the address (concern T4). It is a barrier, not an authenticator. |

So the tunnel is **transport admission only**. The relay then makes the client prove, with the party's own Ed25519 key, that it is the listed party (decision 3). The envelope inside is checked by the receiving client exactly as ADR 0005 says, whatever the relay did.

**What the relay holds.** The tailcat node key and pre-shared key of the relay itself (they let it terminate tunnels addressed to it; they are not envelope keys), the access list, and the stored envelopes. It holds no party identity, no X25519 private key, no workspace store and no vault key.

### 2. The mailbox model

**Addressing: by recipient party fingerprint.** The mailbox of an envelope is the 20-byte fingerprint of the party it is sealed to. The sender states it in the put header, because the relay cannot read it from the envelope (the envelope is an `age` ciphertext; the recipient fingerprint is inside the signed payload).

The three candidates:

* **Party fingerprint (chosen).** It exists today, it is what `EnvelopeSender.Send(ctx, to party.Fingerprint, ...)` already takes, and in the code one machine is one party identity, so a party fingerprint is a device address. It is what ADR 0012 R1 keys the interim list by.
* **Device key (rejected for now).** ADR 0012 decision 3 adds a separate per-workspace device key, cross-signed by the party identity. It does not exist before stage 5. At stage 5 it is how own devices authenticate (decision 7 here).
* **Session id (rejected).** The signing session and request ids are inside the seal. Indexing by them would need the sender to reveal them, which lets the relay link a request, its answers and its closing notice, and gains nothing, because a recipient fetches everything addressed to it and sorts it out after opening.

**A claimed address is not a proof.** A sender can name any fingerprint. If it names the wrong one, the envelope reaches a party that cannot open it, or opens it and finds a different recipient fingerprint in the signed payload. ADR 0005 step 6 refuses both. The address only routes.

**Message identity: the envelope hash.** `mid = Blake2b-256(envelope bytes)`, lower-case hex in names. The client states it in the put header, then sends the envelope as a raw frame. The relay computes the hash while it streams the body to the store and refuses a mismatch as `bad_hash` without storing.

One consequence the owner should know. The `age` ciphertext differs on every `Seal` call, so two seals of the same payload have two hashes. The hash therefore identifies *these bytes*, not *this message*. That is enough for idempotence: a re-put resends the same stored bytes (the ADR 0005 outbox keeps envelopes sealed), so the hash is the same. A re-seal is a new message with a new message id, and the recipient's replay log treats it as one.

ADR 0012 decision 7 says a mailbox delivery is "keyed by the envelope's message id". That cannot be done by a server that cannot read the envelope. This record keys by hash and the recipient's replay log keeps the message-id duty (ADR 0005 step 7).

**No fan-out in stage 4.** Each device is its own party with its own identity, its own node key and its own mailbox. A demand goes to the one fingerprint that the slot assignment names. One device's ack never deletes another device's copy, because there is no other copy: each mailbox belongs to one fingerprint. A **single party identity shared across devices is rejected**, for two reasons. Node keys must be unique (`party.ErrNodeKeyInUse`), so two devices cannot be one enrolled party. And a shared mailbox would let one device's ack hide an envelope from the other. Fan-out to an operator's own devices comes at stage 5 with the devices document and ADR 0012 decision 7 and R9 (answers released after review or a random delay). Whether to defer it is an owner question (Open question 2). This removes the per-device sealing, the 16-device bound and the fan-out metadata leak from stage 4.

**Idempotent put.** A put of `(recipient, sender, mid)` that already exists answers `duplicate`, stores nothing and costs no quota. A put of the same bytes to another recipient, or by another sender to the same recipient, is a separate entry, so a sender learns about its own puts only: keyed by `(recipient, mid)` alone, a second sender could probe whether an envelope is in a mailbox or squat its id. The id still names the recipient's message: an ack of it deletes every copy. There is no tombstone after an ack, so a re-put or a restored directory can deliver a message again; the application already handles repeated requests. Storage is create-if-absent. The store checks existence under its lock to tell `stored` from `duplicate`, because `dir.Put` returns nil for both.

**Ordering: none promised.** `ports.EnvelopeReceiver` already says "Delivery order is not specified". The relay returns entries in name order, one entry for each id (the first stored copy, when several senders put the same bytes). The entry name starts with the arrival time (decision 7), and the store makes the arrival strictly increasing within a mailbox, so the order is arrival order and is the same after a restart; nothing relies on it for correctness. Each message carries an id and an expiry, and the state machines are driven by ids.

**Acknowledgement and deletion.** A client acknowledges an entry when the application has handled it (`EnvelopeAcker.Ack`: "a crash between delivery and handling delivers it again; the replay log makes that harmless"). The ack names up to 64 hashes. The relay deletes each acked entry from the authenticated party's own mailbox only. There is no tombstone: a later put of the same bytes is stored again. This happens in normal operation, because the outbox re-puts unanswered requests (decision 5). The recipient's signer re-answers a repeated request id from its stored response (SPO-Xparty-INV-017), and a replayed envelope is otherwise refused by the replay log until it expires, then by the expiry check (ADR 0005 steps 5 and 7).

**Retention and expiry.** The relay deletes an entry older than its retention, measured from the arrival time in the entry name. Default 7 days (`party.MaxRequestLifetime`), configurable up to 30 days (`party.MaxLifetime`), never beyond. The relay does not read the envelope's own expiry (it cannot), so a short-lived envelope may sit until retention. The recipient refuses it as expired when it opens it. Retention never extends an envelope's life. An expired-and-deleted entry is a drop: the outbox puts it again while the request is live, or the operator asks again.

**Bounds.** Every bound is a constant in `domain/mailbox`, a server may only tighten it, and each is checked **before** the memory or disk it governs is committed.

| Bound | Value | Checked |
| --- | --- | --- |
| Envelope size | 1 to `party.MaxEnvelopeBytes` (1 MiB) | From the declared size in the Put header, before the body is read |
| Frame | 4-byte length. A header frame is at most 4 KiB. A raw envelope frame is exactly the declared size, at most 1 MiB | From the length, before allocation |
| Canonical CBOR in a header frame | nesting 4, array 64, map 8 pairs, no tags, no indefinite length, same decode options as `adapters/envelope` | At decode |
| Entries per mailbox | 256 | Before accepting a put |
| Bytes per mailbox | 64 MiB | Before accepting a put |
| Entries per (sender, recipient) pair | 64 (as `party.MaxPendingPerSender`) | Before accepting a put |
| Bytes per (sender, recipient) pair | 8 MiB | Before accepting a put |
| Outstanding bytes per sender, across all recipients | 64 MiB | Before accepting a put |
| Total relay storage | configured, default 4 GiB. Must be at least the sum of the per-sender totals of the access list (64 MiB each, so 64 parties at the default). Otherwise the relay refuses to start | At configuration load, and before accepting a put |
| Parties in the access list | 1024 | At configuration load |
| Concurrent connections | 64; per node key 2; new per node key per minute 6 | At accept (the existing T7 shape, `tailcat.MaxLivePerKey`, `MaxConnsPerKeyPerMinute`) |
| Requests per connection | 256, then close | Per header frame |
| Bytes received per connection | 64 MiB, then close | Per frame |
| Puts per party per minute | 120 | Per request |
| Connection lifetime | 10 minutes (`tailcat.MaxConnLifetime`) | Timer |
| Idle between frames | 30 seconds (`tailcat.IdleTimeout`); an outstanding `Fetch` wait is at most 20 seconds | Timer |
| Handshake | 10 seconds from accept to `AuthOK` | Timer |
| Hashes per ack | 64 | At decode |
| Items per fetch reply | 16 | At build |

The existing tailcat constants (`MaxFramesPerConn` 64, `MaxConns` 16) are tuned for a coordinator with a few peers. `tailcat.Limits` says "a caller may only tighten them", so the mailbox needs its own limits, not a reuse of that struct.

**What the relay unavoidably learns.** The sender's fingerprint (authenticated), the recipient fingerprint, the hash, the exact byte size (the envelope has no padding today: `adapters/envelope` has none, and stage 4 adds none), the time of every put, fetch and ack, how long an entry waited, the node key and network path of each device, and when each device is online. From the sequence of puts it can see who talks to whom and how often. It cannot learn the message type, the session, the request or message id, the creation or expiry, the key role asked for, the body, or whether an envelope is a request, a response, a refusal or a rotation. A relay log that records these facts is itself an observer; the configuration states its retention (default 90 days), and it never records an envelope byte.

### 3. Authentication and authorisation

**Two layers, kept apart.**

1. **Tunnel admission.** The node key must be in the tailcat allow-list. The allow-list is exactly the node keys in the access list, no more.
2. **Application proof.** The client proves it holds the Ed25519 key of a listed party, by signing a server challenge that is bound to this connection.

**The handshake.** On accept, the relay reads the peer's node key from tailcat. It sends a `Challenge` with a fresh 32-byte nonce from `crypto/rand`, its own node public key, its clock reading and the protocol versions it speaks. The client checks that the relay key in the challenge equals the relay key it has pinned (decision 7) and **closes the connection if it differs**. It then answers with `Auth`: the version it chose, its fingerprint and an Ed25519 signature over this canonical CBOR array:

```
["spo/mailbox-auth/v1", version, relay node key, client node key, nonce, relay time, fingerprint]
```

The label is the first element of the array, as in `["spo/object/1", ...]` (`platform/seal`), not a prefix of the bytes.

**The client signs through a typed method, never raw bytes.** The local identity gets `SignMailboxAuth(relayKey, clientNodeKey party.NodeKey, nonce [32]byte, relayTime int64, version uint) ([]byte, error)`. It builds the signed bytes itself with `domain/mailbox.AuthBytes`. There is no `Sign(ctx, bytes)` callback, so no wiring can get a signature over bytes it chose. The method sits on a new narrow port or is added to `ports.LocalIdentity`; it is listed with the new ports (decision 7). The client passes **its pinned relay key and its own node key**, never values read from the challenge. Only the nonce and the relay time come from the challenge.

The relay verifies with the public key in the access list entry for that fingerprint, recomputing the fingerprint from the listed keys (a listed fingerprint is never trusted alone, as in `party.FingerprintOf`). It also requires that the client node key in the signed bytes is the peer key tailcat reported, and that this is the node key in the entry. It then sends `AuthOK` with the limits that apply. Any failure closes the connection with a fixed error code and no reason, as ADR 0005 does for refused envelopes.

**What the binding gives.** The nonce makes the proof fresh without a clock check, needs no state across connections and no replay cache (the HTTP-signature window in ADR 0012 decision 7 needs both). The pinned relay key in the signed bytes means a signature made for one relay is useless at another. The client's node key means another allow-listed node cannot reuse a captured response on its own tunnel. A fresh relay nonce plus both WireGuard static keys, authenticated by the tunnel handshake, is adequate channel binding: a man in the middle between client and relay needs the relay's private node key, and then it is the relay. The signature authorises that one connection, for at most 10 minutes (the connection lifetime). Every later request on the connection is authenticated by it.

**Relay time is unauthenticated.** The time in the challenge is not signed by the relay in any way the client can check. The client uses it only for a clock-skew warning (decision 5). Nothing else depends on it.

**Authorisation by the access list.** An entry is **the party's signed identity document** (the `party.Document`, with its self-signature and its node key), a label, and `send_to`: the fingerprints this party may put to. The default is nothing. At load the relay verifies the document's self-signature and **refuses a document with no node key**. The peer's tunnel node key must equal the document's node key. There is no "optional node key". A party may fetch and ack only its own mailbox. The relay's reply to a put to an unknown recipient and to a recipient that does not list the sender is the same `refused`, so the relay does not confirm who is on the list.

**The access list does not give authority.** A party the relay admits can put only what its `send_to` allows, and cannot read anything not addressed to it. Whether a received envelope is acted on is the receiver's registry. A hostile or mistaken entry on the relay can therefore add noise, never a signature or a request that the receiving client would accept from a party it has not enrolled.

**Enrolling a device.** Reuse the ADR 0005 ceremony. Two operators compare fingerprints out of band, as they already do to enrol each other. The relay administrator adds the identity document to the configuration. The relay reloads it on `SIGHUP` and at start, validates every entry, and refuses to start or reload with an empty list. A bad reload keeps the old list and logs the reason. Because the relay's admin can add a rogue entry, nothing depends on the entry being genuine (previous paragraph).

**Revoking a device.** The administrator removes the entry and reloads. The relay then closes that party's live connections, refuses its node key at the listener (`Server.Revoke` style), and deletes the mailbox of that fingerprint. Envelopes the party already put stay until delivered or expired: the relay cannot tell they came from a party that is now suspect, and the recipients decide. **Revocation at the relay is not revocation of the party.** The operator must also revoke the party in each client registry (ADR 0005), and for a stolen device rotate its identity. The command help says so. tailcat keeps the key in its allow-list until the relay restarts; that is why the relay's own refusal matters.

**Rotating a party (`party rotate`).** The command fetches and handles the mailbox first, so nothing addressed to the old identity is left unread. Rotation announcements may travel through the mailbox while the old entry is still listed. The administrator then replaces the entry with the new identity document. The old mailbox is **not carried over**: the relay deletes it with the old entry, and anything still queued is a drop that the outbox or the operator repeats.

**A stolen device** holds its identity key (in a sealed store until unlocked), its node key, and perhaps live queued envelopes. With the node key alone it reaches the handshake and fails it. With the identity key it can use its own mailbox and put to the parties its `send_to` lists, until the operator removes it. It cannot read other mailboxes. What it can *ask* of others is bounded by their scopes and refusals (ADR 0005).

**What a compromised relay can and cannot do.**

| It can | Clients detect it by |
| --- | --- |
| Drop an envelope | Only by timeout: the sender sees no answer before the request's `ttl`. A drop looks like an offline party. The mailbox adds no delivery receipt that the relay could not forge. |
| Delay or withhold, or release late | The envelope's own expiry (ADR 0005 step 5). A late request is refused as expired. |
| Reorder | Not needed: nothing relies on order. |
| Replay or duplicate an envelope, or re-deliver an acked one | The signer re-answers a repeated request id from its stored response (SPO-Xparty-INV-017); the replay log refuses other repeats until expiry; the expiry check after that. A duplicate costs the recipient one refusal event at most. |
| Show two devices of one operator different contents | Not detected by the mailbox. Each device is its own party and acts only on envelopes addressed to it. The stage 5 head log is what detects split views of workspace history. |
| Observe metadata (see above) | Not detectable. It is the stated residual. |
| Refuse service, fill quotas of a victim up to the per-pair and per-sender bounds | `full` statuses; the pair bound limits one sender to 8 MiB per recipient and 64 MiB overall, and the access list limits who can be a sender. |

| It cannot | Why |
| --- | --- |
| Read an envelope | It holds no X25519 private key and no `age` identity, and its binary links no `age`. |
| Forge an envelope | Needs a sender's Ed25519 key. |
| Alter an envelope | `age` authenticates the ciphertext and the signature covers the payload. |
| Redirect an envelope to another recipient and have it accepted | The recipient fingerprint is inside the signed payload (ADR 0005). |
| Sign, approve or answer a signing demand | The signer gate needs the operator and a fresh factor presentation (ADR 0012 decision 8). |
| Make a pool cold key sign | The mailbox is `NetworkTransport`; both ends refuse (ADR 0005). |

### 4. Threat model

| Threat | Mitigation | Residual |
| --- | --- | --- |
| **Hostile relay** (operator of the host, or an intruder) | Sealed envelopes only; no key; recipient checks ADR 0005 steps 1 to 8; the client pins the relay's node key and closes on a different one. | Drop, delay, metadata. Impersonating the relay needs its private node key; it yields metadata and denial of service, no content. |
| **Hostile tailnet peer** (another allow-listed node) | Handshake signature bound to its node key; `send_to`; per-key connection and rate limits; per-pair and per-sender quotas. | It can occupy its own quota and connection slots. A peer sharing a node key with another party is refused at enrolment (`ErrNodeKeyInUse`). |
| **Stolen device** | Identity key sealed until the operator unlocks; node key alone fails the handshake; operator revokes in registries and rotates; relay list updated. | Until revoked, the thief with an unlocked store can use the mailbox as the party. Signing still needs the gate. |
| **Revoked device** | The relay closes connections and refuses the node key; clients refuse its envelopes by registry. | tailcat allow-list stays until restart; in-flight envelopes already queued for others stay until expiry. |
| **Replay** (by the relay, by a peer, by a network observer) | Fresh nonce per connection; recipient replay log and expiry; the signer's stored-response rule; no relay-side replay state. | A repeated put costs the sender's own quota. |
| **Flooding and storage exhaustion** | Bounds table; checks before allocation; per-pair (8 MiB), per-sender (64 MiB total), per-mailbox and global quotas; the global quota must cover the per-sender totals or the relay does not start; refuse at the door. | A full mailbox refuses new puts, including genuine ones, until the recipient acks or entries expire. One listed sender can fill at most 8 MiB of one victim's mailbox and 64 MiB of the relay. That is a denial of service the sender can see (`full`). |
| **Rollback of the mailbox state** (older backup restored, volume snapshot reverted) | The mailbox holds no integrity-critical state. A rollback re-delivers acked entries (re-answered or refused by the signer and the replay log) and loses entries put after the snapshot (a drop). | Lost envelopes are re-put by outboxes or asked for again. |
| **Slow or stalled upload** | Handshake, idle and frame timeouts; the body is read only as it arrives; the temporary file is never visible under a final name. | A peer can hold a connection slot until the timers fire. |
| **Malformed frames** | Canonical CBOR with strict options; any deviation closes the connection. | None known; fuzz tests (below). |
| **Cold-key request through the mailbox** | Structural (decision 7, "Cold keys"): `Flush` skips `ColdKey` items unless the transport is `ViaFile`; the signer refuses on `Via()`. | None added. |
| **Relay key compromise** | Clients pin the key; auth signatures name the relay key and are useless elsewhere; lifecycle procedure in decision 7. | Impersonation yields metadata and denial of service only. |

### 5. Failure modes and resumability

* **Broken connection.** The client reconnects and runs the handshake again. A put is idempotent, a fetch is repeated, an ack of an entry already deleted answers a count of zero. Nothing needs a server session beyond the connection.
* **Partial upload.** The relay writes to a temporary name and links it into place only after the hash matches and the size is as declared (the `objstore/dir` write already does this). A cut upload leaves nothing visible. Because an envelope is at most 1 MiB, a partial upload is repeated whole; there is no offset resume.
* **Server restart.** State is the stored entries. In-memory counters are rebuilt from the store's usage counters at start, bounded by the quotas. Connections are lost and clients reconnect. A restart with an empty access list refuses to start.
* **Outbox behaviour is unchanged.** Every `Pump.Run` over a network transport calls `Outbox.Rearm`, so each run **re-puts the requests that are not yet answered, with the same bytes**. A response, a refusal and a closing notice are sent once. The relay answers `duplicate` while the entry is unacked, and stores it again after an ack. The signer re-answers a repeated request id from its stored response (SPO-Xparty-INV-017). The mailbox client does **no duplicate suppression**: no recent-hash set, no filter before the application. Such a filter would hide a re-delivery from the signer and break INV-017. The replay log and the coordinator's rules catch what is not a legitimate repeat.
* **Put status to error.** The mailbox client's `Send` maps the relay's answer as follows. `Flush` already leaves an item queued on `ports.ErrNoRoute` and returns any other error. A new `ports.ErrRefusedByTransport` is not returned by `Flush`: `Flush` records it as an event and goes on, so one refused item never blocks the pump.

  | Put status | `Send` returns | Operator sees |
  | --- | --- | --- |
  | `stored`, `duplicate` | nil | Nothing. |
  | `full`, `busy`, `unavailable`, or the relay is unreachable | `ports.ErrNoRoute` | A reason in the status output: the mailbox is full, the relay is busy, storage failed, or the relay cannot be reached. The item stays queued. |
  | `refused`, `too_large`, `bad_hash` | `ports.ErrRefusedByTransport` | An event naming the item and the status. `Flush` continues with the next item. |
* **Clock skew.** The handshake does not depend on clocks. The relay's time in the `Challenge` is unauthenticated; the client uses it only to warn when its own clock differs by more than 5 minutes (`party.MaxHelloLifetime`), because the envelope's `created` and `expires` are set by the client clock and a recipient with a different clock refuses them. Retention and quotas use only the relay's clock.
* **Offline parties.** The relay holds the envelope until retention. The sender's outbox keeps the sealed bytes and re-puts a live request on every run. The recipient receives them on the next connect. The envelope expiry (at most 7 days for a request) bounds what a long-offline party can be asked.
* **A device that never acks.** Its entries stay until retention. They count against its mailbox bound; once full, senders get `full` and the operator sees a reason. The bound is what protects the relay. The fetch lists a mailbox of at most 256 entries in pages, so an old unacked entry cannot starve new ones.

### 6. Wire protocol

Transport: one tailcat TCP stream to the relay's served port, one connection per client session. A new default port, distinct from the coordinator's `tailcat.DefaultPort` (7345), is chosen at implementation; it is configuration.

**Framing.** A frame is a 4-byte big-endian length `n`, then `n` bytes. A **header frame** is one canonical CBOR array, with `n` at most 4 KiB. A **raw frame** carries an envelope and has `n` equal to the size declared in the header just before it, at most 1 MiB. The length is checked before the body is read. The body is read only as it arrives (as `tailcat.ReadFrame` does). CBOR options are those of `adapters/envelope/cbor.go`: canonical, no duplicate keys, no indefinite length, no tags, UTF-8 checked, and a re-encode must equal the input. The relay hashes a raw frame while it streams it to the store and never holds more than one envelope in memory per connection.

**Versioning.** The version is negotiated once. `Challenge` carries `[min, max]`. `Auth` carries the one chosen. A version the relay does not speak is `err(version)` and a close. Version 1 is this record. A field is never added to an array: a new shape is a new version. At stage 5 own devices authenticate with the device key under a new version (v2); mailbox-only parties keep the party key (decision 7).

**Messages.** The first array element is the message type, an unsigned integer.

| Type | Name | Direction | Shape (after the type) |
| --- | --- | --- | --- |
| 0 | Challenge | relay to client | `[min, max, nonce (32), relay node key (32), relay time (unix seconds)]` |
| 1 | Auth | client to relay | `[version, fingerprint (20), signature (64)]` |
| 2 | AuthOK | relay to client | `[version, max envelope, max entries, max bytes, retention seconds]` |
| 3 | Put | client to relay | header `[request id, to (20), mid (32), size]`, then one raw frame of `size` bytes |
| 4 | PutResult | relay to client | `[request id, status]` |
| 5 | Fetch | client to relay | `[request id, after (mid, or empty), max items (1 to 16), wait seconds (0 to 20)]` |
| 6 | Items | relay to client | header `[request id, [[mid, size], ...], more]`, then one raw frame per listed item, in order |
| 7 | Ack | client to relay | `[request id, [mid, ...]]` (at most 64) |
| 8 | AckResult | relay to client | `[request id, deleted count]` |
| 9 | Error | relay to client | `[code]`, then the relay closes |

The request id is a client counter in a `uint32`, unique on the connection. Replies carry it back. The client has at most 8 requests in flight. A reply to a request id that is not in flight closes the connection. A Put header whose raw frame does not follow, or whose length differs from `size`, closes the connection.

**Status codes (PutResult).** `0 stored`, `1 duplicate`, `2 refused` (unknown recipient, not allowed to send, or a refusal the relay does not explain), `3 full` (a mailbox, pair or sender bound), `4 too_large`, `5 bad_hash`, `6 busy` (rate limit, try later), `7 unavailable` (storage error). `refused` is the same for every cause that depends on the access list, so the list is not probed (the rule ADR 0005 uses for private refusals). Decision 5 maps these to errors.

**Error codes.** `0 version`, `1 auth`, `2 protocol` (malformed or out of order), `3 limit` (a connection bound), `4 revoked`, `5 shutting down`. No text.

**Fetch.** `after` is the last `mid` the client handled in this pass, in name order. The relay returns entries with a name greater than it. `more` says another page exists. With `wait` above zero and nothing to return, the relay holds the request and answers when an entry arrives or `wait` passes, with an empty `Items`. A client acks after it handles an item, then fetches again from the start; acked entries are gone, so it does not need `after` across passes.

**Domain separation.** One new label, `spo/mailbox-auth/v1`, the first element of the signed array (decision 3). It is distinct from `spo/envelope/v1`, `spo/party/v1`, `spo/object/1` and the others, so a signature of one kind cannot be read as another. The envelope hash is plain Blake2b-256 of the bytes, as layout objects are; it is an identifier, not a signature.

**Spec.** Work package 1 adds `spec/extensions/Xmailbox.md` with stable ids for the rules above, as ADR 0005 did with `Xparty.md`. Work packages 6 and 9 amend `spec/extensions/Xparty.md` (decision 7).

### 7. Ports and adapters

**The app layer sees no mailbox.** `ports.EnvelopeSender`, `ports.EnvelopeReceiver` and `ports.EnvelopeAcker` already describe store-and-forward: `Send` is "the transport took the envelope", `Receive` blocks, and `Ack` keeps what was delivered until it is handled. The mailbox client implements them. It makes its `Transport` with `ports.NetworkTransport(client)` and its `Received` with `ports.NetworkReceived(...)`, inside the adapter only. So `multisig.Signer.Handle` and `Coordinator.Handle` take the same `ports.Received` from a mailbox, a direct tailcat stream or a file, and the cold-key rule keys on `Via()` as it does today.

ADR 0012 decision 5 proposes a `ports.Mailbox` with `Deliver`, `Fetch` and `Ack` that "extends the existing envelope senders and receivers". This record does not add it, because the existing ports already cover the client side.

**New ports** (all defined in work packages 1 and 2, before anything uses them):

* `relayport.MailboxStore` (server side, in `internal/ports/relayport`, which imports only the standard library, `domain/mailbox` and `domain/party`, so that the relay's code does not link what `internal/ports` links): `Put(recipient, mid, reader, size)` returning stored or duplicate, `List(recipient, after, limit)`, `Get(recipient, mid)`, `Remove(recipient, mid)`, `Usage(recipient, sender)`. Capability-typed (ADR 0008): the relay's session logic takes it and nothing else that stores. Only the relay's adapter implements `Remove`.
* `relayport.AccessList` (server side): `Lookup(fingerprint) (Entry, bool)`, `NodeKeys() []party.NodeKey`. An entry carries the verified identity document. ADR 0012 decision 5 names this port; its stage 5 implementation reads the devices document, this one reads configuration.
* `relayport.StreamListener`: `Accept` returns a stream and the peer's `party.NodeKey`.
* `relayport.StreamDialer`: `Dial` returns a stream and the peer's `party.NodeKey`; over tailcat that is the pinned key, and the binding is the tunnel's handshake to it.
* The auth signer: `SignMailboxAuth(relayKey, clientNodeKey party.NodeKey, nonce [32]byte, relayTime int64, version uint) ([]byte, error)`, on a new narrow port or added to `ports.LocalIdentity`. The mailbox client takes it and holds no identity key.
* `ports.ErrRefusedByTransport`: a sentinel error (decision 5).

`adapters/tailcat` implements the stream ports over `tc.Server.Listen` and the client dial it already has, and `test/fakenet` implements them in process. The relay's session logic and the mailbox client take these, not tailcat. `archtest` keeps tailcat imports in `adapters/tailcat`. A `tsnet` adapter could implement the same ports later (Open question 5).

**New packages.**

| Package | Contents |
| --- | --- |
| `domain/mailbox` | `Hash`, limits, message types, status and error codes, encode and decode with the strict CBOR options (`DecodeFromClient` and `DecodeFromRelay`, which take the sender's side; `ReadHeaderFrame` and `ReadRawFrame` for frames), `AuthBytes` for the signed array. No I/O. |
| `app/relay` | Session state machine (`Handshake`, `Put`, `Fetch`, `Ack`), quotas, retention sweep. Takes `relayport.MailboxStore`, `relayport.AccessList`, `ports.Clock`, a random source and a stream. |
| `adapters/mailbox` | Client. Implements `ports.EnvelopeSender`, `ports.EnvelopeReceiver`, `ports.EnvelopeAcker`. Takes a `StreamDialer`, the pinned relay node key and the auth signer. |
| `ports/relayport` | The relay's ports: `MailboxStore` and its capabilities, `AccessList`, `Stream`, `StreamListener`, `StreamDialer`, `Clock`. Its suites are in `ports/relayport/relayporttest`. |
| `platform/tomlsubset` | The TOML subset parser that `adapters/config` and `adapters/relayconfig` share. Refuses every control character but tab, and a CR that is not part of a CRLF. |
| `adapters/mailboxstore` | `relayport.MailboxStore` on a directory. |
| `adapters/relayconfig` | Reads and validates the access list file and the limits. The file must be owned by the effective user or root; labels are non-empty and unique. |
| `cmd/spo-relay` | The relay main. |
| `test/fakenet` | In-process stream pairs with a peer node key, byte limits, fault injection. |

**Storage.** `adapters/mailboxstore` is its own type. It wraps the write path of `adapters/objstore/dir` (temporary file, `link(2)`, fsync, mode 0600/0700, refuse a group-writable root) and adds `Remove`. **No type that a backup sink can reach gains a delete method.** In particular `ObjectDeleter` is not put on `objstore/dir`: in ADR 0012 decision 5 that name means the `gc` credential's conditional delete, which is a different thing. Rules: the relay's directory is its own, never a backup sink's directory; the arrival time is kept in the entry name, `mailbox/<recipient fingerprint hex>/<arrival unix seconds>-<mid hex>-<sender fingerprint hex>` (the arrival is never before the newest in that mailbox, so a clock that steps back does not reorder it), because `ports.ObjectInfo` has only name and size; `Put` checks existence under the lock, by `(recipient, sender, mid)`, to tell `stored` from `duplicate`, because `dir.Put` returns nil for both. A put reads exactly the declared size and its reader carries the deadline. One process owns the directory, enforced by `flock`, which is new code. Usage counters (entries and bytes per recipient and per sender-recipient pair, and the totals) are kept by the store and rebuilt by listing at start.

**Cold keys.** Enforcement is structural, as today. `Flush` skips `ColdKey` items unless the transport is `ViaFile`. The signer refuses on `Via()`. `ports.Received` has no setter, so nothing can relabel a delivery. In addition: the mailbox client never writes a fetched envelope into a file inbox or a bag; no command puts an arbitrary file into the mailbox; and the new adapters call only `NetworkTransport` and `NetworkReceived`.

**The allow-list test.** `ports/transport_callers_test.go` is an explicit allow-list of the places that may call `ports.FileTransport(`, `ports.NetworkTransport(`, `ports.FileReceived(` and `ports.NetworkReceived(`: `internal/ports/`, `internal/adapters/filebag/`, `internal/adapters/tailcat/` and `test/multiparty/partyrig/` (tests are skipped). It fails for any other non-test file. Work package 6 adds `internal/adapters/mailbox/` to it and amends SPO-Xparty-INV-024 so the text names the mailbox client beside the file bag and tailcat. That allow-list is what stops wiring from labelling a mailbox as a file.

**Client wiring.** The party and multi-party commands gain `--transport mailbox` (and a configured relay address and relay node key, handled as Secrets like the coordinator address), which makes the `adapters/mailbox` client. `--transport tailcat` stays. Which of file, tailcat or mailbox a signing slot uses is wiring, not use-case code. The client needs an unlocked workspace (Open question 4).

**Deployment shapes.**

* **Local.** `spo-relay` under systemd or in a terminal on any host that can reach the DERP relays outbound. The directory is local storage. No port is opened.
* **State and backup.** The queue is disposable: it is at most 30 days of sealed bytes, and losing it is a drop that outboxes repair. The backup-able state is the configuration (the access list and limits, in version control) and the relay's node key and pre-shared key (in a secret store). There is no `spo mailbox backup` command in stage 4. A restore of an older directory is harmless (threat table).
* **Kubernetes** is stage 6 and is recorded there. In short: one replica, because one tailcat node key is one live WireGuard endpoint, which amends ADR 0012 decision 11. See "What this changes in ADR 0012".

**Relay address and key lifecycle.** The relay address contains the pre-shared key. The address and the relay node key reach clients through the enrolment ceremony, with the node key fingerprint compared out of band. A client pins the node key. If the relay key is compromised, an attacker can impersonate the relay: that yields metadata and denial of service, no content, and auth signatures bound to the relay key are useless elsewhere. The procedure: create a new key and address, redistribute them through the ceremony, and un-pin the old key at each client. Planned rotation of the relay key or address uses the same procedure.

**Stage 5 and the devices document.** At stage 5 own devices authenticate with the device key under a new version (v2) of the handshake, and the access list is read from the devices document. Mailbox-only parties keep the party key. The framing, the messages and the status codes stay as they are; only the signed array and the key change.

### 8. Indistinguishable from a file and from a direct path

The mailbox path and a direct path must be one thing to the application. This is how:

1. **Same port, same bytes.** Both are an `EnvelopeSender`, both deliver the sealed envelope unchanged. The application reads nothing from the transport but `Received.Envelope` and `Via()`.
2. **Kind.** Both are `ViaNetwork`. Neither can be mistaken for the file transport, and the cold-key rule is unchanged.
3. **Failure surface.** `Send` returns `ErrNoRoute` when the relay is unreachable or says `full`, `busy` or `unavailable`, as a tailcat `Server.Send` does for a peer that is not connected. An outbox leaves the item queued.

Stage 4 has no router. A client uses one transport per run, chosen by `--transport`. Because a mailbox `Fetch` wakes within a moment of a put, delivery is near real time without a direct path.

### 9. What this changes in ADR 0012

| ADR 0012 | This record |
| --- | --- |
| Decision 5, `Mailbox` port with `Deliver`, `Fetch`, `Ack` | Not added. The existing `EnvelopeSender`, `EnvelopeReceiver`, `EnvelopeAcker` serve the client. Server-side ports `MailboxStore`, `AccessList`, the stream ports and the auth signer are added. |
| Decision 5, `ObjectDeleter` | Unchanged: it is the `gc` credential's conditional delete. The mailbox store has its own `Remove`, on its own type. |
| Decision 7, requests signed by RFC 9421 HTTP Message Signatures over HTTP | For the mailbox the transport is a tailcat byte stream, not HTTP. Authentication is a challenge signed by the party key through a typed method, bound to the relay key, the client node key and a fresh nonce (decision 3 here). The HTTP signature scheme stays what stage 5 uses for object and head endpoints, if those are HTTP. |
| Decisions 7 and 8, "keyed by the envelope's message id" | Keyed by the envelope hash. The message id is inside the seal. |
| Decision 7, "the sealed ADR 0005 envelope, fanned out to all of the operator's own devices" | No fan-out in stage 4. Each device is its own party with its own mailbox. Fan-out comes at stage 5 with the devices document and R9. |
| Stage 4's "device keys, request signing" | Deferred to stage 5. Stage 4 authenticates with the party key. |
| Decision 2, "a padded size" for envelopes | Not true today, and stage 4 adds no padding. The relay sees exact sizes. |
| Decision 11, stateless replicas, no `StatefulSet` | The mailbox relay is one replica with a volume. Recorded at stage 6. |
| Decision 13, stage 4 as "the server as a relay" | A separate binary `cmd/spo-relay`, not a mode of `spo`. |

## Testing plan

**Principles.** Test first: each package starts with a failing test for each rule it implements. No test opens a real network, a public DERP relay or a real Tailscale account. No test allocates more than 64 MiB itself, and no package's tests peak near 1 GiB; stream tests move bounded buffers and use `io.LimitReader` on every hostile input. **Tests of byte bounds use the store's usage counters and never materialise tens of MiB**: a fake store reports a usage near the bound and one more envelope is put. The project's own limit (concern S21: `cmd/spo` once peaked at 1.8 GiB) is the warning: the relay's tests do not run Argon2id or open a store at all, because the relay has no store.

**In-process fake tailnet.** `test/fakenet` gives `relayport.StreamListener` and `relayport.StreamDialer` over paired in-memory streams. Each dial carries a chosen peer node key, so a test can be "an allow-listed node that is not this party". A wrapper injects faults: cut after n bytes, stall, duplicate or reorder frames, deliver one byte at a time, close mid-frame. A fake clock (`ports.Clock`) drives retention, timers and handshake time.

**Unit and property tests (`domain/mailbox`, `app/relay`).**

* Every bound in the table has a test just under, at and just over it, and asserts that nothing was allocated or stored for the over case (a counting reader shows how many bytes were read). The per-pair 8 MiB bound and the per-sender 64 MiB bound are tested through the usage counters.
* Configuration: a global quota below the sum of the per-sender totals refuses to start.
* Strict CBOR: a corpus of non-canonical, duplicate-key, indefinite, tagged and oversized inputs, all refused. Native Go fuzz targets for the frame reader and the decoder with a bounded seed corpus and a 10 MiB input cap. A Put header whose raw frame is missing, short or long closes the connection.
* Handshake: wrong signature, a relay key in the challenge that differs from the pinned one (the client closes), wrong client node key, replayed `Auth` on a new connection (new nonce, so it fails), unknown fingerprint, a listed fingerprint that does not match the listed keys, a document with no node key (refused at load), a tunnel node key that differs from the document's. The signed bytes are the CBOR array with the label first. `SignMailboxAuth` is the only way to produce a signature.
* Put: idempotent (stored then duplicate, then stored again after an ack), bad hash found while streaming, too large, full at each bound, `refused` identical for an unknown recipient and a forbidden one (compared byte for byte).
* Fetch and ack: paging; a long-poll `Fetch` returns on arrival; ack deletes only the caller's mailbox; ack of a foreign hash deletes nothing and answers the same count as an absent one.
* Retention: entries older than retention (from the arrival time in the name) are deleted at the next sweep; a sweep with a stepped fake clock deletes exactly those.
* Revocation: removing an entry closes its connections and deletes its mailbox.
* Properties (`testing/quick` or a seeded generator): for any sequence of puts, fetches, acks and restarts, no envelope is delivered to a party it was not addressed to, an acked entry is not returned, and the stored set never exceeds a bound.

**Adapter tests.**

* `mailboxstore`: crash safety (a put cut before the link leaves nothing visible), restart rebuilds usage counters, `stored` versus `duplicate` under concurrent puts, a symlink or a foreign file in the directory is refused as the `dir` adapter does, a second process on the directory is refused by `flock`, and `Remove` exists on no type reachable from a backup sink (compile-time, by capability type).
* `relayconfig`: duplicate fingerprints, duplicate node keys, an empty or repeated label, a file of another owner, a control character in a comment (a bare CR), a document whose self-signature fails, a document with no node key, an empty list, a list over 1024 entries, an unreadable or group-writable file.
* `tailcat` listener and dialer: the existing live test pattern (an in-process DERP relay and STUN server from `tailscale.com/tstest/integration`, as `adapters/tailcat/live_test.go` does) gets one case: handshake and one put and fetch through a real tailcat tunnel, still with no external network.
* Status mapping (client and outbox): `stored` and `duplicate` give nil; `full`, `busy`, `unavailable` and an unreachable relay give `ErrNoRoute` with a reason; `refused`, `too_large` and `bad_hash` give `ErrRefusedByTransport`. **One refused item does not stop the others:** with three queued items and the middle one refused, `Flush` sends the first and the third, records one event, and returns no error.
* Outbox behaviour over the mailbox: every pump run re-puts unanswered requests with the same bytes; the relay answers `duplicate` while unacked and stores again after an ack; the signer answers a repeated request id from its stored response; the client delivers a repeated envelope to the application (no suppression).
* `ports/transport_callers_test.go` passes with `adapters/mailbox/` in the allow-list and still fails for a call from any other package.

**Integration tests (`cmd/spo`, small).** Two operators and a relay in one process on `fakenet`: a payment-key signing request goes coordinator to signer through the relay while the signer is offline, and the response comes back. A cold-key request over the mailbox is refused at the coordinator and, with a hand-built envelope, at the signer. A revoked party's envelope is refused by the receiver's registry even though the relay delivered it. **Party rotation:** after `party rotate` fetches and handles the mailbox, the announcement travels through the mailbox while the old entry is listed, the administrator replaces the entry, and the new identity can fetch while the old mailbox is gone. An end-to-end test confirms the relay stores nothing that equals any plaintext field of the body (the body's markers are not present in the directory).

**Architecture tests.** `cmd/spo-relay` has an archtest over `go list -deps`: no `filippo.io/age`, no `adapters/sqlitestore`, no `adapters/envelope`, no `platform/secret`, no `domain/unlock`. `app/relay`, `adapters/mailboxstore`, `adapters/relayconfig` and `ports/relayport` reach none of those either, checked on the import closure and not on direct imports (`internal/archtest/relay_closure_test.go`). The new adapters call only `NetworkTransport` and `NetworkReceived`, enforced by the allow-list test. A test asserts that no type reachable from a sink constructor has a delete method.

**Mutation pass.** The project's practice, recorded as "mutation-checked" in the handoff, is to alter each guard by hand and see a test fail. Each package ends with that pass over: every bound comparison (`<` to `<=`), the hash check, the sender and recipient authorisation, the pinned-relay-key check, the delete scoping, the status mapping, the cold-key and transport-kind paths. I found no automated mutation tool configured in the repository; whether to add one is out of scope.

**Only a real tailnet can check, left for manual verification.**

* That the relay host opens no inbound port and works behind NAT with outbound access only.
* Behaviour over the public DERP relays: latency, idle-connection survival across the 30 second idle bound and the 20 second `Fetch` wait, reconnects after a network change.
* That a node key that is not in the list is refused at the tunnel, on the real library, and that the relay's own refusal covers a revoked key until restart.
* A relay restart: whether clients reconnect to the same address.
* Throughput with a full 1 MiB envelope and the per-connection 64 MiB bound.

The manual steps go into the handoff as a table in the same style as its real-device table, with "unconfirmed" until a human has run them.

## Work packages

Each is small enough to review alone. Each ends with its tests written first, a spec update where it needs one, and an architecture check. None edits the cold-key rule.

1. **Domain and spec.** `domain/mailbox` (limits, hash, message types and codes, strict encode and decode, `AuthBytes`), `spec/extensions/Xmailbox.md` with ids. *Accept:* every bound has under, at and over tests; decode refuses the hostile corpus; fuzz targets run bounded; no I/O imports; the spec ids are all cited by tests.
2. **New ports and fake tailnet.** Defines `relayport.MailboxStore`, `relayport.AccessList`, `relayport.StreamListener`, `relayport.StreamDialer`, the auth signer (`SignMailboxAuth`, on a new narrow port or `ports.LocalIdentity`) and `ports.ErrRefusedByTransport`, plus `test/fakenet` with fault injection. *Accept:* a conformance suite (`relayport/relayporttest`, in the style of `ports/porttest`) passes on `fakenet`, allow-list cases included; a cut, a stall and a one-byte-at-a-time stream behave as specified; no test over 64 MiB.
3. **Relay session logic.** `app/relay` with ports faked: handshake, put (header frame, raw frame, hash while streaming), fetch with long-poll, ack, quotas, retention sweep, revocation. *Accept:* every row of the threat table that the relay can enforce has a test; checks run before allocation (counting reader); byte bounds are tested through usage counters; `refused` is identical for unknown and forbidden; the global-quota rule is enforced; mutation pass done and recorded. *Obligations from the store review:* the server re-checks access immediately next to the `Put` (a put whose caller checked access before an access-list reload, and reserved after `RemoveMailbox`, is otherwise stored; INV-009 cancels only puts that had already reserved), or consults a short-lived tombstone of the removed recipient; the choice is recorded in the spec ("What a session must still do") and tested with a reload between the check and the put. The fetch and ack handler takes `relayport.MailboxAcker`, the reload takes `relayport.MailboxRevoker`, and nothing takes both.
4. **Mailbox store and access list.** `adapters/mailboxstore` (own type over the `dir` write path, `Remove`, arrival time in the name, `flock`, `stored` versus `duplicate` under the lock), `adapters/relayconfig` (signed documents, node key required, limits). *Accept:* crash tests; restart rebuilds usage; no sink-reachable type has a delete method; config rejects every case listed; a reload that fails keeps the old list.
5. **tailcat listener and dialer.** Implement the stream ports in `adapters/tailcat` without changing `Server` or `Client`. *Accept:* one in-process real-tailcat case passes; the node key reported for a connection equals the dialer's; an empty allow-list refuses to start (T2); the existing tailcat tests still pass unchanged.
6. **Mailbox client.** `adapters/mailbox` implementing `EnvelopeSender`, `EnvelopeReceiver` and `EnvelopeAcker`, pinned relay key, reconnect, skew warning, no duplicate suppression, never writes to a file inbox or bag. Adds `internal/adapters/mailbox/` to the allow-list in `ports/transport_callers_test.go` and amends SPO-Xparty-INV-024 in `spec/extensions/Xparty.md`. *Accept:* conformance with the existing sender and receiver port tests; `Transport()` is `ViaNetwork` and `Received.Via()` is `ViaNetwork`; a challenge naming a different relay key closes the connection; a cut connection mid-put leaves the relay without a stored entry and the retry stores it once; the allow-list test passes and still fails elsewhere.
7. **`serve` command (`cmd/spo-relay`).** The relay main: configuration, directory, `SIGHUP` reload, the tailcat listener, the retention sweep, command help that says relay revocation is not party revocation. *Accept:* the `go list -deps` archtest passes; the relay refuses an empty access list and a global quota below the per-sender sum; the relay code path opens no store.
8. **Client wiring.** `--transport mailbox` for party and signing commands, the relay address and node key as Secrets, the local identity's `SignMailboxAuth`, and `party rotate` fetching and handling the mailbox first. *Accept:* the two-operators integration tests pass on `fakenet`; the cold-key tests pass over the mailbox transport; the rotation test passes; help text and the CLI reference are updated.
9. **Status mapping and outbox behaviour.** The put-status to error mapping, `Flush` recording `ErrRefusedByTransport` as an event and continuing, operator-visible reasons for `ErrNoRoute`, and the Xparty amendment for SPO-Xparty-INV-017 (the mailbox re-puts requests each run; no suppression). *Accept:* the mapping table has a test per row; one refused item does not stop the others; every run re-puts unanswered requests with the same bytes; the signer re-answers from its stored response.

Packages 1 to 3 need no network and no tailcat. Package 5 is the first to touch the library. The first useful end-to-end result is package 8. Package 9 can land before 8 on the fake.

**Cut from stage 4.**

* The direct-then-mailbox router (`adapters/route`). The long-poll `Fetch` gives near-real-time delivery, `--transport tailcat` stays available as wiring, and direct-when-both-online is deferred.
* `spo mailbox backup`. The queue is disposable; the backup-able state is the configuration plus the relay keys.
* The Kubernetes manifests. They move to the stage 6 record (one replica, `Recreate`, a volume, a `ConfigMap`, a `Secret`, no inbound exposure, egress policy; **to confirm** DERP reachability from a pod network and that a restarted pod with the same node key resumes service).

## Alternatives considered

* **A public HTTPS relay.** Familiar and easy to put behind a load balancer. It needs a public listener, a certificate, a name and an abuse story; every request is visible to the internet; and the owner has said the server is reachable only over the tailnet and that no device should accept inbound connections. It also moves the trust boundary to TLS and a public CA for something the envelope already protects. Rejected.
* **Taildrop** (Tailscale's file transfer between devices). It moves files between a user's own devices, needs both devices on one tailnet account, and stages files on the recipient until it is online. It is a feature of the Tailscale client and the account, not a library this binary can use, and it does not cross operators (two operators have two accounts) or give a bounded, authenticated, quota-ed queue. Rejected for the primary path. It could be a manual way to carry a file, which the file transport already is.
* **A message broker** (NATS, MQTT, a queue service). A broker gives queues, acks and retention, and it is mature. It adds a second server product, its own authentication and its own idea of identity that has to be tied to party fingerprints, and its ports and plugins widen the attack surface. The volume here is a few kilobytes a day; the rules that matter (who may send to whom, no key on the server, bounds checked before allocation) are small and specific. Rejected, though a broker behind the `MailboxStore` port stays possible if the volume ever needs it.
* **Direct-only** (the present coordinator pattern). No new server. It requires both parties online together, which the owner says is not the usual case, and it gives a signer that is offline no way to receive a request. Kept as `--transport tailcat`, not as the design.
* **Carry the envelope in the object store** (put it in a bucket as a file for the recipient to list). It would reuse the sink adapters. ADR 0012 decision 5 already refuses this as a way around the cold-key rule by labelling an adapter, and a bucket has no per-recipient authentication or quotas. Rejected as the mailbox; the object store stays for objects.
* **The relay as a mode of `spo`.** One binary, one command tree. Rejected: a flag cannot prove that the relay links no `age` and no store. A separate main can be checked by `go list -deps`.

## Consequences

* A signing request reaches an offline party. A relay holds sealed bytes for at most 30 days and learns who talks to whom and when.
* The server host is a small, replaceable process with no key that opens an envelope, in a binary that links no `age` and no store. Losing it loses queued envelopes and nothing else.
* There are now two artefacts to build and ship, `spo` and `spo-relay`. This gives up the one-binary goal for the relay alone.
* One relay is a single point of availability. Store-and-forward and outbox re-puts cover a restart; they do not cover a long outage.
* Whoever runs the relay sees all metadata for its parties and can drop or delay. They cannot read or forge.
* Two lists name parties: the relay's access list and each client's registry. They can drift. The registry is the authority; the relay list is admission. The commands say so.
* A mailbox client needs the party identity key, so it needs an unlocked workspace. A device cannot poll the mailbox unattended. ADR 0012 decision 12 is the place that would change this.
* An operator with several devices enrols each as its own party and is addressed per device. Fan-out comes at stage 5.
* Stage 4 can be built and used before stage 5. At stage 5 own devices authenticate with the device key under version 2 of the handshake; mailbox-only parties keep the party key.

## What is not confirmed

Things about tailcat and Tailscale that this record assumes and the repository does not establish. Each is to be confirmed before work package 5 is accepted.

1. **Whether "tailnet" in the owner's direction means tailcat or a real Tailscale network.** The code uses `github.com/tailscale/tailcat` v0.7.0 (handoff D3, D11; "it replaces the roadmap's Tailscale/tsnet assumption"). A tailcat server is a standalone WireGuard endpoint with a pre-shared key in its address and DERP relays, not a member of a Tailscale account's tailnet. There is then no Tailscale login identity, ACL or MagicDNS to use. This record designs for tailcat. A `tsnet` listener behind the same stream ports would be a second adapter.
2. **The listener model.** From `adapters/tailcat/server.go`, `ts.Listen` serves a TCP port inside the tunnel and does not bind an operating-system port. That is read from the code, not run.
3. **What tailcat reports for a connection.** `Server.PeerEnv` is relied on for the peer's node key (the adapter already does). Whether it is exact for every connection under load is not shown. The binding argument in decision 3 needs it to be exact.
4. **Runtime allow-list changes.** ADR 0005 says tailcat cannot remove an allowed key while running; `Allow` can add one. Both are taken from ADR 0005 and the adapter, not re-tested.
5. **One live endpoint per node key.** The one-replica argument (stage 6) assumes two processes with the same node key do not coexist cleanly over DERP. Not tested.
6. **Behaviour over time.** Idle connections over DERP, the 20 second `Fetch` wait, reconnection after a network change, and throughput are unmeasured. The adapter's 30 second idle and 10 minute lifetime are taken from the existing constants.
7. **Stability.** Upstream gives no API or wire promises (concern T1). The stream ports keep the library confined, so a change touches one adapter.

## Open questions for the owner

Five questions. Each has a recommendation. None is decided.

1. **Who runs the relay?** Recommended: one operator per co-signing group. The others accept that this person sees all metadata and can drop or delay, never read or forge. Trade-off: it is a trust in availability and privacy of metadata, not in content. If that is not acceptable, run one relay per operator group.
2. **Is fan-out to an operator's several devices deferred to stage 5?** Recommended: yes. Until then each device is its own party with its own mailbox, and a demand goes to the one fingerprint the slot assignment names. Trade-off: an operator who wants any device to answer cannot have that in stage 4, against the per-device sealing, a device bound and a fan-out metadata leak that the relay would otherwise see.
3. **Is "state backup-able" met by the access list in version control plus the relay keys in a secret store, with the queue disposable?** Recommended: yes. Trade-off: a lost queue is a drop that the outbox repairs while a request is live; a backup would be more copies of metadata in more places.
4. **No unattended mailbox receive in stage 4?** Recommended: yes. An unlocked workspace is needed to authenticate. A separate, low-privilege mailbox key held by a background process is the alternative and belongs with ADR 0012 decision 12 (the agent), as its own record. Trade-off: no unattended receive, against a second key whose theft lets a thief read the party's queue (still sealed) and use its `send_to`.
5. **tailcat as built, not a Tailscale tailnet via `tsnet`?** Recommended: tailcat as built, with the stream ports leaving room for `tsnet` later. In practice: tailcat is a standalone WireGuard endpoint with a pre-shared key in its address and Tailscale's DERP relays, so nobody needs a Tailscale account, and there is no Tailscale identity, ACL or MagicDNS name to lean on. Every admission rule therefore lives in our access list and our handshake, which this record builds. A `tsnet` tailnet would add Tailscale's own login and ACL as a second layer, at the price of one Tailscale account per operator and of depending on a hosted control plane.

## Defaults taken

Not open questions. Each is a default this record takes, and the owner may change it.

* **`send_to` default is empty.** Each entry lists the fingerprints it may put to; nothing by default. One more field per enrolment, against a hostile or mistaken entry filling everyone's mailbox.
* **Retention** is 7 days by default and 30 days at most.
* **One replica**, which amends ADR 0012 decision 11 (stateless replicas). One tailcat node key is one live endpoint. Availability comes from store-and-forward tolerating a restart. Recorded at stage 6.
* **No delivery receipts.** A drop is detected, imperfectly, by the request's own timeout. A receipt would be a new ADR 0005 message type.
* **The bounds table**, as given. 256 entries and 64 MiB per mailbox are generous for signing traffic; one full 1 MiB bundle is one entry.
* **Relay log kept 90 days**, local file, no envelope bytes.
* **Command name** is `spo-relay`. "Relay" is the role name here and "mailbox" is what the client sees; the help uses both.
* **No padding in stage 4.** The relay sees exact sizes. This corrects the text of ADR 0012 decision 2, which assumes padded sizes. If wanted later, padding goes inside the signed payload in a new envelope version (a format change to ADR 0005, to be reviewed).
