+++
id = "Xparty"
kind = "extension"
title = "Party enrollment and multi-party signing protocol"
status = "draft"
contexts = ["key-custody", "pool-operations", "air-gap-transfer"]
use_cases = ["EnrollParty", "RevokeParty", "RequestSignatures", "ReviewSigningRequest", "ImportSigningResponse"]
depends_on = ["05c", "05d", "Ptransfer", "Ctx"]
+++

# Xparty: party enrollment and multi-party signing

This spec is not upstream behaviour. It defines the protocol that replaces upstream's witness-file passing ([05c](../upstream/scripts/05c_regStakepoolCert.md), [05d](../upstream/scripts/05d_poolWitness.md)) and the unauthenticated transfer file ([Ptransfer](../upstream/patterns/Ptransfer.md)). Design decisions are in [ADR 0005](../../docs/explanation/adr/0005-party-envelope-and-signing-policy.md) and [ADR 0008](../../docs/explanation/adr/0008-capability-typed-ports.md). Requirements have ids so tests cite them like upstream requirements; they have no source ranges.

Terms: a **party** is one enrolled machine with its own store. The **coordinator** is the party that builds a transaction and collects signatures. A **signer** is a party asked for a signature. One machine can be both. A **transport** moves envelope bytes: the file transport and the tailcat transport are specified at the end.

## Party identity

- **SPO-Xparty-INV-001** A party identity is an Ed25519 signing key pair and an X25519 encryption key pair, generated at `init` and stored as Secret records. Neither private key ever leaves the store.
- **SPO-Xparty-INV-002** The fingerprint of an identity is the first 20 bytes of BLAKE2b-256 over the domain string `spo/party/v1`, the Ed25519 public key and the X25519 public key, in that order. It is displayed as 8 groups of 5 lower-case base32 characters.
- **SPO-Xparty-INV-003** A party's public identity document is canonical CBOR of `[version, label, ed25519 public key, x25519 public key, tailcat node public key or null, created]`, signed with the Ed25519 key. The label is chosen by its owner and is not trusted.

## Enrollment

- **SPO-Xparty-IF-001** `party export` writes the local public identity document. It contains no secret and no tailcat address.
- **SPO-Xparty-IF-002** `party enroll <document> --as <local name> --role <role>... [--pool <pool>]...` records another party. Roles: `coordinator` (may send signing requests), `signer` (may be sent signing requests), `machine` (the operator's own other machine: may exchange air-gap bundles).
- **SPO-Xparty-PRE-001** Enrollment refuses a document whose signature does not verify under the Ed25519 key it contains.
- **SPO-Xparty-PR-001** Enrollment shows the computed fingerprint and requires the operator to type its first two groups, as read out by the other party over a separate channel. There is no default and no flag that skips it.
- **SPO-Xparty-OUT-001** An enrolled party is a Sensitive record: public keys, fingerprint, local name, roles, pools, tailcat node key, state (`active`, `revoked`), and the enrollment time. Enrollment is an audit event.
- **SPO-Xparty-INV-004** Enrollment is mutual but not automatic: each side enrolls the other. A party that has enrolled us and that we have not enrolled gets no response at all.
- **SPO-Xparty-IF-003** `party revoke <name>` sets the state to `revoked`. `party rotate` generates a new local identity and exports a rotation statement signed by the old key; a peer that imports it must confirm the new fingerprint as in SPO-Xparty-PR-001.
- **SPO-Xparty-INV-005** A revoked party's envelopes are refused from the moment of revocation, including envelopes created before it. Open collections keep the witnesses already verified; unfilled slots assigned to the party become unassigned.
- **SPO-Xparty-SEC-001** A coordinator's tailcat address is a Secret record. It is given to a signer only inside an envelope addressed to that signer (message `Invite`), never in an identity document, a QR code or a log.

## Envelope

- **SPO-Xparty-OUT-002** An envelope is `age`-encrypted to the recipient's X25519 key. The plaintext is canonical CBOR of `[payload, signature]`, where `signature` is Ed25519 over the domain string `spo/envelope/v1` followed by the payload bytes.
- **SPO-Xparty-OUT-003** The payload is canonical CBOR of `[version, type, sender fingerprint, recipient fingerprint, message id (16 random bytes), created (unix seconds), expires (unix seconds), body]`.
- **SPO-Xparty-PRE-002** A receiver refuses an envelope, in this order, when: it does not decrypt; the payload version is unknown; the sender fingerprint is not an active enrolled party; the signature does not verify under that party's Ed25519 key; the recipient fingerprint is not its own; `expires` has passed or `created` is more than 10 minutes in the future; the message id is in its replay log; the sender's roles and pools do not permit the message type (SPO-Xparty-INV-010).
- **SPO-Xparty-INV-006** Every refusal is an audit event that records the reason and, when known, the sender. Over a network transport the sender receives nothing that distinguishes one refusal from another, and nothing at all before the signature has verified.
- **SPO-Xparty-INV-007** The replay log holds every accepted message id until its `expires` has passed. It is written in the same store transaction as the effect of the message.
- **SPO-Xparty-INV-008** An envelope is at most 1 MiB. A transaction body is at most the protocol's `maxTxSize`.
- **SPO-Xparty-SEC-002** Envelope validity is independent of the transport: the same checks run on an envelope read from a file and on one received over tailcat. No check is skipped because a tunnel authenticated the peer.

## Messages

| Type | From → to | Body |
| --- | --- | --- |
| `SigningRequest` | coordinator → signer | `[collection id, slot id, key role, key hash (28 bytes), operation, transaction body CBOR, body hash (32 bytes), ttl slot, network magic, purpose text]` |
| `SigningResponse` | signer → coordinator | `[collection id, slot id, request message id, witness CBOR]` |
| `SigningRefusal` | signer → coordinator | `[collection id, slot id, request message id, reason code]` |
| `CollectionClosed` | coordinator → signer | `[collection id, outcome: submitted with tx id, discarded, or expired]` |
| `Invite` | coordinator → signer | `[tailcat address, coordinator tailcat node key]` |
| `Bundle` | machine → machine | the air-gap bundle: chain snapshot, queued transactions, attachments |

- **SPO-Xparty-INV-009** `SigningRequest.expires` is no later than the wall-clock time of the body's TTL slot, and no later than 7 days after `created`.
- **SPO-Xparty-INV-010** Authorisation by role: `SigningRequest`, `CollectionClosed` and `Invite` need the sender to be a `coordinator` for the pool the body concerns, when it concerns a pool; `SigningResponse` and `SigningRefusal` need the sender to be the `signer` assigned to that slot; `Bundle` needs `machine`.
- **SPO-Xparty-INV-011** The purpose text is for display only. Nothing a signer shows or decides is derived from it (SPO-Xparty-PR-002).

## Coordinator

A collection is the aggregate `WitnessCollection` of the [domain model](../domain/domain-model.md), with states `OpenIncomplete`, `OpenComplete`, `Expired`, `Submitted`, `Discarded`.

- **SPO-Xparty-PRE-003** A collection is opened only with a signing plan (`custody.Plan`): every slot has a key reference whose holder can produce the signature. A slot whose key is held by a remote party must name an active enrolled `signer` for the pool.
- **SPO-Xparty-INV-012** The body stored in the collection is final when the collection opens. When any slot's holder is a hardware wallet, the body is in hardware-canonical form ([Ctx](../upstream/common/Ctx.md)) before its hash is taken, so every party hashes the same bytes.
- **SPO-Xparty-INV-013** Every slot goes through the same request flow: owner stake keys, the fee payer, the pool cold key and any other required signer (this lifts SPO-05d-INV-007). Slots whose key the coordinator's own machine holds are filled by its local signer through the same verification as a remote response.
- **SPO-Xparty-PRE-004** A request for a pool cold key is not sent over a network transport. The coordinator refuses to create it; the file transport is allowed (ADR 0005).
- **SPO-Xparty-PRE-005** A response is accepted for a slot only when all hold: the collection is `OpenIncomplete`; the slot is empty; the sender is the slot's assigned signer; the request message id is the one last sent for that slot; the witness is a valid Ed25519 signature over the stored body hash; the BLAKE2b-224 hash of the witness's verification key equals the slot's key hash (this closes SPO-05d-INV-006 and SPO-05d-SEC-003).
- **SPO-Xparty-INV-014** Filling a slot is a compare-and-set on the collection version. Of two valid responses for one slot, one is stored and the other is acknowledged without effect.
- **SPO-Xparty-INV-015** A collection whose TTL slot has passed is `Expired`. It accepts no response and cannot be submitted. Expiry is derived from the chain tip when one is available and from the clock otherwise.
- **SPO-Xparty-OUT-004** Opening, each request sent, each response accepted or refused, completion, submission, discard and expiry are audit events (this closes SPO-05d-INV-001).
- **SPO-Xparty-OUT-005** When the last slot is filled the collection is `OpenComplete`. Submission assembles the stored body with the stored witnesses and nothing else.

## Signer

- **SPO-Xparty-PRE-006** A signer refuses a request, with a `SigningRefusal` and an audit event, when: it holds no key with the requested key hash and role; the network magic is not its workspace's; the body hash is not the BLAKE2b-256 hash of the body it received; the body does not decode as a transaction of the current era; its TTL slot has passed; the key is a pool cold key and the request arrived over a network transport; its signer for that key cannot meet the demand of the decoded body (`custody.Plan` on the signer's side).
- **SPO-Xparty-PR-002** Before signing, the signer shows what the body does, decoded locally from the body bytes: every input, every output with its address and value, the fee, the TTL, every certificate with its fields (for a pool registration: pool id, pledge, cost, margin, reward account, owners, relays, metadata URL and hash), withdrawals, mint, votes, proposals, required signers, the presence and hash of auxiliary data, and the total leaving addresses the signer owns. It then asks for approval with default No (this closes SPO-05d-INV-008).
- **SPO-Xparty-INV-016** There is no option that approves without the display of SPO-Xparty-PR-002. A non-interactive signer does not exist in this version.
- **SPO-Xparty-OUT-006** On approval the signer produces the witness with the signer that holds the key (vault or hardware), verifies it itself as in SPO-Xparty-PRE-005, and sends `SigningResponse`. Request, decision and response are audit events that record the body hash.
- **SPO-Xparty-INV-017** A request that was answered is answered again with the stored response when the same message id arrives over a file transport, so a lost reply file can be regenerated. It never signs twice.

## Transports

- **SPO-Xparty-IF-004** File transport: `export` writes one envelope per file, named `<type>-<collection id prefix>-<slot>.spo`; `import <file>...` reads them. A file is at most the envelope size limit. Import never writes outside the store.
- **SPO-Xparty-IF-005** Tailcat transport, coordinator side: a tailcat server with a persistent node key and pre-shared key, listening on one TCP port. It refuses to start when no `signer` or `machine` party with a tailcat node key is enrolled, and it sets the allow-list to exactly those node keys before starting (concern T2).
- **SPO-Xparty-IF-006** Tailcat transport, signer side: a client with a persistent node key dials the address it received in `Invite`, sends its pending responses, and receives its pending requests.
- **SPO-Xparty-INV-018** The stream protocol is a sequence of frames, each a 4-byte big-endian length and one envelope. The first frame from each side must be a valid envelope from an enrolled party; otherwise the connection is closed with no bytes written.
- **SPO-Xparty-INV-019** Per connection: at most 64 frames, at most 30 seconds idle, at most 16 concurrent connections, and at most 6 connections per node key per minute (concern T7).
- **SPO-Xparty-SEC-003** Coordinator state lives in the store, not in the connection. A signer that reconnects, or that answers by file after being asked over the network, completes the same slot.
- **SPO-Xparty-MODE-001** A coordinator in offline mode has no network transport. It exchanges envelopes by file only.

## Upstream compatibility

- **SPO-Xparty-IF-007** `05c` witness transfer files (SPO-Pfiles-OUT-023) can be imported into and exported from a collection, for a party that still uses the upstream scripts. A witness imported this way is verified as in SPO-Xparty-PRE-005, and the slot records that it arrived unauthenticated.

## Open questions

* Whether hardware-canonical form (SPO-Xparty-INV-012) can be produced natively or needs `cardano-hw-cli transaction transform`; see [Go library coverage](../../docs/development/go-library-coverage.md).
* Whether a tailcat client can be told to dial only when the allow-listed server key matches the invite; settle in the transport spike.
* The 7-day cap of SPO-Xparty-INV-009 against the upstream witness window of about 100 000 slots (SPO-05d-INV-003).
