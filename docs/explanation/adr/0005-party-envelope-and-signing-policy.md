# ADR 0005: Party envelope and remote-signing policy

Status: accepted, 2026-11-16. Closes T3, E7 and M6; sets the basis for M7. The message catalogue and state machines are specified separately (M1, T6).

## Context

Parties exchange signing requests and witnesses by carried file or over tailcat. A tailcat node key proves possession of a WireGuard key, not who is acting, and a carried file proves nothing at all. Upstream's transfer file is neither signed nor encrypted (SPO-Ptransfer-SEC-002, SPO-05d-SEC-002).

## Decision

### One envelope, every transport

Every message between two machines is an **envelope**. The transport only moves envelope bytes. The file transport writes them to a file; the tailcat transport sends them over a stream. Remote and carried signing therefore share one code path and one set of checks.

* **Party identity.** Each enrolled machine has a long-term identity: an Ed25519 signing key and an X25519 encryption key, both Secret records. Its fingerprint is a hash over both public keys.
* **Sealing.** The sender builds a payload of `[version, message type, sender fingerprint, recipient fingerprint, message id, created, expires, body]`, signs it with its Ed25519 key, and encrypts payload and signature to the recipient's X25519 key with `age`. Naming the recipient inside the signed payload stops a recipient from re-sending the message to someone else as if it were addressed to them.
* **Opening.** The receiver decrypts, then refuses unless all of these hold: the sender fingerprint is enrolled and not revoked; the signature verifies; the recipient fingerprint is its own; the message has not expired; the message id is not in its replay log; the sender's role permits this message type (M7). A refused envelope gets no reply that reveals why.
* **Enrollment** pins the two public keys of each party after the operators compare fingerprints out of band (T6).

### Layers over tailcat

| Layer | Provides |
| --- | --- |
| WireGuard tunnel with the pre-shared key in the tailcat address | Confidentiality and forward secrecy in transit; hides traffic from the relay |
| `Server.AllowedClients`, always non-empty (T2) | Only enrolled node keys reach the listener |
| First frame bound to the tunnel peer | The party that owns the connection is the party the first envelope names |
| Envelope | End-to-end authenticity, confidentiality, replay protection and authorisation, independent of the tunnel and of address secrecy (T4) |

A coordinator refuses to start with an empty allow-list. The list is built only from active parties that are a signer or a machine and have a node key; a revoked party and a party that is only a coordinator are not in it.

**What the tunnel binds, and what it does not.** tailcat tells our listener the node key it authenticated for each accepted connection (`PeerEnv`, the `TAILCAT_PEER_KEY` of the connection's addresses). The first frame of a connection must be a `Hello` or a response, from an active party whose *enrolled* node key is that peer key, and must not be in the replay log. An allow-listed node therefore cannot present another party's envelope as its first frame to take over that party's route: the envelope is genuine, the sender is active, the signature verifies, and it is still refused, because the node that sent it is not the sender's. What remains unbound: a later frame on the connection is bound to nothing but its own signature and the checks every envelope gets (SPO-Xparty-SEC-002); two parties that share one node key (the operator enrolling the same node twice) are one peer to the tunnel; and a party whose node key is stolen is a party whose node key is stolen, until the operator revokes it. There is no server-issued nonce, so a first frame is made fresh by its message id (the replay log) and by the short `Hello` lifetime (5 minutes), not by a round trip.

**Revocation.** tailcat cannot remove a key from its allow-list while it runs: a revoked party's node key can still open a tunnel until the server restarts without it. Our listener refuses it (`Server.Revoke`), closes its live connections, and the envelope check refuses a revoked party's envelopes from the moment of revocation. One node key holds at most 2 live connections, a connection lives at most 10 minutes, and one enrolled party's replay entries and undecided requests are bounded per sender (SPO-Xparty-INV-022).

### What the envelope does not provide

Envelopes carried by file have no forward secrecy: someone who later obtains a recipient's X25519 key can read old files. Witnesses and transaction bodies become public on chain, so the exposure is the request metadata. The threat model records this.

### What a coordinator may ask: scopes

An enrolled party's authority is explicit. A coordinator enrolled at a signer carries a **scope**: the key roles of the signer's keys it may ask for, the pools it may send bodies about, and whether it may send a body that concerns no pool. The default is nothing, and a record without a scope is read as that. A body concerns a pool when the pool is the subject of a registration or retirement, the target of any delegation, or a stake-pool voter; the signer works that out from the body itself. The check runs at the signer, which does not trust the coordinator for it, and is mirrored at the coordinator before it sends. A request outside the scope is refused and the refusal is kept silent (below).

### Which refusals are sent

A refusal that depends only on the request (wrong network, body hash, a body that does not decode or cannot be displayed, a passed TTL, a cold key over a network) is sent: the coordinator could work it out itself. A refusal that depends on what the signer holds, owns or trusts (no such key, out of scope, no input of the body is the signer's, the inputs cannot be resolved, the signer cannot meet the demand) is recorded locally and never sent, because an enrolled coordinator could otherwise use the answers to probe the signer's keys and addresses: the private checks run after the public ones, so a request that fails a public check cannot be used for that either. The operator's own decision to decline is a message.

### What the signer shows, and re-authentication

The signer works out whose money leaves from its own addresses and its own chain view (SPO-Xparty-PR-002), and refuses a payment-key request whose inputs it cannot resolve. In remote signing it refuses any body with a part whose meaning it does not decode: proposals, scripts, collateral, reference inputs, datums, a mint. Auxiliary data travels with the request and is checked against the body's hash, so the metadata is shown. Approval needs the operator to authenticate again (an approval gate; the wiring prompts for the store passphrase for the pool cold, payment and owner stake keys).

### Memory

The X25519 private scalar is kept in guarded memory, but `age` has no constructor from raw bytes: it is rebuilt as `age`'s own value from a bech32 string, so a copy of the scalar exists in ordinary heap memory, inside `age`, for as long as the unlocked identity is alive and until the garbage collector reclaims it. One `age` identity is built per unlocked identity. tailcat keeps its node key in ordinary memory too. The threat model records both.

### Which keys may sign remotely (M6)

| Key class | Tailcat transport | File transport |
| --- | --- | --- |
| Pool cold key | **Refused**, no override in this version | Allowed |
| Payment, stake, owner stake, DRep, committee hot | Allowed | Allowed |
| Hardware-wallet keys of any class except pool cold | Allowed; the device shows and approves the transaction itself | Allowed |

The refusal is enforced twice: the coordinator does not send a cold-key request over a network transport, and a signer refuses one that arrives over a network transport.

### The air-gap bundle

The Go bundle between an operator's own online and offline machines is an envelope too, so both machines are enrolled with each other. The upstream `offlineTransfer.json` format is still read and written for compatibility. Importing one never writes outside the bundle's own directory (SPO-Ptransfer-SEC-001), and what was imported from an unauthenticated file is marked as such in the audit log.
