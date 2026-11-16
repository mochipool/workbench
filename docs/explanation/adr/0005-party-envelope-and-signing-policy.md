# ADR 0005: Party envelope and remote-signing policy

Status: accepted, 2026-11-16, amended by the second and third security reviews (see the sections on ownership, scopes, reconnecting, approval and the transport kind). Closes T3, E7 and M6; sets the basis for M7. The message catalogue and state machines are specified separately (M1, T6).

## Context

Parties exchange signing requests and witnesses by carried file or over tailcat. A tailcat node key proves possession of a WireGuard key, not who is acting, and a carried file proves nothing at all. Upstream's transfer file is neither signed nor encrypted (SPO-Ptransfer-SEC-002, SPO-05d-SEC-002).

## Decision

### One envelope, every transport

Every message between two machines is an **envelope**. The transport only moves envelope bytes. The file transport writes them to a file; the tailcat transport sends them over a stream. Remote and carried signing therefore share one code path and one set of checks.

* **Party identity.** Each enrolled machine has a long-term identity: an Ed25519 signing key and an X25519 encryption key, both Secret records. Its fingerprint is a hash over both public keys.
* **Sealing.** The sender builds a payload of `[version, message type, sender fingerprint, recipient fingerprint, message id, created, expires, body]` (the format is version 1 as of this decision; nothing was deployed before it, so there is no older one), signs it with its Ed25519 key, and encrypts payload and signature to the recipient's X25519 key with `age`. Naming the recipient inside the signed payload stops a recipient from re-sending the message to someone else as if it were addressed to them.
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

**What the tunnel binds, and what it does not.** tailcat tells our listener the node key it authenticated for each accepted connection (`PeerEnv`, the `TAILCAT_PEER_KEY` of the connection's addresses). The first frame of a connection must be a `Hello`, from an active party with the signer role whose *enrolled* node key is that peer key, with a lifetime of at most 5 minutes, and must not be in the replay log: the same role and lifetime checks that handling the Hello applies run before the connection gets a route, so a refused Hello leaves none (SPO-Xparty-INV-027). The client sends a fresh `Hello` (new message id, 5-minute expiry) first on every connection, built by a callback the wiring supplies so that the adapter holds no identity key; the coordinator closes a connection that opens with anything else, a response included. An allow-listed node therefore cannot present another party's envelope as its first frame to take over that party's route: the envelope is genuine, the sender is active, the signature verifies, and it is still refused, because the node that sent it is not the sender's. What remains unbound: a later frame on the connection is bound to nothing but its own signature and the checks every envelope gets (SPO-Xparty-SEC-002); two parties that share one node key would be one peer to the tunnel, so enrollment refuses a node key that another enrolled party already has; and a party whose node key is stolen is a party whose node key is stolen, until the operator revokes it. There is no server-issued nonce, so a first frame is made fresh by its message id (the replay log) and by the short `Hello` lifetime (5 minutes), not by a round trip.

**Revocation.** tailcat cannot remove a key from its allow-list while it runs: a revoked party's node key can still open a tunnel until the server restarts without it. Our listener refuses it (`Server.Revoke`), closes its live connections, and the envelope check refuses a revoked party's envelopes from the moment of revocation. One node key holds at most 2 live connections, a connection lives at most 10 minutes, and one enrolled party's replay entries and undecided requests are bounded per sender (SPO-Xparty-INV-022).

### What the envelope does not provide

Envelopes carried by file have no forward secrecy: someone who later obtains a recipient's X25519 key can read old files. Witnesses and transaction bodies become public on chain, so the exposure is the request metadata. The threat model records this.

### What a coordinator may ask: scopes

An enrolled party's authority is explicit. A coordinator enrolled at a signer carries a **scope**: the key roles of the signer's keys it may ask for, the pools it may send bodies about, and whether it may send the parts of a body that name no pool. The default is nothing, and a record without a scope is read as that. The scope is checked **per part** of the body and not per body. A part names a pool when it is a pool registration or retirement, a delegation (the pool delegated to), or a stake-pool vote. A combined certificate is split into its parts: its delegation names the pool, but its registration part (tags 11 and 13, a deposit paid) and its vote-delegation part (tags 10 and 13, a DRep chosen) name none and need `Unscoped` each; a combined certificate used to skip that rule and let a pool-only scope choose a DRep. Every other part (a withdrawal, a stake registration, a vote delegation, a DRep or committee certificate, any other vote, and every payment-key request, whose witness can spend the signer's funds) names none and needs `Unscoped`. A body that delegates to an in-scope pool and withdraws rewards to someone else therefore needs the pool and `Unscoped`; a per-body rule would have let the in-scope certificate carry the withdrawal. The check runs at the signer, which does not trust the coordinator for it, when the request arrives and again when it is approved, against the scope as it is then. The scope is **one-directional**: it is what a coordinator may ask of this machine. What this machine asks of a signer is limited by the slot assignment and by the signer's own checks, and the coordinator does not read the scope it recorded for a signer (that was a second use of one field for two directions, and it let a configuration that meant one thing be read as the other). A request outside the scope is refused and the refusal is kept silent (below).

### Which refusals are sent

A refusal that depends only on the request (wrong network, body hash, a body that does not decode or cannot be displayed, a passed TTL, a cold key over a network) is sent: the coordinator could work it out itself. A refusal that depends on what the signer holds, owns or trusts (no such key, out of scope, no input of the body is the signer's, the inputs cannot be resolved, the signer cannot meet the demand) is recorded locally and never sent, because an enrolled coordinator could otherwise use the answers to probe the signer's keys and addresses: the private checks run after the public ones, so a request that fails a public check cannot be used for that either. The operator's own decision to decline is a message.

### What the signer shows, and re-authentication

**Ownership is by credential, resolved by the signer.** A payment key's witness authorises every input whose payment credential is that key, at any address form, so an ownership test that asks whether an input is in the UTxO set of an address string the signer listed is wrong: a coordinator adds a large input at an unlisted address of the same key (a base address with another stake credential, say) and the review calls it foreign. The signer holds the key hashes of its payment and stake keys, resolves every input by reference through its own provider (Koios, or the offline snapshot), decodes the address of each resolved input and classifies it by its payment credential. For a payment-key request every input must resolve; an unknown, spent or failed one refuses the request, and so does a body none of whose inputs is the signer's. An output is the signer's only when its payment credential is the signer's and its stake credential is absent or the signer's: an output to the signer's payment key with someone else's stake credential gives away its rewards and delegation. The net outflow adds the withdrawals from the signer's reward accounts and the refunds on its credentials, subtracts its own outputs and its own deposits, shows each term, and refuses on overflow (SPO-Xparty-PR-002). For a key that cannot spend funds the same resolution runs when a resolver exists, and a body that spends the signer's own payment UTxOs is shown as such, with a prominent note that the payment witness must come from elsewhere.

**Scripts, and what a key witness can satisfy.** A key witness satisfies every native script that names the key, and the script is in the witness set, not the body. An input at a script address used to be classified foreign, so a key witness could co-sign a multisig spend unseen. The signer now refuses, for every key role and in silence (`RefuseScriptInput`: it depends on the signer's own chain view), a body with a resolved input at a script address, a withdrawal from a script reward account, or a certificate or vote on a script credential (SPO-Xparty-PR-004). A mint, reference inputs, collateral and a script data hash stay undisplayable for every role including `policy`: remote signing signs no body whose scripts it cannot see evaluated, and a mint has no scope rule of its own (the alternative, a scope part for a mint, would still sign a policy it cannot read). Where the inputs were not resolved for a key that cannot spend from its own address, the review says plainly that they were not checked and what that leaves open, and it still shows the net from withdrawals, refunds, outputs and deposits labelled as excluding the inputs, so own rewards leaving to someone else's output are visible (SPO-Xparty-PR-003).

**Fail closed, and the network rule.** The kind of a credential is read from the bytes in the view (an address header, a reward account's key header, a credential's kind prefix, a voter kind) and not only from an address inspector, and anything that is not plainly a key is a script: an unreadable reward account or input address, an unknown header or kind. The inspector can add a script verdict, never remove one. A signer built without an address inspector refuses every request with a configuration error instead of passing it (SPO-Xparty-PR-004). A request that came over a network, or over an unknown transport, is refused for every role unless the signer's own resolver resolves every input and every input address reads (`RefuseCannotResolveInputs`, in silence, SPO-Xparty-PRE-007): the operator's hand delivered a file, a network peer did not, and a peer must not be able to make a signer sign blind. The residual we accept is on the file transport: for the roles that cannot spend a payment UTxO, unresolved inputs are warned in the review, not refused. The transport kind is stored with the request, so review and approval apply the same rule.

**The chain view is the signer's own.** An offline snapshot is unauthenticated: whoever wrote it chose what each input is. The signer use case takes a resolver only as `multisig.OwnResolver`, made by `OwnProvider` or `OwnSnapshot`, so a bundle a coordinator carried cannot be passed by accident; a transfer file received from another party is never a resolver source (SPO-Xparty-PR-005). A CLI that wires a snapshot must say it is the operator's own. Types guard the rest: no exported function of `multisig` or `party` turns a received bundle into an `OwnResolver`, and a test reads the source to keep it so. Only the argument of `OwnSnapshot` is convention, an operator and wiring obligation: a CLI builds it from a path the operator named for the purpose and refuses a path inside the party store or a transport's inbox, or one a received bundle wrote.

In remote signing the signer refuses any body with a part whose meaning it does not decode: proposals, scripts, collateral, reference inputs, datums, a mint. Auxiliary data travels with the request and is checked against the body's hash, so the metadata is shown; the body and the auxiliary data together are within `maxTxSize`. Approval needs the operator to authenticate again (an approval gate; the wiring prompts for the store passphrase for the pool cold, payment and owner stake keys). The approval is claimed against the current state inside the claiming store transaction (SPO-Xparty-INV-025): the sender is still an active coordinator, the scope as it is now still allows the request, and the flow the signer works out again has the digest of the flow the operator read. The flow is worked out just before the claim (the provider may be a network call) and compared inside it; a revocation or scope change that happens while the operator is at the gate prompt is not re-checked afterwards. Provider error text is kept out of the digest, so a provider that fails twice with different messages does not make the review stale (SPO-Xparty-INV-026). Only a pending request is claimed; one left in the signing state by a crash is claimable again after the gate timeout, and a second approval while the first is at the gate is refused (SPO-Xparty-INV-028). A signer keeps a refused request only until its envelope expires, and at most 512 per sender (SPO-Xparty-INV-029).

### Reconnecting

A network send has no application acknowledgement, and a replay log that refuses a message id twice would lock a signer out the moment it reconnects with an envelope the coordinator has already accepted. So the first frame is always a fresh `Hello`; a response or a refusal is sent once, when its write succeeds, and is never re-sent of its own accord; and the recovery for a lost response is the coordinator's: it sends the unanswered request again, with the same message id, each time that signer's `Hello` arrives, and the signer answers a request id it has already answered from its stored response without touching its key (SPO-Xparty-INV-017). The same response arriving a second time is acknowledged without a security event, because the coordinator remembers the id it accepted for the slot. A normal reconnect writes no refusal to the audit log.

### The transport kind

The cold-key rule and the offline rule depend on whether an envelope travelled by file or over a network. A constructor that took a kind would let any caller label a network as a file, so there is none: `FileTransport(sender)` and `NetworkTransport(sender)` set the kind and are called only by the adapters (a test enforces it), and an incoming envelope reaches `Signer.Handle` and `Coordinator.Handle` as a `Received` value made by the adapter that read it, whose kind has no setter. The zero kind is a network.

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

## Obligations on whatever wires a signer

The fifth security review (2026-11-16) cleared the stack on these assumptions about the code that constructs a `multisig.Signer`. A command or TUI screen that breaks one of them voids the review.

1. `Signer.Addresses` is always set to the ledger's address inspector. A signer without one refuses every request with a configuration error; surface it as such, never as a request refusal.
2. `Owned` holds only the payment and stake key hashes of keys in this workspace's store.
3. `Resolver` is built only through `OwnProvider` (the provider this operator configured) or `OwnSnapshot`, and a snapshot only from a path the operator named for that purpose. A path inside the party store, a file or tailcat inbox, or any file a received bundle wrote is refused.
4. `Signer.Handle` is fed only from a transport's own `Receive`. Nothing constructs `ports.Received` by hand, and bytes that came over a network or a synced folder are never presented as file-delivered.
5. The file inbox is a local directory the operator controls.
6. There is no approve-without-review path. The approval gate is real: it asks for the passphrase again for pool cold, payment and owner stake keys.
7. The review screen shows how the request arrived and the "inputs not checked" text word for word.
