# ADR 0014: The wallet key is the identity at the relay

Status: accepted in outline by the owner 2026-11-18; details revised after review. It amends [ADR 0013](./0013-tailnet-relay-and-mailbox.md) (the tailcat relay and mailbox), mainly its decision 2 (addressing), decision 3 (authentication and authorisation), the wire protocol (decision 6) and the static access list (decisions 3 and 7). It builds on [ADR 0005](./0005-party-envelope-and-signing-policy.md) (envelope, registry, cold-key rule; **not amended**), [ADR 0010](./0010-object-identity.md) (a key is identified by its hash; role history), [ADR 0011](./0011-key-custody-and-unlock.md) and [ADR 0012](./0012-server-backup-and-deployment.md) (decisions 3, 7 and 12; the cold-key rule). Nothing here is built. "Not confirmed" marks a fact that the code and the documents I could read do not establish.

**Revision note.** The first outline had a seven-line binding text of about 278 bytes (the draft said "six lines" and "about 230 bytes"; both counts were wrong). It does not fit what hardware wallets sign and show, so decision 3 replaces it. The review also changed the routing key (decision 2), kept the typed fingerprint check at enrolment (decision 2), deferred the directory (decision 6), and cut scope (decision 10).

## Context

ADR 0013 admits a party to the relay through a static access list: the relay administrator pastes each party's signed identity document into a configuration file, with a `send_to` list. That has three problems the owner named.

* The administrator has to know every party in advance. The owner has since decided that anyone may run a relay and that several independent relays may exist (ADR 0013, "Owner decisions, 2026-11-18").
* The relay sees opaque device fingerprints. Nobody can tell from the fingerprint which signer in a multisig it is.
* The sender already knows who must sign. A transaction or native script names its signers by key hash.

**Owner direction, 2026-11-18.** "We can actually know who the parties are. TailCat provides the transport, and a connecting client can connect their wallet (software or hardware) to provide their public key - that way the server knows which requests go to whom, and use the transport to do so." Then: "Go with your recommendations; restriction is optional; ensure that a client can logout without having to close the application."

## Decided by the owner

Four questions were put to the owner. The owner said "Go with your recommendations". Each is recorded as decided on that basis: **taken on the owner's standing instruction to follow recommendations; reversible until built.**

1. **Enrolment still needs the typed fingerprint check.** The binding is evidence shown at enrolment and rotation. It does not replace the check (decision 2). ADR 0005 is not amended.
2. **Open mode means anyone with the address.** The address is a group secret. Open mode has the protections of decision 5 and the optional allow-list.
3. **No directory in version 2.** Lookup and Directory frames are deferred with fan-out to stage 5 (decision 6).
4. **A co-signer may identify with a stand-in payment or stake key** when its hardware wallet cannot sign the binding (decision 2).

## Terms

* **Wallet key**: an Ed25519 key of role payment or stake, held in the vault (software) or on a hardware wallet. Its identity is its **key hash** `K`: Blake2b-224 of the 32-byte verification key (`txbuild.KeyHash`, `identity.KindKeyHash`, ADR 0010 decision 1). 28 bytes, 56 hex characters.
* **Device (party) identity**: the ADR 0005 identity of one installed `spo`: Ed25519 key, X25519 key, fingerprint `party.FingerprintOf(ed, x)` (20 bytes). Envelopes are sealed to it. It is `party.Identity`.
* **Binding**: a CIP-8 message signed once by a wallet key that says "this device identity uses key `K` as its mailbox address at relays, from T1 until T2". One wallet key per device.
* **CIP-8 / COSE_Sign1**: the standard message-signing structure (RFC 9052 with the CIP-8 headers). The project has it in `domain/cose`.

## Decisions

### 1. Tailcat is only the transport

Holding the relay's address (its node key and pre-shared key) admits a peer to the WireGuard tunnel and to nothing else. At the relay an unauthenticated peer may do two things: present a binding and prove the device key (decision 7), or send a few self-authenticating revokes (decision 8). The address is a barrier, not an authenticator (ADR 0013, concern T4). The relay operator invalidates a leaked address by creating a new key pair and address (ADR 0013, "Relay address and key lifecycle").

### 2. The wallet key is the mailbox address; the device key is the delegate

The relay files and delivers envelopes by device fingerprint, as ADR 0013 built it. The wallet key `K` is the **admission and quota index**: it says which signer a device speaks for, and counts that signer's devices and rates. A wallet key can sign but cannot receive encrypted mail (an Ed25519 key has no decryption half, and a hardware wallet exports nothing to seal to). So **every envelope is still sealed to a device X25519 key** (ADR 0005, unchanged).

**What the binding is worth.** It delegates *routing and mailbox access*. It never delegates signing. A witness is accepted only if it verifies against the slot's `KeyHash` (`pool.Collection.Fill`; ADR 0010: the verification key's hash must equal the demanded identity). A thief with a bound device reads mail sealed to that device and nothing more.

**Route by the party's key, not the slot's.** The mailbox address of a request is the **`Party.WalletKey`** (a new field of `domain/party.Party`) of the party at `slot.PartyFingerprint` (`domain/pool` `Slot`; `app/multisig/coordinator.go` routes by `PartyFingerprint`). `slot.KeyHash` is never sent to the relay. Routing by the slot's key would break when a stand-in key is used, when one party holds several slot keys, and for a cold slot, whose `KeyHash` is the pool id. A party with no wallet key is reachable by file or direct tailcat only.

* The sealing key and the device fingerprint come from the sender's party registry, filled at enrolment (`spo party enroll`). The relay is never asked for them.
* `ports.EnvelopeSender` stays as it is. A narrow optional capability `ports.KeyedEnvelopeSender` with `SendTo(ctx, key custody.KeyHash, to party.Fingerprint, env)` is added. `Flush` reads the key from the registry entry of the recipient (`Party.WalletKey`) when the transport offers the keyed form. The outbox item does not store it, so a change of a party's key is picked up.
* A reply goes to the coordinator's device under the wallet key recorded for that party.

**No cold key ever needs a mailbox.** No lookup and no put is ever made for a key whose role history is cold, whether it is the slot's key or the party's wallet key: a lookup alone would reveal the pool id to the relay. Cold slots stay on the carried file (ADR 0005, ADR 0012 decision 8). The holder of a cold key binds a payment or stake key for its mailbox traffic.

**The relay identity is the party's chosen key.** It is not necessarily a key named in the script. A co-signer whose hardware wallet cannot sign the binding may identify with another payment or stake key (decided, above). The other side still enrols that party by its typed fingerprint and still checks witnesses against the slot's key.

**The binding does not replace the typed fingerprint check.** An enrolled party gains authority to ask for signatures (ADR 0005 scopes). One CIP-8 signature by `K` must not become the power to impersonate a party: `K` may be a hot key, or a CIP-30 wallet may have been phished into signing the published binding text. So:

* `party enroll` still requires the operator to type the first four fingerprint groups (SPO-Xparty-PR-001; `party rotation accept` likewise, SPO-Xparty-PR-006). ADR 0005 and those requirements are not amended.
* The **binding travels with the identity document** at enrolment, as a companion file (`party export --binding FILE`; the document itself stays secret-free and unchanged, SPO-Xparty-IF-001). `party enroll DOC --binding FILE` verifies it (decision 3, rules 2 to 7, with the enroller's clock; the payload's `device` must equal the fingerprint computed from the document's keys) and shows the key's label or hash prefix and the binding's dates **as evidence next to the typed check**. Only then is `Party.WalletKey` stored, with the binding as evidence.
* At rotation, `party rotation accept NAME --binding FILE` does the same for the new identity. Without it the party's `WalletKey` is cleared and it is reachable by file or direct tailcat until evidence is supplied.
* Without a directory the relay never tells a sender who speaks for `K`. The sender has only what the operator enrolled.

**The address of a put** is the pair `(Party.WalletKey, Party.Fingerprint)`. The relay stores by device fingerprint, unchanged. It refuses the put (`unbound`) unless that device is currently bound to that key. Quotas that count a signer use `K` (decision 5).

### 3. The binding

**Payload.** One line of lower-case ASCII, single spaces, no line feed, no leading or trailing space, at most 120 bytes:

```
spo-relay-binding-v1 device <40 hex> from <unix seconds> until <unix seconds>
```

It is 101 bytes with 10-digit times. `device` is the party fingerprint (`party.FingerprintOf`). Times are decimal unix seconds without sign or leading zero. The relay parses strictly, **re-renders the parsed values and requires equal bytes** (the canonical rule of ADR 0010).

* **Why this shape.** Public documentation says Ledger signs an un-hashed message payload only up to about 160 bytes and with restricted display characters, and that Trezor shows ASCII only, with no control characters (a line feed counts) and no double, leading or trailing spaces. The earlier seven-line text fits neither. Neither fact has been run here.
* **`K` is not repeated in the payload.** It is the 28-byte `address` of the protected header, which is inside the signed `Sig_structure`, and `K` must equal Blake2b-224 of the verification key (rule 4).
* **`role` is dropped.** The relay cannot check it. The client checks the role itself (decision 4).

**Signature.** A CIP-8 `COSE_Sign1` by the wallet key:

* protected header `{1: -8, "address": <28-byte K>}`. That is what the software path writes when `MessageRequest.Address` is `K`, and what `cardano-hw-cli message sign` writes when `--address` is omitted ("the signing key hash is used", public README, not run here). A raw Shelley address is accepted if `cose.KeyBelongsToAddress` finds `K` among its credentials, because an external CIP-30 `signData` writes that form. Any other form is refused;
* the payload is embedded and **not hashed**, so the device and the relay see the text;
* unprotected header exactly `{"hashed": false}`;
* the `COSE_Key` travels with it (`cose.EncodeKey`).

**Strictness at the relay.** `domain/cose/cbor.go` is lenient today: non-shortest integer heads are accepted, the first duplicate map key wins, text is not checked for UTF-8, extra protected-header keys are ignored, and `hashed` is read from the protected header and then overridden by the unprotected one (`ParseSign1`, `cose.go`). A lenient parse makes the signed bytes and the accepted meaning differ. The relay uses a new strict parse beside it (the lenient one stays for CIP-88 and cardano-signer outputs). It refuses:

* duplicate map keys, at any level;
* non-shortest integer or length heads, and indefinite lengths;
* any protected-header key other than `1` (algorithm) and `"address"`;
* a `hashed` key in the protected header;
* an unprotected header other than the map `{"hashed": false}` (the lenient parse also accepts a bare integer);
* a payload that is not an embedded byte string.

The unprotected header is not signed, so it is malleable. The relay therefore **re-encodes the structure canonically itself**: the protected bytes exactly as signed (they are inside the signature, so they are not malleable), the unprotected header written as `{"hashed": false}`, definite lengths, shortest heads. The binding hash inside the v2 auth bytes and the registry's de-duplication use that canonical encoding. The relay compares no protected-header bytes with a template: whether `cardano-hw-cli`'s protected header is byte-identical to the project's is part of the device check below. If it is not, parsed fields are compared, never raw bytes.

**Vectors and the device check.** Payload and `Sig_structure` vectors are written first with software keys but **frozen only after one real-device check**: payment-key and stake-key message signing, un-hashed, at this length, on Ledger and Trezor, recording what the device shows and the exact protected header that `cardano-hw-cli` writes. That check is the precondition of the hardware path (work package 4). Software keys proceed without it. Keystone and Trezor support through hw-cli stays "not confirmed" until checked.

**Structurally impossible to confuse with anything else.**

| Other signature in the project | Why it cannot be a binding |
| --- | --- |
| A transaction witness | It signs the 32-byte transaction hash. A `Sig_structure` is a CBOR array starting `0x84 0x6a "Signature1"`, longer than 32 bytes, and a COSE signature is never a valid witness for a transaction hash. |
| CIP-88 registration (`SignCip88`) | Payload is a 32-byte Blake2b-256 hash. A binding payload is about 100 bytes and starts with ASCII `spo-`. |
| CIP-36 registration, Calidus `sign` | Not COSE_Sign1. |
| The ADR 0010 proof of possession, the ADR 0012 note signature | They use their own tag. The tag list in ADR 0012 decision 3 gains `spo-relay-binding-v1`, `spo-relay-revoke-v1`, `spo/relay-revoke-device/v1` and `spo/mailbox-auth/v2`. |
| A message an operator types | `ports.MessageSigner.SignMessage` takes arbitrary payload today (`native.VaultSignatures.SignMessage`, `hwcli.Session.SignMessage`). **Both gain a guard: a payload whose first bytes are `spo-` or `spo/` is refused.** It runs on the data **before any hashing** (a hashed payload would hide the prefix) and **on the lazy hardware path too**. Only the typed binding and revoke methods can produce those payloads. No CLI command calls `SignMessage` for a payment or stake key today, so the guard closes the door before one is added. |

**Hardware wallet as a signing oracle.** The client builds the payload itself from typed inputs (`SignRelayBinding(ctx, key, device, from, until)`); the relay supplies nothing that is signed, not even the time. The CLI prints the text and the `device` tail for the operator to compare with the screen. If the device shows only hex, the CLI says so and prints the hex.

**`from` and the clock.** `from` is `max(now − 60 s, last not-before + 1 s)`, where `last not-before` is the latest tombstone time the client holds for that device. A slightly fast client clock therefore still binds, and a rebind after a revoke is always later than the tombstone.

**Verification at the relay**, in this order. All failures are answered alike (`Error` code `binding`, decision 7) except the allow-list:

1. Sizes before work: `sign1` at most 512 bytes, COSE key at most 128, payload at most 120.
2. Strict parse (above); algorithm EdDSA; `hashed` false; payload embedded.
3. Ed25519 verify over `cose.SigStructure(protected, payload)`.
4. `K = Blake2b-224(vkey)`, and the protected address is `K` (or a Shelley address with `K` as a credential). The identity is the hash of the verification key, never the header alone.
5. The payload parses and re-renders equal.
6. The `device` in the payload equals `party.FingerprintOf` of the presented Ed25519 and X25519 keys **and** the fingerprint of the authenticated session.
7. Window: `from − skew <= relay now <= until`, `until − from <= MaxBindingLifetime` (180 days), `until − from >= 1 hour`. Skew is 5 minutes (`party.MaxHelloLifetime`). A relay may tighten the maximum, never raise it.
8. `from` is later than every stored tombstone `not-before` that applies to this device or this key (decision 8).
9. Allow-list, if configured (decision 5).

**Lifetime.** Default 90 days; maximum 180; renewable by signing a new binding, with an overlap. A client reminds at 14 days before `until`. An expired binding gives no delivery and no new puts; the queue is kept until retention and serves again if a fresh binding arrives.

**What the node key is not.** The party fingerprint does not cover the tailcat node key (`FingerprintOf` hashes only the Ed25519 and X25519 keys). The binding covers the fingerprint. The node key is authenticated by each connection (the auth signature covers the client node key, and the relay requires it to equal the tunnel peer). A new node key needs no wallet touch.

**Which wallet keys can sign a binding.**

* **Software, in the vault:** works with existing code. `VaultSignatures.SignMessage` with `Address = K`. The profile already allows `OpSignMessage` for payment and stake.
* **Hardware:** `hwcli.Session.SignMessage` exists and calls `message sign`. **It is not usable as it stands**: `custody.HardwareTable` (`domain/custody/hardware.go`) grants `OpSignMessage` only to `RolePoolCold` (Ledger and Keystone) today. New payment and stake rows are needed, sourced from the device documentation **plus the device check**. The profile claims only what a row states. Not confirmed on any device.
* **A co-signer whose wallet cannot sign the binding** may use another payment or stake key it can sign with (decision 2), including a vault key.
* **Any other wallet:** `spo party relay bind --print` shows the payload and its hex; the wallet signs it with CIP-30 `signData`; `--import` takes the `COSE_Sign1` and `COSE_Key` hex back. The relay checks apply unchanged. No browser integration is built.

### 4. Cold keys are excluded

The identifying key must be a payment or stake key. **Never a pool cold key, and never another cold-role key** (`custody.Role.IsCold`; ADR 0005 M6, ADR 0010 decision 3, ADR 0012 decision 8).

**Enforced on the client:**

1. The typed signing method takes a **closed sum type built only from a payment key or a stake key** (`custody.As`), so a key of another role does not compile into the call.
2. **On hardware a typed role names only what the caller claims; the signing file decides which key signs**, and devices sign messages with pool cold and committee keys too. So the binding-signing method **refuses a hardware signing file whose derivation path is not a payment or stake path**: `1852H` or `1854H` / `1815H` / account / `0` or `2` / index.
3. Before signing, the client reads the **role history** of the key identity (`ports.RoleHistoryOf`, `custody.RoleHistory`; the set only grows) and refuses if any role in it is cold. The history is empty for a key never imported (one that lives only on a device); that case rests on items 1 and 2.
4. Routing makes no lookup and no put for a key with cold history (decision 2), so a cold hash is not sent to a relay even by a client that mis-bound.

**What the relay cannot check.** A key hash carries no role, and the relay cannot tell a pool id from a payment key hash. Backstops, all partial: the client rules above; ADR 0005 (a cold-key demand is never sent over a network transport, so a bound cold key would let nobody sign over the relay, and the harm is the exposure of a cold hash and a wallet touch on a cold device); the optional allow-list. A relay with chain access could reject registered pool ids. **Not chosen**: the relay has no chain access and ADR 0013 keeps it small.

### 5. Who may use a relay

**Default (`admission = "open"`): anyone who holds the address and presents a valid binding.** A valid binding proves "this device is authorised by whoever holds `K`". It does not admit anyone in the sense of access control: any Ed25519 key makes a valid binding for free. The command help says: "In open mode the address is a group secret. Anyone who holds it can deny service. Use the allow-list for anything wider."

**Optional restriction, off by default.** `admission = "allow-list"` with a list of wallet key hashes (56 hex plus a label). A binding for another `K` is refused with the distinct `not_allowed` code, so an honest user sees why.

| ADR 0013 | Now |
| --- | --- |
| Access list of signed identity documents in a config file | Removed. Replaced by the durable registry of presented bindings (decision 7). |
| `send_to` per entry | Removed. Anyone with a valid binding may put to a bound device, bounded by the recipient's expected-sender list and the quotas below. |
| Tunnel allow-list is the access list's node keys | Open mode has no node-key list (see "First contact"). |
| `relayconfig` reads documents | It reads limits, `admission` and the optional allow-list. It parses no identity documents (the parser lives in `adapters/envelope`, which links `age` and is forbidden in the relay binary). |
| Refuse to start with an empty list (T2) | Replaced by the required key `admission = "open"` or `"allow-list"`. A missing key refuses to start. The template says `open`. |

**First contact through tailcat.** From `adapters/tailcat/stream` and `server.go`: tailcat's `AllowedClients` gates the handshake by node key and **admits every client when the list is empty**; `stream.Listen` defeats that on purpose with one key nobody holds. The pre-shared key in the address is mixed into the handshake, so only holders of the address can finish one. `AddAllowedClient` adds at runtime; tailcat cannot remove a key. An open relay needs an explicit listener mode `ListenerConfig.Open` (name proposed): empty `AllowedClients`, every node key that completes the handshake is admitted, and the relay's own accept does the checking. In allow-list mode the tunnel is open too, because the relay cannot know `K` before a binding is presented.

> **Note, 2026-11-18: open mode is blocked at the tunnel level, pending the owner's decision.** `ListenerConfig.Open` (an empty library allow-list) is not safe with tailcat v0.7.0: anyone who knows the relay's public key and DERP region can register without the pre-shared key, registrations are permanent, and the cost grows quadratically (ADR 0013, "Limits of the tunnel library"). The owner has been asked to choose between restricted by default, carrying a patch to the library, or open with a warning; the recommendation is restricted by default. Until then `Open` is not built, and the "cost of an unknown peer" measurement of work package 10 waits for the decision. Everything else in this ADR is unaffected: the wallet-key identity, the binding, routing, the registry, the quotas and logout all work inside a restricted tunnel, where "restricted" means that the operator lists the device node keys (the tunnel allow-list of ADR 0013).

**Unauthenticated connections.**

* The relay reads the peer key from `Server.PeerEnv`, sends the `Challenge`, and then accepts only an `Auth` with a binding, or up to 8 `Revoke` frames (decision 8), **within a 5 second budget for the whole connection**. Until `Auth` there is no mailbox access.
* At most **16 unauthenticated connection slots** at once, relay-wide. ADR 0013's per-node-key limits (2 live, 6 per minute) stay but are no abuse bound, since a node key costs nothing.
* **New bindings are capped at 60 per hour plus a burst of 10, relay-wide.** A re-authentication of an already registered device is not a new binding.
* The cost of an unknown peer inside tailcat (engine state, DERP use) is **not confirmed** and is measured before open mode is accepted (work package 10).

**The expected-sender list.** The `Auth` of version 2 carries, from the recipient's own party registry, the **wallet key hashes of up to 64 parties it expects mail from**. The relay stores the latest list with the binding. A put from a sender whose bound key is on the recipient's list uses the ADR 0013 bounds (per pair 8 MiB; queue 256 entries and 64 MiB). **A put from any other key shares a small stranger allowance per recipient: 16 entries and 1 MiB**, inside the queue bound. A stranger can therefore never fill a victim's queue. A list is a hint for admission only: it grants no authority, because the recipient's registry decides what is acted on (ADR 0005).

**Registry bounds.**

* At most 4096 bindings. When it is full, the relay **evicts the least recently authenticated binding that has an empty queue**. A connected device is never evicted, and a device that reconnects refreshes its time. If nothing is evictable, a new binding is refused (`limit`).
* A binding not authenticated for 30 days and with an empty queue is dropped. One with queued mail stays until `until` or retention.
* At most 8 devices per wallet key. One wallet key per device: a new binding for a device replaces its old one.

**Quotas.** As ADR 0013, plus per wallet key: puts per minute (120, summed over its devices), outstanding bytes as a sender (64 MiB). **The global quota reserves room per bound device, not per sender.** At config load the relay refuses to start if the global quota is below the per-device queue bound times the maximum number of bound devices (`max_bound_devices`, default 4096). An operator who wants a smaller disk lowers `max_bound_devices`.

**Open-mode abuse, stated plainly.** An attacker with the address can still register junk bindings (bounded by the 60 per hour cap and eviction), occupy connection slots for 5 seconds each, and use the stranger allowances of many recipients one by one. That is denial of service by someone who holds a group secret. The allow-list is the remedy.

**Mail for a device that never bound.** Refused with the put status `unbound`. A pair that was bound and expired accepts nothing new; its stored mail stays until retention. A signer that has never connected to this relay cannot be queued for. With several relays (ADR 0013) the sender tries the others.

### 6. Several devices and the directory: deferred

Version 2 has **no `Lookup` and no `Directory` frame.** Reasons: enrolment still needs the typed check and carries the binding with the identity document (decision 2), so no lookup is needed for it; a directory would enumerate which wallet keys use the relay (an enumeration oracle); and its main use is fan-out. Both are stage 5, together with ADR 0012 R9 (answer release after review or a random delay), which fan-out needs.

Until then a party has one device per wallet key, and a sender seals to the one device it enrolled. A wallet key may still have several devices at the relay, each with its own mailbox (cap 8), for instance the same person's laptop and a server. Because `unbound` answers only for a `(K, device)` pair, a prober needs both a key hash (public on chain) and a 160-bit fingerprint.

### 7. Wire protocol (version 2), the durable registry, and login

**Version rule.** ADR 0013: a field is never added to an array; a new shape is a new version. Nothing is deployed, so version 2 replaces version 1: the relay's `Challenge` announces `[2, 2]`. The abuse bounds of decision 5 are in this shape now, because a field added later would need version 3. The signed array has a new label:

```
["spo/mailbox-auth/v2", 2, relay node key, client node key, nonce, relay time, fingerprint, binding hash, senders hash]
```

`binding hash` is Blake2b-256 of the **canonical** `COSE_Sign1` bytes (decision 3). `senders hash` is Blake2b-256 of the canonical expected-sender array. `domain/mailbox.AuthBytes` and `VerifyAuth` change accordingly. **`VerifyAuth` v2 drops "the identity's node key" check: there is no identity document at the relay. It keeps "client node key = tunnel peer".** The identity is built from the presented keys.

| Type | Name | Direction | Shape |
| --- | --- | --- | --- |
| 0 | Challenge | relay to client | as ADR 0013, `min` and `max` are 2 |
| 1 | Auth | client to relay | `[version, fingerprint, signature (64), binding, senders]`. `binding` is `[ed25519 (32), x25519 (32), sign1, cose key]`. `sign1` and the COSE key are **byte strings** inside the strict frame CBOR. `senders` is an array of at most 64 byte strings of 28 bytes |
| 2 | AuthOK | relay to client | as ADR 0013, plus the binding's `until` as recorded |
| 3 | Put | client to relay | header `[request id, wallet key (28), to device (20), mid (32), size]`, then one raw frame |
| 4 to 9 | as ADR 0013 | | |
| 10 | Revoke | client to relay | device-signed `[request id, 0, ed25519 (32), x25519 (32), not-before, signature (64)]`; wallet-signed `[request id, 1, sign1, cose key]` (byte strings) |
| 11 | RevokeResult | relay to client | `[request id, status]`: `0 recorded`, `2 refused` |

Types 12 and up are reserved for the deferred lookup. **Bounds:** `sign1` 512 bytes; COSE key 128; `senders` 64 entries; the whole Auth header stays at about 3 KiB, under the 4 KiB header limit; `not-before` a unix time not beyond relay time plus skew. The strict CBOR options of ADR 0013 apply to every new field. `Fetch` and `Ack` are for the authenticated device of the session.

**Status and codes.** Put status `8 unbound`: the device has no valid binding to that key, expired or revoked included. **The client maps `unbound` to `ports.ErrNoRoute`: the item stays queued and the recipient may bind later.** Error codes: `6 not_allowed` (key not on the allow-list; sent only to the presenter, about its own key) and `7 binding` (invalid, expired or revoked binding: the client must sign a new one). Every other authentication failure stays `1 auth`, no text. A registry that cannot take a new binding answers `3 limit`.

**The registry is durable.** Bindings and tombstones are both kept across a relay restart (the registry adapter writes with temporary file, fsync and rename). Otherwise, after a restart every put to an offline recipient would be `unbound` and store-and-forward would fail. At load the relay re-verifies each stored binding and drops expired ones. Losing tombstones alone would also re-open revoked bindings until they expire.

**Revoke statements.** One line each, same text rules as the binding:

```
spo-relay-revoke-v1 device <40 hex or all> not-before <unix seconds>
```

* **Wallet-signed:** a CIP-8 `COSE_Sign1` by `K`, same strict parse and key checks as the binding. It is at most 89 bytes with 10-digit times. It names one device of `K` or all of them. The relay tombstones `(K, device or all)`.
* **Device-signed:** Ed25519 over the canonical array `["spo/relay-revoke-device/v1", device fingerprint, not-before]`, built by a typed method on the local identity, as `SignMailboxAuth` is. The relay recomputes the fingerprint from the two keys in the frame and tombstones the device.

Both are self-authenticating, so the relay accepts a `Revoke` before `Auth` (**at most 8 per connection**, inside the 5 second budget). That serves the lost-device case, where the new device must revoke without a fresh binding.

**What the relay does on a verified revoke.** It records a tombstone, deletes the binding, closes that device's live sessions, **deletes the queued mail for it** (sealed to a device that is gone), and answers `recorded` even if nothing was bound. A tombstone **keeps the maximum `not-before` seen and is never lowered**. A binding is refused unless its `from` is later than every applicable tombstone. A tombstone is kept for its `not-before` plus the maximum lifetime (180 days), then dropped, because no binding signed before it is still valid.

### 8. Revoke, offline relays, and the two actions

**Offline relays.** A client stores every revoke it made, per relay, and **re-sends its pending revokes on every connection until the revoked binding's `until`**, not just until the first `recorded` (a relay may lose state). A hostile or unreachable relay can ignore a revoke. **Expiry is the backstop:** at most 180 days from signing. A sender that confirmed the device keeps it until its operator revokes the party (ADR 0005).

**Logout** (end of the relay session; in the TUI, see decision 9). Effects, in this order:

1. cancel the context of the session: the long-poll `Fetch` and every pending relay operation stop;
2. acknowledge, best effort and bounded to 2 seconds, the items already handled. **Fetched but unacknowledged envelopes are dropped and come back on the next login** (ADR 0013, "Acknowledgement");
3. close every relay stream (`adapters/mailbox` `Client.Close`);
4. **close the tunnel dialer** (`adapters/tailcat/stream/dialer.go` `Close`), which stops the tailcat engine. That engine holds the node private key, and its DERP presence is what shows the device as online. Closing the stream alone is not enough;
5. destroy the in-memory session material: nonce and relay time, the identity handle the auth signer holds (`Kit.Local`'s `Destroy()`), connection handles;
6. stop the outbox pump over this transport (`Pump.Run` calls `Outbox.Rearm`);
7. **leave the bindings and pending revokes untouched.** Logging in again needs the workspace unlocked again (ADR 0003 and 0011) and no wallet touch.

**Forget this device.** Logout first, but **in this order**: (1) log in if needed, fetch and handle the queue (a revoke deletes it); (2) revoke: make and store a device-signed revoke per relay, `not-before` now, send it to reachable relays, keep it for others; (3) log out; (4) delete the stored bindings and `Party.WalletKey` evidence of this device, so a new login needs a new binding (one wallet touch). `spo party relay forget --lost DEVICE` signs a wallet-signed revoke for *another* device and sends it from an unbound connection.

**Plain CLI.** One process per command. `spo party relay login` runs in the foreground (like `party serve`) and **logout is the end of the process**: SIGINT or SIGTERM runs the logout effects and exits. There is no stdin command loop, and no separate `logout` command (it cannot reach another process, and an agent is out of scope). The help says so.

### 9. The TUI relay session

There is no in-process lock action today. The TUI ([ADR 0009](./0009-tui.md)) runs one command at a time under a context, and a command that waits for the relay would block it. So the relay session is a **background component** of the TUI process. It **amends ADR 0009 for this component only.** It owns the connections, the dialer and the identity handle, shows a status item, and has two menu actions: "Log out of relays" and "Forget this device".

* **Who handles fetched mail.** The session's receive loop hands each fetched envelope to the same signer and coordinator handlers that `party serve` runs. Nothing is approved automatically.
* **Store writes are serialised with the foreground command.** The session never writes the store itself. It posts each handler step as a job to the one executor that runs foreground commands, so a handler runs between commands, never during one.
* **Approvals** (a signing request waiting for the operator) are surfaced as notifications and executed as **foreground commands** (the existing review and sign commands).
* **Foreground mailbox commands use the session's transport.** `party request`, `party outbox flush` and the like send and fetch through the session's connection and do not dial a second one. With no login they fail and say "log in first".
* **Maximum login duration**, configurable (`relay_login_max`; proposed default 12 hours). **No idle auto-logout**: it would defeat receiving. At the limit the session performs logout.
* **A logged-out TUI keeps all local work**: store, workspace and any command still run. **After logout the disk holds only public bindings, pending revokes and the sealed outbox.** No node key and no unlocked identity remain in memory.
* The reachability test of ADR 0009 covers `bind`, `login`, `forget` and `status`; "Log out of relays" is a menu entry. Quitting the TUI does logout.

### 10. Scope cuts

* **One wallet key per device.** The store, its quotas, `Fetch` and `Ack` stay keyed by device fingerprint as built. The wallet key is an admission and quota index. A wallet key may have several devices (cap 8), each with its own mailbox.
* **No stdin command loop** in the plain CLI (decision 8). The logout action lives in the TUI session.
* **No directory and no fan-out** (decision 6).

### 11. Rotation and loss

| Event | What happens |
| --- | --- |
| Device key rotates (`party rotate`) | ADR 0013 order is kept: fetch and handle the mailbox, send the rotation announcement while the old binding is valid. Then a **new binding** for the new fingerprint (one wallet touch), then a device-signed revoke of the old fingerprint made with the old key before it is destroyed. Peers accept the rotation with the typed check and `--binding FILE` (decision 2). |
| Node key changes | Nothing to sign again. |
| Wallet key changes (`K` to `K2`) | A new binding for `K2` replaces the old; peers enrol again with evidence. |
| Binding expires | The client says so at login and 14 days before. A new binding is one wallet touch. |
| Device lost, wallet key and another device fine | Wallet-signed revoke from the new device (`forget --lost`); the lost device is also revoked in the registries (ADR 0005). |
| Device lost, wallet key lost too | Nothing can sign a revoke. Expiry ends it, at most 180 days. The thief reads only mail sealed to the device. |
| Wallet key stolen | The thief can bind a device of their own. No peer seals to it: peers enrol by typed fingerprint. The defence is the chain-side key change. |

### 12. Privacy

In ADR 0013 the relay learned that fingerprint A puts to fingerprint B. Now it also learns **which wallet key hashes talk to each other** and the validity dates. A key hash is public on chain once a script or address is used, so the relay can join its metadata to the chain. Content, message type and session stay unknown to it. Options: accept it and rely on who runs the relay; one relay per co-signing group run by a trusted party; a stand-in key used only for relays (decision 2, which hides the script key); a blinded address (breaks the open registry). **Chosen:** accept, advise a relay per group, and let a party use a key named in no script. Padding stays out of scope.

## Threat model

| Threat | Mitigation | Residual |
| --- | --- | --- |
| **Hostile relay** | Sees keys, devices and dates; cannot forge a binding (needs `K`'s signature), read an envelope, or make a witness verify. No directory to serve stale entries. | Metadata (decision 12), withholding revokes, dropping mail. |
| **Hostile bound user** | Quotas per device and per `K`; device cap; expected-sender list with the stranger allowance (16 entries, 1 MiB per recipient); recipients act only on registry-confirmed parties. | A listed sender fills its own 8 MiB pair bound. |
| **Stolen device with a valid binding** | Delegates routing only. Identity key sealed until unlock (ADR 0011). Revoke (wallet or device signed), expiry at most 180 days. | Reads mail sealed to it until revoked or expired. Cannot sign for `K`. |
| **Replayed or stale binding** | Window against relay time; fingerprint fixed in the payload; tombstones keep the maximum `not-before`; auth signature covers the canonical binding hash and a fresh nonce. | A relay that lost its tombstones accepts a revoked binding until it expires. The registry is durable to prevent that. |
| **Binding for a key the presenter does not control** | Needs `K`'s signature over a payload naming that device; `K = hash(vkey)`. | Anyone may bind their own fresh key (free). |
| **Binding used to impersonate a party** (hot `K`, or a CIP-30 wallet phished into signing the published text) | The binding is evidence only; enrolment and rotation still require the typed fingerprint groups (ADR 0005 unchanged). | None added over ADR 0005. |
| **COSE malleability** (lenient parse, unsigned unprotected header) | Strict parse refuses duplicate keys, non-shortest heads, extra protected keys and a non-canonical unprotected header; canonical re-encoding for hashes and de-duplication. | Device header bytes differing from the project's are compared by parsed fields (device check). |
| **Binding text as a signing oracle on a hardware wallet** | Typed method builds the bytes; relay supplies nothing; `spo-`/`spo/` guard before hashing, also on the lazy path; derivation path check; payload cannot be a transaction hash or a CIP-88 payload. | The operator must read the screen. Whether devices sign and show this text is not confirmed on real hardware. |
| **Flooding: first-contact peers and mailbox** | 5 s budget, 16 unauthenticated slots, 8 revokes before auth, checks before allocation; per-recipient stranger allowance; global quota reserves room per bound device. | A holder of the group secret can still deny service; the allow-list is the remedy. Cost of unknown peers inside tailcat not confirmed. |
| **Registry fill** | 60 new bindings per hour plus burst 10; cap 4096; eviction of the least recently authenticated empty-queue binding; connected devices never evicted; 30 day idle drop. | If every binding has queued mail, a new one is refused. |
| **Cold key bound by mistake or by a hostile client** | Closed sum type, derivation path check, role history refusal, no lookup or put for cold history, ADR 0005 transport rule. | The relay cannot see it. |
| **Revoke forged or replayed** | Both kinds signed over `not-before`; at most 8 before auth; `not-before` beyond relay time plus skew refused. | A replayed revoke only repeats itself. |
| **Address leaked** | New relay key and address (ADR 0013). Allow-list mode limits what a holder can do. | Handshake budget is spent by outsiders. |

## What changes in the packages already built

The working tree has uncommitted work in `adapters/mailbox/`, `adapters/tailcat/stream/`, `ports/relayport/authsigner.go` and `test/multiparty/mailbox_test.go`; the table treats them as built.

| Package | Keep | Change | Remove |
| --- | --- | --- | --- |
| `domain/mailbox` | Framing, `Hash`, retention, strict CBOR, quota arithmetic, device-keyed shapes | Version 2: `Auth` (binding, senders), `AuthBytes` and `VerifyAuth` (new label, binding and senders hashes, no identity node key check), `Put` header gains the wallet key, `Revoke` and `RevokeResult`, status 8, codes 6 and 7, limits | Version 1 shapes and the `AuthLabel` v1 |
| `domain/cose` | Lenient parse for CIP-88 and cardano-signer | A strict `Sign1` parse and canonical re-encoding for the relay | Nothing |
| `domain/relaybind` (new) | | Payload and revoke payloads, strict parse and verify, closed sum type | |
| `ports/relayport` | `MailboxStore` family, `Stream*`, `Clock`, store keyed by device fingerprint | `AccessList` and `AccessEntry` become a durable `Registry` (device to binding and expected senders; wallet-key index; tombstones) and an `Admission` (open or allow-list). `AuthSigner` gains the binding and senders hash parameters | `WithSendTo` and the node-key list |
| `app/relay` | `Sweeper`, quotas, put and fetch loops, long-poll | Handshake (binding, 5 s budget, unauthenticated `Revoke`), sender and recipient checks use the registry, stranger allowance, eviction, new-binding rate cap, revoke handler | The `send_to` decision, `LookupNode` |
| `adapters/mailboxstore` | **Essentially unchanged**: `dir` write path, `flock`, usage counters, arrival names, keying by device fingerprint, `Fetch`, `Ack` | One addition: delete a device's queue on revoke; counters per wallet key kept by the registry, not the store | Nothing. No migration: nothing is deployed. |
| `adapters/mailboxregistry` (new, name proposed) | | Durable bindings and tombstones | |
| `adapters/relayconfig` | TOML subset, ownership checks, limits | `admission`, optional allow-list, `max_binding_days`, `max_bound_devices`, the new limits, global-quota rule | Identity documents, `send_to`, `DocumentParser` |
| `adapters/mailbox` (client) | Reconnect, backoff, status mapping, no suppression, long-poll | Auth with binding and senders, `KeyedEnvelopeSender`, `Revoke`, `unbound` to `ErrNoRoute`, pending revokes | The v1 handshake |
| `adapters/tailcat/stream` | `Stream`, `Dialer` (`Close`), keys, `SetAllowed` | `ListenerConfig.Open`; no dummy key in open mode; unauthenticated accounting | The "empty means nobody" rule in open mode only |
| `domain/party`, `app/multisig` | ADR 0005 envelope, registry, typed check, cold rule | `Party.WalletKey` and evidence; enrolment and rotation take `--binding`; `Flush` reads the key from the registry | Nothing |
| `domain/pool.Slot` | `KeyHash`, `PartyFingerprint` | None. `KeyHash` is never sent to the relay | Nothing |
| `custody.HardwareTable`, `native.VaultSignatures`, `hwcli.Session` | The pool cold rows | New payment and stake `OpSignMessage` rows (sourced, device-checked); `spo-`/`spo/` guard incl. the lazy path; derivation path refusal | Nothing |

## Work packages

All test first, each ends with a mutation pass (alter each guard by hand and see a test fail), all in the container with no real wallet, authenticator or network. Hardware wallets are exercised only through the existing stand-in tools. Packages 1 to 3 need nothing else.

1. **Binding, revoke and strict COSE (`domain/relaybind`, `domain/cose`).** Pure. Payload and revoke build and strict parse, strict `Sign1` parse, canonical re-encoding, the closed sum type, vectors with software keys (provisional until the device check). *Accept:* canonical round trip; near-miss payloads refused (case, spaces, line feed, length over 120, number form, bad address, wrong hash, window edges at skew, 180-day cap); each strictness rule of decision 3 has a refusing test (duplicate key, non-shortest head, extra protected key, `hashed` in protected, other unprotected header); two encodings of one binding give one canonical hash; the relay's import closure holds no `age`.
2. **Protocol v2 (`domain/mailbox`).** Frames, `AuthBytes` and `VerifyAuth` with vectors, bounds. *Accept:* under, at and over tests for every new bound (senders 64, `sign1` 512, key 128); fuzz targets; v1 input refused; the auth signature fails if the binding or the senders list changes.
3. **Software signing path.** `SignRelayBinding` and `SignRelayRevoke` on the vault, the device-signed revoke, `from` rule, the `spo-`/`spo/` guard on generic `SignMessage` (before hashing, lazy path included), print and import for external wallets. *Accept:* software signs and verifies; a cold-role key and a cold-history key are refused; the guard refuses prefixed payloads on every path.
4. **Hardware signing path (gated).** **Precondition: the real-device check** (payment and stake message signing, un-hashed, at this length, Ledger and Trezor; header bytes recorded). Then the hardware table rows, derivation path refusal, vector freeze. *Accept:* the stand-in hw-cli test covers the argument list (no `--address`, ASCII one-line message); a non-payment, non-stake path is refused; rows cite the device documentation and the check. Not started until the check is done.
5. **Durable registry (`relayport.Registry`, `Admission`, `adapters/mailboxregistry`).** *Accept:* **restart, then a put to an offline bound device is stored**; tombstones survive restart and keep the maximum `not-before`; expired bindings dropped at load; eviction of the least recently authenticated empty-queue binding; connected device never evicted; 4096 cap; 30 day idle drop; device cap 8; replayed binding refused after a revoke; queue deleted on revoke.
6. **Relay session v2 (`app/relay`).** *Accept:* every verification step of decision 3 has a refusing test; unauthenticated peers cannot reach put or fetch; the 5 s budget, 16 slots, 8 revokes before auth and 60 per hour plus burst 10 hold under a fake clock; stranger allowance (16 entries, 1 MiB) enforced and listed senders use the full bounds; `unbound` for unbound, expired and revoked pairs; global-quota rule.
7. **Mailbox client v2.** *Accept:* bind, login, put, revoke over `fakenet`; `unbound` leaves the item queued (`ErrNoRoute`); pending revokes re-sent on every connection until `until`; relogin needs no signing call.
8. **Party field and enrolment evidence.** `Party.WalletKey`, `--binding` on export, enrol and rotation accept, routing by `Party.WalletKey`, keyed send, cold-history refusal; amend Xparty and Xmailbox in `spec/`. *Accept:* the two-operator test goes `PartyFingerprint` to `WalletKey` to mailbox to sealed device on `fakenet`; a stand-in key and a party with several slot keys route correctly; a cold slot is never looked up or put; enrolment without the typed groups still fails with a valid binding; the cold-key tests of ADR 0013 still pass.
9. **TUI session and logout.** Session component, executor serialisation, notifications, session transport, `relay_login_max`, logout including `Dialer.Close`, forget order, CLI `login` as process lifetime, help text. *Accept:* reachability test passes; logout leaves no connection, goroutine, tunnel engine or identity handle (leak test as `stream/leak_test.go`); unacknowledged items return on the next login; forget fetches before revoking; a logged-out TUI still runs local commands; only bindings, revokes and the outbox remain on disk.
10. **Relay config and open tailcat mode.** `relayconfig` with `admission` as a required key, the optional allow-list, the global-quota rule, `stream.ListenerConfig.Open`. *Accept:* a missing `admission` refuses to start; a global quota below the per-device bound times `max_bound_devices` refuses to start; open mode admits an unknown node key on the in-process tailcat harness and nothing without a binding goes further; allow-list mode refuses an unlisted `K` with its code; the cost per unknown peer is measured and recorded.

The first end-to-end result is package 8.

## For the owner to note

* **A real-device check is needed before hardware binding is offered.** Until then only vault keys, and external wallets through `--print` and `--import`, can bind.
* **The TUI gains a background relay session.** This amends ADR 0009 as one named exception. The alternative, a long-lived agent, stays deferred (ADR 0012).
* **Binding lifetime** is 90 days by default and 180 at most; relays may tighten. Shorter means more wallet touches.

## Deferred

* `Lookup` and `Directory` frames, the enumeration they allow, and fan-out to several devices (stage 5, with ADR 0012 R9).
* A recipient-chosen list of expected senders beyond 64 entries.
* Relays rejecting registered pool ids (needs chain access).
