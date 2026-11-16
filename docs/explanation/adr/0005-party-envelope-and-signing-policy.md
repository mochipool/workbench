# ADR 0005: Party envelope and remote-signing policy

Status: accepted, 2026-11-16. Closes T3, E7 and M6; sets the basis for M7. The message catalogue and state machines are specified separately (M1, T6).

## Context

Parties exchange signing requests and witnesses by carried file or over tailcat. A tailcat node key proves possession of a WireGuard key, not who is acting, and a carried file proves nothing at all. Upstream's transfer file is neither signed nor encrypted (SPO-Ptransfer-SEC-002, SPO-05d-SEC-002).

## Decision

### One envelope, every transport

Every message between two machines is an **envelope**. The transport only moves envelope bytes. The file transport writes them to a file; the tailcat transport sends them over a stream. Remote and carried signing therefore share one code path and one set of checks.

* **Party identity.** Each enrolled machine has a long-term identity: an Ed25519 signing key and an X25519 encryption key, both Secret records. Its fingerprint is a hash over both public keys.
* **Sealing.** The sender builds a payload of `[version, message type, sender fingerprint, recipient fingerprint, message id, created, expires, body]`, signs it with its Ed25519 key, and encrypts payload and signature to the recipient's X25519 key with `age`. Naming the recipient inside the signed payload stops a recipient from re-sending the message to someone else as if it were addressed to them.
* **Opening.** The receiver decrypts, then refuses unless all of these hold: the sender fingerprint is enrolled and not revoked; the signature verifies; the recipient fingerprint is its own; the message has not expired; the message id is not in its replay log; the sender's role permits this message type for this pool (M7). A refused envelope gets no reply that reveals why.
* **Enrollment** pins the two public keys of each party after the operators compare fingerprints out of band (T6).

### Layers over tailcat

| Layer | Provides |
| --- | --- |
| WireGuard tunnel with the pre-shared key in the tailcat address | Confidentiality and forward secrecy in transit; hides traffic from the relay |
| `Server.AllowedClients`, always non-empty (T2) | Only enrolled node keys reach the listener |
| Envelope | End-to-end authenticity, confidentiality, replay protection and authorisation, independent of the tunnel and of address secrecy (T4) |

A coordinator refuses to start with an empty allow-list.

### What the envelope does not provide

Envelopes carried by file have no forward secrecy: someone who later obtains a recipient's X25519 key can read old files. Witnesses and transaction bodies become public on chain, so the exposure is the request metadata. The threat model records this.

### Which keys may sign remotely (M6)

| Key class | Tailcat transport | File transport |
| --- | --- | --- |
| Pool cold key | **Refused**, no override in this version | Allowed |
| Payment, stake, owner stake, DRep, committee hot | Allowed | Allowed |
| Hardware-wallet keys of any class except pool cold | Allowed; the device shows and approves the transaction itself | Allowed |

The refusal is enforced twice: the coordinator does not send a cold-key request over a network transport, and a signer refuses one that arrives over a network transport.

### The air-gap bundle

The Go bundle between an operator's own online and offline machines is an envelope too, so both machines are enrolled with each other. The upstream `offlineTransfer.json` format is still read and written for compatibility. Importing one never writes outside the bundle's own directory (SPO-Ptransfer-SEC-001), and what was imported from an unauthenticated file is marked as such in the audit log.
