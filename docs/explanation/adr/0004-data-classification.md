# ADR 0004: Data classification

Status: accepted, 2026-11-16. Closes E5.

## Decision

Every field the store persists belongs to one class. A new record kind names its class in code, and a test fails when a kind has none.

| Class | Contents | At rest | In memory | Display, logs, export |
| --- | --- | --- | --- | --- |
| **Secret** | Signing keys of every kind, mnemonics, the Catalyst QR code, provider API tokens, party identity private keys, tailcat node keys and addresses | Sealed | Guarded buffers only, never a Go `string`; passed to a tool only through an inherited file descriptor (X2) | Never logged or printed. Leaves the process only through a named, audited export use case (E6, E8) |
| **Sensitive** | Addresses, verification keys, owner relationships, wallet inventory, pool descriptors, certificates, counters, cached balances and UTxOs, run history, the party registry, audit event details | Sealed | Ordinary memory | Shown to the unlocked operator. Not written to logs at the default level |
| **Structural** | Record ids (random), kinds, versions, write times, lookup tags, key-slot parameters, key epoch, audit row kinds and times, schema version | Plaintext | Ordinary memory | Unrestricted |

How the store realises the classes ([ADR 0003](./0003-vault-and-store.md)):

* The class is not stored. It follows from the record kind and is bound into the associated data, so changing a kind or class makes the record fail to open.
* A Secret payload is opened only into guarded memory and is padded to a size bucket. A plain read of a secret kind is refused; secrets leave the store only through the vault interface.
* A Sensitive payload is sealed but not padded, so its exact length is visible in the file.
* Error text names only the kind of a record, never the operator's name for it. Sensitive values must not be logged at the default level.

**The pool `regProtectionKey`** (SPO-05a-SEC-001) is Sensitive, not Secret. It lives inside the pool descriptor, which is sealed at rest like every record, is never displayed (`pool descriptor show` omits it), never returned in a result and never sent to any service (hazard H6). It does not get guarded memory or padding, because that would mean treating the whole descriptor as a secret for the sake of a value that protects only a ticker registration at a third-party service. Decided 2026-11-16.

Rules:

* Record ids are random. They are never derived from an address, a pool id or a name.
* A value needed for lookup is stored as a keyed hash ([ADR 0003](./0003-vault-and-store.md)).
* Data that is public on chain is still Sensitive here, because the link between it and this operator is not public.
* What leaves the machine is governed separately: the envelope ([ADR 0005](./0005-party-envelope-and-signing-policy.md)) and the chain provider ([ADR 0006](./0006-chain-access-providers.md)).
