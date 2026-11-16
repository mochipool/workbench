# ADR 0004: Data classification

Status: accepted, 2026-11-16. Closes E5.

## Decision

Every field the store persists belongs to one class. A new record kind names its class in code, and a test fails when a kind has none.

| Class | Contents | At rest | In memory | Display, logs, export |
| --- | --- | --- | --- | --- |
| **Secret** | Signing keys of every kind, mnemonics, the pool `regProtectionKey` (SPO-05a-SEC-001), provider API tokens, party identity private keys, tailcat node keys and addresses | Sealed | Guarded buffers only, never a Go `string`; passed to a tool only through an inherited file descriptor (X2) | Never logged or printed. Leaves the process only through a named, audited export use case (E6, E8) |
| **Sensitive** | Addresses, verification keys, owner relationships, wallet inventory, pool descriptors, certificates, counters, cached balances and UTxOs, run history, the party registry, audit event details | Sealed | Ordinary memory | Shown to the unlocked operator. Not written to logs at the default level |
| **Structural** | Record ids (random), kinds, versions, write times, key-slot parameters, schema version | Plaintext | Ordinary memory | Unrestricted |

Rules:

* Record ids are random. They are never derived from an address, a pool id or a name.
* A value needed for lookup is stored as a keyed hash ([ADR 0003](./0003-vault-and-store.md)).
* Data that is public on chain is still Sensitive here, because the link between it and this operator is not public.
* What leaves the machine is governed separately: the envelope ([ADR 0005](./0005-party-envelope-and-signing-policy.md)) and the chain provider ([ADR 0006](./0006-chain-access-providers.md)).
