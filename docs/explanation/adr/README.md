# Architecture decision records

Decisions for the Go reference implementation (`spo/`). Each record closes concerns listed in [Go reference implementation: concerns](../../development/go-reference-implementation-concerns.md). A record is changed only by a later record that supersedes it.

| ADR | Decision | Closes |
| --- | --- | --- |
| [0001](./0001-go-binary-beside-the-workbench.md) | The Go binary `spo` sits beside the Python `workbench` | C1 |
| [0002](./0002-architecture-and-dependencies.md) | Package layout, dependency rule and third-party libraries | C6, X4, U1, T1 (part) |
| [0003](./0003-vault-and-store.md) | Sealed single-file store: ciphers, key slots, record format, backup | E1, E2, E3, S1, S3 (part) |
| [0004](./0004-data-classification.md) | What is sealed and how each class is handled | E5 |
| [0005](./0005-party-envelope-and-signing-policy.md) | One signed and encrypted envelope for every transport; which keys may sign remotely | T3, E7, M6, M7 (part) |
| [0006](./0006-chain-access-providers.md) | Chain access over HTTP and gRPC providers, and trust in their answers | N1, N2, N4 |
| [0007](./0007-native-first-with-blink-labs.md) | Native first with Blink Labs' Go libraries; cardano-cli becomes the test oracle | X2 finding; amends D2 |
| [0008](./0008-capability-typed-ports.md) | One workflow; adapters declare capability in types, checked at compile time and before any effect | M5; basis for M4, X6 |
| [0009](./0009-tui.md) | The TUI is a second driver of the same command tree: menus and forms generated from it, prompts as modals, secrets on private pipes | U1, U2 |
| [0010](./0010-object-identity.md) | **Accepted.** Objects are identified by hash, names are labels; a key reference carries no holder | closes the name-binding class behind the Xmulti import limits |
| [0011](./0011-key-custody-and-unlock.md) | **Accepted.** No plaintext secret from the release binary; unlock policies with FIDO2 and Vault/KMS factors; rotation | decisions 1 and 2 are built; slots, policies, the cold sub-key, rotation and node delivery are built; amendments accepted 2026-11-18 |
| [0012](./0012-server-backup-and-deployment.md) | **Accepted 2026-11-18 with the owner-question recommendations.** Server that cannot decrypt, object store, signed history, backup to S3 or a filesystem | stages 1 to 4 may be built; stage 5 needs the formal model and a further review of decision 3 |
