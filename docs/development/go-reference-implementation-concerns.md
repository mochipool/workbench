# Go reference implementation: concerns and decisions

This page lists every concern raised before building a Go reference implementation of the SPO scripts from the [spec corpus](../../spec/README.md). Agents working on that implementation must read it first, and must close or explicitly waive each concern they touch. It complements [Roadmap: native port](./roadmap-native-port.md), which predates the switch to Go.

Last updated: 2026-11-16.

## Decisions already taken by the user

| # | Decision | Consequence |
| --- | --- | --- |
| D1 | The reference implementation is written in **Go**, as **one binary** holding all major functionality. | Supersedes the roadmap's Python assumption and its stdlib-only rule for the native port. The existing Python `workbench` orchestrator is not rewritten by this decision; see C1. |
| D2 | **External dependencies stay external**: cardano-node, cardano-cli, cardano-hw-cli, cardano-signer, bech32, gpg and the HTTP services remain separate tools pinned by the flake. | "Single binary" means one Go binary that drives the pinned toolchain. It does not mean a statically linked Cardano stack. The `Ledger`, `KeyGen`, `Signer` (hardware) and `Toolchain` ports get adapters that execute those tools. |
| D3 | **Tailcat** (`github.com/tailscale/tailcat`) is the first `Transport` adapter for multi-party interaction over the internet. | It replaces the roadmap's "Tailscale/tsnet" assumption; the word "tailcat" in the roadmap was not a typo. Concerns T1–T8 apply. |
| D4 | **Encryption wherever it is necessary**: at rest, in transit, in exports and in the air-gap bundle. | Concerns E1–E9. |
| D5 | **The Go binary is new and sits beside the Python `workbench`** (binary `spo`, module in `spo/`). `orchestrator/` is frozen to bug fixes, kept as a test oracle, and retired when the Go binary covers its four workflows. | Settles C1: [ADR 0001](../explanation/adr/0001-go-binary-beside-the-workbench.md). |
| D6 | **Key-encryption key: passphrase plus a printed recovery key**, in a key-slot format that can later take a hardware token. | Settles E2: [ADR 0003](../explanation/adr/0003-vault-and-store.md). |
| D7 | **Every record payload is sealed**, not only signing keys. Only opaque ids, kinds and versions are stored in plaintext. | Settles E5: [ADR 0004](../explanation/adr/0004-data-classification.md). Reading anything, `status` included, needs an unlock. |
| D8 | **Pool cold keys sign only through the file transport.** There is no override in the first version. Payment, stake, owner, DRep and hardware-wallet keys may sign remotely. | Settles M6: [ADR 0005](../explanation/adr/0005-party-envelope-and-signing-policy.md). |
| D9 | **The TUI is in scope**, as a second `UI` adapter. PostgreSQL, Kubernetes and a server API are deferred; their ports stay ready. Catalyst, SPO polls, token registry and minting are ported last. | Concerns U1–U2. |
| D10 | **Chain access must not require a node socket.** HTTP and gRPC providers (for example UTxO RPC as served by TxPipe's Dolos and Blink Labs' tooling, Blockfrost-compatible APIs, Koios) are `ChainQuery` and `Submitter` adapters beside the socket adapter. | Concerns N1–N5; [ADR 0006](../explanation/adr/0006-chain-access-providers.md). The user has no preview node; settling spec open questions (C3) and acceptance runs use a remote provider. |
| D12 | **Native first.** Key and ledger operations run in process through Blink Labs' Go libraries (`bursa`, `gouroboros`) where they cover the operation; the pinned cardano-cli becomes the test oracle. Pre-1.0 libraries and less than full conformance are accepted, with parity tests where it matters most. | Amends D2: [ADR 0007](../explanation/adr/0007-native-first-with-blink-labs.md). Hardware wallets (cardano-hw-cli) and gpg stay external. Concerns X2, X3 and M2 are read in that light: the signer decodes a body natively, and the adapters under contract test are the native ones against the oracle. |
| D13 | **One workflow, capability-typed adapters.** A use case is written once against key references and narrow ports. Signers and chain providers declare what they can do in types; an unsupported combination is refused by the compiler where possible and otherwise before any effect, never from inside a signing call. | [ADR 0008](../explanation/adr/0008-capability-typed-ports.md). Hardware wallets stay on cardano-hw-cli as one signer adapter, because no Go library drives the devices. |
| D11 | **Tailcat is pinned at v0.7.0**, the latest tag on 2026-11-16. Manual runs use the public DERP relays; sandboxed tests use an in-process relay if a spike shows that works. | T1, T5. |

## How to use this page

Which library covers which need, and what we must write ourselves, is in [Go library coverage](./go-library-coverage.md).

Decisions are recorded in [`docs/explanation/adr/`](../explanation/adr/README.md); its index lists which concerns each record closes.

Every concern has an id (`C1`, `E3`, ...). The ids are stable: an agent that closes one records the decision as an ADR in `docs/explanation/` (or a section of the Go project's design doc), and links it from the concern's row here. The *Done when* column is the closing criterion. Requirement ids (`SPO-...`) point into the spec corpus.

Severity: **blocker** must be settled before code that depends on it is written; **major** before the slice that exercises it ships; **minor** before 1.0.

## Status

Updated as concerns close. A concern not listed here is open.

| Id | State | Evidence |
| --- | --- | --- |
| C1, E2, E5, M6 | closed | ADRs 0001, 0003, 0004, 0005 |
| E1, E3, S1, T3, E7, N1, N2, N4 | decided, not yet implemented | ADRs 0003, 0005, 0006 |
| C7 | closed | `spo/NOTICE` |
| X1 | closed | `tools/spo.nix` bakes the manifest; `spo/internal/adapters/toolchain` applies upstream's gates and requires the pinned version exactly; `spo toolchain check` passes against the real release set |
| X4 | closed for the runner | `spo/internal/platform/execx` takes an argument vector only and refuses shells; `spo/internal/archtest` confines `os/exec` to it. Input validation is per use case |
| X2 | closed for what exists | `execx` passes and captures secrets through inherited pipes, with tests on argv and environment. Native operations (D12) involve no process at all. No waiver is needed |
| P1 | partly closed | `packages.<sys>.spo` and `checks.<sys>.spo-tests` build on x86_64-linux; other systems and the parity harness are not yet exercised |
| P2 | partly closed | CI runs `spec-lint`, `workbench-tests`, `spo-tests` and `govulncheck`; contract tests (X3) do not exist yet |
| C4 | partly closed | `spo/test/parity` runs the pinned upstream script and the Go use case on separate workspaces and compares names, modes, counters and envelope types (`checks.<sys>.spo-parity`). `specctl coverage` with `spo/spec-coverage.toml` fails the build when an id of an implemented spec is neither cited by a test nor waived (`checks.<sys>.spo-spec-coverage`). Still missing: fixed-tip fixtures and recorded Koios responses |
| C3 | started | First executed findings folded into the spec: the quirk notes under SPO-04c-INV-002 and SPO-04b-EXT-002. No spec is `reviewed` yet |
| C5 | in use | Quirk decisions for 04c are recorded in the tests that cite the ids (`generate_kes_test.go`, `root_test.go`) |
| S4 | partly closed | `spo/internal/adapters/fsstore` covers the pool key and KES artefacts; kinds are added as use cases need them |
| C2 | in use | First use case at parity: `GenerateKesKey` (04c), 12 ids cited, 8 waived with reasons |
| M1, T6 | specified, not implemented | [`spec/extensions/Xparty.md`](../../spec/extensions/Xparty.md): identity, enrollment, envelope, messages, coordinator and signer rules, transports, with requirement ids |
| H2, H3, H4, H5, H10 | closed for `SendLovelaces` (2026-11-16) | H2: the body is built once before the confirmation and nothing is rebuilt (`spo/internal/app/wallet`, `TestSendQueuesWhatWasConfirmed`). H3: every refusal and failure is a returned error, each decision recorded per id in the tests. H4: `txbuild.SelectionStrategy`, only `all` implemented. H5: the native minimum output value and fee are byte-equal to cardano-cli's under `spo/test/parity` (the array form is the ledger's, not the map form; see the dated note in Cutxo). H10: `transferfile` writes by temporary file and rename and reads the entry back |
| E1, E2, E3, S1, S2, S3 | implemented, **review open** | `spo/internal/platform/seal`, `spo/internal/adapters/sqlitestore`, [ADR 0003](../explanation/adr/0003-vault-and-store.md). Four Opus reviews; the fourth requires one more fix before the store holds a real key |
| T2, T3, E7 | implemented, not yet reviewed | `spo/internal/adapters/{envelope,tailcat,filebag,partystore}`, `spo/internal/domain/party`. An un-enrolled node key gets no connection; the server refuses to start with an empty allow-list. Coordinator and signer use cases are not built |
| T8 | measured | Tailcat takes the binary from about 26 MB to about 44 MB; its in-process relay for tests adds about 90 test-only modules |
| N1, N3 | partly closed | Koios adapter with recorded responses; provider tokens are secret records. No second independent provider exists, so reads classed harmful need `--single-source` |
| T1 | partly closed | Tailcat pinned at v0.7.0 (D11); confinement to its adapter is enforced by `archtest` |
| H6 | closed for pool registration (2026-11-16) | `RegisterPool.Tickers` is opt-in (nil by default) and `ports.TickerProtectionChecker.CheckTicker` takes the ticker only: the protection key is stored in the descriptor (`GeneratePoolCertificate`) and has no path to any service. `TestTickerProtectionIsOptInAndSendsOnlyTheTicker`, `TestProtectionKeyIsRecordedAndNeverReturned` |
| M3 | closed for the pool witness collection (2026-11-16) | `pool.Collection.Fill` verifies the signature over the stored body hash and the key hash of the slot before the slot is touched, for a local signer, an imported upstream transfer file and (later) a remote response. A negative test per failure (`TestFillVerifiesBeforeTouchingTheSlot`, `TestImportRefusals`); against upstream's real `05d add`, which accepts a forged witness (`TestPoolWitnessTransferMatchesUpstream`) |
| M5 | partly closed | The cold-key and payer slots go through the same collection as owner slots, with a pending slot and a transfer file when the holder has no signer here and `AllowPending` is set (`TestPayerAndColdKeySlotsCanBePendingToo`). The remote request flow itself (SPO-Xparty) is not built |
| H3 (pool) | closed for 05a, 05c, 05e, 07a, 07b (2026-11-16) | No-funds, too-small change, read-back mismatch and a failed submission are returned errors; the decisions are recorded per id in `spo/internal/app/poolops/*_test.go` |

### Finding under X2 (resolved by D12): cardano-cli cannot write KES or VRF keys to a pipe

Run against the pinned cardano-cli 11.2.3.0 on 2026-11-16:

* `address key-gen` and `node key-gen` (cold key and counter) write their outputs to `/dev/fd/N` pipes. No file is needed.
* `node key-gen-KES` and `node key-gen-VRF` fail on a pipe: they create a temporary file beside the destination and rename it (`/dev/fd/: openTempFile: does not exist`).

**Resolved 2026-11-16:** KES and VRF keys are generated in process (`spo/internal/adapters/native`), with no file, pipe or child process. `TestNativeKeysMatchCardanoCLI` shows that the pinned cardano-cli accepts those keys and derives the same verification keys. The handling below was the plan before D12 and is kept for the record.

So X2's "never a temp file" cannot hold for KES and VRF generation through cardano-cli. Planned handling, to be confirmed in an ADR when key generation is implemented:

1. The cardano-cli `KeyGen` adapter gives those two commands a path inside a private `0700` directory on a memory-backed file system (`$XDG_RUNTIME_DIR` or `/dev/shm` on Linux), reads the file into guarded memory, overwrites and removes it. The key is on a file system for milliseconds and never on a disk.
2. Where no memory-backed file system exists, the adapter refuses unless the operator opts in.
3. Native generation of KES and VRF keys (the model lists a native `KeyGen` adapter) removes the waiver and is the preferred end state.

KES and VRF keys are the hot keys that must exist in plaintext on the block producer anyway, which is why a waiver here is tolerable and one for cold or payment keys would not be.

## Strategy and scope

| Id | Severity | Concern | Done when |
| --- | --- | --- | --- |
| C1 | blocker (decided: D5) | **Relationship to the existing `workbench` (Python).** It is unspecified whether the Go binary replaces the `workbench` CLI, sits beside it, or is driven by it. The roadmap recommended keeping the front end and swapping adapters, but that assumed Python. | An ADR states which binary operators run, what happens to `orchestrator/`, its docs and its tests, and how `workbench.toml` and run state migrate. |
| C2 | major | **Do not build everything at once.** "All major functionality" is about 77 use cases ([use-cases](../../spec/domain/use-cases.md)). A big-bang port cannot be checked for parity. | Work proceeds in vertical slices, each with differential tests. Suggested first slice: KES rotation (`04c`/`04d`/`04e`), send ADA (`01_sendLovelaces`, the shared pipeline `Ptx`), and a two-owner pool registration with one remote software signer and one hardware signer (`05a`/`05c`/`05d`). |
| C3 | blocker | **The spec is a source reading, not an execution record.** Two Opus reviews checked it against the Bash, but nothing in it has been run. Every spec has *Open questions* that depend on tool output. | Before a slice is implemented, its specs' open questions are settled by runs against the pinned toolchain on preview, and the answers are folded back into the spec (`status = "reviewed"`). |
| C4 | blocker | **There is no parity harness.** Requirement ids are only useful if tests cite them and a check enforces coverage. | A harness exists with fixture workspaces (fixed keys, fixed tip), a differential runner that executes the pinned upstream script and the Go use case on the same fixture and compares state, recorded Koios responses for light mode, and a flake check that fails when a requirement id of an implemented use case has no citing test (`specctl ids`). Seed: `orchestrator/tests/test_e2e_real_scripts.py`. |
| C5 | major | **Each upstream quirk needs an explicit decision.** The corpus marks behaviour that looks unintended with `> **Upstream quirk:**`; parity does not mean copying it. | Every quirk in an implemented spec has a recorded decision (reproduce, fix, or make configurable) in the test that cites its id. The fix-by-default list is under *Correctness hazards*. |
| C6 | major | **The spec is the source of truth, not the Bash.** If implementers read the Bash directly, the corpus decays. | `AGENTS.md` rule: behaviour questions go to `spec/`; a discovered discrepancy is fixed in the spec (and its tests) in the same change as the code. |
| C7 | minor | **Licensing.** Upstream `gitmachtl/scripts` is MIT (copyright 2021 Gitmachtl/ATADA_StakePool_Austria); this repo is GPL-3.0. A port derived from the spec is compatible, but the spec quotes short fragments of upstream code. | The Go project carries upstream's MIT notice in a `NOTICE` or `THIRD_PARTY` file. |

## External tools (D2)

| Id | Severity | Concern | Done when |
| --- | --- | --- | --- |
| X1 | blocker | **Locating the pinned toolchain.** The binary must run the release set's exact tool versions, not whatever is on `PATH`. | The Nix wrapper bakes absolute tool paths and versions into the binary or a manifest, as `tools/workbench.nix` does for Python. Startup refuses version mismatches with the same gates as `00_common.sh` (SPO-Cconf-PRE-*, `tools/spo-compat.nix`). |
| X2 | blocker | **Secrets must never appear in argv, the environment or a temp file.** Upstream passes the gpg passphrase in argv (SPO-Ckey-SEC-001), allows it in the environment (SPO-Ckey-SEC-003), and leaves signed transactions in world-readable temp files (SPO-Ptx-SEC-002). | Every adapter that hands a secret to a tool uses an inherited pipe or file descriptor (`exec.Cmd.ExtraFiles`, `/dev/fd/N`), the equivalent of upstream's `<(echo ...)` (SPO-Ptx-SEC-001). A test inspects argv and env of every spawned process for key material. Temporary non-secret files go in a private `0700` directory that is removed on exit. |
| X3 | major | **Parsing tool output is brittle across versions.** Many upstream behaviours hinge on cardano-cli output shapes (see the open questions in Cconf, Clight, 03a and 24c). | Adapters parse JSON output only, and are versioned against the release set. Contract tests run each adapter against the pinned tools in CI. |
| X4 | major | **No shell.** Upstream builds commands with string interpolation; names reach `jq` program text unescaped (SPO-01workOffline-SEC-005) and bash arithmetic (SPO-07a-SEC-001). | Tools are executed with argument vectors only, never through `sh -c`. All operator input is validated before it reaches any tool. |
| X5 | minor | **gpg is needed only for compatibility.** It remains external, for importing upstream `enc` keys (SPO-Ckey-OUT-001, SPO-Ckey-INV-003) and optional export in that format. | gpg is not on the path of any native-vault operation. |
| X6 | major | **cardano-hw-cli is a Node tool** that must be present wherever a hardware wallet signs, including remote signer machines. | The signer-client packaging includes the pinned cardano-hw-cli. `Signer.openHardwareSession` applies the version gates of [Chw](../../spec/upstream/common/Chw.md). |

## Encryption and secret handling (D4)

| Id | Severity | Concern | Done when |
| --- | --- | --- | --- |
| E1 | blocker | **Vault construction.** The vault design is: an AEAD per record (for example XChaCha20-Poly1305), a data key per record wrapped by a key-encryption key, and associated data binding each ciphertext to its record id, kind and owner (closing SPO-Ckey-SEC-004). | An ADR fixes the cipher, the KDF and its parameters (Argon2id memory, time and parallelism), the record format and its versioning. Test vectors are committed. |
| E2 | blocker | **Where the key-encryption key comes from** (roadmap Phase 0 question 4): passphrase only, or also a hardware token or the hardware wallet. | ADR. |
| E3 | blocker | **Single-file store is a single point of failure.** Losing or corrupting one SQLite file loses every key. | A backup and recovery design exists (encrypted export, restore, verification of a backup), with a tested restore. |
| E4 | major | **Go cannot reliably wipe memory.** The garbage collector may copy buffers, and strings are immutable. | Key material lives only in locked, guarded buffers (for example `memguard`), never in `string`. Core dumps are disabled (`RLIMIT_CORE=0`, `PR_SET_DUMPABLE`), and swap exposure is documented. A test asserts that no plaintext key appears in a heap profile of a signing operation. |
| E5 | major | **What counts as sensitive** beyond keys (roadmap Phase 0 question 3): owner relationships, wallet inventories, balances, the pool `regProtectionKey` (SPO-05a-SEC-001), and mnemonics (SPO-Pfiles-SEC-003). | ADR with a classification table; every `Store` field is classified. |
| E6 | major | **Exports.** The block producer needs a plaintext KES key and opcert. Today's bundle is a tar of plaintext files. | Export is a named, audited use case. The bundle is encrypted to the recipient (for example an `age` recipient key of the block producer), and plaintext lands only on the destination host. |
| E7 | major | **The air-gap bundle is unauthenticated.** `offlineTransfer.json` is neither signed nor encrypted (SPO-Ptransfer-SEC-002), and `extract` trusts stored paths (SPO-Ptransfer-SEC-001, SPO-01workOffline-SEC-004). | The Go file transport signs and encrypts the bundle between enrolled machines, never writes outside its own directory, and still imports and exports the upstream format for compatibility. |
| E8 | major | **Logs and display.** Upstream prints signing keys, mnemonics and passwords (SPO-04c-SEC-001, SPO-04a-SEC-001, SPO-04c-SEC-002). | No code path prints, logs or traces secret material. A test greps captured output of every use case for key material. Display of a mnemonic is an explicit, audited export. |
| E9 | minor | **Importing upstream workspaces** must read plaintext and gpg-wrapped keys, including passwords that upstream's `read` without `-r` mangled (see [Cui](../../spec/upstream/common/Cui.md), [Ckey](../../spec/upstream/common/Ckey.md)), and seal them on import. | An import test covers each form. |

## Transport: tailcat (D3)

Facts as published (pkg.go.dev, v0.7.0, BSD-3-Clause, open-sourced August 2026):

* WireGuard point-to-point tunnels over Tailscale's data plane and DERP relays, **without Tailscale's control plane**: no Tailscale account, no root.
* Identity is the node key.
* A `Server` restricts clients with `AllowedClients` / `AddAllowedClient`.
* A `Client` dials a server by its tailcat `Addr`.

| Id | Severity | Concern | Done when |
| --- | --- | --- | --- |
| T1 | blocker | **No stability promises.** Upstream states there are no API, CLI or wire-format stability promises, and v0.7.0 is not the latest version. | The module version is pinned (Nix `vendorHash`). Tailcat is used only inside the `Transport` adapter. A second adapter (plain TLS or `tsnet`) is feasible behind the same port, shown by an interface test suite both could pass. |
| T2 | blocker | **Fail-open authorisation.** Per the docs, until a key is allowed all clients are allowed. | Every server is constructed with a non-empty `AllowedClients` before `Start`. A test proves that an unenrolled key is refused. The binary refuses to start a server with an empty allow-list. |
| T3 | blocker | **Tunnel identity is not application identity.** A tailcat node key proves possession of a WireGuard key, not which operator or role is acting. | The application layer adds mutual authentication with pinned long-term keys (Noise or signed messages), and every request and response is signed end to end, so a compromised relay, tunnel or address leak cannot forge a signing request or a witness. |
| T4 | major | **Addresses are secrets, but not confidential enough to rely on.** A tailcat address grants connectability; saved keys make addresses reusable. | Addresses are distributed only through the enrollment ceremony (T6). Rotation is supported, and authorisation never depends on address secrecy (T2, T3). |
| T5 | major | **Public DERP relays have no SLA** and may be revoked. | Self-hosted DERP is supported through `DERPMapURL`. The design tolerates relay outages within the witness window (`ttl`, SPO-05d-INV-003). |
| T6 | blocker | **Enrollment.** Pinning keys needs an out-of-band ceremony: who is a party, in which role, for which pool. | A protocol spec defines enrollment (key exchange and verification by fingerprint), the party registry in `Store`, revocation, and key rotation. |
| T7 | major | **Exposure.** A coordinator reachable from the internet can be probed and flooded. | Rate limits, request size limits and timeouts are set. Unauthenticated peers get no application-level response. A threat model is written. |
| T8 | minor | **Dependency weight.** Tailcat pulls in much of `tailscale.com` (gVisor netstack, magicsock). | `govulncheck` runs in CI, the build is reproducible in Nix, and binary size and the dependency list are reviewed once. |

## Multi-party signing protocol

| Id | Severity | Concern | Done when |
| --- | --- | --- | --- |
| M1 | blocker | **The protocol is not specified.** [extension-points](../../spec/domain/extension-points.md) sketches coordinator and signer, but the messages, states and errors are missing. | A protocol spec with its own requirement ids defines: signing request (body, body hash, slot, key hash, expiry, nonce, coordinator identity), response (witness, nonce), errors, the coordinator and signer state machines, idempotency, and the replay log. |
| M2 | blocker | **The signer must decode the body itself** and show it in human terms before approval (closing SPO-05d-INV-008). That needs a `Ledger` adapter, and therefore cardano-cli, on each signer machine. | The signer client packaging includes cardano-cli; approval shows certificates, deposits, outputs, fee, TTL and pool id from the locally decoded body. |
| M3 | blocker | **Verify every witness on import**: valid signature over the stored body, and key hash equal to the slot's key hash (closing SPO-05d-INV-006, SPO-05d-SEC-003). | Implemented with a negative test per failure. |
| M4 | major | **Hardware wallets on remote clients.** The body must be in hardware-canonical form ([Ctx](../../spec/upstream/common/Ctx.md)) before hashing, so the hash a signer verifies is the hash the device signs. Some hardware flows need unrestricted mode (SPO-21b-SEC-003). | The coordinator canonicalises before creating the request. Unrestricted mode is never defaulted on. |
| M5 | major | **Every slot must be signable.** Upstream can sign only owner stake-key slots (SPO-05d-INV-007). | Owner, payer and cold-key slots all go through the same request flow. |
| M6 | major | **Air-gap policy** (roadmap Phase 0 question 6): which key classes may sign over the network. | ADR. Default: pool cold keys sign only through the file transport. |
| M7 | major | **Authorisation model:** who may ask whom to sign what. | Requests are authorised against the party registry (T6) by role and pool. Signers refuse requests outside their enrolment. |

## Correctness hazards found in the spec (fix by default)

These behaviours are dangerous or wrong. The Go implementation fixes them by default and records each decision under C5.

| Id | Requirement | Hazard |
| --- | --- | --- |
| H1 | SPO-04d-SEC-003, SPO-04d-MODE-003 | In light mode a failed Koios lookup is read as "no block made yet", leading to an offer (default Yes) to reissue the opcert with counter 0. Treat "unknown" as distinct from "none" and refuse. |
| H2 | SPO-01claimRewards-PRE-009 | An unchecked final build signs and submits a stale body from an earlier run. Build into a fresh path and check every tool exit. |
| H3 | SPO-Ptx-MODE-002, SPO-Ptx-MODE-003, SPO-Ptx-MODE-008, SPO-Ptx-MODE-009 | Many failures exit 0. Every failure is an error result. |
| H4 | SPO-Ptx-INV-002 | There is no coin selection: every UTxO is spent, so large wallets hit `maxTxSize`. Keep the default for parity, but make the selection strategy a port option. |
| H5 | SPO-Cutxo-INV-007 and the open question in [Cutxo](../../spec/upstream/common/Cutxo.md) | The native minimum-output computation may not match the ledger (map versus array form). Use cardano-cli's computation (D2), and keep the native one only as a cross-check. |
| H6 | SPO-05c-SEC-002 | The ticker and the protection key are sent to a hard-coded third-party URL. Make this opt-in, and never send the protection key. |
| H7 | SPO-07a-SEC-001, SPO-01workOffline-SEC-005 | Command or `jq` injection through arguments. Moot without a shell (X4), but test the inputs anyway. |
| H8 | SPO-Ckey-PRE-003, SPO-Ckey-PRE-006, SPO-Ckey-PRE-010 | A malformed encrypted key loops on password prompts forever. Fail fast on a malformed envelope. |
| H9 | SPO-11a-MODE-002 | Offline mint and burn update the asset record when the transaction is queued, not when it is submitted. Update on confirmed submission (domain event). |
| H10 | SPO-Ptransfer-INV-002 | The transfer file is rewritten non-atomically with no lock. All `Store` writes are atomic per aggregate. |

## Storage

| Id | Severity | Concern | Done when |
| --- | --- | --- | --- |
| S1 | blocker | **SQLite driver versus static binary.** SQLCipher needs CGO, which conflicts with a simple static build; the pure-Go `modernc.org/sqlite` has no built-in encryption. | ADR. Recommended: pure-Go SQLite with application-level sealing (E1), so the same sealing works on PostgreSQL. |
| S2 | major | **Atomic aggregate writes and concurrency.** These are required by the domain model and needed for several coordinator replicas (Kubernetes). | `Store` exposes transactions per aggregate with optimistic concurrency, and the witness slot fill is a compare-and-set (see [05d port notes](../../spec/upstream/scripts/05d_poolWitness.md)). |
| S3 | major | **Schema migrations and the audit log.** | Versioned migrations, plus an append-only, hash-chained audit table. |
| S4 | minor | **The file-system adapter** with the upstream layout ([Pfiles](../../spec/upstream/patterns/Pfiles.md)) is still needed for import, export and differential tests. | Implemented first, because the parity harness needs it. |

## Chain access without a node socket (D10)

| Id | Severity | Concern | Done when |
| --- | --- | --- | --- |
| N1 | major | **Which providers.** Candidates: UTxO RPC over gRPC (`github.com/utxorpc/go-sdk`; served by Dolos, and by Blink Labs' `cardano-node-api` and Dingo), a Blockfrost-compatible HTTP API, Koios (upstream's light mode, [Clight](../../spec/upstream/common/Clight.md)), Ogmios, and Ouroboros node-to-client over TCP (`github.com/blinklabs-io/gouroboros`). Each covers a different subset of the `ChainQuery` operations; governance and pool-state reads are the gaps. | An ADR picks the first adapters and records, per `ChainQuery` operation, which adapter serves it. One contract suite runs against every adapter. A use case that needs an operation the configured adapter lacks refuses before any effect, as upstream does per work mode. |
| N2 | blocker | **A remote provider is untrusted for integrity.** A false UTxO set only makes a transaction fail, but a false opcert counter, reward balance or pool state leads the operator into a harmful action (compare H1). | Every `ChainQuery` read is classified by the harm of a false answer. "Unknown" is a distinct result from "none". Reads classed harmful either come from two agreeing providers or need an explicit, audited confirmation that names the single source. |
| N3 | major | **Provider credentials are secrets.** API keys and tokens (the handoff's plaintext `koiosApiToken` item) must not sit in a config file. | Credentials are vault records. Adapters require TLS, except to loopback, and verify certificates. Credentials never appear in argv, logs or error text (X2, E8). |
| N4 | major | **Privacy.** Querying a provider reveals the operator's addresses and wallet inventory to it, and D7 classes that as sensitive. | The provider is an explicit per-network choice with no silent default to a third party. The threat model states what each provider learns. Self-hosting (for example Dolos) is documented. |
| N5 | major | **Protocol-parameter and UTxO shapes differ by provider**, while the `Ledger` adapter (cardano-cli) needs its own JSON forms. Upstream fetches a prepared parameters file in light mode. | Each adapter converts to the canonical domain types, and a test compares the converted parameters with cardano-cli's for the same epoch. |

## Front ends (D9)

| Id | Severity | Concern | Done when |
| --- | --- | --- | --- |
| U1 | major | **The TUI must not grow its own behaviour.** | CLI and TUI are adapters of one `UI` port over the same use cases. A test drives every use case through both, and a check fails when a use case is reachable from one and not the other. |
| U2 | major | **Secrets on screen.** A TUI redraws, keeps scrollback and may be recorded. | Passphrases are never echoed. A mnemonic or key is shown only by the audited export use case (E8), on the alternate screen, and cleared on exit. Signing-request review shows the locally decoded body (M2). |

## Packaging and process

| Id | Severity | Concern | Done when |
| --- | --- | --- | --- |
| P1 | major | **Nix packaging** on all supported systems, with the pinned toolchain wrapped (X1). Note the hw-cli linux-arm64 pin issue recorded in the handoff and in `versions.nix`. | `packages.<sys>.<binary>` builds with `buildGoModule`, and `checks.<sys>` runs the Go tests and the parity harness. |
| P2 | major | **CI** runs `spec-lint`, Go tests, contract tests (X3) and `govulncheck`. | Added to `.github/workflows/validate-nix.yml`. |
| P3 | major | **Upstream bumps** must flow through the spec, then the tests, then the code. | The release procedure in [`spec/README.md`](../../spec/README.md#absorbing-an-upstream-release) gains a final step: re-run the tests that cite changed ids. |
| P4 | minor | **Subagent model routing.** The user's rule applies: an explicit `model` on every dispatch, `sonnet` for work, `opus` for review. | Followed. |
