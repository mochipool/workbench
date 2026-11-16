# Roadmap: native port of the SPO scripts

This is the planned next major piece of work. It replaces orchestrating `gitmachtl/scripts` with a native Python implementation at feature parity. That implementation has stronger controls: a single encrypted store, remote and multi-party signing over a secure channel, and alternative front ends such as a TUI. All of it is built against a structured specification of the upstream scripts that an agent can keep in sync with upstream changes.

Status: **Phase 1 (spec foundation) in progress, ahead of the original scope.** The corpus in [`spec/`](../../spec/README.md) covers every upstream script and every `00_common.sh` function, not only the wrapped ones. Direction agreed with the user on 2026-11-15. The current state is in [Handoff](./handoff.md). The other Phase 0 decisions are still open. **2026-11-16:** the user chose Go (one binary, external tools stay external), tailcat as the first transport, a TUI, and chain access without a node socket; this supersedes the Python assumptions below, and settles open questions 3, 4, 6 and 8. Concerns and their closing criteria: [Go reference implementation: concerns](./go-reference-implementation-concerns.md).

## Why

The orchestrator removed much of the sequencing pain, but the remaining pain is structural to the scripts. Wrapping them cannot fix it:

* **Multi-party signing is file passing.** Pool registrations with several owners or hardware-wallet owners collect witnesses by moving `<pool>.<owner>_<id>.witness` files between people and machines (`05d_poolWitness.sh`), inside a roughly 100 000-slot window.
* **State is hundreds of loose files.** Keys, counters, certs, metadata and addresses sit in one flat directory, protected by `chmod 400` and naming conventions. Rotations and packaging are file management.
* **Encryption is opt-in and manual.** `enc` keys are gpg-wrapped per file (`01_protectKey.sh`). Plaintext keys are the default, and a decrypted key is a normal file again.
* **The air gap moves a JSON file by hand.** It works, but every round trip is a manual copy with no integrity or authenticity beyond the operator's care.

## Target architecture: ports and adapters

A pure application core of use cases (rotate KES, register pool, collect witnesses, withdraw, vote, ...) talks only to ports. Adapters implement the ports. The upstream work modes and the carry bag become adapter choices, not branches through every script.

| Port | Responsibility | Adapters (first in bold) |
| --- | --- | --- |
| `Store` | All non-secret state: addresses, certs, counters, pool config, run journal, audit log | **SQLite single file**; later others |
| `Vault` | Secret material. The port's API accepts and returns only sealed objects; plaintext exists only inside a signing operation, in memory | **SQLite (same file), envelope-encrypted**; HW wallet as a vault that never releases keys |
| `Ledger` | Build, inspect, hash and assemble transactions and certificates | **cardano-cli** (release-set pinned); maybe a native library later |
| `ChainQuery` | Tip, UTxOs, rewards, protocol parameters, pool state | **local node socket** (online), **Koios** (light), **offline snapshot** (offline) |
| `Submitter` | Submit signed transactions | node socket, Koios |
| `Signer` | Produce witnesses for a tx body or certificate | **local vault key**, **hardware wallet** (cardano-hw-cli), **remote signer** |
| `Transport` | Move requests and responses between machines and parties | **file carry bag** (air gap), **secure channel** (server mode) |
| `UI` | Interaction and confirmation | **CLI**, **TUI**, server API |

The upstream work modes map onto `ChainQuery` adapters (online = node socket, light = Koios, offline = snapshot) and onto the choice between submitting and queuing. `offlineTransfer.json` becomes one `Transport` adapter.

### Single file, no plaintext

* One SQLite database per operator workspace holds everything.
* Sensitive data is **sealed at the port**: the `Vault` interface has no method that stores or returns plaintext. Envelope encryption: a per-record data key under an AEAD cipher, wrapped by a key-encryption key derived from the operator passphrase (Argon2id), or held by a hardware token. Associated data binds each ciphertext to its record id and type, so records cannot be swapped.
* Decide whether non-secret tables are also encrypted, by whole-database encryption (SQLCipher) or by sealing every column. "No plaintext of sensitive data" is the requirement; which data counts as sensitive is a Phase 0 decision. Addresses and pool parameters are public on chain; owner relationships and wallet inventories arguably are not.
* `cardano-cli` reads signing keys from files. Hand them over through an anonymous pipe or `memfd` (the upstream scripts already use `<(echo "$skeyJSON")`), never a temporary file.
* Explicit export boundaries remain: the block producer needs a plaintext KES key and opcert. Exports are a named use case, are audited, and produce the same bundle format as today's `kes-rotate`.
* Import from an existing scripts directory, the equivalent of `0x_importHelper.sh`, is a first-class use case. Operators arrive with directories of files.

### Server mode and remote signing

The goal is to replace file passing with a request and response over a secure channel, while keeping keys where they are:

1. A coordinator (online) builds the unsigned body and sends a **signing request** to each required signer.
2. The signer **decodes and verifies the body itself** (via the `Ledger` port; it never trusts the coordinator's summary) and shows it in human terms. The operator approves locally. The signer returns **only a witness**.
3. The coordinator assembles the witnesses and submits.

Multi-owner pool registration becomes "each owner approves a request", replacing `05d` file shuffling.

Requirements and open points:

* **Mutual authentication and pinning.** Use Tailscale (WireGuard with NAT traversal) for reachability. The user wrote "tailcat"; this is assumed to mean Tailscale, so confirm. Tailscale identity is not enough on its own: add application-level mutual authentication with pinned keys (Noise or mTLS) so a compromised tailnet cannot impersonate a coordinator.
  * Tailscale's embeddable `tsnet` is Go-only. From Python, rely on the system `tailscaled` (or a userspace instance) and bind to the tailnet address, or reconsider the language for the signer daemon.
* **Request integrity.** Requests carry a body hash, an expiry (slot-bounded) and a nonce. Signers keep a replay log. Every request and response is in the audit log.
* **The air-gap trade-off is explicit.** A networked signer is not air-gapped. Offer remote signing for owner, payment and hardware-wallet keys, and keep pool cold keys on the air-gapped file `Transport` by default. Let the operator choose per key class, and record the choice.

### TUI

The TUI is a second `UI` adapter over the same use cases as the CLI. It is a good fit for reviewing signing requests, run status and KES expiry at a glance. A TUI library (for example Textual) would be a third-party dependency; decide in Phase 0.

## Spec-first porting

Porting without a specification means rediscovering behaviour script by script, and losing it again at every upstream release. The port is built against a **specification corpus** of the upstream scripts.

### What a spec records

One spec per upstream script (and per shared `00_common.sh` function), with a machine-readable header and prose body:

* **Identity:** upstream path, upstream tag, file SHA-256.
* **Interface:** positional arguments and options, including the free-form `msg:` / `utxolimit:` style parameters.
* **Inputs:**
  * files read (naming patterns such as `<pool>.kes-NNN.skey`);
  * `common.inc` settings;
  * environment variables (`ENV_SKIP_PROMPT`, `ENV_DECRYPT_PASSWORD`, ...).
* **Outputs:** files written with names and modes, `offlineTransfer.json` mutations, and stdout content that is security-relevant (key material).
* **Behaviour per mode:** online, light and offline differences, including refusals.
* **Prompts:** every `ask` / `ask_pass`, with its default.
* **External calls:** cardano-cli and cardano-hw-cli subcommands, and Koios endpoints.
* **Preconditions and failures:** each check, its message and its exit code.
* **Invariants:** for example "every `04d` run increments `node.counter`" and "`execute` removes the transaction on success".

Each requirement has a **stable id** (for example `SPO-04d-INV-001`). Tests cite the ids they cover. A flake check fails when any id has no test, giving **full coverage** as a mechanical property, not a claim.

### Parity testing

Wherever behaviour is deterministic offline, test the port **differentially** against upstream: run the pinned upstream script and the port on the same fixture workspace, with fixed keys and a fixed tip, and compare the outputs. The existing e2e harness (`tests/test_e2e_real_scripts.py`) is the seed. For online and light behaviour, record and replay Koios responses.

### Keeping the spec current with upstream

When `spo-scripts` moves to a new `Update-*` tag:

1. Compare per-file SHA-256: the spec headers against upstream's `sha256sum_sposcripts.txt` and the source tree.
2. For each changed file, an agent diffs the old and new source, maps every hunk to the requirement ids it touches, and proposes spec edits.
3. Every hunk ends up classified as **behaviour change** (spec edit plus tests flagged), **no behavioural effect**, or **cosmetic**. The upgrade is done when no hunk is unclassified and the coverage check is green.

`tools/spo-compat.nix` already parses `00_common.sh` for version requirements at evaluation time. `spec/tools/specctl.py` extends the idea: it extracts per-file and per-function hashes, cardano-cli, hw-cli and signer subcommands, HTTP endpoints and `ENV_*` variables, and lints them against each spec's front matter (`checks.<system>.spec-lint`). The upgrade procedure is in [`spec/README.md`](../../spec/README.md#absorbing-an-upstream-release).

## Phases

Each phase ends on a checkable criterion. Do not start a phase before the previous one's criterion holds.

| Phase | Work | Done when |
| --- | --- | --- |
| 0. Decisions | ADRs for every open question below, recorded in `docs/explanation/` | Every open question has an accepted ADR |
| 1. Spec foundation | Spec format, id scheme, coverage check; specs for the scripts the current workbench wraps (`04a`–`04e`, `01_workOffline`, `01_claimRewards`, `01_sendLovelaces`, `05a`, `05c`) and the `00_common.sh` functions they use | Those specs exist; the coverage check runs in `nix flake check` and fails on an uncovered id |
| 2. Core and storage | Domain core, ports, SQLite `Store`, sealed `Vault`, import from a scripts directory, audit log | Importing a scripts workspace and re-exporting it round-trips byte for byte; no plaintext secret is found in the database file (tested) |
| 3. Parity slice | Native `kes-rotate`, `claim-rewards`, `send-ada`, `pool-update` behind the current CLI; the journal moves into the store | Differential tests pass against upstream for the slice; the current workbench tests pass with native adapters |
| 4. Remote signing | Signer daemon, coordinator, secure channel, multi-party witness collection (`05d` parity) | A two-owner preview pool registration completes with each owner signing remotely, with no witness files handled by hand |
| 5. TUI | TUI adapter for run status, signing-request review, KES expiry | Every use case available in the CLI is reachable in the TUI |
| 6. Full parity | Remaining scripts (inventory below), upstream-diff agent workflow automated | Every upstream script has a spec and a ported use case or a recorded decision not to port it; one upstream tag bump has been absorbed using the agent workflow |

### Inventory (Update-2026-04, mainnet variant)

`00_common`, `01_claimRewards`, `01_protectKey`, `01_queryAddress`, `01_sendAssets`, `01_sendLovelaces`, `01_workOffline`, `02_genPaymentAddrOnly`, `03a`–`03c` (stake address), `04a`–`04e` (node keys, VRF, KES, opcert, opcert check), `05a`–`05e` (pool cert, delegation cert, registration, witnesses, on-chain check), `06_regDelegationCert`, `07a`–`07b` (pool retirement), `08a`–`08b` (stake-address retirement), `09a_catalystVote`, `0x_importHelper`, `10_genPolicy`, `11a`–`11b` (mint, burn), `12a`–`12b` (asset metadata), `15_calidusPoolKey`, `21a`–`21d` (DRep), `22a`–`22b` (vote delegation), `23a`–`23e` (committee), `24a`–`24c` (votes), `25a`–`25b` (governance actions).

The testnet variant adds `04f_genBLSKeys`, `13a_spoPoll` and `13b_sendSpoPoll`. Bundled helper binaries (`bech32`, `cardano-signer`, `catalyst-toolbox`, `token-metadata-creator`) are already provided by the flake or need a decision.

## Open questions (Phase 0)

1. **Ledger engine.** Keep cardano-cli behind the `Ledger` port (parity and the release-set guarantee come free) or adopt a native library? Recommendation: keep cardano-cli.
2. **Crypto dependency.** The standard library has no AEAD or Argon2. Accept one audited, nixpkgs-pinned dependency (`cryptography` or PyNaCl) behind the `Vault` port, or use SQLCipher? This deliberately breaks today's stdlib-only rule; record why.
3. **What counts as sensitive** (see "Single file, no plaintext"), and whether the whole database is encrypted.
4. **Key-encryption key source:** passphrase only, or also hardware tokens (YubiKey or the HW wallet itself)?
5. **Transport security:** Tailscale assumed (confirm "tailcat"), plus which application-level authentication (Noise or mTLS)? Is the signer daemon Python, or Go to embed `tsnet`?
6. **Air-gap policy:** which key classes may use remote signing by default?
7. ~~**Spec format:**~~ *Decided 2026-11-15:* Markdown with TOML front matter (parsed by the standard library's `tomllib`, so no dependency), requirement ids `SPO-<code>-<KIND>-<NNN>` with `(src: Lx-Ly)` ranges. Contract: [`spec/format.md`](../../spec/format.md).
8. **Migration:** does the current `workbench` CLI stay as the front end (recommended, keeping its docs and workflows), with the `ScriptRunner` adapter retired script by script as native use cases land?

## What carries over from the current orchestrator

* **Kept:**
  * the engine concepts: step location, done-probes, non-repeatable steps, drift detection, one open run per workflow, check-before-change;
  * the report format and the release-set toolchain manifest;
  * the strict config schema;
  * the docs structure.
* **Replaced:**
  * `ScriptRunner` and the `common.inc` generation, by native adapters;
  * file probes, by store queries;
  * the `offlineTransfer.json` ticket, by a `Transport` adapter, which keeps a file-carry option for true air gaps;
  * the JSON journal files, by store tables.
