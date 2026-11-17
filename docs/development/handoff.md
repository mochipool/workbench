# Handoff: state of the workbench

Read this before changing `orchestrator/`, `tools/workbench.nix` or `docs/`. It records what exists, how to prove it still works, what is unfinished, and what we learned about the upstream scripts that the code relies on. The longer-term direction is in [Roadmap: native port](./roadmap-native-port.md).

Last updated: 2026-11-16.

## Completed

| Area | What | Where |
| --- | --- | --- |
| Orchestrator | `workbench` CLI: `init`, `workflows`, `check`, `run`, `resume`, `abandon`, `status`, `runs`, `show`, `exec`, `edit` | `orchestrator/src/spo_workbench/` |
| Workflows | `kes-rotate` (+ block-producer tar bundle), `claim-rewards`, `send-ada`, `pool-update` | `orchestrator/src/spo_workbench/workflows/` |
| Engine | Steps with a location (`chain` / `keys` / `any`), filesystem done-probes, non-repeatable steps, artefact digests and drift detection, one open run per workflow, air-gap hand-off via a ticket attached to `offlineTransfer.json` | `engine.py`, `transfer.py`, `journal.py` |
| Validation | Strict `workbench.toml` schema; per-workflow check-time validation (address network prefixes, `pool.json` limits mirroring `05a`, KES counter consistency, offline hand-off precondition, partial-`04d` guard) | `config.py`, `validate.py`, each workflow's `validate()` |
| Packaging | `packages.<sys>.workbench`, `apps.<sys>.workbench`, `checks.<sys>.workbench-tests`; toolchain manifest JSON baked into the wrapper | `tools/workbench.nix`, `flake.nix` |
| Flake fixes | `gnupg` added to the SPO script runtime (needed for `enc` keys); `mkParams` exposed; dev shell no longer clobbers a user's own `~/.common.inc` | `tools/spo-scripts.nix`, `flake.nix` |
| Spec corpus | Behavioural spec of every upstream script and `00_common.sh` function (67 specs, 2257 requirement ids with source ranges, about 95% of upstream code lines cited; reviewed once by Opus against source, all findings applied), domain model, ports, `specctl` (lint, drift, hunks, gaps, index), `checks.<sys>.spec-lint` | `spec/` |
| Docs | Diataxis set (tutorials, how-to, reference, explanation); `readme.md` trimmed to a landing page; `RELEASING.md` points into `docs/` | `docs/` |

Commits (jj, colocated): `feat(workbench): ...` then `docs: Diataxis ...` on bookmark `workbench-orchestrator`, merged into `main` with `merge: workbench orchestrator and Diataxis docs`. **Not pushed**: the user pushes.

## Verify the current state

Every one of these must pass before and after your change:

```sh
nix flake check --accept-flake-config                     # includes workbench-tests (52 unit tests)
nix build --accept-flake-config -o result-workbench .#workbench
cd orchestrator && SPO_WB_E2E_WORKBENCH=$PWD/../result-workbench/bin/workbench \
  nix shell --impure --expr '(import (builtins.getFlake "nixpkgs") {}).python3.withPackages (p: [p.pytest])' \
  -c sh -c 'PYTHONPATH=src python -m pytest -q -p no:cacheprovider'   # 52 unit + 1 real-script e2e
```

The e2e test (`tests/test_e2e_real_scripts.py`) drives the real pinned scripts and cardano-cli in offline mode on preview. It needs network access for one light-mode `01_workOffline.sh new`. The tutorial `docs/tutorials/rotate-kes-on-preview.md` was executed verbatim and ends `[DONE]`. Re-run it after changing `kes-rotate`.

Unit tests use stand-ins (`tests/fake_scripts.py`) that reproduce the upstream file contract. When you learn something new about upstream behaviour, encode it in the stand-in first, so the unit tests cannot drift from reality again (this happened once; see Gotchas).

## Go reference implementation (`spo/`)

Started 2026-11-16. Read [Go reference implementation: concerns](./go-reference-implementation-concerns.md) and the [ADRs](../explanation/adr/README.md) before touching it. The concerns page has a *Status* table that says what is closed.

State: 68 of 68 specs are implemented (`spo/spec-coverage.toml`; the waived ids carry their reasons, and `python3 spec/tools/specctl.py coverage --tests spo --config spo/spec-coverage.toml` is the proof). The sealed store is the default (ADR 0003): `spo init` creates a workspace (`workspace.spo`, its head file and `spo.toml`), every command opens it with a passphrase from the terminal or `--passphrase-fd`, a rekey always revokes the old recovery key, and a rolled-back file is refused unless `--accept-rollback`. `--upstream-layout` still works on a plain directory, with keys unsealed. Offline mode (clock, transfer file) and light mode (Koios, light-mode parameters file) are wired. Provider API tokens are stored in the sealed store. See [spo CLI](../reference/spo-cli.md) and [spo.toml](../reference/spo-toml.md).

Built, by area (the table below says where):

* Keys and pool: KES, VRF and cold keys, opcert issue and check, the pool descriptor, certificates, registration and retirement with witness collections, and the import of a pool from the chain or an info file (`pool import`, `pool export-info`).
* Money: `wallet send`, `claim-rewards`, `send-assets`, the stake commands, the offline transfer file (`offline ...`), native policies, mint, burn and settle, and the token-registry entry (`asset meta generate` and `check`; the registry needs light mode with a server, so a test network needs `[registry] url`).
* Governance: DReps, committee, votes and actions (`info`, `no-confidence`, `update-committee`, `new-constitution`, `hard-fork`, `treasury-withdrawal`, `parameter-change`), with the checks the commands can make. `parameter-change` checks a cost model's length against the current model and refuses when that model cannot be read as an array (a provider that serves the models keyed by name) unless `--allow-cost-model-length-change`, which then prints "cost model length not checked". `action submit` carries the guardrails script when the constitution has one, with the execution units from a provider (see "Not built"); its parameter-change and guardrails parts are compared with cardano-cli in `test/parity` (`gov_params_oracle_test.go`, `gov_plutus_oracle_test.go`) but never ran on a network.
* Other: Calidus (`new`, `register-metadata`, `status` in light mode, `sign`) and Catalyst (`key new`, `key qrcode`, `register`) registration (signed metadata records, with a pool cold key, a voting key and a stake key on a device where the profile says so), ADA Handles, SPO polls, BLS keys.
* Hardware wallets: the adapter over `cardano-hw-cli` is built and tested against a stand-in tool only. **Untested on devices**: work through [the device checklist](./hardware-device-checklist.md) before relying on it.
* Multi-party signing (file and tailcat transports, ADR 0005): the `spo party ...` commands and the signing and review flows (`cli/party*.go`, `cmd/spo/party.go`) are wired. The library stack and the wiring were cleared by review (nine Opus passes in all; the last lists no required change) with the operating conditions in the "Multi-party signing" section of [the command reference](../reference/spo-cli.md). The pre-signature summary (`cli/party_summary.go`) and the rule that `approve` refuses when any certificate, vote, withdrawal or required-signer line was folded are the parts reviews kept finding gaps in: change them only with a regression test and a review. Since the ninth review: the review body quotes a peer's relay hosts, metadata URL and anchor URLs, `approve` re-reads the terminal size just before it asks, `review` ends with a warning when it folded an authority section, and `foldedError` names every foldable category from one table (`authorityCategories` in `cli/party_review.go`; a test fails when a line of the authority region belongs to no row). Identity rotation (`party rotate`, `party rotation list|accept|reject`, SPO-Xparty-IF-008 and INV-030 to INV-033, PR-006) and the collection-closed notice (INV-035 to INV-037) are built and have **not** been through a review pass: treat `app/multisig/rotation.go`, `domain/party/rotation.go` and the closing-notice changes in `signer.go` as new, security-relevant code. Not built: nothing in the party stack is known to be missing.
* TUI (`spo tui`, ADR 0009, [reference](../reference/spo-tui.md)): a second driver that walks the same command tree, so a new command is in it with no TUI code. The parity test is `TestU1...` in `cmd/spo`; a new `*-fd` flag must be classified in `cli/uihints.go` (`TestU2...`). Name completion, the file picker and the flag-group display are driven by hints registered in `cli/uihints_table.go` (command path and argument label or flag name to a `uihint` value); a new command that takes a wallet, pool, file and so on adds a line there, and `TestUIHintTableMatchesTheTree` (`cli`) fails when a label no longer exists. Flags that exclude each other are declared with cobra's `MarkFlags...` so the form shows them. The pty tests (`cmd/spo/tui_pty_test.go`, `TestPTY...`) run `spo tui` on a real pseudo-terminal and skip, saying "no pseudo-terminal", where there is none (a Nix sandbox).

* Transaction status and waiting (`spo tx status`, `--wait` on every submitting command; [Xconfirm](../../spec/extensions/Xconfirm.md), ADR 0006 addendum): `ports.TxStatusReader` on Koios, Blockfrost and the node, `app/txconfirm`, `cmd/spo/txwatch.go` (per-call freshness and sync guards), `cli/txwait.go` (the submit recorder, the wait, the exit codes). Built and tested against loopback stand-ins and the fake node only: the Koios and Blockfrost shapes are from public documentation, never a live service, and the node's answers are the fake's. **Local state is still applied on an accepted submission, not on confirmation**: the asset record update of `asset mint`/`burn` (`app/assets/mint.go`, `ApplyChange` when `res.Submitted`) and of a queued one (`UpdateHook`, `SettlingSubmitter`/`Settle` in `app/assets/record.go`); the offline queue entry's removal, the addresses marked used and the history line (`airgap.ExecuteTx`, `Bundle.CompleteSubmit`); the pool descriptor's registration and retirement records (`RecordRegistration`, `RecordRetirement`) and the `.multisig.submitted` record of a pool registration (`poolops/register_pool.go`); and the party collection's close (`multisig.Coordinator.CompleteNow` sends `CollectionClosed` with outcome submitted). Whether any of these should wait for a confirmation is undecided.
* Pending records (hazard H9, [Xconfirm](../../spec/extensions/Xconfirm.md) PR, ADR 0006 addendum): the asset record of a mint or burn and the registration and retirement records of a pool descriptor are applied when the transaction is **confirmed**, not when it is accepted. `assets.Pending` (domain; carries a kind and the validity bound) is stored as `<txid>.pending` (`ports.PendingUpdate`; `<txid>.asset-pending` is still read); `app/assets` has the one apply path (`Settle.Apply`, one store commit with the removal, so a crash cannot apply twice), `SettleFromBundle` (offline machine; applies only on a history entry `spoConfirmed`, `--accept-submitted` trusts the submit) and `UpdateHook`; `poolops.ApplyRegistration`/`ApplyRetirement` are the pool appliers, plugged in by `cli/txsettle.go` (`settleAppliers`); `app/txsettle` is the provider settle (`spo tx settle`) and `RecordInTransferFile` (writes `spoConfirmed`/`spoExpired` history entries on the online machine); `txconfirm.Waiter.Probe` makes a settle cost one poll. A command that leaves a pending record sets `envSpec.settles` (wait by default, `--no-wait`, `addSettleFlags`); `offline execute` sets `settlesIfPending` and decides after the submit (`executeSettling`). `txflow.Input.Stage` is where the retirement writes its pending update before the transaction leaves. Choices a reader should know: the carrying fields keep their first names (`spoAssetPending`, `spoAssetSubmitted`) and now hold any kind, because the parity tests and old files use them; confirmation is recorded in the file by `spo tx settle` on the online machine (not by re-running `offline execute`, whose queue is empty after the submit); a registration's witness collection and certificate are consumed when the transaction is sent while `regEpoch`/`regSubmitted` wait; the multi-party coordinator's "submitted" notice takes a pending registration for the body as proof. Not done: a retirement or registration whose submission outcome is unknown after a crash that lost the process before the pending record was written (the record is written before the transaction leaves, so only a failed write of the record itself, which stops the command first, would lose it); `UpdateHook` still applies a carried asset update to a local copy of the record when no pending record is found, as the first version did (a repeat on the queuing machine would apply it again to its own record); it now first checks the update against the confirmed transaction (id, and the mint field's policy, name and amount; PR-027). The transfer file is unauthenticated (E7): `SettleFromBundle` applies an outcome only for a transaction recorded as submitted and gone from the queue, discards on an expiry only when the stored bound equals the queued one, and `RecordInTransferFile` takes the id and bound from the transaction stored in the history entry (`spoTxCbor`), so a file written before that key existed cannot be settled from. A submission whose provider answered another id is an unknown outcome (`chain.IDMismatchError`) and keeps the pending record; the status rule for web providers is `chain.SubmitStatusRefuses` (PR-008). `spo tx settle` settles every item and exits 1 if one failed (PR-016). Not tested: `test/parity` `settlePending` now asserts the pending record exists, but the parity tests skip without the toolchain and were only vetted here.
* Chain access (ADR 0006): Koios, Blockfrost (second provider), the offline snapshot and the node socket (online mode; **never run against a real node**, see below) are wired. Reads of the harmful-if-false class (reward balance, pool registration, DRep registration, opcert counter, pool import data) need two agreeing sources or `--single-source`; the acknowledgement is recorded in the audit log by a `ports.SingleSourceHook` that each use case calls at the point where it accepts the single source, before anything is signed, submitted, queued or written (a use case told to accept one without a hook refuses). One record per accepted read: `stake deregister` writes two. `pool import` reads the chain once (`ImportPoolFromChain.Fetch`) and every later step uses that answer. A web provider needs a tip under ten minutes old as the first or the second source; two sources on one host need `same_host_ok`, and the summary says when that was relied on. Every string a chain, provider, peer or file chose is written through `platform/textsafe` (`shown` in `cli`, `ports.IsPlainText` in the use cases); `cmd/spo` prints every command error through `cli.SafeMessage`.
* Multi-party: `enqueue` has no exemption by item type; only `enqueueRotation`, called by `RotateIdentity`, queues announcements sealed by the identity they replace, and marks them (`OutItem.Rotation`) so the outbox sweep keeps them. An outbox written before that mark existed would have its undelivered rotation announcements dropped by the sweep.

**Not built:**


* A Blockfrost reading of the stake key deposit and of a DRep's deposit. The Blockfrost adapter (`adapters/blockfrost`, ADR 0006 adapter 4) is the second provider of the harmful-class reads (reward balance, pool registration, DRep registration), wired in `cmd/spo/providers.go`; its response shapes are from the public documentation and were never checked against a live service, and the API states neither deposit, so those values rest on the first provider. Blockfrost has no opcert counter.
* Node-socket gaps (the adapter itself is built, see "Never run against a real cardano-node" below): the node cannot answer asset holders (ADA Handles), transaction metadata (SPO polls, Calidus registrations), a pool's last-update time, a tally or script evaluation, so those capabilities are absent in online mode unless a web provider is configured *and* named in `[provider] order`; the adapter has no era reader for the air-gap commands (`offline new` in online mode reports `era` absent); and the node cannot give a block height or depth for a transaction (`spo tx status`, `--wait`: it states presence only, so a wait on `--wait-confirmations N` above 1 needs a web provider to state a depth).
* A treasury withdrawal to a script reward account can be made (`action create`), and its file now orders the map as cardano-cli does (script accounts before key accounts, observed with the pinned cardano-cli in `test/parity`: `TestGovActionFilesMatchCardanoCLI`), but `action submit` refuses a script receiver (`ErrNeedsKeyCredential`). Only one script and one key account were compared; three or more accounts, and accounts on both networks, follow the ledger's order by reasoning, not by observation.
* A Calidus key on a hardware device (upstream suspends it, `SPO-15-PRE-002`; refused with that message), the per-call Ledger minimum for the Catalyst calls (the 6.0.3 of `SPO-Chw-IF-001` is not applied), a Trezor derivation type, and use of the combined two-key witness (`WitnessMany`) by 05c: see items 17, 19, 20 and 21 of [the device checklist](./hardware-device-checklist.md).
* Unconfirmed against the real world: the Koios `pool_calidus_keys` answer (the reader's test data is hand-written from the documentation) and the Catalyst QR code (built from the toolbox source, never scanned by the mobile app; `spo catalyst key qrcode` says so). The first live Koios answer should be recorded in `spo/internal/adapters/koios/testdata/` and the test switched to it; the first QR code should be scanned with a throw-away key.
* A Plutus evaluator of its own: a treasury withdrawal or parameter change under a constitution with a guardrails script takes the script's execution units from a provider (`ports.TxEvaluator`, wired for Koios only; offline mode and Blockfrost cannot). The Koios `/ogmios` request and answer shapes are from public documentation and have never been compared with a real answer; record one under `adapters/koios/testdata/` and switch `evaluate_test.go` to it. Upstream's `--ex-units` by hand does not exist (upstream computes the units in every mode, SPO-25b-EXT-002/003), so none is offered. A body whose proposals need the script is refused when a proposal without it comes first (cardano-cli numbers the redeemer among the scripted proposals, the ledger by position; no node was available to settle which is right).

**Never run against a real cardano-node.** Online mode (`mode = "online"` with a `[node]` section, or the node as a layer of `[provider] order`) is built and wired: the node-to-client adapter `adapters/native/n2c` is connected through `cmd/spo/online.go`, dialled lazily once per command, and covered by end-to-end tests against an in-process fake node on a temporary UNIX socket (`internal/adapters/native/n2c/n2ctest`, used by `cmd/spo/online_e2e_test.go`). No test used a node. One reply (`GetDRepState`) is bytes a node sent, copied from the gouroboros tests; everything else is hand-written from the library's documentation or encoded by the library. The adapter's README lists, per port, which. Run [the node-socket checklist](./node-socket-checklist.md) against a preview node before relying on this mode; its three "may come back unknown" replies (constitution, committee members state, ratify state), the era-history units and the previous-action-id order are the likeliest to differ.


How a command gets what it needs, and how to add one:

* One `Env` carries every capability, each typed by its narrow port (`adapters/cli/env.go`). `cmd/spo/env.go` builds it with `Deps.Wire(store, WireOptions)` from the workspace config, the effective mode, the genesis overrides, the provider token and the transfer-file path. A chain capability is nil when the mode or provider cannot supply it, and the wiring records why (`Env.Absent`). `spo capabilities` prints the same Env.
* A command is one file in `spo/internal/adapters/cli` with a `*cobra.Command`, registered in `root.go`. It calls `a.withEnv(cmd, envSpec{needs: ...}, fn)`. The needs (`Cap` constants, `OneOf(...)`) are checked on an Env built before the store is opened, so a command that cannot run here fails before any prompt, with one error listing every missing capability and why. Inside `fn`, use the `Env` fields; never nil-check a field. Chain commands add `addChainFlags` (`--offline`, genesis flags, optionally `--transfer-file`).
* Nothing changes in `cmd/spo` when you add a command. It changes only when you introduce a new adapter, or a new capability: add a field and a `Cap` in `env.go`, give `Env.has` its case, and wire it in `cmd/spo/env.go` for each mode (or record why it is absent).
* Errors from the store are sentinels in `cli/deps.go`; `explain.go` turns each into one sentence with the remedy, for every command.
* Tests: fakes in `adapters/cli` (a fake `Deps.Wire`; see `wallet_test.go` for a fixture around the real native ledger), the real adapters in `cmd/spo` on a sealed workspace (`e2e_test.go`; Argon2 runs at its floor, so one workspace is created and copied).

| What | Where |
| --- | --- |
| Composition root: wiring of every adapter, the `Env` of each mode, the TUI entry | `spo/cmd/spo` |
| Command tree (cobra driving adapter) and the `Env`/`Cap`/`Require` pattern | `spo/internal/adapters/cli` |
| Terminal UI over the same tree (ADR 0009) | `spo/internal/adapters/tui` |
| Dependency rule and import confinement, enforced as a test | `spo/internal/archtest` |
| Process runner (argument vectors only, secrets through pipes), guarded memory, sealing primitives, core dumps disabled | `spo/internal/platform/{execx,secret,seal}` |
| Release-set gates, manifest from `tools/spo.nix` | `spo/internal/adapters/toolchain` |
| Ports (one small interface per capability) and domain (custody, chain vocabulary, txbuild, pool, stake, assets, tokenmeta, party, ...) | `spo/internal/ports`, `spo/internal/domain` |
| Use cases | `spo/internal/app/*` |
| Native ledger, key generation, signers (vault, registry), verification-key and VRF derivation, on Blink Labs libraries (ADR 0007) | `spo/internal/adapters/native` |
| Sealed single-file store, its audit chain, backup and restore; the upstream-layout store | `spo/internal/adapters/{sqlitestore,storeaudit,fsstore}` |
| `spo.toml` with a strict schema, and the network presets | `spo/internal/adapters/config` |
| Chain and web readers: Koios (recorded responses) and the light-mode parameters, ADA Handle API, token-registry server, metadata fetch | `spo/internal/adapters/{koios,adahandle,tokenregistry,httpfetch}` |
| Offline: tip from the clock, genesis file reader, the transfer file as snapshot, queue and bundle | `spo/internal/adapters/{offline,genesisfile,systemclock,transferfile}` |
| Hardware wallets over `cardano-hw-cli` (untested on devices) | `spo/internal/adapters/hwcli` |
| Multi-party: party registry, envelopes, file and tailcat transports | `spo/internal/adapters/{partystore,envelope,filebag,tailcat}` |
| gpg envelope for upstream's encrypted keys | `spo/internal/adapters/gpg` |
| Differential tests against the pinned upstream scripts | `spo/test/parity` |
| Which specs are implemented, and the waived ids with reasons | `spo/spec-coverage.toml` |


Fast loop, from `spo/` (needs Go 1.27; `-count=1` matters, Go caches the import-rule test):

```sh
gofmt -l internal cmd && go vet ./... && go test -count=1 ./...
go test -count=1 ./internal/archtest/            # the dependency rule
go test -count=1 -run TestU ./cmd/...             # the TUI parity and descriptor-flag tests
go test -count=1 -run TestPTY -v ./cmd/spo          # the TUI on a real pty (skips without one)
```

Verify:

```sh
# a sealed workspace without a terminal: passphrase and recovery key on descriptors
printf 'correct horse battery staple\n' > pw
nix run --accept-flake-config .#spo -- -C ws init --network preview --passphrase-fd 3 --recovery-key-fd 4 3<pw 4>rk
nix run --accept-flake-config .#spo -- -C ws --passphrase-fd 3 store verify 3<pw
nix build --accept-flake-config --no-link -L .#checks.x86_64-linux.spo-tests   # go vet + go test in the sandbox
nix run --accept-flake-config .#spo -- toolchain check                        # real pinned tools pass the gates
cd spo && go test -count=1 ./...                                              # fast loop; needs Go 1.27. -count=1 matters: Go caches the import-rule test
nix build --accept-flake-config --no-link -L .#checks.x86_64-linux.spo-parity # upstream 04c against the Go use case
python3 spec/tools/specctl.py coverage --tests spo --config spo/spec-coverage.toml
```

Things that will bite:

* **Hardware wallets are untested on real devices.** The adapter is built and tested against a stand-in tool. Before relying on it, work through [the device checklist](./hardware-device-checklist.md).

* **The multi-party stack passed its fifth security review** with operating conditions (ADR 0005, `spec/extensions/Xparty.md`). Four fix rounds preceded it and two of them left a fail-open edge, so any change to `domain/party`, `app/multisig` or the transports needs a regression test that fails without the change, and an Opus review. The wiring obligations a command must meet are listed in ADR 0005 (address inspector always set; resolver only through `OwnProvider`/`OwnSnapshot`; `Received` only from a transport; a real approval gate).
* **The sealed store passed its seventh security review** with operating conditions (ADR 0003). Its history matters: each of the first five fix rounds introduced a new defect, mostly around rekeying, locking and SQLite's side files. Change `spo/internal/adapters/sqlitestore` only with a regression test per change and an Opus review afterwards. The multi-party library stack is cleared; the wiring of its commands is pending review (see the *Status* table in the concerns page).
* **Parity tests that need cardano-signer skip inside the Nix sandbox.** The signer is a prebuilt binary whose interpreter path cannot be patched, so it does not run there. Run them in the development loop: `source <scratch>/env.sh` style variables as described in `spo/test/parity/parity_test.go`, then `go test ./test/parity/`. The Nix check allows exactly that skip and fails on any other.
* **Tailcat adds about 18 MB** to the binary and a large test-only dependency set (concern T8).

* **Nix does not see files jj has not told git about.** After creating files, run `git add -N <paths>` before `nix build`, or the flake fails with "not tracked by Git".
* **`vendorHash`.** After any change to `spo/go.mod` or `spo/go.sum`, set `vendorHash` in `tools/spo.nix` to the all-`A` placeholder, build, and paste the hash Nix reports.
* **Go version.** `spo` needs Go 1.27 (tailcat). It is built with the `nixpkgs-go` flake input, which is locked separately from the release set's `nixpkgs`.
* **Check [Go library coverage](./go-library-coverage.md) before writing an adapter.** It says which library function to use, what has only been read and not run, and what we write ourselves.
* **Capability-typed ports (ADR 0008).** One small interface per capability; no method whose honest implementation is "unsupported". Signatures go through a `custody.Plan`, built before any effect. Do not write a hardware variant of a use case.
* **Native first (ADR 0007).** New key, signing and ledger operations go in `spo/internal/adapters/native` on Blink Labs' libraries, each with a parity test against the pinned cardano-cli in `spo/test/parity`. Do not add a cardano-cli adapter for something `bursa` or `gouroboros` covers. cardano-cli 11.2.3.0 cannot write KES or VRF keys to a pipe, which is one reason.

How to port a use case (the pattern `GenerateKesKey` sets):

1. Read its specs. Put state rules in `domain/<context>`, the sequence in `app/<context>`, and add only the port operations it needs.
2. Unit-test the use case with fakes, citing ids in `// spec:` comments. Record each upstream-quirk decision in the test that cites the id.
3. Add a differential test in `spo/test/parity` that runs the upstream script through `workbench exec` and compares state.
4. Add the spec code to `implemented` in `spo/spec-coverage.toml`; waive what is deliberately not ported, with a reason.
5. Fold anything the real tools taught you back into the spec.

Where to go next: the **Not built** list above. Running the node-socket checklist against a preview node comes first, then a recorded Koios `/ogmios` answer and a local Plutus evaluator.

## Backlog

Ordered by value. Each item has a done-criterion.

1. ~~**CI runs the orchestrator tests.**~~ Done 2026-11-16: the `checks` job builds `spec-lint`, `workbench-tests` and `spo-tests` on all three systems. Not yet observed green on GitHub, because nothing has been pushed.
2. **Independent review.** No second reviewer has read `orchestrator/`. Done when a review (use model `opus`) of engine resume semantics, the ticket import path and `unpack_carried` has been addressed or explicitly waived.
3. **Real-script coverage of transaction workflows.** `claim-rewards`, `send-ada` and `pool-update` have only been run against stand-ins. Done when each completes on preview with funded throw-away wallets, both air-gapped and not, and any upstream behaviour found is folded into `fake_scripts.py`. Unknowns to settle:
   * ~~what `05c` prompts for in offline mode~~: two confirmations, both default No, plus two attach prompts, default No (from source; see `spec/upstream/scripts/05c_regStakepoolCert.md`);
   * ~~whether `execute` prompts~~: always, default No, and `ENV_SKIP_PROMPT` is not honoured (`spec/upstream/scripts/01_workOffline.md`);
   * ~~the exit codes `04e` uses on a counter mismatch~~: 0 for every completed check, including a FALSE verdict; 1 for usage, offline and not-found; 2 for unsynced or query errors (`spec/upstream/scripts/04e_checkNodeOpCert.md`). The `kes-rotate` probes must parse the verdict, not the exit code.

   These answers come from reading source; confirm them in the preview run.
4. **`enc` and hardware-wallet paths.** Untested: `kes_key = "enc"` (gpg password prompt, bundle contains an encrypted key) and `.hwsfile` cold keys (`04d` via cardano-hw-cli). Done when each is exercised once with notes in this file.
5. **Workflows not yet wrapped.** Done per item when it has a workflow, validation, stand-in coverage and a how-to page:
   * pool registration from scratch (`04a`, `04b`, `05a`, `05b`, `05c`, `06`);
   * stake-address registration (`03a`, `03b`);
   * multi-owner witnesses (`05d`);
   * retirement (`07a`, `07b`, `08a`, `08b`);
   * governance (`21*`–`25*`);
   * minting (`10`–`12`).

   The [native port](./roadmap-native-port.md) may supersede this item; decide before investing.
6. **`status` KES headroom.** Shows `expireKESdate` verbatim. Done when it prints days remaining computed offline from the genesis (`slotLength`, `slotsPerKESPeriod`) and the current KES period, and warns under a threshold.
7. **Ticket authenticity.** The hand-off ticket is unsigned (documented in `docs/explanation/security-model.md`). The native port's secure channel replaces this. Leave it until then unless a cheap signing scheme appears.
8. **Small leftovers.**
   * `scripts/determinate-nix-config.sh` reads a `TARGET` argument it never uses.
   * `packages.spo-scripts-testnet` is built with network `PreProd`.
   * The dev shell's EXIT trap does not fire under `nix develop --command` (the shell `exec`s), so the `~/.common.inc` link lingers. Pre-existing.
   * A `koiosApiToken` in `[scripts]` is stored in plaintext in `workbench.toml` (mode `0600`).

## Gotchas: the upstream contract the code depends on

All verified against `gitmachtl/scripts` `Update-2026-04`. If a bump to `spo-scripts` changes any of these, the probes or validation that cite it break.

* **Scripts print signing keys.** `04c` prints the new KES `.skey` `cborHex` to stdout. Never capture, log or tee script output. `ScriptRunner` inherits the terminal and, under `--json`, sends script stdout to stderr.
* **Prompts read the terminal.** `ask()` reads from `$(tty)`, else `/dev/tty`. A prompt without a default loops forever without a terminal. `ENV_SKIP_PROMPT=YES` skips only the final transaction confirmation.
* **Config precedence.** `00_common.sh` sources `<scriptDir>/common.inc`, then `~/.common.inc`, then `./common.inc`. The workbench owns `./common.inc` (first line `# managed-by: spo-workbench`).
* **Offline mode needs an online-made transfer file.** In offline mode every `01_workOffline.sh` action, `attach` included, calls `readOfflineFile`, which exits unless `offlineTransfer.json` exists with non-empty `.protocol.parameters`. The engine's `_handoff_problems` checks this. The stand-ins originally missed it; the e2e test caught it.
* **KES counters.** `04c` writes `kes.counter-next` if absent, exits 2 when `kes.counter == kes.counter-next`, and sets `kes.counter` to N. `04d` requires them equal, issues `node-N.opcert`, increments `node.counter`, and sets `kes.counter-next` to N+1. **Every `04d` run increments the cold counter**, hence non-repeatable.
* **`offlineTransfer.json` shape.**
  * `.address` is keyed by the bech32 string (the `.addr` file content).
  * `.transactions[]` entries carry `txJSON`; `execute <n>` (1-based) deletes the entry on success.
  * `.files."<name>".base64` holds attachments.
  * `new` discards everything.
* **`04e ... next`** in light mode for a pool with no blocks expects counter 0 and exits 0.
* **File locking** is `chmod 400` (`file_lock`) / `600` (`file_unlock`).
* **Variants.** Mainnet and testnet script directories differ: the testnet one adds `04f_genBLSKeys.sh`, `13a_spoPoll.sh`, `13b_sendSpoPoll.sh` and example `common.inc` files; only mainnet ships `sha256sum_sposcripts.txt`.

## Conventions

* VCS: jj colocated with git. Develop on a change on top of `main`, `jj bookmark create <topic> -r @`, then `jj new main <topic> -m "merge: ..."` and `jj bookmark set main -r @`. Commit; leave pushing to the user.
* Runtime code is Python standard library only; `pytest` exists only in the test derivation. Adding a runtime dependency is a decision to record in [Orchestrator design](../explanation/orchestrator-design.md).
* Docs follow Diataxis; keep facts in one place. `docs/reference/` is the single source for CLI, config, workflow and state formats. Update it in the same change as the code.
* Subagents: pass an explicit `model` on every dispatch: `sonnet` for work, `opus` for review.
