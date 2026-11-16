# Handoff: state of the workbench

Read this before changing `orchestrator/`, `tools/workbench.nix` or `docs/`. It records what exists, how to prove it still works, what is unfinished, and what we learned about the upstream scripts that the code relies on. The longer-term direction is in [Roadmap: native port](./roadmap-native-port.md).

Last updated: 2026-11-15.

## Completed

| Area | What | Where |
| --- | --- | --- |
| Orchestrator | `workbench` CLI: `init`, `workflows`, `check`, `run`, `resume`, `abandon`, `status`, `runs`, `show`, `exec`, `edit` | `orchestrator/src/spo_workbench/` |
| Workflows | `kes-rotate` (+ block-producer tar bundle), `claim-rewards`, `send-ada`, `pool-update` | `orchestrator/src/spo_workbench/workflows/` |
| Engine | Steps with a location (`chain` / `keys` / `any`), filesystem done-probes, non-repeatable steps, artefact digests and drift detection, one open run per workflow, air-gap hand-off via a ticket attached to `offlineTransfer.json` | `engine.py`, `transfer.py`, `journal.py` |
| Validation | Strict `workbench.toml` schema; per-workflow check-time validation (address network prefixes, `pool.json` limits mirroring `05a`, KES counter consistency, offline hand-off precondition, partial-`04d` guard) | `config.py`, `validate.py`, each workflow's `validate()` |
| Packaging | `packages.<sys>.workbench`, `apps.<sys>.workbench`, `checks.<sys>.workbench-tests`; toolchain manifest JSON baked into the wrapper | `tools/workbench.nix`, `flake.nix` |
| Flake fixes | `gnupg` added to the SPO script runtime (needed for `enc` keys); `mkParams` exposed; dev shell no longer clobbers a user's own `~/.common.inc` | `tools/spo-scripts.nix`, `flake.nix` |
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

## Backlog

Ordered by value. Each item has a done-criterion.

1. **CI runs the orchestrator tests.** `.github/workflows/validate-nix.yml` builds an explicit list of checks that does not yet include `workbench-tests`. Done when the `checks` job builds `.#checks.<system>.workbench-tests` on all three systems.
2. **Independent review.** No second reviewer has read `orchestrator/`. Done when a review (use model `opus`) of engine resume semantics, the ticket import path and `unpack_carried` has been addressed or explicitly waived.
3. **Real-script coverage of transaction workflows.** `claim-rewards`, `send-ada` and `pool-update` have only been run against stand-ins. Done when each completes on preview with funded throw-away wallets, both air-gapped and not, and any upstream behaviour found is folded into `fake_scripts.py`. Unknowns to settle:
   * what `05c` prompts for in offline mode;
   * whether `execute` prompts;
   * the exit codes `04e` uses on a counter mismatch.
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
