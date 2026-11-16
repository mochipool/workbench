# Security model

This page explains what the workbench protects, what it relies on, and where its protection ends. It covers both the Nix packaging and the `workbench` orchestrator.

## What is worth protecting

In order of damage, following the upstream scripts' own advice:

1. **Owner and pledge payment keys.** Losing these loses funds.
2. **Pool cold keys** (`<pool>.node.skey`) and the cold counter. With these, someone else can issue operational certificates for your pool.
3. **KES and VRF signing keys.** These are hot keys and live on the block producer by design. A leak lets someone produce blocks as you until the next rotation.
4. **Stake keys.** A leak lets someone redirect your delegation and withdraw your rewards.

The best-practice setup the scripts recommend, and the workbench supports, keeps classes 1 and 2 on an offline machine or a hardware wallet.

## Keys never enter the Nix store

The Nix store is world-readable and content-addressed: anything that enters it is readable by every user of the machine and can be copied to binary caches. The flake therefore handles only public, fixed inputs: tool sources, prebuilt binaries pinned by hash, and genesis files. No key, address or `workbench.toml` is ever an input to a derivation.

This is the main reason the orchestrator's input validation is not done by Nix evaluation (see [Orchestrator design](./orchestrator-design.md)).

## What the orchestrator writes, and where

| Location | Contents | Mode |
| --- | --- | --- |
| Workspace root | The scripts' own files, created and locked (`0400`) by the scripts | as the scripts set them |
| Workspace root, `.workbench/` | Created or tightened to `0700` on every run | `0700` |
| `./common.inc` | Binary paths, genesis paths, network, work mode, `[scripts]` settings | `0600` |
| `.workbench/runs/<id>.json` | Run journal: parameters, step status, file names and SHA-256 digests | `0600` |
| `.workbench/out/<id>/` | Block-producer bundle (contains the KES signing key) | `0600` |

The journal records *which* files a step produced and their digests, never their contents. Script output is never captured: the terminal is handed to the script, because the scripts print signing keys (04c prints the KES `.skey`). The workbench also removes `ENV_DECRYPT_PASSWORD` from the scripts' environment, so a password exported in the operator's shell cannot reach them by accident.

`workbench edit` refuses to open signing keys in an editor, where swap files and editor history could leak them.

## The air gap

Only `offlineTransfer.json` crosses the gap, as with the plain scripts. The workbench adds two kinds of content to it:

* **The ticket** (`workbench-ticket.json`, attached): the run journal. It holds no secrets by construction.
* **Carried files** (attached): non-secret files the other machine needs, for example the new opcert so the online machine can check its counter. The engine refuses to carry any file that a step recorded as secret.

The KES signing key is deliberately *not* carried. The bundle for the block producer is written to `.workbench/out/` on the machine that made it, and the operator delivers it by their own channel.

### What the ticket does not protect against

The ticket is not signed. There is no key shared between the two machines that could sign it without becoming another secret to manage. Someone who can modify `offlineTransfer.json` in transit can change the ticket's parameters, for example the destination of a withdrawal. The defences are:

* `workbench resume` prints the imported parameters and asks for confirmation (unless `--yes`).
* The signing scripts show the full transaction (amounts, addresses) and ask before signing or submitting (unless `--yes`).
* Carried files are checked against the digests in the ticket, and an existing file with different content is never overwritten.

On the offline machine, read the imported parameters and the script's transaction summary before confirming. Treat `--yes` as unsafe for imported runs on the offline machine.

## Integrity between steps

Once a step finishes, the digests of its files are recorded. On every later resume on the same machine, the engine re-checks them and stops with a drift error if a file changed or vanished. A KES key swapped between generation and packaging is detected, and the bundle carries a `SHA256SUMS` and a `MANIFEST.json` for checking on the block producer.

## Release-set integrity

Every tool is pinned: flake inputs by revision, which the `version-manifest` check enforces, and prebuilt binaries by SRI hash. `workbench` resolves every script and binary through the toolchain manifest baked in at build time, never through `PATH`. A workflow cannot silently run a different `cardano-cli` from the one the release set was verified with.

## Out of scope

* Compromise of the machine itself (malware, physical access). The workbench is not a sandbox.
* Backup and recovery of keys. Copies of cold and owner keys on encrypted offline media remain the operator's responsibility.
* Hardware-wallet firmware integrity. See the firmware how-to guides; `workbench-doctor` only checks versions.
