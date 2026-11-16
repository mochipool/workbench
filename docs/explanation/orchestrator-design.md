# Orchestrator design

This page explains why the `workbench` orchestrator exists, why it is built the way it is, and which alternatives were considered and rejected.

## The problem

The SPO scripts are thorough at the level of one operation: generate KES keys, issue an opcert, sign a withdrawal. The operator's real tasks are sequences of those operations, and the sequence is left to the operator:

* Which scripts to run, in which order, with which file names (`mypool.kes-004.skey` or `-005`?).
* Unlocking and relocking files the scripts protect with `chmod 400`.
* For an air-gapped setup, remembering which half of the task happens on which machine, and moving `offlineTransfer.json` across at the right moments.
* After a key rotation, packaging the right two files for the block producer under the names the node expects.
* After an interruption, working out what already happened before running anything again. A repeated opcert issue skips a counter. A repeated submission can double-spend.

The scripts validate their inputs, but often only part-way through a run, after other files have already been written. The orchestrator moves that validation to the front and adds the missing layer: a named, resumable, multi-machine workflow with a report at the end.

## Requirements that drove the design

1. **Terminal pass-through.** The scripts prompt for confirmation and passwords on the terminal (`read` from `$(tty)`), and hardware wallets ask the operator to confirm on the device. The orchestrator must hand the real terminal to each script, not drive it through pipes.
2. **No secret ever leaves the scripts' own files.** The scripts print signing-key `cborHex` to stdout (04c prints the new KES `.skey`). Script output therefore can never be captured, logged or stored.
3. **Validation against the filesystem.** Most inputs are files: does `owner.staking.addr` exist, does it hold a preview address, do the KES counters agree? Validation has to read the workspace.
4. **Truthful resume.** State recorded in a journal can disagree with the disk, for example after a crash between a script finishing and the journal being written. Resume must consult the disk.
5. **Two machines, one file.** The upstream model moves exactly one file, `offlineTransfer.json`, across the air gap. The orchestrator must not add a second.
6. **Reproducible toolchain.** A workflow must always run the binaries of the pinned release set, never whatever is on `PATH`.

## Choosing the tool

| Option | Verdict |
| --- | --- |
| Nix only (workflows as derivations or `nix run` apps) | Rejected as the engine. Evaluation is pure and cannot prompt, sign or wait. Validating inputs means reading key material, and anything Nix reads can end up in the world-readable `/nix/store`. Nix stays the packager, pins the toolchain and runs the checks. |
| Shell (bash, `just`, `make`) | Rejected. There is no safe way to model a typed journal, schema validation, atomic state writes and locking. `make` targets rely on mtimes, which the scripts' `chmod` locking and file copies between machines break. |
| Go or Rust | Viable. A single static binary and strong types. Rejected for now: iteration is slower, and Nix already ships the closure to air-gapped machines, so a static binary buys little. |
| A workflow engine (Temporal, Airflow, Dagger) | Rejected. A daemon or service is the wrong shape for an air-gapped machine, and the dependency footprint is large for a key-handling tool. |
| **Python, standard library only** | **Chosen.** `tomllib`, `dataclasses`, `fcntl`, `subprocess` and `tarfile` cover everything needed. It is easy to test against stand-in scripts, and Nix packages it in a few lines. |

The standard-library-only constraint is deliberate: the trusted code base of a tool that runs next to cold keys is CPython plus this package. `pytest` is used only by the test derivation.

## How the pieces fit

```
workbench.toml ──► config (strict schema)       toolchain.json (from Nix)
                        │                              │
                        ▼                              ▼
                     Engine ──── plans ────► Workflow (kes-rotate, claim-rewards, ...)
                        │                              │
                        │                      Steps: where + action + done-probe
                        ▼
            ScriptRunner (terminal attached) ──► SPO scripts in the workspace
                        │
            Journal (.workbench/runs/*.json)  +  ticket in offlineTransfer.json
```

### The workspace is the scripts' working directory

The scripts address every file by bare name, relative to the current directory. The orchestrator does not invent a new layout. The workspace root is where the scripts run, and the orchestrator keeps its own state under `.workbench/`.

It also owns `./common.inc`, which the scripts source last, after `~/.common.inc`. Generating it on every run from the release set and `workbench.toml` means the work mode always matches the machine's declared role. A typo in a hand-edited file cannot switch an offline machine to light mode.

### Steps declare where they run

Each step declares one of three locations:

* `chain`: needs chain access, so it runs on an online or light machine.
* `keys`: needs signing keys. When air-gapped, that means the offline machine; otherwise it is the local machine.
* `any`: runs anywhere.

The same workflow definition then covers both setups. Not air-gapped, a claim is one step that signs and submits. Air-gapped, it is `prepare` (online), then `sign` (offline), then `execute` (online), and the engine pauses at each change of machine.

### Probes make resume truthful

Where possible, a step has a `done` probe that inspects the workspace. "Has rotation 3 happened?" is answered by `kes.counter == 3` together with the existence of `mypool.kes-003.skey`, not by the journal alone.

To make that question stable, workflows pin run-wide facts when they start. `kes-rotate` records the rotation index N, because the steps themselves move the counters that would otherwise be read.

Probes also let the engine *adopt* work done by hand. If an operator ran `04c` manually yesterday, `kes-rotate` recognises the result and goes on to `04d`.

Steps whose effect cannot be observed locally (a direct submission in light mode) or which must not repeat (`04d` increments the cold counter) are marked non-rerunnable. After an interruption, the engine stops and asks the operator to say what happened (`--mark-done` or `--retry`) instead of guessing.

### Validation happens before anything changes

`workbench check` and the start of every `run` validate:

* the configuration,
* the parameters,
* the files this machine needs, and
* cross-machine preconditions, such as an offline machine needing an `offlineTransfer.json` that originated online before it can hand anything back.

Only then does the first script run. A failed check leaves the workspace untouched.

### Crossing the air gap through the existing carry bag

When the next step cannot run here, the engine writes the run journal (the *ticket*) and any non-secret files the other side needs. It attaches them to `offlineTransfer.json` with the upstream `01_workOffline.sh attach`. On the other machine, `workbench resume` reads the ticket back out, checks each carried file against the digest in the ticket, and continues.

The operator still moves exactly one file, and every write to `offlineTransfer.json` still goes through the upstream script.

### One open run per workflow

Two interleaved KES rotations, or two claims sharing one `offlineTransfer.json` queue, would corrupt each other's state. A workflow cannot start while another run of it is unfinished. `workbench abandon` is the explicit way out.

## Trade-offs and limits

* **Upstream coupling.** The probes depend on the scripts' file contract: counter files, `offlineTransfer.json` keys and file naming. That contract is stable across releases, and the opt-in end-to-end test (`orchestrator/tests/test_e2e_real_scripts.py`) runs the real scripts of the pinned release set to catch drift. Bumping `spo-scripts` in `versions.nix` should be followed by that test.
* **The ticket is not authenticated.** Anyone who can alter `offlineTransfer.json` in transit can alter the ticket's parameters. The scripts' own confirmation prompts and the imported-run confirmation are the defence. See [Security model](./security-model.md).
* **Interactive by design.** The scripts prompt on the terminal, so `workbench` is meant to be run by a person at a terminal. `--yes` skips only the scripts' final confirmation and the import prompt.
* **Scope.** Four workflows cover the routine tasks. Pool registration from scratch, multi-owner witness collection (`05d_poolWitness.sh`), governance and token minting are not wrapped yet. `workbench exec` runs any script with the managed configuration in the meantime.
