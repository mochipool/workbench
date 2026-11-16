# workbench CLI

This page lists every `workbench` command, option and exit code.

`workbench` is on `PATH` inside every dev shell. Outside one, use `nix run --accept-flake-config .#workbench -- <args>`.

## Synopsis

```
workbench [-C DIR] [--json] [-y] COMMAND ...
```

## Shared options

These are accepted before or after the command name.

| Option | Meaning |
| --- | --- |
| `-C`, `--directory DIR` | Workspace directory. Default: `$WORKBENCH_DIR`, else the current directory. |
| `--json` | Print a machine-readable result on stdout. Script output is sent to stderr instead, so stdout carries only JSON. |
| `-y`, `--yes` | Set `ENV_SKIP_PROMPT=YES` for the scripts (skips their final "continue?" confirmation) and accept an imported run without asking. |
| `--version` | Print the version (top level only). |

## Commands

### `init`

```
workbench init -C DIR --network {mainnet,preprod,preview} --role {online,light,offline}
               [--airgapped] [--pool NAME] [--socket PATH]
```

Creates `DIR/workbench.toml` (mode `0600`) and `DIR/.workbench/` (mode `0700`), and tightens `DIR` to `0700`. Fails if `workbench.toml` exists. The rendered file is validated before it is written. See [workbench.toml](./workbench-toml.md).

### `workflows`

Lists the workflows and their parameters. See [Workflows](./workflows.md).

### `check WORKFLOW [--PARAM VALUE ...]`

Validates the configuration, the parameters and the files this machine needs, then prints the plan:

* which steps run here,
* which run on the other machine, and
* which are already in place and will be adopted.

Changes nothing: it writes no journal and no `common.inc`, and runs no script.

### `run WORKFLOW [--PARAM VALUE ...]`

Performs the same checks as `check`, then runs steps until the workflow finishes, a step fails, or the next step belongs to the other machine (the run pauses). Refuses to start if another run of the same workflow is unfinished.

### `resume [RUN_ID] [--mark-done STEP] [--retry STEP]`

Continues a run. Without `RUN_ID`, it picks, in order:

1. The run carried in `./offlineTransfer.json`, if its ticket is newer than this machine's copy. It is imported after confirmation and its carried files are unpacked.
2. The only unfinished local run.

| Option | Meaning |
| --- | --- |
| `--mark-done STEP` | Record STEP as done without running it. Use after checking that an interrupted, non-repeatable step took effect. |
| `--retry STEP` | Reset STEP to pending so it runs again. |

### `abandon RUN_ID`

Marks a run abandoned so the workflow can be started again. Files produced so far are left in place.

### `status`

Shows the workspace role, the pool's key files and KES counters, the KES expiry from `<pool>.kes-expire.json`, a summary of `offlineTransfer.json` (queued transactions, attached files, a carried run) and unfinished runs.

### `runs`

Lists all runs with status and last update.

### `show RUN_ID`

Prints one run's report: steps, artefacts with digests and modes, notes and next actions.

### `exec SCRIPT [ARGS ...]`

Runs one SPO script by name (for example `04a_genNodeKeys.sh`) in the workspace, after regenerating `./common.inc`. The script's exit code becomes the command's exit code. Paths are refused; only names in the release set's scripts directory resolve.

### `edit FILE`

Unlocks a script-locked file in the workspace (`chmod 600`), opens `$VISUAL` or `$EDITOR` (default `vi`), and restores the original mode afterwards. `.json` files are checked for valid JSON after editing. Signing keys (`*.skey`, `*.hwsfile`) are refused.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success; the run finished. |
| 1 | Other error. |
| 2 | Usage error. |
| 3 | Configuration error (`workbench.toml` or toolchain manifest). |
| 4 | Check failed; nothing was changed. |
| 5 | A step failed; fix the cause and `resume`. |
| 6 | Needs an operator decision (interrupted non-repeatable step, declined import). |
| 7 | Drift: a file recorded by a finished step changed. |
| 8 | Another `workbench` process holds the workspace lock. |
| 10 | The run paused; continue on the other machine. |
| 130 | Interrupted. |

## Environment

| Variable | Meaning |
| --- | --- |
| `WORKBENCH_DIR` | Default workspace directory. |
| `SPO_WB_TOOLCHAIN` | Path of the toolchain manifest. Set by the Nix wrapper; override only for development. |
| `VISUAL`, `EDITOR` | Editor for `edit`. |

`ENV_DECRYPT_PASSWORD` is removed from the scripts' environment.
