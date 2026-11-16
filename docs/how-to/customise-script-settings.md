# Customise script settings

This guide shows how to override the SPO scripts' settings, such as the work mode, without editing the scripts.

## Prerequisites

* A workbench shell, for example `nix develop --accept-flake-config .#preview`.

## How settings are loaded

Every SPO script starts by loading `00_common.sh`, which sets defaults and then sources up to three `common.inc` files, in this order:

1. `common.inc` next to the script (`<scriptDir>/common.inc`).
2. `$HOME/.common.inc`.
3. `common.inc` in the current working directory.

Later files override earlier ones, so a `common.inc` in your working directory wins over `~/.common.inc`.

In the workbench the scripts live in the Nix store, so the first location is never populated. The dev shell fills the second one: on entry, if `~/.common.inc` is absent or already a link into the Nix store, it links it to a generated file and registers an exit trap that removes the link when the shell ends, provided it still points to that file. The generated file sets the network, `workMode="light"`, the genesis file paths and the paths to cardano-node, bech32, cardano-cli, cardano-hw-cli and cardano-signer. It is read-only, because it lives in the Nix store.

## Override a setting

Create `common.inc` in the directory you run the scripts from. It is plain shell, so each line is an assignment. For example, to work offline on an air-gapped machine:

```sh
workMode="offline"
```

Only list the variables you change. The generated values stay in effect for everything else.

Check what the scripts picked up:

```sh
bash 00_common.sh
```

The `Mode:` text shows the active work mode. The settings and their allowed values are listed in the "Configuration, Scriptfiles Syntax & Filenames" section of the [upstream SPO scripts README](https://github.com/gitmachtl/scripts/blob/master/cardano/mainnet/README.md). The upstream script also accepts a lowercase `workmode` entry.

## Things to know

* Do not edit `~/.common.inc`. It is a symlink into the Nix store and is replaced each time you enter a shell.
* A `~/.common.inc` of your own (a regular file) is never replaced: the shell warns and leaves it in place, and the scripts will then use it instead of the generated settings.
* Under `nix develop --command ...` the shell `exec`s the command, so the exit trap does not run and the link stays until the next shell replaces it.
* In a `workbench` workspace, `./common.inc` belongs to the workbench: it is regenerated on every run and a hand-written one is refused. Put overrides in the `[scripts]` table of `workbench.toml` instead (see [workbench.toml](../reference/workbench-toml.md)).
* Work modes are explained in [Work modes](../explanation/work-modes.md).
