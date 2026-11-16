# Flake outputs

This page lists every output of the workbench flake. Systems are `x86_64-linux`, `aarch64-linux` and `aarch64-darwin` (from `supportedSystems` in `versions.nix`). Outputs marked Linux exist only on Linux systems.

Inspect them with:

```sh
nix flake show --accept-flake-config
```

## Inputs

| Input | Source | Flake |
| --- | --- | --- |
| `nixpkgs` | `github:nixos/nixpkgs?ref=nixos-unstable` | yes |
| `cardano-node` | `github:IntersectMBO/cardano-node`, ref from `versions.nix` | yes |
| `cardano-cli` | `github:IntersectMBO/cardano-cli`, ref from `versions.nix` | yes |
| `spo-scripts` | `github:gitmachtl/scripts`, ref from `versions.nix` | no (plain source tree) |

Refs in `flake.nix` must match `versions.nix`; see [Release set](./release-set.md).

## nixConfig

| Setting | Value |
| --- | --- |
| `extra-substituters` | `https://cache.iog.io` |
| `extra-trusted-public-keys` | `hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ=` |
| `allow-import-from-derivation` | `true` |
| `lazy-trees` | `false` |

Applied when you pass `--accept-flake-config`.

## devShells

Each shell is named `workspace-<network>`, includes the base packages (among them `workbench`) plus the SPO script dependencies (`jq`, `curl`, `bc`, `xxd`, `gnupg`) and the network's SPO scripts, and sets up autocompletion for cardano-hw-cli. If `~/.common.inc` is absent or already a link into the Nix store, the shell points it at the network's generated settings, prints `Configured for <network> network`, and removes the link on exit if it still points there. An `~/.common.inc` of your own is left alone, with a warning. All use work mode `light`.

| Output | Network | Scripts variant |
| --- | --- | --- |
| `devShells.<system>.default` | Mainnet (alias of `mainnet`) | `mainnet` |
| `devShells.<system>.mainnet` | Mainnet | `mainnet` |
| `devShells.<system>.preprod` | PreProd | `testnet` |
| `devShells.<system>.preview` | Preview | `testnet` |

## packages

| Output | Purpose |
| --- | --- |
| `cardano-node` | cardano-node, re-exported from the upstream flake (IOG cache). |
| `bech32` | The `bech32` utility, re-exported from the cardano-node flake. |
| `cardano-cli` | cardano-cli, re-exported from the cardano-cli flake. |
| `cardano-hw-cli` | Prebuilt hardware wallet CLI for the current platform. |
| `cardano-signer` | Prebuilt CIP-8/CIP-36 signing tool. |
| `trezorctl` | Trezor CLI built from PyPI at the pinned version. |
| `doctor` | The `workbench-doctor` health check. |
| `workbench` | The workflow orchestrator, bound to this release set's toolchain (see [workbench CLI](./workbench-cli.md)). |
| `spo-scripts-mainnet` | SPO scripts, mainnet variant, copied to `bin/`. |
| `spo-scripts-testnet` | SPO scripts, testnet variant (the derivation is built for PreProd). |
| `default` | A `buildEnv` named `spo-workbench-tools` with node, bech32, cli, hw-cli, signer, trezorctl, doctor, workbench and `spo-scripts-mainnet`. |
| `udev-rules` (Linux) | One rules file for Ledger and Trezor, at `lib/udev/rules.d/70-cardano-spo-workbench.rules`. |

## apps

| Output | Purpose |
| --- | --- |
| `doctor` | Runs `workbench-doctor`. Accepts `--no-device`. |
| `workbench` | Runs the `workbench` orchestrator, e.g. `nix run .#workbench -- status`. |
| `install-udev-rules` (Linux) | Prints the rules path and install command; with `--install` copies the rules to `/etc/udev/rules.d` and reloads udev. On NixOS prints the configuration to use instead. |
| `update-readme` | Rewrites the generated requirements block in `readme.md` (or in the file given as first argument). |

## checks

| Output | Purpose |
| --- | --- |
| `version-manifest` | Fails if a flake input's locked revision differs from `versions.nix`. |
| `spo-compat` | Fails if a pinned tool violates a version requirement of the SPO scripts. |
| `readme-sync` | Fails if the generated block in `readme.md` differs from the computed one. |
| `workbench-tests` | Runs the orchestrator's unit tests against stand-in scripts. Does not depend on the Haskell toolchain. |

Run one with:

```sh
nix build --accept-flake-config --no-link .#checks.x86_64-linux.readme-sync
```

## formatter

`formatter.<system>` is `nixfmt-rfc-style` from nixpkgs. Run `nix fmt`.
