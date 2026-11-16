# Architecture

This page explains how the flake is assembled and why it is structured the way it is.

## One function per system

`flake.nix` defines `workbenchFor system`, which builds everything the flake offers for one platform: nixpkgs, the upstream node and CLI packages, the prebuilt tools, the doctor, the SPO scripts and a shell generator, `mkNetworkShell`. The flake outputs (`devShells`, `packages`, `checks`, `apps`) are then projections of that one attribute set over the list in `supportedSystems`. Keeping one assembly point means a shell, a package and a check always see the same tool instances.

## Where each tool comes from

| Tool | How it is obtained | Defined in |
| --- | --- | --- |
| cardano-node, bech32 | Upstream flake input, built by IOG's Hydra | `flake.nix` |
| cardano-cli | Upstream flake input (separate repository) | `flake.nix` |
| SPO scripts | Upstream repository as a non-flake input | `tools/spo-scripts.nix` |
| cardano-hw-cli | Prebuilt release tarball per platform | `tools/cardano-hw-cli.nix` |
| cardano-signer | Prebuilt release tarball per platform | `tools/cardano-signer.nix` |
| trezorctl | Built from PyPI with nixpkgs Python packages | `tools/trezorctl.nix` |
| workbench-doctor | `writeShellApplication` | `tools/doctor.nix` |
| workbench | `buildPythonApplication`, wrapped with the toolchain manifest | `tools/workbench.nix`, source in `orchestrator/` |
| udev rules | Concatenation of nixpkgs rule files | `tools/udev-rules.nix` |

### Cache or prebuilt binary

Haskell tools take hours to compile. They come from flake inputs because IOG's binary cache (`https://cache.iog.io`, configured in `nixConfig`) already holds their builds. That is why the flake needs `allow-import-from-derivation` and, under Determinate Nix, `lazy-trees = false`: the upstream builds use haskell.nix, which relies on import-from-derivation.

hw-cli and signer are different. They are single-file executables produced with `pkg`, which appends a JavaScript payload to a node binary. Upstream has no Nix support, so the workbench downloads the official release tarballs and pins their hashes in `versions.nix`. The trade-off is that the binaries cannot be patched: `patchelf` and `strip` shift the payload offsets and corrupt it, so the derivations disable both (`dontPatchELF`, `dontStrip`). Regular Linux distributions run the result as-is. NixOS has no standard loader path, so it needs `nix-ld`. See [Use on NixOS](../how-to/use-on-nixos.md).

## The SPO scripts: two variants and a generated configuration

Upstream keeps two directories, `cardano/mainnet` and `cardano/testnet`. `tools/spo-scripts.nix` selects one from the network name (Mainnet gets `mainnet`, anything else gets `testnet`) and copies its files into `$out/bin`, so every script is on `PATH` in the shell. This is why `packages.spo-scripts-mainnet` and `packages.spo-scripts-testnet` exist as two derivations.

The scripts expect to be configured by variables in `00_common.sh` or a `common.inc`. Rather than patching the scripts, the flake generates a `common.inc` with `writeText`. Its attribute names match the variables the scripts read: `network`, `workMode`, `genesisfile`, `genesisfile_byron`, `cardanonode`, `bech32_bin`, `cardanocli`, `cardanohwcli`, `cardanosigner`. The values are store paths. The dev shell links this file to `~/.common.inc`, which the scripts source (see [Customise script settings](../how-to/customise-script-settings.md)). This leaves the upstream scripts byte-identical to the pinned revision and lets a user override any value with a later `common.inc`.

The generated configuration sets `workMode` to `light`. A shell therefore needs no local node, at the cost of depending on public APIs. [Work modes](./work-modes.md) discusses the options.

### Genesis files

The scripts need the Shelley and Byron genesis files for the selected network. `tools/cardano-configs.nix` fetches the official files from `book.world.dev.cardano.org` with `fetchurl` and a fixed hash, one derivation per network and era. A fixed-output derivation makes the file part of the closure, so a shell works without fetching it at run time, and any change upstream shows up as a hash mismatch.

## Checks without the Haskell toolchain

`version-manifest`, `spo-compat` and `readme-sync` read only text: `versions.nix`, `flake.lock` and `00_common.sh`. They deliberately avoid building cardano-node or cardano-cli, so they run in seconds on every platform, including `aarch64-linux`, where no upstream cache exists for cardano-cli. The `spo-compat` check works by parsing the scripts' own version variables at evaluation time, so the scripts remain the single source of truth for what they require. [Release sets and versioning](./release-sets-and-versioning.md) explains the policy behind them.

## One source for documentation of requirements

`tools/release-docs.nix` renders the requirements table from the same data the checks use, and `tools/doctor.nix` bakes the same requirement values into the doctor script. The readme table, the doctor and the checks therefore cannot disagree unless a check fails.

## The orchestrator

The `workbench` command runs multi-step workflows on top of these scripts. `tools/workbench.nix` builds it from `orchestrator/` and wraps it with a JSON toolchain manifest. The manifest maps each network to its scripts variant and to the same settings `mkParams` produces for the dev shells' `common.inc`, so a `workbench` binary only ever drives the release set it was built with. Its design is described in [Orchestrator design](./orchestrator-design.md).
