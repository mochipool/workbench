# Release set

This page describes `versions.nix`, the manifest that pins every bundled tool, and the checks that enforce it. For the reasoning, see [Release sets and versioning](../explanation/release-sets-and-versioning.md). For the procedure, see [Cut a release](../how-to/cut-a-release.md).

## versions.nix schema

`versions.nix` evaluates to an attribute set with two top-level fields.

### supportedSystems

A list of Nix system strings. Currently `x86_64-linux`, `aarch64-linux`, `aarch64-darwin`. The flake builds all per-system outputs from this list.

### tools.cardano-node

| Field | Meaning |
| --- | --- |
| `version` | Version string, checked against the scripts' node requirements. |
| `ref` | Git ref in the flake input URL. |
| `rev` | Commit the lock file must hold for the input. |

### tools.cardano-cli

Same fields as `cardano-node`. The `ref` has the form `cardano-cli-<version>`.

### tools.spo-scripts

Same fields. `version` and `ref` are the upstream `Update-*` tag. The scripts' `cardano/mainnet/00_common.sh` at this revision is the source of the version requirements.

### tools.cardano-hw-cli

| Field | Meaning |
| --- | --- |
| `version` | Nominal release-set version. Used for the autocomplete script download. |
| `platforms` | Per-platform artifact pins, keyed `linux-x64`, `linux-arm64`, `mac-arm64`. |
| `platforms.<name>.version` | Version of that platform's artifact. May differ from the nominal version. |
| `platforms.<name>.hash` | SRI hash of the release tarball. |
| `autocompleteHash` | SRI hash of `autocomplete.sh` at the nominal version. |

### tools.trezorctl

| Field | Meaning |
| --- | --- |
| `version` | PyPI version of the `trezor` package. |
| `hash` | SRI hash of the PyPI source tarball. |

### tools.cardano-signer

| Field | Meaning |
| --- | --- |
| `version` | Release version. |
| `hashes` | SRI hashes keyed `linux-x64`, `linux-arm64`, `mac-x64`. |

## Platform mapping

| Nix system | cardano-hw-cli platform | cardano-signer platform |
| --- | --- | --- |
| `x86_64-linux` | `linux-x64` | `linux-x64` |
| `aarch64-linux` | `linux-arm64` | `linux-arm64` |
| `aarch64-darwin` | `mac-arm64` | `mac-x64` (runs under Rosetta 2) |

## Checks

All three exist for every supported system as `checks.<system>.<name>`.

### version-manifest

For `cardano-node`, `cardano-cli` and `spo-scripts`, compares `tools.<name>.rev` with the revision the flake input is locked to. Any difference is reported as `flake input <name> is locked to <rev> but versions.nix declares <rev>`.

### spo-compat

Parses these variables from the SPO scripts' `00_common.sh`: `minCliVersion`, `maxCliVersion`, `minNodeVersion`, `maxNodeVersion`, `minHardwareCliVersion`, `minCardanoSignerVersion`, plus the device minimums `minLedgerCardanoAppVersion`, `minTrezorCardanoAppVersion` and `minKeystoneCardanoAppVersion`. It then fails if the pinned cardano-cli, cardano-node, any per-platform cardano-hw-cli version or cardano-signer is below a minimum or above a maximum. Device minimums are not checked here; they are reported by `workbench-doctor`.

### readme-sync

Computes the requirements block and compares it with the text between `<!-- BEGIN generated:requirements -->` and `<!-- END generated:requirements -->` in `readme.md`. Regenerate with `nix run --accept-flake-config .#update-readme`.

## Requirements table

The generated table of pinned versions and requirements is maintained in the readme: [Requirements and compatibility](../../readme.md#-requirements--compatibility). It is not copied here to avoid drift.
