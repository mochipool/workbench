# Supported systems and networks

This page lists the platforms and Cardano networks the workbench supports and how each tool is obtained on them.

## Systems

| System | cardano-node / cardano-cli | cardano-hw-cli | cardano-signer | Notes |
| --- | --- | --- | --- | --- |
| `x86_64-linux` | From the IOG cache | Prebuilt `linux-x64` | Prebuilt `linux-x64` | Recommended for block producers. |
| `aarch64-linux` | Node from the IOG cache. No native upstream cache for cardano-cli. | Prebuilt `linux-arm64` | Prebuilt `linux-arm64` | The first cardano-cli build compiles from source. CI does not build the full dev shell on this system. |
| `aarch64-darwin` | From the IOG cache | Prebuilt `mac-arm64` | Prebuilt `mac-x64`, run through Rosetta 2 | Suited to client-side use: key and certificate management, signing. |

`x86_64-darwin` is not supported. cardano-hw-cli 1.20.0 and later, which the SPO scripts require, publish no mac-x64 artifact.

cardano-signer publishes no native Apple Silicon binary. cardano-hw-cli has published a native `mac-arm64` build since 1.20.0.

On NixOS the prebuilt hw-cli and signer binaries need `nix-ld`. See [Use on NixOS](../how-to/use-on-nixos.md).

The udev rules package and the `install-udev-rules` app exist on Linux only. macOS needs no rules.

## Networks

| Network | Shell | Scripts variant | Notes |
| --- | --- | --- | --- |
| Mainnet | `.#mainnet` (also the default shell) | `cardano/mainnet` | Default. |
| PreProd | `.#preprod` | `cardano/testnet` | |
| Preview | `.#preview` | `cardano/testnet` | |

Network names are case-insensitive internally and normalised to `Mainnet`, `PreProd` and `Preview`. Other names are rejected with an error listing the valid ones. The upstream scripts also know `sancho` and `guildnet`, but the workbench bundles genesis files only for the three above.

Each shell starts in work mode `light`. See [Work modes](../explanation/work-modes.md) and [Customise script settings](../how-to/customise-script-settings.md).

Version requirements are in the [readme](../../readme.md#-requirements--compatibility).
