# Use on NixOS

This guide shows what a NixOS machine needs on top of the normal setup: `nix-ld` for the prebuilt binaries and udev rules through your system configuration.

## Prerequisites

* NixOS with flakes enabled.
* The repository cloned.

## Enable nix-ld

cardano-hw-cli and cardano-signer are prebuilt release binaries (pkg-bundled node executables). They are dynamically linked foreign binaries, and the flake cannot patch them with `patchelf` or strip them because that corrupts the JavaScript payload appended to the executable. On NixOS they therefore need [`nix-ld`](https://github.com/nix-community/nix-ld) to find a loader:

```nix
programs.nix-ld.enable = true;
```

Rebuild, then check that both tools start:

```sh
nix develop --accept-flake-config --command sh -c 'cardano-hw-cli version && cardano-signer version'
```

cardano-node, cardano-cli and trezorctl are built by Nix and need no special handling.

## Install the udev rules

`/etc` is declarative on NixOS, so `install-udev-rules` does not install anything there. It prints a hint and exits. Add the rules package from this flake to your configuration:

```nix
services.udev.packages = [ workbench.packages.x86_64-linux.udev-rules ];
```

Replace `workbench` with your flake input name and the system with yours. For Ledger alone, `hardware.ledger.enable = true;` is an alternative. Rebuild and replug the device, then run:

```sh
workbench-doctor
```

## Configure the cache

NixOS does not use Determinate's configuration file. The flake's `nixConfig` adds the IOG cache when you pass `--accept-flake-config`. To make it permanent, add `https://cache.iog.io` and the key `hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ=` to `nix.settings.substituters` and `nix.settings.trusted-public-keys`. If you run Determinate Nix on NixOS, see [Configure Determinate Nix](./configure-determinate-nix.md).
