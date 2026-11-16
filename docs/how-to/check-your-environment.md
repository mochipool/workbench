# Check your environment

This guide shows how to verify that the bundled tools, and optionally a connected hardware wallet, meet the requirements of the SPO scripts.

## Prerequisites

* The workbench repository cloned (see [Set up the workbench](../tutorials/set-up-the-workbench.md)).
* For the device check: the wallet connected and unlocked, and on a Ledger the Cardano app opened.

## Run the check

Inside a workbench shell:

```sh
workbench-doctor              # tools and connected hardware wallet
workbench-doctor --no-device  # tools only
```

Without entering a shell:

```sh
nix run --accept-flake-config .#doctor
nix run --accept-flake-config .#doctor -- --no-device
```

## Read the result

Each line is `OK`, `WARN` or `FAIL`.

* `FAIL` means a tool or the device is older than the required minimum or newer than an allowed maximum. The command then exits with status 1 and prints the number of problems.
* `WARN` for a tool means its version satisfies the requirements but differs from the version pinned in `versions.nix`.
* `WARN` about udev rules (Linux only) means no rules for Ledger devices were found. See [Give USB access to hardware wallets](./give-usb-access-to-hardware-wallets.md).
* `WARN` about "no usable device" means the device query did not return a recognised answer within 20 seconds, and the device checks were skipped. Unlock the device, open the Cardano app and run the check again.

An unknown flag prints the usage text and exits with status 2.

## Fix a failing device version

* Ledger: [Update the Ledger Cardano app](./update-ledger-cardano-app.md)
* Trezor: [Update Trezor firmware](./update-trezor-firmware.md)
* Keystone: [Update Keystone firmware](./update-keystone-firmware.md)

The minimum versions are listed in the requirements table in the [readme](../../readme.md#-requirements--compatibility).
