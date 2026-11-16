# Give USB access to hardware wallets

This guide shows how to let your user talk to a Ledger or Trezor over USB on Linux without `sudo`.

## Prerequisites

* A Linux system (the app and package exist only on Linux; macOS needs no rules).
* The repository cloned.
* On non-NixOS systems, `sudo` rights.

Keystone needs no rules on any platform: it signs by QR code.

## Install the rules (non-NixOS)

The workbench builds one rules file from nixpkgs' Ledger and Trezor rule sets. The rules grant the logged-in user access through the `uaccess` tag.

Print the rules file path and the install command without changing anything:

```sh
nix run --accept-flake-config .#install-udev-rules
```

Install them:

```sh
nix run --accept-flake-config .#install-udev-rules -- --install
```

This copies the file to `/etc/udev/rules.d/70-cardano-spo-workbench.rules`, reloads the rules and triggers udev.

Unplug and replug the device, then confirm:

```sh
workbench-doctor
```

## NixOS

On NixOS `/etc` is declarative. The app detects `/etc/NIXOS`, prints a hint and exits without installing. Add the rules to your system configuration instead:

```nix
services.udev.packages = [ workbench.packages.x86_64-linux.udev-rules ];
```

Replace `workbench` with however your configuration refers to this flake, and the system with yours. For Ledger only, `hardware.ledger.enable = true;` also works. Rebuild and replug the device. See also [Use on NixOS](./use-on-nixos.md).
