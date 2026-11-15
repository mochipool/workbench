<div align="center">

# Mochi's SPO Workbench ✨

[![License](https://img.shields.io/badge/license-GPLv3-blue?style=flat-square)](./LICENSE)
[![GitHub last commit](https://img.shields.io/github/last-commit/mochipool/workbench?style=flat-square)](https://github.com/mochipool/workbench/commits/main)
[![GitHub issues](https://img.shields.io/github/issues/mochipool/workbench?style=flat-square)](https://github.com/mochipool/workbench/issues)
[![GitHub stars](https://img.shields.io/github/stars/mochipool/workbench?style=flat-square)](https://github.com/mochipool/workbench/stargazers)

A reproducible, hassle-free environment for Cardano SPOs. Mochi's SPO Workbench bundles all essential tools, binaries, and configurations into a single, robust Nix-based setup.

</div>

---

## 🌟 Features

* 🌍 **Cross-Platform & Reproducible**: x86_64/aarch64 Linux and macOS, from one flake.
* 🔄 **Environment Switching**: Switch effortlessly between mainnet, preprod, or preview.
* 🏷️ **Version Management**: One release set (`versions.nix`) pins every tool to a verified-compatible combination, enforced by `nix flake check`.
* 🧹 **Minimal Host Impact**: Keeps your filesystem clean and organized.
* ⚙️ **Customizable Scripts**: Override defaults safely with a local `common.inc`.
* 🔒 **Hardware Wallet Friendly**: Built-in guidance for Ledger integration.

## 📦 Bundled tools

| Tool | Purpose | Source |
| --- | --- | --- |
| [cardano-node](https://github.com/IntersectMBO/cardano-node) + `bech32` | Node & utilities | nix flake (IOG cache) |
| [cardano-cli](https://github.com/IntersectMBO/cardano-cli) | Command-line interface | nix flake (IOG cache) |
| [SPO Scripts](https://github.com/gitmachtl/scripts) | Operator script collection | locked flake input |
| [cardano-hw-cli](https://github.com/vacuumlabs/cardano-hw-cli) | Ledger/Trezor/Keystone signing | official release binaries |
| [cardano-signer](https://github.com/gitmachtl/cardano-signer) | CIP-8/CIP-36 signing & verification | official release binaries |
| [trezorctl](https://github.com/trezor/trezor-firmware/tree/main/python) | Trezor firmware updates | built from PyPI (pinned) |
| `workbench-doctor` | Checks tools and your hardware wallet against the requirements below | this flake |
| udev rules (Linux) | Ledger/Trezor USB access, ready to copy into place | this flake |

The exact pinned versions live in [`versions.nix`](./versions.nix) — the single source of truth for the release set. See [RELEASING.md](./RELEASING.md) for the versioning policy and how compatibility is enforced.

---

## ✅ Requirements & compatibility

<!-- BEGIN generated:requirements -->
Pinned versions and the minimum/maximum versions the SPO scripts (`Update-2026-04`) enforce at runtime:

| Tool | Pinned | Required min | Required max |
| --- | --- | --- | --- |
| cardano-node | 11.1.3 | ≥ 11.0.0 | — |
| cardano-cli | 11.2.3.0 | ≥ 11.0.0 | — |
| cardano-hw-cli | 1.20.0 | ≥ 1.20.0 | — |
| cardano-signer | 1.35.0 | ≥ 1.35.0 | — |

Hardware wallet device requirements (managed on the device, not by this flake):

| Device | Required min |
| --- | --- |
| Ledger Cardano app | ≥ 8.0.8 |
| Trezor firmware | ≥ 2.7.2 |
| Keystone firmware | ≥ 1.7.7 |

Supported systems: `x86_64-linux`, `aarch64-linux`, `aarch64-darwin`.

_This section is generated from `versions.nix` and the scripts' `00_common.sh` — do not edit by hand; run `nix run .#update-readme`._
<!-- END generated:requirements -->

---

## ⚡ Quick Start

### 1. Install Nix

```sh
curl -fsSL https://install.determinate.systems/nix | sh -s -- install --determinate
```

### 2. Clone the Repository

```sh
git clone https://github.com/mochipool/workbench.git
cd workbench
```

### 3. Enter a Development Shell

```sh
# Default: mainnet
nix develop --accept-flake-config

# Switch network (example: preview)
nix develop --accept-flake-config .#preview
```

🎉 You're ready to run!

**NOTE (Determinate Systems Nix):**

When using Determinate Systems Nix, some extra configuration is needed to use the iog cache. It is highly recommended to do so to avoid building everything from source.

Run the following script to configure the cache correctly. It requires sudo:

```sh
./scripts/determinate-nix-config.sh
```

The flake also sets `lazy-trees = false` in its `nixConfig` (applied via `--accept-flake-config`): Determinate Nix's lazy-trees default breaks import-from-derivation in haskell.nix, which the Cardano toolchain relies on.

---

## 💻 Supported Systems

| System | Node/CLI | hw-cli & signer | Notes |
| --- | --- | --- | --- |
| `x86_64-linux` | ✅ cached | ✅ native | Recommended for block producers |
| `aarch64-linux` | ✅ node cached | ✅ native | First `cardano-cli` build compiles from source (no native upstream cache) |
| `aarch64-darwin` | ✅ cached | ✅ hw-cli native, signer via Rosetta 2 | Client-side use (key/cert management, signing) |

* cardano-signer ships no native Apple Silicon binary; the bundled `mac-x64` build runs transparently under Rosetta 2. cardano-hw-cli ships a native `mac-arm64` build since 1.20.0.
* `x86_64-darwin` (Intel Mac) is no longer supported: cardano-hw-cli 1.20.0+ (required by the SPO scripts) publishes no mac-x64 artifact.
* On **NixOS**, the prebuilt hw-cli/signer binaries need [`nix-ld`](https://github.com/nix-community/nix-ld) (they are dynamically linked foreign binaries and cannot be patched without corrupting their embedded payload).

---

## 🛠️ Customization

### SPO Scripts

* Preconfigured for immediate use.
* Override defaults by creating a `common.inc` in your working directory. It takes priority over `.common.inc`.

### Hardware wallets

Setup, firmware updates and troubleshooting are covered in the [how-to guides](#-how-to-guides).

---

## 🧭 How-to guides

Task-oriented recipes for keeping hardware wallets working with the workbench. The versions each device must meet are in [Requirements & compatibility](#-requirements--compatibility). All commands run inside `nix develop --accept-flake-config`, or via `nix run` as shown.

### How to check that your environment is ready

```sh
workbench-doctor              # tools + connected hardware wallet
workbench-doctor --no-device  # tools only
# without entering the shell:
nix run --accept-flake-config .#doctor
```

For the device check, connect and unlock the wallet, and on a Ledger open the Cardano app. The command exits non-zero if any tool or the device is below the required version, and warns when no device is found or the udev rules are missing.

### How to give your user USB access to a Ledger or Trezor (Linux)

The workbench ships one rules file covering both wallets (built from nixpkgs' maintained rule sets). It grants the logged-in user access, so no `sudo` is needed to run the tools.

1. Install the rules:

   ```sh
   nix run --accept-flake-config .#install-udev-rules -- --install
   ```

   Without `--install` the command only prints the rules file path and the exact `sudo install …` command, so you can copy the file yourself.

2. Unplug and replug the device.
3. Confirm with `workbench-doctor`.

On **NixOS** `/etc` is declarative, so add the rules to your system configuration instead (the command prints this for you):

```nix
services.udev.packages = [ workbench.packages.x86_64-linux.udev-rules ];
```

macOS needs no rules. Keystone needs none on any platform: it signs via QR code.

### How to update Trezor firmware

Cardano is only available in the **universal** firmware, not the Bitcoin-only variant, so do not pass `--bitcoin-only`.

1. Make sure your recovery seed is backed up, and connect the device with a good cable.
2. Reboot the device into bootloader mode:

   ```sh
   trezorctl device reboot-to-bootloader
   ```

   If that is not available on your model, enter the bootloader by the key combination in Trezor's documentation for your model.
3. Preview what would be installed (downloads the firmware and verifies its fingerprint, but writes nothing):

   ```sh
   trezorctl firmware-update --dry-run
   ```

4. Install it, then confirm on the device when prompted:

   ```sh
   trezorctl firmware-update
   # or a specific release:
   trezorctl firmware-update --version <x.y.z>
   ```

5. Once the device restarts, confirm the new version with `workbench-doctor`.

`trezorctl` checks the firmware fingerprint against `data.trezor.io` by default. To pin it yourself, pass `--fingerprint <hex>`.

### How to update Keystone firmware

Keystone firmware cannot be updated from the command line: the USB route is browser-only (WebUSB). The microSD route needs only a download and a file copy, and works on any OS. These steps are for the Keystone 3 Pro; see [Keystone's firmware guide](https://guide.keyst.one/docs/firmware-upgrade) for other models.

1. Charge the device (Keystone recommends at least 70%).
2. Download the firmware for your model from Keystone's official firmware page and note the published checksum.
3. Verify the download, then copy it to the root of a FAT32 microSD card as `keystone3.bin`:

   ```sh
   sha256sum keystone3.bin    # compare with the checksum Keystone publishes
   cp keystone3.bin /path/to/mounted/sdcard/keystone3.bin
   sync
   ```

4. Insert the card into the device, tap **Update** on the *New firmware detected* prompt (or Device Settings → About → Firmware → Via MicroSD Card) and enter your PIN.
5. After the device reboots, confirm the version with `workbench-doctor`.

### How to update the Ledger Cardano app

Ledger apps are installed through Ledger's own tooling, which is not packaged in this flake.

1. Update the device firmware first in [Ledger Live](https://www.ledger.com/ledger-live), then update or install the **Cardano** app in its *My Ledger* tab.
2. If the Cardano app version you need is not offered yet, the SPO scripts suggest enabling *Settings → Experimental Features → My Ledger provider* and setting it to `4`. This is at your own risk.
3. Plug in the device, open the Cardano app, and confirm with `workbench-doctor`.

---

## 🌐 Supported Networks

| Network    | Default  | Notes               |
| ---------- | -------  | ------------------- |
| Mainnet    | ✅       | Default environment |
| Preprod    |          | .#preprod |
| Preview    |          | .#preview |

---

## 🏷️ Versioning & Releases

Every workbench tag (`vX.Y.Z`) pins a **release set**: one verified-compatible combination of node, CLI, scripts, and signing tools. Two flake checks enforce this on every commit:

* `version-manifest` — flake inputs must match the revisions declared in `versions.nix`.
* `spo-compat` — the pinned tool versions must satisfy the min/max version requirements the SPO scripts enforce at runtime.
* `readme-sync` — the generated [requirements table](#-requirements--compatibility) above must match `versions.nix` and the scripts' requirements. After a bump, regenerate it with `nix run .#update-readme`.

```sh
nix flake check --accept-flake-config
```

See [RELEASING.md](./RELEASING.md) for the full release process.

---

## 🤝 Contributing

Contributions are welcome! Please ensure your changes are reproducible with Nix and follow standard GitHub contribution practices. This repo uses [jj](https://jj-vcs.github.io/jj/) (colocated with git) for development — create a bookmark per feature and merge back to `main`.

---

## 🙏 Acknowledgements

* [Martin Lang](https://github.com/gitmachtl/scripts) for the SPO scripts and [cardano-signer](https://github.com/gitmachtl/cardano-signer), which form a core part of this environment.
* [Vacuumlabs](https://github.com/vacuumlabs/cardano-hw-cli) for the hardware wallet CLI.
* The Nix community for making reproducible, cross-platform development environments possible.
* LedgerHQ for maintaining the official udev rules for hardware wallets.

---

## 📜 License

This project is licensed under the [GNU GPL v3](./LICENSE).
