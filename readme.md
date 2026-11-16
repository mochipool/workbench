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
* 🧭 **One-Command Workflows**: `workbench run kes-rotate` (and claim-rewards, send-ada, pool-update) validates inputs up front, resumes after interruptions, carries work across an air gap, and reports every file it produced.
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
| `workbench` | Runs common operator workflows (KES rotation, rewards, pool updates, payments) end to end, with validation, resume and air-gap hand-off | this flake |
| `workbench-doctor` | Checks tools and your hardware wallet against the requirements below | this flake |
| udev rules (Linux) | Ledger/Trezor USB access, ready to copy into place | this flake |

The exact pinned versions live in [`versions.nix`](./versions.nix) — the single source of truth for the release set. See [Release sets and versioning](./docs/explanation/release-sets-and-versioning.md) for the policy and how compatibility is enforced.

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

Details on the release set and how it is checked: [Release set reference](./docs/reference/release-set.md).

---

## ⚡ Quick Start

```sh
# 1. Install Nix (Determinate)
curl -fsSL https://install.determinate.systems/nix | sh -s -- install --determinate

# 2. Clone the repository
git clone https://github.com/mochipool/workbench.git
cd workbench

# 3. Enter a shell (mainnet by default; .#preprod and .#preview also exist)
nix develop --accept-flake-config
nix develop --accept-flake-config .#preview
```

With Determinate Nix, configure the IOG cache first to avoid building from source: see [Configure Determinate Nix](./docs/how-to/configure-determinate-nix.md). For a guided walk-through, start with the [set-up tutorial](./docs/tutorials/set-up-the-workbench.md).

---

## 📚 Documentation

The documentation in [`docs/`](./docs/README.md) follows the Diataxis structure.

* **Tutorials**: [Set up the workbench](./docs/tutorials/set-up-the-workbench.md), [Rotate KES keys on preview](./docs/tutorials/rotate-kes-on-preview.md)
* **How-to guides**: [Check your environment](./docs/how-to/check-your-environment.md), [Configure Determinate Nix](./docs/how-to/configure-determinate-nix.md), [Give USB access to hardware wallets](./docs/how-to/give-usb-access-to-hardware-wallets.md), [Use on NixOS](./docs/how-to/use-on-nixos.md), [Customise script settings](./docs/how-to/customise-script-settings.md), [Cut a release](./docs/how-to/cut-a-release.md)
* **Reference**: [Flake outputs](./docs/reference/flake-outputs.md), [Release set](./docs/reference/release-set.md), [Supported systems and networks](./docs/reference/supported-systems-and-networks.md)
* **Explanation**: [Architecture](./docs/explanation/architecture.md), [Release sets and versioning](./docs/explanation/release-sets-and-versioning.md), [Work modes](./docs/explanation/work-modes.md)

The full index, including the hardware wallet firmware guides, is in [docs/README.md](./docs/README.md). The release procedure is in [RELEASING.md](./RELEASING.md), which points into the docs.

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
