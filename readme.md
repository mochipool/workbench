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

The exact pinned versions live in [`versions.nix`](./versions.nix) — the single source of truth for the release set. See [RELEASING.md](./RELEASING.md) for the versioning policy and how compatibility is enforced.

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
| `aarch64-darwin` | ✅ cached | ✅ via Rosetta 2 | Client-side use (key/cert management, signing) |
| `x86_64-darwin` | ✅ cached | ✅ native | Client-side use |

* cardano-hw-cli and cardano-signer ship no native Apple Silicon binaries; the bundled `mac-x64` builds run transparently under Rosetta 2.
* On **NixOS**, the prebuilt hw-cli/signer binaries need [`nix-ld`](https://github.com/nix-community/nix-ld) (they are dynamically linked foreign binaries and cannot be patched without corrupting their embedded payload).

---

## 🛠️ Customization

### SPO Scripts

* Preconfigured for immediate use.
* Override defaults by creating a `common.inc` in your working directory. It takes priority over `.common.inc`.

### Ledger Hardware Wallet Support

On Linux, add udev rules for non-root access:

```sh
curl -L https://raw.githubusercontent.com/LedgerHQ/udev-rules/master/add_udev_rules.sh | sudo bash
```

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
