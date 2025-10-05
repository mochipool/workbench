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

* 🌍 **Cross-Platform & Reproducible**: Works anywhere Nix is supported.
* 🔄 **Environment Switching**: Switch effortlessly between mainnet, testnet, or previewnet.
* 🏷️ **Version Management**: Pin specific `cardano-node` versions or other tools directly in the flake.
* 🧹 **Minimal Host Impact**: Keeps your filesystem clean and organized.
* ⚙️ **Customizable Scripts**: Override defaults safely with a local `common.inc`.
* 🔒 **Hardware Wallet Friendly**: Built-in guidance for Ledger integration.

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

# Switch network (example: previewnet)
nix develop --accept-flake-config .#preview
```

🎉 You're ready to run!

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

| Network    | Default | Notes               |
| ---------- | ------- | ------------------- |
| Mainnet    | ✅       | Default environment |
| Testnet    |         | Configure via flake |
| Previewnet |         | Configure via flake |

Easily add custom networks in your flake configuration.

---

## 🤝 Contributing

Contributions are welcome! Please ensure your changes are reproducible with Nix and follow standard GitHub contribution practices.

---

## 📌 Roadmap / TODO

* [ ] Enable full customization of SPO scripts via flake integration
* [ ] Improve documentation for advanced flake configurations
* [ ] Add CI checks for reproducibility and network switching

---

## 🙏 Acknowledgements

* [Martin Lang](https://github.com/gitmachtl/scripts) for the SPO scripts which form a core part of this environment.
* The Nix community for making reproducible, cross-platform development environments possible.
* LedgerHQ for maintaining the official udev rules for hardware wallets.

---

## 📜 License

This project is licensed under the [GNU GPL v3](./LICENSE).
