# Set up the workbench

This tutorial takes you from a machine without Nix to a working preview-network shell in which the tools are installed, the health check passes and one SPO script has run.

You need a Linux or macOS machine (see [Supported systems and networks](../reference/supported-systems-and-networks.md)), a network connection, and `sudo` rights for the Nix installation and cache setup. Nothing in this tutorial touches mainnet or creates keys.

## 1. Install Nix

Install Nix with the Determinate installer:

```sh
curl -fsSL https://install.determinate.systems/nix | sh -s -- install --determinate
```

Open a new terminal afterwards so that `nix` is on your `PATH`, then check it:

```sh
nix --version
```

## 2. Clone the repository

```sh
git clone https://github.com/mochipool/workbench.git
cd workbench
```

## 3. Configure the IOG cache

cardano-node and cardano-cli are built by IOG's Hydra and served from `https://cache.iog.io`. Without the cache, Nix compiles them from source, which takes hours. Determinate Nix needs extra configuration to trust that cache, and the repository ships a script for it. It uses `sudo` and restarts the Nix daemon:

```sh
./scripts/determinate-nix-config.sh
```

The script ends by checking that the cache and its key are active. If it prints an `ERROR:` line, see [Configure Determinate Nix](../how-to/configure-determinate-nix.md).

## 4. Enter the preview shell

```sh
nix develop --accept-flake-config .#preview
```

The first run downloads the tools and genesis files, so it takes a while. When the shell starts it prints `Configured for Preview network`. The shell has put cardano-node, cardano-cli, cardano-hw-cli, cardano-signer, trezorctl, `workbench-doctor` and the SPO scripts on your `PATH`, and linked a generated configuration to `~/.common.inc`. That file is removed when you leave the shell.

## 5. Run the health check

```sh
workbench-doctor --no-device
```

`--no-device` skips the hardware wallet check, so you do not need a wallet for this tutorial. The command lists each tool with its version. A line such as `OK    cardano-node 11.1.3 (required >= 11.0.0)` means the tool meets the scripts' requirements. On Linux it also reports whether Ledger udev rules are installed. A `WARN` for missing udev rules is expected on a fresh machine and does not fail the check. The command ends with `All checks passed` and exits with status 0.

## 6. Run one SPO script

The workbench shell configures the scripts for the preview network in light mode, which means they query public APIs instead of a local node. Running the shared library on its own prints a version line and the active mode and does not create keys or send transactions:

```sh
bash 00_common.sh
```

You should see a `Version-Info:` line with the cardano-cli version, followed by `Mode: online(light)`. Light mode downloads a small parameters file when it starts, so this step needs internet access. If it reports an error about the light-mode parameters, try again later.

You have now run the same code every SPO script starts with. The scripts are all on your `PATH`, so you could run any of them by name. Stay with read-only ones until you have read [Work modes](../explanation/work-modes.md).

## 7. Leave the shell

```sh
exit
```

Leaving the shell removes `~/.common.inc`.

## Next

Continue with [Rotate KES keys on preview](./rotate-kes-on-preview.md). To understand what you just assembled, read [Architecture](../explanation/architecture.md).
