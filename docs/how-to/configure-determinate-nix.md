# Configure Determinate Nix

This guide shows how to make Determinate Nix use the IOG binary cache and why the flake sets `lazy-trees = false`.

## Prerequisites

* Determinate Nix installed.
* `sudo` rights. The script edits `/etc/nix/nix.custom.conf` and restarts the Nix daemon.
* The repository cloned.

## Configure the cache

From the repository root:

```sh
./scripts/determinate-nix-config.sh
```

The script takes one optional argument, a flake target stored in a variable named `TARGET`, defaulting to `.#mainnet`. The current script does not use it. You can ignore it.

The script does the following, in order:

1. Deletes `~/.local/share/nix/trusted-settings.json`, which forgets earlier answers to flake configuration prompts.
2. Backs up `/etc/nix/nix.custom.conf` to a timestamped `.bak` file, then rewrites it without existing IOG cache entries and appends `extra-trusted-substituters` for `https://cache.iog.io` and the matching `extra-trusted-public-keys` entry.
3. Restarts the daemon with `systemctl` (Linux) or `launchctl` (macOS).
4. Adds `extra-substituters` and `allow-import-from-derivation = true` to `~/.config/nix/nix.conf` if they are not already present.
5. Checks that `nix config show` reports the `hydra.iohk.io:` key and the cache URL, and exits with an error if not.

Re-running it is safe.

## Use the flake configuration

Always pass `--accept-flake-config` so that the settings in the flake's `nixConfig` apply:

```sh
nix develop --accept-flake-config .#preview
```

On the first use Nix may ask whether to trust the flake's settings. The flake sets the IOG substituter and key, `allow-import-from-derivation = true` and `lazy-trees = false`.

## Why lazy-trees is disabled

Determinate Nix enables lazy trees by default. With lazy trees, haskell.nix import-from-derivation fails and sources do not materialise. The error looks like `path ... does not exist and cannot be created`. The Cardano toolchain relies on haskell.nix, so the flake pins `lazy-trees = false` in `nixConfig`. Import-from-derivation must also be allowed, which is why the setting appears in both the flake and the script.

## Troubleshooting

* Everything builds from source: the cache is not trusted. Run `nix config show trusted-substituters` and confirm it lists `https://cache.iog.io`. If not, rerun the script.
* `ERROR: hydra.iohk.io key is still missing`: the daemon did not pick up the new configuration. Restart it manually and rerun the script.
* The `path ... cannot be created` error: you ran without `--accept-flake-config`, so `lazy-trees = false` was not applied.
