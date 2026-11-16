# workbench.toml

This page specifies the workspace configuration file read by `workbench`.

The file lives in the workspace root. Validation is strict: unknown sections and keys are errors.

## Example

```toml
[workbench]
network = "mainnet"
role = "offline"
airgapped = true

[pool]
name = "mypool"
kes_key = "cli"

[bundle]
kes_skey = "kes.skey"
opcert = "node.opcert"
include_vrf = false

[scripts]
koiosApiToken = "..."
```

## `[workbench]` (required)

| Key | Type | Required | Values | Meaning |
| --- | --- | --- | --- | --- |
| `network` | string | yes | `mainnet`, `preprod`, `preview` | Selects the scripts variant and genesis files. |
| `role` | string | yes | `online`, `light`, `offline` | What this machine is. Becomes the scripts' `workMode`. |
| `airgapped` | bool | no (default `false`) | | Signing keys live on a separate offline machine. Steps that need keys run only where `role = "offline"`; steps that need the chain run only where `role` is `online` or `light`. |
| `socket` | string | when `role = "online"` | path | cardano-node socket, relative to the workspace or absolute. Checked for existence before each run. Not allowed for other roles. |

Rules:

* `role = "offline"` requires `airgapped = true`.
* `role = "online"` requires `socket`.

## `[pool]` (needed by `kes-rotate` and `pool-update`)

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | string | required | The pool name used in file names (`<name>.node.vkey`, ...). Letters, digits, `_` and `-`, at most 64 characters, not starting with `_` or `-`. |
| `kes_key` | string | `cli` | `cli` or `enc`: passed to `04c_genKESKeys.sh`. `enc` keys are password-encrypted with gpg. |

## `[bundle]`

Names of files inside the block-producer bundle made by `kes-rotate`.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `kes_skey` | string | `kes.skey` | Name of the KES signing key in the bundle. |
| `opcert` | string | `node.opcert` | Name of the operational certificate in the bundle. |
| `include_vrf` | bool | `false` | Also include `<pool>.vrf.skey` as `vrf.skey`. |

The names must be plain file names (no `/`, not starting with `.`).

## `[scripts]`

Extra settings written to `./common.inc`, for example `koiosApiToken`. Keys must be valid shell variable names; values must be strings, integers or booleans (written as `true`/`false`). Values are shell-escaped.

These keys are managed by the workbench and are rejected here:

`network`, `workMode`, `workmode`, `socket`, `offlineFile`, `cardanocli`, `cardanonode`, `cardanohwcli`, `cardanosigner`, `bech32_bin`, `genesisfile`, `genesisfile_byron`.

## The generated `common.inc`

On every `run`, `resume` and `exec`, `./common.inc` is rewritten (mode `0600`) from:

1. The release set's settings for the network (binary and genesis paths).
2. `workMode` from `role`, `offlineFile="./offlineTransfer.json"` and `socket`.
3. The `[scripts]` table.

Its first line is `# managed-by: spo-workbench`. A `common.inc` without that line was written by hand; the workbench refuses to replace it.
