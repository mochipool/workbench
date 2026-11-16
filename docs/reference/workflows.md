# Workflows

This page lists each workflow's parameters, steps, checks and outputs.

Step locations:

* `chain`: needs chain access, so it runs where `role` is `online` or `light`.
* `keys`: needs signing keys. When `airgapped = true` that is the offline machine; otherwise it is this machine.

A step marked *not repeatable* stops the run after an interruption until you choose `--mark-done` or `--retry` (see [Resume an interrupted run](../how-to/resume-an-interrupted-run.md)).

Checks common to every workflow:

* Parameters are known, present and well formed.
* The run's network matches `workbench.toml`.
* On an online machine, the node socket exists.
* No other run of the same workflow is unfinished.
* The first step can run on this machine.
* On an air-gapped offline machine whose plan hands back to the online machine, `offlineTransfer.json` must exist with protocol parameters (made online with `01_workOffline.sh new`).

## kes-rotate

Rotates the KES keys, issues a new operational certificate, and packages both for the block producer. Requires `[pool]`. Starts on the key machine.

Parameters: none.

The rotation index N is pinned when the run starts: `kes.counter-next` if present, else `kes.counter + 1`, else 0.

| Step | Where | Script | Done when | Outputs |
| --- | --- | --- | --- | --- |
| `gen-kes` | keys | `04c_genKESKeys.sh <pool> <kes_key>` | `kes.counter` = N and `kes-N.skey`, `kes-N.vkey` exist. Not repeatable. | `<pool>.kes-N.vkey`, `<pool>.kes-N.skey` (secret), `<pool>.kes.counter` |
| `gen-opcert` | keys | `04d_genNodeOpCert.sh <pool>` | `node-N.opcert` exists and `kes.counter-next` = N+1. Not repeatable. | `<pool>.node-N.opcert` (carried), `<pool>.node.counter`, `<pool>.kes-expire.json` |
| `package` | keys | (built in) | the bundle exists with all members | `.workbench/out/<run>/<pool>-kes-N-bp.tar` (secret) |
| `verify-opcert` | chain | `04e_checkNodeOpCert.sh <pool>.node-N.opcert next` | exit status 0 | |

N is written zero-padded to three digits in file names (`kes-004`).

Checks on the key machine:

* `<pool>.node.vkey` exists.
* `<pool>.node.skey` or `<pool>.node.hwsfile` exists.
* `<pool>.node.counter` exists.
* The shelley genesis file exists.
* `kes.counter-next` is `kes.counter` or `kes.counter + 1`.
* No `kes-N.*` file exists unless rotation N's keys are complete.

On the chain machine, the carried opcert must be present.

The bundle is an uncompressed tar, mode `0600`, with members of mode `0400`:

| Member | Content |
| --- | --- |
| `kes.skey` (from `[bundle] kes_skey`) | `<pool>.kes-N.skey` |
| `node.opcert` (from `[bundle] opcert`) | `<pool>.node-N.opcert` |
| `vrf.skey` | `<pool>.vrf.skey`, only with `include_vrf = true` |
| `MANIFEST.json` | pool, network, `kesIndex`, `kesKeyType`, run id, member sources and digests, KES expiry |
| `SHA256SUMS` | `sha256sum`-format digests of the key files |

## claim-rewards

Withdraws staking rewards.

| Parameter | Required | Meaning |
| --- | --- | --- |
| `--stake` | yes | Stake account name. `owner` and `owner.staking` both mean `owner.staking.*`. |
| `--to` | yes | Destination wallet name, for example `owner.payment` (`owner.payment.addr`). |
| `--payer` | no | Wallet that pays the fee. Default: the destination. |
| `--message` | no | Transaction message. `\|` separates lines; each line at most 64 bytes. |

Script: `01_claimRewards.sh <stake>.staking <to> [<payer>] ["msg: ..."]`.

Checks:

* On the chain machine, `<stake>.staking.addr` holds a stake address and the fee payer's `.addr` holds a payment address, both of this network.
* On the key machine, `<stake>.staking.skey|hwsfile`, the fee payer's `.skey|hwsfile`, and `<to>.addr`.

## send-ada

Sends ADA.

| Parameter | Required | Meaning |
| --- | --- | --- |
| `--from` | yes | Source wallet name. |
| `--to` | yes | Wallet name, bech32 address, or `$adahandle`. |
| `--amount` | yes | Lovelace (`5000000`), ADA (`5ada`, `2.5 ADA`), or `ALL`, `ALLFUNDS`, `MIN`. At least 1 ADA. |
| `--message` | no | As for claim-rewards. |

Script: `01_sendLovelaces.sh <from> <to> <lovelace> ["msg: ..."]`.

Checks:

* `<from>.addr` holds an address of this network.
* A bech32 destination belongs to this network.
* A destination given by name has `<to>.addr` on the key machine.
* `$adahandle` destinations are refused when air-gapped, because resolving them needs chain access.

## pool-update

Re-registers the pool after you edit `<pool>.pool.json`. Requires `[pool]`.

| Parameter | Required | Meaning |
| --- | --- | --- |
| `--payer` | yes | Wallet that pays the fee (and the deposit for a first registration). |

Extra steps:

| Step | Where | Script | Notes |
| --- | --- | --- | --- |
| `gen-cert` | keys | `05a_genStakepoolCert.sh <pool>` | Outputs `<pool>.pool.cert` and `<pool>.metadata.json` (carried). Records `poolMetaUrl`. |
| `check-metadata` | chain | (built in) | Fetches `poolMetaUrl` (30 s timeout, first 64 KiB) and requires it to be byte-identical to `<pool>.metadata.json`. |

Signing uses `05c_regStakepoolCert.sh <pool> <payer>`. `check-metadata` runs before submission: before `sign` when not air-gapped, before `execute` when air-gapped.

`<pool>.pool.json` checks, mirroring `05a`:

* `poolName` equals the pool name.
* `poolPledge` and `poolCost` are whole lovelace.
* `poolMargin` is between 0 and 1.
* There is at least one owner, and every owner's witness is `local` (external witnesses are not handled; use `05d_poolWitness.sh`).
* There is at least one relay. Each relay type is `ip`, `ip6`, `dns` or `srv`, and ports are 1-65535 (except `srv`).
* `poolMetaName` is at most 50 characters.
* `poolMetaTicker` is 3-5 characters.
* `poolMetaDescription` is at most 255 characters.
* `poolMetaHomepage` and `poolMetaUrl` are http(s) URLs of at most 128 characters.

Signing keys required: the payer, `<pool>.node`, and each owner's `.staking`.

## Transaction step shapes

claim-rewards, send-ada and pool-update share this shape.

Not air-gapped:

| Step | Where | Notes |
| --- | --- | --- |
| `sign` | keys (here) | Runs the script, which builds, signs and submits. Not repeatable. |

Air-gapped:

| Step | Where | Script | Done when |
| --- | --- | --- | --- |
| `prepare` | chain | `01_workOffline.sh new`, then `add <name>` for each address | Always re-run, so balances are fresh. |
| `sign` | keys | the workflow's script | exactly one new transaction is queued in `offlineTransfer.json`. Its digest is recorded. |
| `execute` | chain | `01_workOffline.sh execute <index of that transaction>` | that transaction has left the queue. |

When starting air-gapped, `offlineTransfer.json` must have no queued transactions and no attached files other than a workbench ticket. `new` would discard them.
