# Work modes

This page explains the three work modes of the SPO scripts and the `offlineTransfer.json` file used to move data between an online and an offline machine. It follows the upstream scripts' README.

## Three ways to run the same scripts

Every script reads one setting, `workMode`, which is `online`, `light` or `offline`. The scripts are the same; the mode changes where they get chain data and how they submit transactions.

| Mode | Local node | Network access | Chain data comes from |
| --- | --- | --- | --- |
| `online` (full mode) | Running, synced cardano-node | Yes | The local node |
| `light` | None | Yes | Online APIs such as Koios and Ada Handle |
| `offline` | None | None | The `offlineTransfer.json` file |

In light mode all transactions are still built and signed locally. Only queries and submission go through online APIs. Light mode lets you switch between Mainnet, PreProd and Preview quickly without syncing a node. Offline mode suits machines that hold signing keys.

The upstream README gives the reason for having offline mode: doing transactions with pledge accounts in online mode can be a security risk, and so can stake pool registrations. Its best-practice advice is to work offline whenever you can, so that cold keys live on an offline machine.

The workbench's shells start in light mode, which needs only cardano-cli and a connection. Changing the mode is covered in [Customise script settings](../how-to/customise-script-settings.md).

## Why not always offline

Offline work means carrying a file back and forth. Balances must be gathered online, and transactions must be submitted online. For testnets, or for small wallets, that effort buys little. The scripts leave the choice to the operator.

## The carry bag

When the machine that holds signing keys is air-gapped, the only thing that crosses the gap is one file, `offlineTransfer.json`, by default in the current directory (the `offlineFile` setting). The upstream README calls it the carry bag. The script that reads and writes it is `01_workOffline.sh`. Keeping the same directory structure on both machines is advised.

It holds three kinds of content:

* Balance, rewards and protocol-parameter information collected online.
* Transactions signed offline and queued for submission.
* Small attached files, such as address files or pool metadata, in either direction.

The flow has three steps.

1. On the online or light machine, gather current information for the addresses you will pay from or claim rewards on (`01_workOffline.sh add <name>`) and move the file to the offline machine. A fresh file is started with `01_workOffline.sh new`.
2. On the offline machine, do the normal work: send funds, update pool parameters, claim rewards. Signed transactions and files you choose to include are stored in the carry bag. Move it back.
3. On the online or light machine, submit the queued transactions (`01_workOffline.sh execute`) and extract attached files (`01_workOffline.sh extract`).

The subcommands `new`, `add` and `execute` refuse to run in offline mode. `attach`, `extract`, `info` and the `clear*` commands manage the file contents.

Information about a balance is a snapshot. An offline transaction pays from one wallet at a time, so doing several transactions in one round trip needs several small payment wallets. The upstream README advises keeping at least three small operator wallets for that, and keeping owner pledge funds out of daily use.

The offline machine needs cardano-cli at the same version as the online side, plus `curl`, `bc`, `xxd` and `jq`, but no cardano-node. In the workbench, those come from the same Nix closure on both machines.

## Related pages

* [Customise script settings](../how-to/customise-script-settings.md)
* [Architecture](./architecture.md)
* [Security model](./security-model.md)
