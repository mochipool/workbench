# Claim rewards air-gapped

This guide withdraws staking rewards when the stake key is on an offline machine.

## Prerequisites

* Two workspaces for the same network, both with `airgapped = true`:
  * Online machine: `role = "online"` (synced node, `socket` set) or `role = "light"`.
  * Offline machine: `role = "offline"`.
* On the online machine: `<stake>.staking.addr` and the fee payer's `.addr` (for example `smallwallet1.addr`).
* On the offline machine: `<stake>.staking.skey` (or `.hwsfile`), the fee payer's `.skey` (or `.hwsfile`), and the destination's `.addr`.
* The online machine's `offlineTransfer.json`, if it exists, has no queued transactions or attached files. The workflow resets it.

The example claims the rewards of `owner.staking` into `owner.payment`, with `smallwallet1` paying the fee.

## Steps

1. On the online machine, check and start:

   ```sh
   workbench check claim-rewards --stake owner --to owner.payment --payer smallwallet1
   workbench run claim-rewards --stake owner --to owner.payment --payer smallwallet1
   ```

   The workbench loads fresh balances and the rewards state into `offlineTransfer.json`, attaches the run ticket, and pauses (exit code 10).

2. Copy `offlineTransfer.json` to the offline workspace. There:

   ```sh
   workbench resume
   ```

   Check the imported parameters, confirm, then check the transaction summary that `01_claimRewards.sh` shows before it signs. The signed transaction is queued in `offlineTransfer.json` and the run pauses again.

3. Copy `offlineTransfer.json` back to the online workspace and run:

   ```sh
   workbench resume
   ```

   The workbench submits exactly the transaction signed in step 2 (`01_workOffline.sh execute <n>`). The run is done when that transaction has left the queue.

## Notes

* Omit `--payer` to have the destination pay the fee. The destination's `.addr` must then also be on the online machine, and its key on the offline machine.
* Add `--message "claim for epoch 512"` to attach a transaction message.
* Use the same pattern for payments: `workbench run send-ada --from smallwallet1 --to owner.payment --amount 100ada`. See [Send ADA](./send-ada.md).
* If you lose track, `workbench status` on either machine shows the run, what it is waiting for, and what `offlineTransfer.json` contains.

Related: [Work modes](../explanation/work-modes.md), [Workflows reference](../reference/workflows.md#claim-rewards).
