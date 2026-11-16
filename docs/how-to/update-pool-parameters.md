# Update pool parameters

This guide changes your pool's pledge, cost, margin, relays or metadata and re-registers it.

## Prerequisites

* `[pool] name` set in `workbench.toml` on the key machine.
* On the key machine:
  * `<pool>.pool.json`,
  * `<pool>.node.skey` (or `.hwsfile`),
  * each owner's `.staking.skey` (or `.hwsfile`),
  * the payer's `.skey` (or `.hwsfile`).
* On the chain machine: the payer's `.addr`, and the ability to upload files to the web server behind `poolMetaUrl`.
* All owners use local witnesses (`"ownerWitness": "local"`). External witnesses are not handled by this workflow; collect them with `05d_poolWitness.sh`.

## Steps

1. Edit the pool configuration on the key machine. The file is locked by the scripts, and `edit` unlocks and relocks it:

   ```sh
   workbench edit mypool.pool.json
   ```

   Only change values above the `--- DO NOT EDIT BELOW THIS LINE ---` entry.

2. Check it. This validates the same limits `05a_genStakepoolCert.sh` enforces (ticker length, URL format, margin range, relays), without generating anything:

   ```sh
   workbench check pool-update --payer smallwallet1
   ```

3. Air-gapped: start on the online machine, then carry `offlineTransfer.json` to the offline machine and resume there:

   ```sh
   # online
   workbench run pool-update --payer smallwallet1
   # offline
   workbench resume
   ```

   On the offline machine, `05a` generates the certificate and `<pool>.metadata.json`, and `05c` signs the re-registration. Answer `05c`'s questions about including the metadata files in `offlineTransfer.json` as you like: the workbench carries `<pool>.metadata.json` either way. Carry the file back to the online machine.

   Not air-gapped: run `workbench run pool-update --payer smallwallet1` once.

4. Before submitting, the workbench fetches `poolMetaUrl` and stops if it does not serve the new `<pool>.metadata.json` byte for byte:

   ```
   error: https://example.org/mypool.metadata.json does not serve the new mypool.metadata.json byte-for-byte. Upload ... then run `workbench resume`.
   ```

   Upload the file shown, then:

   ```sh
   workbench resume
   ```

   The registration is submitted once the published metadata matches.

## Notes

* If you added a new owner, register that owner's delegation afterwards with `workbench exec 06_regDelegationCert.sh ...`.
* While the signed re-registration waits to be submitted, do not spend from the payer wallet. The transaction already consumes specific outputs.

Related: [Workflows reference](../reference/workflows.md#pool-update).
