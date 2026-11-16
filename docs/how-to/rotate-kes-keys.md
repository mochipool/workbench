# Rotate KES keys

This guide rotates your pool's KES keys and operational certificate and delivers them to the block producer.

## Prerequisites

* A workspace on the machine that holds the pool's cold key (`<pool>.node.skey` or `<pool>.node.hwsfile`), with `[pool] name` set in `workbench.toml`. This is your offline machine if you are air-gapped.
* `<pool>.node.vkey` and `<pool>.node.counter` in the workspace. If you imported your pool from another tool and have no counter file, create one with the on-chain counter value first (`04d_genNodeOpCert.sh` documents the optional counter argument).
* Air-gapped only: a fresh `offlineTransfer.json` from your online machine. Make it there with:

  ```sh
  workbench exec 01_workOffline.sh new
  ```

  and copy it into the offline workspace. The online check at the end travels back in this file.

## Steps

1. Check the rotation first. This changes nothing:

   ```sh
   workbench check kes-rotate
   ```

   The plan shows the rotation index (`kes_index`) and which steps run on this machine.

2. Run it:

   ```sh
   workbench run kes-rotate
   ```

   With `kes_key = "enc"`, `04c` asks you for a password for the new KES key. With a hardware-wallet cold key, `04d` asks you to confirm on the device.

3. Air-gapped: the run pauses with exit code 10 after packaging. Copy `offlineTransfer.json` to the online workspace and run:

   ```sh
   workbench resume
   ```

   Confirm the imported run. The workbench unpacks the new opcert, checks its digest, and runs `04e_checkNodeOpCert.sh ... next` against the chain.

   Not air-gapped: the check runs immediately.

4. Deliver the bundle shown under **Next** in the report (`.workbench/out/<run>/<pool>-kes-NNN-bp.tar`) to the block producer by your usual secure channel. On the block producer:

   ```sh
   mkdir -p /path/to/keys/new && tar -xf mypool-kes-004-bp.tar -C /path/to/keys/new
   cd /path/to/keys/new && sha256sum -c SHA256SUMS
   ```

5. Point the node at the new files: `--shelley-kes-key .../kes.skey` and `--shelley-operational-certificate .../node.opcert` (the names are set in `[bundle]`). Restart cardano-node.

6. Delete the bundle from the machine that made it once the block producer runs on the new keys:

   ```sh
   rm .workbench/out/<run>/<pool>-kes-NNN-bp.tar
   ```

## If something goes wrong

* `Check failed` means nothing was generated. Fix the listed problem and run again.
* If the run stops part-way, see [Resume an interrupted run](./resume-an-interrupted-run.md). Do not re-run `04d` by hand: each run increments the cold counter.
* To see when the keys expire, run `workbench status`.

Related: [Workflows reference](../reference/workflows.md#kes-rotate), [Security model](../explanation/security-model.md).
