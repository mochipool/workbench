# Send ADA

This guide sends ADA from one of your wallets with the `send-ada` workflow.

## Prerequisites

* `<from>.addr` on the chain machine and `<from>.skey` (or `.hwsfile`) on the key machine. These are the same machine if you are not air-gapped.
* A destination: a wallet name with a `.addr` file (on the key machine), a bech32 address of the workspace's network, or, when not air-gapped, an `$adahandle`.

## Steps

1. Check the payment. Amounts are lovelace (`5000000`), ADA (`5ada`, `2.5 ADA`), or `ALL`, `ALLFUNDS` or `MIN`:

   ```sh
   workbench check send-ada --from smallwallet1 --to addr_test1... --amount 25ada
   ```

   An address of the wrong network, an amount below 1 ADA, or a missing key file fails here.

2. Send it:

   ```sh
   workbench run send-ada --from smallwallet1 --to addr_test1... --amount 25ada
   ```

   Not air-gapped: `01_sendLovelaces.sh` shows the transaction and asks before submitting.

   Air-gapped: the run pauses after loading balances. Carry `offlineTransfer.json` to the offline machine, run `workbench resume` there to sign, carry it back, and run `workbench resume` to submit. The full round trip is described in [Claim rewards air-gapped](./claim-rewards-air-gapped.md).

3. Add a message with `--message "invoice 42"`. Use `|` to separate lines; each line can be at most 64 bytes.

## If it is interrupted

When not air-gapped, the signing step also submits. After an interruption the workbench cannot tell whether the transaction reached the chain, so it will not send again on its own. See [Resume an interrupted run](./resume-an-interrupted-run.md).

Related: [Workflows reference](../reference/workflows.md#send-ada).
