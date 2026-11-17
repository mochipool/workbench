+++
id = "Xconfirm"
kind = "extension"
title = "Transaction status and waiting for confirmation"
status = "draft"
contexts = ["pool-operations", "chain-access"]
use_cases = ["QueryTxStatus", "WaitForConfirmation"]
depends_on = ["Ptx", "Cchain", "Clight"]
+++

# Xconfirm: transaction status and waiting for confirmation

This spec is not upstream behaviour: no upstream script reports whether a submitted transaction reached a block (they print the id and stop). It defines the status query `spo tx status` and the opt-in wait of the submitting commands, and what each may claim. Providers are those of [ADR 0006](../../docs/explanation/adr/0006-chain-access-providers.md); the port is `ports.TxStatusReader`, narrow in the sense of [ADR 0008](../../docs/explanation/adr/0008-capability-typed-ports.md).

Terms: a **provider** is a configured chain source (Koios, Blockfrost, the node socket). **Seen** means a provider states the transaction is in a block or in its mempool. **Not seen** is a provider's positive statement that it has no such transaction. **Unknown** is the lack of a usable answer.

## Interface

- **SPO-Xconfirm-IF-001** `spo tx status <txid> [--confirmations N]` asks every configured provider once and prints one line per provider (its source name and its statement: in a block with the block height, slot and confirmations the provider gave, in the mempool, not seen, or unknown with the reason), then one verdict line. `--confirmations` is the depth that counts as confirmed, default 1.
- **SPO-Xconfirm-IF-002** The Koios reader is `POST /tx_status` with `{"_tx_hashes":[<id>]}`. A row for the asked hash with a number is in a block with that many confirmations; a row with an explicit null is not seen; every other answer (failure, empty array, another hash, two rows, no member, a non-integer, a count above 100,000,000) is unknown. The request asks intermediaries not to cache (`Cache-Control: no-cache, no-store`). Koios has no mempool view here.
- **SPO-Xconfirm-IF-003** The Blockfrost reader is `GET /txs/{hash}`. A 404 whose body is the documented Blockfrost error object (a JSON object with `status_code` 404) is not seen; a 404 with any other body (a proxy's page, another code) is unknown. A 200 for the asked hash with a block height is in a block, with confirmations counted from `GET /blocks/latest` (the latest height minus the block height plus one) when that is readable; every other status, a failure, an answer for another hash or a computed depth above 100,000,000 is unknown. Both requests carry `Cache-Control: no-cache`. Blockfrost has no mempool view here.
- **SPO-Xconfirm-IF-004** The node reader looks up the transaction's own outputs by reference (the first N, N from the transaction when known, else 8): an output in the UTxO set is in a block, with no height or depth. Otherwise the local tx monitor says whether the mempool holds it. Otherwise, when the caller gave the transaction's inputs (it has no collateral), an input that is still unspent proves the transaction is not in a block, and with the mempool not holding it the reading is not seen. Every other case is unknown, with the reason (SPO-Xconfirm-INV-006).
- **SPO-Xconfirm-IF-005** Every command that submits in light or online mode takes `--wait`, `--wait-confirmations N` (default 1) and `--wait-timeout DURATION` (default 5m, at most 24h). The flags are registered by one helper shared with the chain flags, and the wait runs after the command's own work has finished, on every transaction the command submitted (SPO-Xconfirm-INV-005).

## Invariants

- **SPO-Xconfirm-INV-001** A reading is not seen only from a positive answer of a provider that is fresh and, for a node, synced. A failed request, an answer that cannot be read, a web provider whose tip is older than ten minutes against this machine's clock (or unreadable), and a node that is not synced are unknown; none of them is ever reported as not seen.
- **SPO-Xconfirm-INV-002** Providers are combined, never trusted singly. Confirmed is stated only when every configured provider says the transaction is in a block at the depth asked. When one provider has seen it and another has not, the output says they disagree and names each provider's answer. When one has seen it and the rest gave no answer, the verdict is partial, not confirmed. Not seen is stated only when every provider answered not seen; one silent provider makes it unknown.
- **SPO-Xconfirm-INV-003** Confirmations count blocks from the one that holds the transaction to the provider's tip, the holding block being one; a provider that says in a block and not how deep counts as depth 1 and satisfies a wanted depth of 1 or less only. A confirmation is never called final: the message states the depth reached and that a rollback is possible at low depth.
- **SPO-Xconfirm-INV-004** A wait never submits, rebuilds or resubmits anything. It polls with a pause of 5 seconds that grows by half each time to at most 30 seconds, never sleeps past its timeout, and stops at once when the context is cancelled (Ctrl-C). The requests of each poll end by the time left of the timeout plus 5 seconds, so a wait ends within 5 seconds of its timeout however slow a provider is.
- **SPO-Xconfirm-INV-005** A wait changes no local state. Whatever a command records on an accepted submission (the asset record, the offline queue entry, the audit log) is recorded before the wait starts and is not undone by a timeout, an expiry or a cancellation. Cancelling a wait does not cancel the transaction.
- **SPO-Xconfirm-INV-006** The node cannot prove absence from outputs: an output that was spent after the transaction was included is not in the UTxO set, so no unspent output looks the same as never included. The node reader therefore returns not seen only from an unspent input of the transaction (a transaction in a block has spent all its inputs) and never from outputs; a transaction with collateral is not judged this way, because one that failed phase 2 is in a block with its inputs unspent.

- **SPO-Xconfirm-INV-007** The id a wait asks about is computed from the bytes that were submitted, never taken from the provider's answer. A provider's answer that differs is an error naming both ids, and the submission is not waited for: no confirmed or expired statement is made about it. A submission whose id cannot be computed here is reported the same way. `offline execute` refuses the same mismatch as the other submitting commands, before it changes the queue.

## Outputs and exit codes

- **SPO-Xconfirm-OUT-001** `spo tx status` exits 0 when confirmed at the depth asked, 10 when seen but pending (in a mempool, or in a block not yet that deep), 11 when not seen by every provider, 12 when unknown or partial, 13 when the providers disagree, and 1 for any other failure (a bad id, no provider configured).
- **SPO-Xconfirm-OUT-002** A wait exits 0 when confirmed, 20 when the time ran out, 21 when the transaction expired, 22 when no provider answered for the whole wait, 23 when the providers disagreed at the end, and 130 when cancelled. The submission itself had succeeded in every case, and the output says so.
- **SPO-Xconfirm-OUT-003** A command that submitted several transactions waits for each in turn and prints every outcome. Its exit status is the worst, from mildest to worst: 0 confirmed, 21 expired, 20 timed out, 22 unknown, 23 disagree, 1 an id that could not be tied to the transaction, 130 cancelled. A cancellation ends the wait; the transactions not yet waited for are named with `spo tx status` as the way to check them.

## Preconditions and failures

- **SPO-Xconfirm-PRE-001** When the time runs out with the transaction not confirmed, the message says it may still be included and must not be built again from the same inputs until it has expired, and names `spo tx status <id>`.
- **SPO-Xconfirm-PRE-002** Expired is stated only when the transaction has a validity upper bound known to the command and the decision is made per provider: for every configured provider, in one poll, a tip read before that provider's status read is at or past the bound plus the slack (compared without overflow), and the same provider's status read after it is not seen. A provider without a tip, with an unreadable tip, with a tip short of the mark, or with any other answer means not expired. The slack is the freshness window of SPO-Xconfirm-INV-001 plus 5 minutes, in slots (900, counting 1 s per slot), so a provider that lags by as much as the window allows still cannot reach the mark early. The freshness check and the status read are separate requests, so behind a load-balanced address this assumes every server is within the slack of the chain; that is not checkable, and the message says so. A rollback deeper than the slack could also overturn the verdict. The condition must hold on two consecutive polls. The message says that "expired" rests on the providers' answers and on that assumption. It is the only outcome whose message says the transaction can no longer be included and that it is safe to build it again.
- **SPO-Xconfirm-PRE-003** When no provider gave a usable answer for the whole wait, the message says the status is unknown and does not say the transaction was or was not included.
- **SPO-Xconfirm-PRE-004** `--wait` is refused before any prompt, naming the missing capability (`tx-status`), when the mode has no provider: air-gap (offline) mode, where a transaction is queued and a later `offline execute` submits it.
- **SPO-Xconfirm-PRE-005** When a submission ends with an unknown outcome, the error also names `spo tx status <id>` when the id can be computed from the transaction, and says not to build it again from the same inputs first.

## Work modes

- **SPO-Xconfirm-MODE-001** Light and online mode: every configured provider is asked (in online mode the web providers named in `[provider] order` only, as for every other read). Offline mode has no provider, so neither the status command nor the wait exists there.

## Security

- **SPO-Xconfirm-SEC-001** Every string a provider chose (its reason text, its answer) is written through the terminal-safe escaper before it is printed. The confirmation text states only numbers this code computed and the provider's source name, escaped.

## Open questions

* Whether Koios' `num_confirmations` counts the block that holds the transaction. The Koios document says only "number of block confirmations"; the number is used as given, so a count that starts at zero makes the wait cautious by one block.
* Whether a recently submitted transaction gives a 404 from Blockfrost or a null from Koios while it is in the provider's mempool; both are read as not seen, which is true of the chain and says nothing of the mempool.
