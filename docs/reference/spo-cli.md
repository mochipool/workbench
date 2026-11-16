# spo CLI

This page lists every `spo` command and option that is wired. `spo` is the Go reference implementation in `spo/`. Commands not listed here do not exist yet.

Run it with `nix run --accept-flake-config .#spo -- <args>`. The packaged binary carries the release-set manifest; a binary built without it (`go build`) has no bundled genesis files and no toolchain checks.

## Synopsis

```
spo [-C DIR] [--passphrase-fd N | --upstream-layout] [--accept-rollback] COMMAND ...
```

## Global options

| Option | Meaning |
| --- | --- |
| `-C`, `--workspace DIR` | Workspace directory. Default: the current directory. |
| `--passphrase-fd N` | Read the workspace passphrase from inherited file descriptor `N` instead of prompting. The trailing newline is stripped. An empty value is refused. |
| `--upstream-layout` | Work on a plain directory in the upstream scripts' file layout. Signing keys are stored unsealed, as upstream stores them, and there is no passphrase. Refused when the directory holds `workspace.spo`. |
| `--accept-rollback` | Open a workspace file that is older than the state recorded for it (see [Rollback detection](#rollback-detection)). Never saved; a warning is printed whenever it is used. Use it once, after you restored an older backup on purpose. |

There is no passphrase flag and no passphrase environment variable. A passphrase is never taken from `argv` or the environment. Without `--passphrase-fd`, the passphrase is read from the terminal without echo; with no terminal the command fails and names `--passphrase-fd`.

Prompts, warnings and `note:` lines go to stderr; results go to stdout. After every successful open of the store, the notices the store produced (for example a recreated head file) are printed to stderr, each prefixed `note:`.

A command that needs a chain capability, a transfer file or a genesis checks for it when it starts, before it asks for the passphrase or anything else, and fails with one error listing everything it lacks and why. `spo capabilities` shows the same list. Locked memory: `spo` locks the pages that hold secrets. When the locked-memory limit is too low it exits with advice naming `ulimit -l` (`RLIMIT_MEMLOCK`).

## Workspace

A workspace is a directory with:

* `workspace.spo`: the sealed store. Every record, name and key is encrypted; see [ADR 0003](../explanation/adr/README.md).
* `workspace.spo.head`: the chain head recorded after every write, for rollback detection. Not secret; keep it beside `workspace.spo`.
* `spo.toml`: non-secret settings, mode `0600`. See [spo.toml](./spo-toml.md).
* `offlineTransfer.json` (offline mode only, made on the online machine): read by `wallet send`; see its `--transfer-file`.

Without `--upstream-layout`, every command that touches keys or records opens the sealed store.

## Commands

### `init`

```
spo init --network {mainnet,preprod,preview} [--mode {online,light,offline}]
         [--recovery-key-fd N] [--yes]
```

Creates the directory if needed, then `spo.toml` and `workspace.spo`. Refuses when either file exists. Default mode: `offline`.

* The passphrase is asked for twice without echo, or read once from `--passphrase-fd`. It must be at least 12 characters; an empty passphrase is refused. There is no other strength rule.
* The recovery key is shown once, with an instruction to write it down. The operator must then type back its last group (4 characters, case-insensitive; three tries).
* With `--recovery-key-fd N` (which requires `--passphrase-fd`), the key is written to descriptor `N` and neither shown nor confirmed.
* `--mode light` prints what Koios will learn (the pools, addresses and stake addresses queried, the transactions submitted, the requester's network address) and asks `[y/N]`. The default is no; nothing is created on no. `--yes` answers yes, and the statement is still printed. `--mode offline` and `--mode online` configure no provider.

### `store verify`

```
spo store verify [--backup FILE]
```

Opens the workspace (or `FILE`) read-only and checks every record's authentication and the audit chain. Writes nothing. Prints the chain head (sequence number and MAC, hex) and every notice. It does not need `--accept-rollback`.

Record the head somewhere other than the workspace directory. Replacing both `workspace.spo` and its head file by an older matching pair cannot be detected from the files; comparing with a recorded head can.

### `store backup`

```
spo store backup DEST
```

Writes a consistent copy of `workspace.spo` to `DEST` (must not exist, mode `0600`), then verifies the copy and prints its head. The copy opens with the passphrase and recovery key of the moment it was made; a later passphrase change or new recovery key does not reach it. It does not include `spo.toml`.

### `store restore`

```
spo store restore BACKUP [--force] [--allow-older] [--allow-other-workspace] [--network NAME]
```

Verifies `BACKUP` with its passphrase and installs it as `workspace.spo`, rewriting the head file from it, so the restored workspace opens normally.

| Option | Meaning |
| --- | --- |
| `--force` | Replace an existing workspace. |
| `--allow-older` | Accept a backup that is older than the workspace or has diverged from it. Without it such a restore is refused, because it discards every change made since. |
| `--allow-other-workspace` | Dangerous. Accept a backup of a different workspace; the current workspace and all it holds is lost. Prints a warning. Needs `--force`. |
| `--network NAME` | When the directory has no `spo.toml`, write one for `NAME` in mode `offline` (change it with `mode set`). Required in that case. |

### `store slots`

Lists key slots: kind (`passphrase` or `recovery`), id, and the key-derivation parameters of a passphrase slot. Nothing secret.

### `store passphrase change`

```
spo store passphrase change [--new-passphrase-fd N] [--recovery-key-fd N]
```

Replaces the passphrase. The new one is asked for twice, or read from `--new-passphrase-fd`; the 12-character minimum applies. This replaces the workspace key, so **the old recovery key no longer works**. A new recovery key is shown once with the same type-back check as `init`, or written to `--recovery-key-fd` (which requires `--passphrase-fd`). If the type-back fails the rekey has already happened; the error says so. Backups made earlier keep the old passphrase and old recovery key.

### `store recovery-key new`

```
spo store recovery-key new [--recovery-key-fd N]
```

Opens with the current passphrase, replaces the workspace key and shows the new recovery key once (type-back check). **The old recovery key no longer works**: a recovery key cannot be added beside another without leaving the old one able to open the workspace, so making one always revokes the old. There is no `--remove-old`, and no command that adds a recovery key without revoking. `--recovery-key-fd` requires `--passphrase-fd`.

### `store recover`

```
spo store recover [--recovery-key-in-fd N] [--new-passphrase-fd N] [--recovery-key-fd N]
```

For a lost passphrase. Reads the recovery key without echo, or from `--recovery-key-in-fd`; the printed grouped form is accepted, in any case, with or without dashes and spaces. Then requires a new passphrase (asked twice, or `--new-passphrase-fd`; 12-character minimum), replaces the workspace key and shows the new recovery key once. The key just used no longer works. This is the only command that reads a recovery key. `--passphrase-fd` is refused here. `--recovery-key-fd` requires both `--recovery-key-in-fd` and `--new-passphrase-fd`.

### Rollback detection

The store writes `workspace.spo.head` (sequence number and MAC of the newest audit row) after every write. Opening a file whose chain does not contain that head fails: the file is older than its recorded state, which is what an old copy put back looks like. The error says so and names `--accept-rollback`. A missing head file is recreated with a `note:`. Errors from the store are translated into one sentence that says what happened and what to do:

| Situation | Advice |
| --- | --- |
| File older than its head (`workspace.spo.head`) | Restore your newest backup, or if the older file is deliberate, run once with `--accept-rollback`. |
| Head file of another workspace | Restore the right pair of files, or `--accept-rollback` if the swap was deliberate. |
| Workspace open elsewhere or being replaced | Wait for the other `spo` process. |
| Restore of an older backup | Add `--allow-older`. |
| Restore of another workspace's backup | `--allow-other-workspace` with `--force`; destroys the current workspace. |
| Wrong recovery key (maybe a revoked one) | Use the newest recovery key. |

### `provider set koios`

```
spo provider set koios [--url URL] [--yes]
```

Names Koios as the chain provider: writes `[koios]` to `spo.toml` with the network's public endpoint, or `URL`. Prints the privacy statement and asks `[y/N]` first (default no). A provider is never configured without this step.

### `provider token set koios`, `provider token clear koios`

```
spo provider token set koios [--token-fd N]
spo provider token clear koios
```

Store or remove the Koios API token as a secret record in the sealed workspace. `set` reads the token without echo or from `--token-fd`; with neither a terminal nor `--token-fd` it fails with "no terminal to ask for the token on". The token is not written to `spo.toml` and is never printed. In light mode it is loaded from the store when a command starts and given to the Koios client.

### `mode set`

```
spo mode set {online,light,offline}
```

Changes `mode` in `spo.toml`. `light` is refused while there is no `[koios]` section.

### `capabilities`

Prints what the environment of this workspace's configuration provides, from the same `Env` the commands use. It opens no store and uses no network.

* **Chain capabilities**: for each of `tip`, `sync-check`, `opcert-counter`, `protocol-parameters`, `utxo`, `reward-account`, `pool-state`, `drep-state`, `reward-account-crosscheck`, `tx-submit`, `tx-queue`, the provider that supplies it (and its endpoint), or under **Not available** the reason and the remedy, for example "offline mode has no transaction submitter; queue to a transfer file instead" or "no chain provider is configured: spo provider set koios".
* **Local**: clock, genesis, key generation (`kes-keygen`, `vrf-keygen`, `cold-keygen`, `payment-keygen`, `stake-keygen`), `mnemonic-generation`, `wallet-derivation`, `address-building`, address inspection, minimum output, fee estimation, transaction body and assembly, `certificate-building` and `certificate-decoding`.
* **Signers**: each signer with its profile (role, then the operations it can do).

Offline mode lists `utxo`, `protocol-parameters`, `tx-queue`, `reward-account` and `drep-state` only when the transfer file (`offlineTransfer.json` in the workspace directory) exists. Light mode takes the protocol parameters from the network's hosted light-mode parameters file, as upstream does, and everything else from Koios. Online mode names the missing cardano-node socket adapter.

### `pool keys generate POOL`

Generates the pool's cold key pair and its operational certificate issue counter (at 0). Prints the pool id as hex and bech32. The signing key is stored in the workspace and never printed. Needs: `cold-keygen`. Refused when any cold artefact of the pool exists.

### `pool vrf generate POOL`

Generates the pool's VRF key pair. Prints the verification key; the signing key is stored and never printed. Needs: `vrf-keygen`. Refused when a VRF key of the pool exists.

### `pool kes generate POOL`

Generates the KES key pair for the next operational certificate. Prints the verification key. The signing key is stored in the workspace and never printed.

### `pool opcert new-counter POOL [--value N]`

Creates the issue counter of a pool that has none, at `N` (default 0).

### `pool opcert issue POOL`

```
spo pool opcert issue POOL [--counter N] [--offline]
     [--shelley-genesis FILE] [--byron-genesis FILE] [--byron-to-shelley-epochs N]
```

Issues the operational certificate for the waiting KES key. Needs: signers, clock, genesis, tip, opcert-counter. The environment follows the mode in `spo.toml`:

| Mode | Chain check |
| --- | --- |
| `offline` | None. The current slot comes from the clock and the Shelley genesis; the report says the counter was not checked. |
| `light` | Koios supplies the tip and the counter the chain has seen. A counter the chain would refuse is refused with the required value. A failed or unreadable answer stops the command; it is never read as "no blocks". The API token is loaded from the store when one is stored. |
| `online` | Not built (no node-socket adapter). The command says so. |

| Option | Meaning |
| --- | --- |
| `--counter N` | Issue with `N` instead of the stored counter. |
| `--offline` | Override the mode for this invocation: no chain check. Required when the directory has no `spo.toml`. |
| `--shelley-genesis FILE` | Override the bundled Shelley genesis. Required with a binary that has no manifest. |
| `--byron-genesis FILE` | Override the bundled Byron genesis. Needed for the offline slot on a network with Byron epochs when none is bundled. |
| `--byron-to-shelley-epochs N` | Override the network preset (mainnet 208, preprod 4, preview 0). |

### `wallet new`

```
spo wallet new NAME [--stake] [--mnemonic | --mnemonic-in-fd N] [--account N] [--index N]
```

Creates a wallet in the workspace. Signing keys and any mnemonic are never printed.

| Form | Creates | Needs |
|---|---|---|
| `NAME` | a random payment key and its enterprise address | `payment-keygen`, `address-building` |
| `NAME --stake` | random payment and stake keys, the base address and the stake address | adds `stake-keygen` |
| `NAME --mnemonic` | the same, derived (CIP-1852) from a freshly generated 24-word phrase | `mnemonic-generation`, `wallet-derivation`, `address-building` |
| `NAME --mnemonic-in-fd N` | the same, derived from the phrase read from file descriptor N (a trailing newline is dropped; case and spacing are normalised) | `wallet-derivation`, `address-building` |

`--mnemonic` and `--mnemonic-in-fd` imply `--stake` and are mutually exclusive. `--account` and `--index` (0 to 2147483647) select the derivation path `1852H/1815H/ACCOUNTH/{0,2}/INDEX` and are refused without one of them. The phrase is never read from the command line or the environment. A generated phrase is stored sealed in the workspace and is not shown; the command that displays it does not exist yet (the audited export use case is not built), so for now such a wallet is recoverable only from a workspace backup. All flag combinations are checked, and the needs stated, before the workspace is opened. An existing wallet of that name is not overwritten. The network is the workspace's (`mainnet` gives `addr1...`, others `addr_test1...`).

### `wallet send`

```
spo wallet send FROM TO AMOUNT [--message TEXT]... [--yes] [--transfer-file PATH]
     [--offline] [--shelley-genesis FILE] [--byron-genesis FILE] [--byron-to-shelley-epochs N]
```

Builds, signs and sends a payment (upstream `01_sendLovelaces`). `FROM` names a stored wallet (address and signing key in the workspace). `TO` is a stored address name or a payment address. `AMOUNT` is a number of lovelace, `ALL` or `ALLFUNDS` (everything), or `MIN` (the least the destination can take). Every UTxO of the source is spent, every asset moves with it, and the change returns to the source. Requires `spo.toml`.

Needs: signers, genesis, tip, protocol-parameters, utxo, the ledger capabilities, and one of `tx-submit` or `tx-queue`. A missing need is reported, all at once, before the passphrase is asked.

The summary (source, destination, outputs with assets, fee, valid-until slot, change, message, size, tx id, route) is shown and `Sign and queue/submit this transaction? [y/N]` asked; the default is No, and a decline signs, submits and queues nothing. With no terminal and no `--yes` the command refuses. `--yes` skips the question; the summary is then printed after signing, because the use case produces it only for the question. Nothing printed contains key material.

| Mode | What happens |
| --- | --- |
| `offline` | UTxOs and protocol parameters come from the transfer file; the signed transaction is appended to it for an online machine to submit. The output names the tx id and the file. |
| `light` | The transaction is submitted through Koios; the output names the tx id. |
| `online` | Not built. |

| Option | Meaning |
| --- | --- |
| `--message TEXT` | CIP-20 message line, at most 64 bytes. Repeatable. |
| `--yes` | Approve without asking. |
| `--transfer-file PATH` | The offline transfer file. Default: `offlineTransfer.json` in the workspace directory. It must exist (made by `01_workOffline.sh new` on the online machine). |
| `--offline`, genesis options | As for `pool opcert issue`. The offline slot needs a Shelley genesis. |

### `wallet claim-rewards`

```
spo wallet claim-rewards STAKE DESTINATION [--payer NAME] [--message TEXT]... [--yes] [--transfer-file PATH]
     [--offline] [--shelley-genesis FILE] [--byron-genesis FILE] [--byron-to-shelley-epochs N]
```

Withdraws the whole reward balance of a stored stake account to `DESTINATION` (a stored address name or an address), upstream `01_claimRewards`. The fee is paid by `--payer`; when it is not given the destination pays, if it is a stored address. The stake key and the payment key sign. The balance is read once at the start; a stale one only makes the ledger reject the transaction, so one source is enough and there are no policy flags. Needs: the `wallet send` needs and `reward-account`. Confirmation, `--yes`, `--message`, `--transfer-file` and the output are as for `wallet send`; the summary adds the account and the withdrawal.

Offline, the balance comes from the transfer file, which must hold the stake address (`01_workOffline.sh add`); an address it does not hold is an unknown answer and the command stops.

### Stake commands: shared rules

Every transaction command of this group shares: `--message TEXT` (repeatable), `--yes`, `--transfer-file PATH`, `--offline`, the genesis options, and the confirmation of `wallet send` (default No; no terminal and no `--yes` refuses). Needs, checked before the passphrase is asked: the `wallet send` needs, plus those named under each command. The summary names the account, the stake address, the payer, the certificates or withdrawal, the deposit paid and refunded, the fee, the sources the checks rest on, a `WARNING` line when a read rested on one source, and a `NOT CHECKED` line for each check skipped. With `--yes` the summary is printed after signing and lacks the stake address and the certificate lines. After success the output names the tx id and the file (queued) or the provider (submitted), then each artefact stored (`NAME.staking.cert`, `NAME.deleg.cert`, `NAME.vote-deleg.cert`, `NAME.staking.dereg-cert`). Key material is never printed.

Two policy flags exist, never on by default, and a mode never implies them. A refusal that one of them would lift names it and what it gives up.

| Flag | Gives up |
| --- | --- |
| `--allow-unverified` | The chain checks that cannot be made: the registration state of the stake address (in offline mode an address the transfer file does not hold is an unknown answer), the pool registration (no reader in any mode today), the DRep registration. A wrong answer only makes the ledger reject the transaction. The summary lists each skipped check. |
| `--single-source` | The corroboration of a read that rests on one source: the reward balance and deposit before a deregistration, the pool registration. A false answer from one provider can cost the deposit or the rewards. The summary says the read rested on one source. |

The second reward-account source (`reward-account-crosscheck`) exists in no mode today, so `stake deregister` always needs `--single-source` and `stake delegate` needs it as soon as a pool reader exists.

### `stake register`

```
spo stake register STAKE PAYER [--allow-unverified] [common options]
```

Registers the stake address of wallet `STAKE`; `PAYER` names the stored address that pays the fee and the key deposit of the protocol parameters (upstream `03b`). Needs also: `certificate-building`. `reward-account` is used when present. The certificate is stored as `STAKE.staking.cert` only after the transaction was queued or submitted, so a declined or refused run stores nothing.

### `stake delegation-cert`, `stake delegate`

```
spo stake delegation-cert POOL DELEGATOR
spo stake delegate DELEGATOR POOL [--payer NAME] [--allow-unverified] [--single-source] [common options]
spo stake delegate DELEGATOR --stored-cert [--payer NAME] [...]
```

`delegation-cert` (upstream `05b`) stores `DELEGATOR.deleg.cert` for a pool id (hex or `pool1...`) or a stored pool name; it needs only `certificate-building` and sends nothing. `delegate` makes that certificate and registers it (upstream `06`, no deposit); `--stored-cert` skips the first step and uses the stored file, because the registration reads the certificate from the store. `--payer` defaults to `DELEGATOR.payment`, the address `wallet new --stake` makes. Needs also: `certificate-building` (not with `--stored-cert`), `certificate-decoding`, `address-building`. The pool registration is a read where a false answer is costly: it needs `--single-source`, or `--allow-unverified` when no pool reader exists.

### `stake vote-delegation-cert`, `stake vote-delegate`

```
spo stake vote-delegation-cert TARGET DELEGATOR
spo stake vote-delegate DELEGATOR TARGET [--payer NAME] [--allow-unverified] [common options]
spo stake vote-delegate DELEGATOR --stored-cert [...]
```

As above for the vote delegation (upstream `22a`, `22b`). `TARGET` is a DRep id, a stored DRep name, `always-abstain` or `always-no-confidence`; the last two need no DRep check. A DRep target needs a DRep reader (offline: the transfer file's `drep` entries) or `--allow-unverified`.

### `stake deregister`

```
spo stake deregister STAKE PAYER [--single-source] [common options]
```

Makes the deregistration certificate carrying the deposit the chain holds (upstream `08a`) and registers it (`08b`); the deposit is refunded to `PAYER`. The account must be registered, hold no rewards and have no open governance deposit. Needs also: `certificate-building`, `certificate-decoding`, `reward-account`. Stores `STAKE.staking.dereg-cert`; a later decline leaves that file in the workspace.

### `stake status`

```
spo stake status STAKE|STAKE-ADDRESS [--transfer-file PATH] [--offline] [genesis options]
```

Prints the state of a stake address (upstream `03c`): registered, deposit, rewards, pool (with name and ticker when a pool reader exists), vote delegation, governance deposits, each followed by `[source]`. An unknown answer is an error, never "not registered". An address that is not registered is printed and the command then exits unsuccessfully, as `03c` does. Needs: `address-inspection`, `reward-account`.

### `toolchain check`

Locates each external tool in the manifest and applies the version gates. Exit status is non-zero if any fails.

### `version`

Prints the binary version and release set.

## Output rules

No command prints a passphrase, a token or a signing key. The recovery key appears only in the one-time display of `init`, `store passphrase change`, `store recovery-key new` and `store recover` (or on the descriptor given), and is read only by `store recover`. Error messages never include them.

## Exit status

`0` on success, `1` on any error. The message is on stderr, prefixed `spo:`.
