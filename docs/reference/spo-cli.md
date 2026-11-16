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
* `offlineTransfer.json` (offline mode only, made on the online machine with `offline new` and `offline add`): read by `wallet send` and `address`, and managed by the `offline` commands; see `--transfer-file`.
* `extracted/` (created by `offline extract`): the files carried in the transfer file.

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

* **Chain capabilities**: for each of `tip`, `sync-check`, `opcert-counter`, `protocol-parameters`, `utxo`, `reward-account`, `pool-state`, `drep-state`, `reward-account-crosscheck`, `tx-submit`, `tx-queue`, and the governance readers `committee-state`, `governance-actions`, `constitution`, `last-enacted-action`, `stake-distribution`, `epoch`, `voting-summary`, `drep-state-crosscheck`, `ada-handle` and `poll-question`, the provider that supplies it (and its endpoint), or under **Not available** the reason and the remedy, for example "offline mode has no transaction submitter; queue to a transfer file instead" or "no chain provider is configured: spo provider set koios".
* **Local**: clock, genesis, key generation (`kes-keygen`, `vrf-keygen`, `cold-keygen`, `payment-keygen`, `stake-keygen`), `mnemonic-generation`, `wallet-derivation`, `address-building`, address inspection, minimum output, fee estimation, transaction body and assembly, `certificate-building` and `certificate-decoding`, and for the Calidus and Catalyst commands `calidus-keygen`, `voting-keygen` and `registration-signing` (always) and `calidus-registrations` (never: no provider reads them yet), and for the governance commands `drep-keygen`, `committee-cold-keygen`, `committee-hot-keygen`, `governance-derivation`, `vote-file`, `action-file` (always), `anchor-fetch` (light) and `anchor-verification` (never: no verifier is built), and for the pool commands `pool-certificate-building`, `pool-certificate-decoding`, `metadata-hash`, `tx-id` and `tx-view` (always), for the extra parameters and native assets `metadata-file`, `message-encryption` and `policy-id` (always), for the workspace commands `verification-key-derivation` (always) and `key-encryption` (upstream's gpg envelope: only where the binary has a toolchain manifest with `gpg`; needed only for upstream's encrypted keys), `transfer-file` (always: the bundle at `--transfer-file`) and `extract-sink` (always), `era` (offline with a transfer file; light, from the Koios tip), `transfer-attach` (offline, with a transfer file), `metadata-fetch` (light) and `ticker-protection` (never: see [Pool registration](#pool-registration-and-retirement)), `bls-keygen` (always) and `hardware-wallet` (only where the binary has a toolchain manifest that provides `cardano-hw-cli`, a network with a magic, and a workspace; whether a device is connected is not probed: `capabilities` never starts the tool, see [Hardware wallets](#hardware-wallets)). `ada-handle` is present in light mode and absent offline with the reason; `poll-question` is present in light mode (Koios) only.
* **Signers**: each signer with its profile (role, then the operations it can do).

Offline mode lists `utxo`, `protocol-parameters`, `tx-queue`, `reward-account` and `drep-state` only when the transfer file (`offlineTransfer.json` in the workspace directory) exists. Light mode takes the protocol parameters from the network's hosted light-mode parameters file, as upstream does, and everything else from Koios. Online mode names the missing cardano-node socket adapter. The Koios adapter reads the committee (`GET /committee_info`), the open governance actions with their votes (`/proposal_list`, `/proposal_votes`), the epoch and era (`/tip`) and the voting summary of an action (`/proposal_voting_summary`); the constitution and the last enacted action ids come from the hosted light-mode parameters document, as upstream's light mode takes them. Every field follows the three-valued rule: an empty, failed or uninterpretable answer is unknown, never none. No adapter reads the DRep and pool stake distribution (upstream's light mode does not; `stake-distribution` is absent in every mode, with the reason) or a second DRep source (`drep-state-crosscheck`). Offline mode has none of the governance readers. Readers are picked up by type assertion when an adapter gains the interface.

### `pool keys generate POOL`

Generates the pool's cold key pair and its operational certificate issue counter (at 0). Prints the pool id as hex and bech32. The signing key is stored in the workspace and never printed. Needs: `cold-keygen`. Refused when any cold artefact of the pool exists. `--hardware [--index N]` makes the key on a hardware wallet instead (see [Hardware wallets](#hardware-wallets)); it needs `hardware-wallet` and not `cold-keygen`.

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

### `pool opcert check [POOL] [--next] [--opcert-file FILE] [--number N]`

```
spo pool opcert check [POOL] [--next] [--opcert-file FILE] [--number N]
     [--offline] [--shelley-genesis FILE] [--byron-genesis FILE] [--byron-to-shelley-epochs N]
```

Upstream `04e`. Checks the counter and the KES period of an operational certificate: the newest stored one of `POOL` (`--number N` picks another), or the file given with `--opcert-file` (no pool name then). Without `--next` the counter in the certificate must equal the counter of the pool's last block on the chain (0 and no block yet passes); with `--next` it must be that counter plus one. The KES period of the tip must lie inside the certificate's validity. Needs: tip, genesis, opcert-counter.

The output lists the pool, the counter in the certificate, the counter on the chain with its source, the counter the next certificate needs, the KES window, and a verdict line:

| Verdict | Meaning |
| --- | --- |
| `VERDICT: OK` | Both checks passed. |
| `VERDICT: FALSE` | A check failed; each reason is listed. |
| `VERDICT: UNKNOWN` | The chain's counter is not known and no check failed: no connection, a pool the provider does not know (an unregistered pool and a wrong network look alike), or offline mode. The reason is printed. |

**Exit status: `0` only for OK. FALSE and UNKNOWN both exit `1`.** Upstream `04e` exits `0` after a FALSE verdict. This is a deliberate change: a script that tests the status must not read a FALSE or UNKNOWN verdict as success. An unknown counter together with a KES period out of range is FALSE.

### `pool opcert counter POOL|POOL-ID`

Shows the counter of the pool's last block on the chain (with its source), the number the next certificate must carry, and the registered ticker and name when the provider states them. `POOL` is a stored pool name (its `.pool.id-bech`), or a pool id in bech32 or hex. Needs: opcert-counter. The exit status is `1` when the chain's answer is not known.

### `wallet new`

```
spo wallet new NAME [--stake] [--mnemonic | --mnemonic-in-fd N] [--account N] [--index N]
               [--hardware [--multisig] [--hybrid]]
```

Creates a wallet in the workspace. Signing keys and any mnemonic are never printed.

| Form | Creates | Needs |
|---|---|---|
| `NAME` | a random payment key and its enterprise address | `payment-keygen`, `address-building` |
| `NAME --stake` | random payment and stake keys, the base address and the stake address | adds `stake-keygen` |
| `NAME --mnemonic` | the same, derived (CIP-1852) from a freshly generated 24-word phrase | `mnemonic-generation`, `wallet-derivation`, `address-building` |
| `NAME --mnemonic-in-fd N` | the same, derived from the phrase read from file descriptor N (a trailing newline is dropped; case and spacing are normalised) | `wallet-derivation`, `address-building` |
| `NAME --hardware` | the payment key on a hardware wallet (a hardware signing file is stored, never a private key); with `--stake` the stake key too, or with `--hybrid` a stake key from the workspace | `hardware-wallet`, `address-building` (`stake-keygen` with `--hybrid`) |

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
| extra parameters | `--metadata-file`, `--encrypt-messages`, `--message-passphrase-fd`, `--utxo-limit`, `--only-utxo-with-asset`, `--skip-utxo-with-asset`, `--input`: see [Extra parameters](#extra-parameters). |

### `wallet claim-rewards`

```
spo wallet claim-rewards STAKE DESTINATION [--payer NAME] [--message TEXT]... [--metadata-file FILE]...
     [--metadata-record NAME]... [--encrypt-messages] [--yes] [--transfer-file PATH]
     [--offline] [--shelley-genesis FILE] [--byron-genesis FILE] [--byron-to-shelley-epochs N]
```

Withdraws the whole reward balance of a stored stake account to `DESTINATION` (a stored address name or an address), upstream `01_claimRewards`. The fee is paid by `--payer`; when it is not given the destination pays, if it is a stored address. The stake key and the payment key sign. The balance is read once at the start; a stale one only makes the ledger reject the transaction, so one source is enough and there are no policy flags. Needs: the `wallet send` needs and `reward-account`. Confirmation, `--yes`, `--message`, `--transfer-file` and the output are as for `wallet send`; the summary adds the account and the withdrawal. The message and metadata extras (`--metadata-file`, `--metadata-record`, `--encrypt-messages`, `--message-passphrase-fd`) are taken as by the other certificate commands; the UTxO flags are not.

Offline, the balance comes from the transfer file, which must hold the stake address (`01_workOffline.sh add`); an address it does not hold is an unknown answer and the command stops.

### Extra parameters

Upstream's transaction scripts take free-form words after their arguments (`msg:`, `enc:`, `pass:`, a metadata file name, `utxolimit:`, `onlyutxowithasset:`, `skiputxowithasset:`, a `txhash#ix` list). Here they are flags, one surface for every command that takes them. Each flag is turned into the equivalent upstream word and read by the same grammar (`txparam.Parse`, with the acceptance row of the command), so a refusal is the grammar's: a metadata file that is not `.json` or `.cbor`, an `--input` that is not `TXHASH#INDEX`, a `--utxo-limit` that is not a whole number above zero, an asset filter that is not a policy id (with or without a hex asset name), a message line over 64 bytes. These are refused before the workspace is opened and before any prompt.

| Flag | Meaning | Where |
| --- | --- | --- |
| `--message TEXT` | One CIP-20 line, at most 64 bytes, kept as typed (a `|` is part of the line). Repeatable. | every transaction command |
| `--metadata-file FILE` | Attach a `.json` or `.cbor` metadata file as further labels of the transaction's metadata, in command-line order. Read in place, never changed. Repeatable. Needs `metadata-file`. | every transaction command |
| `--metadata-record NAME` | Attach a registration record of the workspace as metadata, by the name `pool calidus register-metadata` or `catalyst register` printed (`NAME.calidus-registration.json` or `NAME.vote-registration.cbor`; the extension gives the format). The record is read through the workspace and no file is written. Repeatable. Needs `metadata-file`. | every transaction command |
| `--encrypt-messages` | CIP-83 `basic` encryption of the `--message` lines. Without a message it has no effect. Needs `message-encryption`. | every transaction command |
| `--message-passphrase-fd N` | The encryption passphrase, read from this inherited descriptor. Without it the passphrase is asked for without echo, twice; an empty entry means the CIP-83 default `cardano`. There is no flag, argument or variable that carries the passphrase, and it is never printed or stored. | with `--encrypt-messages` |
| `--utxo-limit N` | Spend at most `N` UTxOs of the source. | `wallet send`, `wallet send-assets` |
| `--only-utxo-with-asset ID` | Spend only UTxOs that hold the asset (a policy id, or a policy id followed by the asset name in hex). Repeatable. | `wallet send`, `wallet send-assets` |
| `--skip-utxo-with-asset ID` | Never spend UTxOs that hold the asset. Repeatable. | `wallet send`, `wallet send-assets` |
| `--input TXHASH#IX` | Spend exactly these UTxOs. Repeatable. | `wallet send`, `wallet send-assets`, `asset mint`, `asset burn` |

"Every transaction command" is `wallet send`, `wallet send-assets`, `asset mint`, `asset burn`, `stake register`, `stake delegate`, `stake vote-delegate`, `stake deregister`, `pool register`, `pool retire`, `drep register` (also an update), `drep retire`, `committee authorize`, `committee resign`, `vote submit` and `action submit`. `wallet claim-rewards` is one of the certificate-type commands here: it takes the message and metadata extras and not the UTxO flags. The certificate commands do not take the UTxO flags (upstream ignores them there). A pool registration whose witness collection is already open refuses any extra, as it refuses `--message`.

### `wallet send-assets`

```
spo wallet send-assets FROM TO ASSET[=AMOUNT]... [--lovelace N] [--keep-policy POLICY-ID]... [--sum-duplicates]
     [--message TEXT]... [--yes] [--transfer-file PATH] [--offline] [genesis options] [extra parameters]
```

Sends native assets with the lovelace they need (upstream `01_sendAssets`). Each `ASSET[=AMOUNT]` is one selection: `POLICY.NAME=100`, `POLICYHEX+NAMEHEX=100`, `asset1...=100` (fingerprint), `POLICY.PREFIX*=ALL` or `POLICYHEX+PREFIX*=ALL` (a bulk selection needs `ALL`), `NAME.asset=100` (the record of `asset mint`), or the keywords `ALLASSETS` and `FORCEADA`. An amount is a positive number or `ALL`. The words are read by the domain's selection grammar (`assets.ParseSelections`), so its refusals apply. An asset named twice is refused unless `--sum-duplicates`. `--lovelace N` sends at least that much with the assets (raised to the destination's minimum); `--keep-policy` is for `ALLASSETS`. Needs, confirmation, modes and output are those of `wallet send`; the summary shows each asset of each output, and the output lists what was sent.

### Stake commands: shared rules

Every transaction command of this group shares: `--message TEXT` (repeatable), `--yes`, `--transfer-file PATH`, `--offline`, the genesis options, and the confirmation of `wallet send` (default No; no terminal and no `--yes` refuses). Needs, checked before the passphrase is asked: the `wallet send` needs, plus those named under each command. The summary names the account, the stake address, the payer, the certificates or withdrawal, the deposit paid and refunded, the fee, the sources the checks rest on, a `WARNING` line when a read rested on one source, and a `NOT CHECKED` line for each check skipped. With `--yes` the summary is printed after signing and lacks the stake address and the certificate lines. After success the output names the tx id and the file (queued) or the provider (submitted), then each artefact stored (`NAME.staking.cert`, `NAME.deleg.cert`, `NAME.vote-deleg.cert`, `NAME.staking.dereg-cert`). Key material is never printed.

Two policy flags exist, never on by default, and a mode never implies them. A refusal that one of them would lift names it and what it gives up.

| Flag | Gives up |
| --- | --- |
| `--allow-unverified` | The chain checks that cannot be made: the registration state of the stake address (in offline mode an address the transfer file does not hold is an unknown answer), the pool registration (light mode reads it from Koios; offline has no reader unless the transfer file holds pool state), the DRep registration. A wrong answer only makes the ledger reject the transaction. The summary lists each skipped check. |
| `--single-source` | The corroboration of a read that rests on one source: the reward balance and deposit before a deregistration, the pool registration. A false answer from one provider can cost the deposit or the rewards. The summary says the read rested on one source. |

The second reward-account source (`reward-account-crosscheck`) exists in no mode today, so `stake deregister` always needs `--single-source`, and so do `stake delegate` and `pool register` whenever a pool reader exists (light mode).

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

## Pool registration and retirement

The pool commands are upstream `05a`, `05c`, `05d` (the importing side), `05e`, `07a` and `07b`. They work on the descriptor `POOL.pool.json` kept in the workspace. The descriptor holds a pool's operator fields (the ones you edit) and what the commands record (ids, metadata hash, certificate and registration records, the open witness collection, the registration protection key).

### `pool descriptor new`, `show`, `set`

```
spo pool descriptor new POOL [--owner NAME[:WITNESS]]... [--reward NAME] [--pledge LOVELACE] [--cost LOVELACE]
    [--margin 0.05] [--relay TYPE:ENTRY:PORT]... [--meta-name S] [--meta-description S] [--meta-ticker S]
    [--meta-homepage URL] [--meta-url URL] [--extended-meta-url URL]
spo pool descriptor show POOL
spo pool descriptor set POOL KEY=VALUE...
```

`new` writes the template of upstream `05a` (SPO-05a-IF-003), in the upstream field order, with the operator fields from the flags. A field you do not give keeps a `CHANGE-ME` placeholder (owner, reward account, relay, metadata) or the template default (pledge `100000000000`, cost `10000000000`, margin `0.10`); the output lists both. It refuses to overwrite a descriptor. `--owner` is `NAME` or `NAME:WITNESS`; the witness is `local` (this workspace signs) unless you give another word, conventionally `external`, which makes that owner's stake key sign elsewhere. `--relay` is `IP:ADDRESS:PORT`, `IP6:ADDRESS:PORT`, `DNS:NAME:PORT` or `SRV:NAME` (no port).

`show` prints the descriptor without `regProtectionKey` (it says on stderr that the key is set). `set` changes the operator fields `poolOwner` (`NAME[:WITNESS],...`), `poolRewards`, `poolPledge`, `poolCost`, `poolMargin`, `poolRelays` (`TYPE:ENTRY:PORT,...`), `poolMetaName`, `poolMetaDescription`, `poolMetaTicker`, `poolMetaHomepage`, `poolMetaUrl`, `poolExtendedMetaUrl`. Each value is validated as certificate generation validates it, and once no placeholder is left the whole descriptor is checked. Fields the commands write are refused, and so is any change while a witness collection is open. A change after the certificate was generated is reported: generate the certificate again.

### `pool cert generate`

```
spo pool cert generate POOL [--raise-cost] [--accept-ticker] [--protection-key-fd N] [--transfer-file PATH] [--offline] [genesis options]
spo pool metadata show POOL [--extended]
```

Checks the descriptor, then in one store transaction writes the metadata, the pool id files and `POOL.pool.cert`; a refusal writes nothing. The descriptor must hold no `CHANGE-ME` placeholder. The two prompts of `05a` are flags, both off: `--raise-cost` raises `poolCost` to the protocol minimum, `--accept-ticker` accepts the ticker with disallowed characters replaced by `_`. The refusal names the flag and the figures. `--protection-key-fd N` reads the registration protection key from an inherited descriptor (never from argv or the environment); it is recorded in the descriptor for the offline entry, never sent anywhere and never printed. `metadata show` prints the public `POOL.metadata.json` (or the extended one) so you can publish it at `poolMetaUrl`. Needs: `protocol-parameters`, `clock`, `pool-certificate-building`, `metadata-hash`.

### `pool register`

```
spo pool register POOL PAYER [--type REG|REREG] [--allow-unverified] [--single-source] [--allow-pending]
    [--message TEXT]... [--transfer-file PATH] [--offline] [genesis options]
```

Builds one transaction with the pool certificate and the owners' delegation certificates, collects one witness per signer (the cold key, `PAYER`, every owner), and sends it (light) or queues it (offline). `PAYER` names the stored address that pays the fee and, for a first registration, the pool deposit. Needs: the `wallet send` needs, `pool-certificate-decoding`, `certificate-decoding`, `tx-id`, `metadata-hash`, `clock`.

**There is no `--yes`.** The flag exists only to be refused, with the reason, before anything is read. You are asked twice: before the body is built and the witnesses collected (a decline stores nothing), and again before the transaction goes out. The default is No. Both summaries show the registration type (first registration, which pays the deposit, or re-registration), the pool id, pledge, cost, margin, reward account, owners, relays, metadata URL and hash, the deposit, the fee, the TTL, who holds each signature (this workspace, hardware wallet, signs elsewhere with the party, missing or signed), the sources the checks rest on and each check not made. No key and no protection key is printed.

The type is decided from the chain when a pool reader exists (light mode) and from the descriptor otherwise; `--type` forces it. A chain check that cannot be made refuses unless `--allow-unverified`; a registration state that rests on one source (`reward-account-crosscheck` exists in no mode) refuses unless `--single-source`. In light mode the published metadata at `poolMetaUrl` is downloaded and its hash compared with `poolMetaHash` (https only, or http to the loopback; at most 3 redirects, all https; 20 seconds in all; at most 512 bytes; no credentials, cookies or proxy; the User-Agent is `spo`); offline it is not, and the summary says so. The ticker-protection lookup is not built (hazard H6: upstream sends the ticker and the protection key to a third-party URL): `ticker-protection` is absent in every mode with the reason "ticker protection lookup is not built; it will be opt-in and will never send the protection key", and the use case runs without it. After a queued registration the metadata files are attached to the transfer file.

`--allow-pending` leaves the slots whose signer is not in this workspace empty. The collection stays open, a witness transfer file `POOL_SLOT_ID.witness` is written to the workspace for each open slot, the output lists each open slot with its role and holder, and the command exits 0 saying `waiting for N signature(s)`. Without the flag a registration that cannot be assembled yet is an error. Import each signed file with `pool witness import`, then run `pool register` again: the stored collection is final, so `--type` and `--message` are refused while it is open, and one confirmation remains.

### `pool witness import`, `pool witness status`, `info`, `sign`, `clear`

```
spo pool witness import POOL FILE [--overwrite] [--offline] [genesis options]
spo pool witness status POOL [--offline] [genesis options]
spo pool witness info POOL [--offline] [genesis options]
spo pool witness sign FILE --key NAME [--offline] [genesis options]
spo pool witness clear POOL [--yes]
```

`import` verifies the signed witness in `FILE` against the stored body hash and the key hash of its slot, and stores it. The file carries no authenticated sender, and the output says so. A slot that already holds a witness is replaced only with `--overwrite`. `status` prints the lifecycle (`Draft`, `CertificateIssued`, `CollectingWitnesses`, `Registered`, `RetirementScheduled`) and, for an open collection, its id, body hash, payer, TTL, the state at the current slot (`OpenIncomplete`, `OpenComplete`, `Expired`) and each slot with its holder and whether it is signed. Needs: `tx-id` (import also `tip`, `genesis`); `status` shows the current slot when it can.

`info` (upstream `05d info`) reports the collection of a pool: id, type, ticker, payer, valid-until slot, the state at the current slot and each slot signed or open (with the witness file it waits for). An expired collection is reported in full and the command fails. Needs: `genesis`, `tip`, `tx-id`.

`sign` (upstream `05d sign`) runs on the signer's machine with the transfer file and the signer's keys only. It checks the file (valid JSON, window open at the current slot, not signed yet, `NAME.staking` is the key the witness was requested for), **decodes the transaction body and prints it in full** (inputs, outputs, fee, validity, every certificate with its fields, withdrawals, mint, votes, required signers), and signs only after you answer yes at the terminal (default No). No flag answers that question and without a terminal the command refuses: a transaction is never signed unseen. A body with parts that cannot be shown in full (proposals, a mint, scripts, datums, collateral, reference inputs) or for another network is refused. On success the file is rewritten in place with the witness and the date; send it back and import it. A key on a hardware wallet signs through the device. Needs: `signers`, `genesis`, `tip`, `clock`, `tx-view`, `tx-id`.

`clear` (upstream `05d clear`) discards the open collection after asking (default No; `--yes` answers yes). Witness files on disk are not touched.

### `pool status`

```
spo pool status POOL|POOL-ID [--transfer-file PATH] [--offline] [genesis options]
```

Reads the registration of a pool (upstream `05e`) and prints each fact with its `[source]`: status (`registered`, `retiring`, `retired`, `not registered`), name, ticker, retirement epoch, pledge, cost, margin, reward address, metadata URL and hash, as far as the provider reports them. An answer the provider did not give is `unknown` and fails the command; it is never `not registered`. Needs: `pool-state` (light mode: Koios; offline: only a transfer file that holds pool state).

### `pool retire-cert`, `pool retire`

```
spo pool retire-cert POOL [--epoch N] [--transfer-file PATH] [--offline] [genesis options]
spo pool retire POOL PAYER [--message TEXT]... [--transfer-file PATH] [--offline] [genesis options]
```

`retire-cert` (upstream `07a`) stores `POOL.pool.dereg-cert` for `--epoch` (default: the next epoch); an epoch outside the window the ledger accepts is moved to the nearest edge and the output says so. `retire` (upstream `07b`) sends it in one transaction signed by `PAYER` and the cold key; no deposit moves. As for `pool register`, `--yes` is refused and the question is always asked. The epoch is checked again before a fee is spent. Needs: the `wallet send` needs, `pool-certificate-decoding`, `clock`.

## Governance: DReps, committee, votes, actions

Governance commands follow the stake commands: the same transaction options (`--message TEXT`, `--yes`, `--transfer-file PATH`, `--offline`, the genesis options), the same confirmation (default No; no terminal and no `--yes` refuses) and the same `wallet send` needs, checked before the passphrase is asked. Each command adds the needs named below; a refusal lists every missing capability with its reason. Key material and mnemonics are never printed. The summary names the account, the payer, the certificate, votes or proposals, the deposit paid or refunded, the fee, the valid-until slot, the sources and the checks not made. A **Details** block adds what the public files hold: the DRep id, the anchor URL and hash, each vote as voter role, action id (hex and `gov_action1...`) and decision, each proposal as kind, deposit, return address and anchor. With `--yes` the same summary is printed after signing, attachments, deposit and refund included: the use case returns the summary it prepared.

Five policy flags exist, never on by default and never implied by a mode. A refusal that one of them would lift names it and what it gives up.

| Flag | Where | Gives up |
| --- | --- | --- |
| `--anchor-unverified` | `vote create`, `action create`, `drep status`, `drep register`, `committee resign` | The check of the anchor document against CIP-100/108/119: this build has no verifier (`anchor-verification` is absent in every mode). The hash is recorded as given. The output says `NOT CHECKED`. |
| `--single-source` | `drep retire` | The corroboration of the DRep deposit the refund rests on. A second DRep source (capability `drep-state-crosscheck`) corroborates it; none exists in any mode today, so the command needs the flag. A false answer from one provider can cost the deposit. The summary says the read rested on one source. |
| `--allow-unverified` | `action submit` | The check that the deposit-return stake address is registered, when no reader answers. A wrong answer only makes the ledger reject the transaction. The summary lists the skipped check. |
| `--allow-anchor-clear` | `drep register` | Lets an update without an anchor replace the anchor the DRep has on chain with none. |
| `--allow-unrestricted` | `drep register`, `drep retire`, `vote submit` | Starts the question that allows a hardware wallet's unrestricted signing mode; see [Hardware wallets](#hardware-wallets). The flag allows nothing by itself. |

An anchor is `--anchor-url URL` (https or ipfs, at most 128 characters) with `--anchor-hash HEX`. Where the mode downloads documents (light) the document is hashed and its own hash replaces `--anchor-hash`. Where it does not (offline) both are required together and the hash is recorded as given. `drep register` and `committee resign` give an anchor the same policy as `vote create` (`drep register` for CIP-119, `committee resign` for CIP-100): with an anchor and no verifier they are refused, before anything is read, unless `--anchor-unverified` is given, and the decision is recorded and printed as `Decision: the anchor document was not verified`.

### `drep keys generate`, `committee keys generate-cold`, `committee keys generate-hot`

```
spo drep keys generate NAME [--mnemonic | --mnemonic-in-fd N] [--account N] [--index N] [--hardware]
spo committee keys generate-cold NAME [same options]
spo committee keys generate-hot NAME [--replace] [same options]
```

`--hardware` makes the key on a hardware wallet (`--account` and `--index` then select the device path, and the mnemonic options are refused); it needs `hardware-wallet` instead of the key generator. See [Hardware wallets](#hardware-wallets).

Upstream `21a`, `23a`, `23b`. Stores `NAME.drep.{vkey,skey,id}` or `NAME.cc-cold.*` / `NAME.cc-hot.*` (`vkey`, `skey`, `hash`); prints the id or hash in every spelling, never the signing key. `--mnemonic` derives the key (CIP-1852, role 3, 4 or 5) from a fresh 24-word phrase stored sealed and not shown; `--mnemonic-in-fd N` derives it from a phrase read from descriptor N; `--account` and `--index` select the path and need one of them. An existing key is refused; `--replace` (hot key only) deletes the old key, its signing key and its files first. Needs: `drep-keygen`, `committee-cold-keygen` or `committee-hot-keygen` (`governance-derivation` with a mnemonic, plus `mnemonic-generation` for a fresh phrase). The era is checked when parameters are available.

### `drep register`

```
spo drep register NAME PAYER [--anchor-url URL --anchor-hash HEX] [--anchor-unverified] [--allow-anchor-clear] [common options]
```

Upstream `21b`. There is no separate update command: the use case reads the DRep state and makes a registration (pays the `dRepDeposit`) or an update (no deposit); an unknown answer is refused. The payment key and the DRep key sign (two witnesses). Needs also: `certificate-building`, `drep-state` (offline: the DRep must be in the transfer file, `offline add-drep`). Stores `NAME.drep-reg.cert` after the transaction was sent or queued.

### `drep retire`

```
spo drep retire NAME PAYER [--single-source] [common options]
```

Upstream `21d`. Refunds the deposit of the on-chain DRep state. "Not registered" and an unknown answer are errors. Needs `--single-source` unless a second DRep source answers (`drep-state-crosscheck`, absent today; two sources that disagree are refused). Needs also: `certificate-building`, `drep-state`. Stores `NAME.drep-ret.cert`.

### `drep status`

```
spo drep status NAME|DREP-ID [--anchor-unverified] [--transfer-file PATH] [--offline] [genesis options]
```

Upstream `21c`. Prints registered, registered but expired, or not registered, with the ids, epoch, deposit, expiry, delegated stake, anchor and its check, and the source. Needs: `drep-state`. The `epoch` reader is optional: without one (or when it fails) registration, deposit and anchor are still reported, the standing is `registered (expiry not assessed)` and the epoch line says `unknown` with the reason. An expiry or stake the provider does not state is printed as `unknown: <reason>`, never as zero; a DRep the provider has never seen (Koios answers `[]`) is an error, not "not registered".

### `committee authorize`, `committee resign`, `committee status`

```
spo committee authorize COLD HOT PAYER [common options]
spo committee resign COLD PAYER [--anchor-url URL --anchor-hash HEX] [--anchor-unverified] [common options]
spo committee status NAME|HASH|ID
```

Upstream `23c`, `23e`, `23d`. `authorize` and `resign` sign with the payment key and the cold key; the hot key never signs. They read the committee state from the chain and are refused when the transaction would be queued (offline). A resigned cold key cannot be authorised; a key that is not on chain cannot resign; a key that already resigned resigns again and the output says so. Stores `HOT.cc-hot.cert` and `COLD.cc-cold-ret.cert` after sending. `status` tries the hash as a key and as a script credential, as cold key and then as authorised hot key; "not a member" is an answer. The Koios committee list states the authorisation and the expiration epoch but neither a member status (`Active`, `Expired`) nor a pending change: those lines are omitted, not invented. Needs also: `certificate-building` (not `status`), `committee-state`.

### `vote create`, `vote submit`, `vote tally`

```
spo vote create VOTER ACTION-ID yes|no|abstain [--anchor-url URL --anchor-hash HEX] [--anchor-unverified]
spo vote create VOTER all [--anchor-unverified]
spo vote submit PAYER VOTE-FILE... [--voter NAME] [common options]
spo vote tally [all | ACTION-ID | VOTER | STAKE-ACCOUNT | ACTION-KIND]...
```

Upstream `24a`, `24b`, `24c`. `create` writes `NAME_yymmddHHMMSS.drep.vote`, `.cc-hot.vote` or `.pool.vote`; with an action id and a decision nothing is asked, with `all` you are asked per open action (default cancel). The action must be open and the voter's role must be allowed to vote on its kind. Needs: `governance-actions`, `protocol-parameters`, `epoch`, `clock`, `vote-file`; it is refused offline. `submit` puts the votes in one transaction signed by the payment key and the voter's key; no chain state is consulted. The voter's key is derived from the vote files: the stored key of the files' role whose hash is the voter in them, looked up under the part of each file name before its time stamp; `--voter NAME` overrides it, and a refusal that no stored key matches says to pass it. Needs: `vote-file`. `tally` is a read model: percentages, thresholds and verdict per DRep, pool and committee body for each matching open action, with the source of each input. Nothing is decided or gated by it. Needs: `governance-actions`, `protocol-parameters`, `epoch` and one of `stake-distribution` (percentages computed here from the DRep and pool stake and the committee) or `voting-summary` (light mode: the percentages are the provider's own, Koios `proposal_voting_summary`, as upstream's light mode takes them; only the thresholds, from the protocol parameters and the committee quorum, are computed here). No adapter reads the stake distribution: in light mode `voting-summary` serves.

### `action create`, `action submit`

```
spo action create KIND RETURN --anchor-url URL [--anchor-hash HEX] [--anchor-unverified] [kind options]
spo action submit PAYER ACTION-FILE... [--allow-unverified] [common options]
```

Upstream `25a`, `25b`. `KIND` is `info`, `no-confidence`, `update-committee`, `new-constitution`, `hard-fork`, `treasury-withdrawal` or `parameter-change`. `RETURN` is a stored stake account or a stake address. Kind options: `--amount` and `--to` (treasury), `--version MAJOR[.MINOR]` (hard fork), `--threshold`, `--add-key`, `--add-script`, `--remove-key`, `--remove-script`, `--term-epoch` (committee), `--constitution-url`, `--constitution-hash`; an option of another kind is refused by name. `parameter-change` is refused (`ErrParameterChangeUnsupported`, matched by type, not text): its file is not built yet and nothing is written. `create` needs `protocol-parameters`, `clock` and `action-file`, and each kind adds only what it reads: `last-enacted-action` for the kinds that name a previous action (`no-confidence`, `update-committee`, `new-constitution`, `hard-fork`, `parameter-change`), `constitution` for `treasury-withdrawal` and `parameter-change`, `epoch` for `update-committee`. An `info` action therefore needs no chain reader and also runs offline from the transfer file's parameters. `submit` puts the proposals in one transaction paid by `PAYER` and signed by the payment key, valid for 25000 slots; the return address must be registered (checked when a `reward-account` reader answers). Treasury withdrawals and parameter changes carry the constitution's guardrails script, which this build does not evaluate: the command checks the rest and refuses, printing what is missing. After success it prints the id each proposal will have. Needs: `action-file`.

## Address queries

### `address NAME|ADDRESS`

```
spo address NAME|ADDRESS [--offline] [--transfer-file PATH]
     [--shelley-genesis FILE] [--byron-genesis FILE] [--byron-to-shelley-epochs N]
```

Upstream `01_queryAddress`. `NAME` is a stored address (`NAME`, or `NAME.staking` for the stake address); an address is used as given. An ADA Handle (`$name`, `$sub@name`) is resolved (see [ADA Handles](#ada-handles)); the report shows the handle and the address it resolved to. Needs: address-inspection and one of utxo, reward-account.

For a payment address: the UTxOs (reference and lovelace; native assets with policy, name and CIP-14 fingerprint; datum hash), the total lovelace and the asset totals. For a stake address: the registration deposit, the rewards, the pool and vote delegation and the governance deposits that will be refunded to it. Every line names the source that stated it (`[koios preview]`, `[offline transfer file]`); a value the source did not state is printed as "not stated" with the reason, never as zero. An address with no funds and an unregistered stake address are errors.

In offline mode the answer is read from the offline transfer file: the output carries a `snapshot` line with the date of the snapshot and says it is not the chain as it is now. An address that is not in the file is refused with the remedy (`offline add` on the online machine).

## The transfer file: `offline`

The transfer file (`offlineTransfer.json`, in the workspace directory unless `--transfer-file PATH` says otherwise) carries a snapshot of the chain to the offline machine, the signed transactions queued there back to the online one, and small files in both directions. The format is upstream's and stays compatible with `01_workOffline.sh`. Every `offline` command takes `--transfer-file`.

`new`, `add`, `add-drep` and `execute` need the chain: they are refused in offline mode, before any prompt, with the missing capabilities and why (for example `sync-check: offline mode has no chain to check the sync of`). `info`, `attach`, `extract` and `clear` work in every mode and read only the transfer file: they do not open the workspace and do not ask for the passphrase (`extract` still uses the workspace directory to place `extracted/`).

### `offline new [--yes]`

Writes a new transfer file: the protocol parameters, the era, the work mode, an empty queue. Needs: transfer-file, clock, protocol-parameters, sync-check. An existing file is replaced; when it holds queued transactions or attached files you are asked first (default No; `--yes` approves).

### `offline add NAME`, `offline add-drep NAME DREP-ID`

`add` records the UTxOs of a stored payment address (`NAME`) or the reward account of a stored stake address (`NAME.staking`) and refreshes the protocol parameters. `add-drep` records the state of a DRep (`DREP-ID` in bech32). The output names the amounts, the source of the state and of the parameters, and the date. A stake address that is not registered, a DRep whose state is not known and a source that is not synced are refused and the file is left as it was. Needs: the `new` needs, plus address-inspection, utxo and reward-account (`add`), or drep-state (`add-drep`).

### `offline info`

Shows the general information (usable or not, era, versions, last action, history length), the addresses with their balances, the DReps, the queued transactions (position, type, era, date, names, and the fee and id computed from the signed transaction), and the attached files by name and size. Every other field of a queue entry is the file writer's claim and is not compared with the transaction; the output says so. A missing file is an error. When the history records submitted asset record updates (a mint or burn that `offline execute` submitted), a line says so and names `spo asset settle`; `info` itself writes nothing.

### `offline execute [N] [--yes]`

Submits the `N`th queued transaction (default 1) through the chain provider (light mode). It first checks that the UTxOs of the paying address, and the rewards for a withdrawal, are as in the snapshot. It then prints a summary (the entry, the tx id computed from the signed transaction, the provider, `WARNING` lines, `checked` lines and `NOT CHECKED` lines) and asks `Submit this transaction? [y/N]`; the default is No, and no terminal without `--yes` refuses. A declined run submits nothing and leaves the queue as it was (exit `1`). `--yes` is the explicit skip of the question: the summary is still printed (after the run, from what the checks found), the skip is reported, and the exit status is as for any other run. The entry is removed from the queue only after the submission. A queued asset mint or burn carries its asset record update in the queue entry (the port's own field `spoAssetPending`, which upstream's readers ignore). After the submit the update is added to that entry's `tx submit` history line (`spoAssetSubmitted`), so the result travels back with the file, and it is applied at once if this workspace holds the pending update or the asset record; a workspace that holds neither (the usual online machine) changes nothing. A failure to apply it never fails the submission and is printed as a notice. See `asset mint` and `asset settle`. Pool registrations also check the published metadata hash. Needs: transfer-file, clock, tx-submit, utxo, reward-account, tx-id.

### `offline attach FILE [--name NAME]`, `offline extract [--dir DIR] [--overwrite]`

`attach` stores a file of at most 1 MiB under `NAME` (default: the file's own name, which must be a plain file name). `extract` writes every attached file that was not extracted yet into `DIR`, by default the new subdirectory `extracted/` of the workspace. It never writes into the workspace directory itself (`--dir` naming it is refused), and writes only plain file names inside `DIR`: an entry whose name is a path (`../x`, an absolute path) is refused and listed, and makes the command fail. An existing file is kept (`skipped`) unless `--overwrite` is given. An extracted file is removed from the transfer file and the history records it.

### `offline clear transactions|history|files [--yes]`

Removes the queue, the history or the attached files and records that in the history. Clearing the queue or the files discards work that is stored nowhere else, so you are asked first (default No; `--yes` approves). Clearing the history is not asked.

## Native assets

### `policy new NAME [--lifetime SLOTS] [--hardware]`

`--hardware` makes the policy key on a hardware wallet (path `1855H/1815H/0H`) and asks the device for the policy id, which must equal the id computed from the script; see [Hardware wallets](#hardware-wallets).

Creates the minting policy `NAME` (upstream `10_genPolicy`, software keys): a payment-type key (signing key sealed in the workspace, never printed), the native script that requires its signature, and the policy id. `--lifetime SLOTS` makes the script expire that many slots after the current slot, which needs `genesis` and `tip` (offline: the clock); without it the policy never expires. The four artefacts are written together or not at all; an existing policy is refused. The output names the policy id, the key hash and the expiry. Needs: payment-keygen, policy-id.

### `asset mint POLICY.ASSET AMOUNT PAYER`, `asset burn POLICY.ASSET AMOUNT PAYER`

```
spo asset mint|burn POLICY.ASSET AMOUNT PAYER [--yes] [--message TEXT]... [--transfer-file PATH]
     [--offline] [genesis options] [--metadata-file FILE]... [--encrypt-messages] [--input TXHASH#IX]...
```

Mints or burns `AMOUNT` (a positive number) of the asset `ASSET` (letters and digits, or `{hex}`) under the stored policy `POLICY` (upstream `11a`, `11b`). `PAYER` names the stored address that pays the fee and receives the asset. The policy key and the payer's key sign. The use case refuses an expired policy, a policy id that does not match its script, and a burn of more than the inputs hold. Needs: those of `wallet send`, plus policy-id and clock. Confirmation, `--yes`, modes and output are those of `wallet send`.

The asset record `POLICY.ASSET` keeps the `minted` total. It is updated when the transaction is **submitted**: at once in light mode. A mint or burn that is only queued (offline mode) changes no record. Two things are kept for it: a pending update in the workspace under the transaction id, and the same update inside the queue entry of the transfer file, so it crosses the air gap with the transaction. When `offline execute` submits the entry (on the online machine, which usually holds neither the policy key nor the record) the submission is written into the file's history; carry the file back and run `asset settle` on the machine that holds the record. This is the air-gap flow of a mint:

1. offline: `policy new p`, then `asset mint p.tok 100 PAYER` (the transaction is queued);
2. carry the transfer file to the online machine and run `offline execute`;
3. carry the file back and run `asset settle`: the record shows the minted amount, once.

Upstream writes the record when it queues the transaction; the port writes it when the submission is known (hazard H9). Show the record with `asset show`.

### `asset settle`

```
spo asset settle [--dry-run] [--discard-unmatched] [--transfer-file PATH]
```

Reads the history of the transfer file that came back from the online machine and applies, to the asset records of this workspace, every queued mint or burn that `offline execute` submitted and whose pending update waits here. Each is applied exactly once: the pending update is removed in the same commit, so a second run changes nothing and says so. An update whose transaction is still queued is reported as waiting. An update the file knows nothing about (neither queued nor submitted) is reported as unmatched and kept, because the file may simply be the wrong one; if its transaction was removed with `offline clear transactions`, `--discard-unmatched` drops the update, which is never applied. `--dry-run` prints what would be applied or discarded and changes nothing. The output names each transaction id. Needs: transfer-file, clock. Opens the workspace; needs no chain.

### `asset show POLICY.ASSET`

Prints the asset record (a JSON document: `minted`, the identifying fields, `lastAction`, the `meta*` keys an operator edits). It holds no secret. Before anything was submitted it says there is no record yet. Opens the workspace; needs no chain.

## Calidus pool key and Catalyst registration

Both register a key by a signed metadata record and neither submits anything: the registration is stored in the workspace (as `NAME_yymmddHHMMSS.calidus-registration.json` or `NAME_yymmddHHMMSS.vote-registration.cbor`) and put on the chain by an ordinary payment that carries it, `spo wallet send PAYER PAYER MIN --metadata-record NAME.…`, upstream's `01_sendLovelaces <wallet> <wallet> min <file>`. No command writes the record to a file. Signing goes through the signing plan (ADR 0008): the vault signer signs CIP-88 and CIP-36 registrations (capability `registration-signing`), and a pool cold key or stake key held on a hardware wallet is refused before anything is built. No command prints a signing key or a recovery phrase.

### `pool calidus new NAME [--mnemonic-in-fd N] [--account N] [--index N]`

Derives the Calidus key (CIP-151) along `1852H/1815H/ACCOUNTH/0/INDEX` (default `0/0`) from a 24-word phrase and stores `NAME.calidus.vkey`, `.skey`, `.mnemonics` and `.id` together or not at all; existing ones are refused. `--mnemonic-in-fd N` reads the phrase from descriptor `N`; without it a fresh phrase is generated and stored sealed, never shown (there is no random-seed path, as upstream has none). Prints the Calidus id and the public key. Needs: `calidus-keygen`, and `mnemonic-generation` without `--mnemonic-in-fd`.

### `pool calidus register-metadata CALIDUS POOL [--nonce N]`

Builds the CIP-88 version 2 registration of the Calidus key `CALIDUS` for `POOL` and signs it with the pool's cold key (upstream `15 genmeta`). Prints the Calidus id, the pool id, the nonce and the stored record's name, and the exact follow-up `spo wallet send <payer> <payer> MIN --metadata-record NAME`. `--nonce` defaults to the current slot of the work mode; where the mode has none (offline without genesis) on a testnet the command asks for `--nonce`. The command has no `--submit-with`: the follow-up is printed, not run. Needs: signers, `registration-signing`, clock.

### `pool calidus status CALIDUS-ID|KEY|POOL|NAME|all`

Lists the Calidus keys registered on chain for a pool, a Calidus id or key (upstream `15 query`). The capability `calidus-registrations` is absent in every mode: no provider adapter reads CIP-88 registrations yet, and the command says so and stops.

### `catalyst key new NAME [--mnemonic-in-fd N] [--account N] [--index N]`

Derives the voting key (CIP-36) along `1694H/1815H/ACCOUNTH/0/INDEX` and stores `NAME.voting.vkey`, `.skey`, `.pkey` and `.mnemonics`. The phrase is read or generated as for `pool calidus new`. Prints the public key (`cvote_vk`). Needs: `voting-keygen`, and `mnemonic-generation` without `--mnemonic-in-fd`.

### `catalyst register STAKE REWARDS --vote-key NAME[:WEIGHT]... [--nonce N] [--purpose N]`

Delegates the voting power of the stake account `STAKE` to the voting keys and signs the CIP-36 registration with its stake key (upstream `09a genmeta`). A `--vote-key` is the name of a stored voting key, a public key in hex or a `cvote_vk` text; `WEIGHT` defaults to 1; repeat the flag for several. `REWARDS` is a stored address name or a payment address of the network. `--nonce` defaults to the current slot as above; `--purpose` to 0 (Catalyst). Prints the nonce, the keys with their weights, the rewards address, the stored record's name and the follow-up send command. Needs: signers, `registration-signing`, clock. The QR code of the Catalyst mobile app is **not built**: there is no command for it.

## Moving between the upstream layout and the sealed workspace

### `workspace import DIR`

```
spo workspace import DIR [--owner NAME]... [--password-fd N] [--keep-encrypted] [--overwrite]
```

Reads `DIR` (an upstream-layout directory; it is opened read-only and never changed) and stores what it holds in the sealed workspace, owner by owner. Each signing key is checked against its verification key, and each address against its keys (`verification-key-derivation`, `address-inspection`). An owner is imported whole or not at all. Files that are not artefacts of the catalogue are listed as `ignored`. It does not apply with `--upstream-layout`.

A key that upstream encrypted needs its password: `--password-fd N`, else a prompt without echo when such a key is met (the source is looked at first). That needs `key-encryption` (gpg); without it the command names the missing tool and says gpg is needed only for upstream's encrypted keys. `--keep-encrypted` stores such a key in upstream's encrypted form without decrypting (no password, no gpg). Existing artefacts are kept and their owner refused unless `--overwrite`.

The result is a table:

```
OWNER   ARTEFACT       STATUS   REASON
pool-a  pool-a.node.skey  done
bad     bad.addr.skey  failed   the verification key does not belong to the signing key
```

It holds owners, artefact names, statuses and reasons, never key material. The exit status is `1` when any owner was not imported.

### `workspace export DIR`

```
spo workspace export DIR [--owner NAME]... (--password-fd N | --plaintext) [--overwrite] [--reason TEXT] [--yes]
```

Writes the pools and wallets of the sealed workspace into `DIR` in the upstream layout, with the same names, modes and contents the upstream scripts expect. `DIR` must be new or empty (`--overwrite` allows a directory that is not). You must choose how the signing keys leave: `--password-fd N` encrypts each in upstream's gpg form with the password read from that descriptor (needs `key-encryption`); `--plaintext` writes them in clear, and needs the word `plaintext` typed at the prompt (`--yes` types it). Mnemonics have no protected form and are written only with `--plaintext`. Giving both, or neither, is refused. It does not apply with `--upstream-layout`.

The audit record is written to the workspace (operation, owners, counts of keys written in clear and protected, whether a password was used, `--reason`) **before** any key is written; if it cannot be made, nothing is exported. `store verify` covers it like any other change. The output is the table of `import`, with each secret's protection (`PLAINTEXT` or `encrypted`), and the exit status is `1` when any owner was not exported. A refused or failed export leaves no empty directory behind.

### `key protect FILE`, `key unprotect FILE`

```
spo --upstream-layout key protect FILE [--password-fd N]
spo --upstream-layout key unprotect FILE [--password-fd N] [--reason TEXT] [--yes]
```

Encrypts a plain signing key file of an upstream-layout directory in place in upstream's form (`protect`, upstream `01_protectKey enc`), or decrypts it (`unprotect`, `dec`). `FILE` is the upstream file name (`pool.node.skey`, `wallet.skey`). The password is read from `--password-fd N`, else asked for without echo (twice for `protect`) and must be strong in upstream's sense. `protect` checks that the new file decrypts to the same key before it replaces the old one. `unprotect` writes the key in clear: it needs the typed word `plaintext` (or `--yes`) and an audit record, kept in the dotfile `.spo-workspace-audit.json` in that directory (`workspace import` lists it as ignored, without a warning). Without `--upstream-layout` both return that keys in the sealed store are always protected. Needs: key-encryption (gpg).

## Hardware wallets

> **Untested on real devices.** The hardware path is built and tested against a stand-in for `cardano-hw-cli`, not against a Ledger, Trezor or Keystone. Before relying on it, work through the [device checklist](../development/hardware-device-checklist.md) with throw-away keys on a test network.

The device is driven by the release set's pinned `cardano-hw-cli` (a Node tool). It is wired only when the binary has a toolchain manifest that provides it (`nix run .#spo`); otherwise capability `hardware-wallet` is absent with that reason and every `--hardware` command refuses, listing it, before anything is asked. The device is not opened to describe the environment or to start a command: the first step that needs it (the signing plan) opens it, and a software-only command never touches it. While waiting for the device, `spo` prints on stderr `Connect and unlock your device and open the Cardano app` with the time left (default 60 seconds, `[hardware] wait_seconds` in [spo.toml](./spo-toml.md)).

What a device may hold is decided by its vendor and app version, before anything is built or shown ([ADR 0008](../explanation/adr/0008-capability-typed-ports.md)): for example a Trezor is refused for a pool cold key with one message and is never asked to generate one. Only the public key and the derivation path of a hardware key are stored (the hardware signing file); a private key never leaves the device.

**Key generation** takes `--hardware` (the holder becomes the device) and the variants of the key:

| Command | Hardware flags |
| --- | --- |
| `wallet new NAME` | `--hardware`, `--account N`, `--index N`, `--multisig` (purpose 1854H for the payment key), `--hybrid` (with `--stake`: payment key on the device, stake key in the workspace). Not with `--mnemonic`. |
| `pool keys generate POOL` | `--hardware`, `--index N` (path `1853H/1815H/0H/NH`) |
| `drep keys generate`, `committee keys generate-cold`, `committee keys generate-hot` | `--hardware`, `--account N`, `--index N` |
| `policy new NAME` | `--hardware` |

`--multisig`, `--hybrid` and the path numbers without `--hardware` are refused.

**Transactions** need no flag: when a key of the transaction is held on a device, the body is first brought to the form the device accepts, so the summary you are shown carries the id of the body that is signed, then the device witnesses exactly that body and you confirm on the device. `pool opcert issue` for a hardware cold key is issued by the device and checked before it is stored. A hardware key cannot be combined with a key held in the workspace in one transaction, except where the specs allow it.

**Unrestricted mode.** A device signs a certificate or vote that is not its own only in unrestricted mode (`drep register`, `drep retire` and `vote submit` with several votes can need it). `--allow-unrestricted` does not allow it: it only starts a question that says what the mode means and asks yes or no, default No. `--yes` does not answer that question, and without a terminal the command refuses. Without the flag the question is never asked and consent is never given; a command that needs the mode then fails with `the hardware wallet can sign this transaction only in unrestricted mode`.

**Errors**, each with what to do next:

| Error | Meaning and remedy |
| --- | --- |
| no device | none answered in time: connect, unlock, open the Cardano app; `[hardware] wait_seconds` waits longer |
| device too old | update the Cardano app or firmware; the minimums are `[hardware] min_ledger`, `min_trezor`, `min_keystone` |
| rejected | you declined on the device; nothing was signed, submitted or stored |
| disconnected | the device went away; reconnect and run again |
| expert mode required | enable expert mode in the device's Cardano app and use `--allow-unrestricted` |
| no canonicalizer, mixed holders, not hardware-canonical | the build cannot drive a device, the keys cannot be mixed, or a body was not canonical (a fault; report it) |

## ADA Handles

A payment destination (`wallet send`, `wallet send-assets`, `wallet claim-rewards`, and `poll submit`) and `spo address` accept an ADA Handle, `$name` or `$sub@name`, in any letter case. Capability `ada-handle`: light mode only (a handle is looked up on the chain; offline mode refuses with `ADA Handles can only be resolved with a chain provider, not offline`).

The Handle API is a third party, so its answer is checked against the chain before it is used: a root handle is looked up by who holds the handle asset (Koios `asset_addresses`) and the holder's outputs must hold it exactly once; a sub-handle is read from the Handle API and verified against the chain or the inline datum; anything unverifiable is refused. Only the current handle policy is trusted. **The confirmation shows both the handle and the address it resolved to** (`to  $alice (addr1...)`), before you are asked. The API root is the network's (`https://api.handle.me`, `https://preprod.api.handle.me`, `https://preview.api.handle.me`), or `[handles] url` in [spo.toml](./spo-toml.md).

## Pool BLS keys

### `pool bls generate POOL`

Generates the pool's BLS12-381 key pair (upstream `04f_genBLSKeys`) into the workspace; the signing key is sealed and never printed, the verification key is. Refused on `mainnet`: upstream ships the script in its testnet tree only, and the key is needed in a registration certificate only from protocol version 12. An existing BLS key is refused. Needs: `bls-keygen`.

## SPO polls

CIP-94 polls, upstream `13a` and `13b`. They need the chain (light mode): offline, `poll-question` is absent and the commands refuse before anything is asked.

### `poll show TXHASH`

Prints the question, the numbered options (from 0) and the question hash an answer commits to, with the source. The question is what the chain provider reported. Needs: `poll-question`.

### `poll answer TXHASH [--option N] [--out FILE] [--yes]`

Shows the poll, takes the option (`--option`, or asks), confirms it (default No; `--yes` answers the confirmation) and writes the answer metadata to `FILE` (default `spopoll_<hash>.cbor`; an existing file is not replaced). An option outside the poll is refused.

### `poll submit PAYER DESTINATION AMOUNT POOL [--poll TXHASH [--option N] | --metadata-file ANSWER]`

Sends the answer as a payment that carries it and that the pool's cold key co-signs (a required signer), so it is attributable to the pool. The answer is built here (`--poll`, option asked when not given) or read from a file (`--metadata-file`); a message does not count. The cold key must be in the workspace. All options and needs of `wallet send` apply.

## Output rules

No command prints a passphrase, a token or a signing key. The recovery key appears only in the one-time display of `init`, `store passphrase change`, `store recovery-key new` and `store recover` (or on the descriptor given), and is read only by `store recover`. Error messages never include them.

## Exit status

`0` on success, `1` on any error. The message is on stderr, prefixed `spo:`. A check whose verdict is not OK (`pool opcert check`: FALSE or UNKNOWN) is an error, unlike upstream `04e`, which exits `0` after a FALSE verdict.
