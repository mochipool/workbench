# spo CLI

This page lists every `spo` command and option that is wired. `spo` is the Go reference implementation in `spo/`. Commands not listed here do not exist yet.

The same commands are available as menus and forms in the terminal UI: see [spo TUI](./spo-tui.md).

Run it with `nix run --accept-flake-config .#spo -- <args>`. The packaged binary carries the release-set manifest; a binary built without it (`go build`) has no bundled genesis files and no toolchain checks.

## Synopsis

```
spo [-C DIR] [--passphrase-fd N] [--accept-rollback] COMMAND ...
```

## Global options

| Option | Meaning |
| --- | --- |
| `-C`, `--workspace DIR` | Workspace directory. Default: the current directory. |
| `--passphrase-fd N` | Read the workspace passphrase from inherited file descriptor `N` instead of prompting. The trailing newline is stripped. An empty value is refused. |
| `--accept-rollback` | Open a workspace file that is older than the state recorded for it (see [Rollback detection](#rollback-detection)). Never saved; a warning is printed whenever it is used. Use it once, after you restored an older backup on purpose. |

There is no option that works on a plain directory in the upstream scripts' file layout, and none that writes a signing key or any other secret unprotected: the release binary is unable to (ADR 0011 (proposed), [Xcustody](../../spec/extensions/Xcustody.md)). A directory in that layout is brought in with [`workspace import`](#workspace-import-dir). A build made with `-tags plainlayout` (the parity and differential checks, not a release) adds a global `--upstream-layout` for its tests; the release has no such flag.

There is no passphrase flag and no passphrase environment variable. A passphrase is never taken from `argv` or the environment. Without `--passphrase-fd`, the passphrase is read from the terminal without echo; with no terminal the command fails and names `--passphrase-fd`.

Prompts, warnings and `note:` lines go to stderr; results go to stdout. After every successful open of the store, the notices the store produced (for example a recreated head file) are printed to stderr, each prefixed `note:`.

A command that needs a chain capability, a transfer file or a genesis checks for it when it starts, before it asks for the passphrase or anything else, and fails with one error listing everything it lacks and why. `spo capabilities` shows the same list. Locked memory: `spo` locks the pages that hold secrets. When the locked-memory limit is too low it exits with advice naming `ulimit -l` (`RLIMIT_MEMLOCK`).

Shell completion (`spo completion SHELL`) completes the names a command takes (wallet, pool, stake key, policy, asset, DRep, committee key, voting key, Calidus key, party), directories and files of the extension a flag names. Names are read from the workspace without a passphrase prompt, and a sealed workspace cannot be opened without one, so the shell never offers workspace names in the release (it has no plain directory to read them from); it completes paths only, directories and the files of the extension a flag names. The TUI uses the same hints; see [spo tui](./spo-tui.md).

A command that documents flags as mutually exclusive or required together declares them to cobra, so the error is cobra's (`if any flags in the group [a b] are set none of the others can be; [a b] were all set`) and the TUI form shows it before the run. `wallet new` (`--mnemonic`, `--mnemonic-in-fd`, `--hardware`), `pool opcert check` (`--number`, `--opcert-file`) and `workspace export` (`--password-fd`, `--generate-password`: exactly one) do.

## Workspace

A workspace is a directory with:

* `workspace.spo`: the sealed store. Every record, name and key is encrypted; see [ADR 0003](../explanation/adr/README.md).
* `workspace.spo.head`: the chain head recorded after every write, for rollback detection. Not secret; keep it beside `workspace.spo`.
* `spo.toml`: non-secret settings, mode `0600`. See [spo.toml](./spo-toml.md).
* `offlineTransfer.json` (offline mode only, made on the online machine with `offline new` and `offline add`): read by `wallet send` and `address`, and managed by the `offline` commands; see `--transfer-file`.
* `extracted/` (created by `offline extract`): the files carried in the transfer file.

Every command that touches keys or records opens the sealed store.

## Commands

### `workspace migrate`, and `<kind> rename`, `<kind> merge`

`spo workspace migrate [--quarantine POOL]... [--remove-copies]` converts a workspace of the old format (records keyed by the name of their owner) to the current one, where a record is keyed by the anchor identity of its owner and a name is a label ([ADR 0010](../explanation/adr/0010-object-identity.md); how to: [Migrate a workspace](../how-to/migrate-a-workspace.md)). Every other command on an old workspace refuses and names this one. It asks for the passphrase, copies the file beside it first (`<file>.pre-migrate-v1`, mode 0600), converts in one transaction (a failure leaves the original), and prints the copy, the counts, the descriptors rewritten, the pools quarantined and the witness slots whose party no longer resolves. It refuses with a list, and changes nothing, when a name in a descriptor resolves to no key or its registration data disagrees with the keys, when one key would belong to two owners, or when two records that become one differ. `--quarantine POOL` goes on for a pool whose own problems those are and leaves it unusable. After the conversion to format 2 the command goes on to store format 3 (ADR 0011: slot kinds and a workspace policy on disk) in a second transaction with a copy of its own, `<file>.pre-migrate-v2`; the workspace gets the policy `standard` and its passphrase and recovery slots are unchanged. A workspace already in format 2 (no records to convert) runs only that step. The copies hold a pool cold key or committee cold key sealed the older way (under the master key alone, no cold-key passphrase); the command prints a warning saying so. `--remove-copies` unlinks the copies after the migrated file passes `VerifyFile` and opens, and keeps them with a message when either fails; deletion is best effort on modern storage (no overwrite is attempted, the bytes may remain). The migration also records a role history from the stored verification key for a Calidus or Catalyst voting signing key that has none. Every other command on a workspace of format 2 refuses, names `spo workspace migrate`, and derives no key first.

`spo wallet rename OLD NEW`, `spo pool rename OLD NEW`, `spo drep rename OLD NEW`, `spo committee rename OLD NEW` and `spo policy rename OLD NEW` give an owner another name. A name is a label, so one record is replaced and no other record of the workspace changes; a name another owner of the kind has is refused.

`spo <kind> merge NAME --from DIR [--as NAME]` (same five kinds) declares an owner of an upstream directory the same as `NAME` in the workspace when their member sets are identical: the workspace keeps its anchor and records the directory's as an alias. It resolves the residual case of the wallet anchor rule (a wallet made stake-only here that gained a payment key; the directory's copy is anchored by its payment key), which an import refuses, showing both. Owners with different member sets cannot merge.

### `init`

```
spo init --network {mainnet,preprod,preview} [--mode {online,light,offline}]
         [--recovery-key-fd N] [--yes]
```

Creates the directory if needed, then `spo.toml` and `workspace.spo`. Refuses when either file exists. Default mode: `offline`.

* The passphrase is asked for twice without echo, or read once from `--passphrase-fd`. It must be at least 12 characters; an empty passphrase is refused. There is no other strength rule.
* The recovery key is shown once, with an instruction to write it down. The operator must then type back its last group (4 characters, case-insensitive; three tries).
* With `--recovery-key-fd N` (which requires `--passphrase-fd`), the key is written to descriptor `N` and neither shown nor confirmed. `N` must be the write end of a pipe or a Unix socket (a password manager, or the process that consumes the key): a regular file, a directory, a device or terminal, descriptors 0, 1 and 2, and a closed or read-only descriptor are refused before anything is created, because a secret is never written to a file ([Xcustody](../../spec/extensions/Xcustody.md) OUT-005, PRE-006). The same rule applies to `--recovery-key-fd` of `store` commands. If the pipe then fails on write, `init` removes the workspace it just created, since the recovery key went nowhere. A network socket is refused too. `spo` can only check the descriptor: if the program reading the pipe writes the key to a file, the key is on disk in the clear, and that is outside what `spo` can prevent.
* `--mode light` prints what Koios will learn (the pools, addresses and stake addresses queried, the transactions submitted, the requester's network address) and asks `[y/N]`. The default is no; nothing is created on no. `--yes` answers yes, and the statement is still printed. `--mode offline` and `--mode online` configure no provider; for online mode name the node afterwards with `spo provider set node`.

### `store verify`

```
spo store verify [--backup FILE] [--checkpoint FILE.checkpoint --pin PIN] [--layout DIR --pin PIN [--at SEQ] [--locked]]
```

Opens the workspace (or `FILE`) read-only and checks every record's authentication and the audit chain. Writes nothing. Prints the chain head (sequence number and MAC, hex) and every notice, among them "N cold records without a recovery wrap" (same rule as `store slots`). It also notes each cold record that was healed from its previous wrap, and it FAILS (non-zero exit) while a cold record is out of step with the workspace: a header kind that does not match the policy, a FIDO2 credential that belongs to no current daily slot, or a record a rotation or recovery left under its old factor (`--leave-unreachable`); each is named as `kind/label`. `--with-cold-factor` asks for the factor with no read snapshot held. It does not need `--accept-rollback`.

Record the head somewhere other than the workspace directory. Replacing both `workspace.spo` and its head file by an older matching pair cannot be detected from the files; comparing with a recorded head can.

With `--backup FILE --checkpoint FILE.checkpoint --pin <workspace id>:ck:<key hash>[:<minimum sequence>]` only the pair is checked, and no passphrase is asked: the checkpoint's SSH signature against the pinned key hash (user presence and user verification must be set), the workspace id and the minimum sequence, then the file's SHA-256, size, workspace id, head and slot-table hash against the signed statement. It does not open the backup; run `store verify --backup FILE` for that. SPO-Xbackup-OUT-016.

### `store backup`

```
spo store backup DEST [--no-checkpoint] [--checkpoint-device PATH] [--checkpoint-pin-fd N]
spo store backup --sink URL [--no-checkpoint] [--checkpoint-device PATH] [--checkpoint-pin-fd N]
```

Writes a consistent copy of `workspace.spo` to `DEST` (must not exist, mode `0600`), then verifies the copy and prints its head. The copy opens with the passphrase and recovery key of the moment it was made; a later passphrase change or new recovery key does not reach it. It does not include `spo.toml`.

With `--sink URL` (`s3://bucket/prefix` or `dir:/absolute/path`) the verified copy goes to a sink instead of `DEST`; exactly one of the two is given. The object is `backups/<workspace id>/<head sequence, 20 digits>-<sha256>.spo`. An S3 sink is refused for a `standard` workspace and for a bucket that has no versioning, no Object Lock in COMPLIANCE mode with a default retention, or credentials that are not short-lived; (all of this is checked before the workspace is unlocked, so no passphrase, PIN or touch is asked) and credentials must expire within 12 hours and the endpoint must be https; a directory sink is allowed for every policy and prints the `standard` warning. The copy is verified, sent with its SHA-256, read back and compared; then the command prints the object, the head and a `Pin:` line (`<workspace id>:<head sequence>:<head hash>:<file sha256>`) with the advice to keep the pin somewhere other than the sink. An interrupted run says what state is left and can be run again; see [Back up to a sink](../how-to/back-up-to-a-sink.md). [Xbackup](../../spec/extensions/Xbackup.md). Nothing has been run against a real bucket.

**The checkpoint (ADR 0012 stage 2).** When the workspace has a checkpoint key ([`workspace checkpoint-key`](#workspace-checkpoint-key)), a backup to a sink is also signed: after the object has been put and read back (nothing is asked of the checkpoint authenticator before that), the checkpoint authenticator asks for its PIN (`--checkpoint-pin-fd` or a prompt; `--checkpoint-device`) and one touch, and the signed statement is put as `backups/<workspace id>/<sequence>-<sha256>.checkpoint`, create-if-absent and read back. The command prints the exact `Pin:` and a `Long-lived pin:` (`<workspace id>:ck:<checkpoint key hash>`) with the sentence that adding `:<sequence>` makes a restore refuse anything older. A signing failure after a verified upload is "uploaded and verified, but NOT signed", with the exact pin and a non-zero status; run the command again and it signs without uploading again. `--no-checkpoint` skips signing. With no key the behaviour is stage 1. A backup to `DEST` with a key writes `DEST.checkpoint` beside it (mode 0600, never overwritten). SPO-Xbackup-OUT-013, OUT-014.

### `store backups`

```
spo store backups --sink URL [--pin <workspace id>:ck:<key hash>] [--below SEQ]
```

Lists the backups of this workspace id in the sink, newest first (sequence, size, SHA-256, object name, and whether a checkpoint sits beside it). With `--pin` it also reads the checkpoints (at most 16) and says whether each verifies against the pinned key hash. SPO-Xbackup-OUT-016. A name under the workspace's prefix that does not parse is listed as `unrecognised (ignored)`. It asks for no passphrase and downloads nothing. Names that a sink supplied are printed quoted, with control and non-printable characters escaped.

With `--layout DIR --pin PIN` the sealed object layout in `DIR` is checked and nothing is changed (SPO-Xlayout-IF-002). `--pin` is required: `<workspace id>:layout:<sequence>:<head hash>`, the long-lived `<workspace id>:ck:<key hash>[:<minimum sequence>]`, or `local`. A locked pass (pin, head chain, signatures, slots object and manifest root by hash, the unlock-policy check) asks for no credential; `--locked` stops there. An unlocked pass opens every object with the workspace credential (never a passphrase for `hardware` or `strict`; `--unlock recovery-composite` is refused), checks INV-007 to INV-011 and INV-017, and writes the rebuilt rows into a private scratch store file that must pass the store's full verification. A failing head stops the check and is named; `--at SEQ` uses an older head the pin accepts. The slot table that picks the credential must be one the pin vouches for (the pinned head's, or a later one that is not weaker, binds the same recovery key and names only this workspace's RP id), else the check refuses before any prompt (PRE-028); a signature counts only for a key the pin vouches for (PRE-029); the slots object is at most 256 KiB (PRE-027). SPO-Xlayout-PRE-020 to PRE-026, OUT-020 to OUT-022, INV-024 to INV-026.

### `store convert`

```
spo store convert --to-layout DIR [--no-checkpoint] [--adopt-layout] [--checkpoint-device PATH] [--checkpoint-pin-fd N]
spo store convert --from-layout DIR --pin PIN [--at SEQ] [--force] [--allow-older] [--allow-other-workspace] [--allow-weaker-policy ...] [--accept-lower-counters] [--network NAME]
```

`--from-layout` checks the layout as `store verify --layout` does and installs it as the workspace through the path of `store restore`: the counter rule, the weaker-policy refusal, older or diverged, another workspace and the checkpoint-key carry all apply, and an existing workspace needs `--force`. It never writes a store file onto the destination itself, opens no record payload, retires nothing, and records the layout pin beside the new workspace so a later `--to-layout` continues the chain. In an empty directory it writes `spo.toml` (`--network` is needed) and, since nothing was replaced, says that no counter was compared (as `store restore` now does into an empty directory). The layout pin is recorded only for a head note the workspace would have written. `--pin`, `--at` and the restore flags are refused with `--to-layout`, the checkpoint flags with `--from-layout`. A hardware or strict layout costs two authenticator touches for a verify and three for an import. SPO-Xlayout-IF-003, OUT-023, OUT-024, PRE-025, PRE-026. The text below is the `--to-layout` direction.

ADR 0012 stage 3, work package 3 ([Xlayout](../../spec/extensions/Xlayout.md); how-to: [Convert a workspace to a sealed layout](../how-to/convert-to-a-sealed-layout.md)). Writes the workspace into the local directory `DIR` as sealed, padded, content-named objects (`objects/<aa>/<hash>`), the manifest, the plaintext slots object and a head note (`heads/<sequence, 20 digits>`). The workspace file is not changed and stays the only writable store; nothing is retired. The other direction, and the check of a layout, are described above; there is no read-only open yet.

| Option | Meaning |
| --- | --- |
| `--to-layout DIR` | Required. An absolute or relative path or `dir:/absolute/path`. Empty or new, or already a layout of this workspace. Not the workspace directory or inside or above it, owned by you, not group- or world-writable. An `s3://` URL is refused. |
| `--no-checkpoint` | Do not sign the head although the workspace has a checkpoint key. |
| `--adopt-layout` | Trust an existing layout in `DIR` that this machine has no pin for, when the workspace has NO checkpoint key. With a key it never overrides a head that fails verification. The tool prints what it trusts (sequence, audit sequence, hash, time) before it records the pin. |
| `--checkpoint-device PATH`, `--checkpoint-pin-fd N` | The checkpoint authenticator and where its PIN is read, as for `store backup`. |

The workspace is unlocked as for any command (`--passphrase-fd`; `--fido2-device`, `--fido2-pin-fd` for `hardware` and `strict`); `--unlock recovery-composite` is refused. Every refusal that needs no secret is made before anything is asked (anything in `DIR` that is not a layout's regular file, including a FIFO or a link, is refused by name). Every object a head will name is read and hashed in the run, and a file with the wrong content under an object's name refuses the export (a fresh directory is the remedy); a signature file counts only when it verifies against the checkpoint key; heads above this machine's pin are chained onto only when they link, leave no gap and (with a key) verify. Every head built on must be this workspace's history (audit position and MAC; epoch and recovery key since the last rotation). An export interrupted between a head and its signature is completed by the re-run under strict conditions (OUT-019). SPO-Xlayout-PRE-018, PRE-019, OUT-019, INV-018 to INV-023. A single-writer lock (`DIR/.spo-export.lock`) is held for the whole run. Objects are put first (each create-if-absent and read back), then the manifest, then the head; an object that is already there is found, not written again, and with nothing changed since the newest head no head is written ("already up to date"). With a checkpoint key the head note is signed (namespace `spo/head-provisional/v1`) after everything else succeeded and put as `heads/<sequence>.sig`; a signing failure writes no head. Output: counts of objects written and reused, the head sequence and hash, `Pin: <workspace id>:layout:<sequence>:<head hash>` (also kept forward-only in `workspace.spo.layout-<16 hex>.pin` beside the workspace file), `Long-lived pin:` when signed, the advice that an unsigned head protects against accidents only, and a paragraph on what a reader of the directory sees. SPO-Xlayout-IF-001, OUT-014 to OUT-018, PRE-013 to PRE-017, SEC-006, SEC-007, INV-012 to INV-014.

### `store restore`

```
spo store restore (BACKUP | --sink URL --pin PIN | --sink URL --pin <workspace id>:ck:<key hash>[:<minimum sequence>] [--below SEQ]) [--force] [--allow-older] [--allow-other-workspace] [--allow-weaker-policy
                         [--recovery-key-in-fd N] [--current-recovery-device PATH] [--recovery-pin-fd N]] [--network NAME]
```

Verifies `BACKUP` with its passphrase, or through its FIDO2 factors when it is a backup of a `hardware` or `strict` workspace (the daily authenticator: `--fido2-device`, `--fido2-pin-fd`), and installs it as `workspace.spo`, rewriting the head file from it, so the restored workspace opens normally. A backup whose unlock policy is weaker than the workspace it would replace is refused with or without `--force` and `--allow-older`; see `--allow-weaker-policy`.

| Option | Meaning |
| --- | --- |
| `--sink URL`, `--pin PIN` | Download the backup the pin names from a sink instead of reading `BACKUP`. The file is used only when its SHA-256, workspace id and head equal the pin's; then the restore below runs on it unchanged. A restore without a pin is refused. With the long-lived pin `<workspace id>:ck:<checkpoint key hash>[:<minimum sequence>]` instead, the newest backup whose checkpoint verifies is used: at most 16 candidates newest first; for each the checkpoint (at most 16 KiB) is read and verified against the pinned key hash, workspace id, minimum sequence and the object's own name, and only then is the object downloaded and its size, SHA-256, workspace id, head and slot-table hash checked against the statement; a candidate whose checkpoint does not verify is reported and skipped; once a checkpoint verified for sequence N it is a floor: an object that is missing or does not match refuses the restore and names N, and an older backup needs an explicit `--below N`. `--below SEQ` starts the search below a sequence (also after a stop at a limit, which says how many candidates were not examined). A transport or restore failure ends the search, and no valid candidate is a refusal. **Without a sequence the pin proves the backup is authentic, not that it is the newest**: a sink can hide newer backups and offer an older valid one (SPO-Xbackup-SEC-019). An interrupted download is resumed by running the command again with the same pin (partial file `.spo-fetch-<sha256>.partial`, mode 0600, in the workspace directory). The flag combinations that can be checked without the file (an existing workspace needs `--force`, `--allow-weaker-policy` and `--allow-other-workspace` need `--force`) are checked before anything is downloaded; a refusal after the download that is not about the file (a wrong passphrase or PIN) keeps the verified file for the re-run. `--allow-older` works with `--sink` under the counter rule below. |
| `--force` | Replace an existing workspace. |
| `--allow-older` | Accept a backup that is older than the workspace or has diverged from it. Without it such a restore is refused, because it discards every change made since. The counter rule applies: the operational-certificate and KES counters of the workspace are carried forward, never lowered (below). |
| `--accept-lower-counters` | Go on although the counters of the workspace being replaced cannot be fully read because its file is unusable: it does not parse as a workspace or fails verification (nothing is compared), or it is older than its head file with no restore sidecar (the counters in the file are still carried as a floor, and the true counters may be higher: a warning says to check on chain). The restored copy records an audit event. Never honoured for a credential problem, a busy file or an I/O error, and never applies when the workspace being replaced can be opened and its head file agrees. |
| `--allow-other-workspace` | Dangerous. Accept a backup of a different workspace; the current workspace and all it holds is lost. Prints a warning. Needs `--force`. |
| `--allow-weaker-policy` | Accept a backup whose policy is weaker than the workspace's (`hardware` or `strict` replaced by an older `standard` copy). Needs `--force` and the current workspace's recovery credential, checked on the current file before anything is replaced: the recovery key (`--recovery-key-in-fd` or a prompt) and, under `hardware`, the second authenticator (`--current-recovery-device`, PIN from `--recovery-pin-fd` or a prompt). A `strict` workspace has none and is never replaced by a weaker backup. SPO-Xunlock-PRE-033. |
| `--network NAME` | When the directory has no `spo.toml`, write one for `NAME` in mode `offline` (change it with `mode set`). Required in that case. |

**The counter rule.** A restore never lowers an operational-certificate counter or a KES counter of the workspace it replaces (ADR 0012 decision 9; [Xbackup](../../spec/extensions/Xbackup.md) PRE-011 to PRE-014). It applies whenever the destination exists and can be opened, whatever its workspace id and whether or not the backup contains its head (a chain can hold a lower counter: `pool opcert issue --counter N` writes N+1 whatever was stored). The destination is opened read-only with the credential given for the backup; when its slots changed since, with its own recovery key (`--recovery-key-in-fd` or a prompt; under `hardware` also `--current-recovery-device` and `--recovery-pin-fd`), asked for only then. If neither opens it the restore refuses, names those flags and shows no value; for a `strict` workspace, which has no recovery key or recovery authenticator, the refusal says instead that it can be opened only with one of its own enrolled authenticators and, if none is left, that the file is to be moved aside, the backup restored into the empty directory and every pool's counter checked on chain (SPO-Xbackup-PRE-015); `--accept-lower-counters` is not honoured for a credential problem (if the credentials are lost, move `workspace.spo` aside and restore into the empty directory; nothing is compared). Per pool, the issue counter (`node.counter`) and the KES counter-next (`kes.counter-next`) are written into the restore's private copy when the destination's is larger, as one audited write with an event per counter, before the copy is installed; a KES key generated and not yet used for a certificate that the backup lacks moves counter-next past its number. The command prints each. `kes.counter` (the newest key) is not carried. A counter record that cannot be carried is refused naming the pool. A destination that does not parse or fails verification compares nothing and refuses with `--accept-lower-counters` as the way through (a file that is not a workspace at all, replaced with `--allow-other-workspace`, needs `--allow-weaker-policy` and `--accept-lower-counters` too; the first refusal names them all). A destination that unlocks but whose head file is ahead of it (rolled back, or the head file rewritten) refuses saying the true counters may be higher, and with the flag its own counters are still carried as a floor, with a warning. The rule never applies as a shortcut: a credential that does not open the destination is a refusal with or without `--allow-older`. A read-only open can leave an empty `-wal` and `-shm` beside the destination until the swap or the next open.

### `workspace checkpoint-key enroll|show|remove`

ADR 0012 stage 2 ([Xbackup](../../spec/extensions/Xbackup.md); how-to: [Back up to a sink](../how-to/back-up-to-a-sink.md#the-checkpoint-key-and-the-long-lived-pin)). The checkpoint key is a FIDO2 credential used as an OpenSSH security-key signing key (`sk-ecdsa-sha2-nistp256@openssh.com`, application `ssh:spo-checkpoint`); the workspace keeps its public key, credential id and key hash in one sealed record.

```
spo workspace checkpoint-key enroll --checkpoint-device PATH [--checkpoint-pin-fd N]
        [--recovery-key-in-fd N] [--recovery-device PATH] [--recovery-pin-fd N]
        [--old-checkpoint-device PATH] [--old-checkpoint-pin-fd N]
spo workspace checkpoint-key show
spo workspace checkpoint-key remove [same recovery and --old-checkpoint-* flags]
```

* `enroll` makes the credential (the authenticator asks for its PIN and a touch) and records it. The authenticator may not be the one the command unlocked the workspace with (compared after auto-pick and symbolic links are resolved) and is probed, without a touch, for each daily slot's credential and refused if it holds one (not under `standard`, which has none; the probe has not been run on a real authenticator); it may be the recovery authenticator (the recovery token is then used at every backup). The first key needs only the unlocked workspace. It prints the key hash, the SSH fingerprint, the SSH public key line and the long-lived pin. The flag is `--checkpoint-device`, not `--fido2-device`, because `--fido2-device` already names the authenticator that unlocks a `hardware` or `strict` workspace.
* Replacing an existing key, and `remove`, need the current recovery credential under `standard` and `hardware` (`--recovery-key-in-fd` or a prompt; under `hardware` also `--recovery-device` and `--recovery-pin-fd`), presented before any credential is made. A `strict` workspace has no recovery path: it needs a signature by the EXISTING key (`--old-checkpoint-device`, `--old-checkpoint-pin-fd`) over a replacement statement (namespace `spo/checkpoint-replace/v1`). SPO-Xbackup-PRE-016 to PRE-018.
* `show` prints the same facts. A workspace rotation keeps the record (SPO-Xbackup-PRE-019). `store restore` carries it into a restored workspace whose backup has none, keeps the backup's own when it differs (naming both hashes), and with the long-lived pin says whether the restored key is the pin's (SPO-Xbackup-PRE-020). `store verify` reports the record as present and `--deep` parses it (PRE-021). `init --policy hardware|strict` and `workspace migrate` say no key is enrolled (PRE-022).

### `workspace slot list|add-fido2|remove`, `workspace policy show|set`, `workspace rotate`, `init --policy`, `node export`

ADR 0011 ([Xunlock](../../spec/extensions/Xunlock.md), [Xcustody](../../spec/extensions/Xcustody.md)). How-to: [slots, policy, rotation and node export](../how-to/slots-policy-and-rotation.md).

* `workspace policy show` and `workspace slot list` read the policy and the slot table without any key (kinds, ids, factor kinds; a slot carried over from store format 2 is marked "legacy (rekey to bind policy)"). A FIDO2 factor shows the stored result of the touch probe made at enrolment: `touch enforced`, `touch not enforced` (the authenticator returned its secret to an assertion without a touch: the touch requirement of a cold-role key is then a stated residual risk) or `touch enforcement not confirmed`. "Two different authenticators" is checked by device path and credential only; one token unplugged and plugged again would pass, so use two physically separate tokens.
* `workspace slot add-fido2` opens the workspace, enrols the authenticator named by `--fido2-device` (credProtect 3, hmac-secret, user verification) and adds a `fido2-hmac` slot; under `standard` that is a convenience, not a strengthening, and a legacy-only workspace must be rekeyed first.
* `workspace rotate --policy standard|hardware|strict` (and `workspace policy set`, the same operation) replaces the workspace key and every data key, re-encrypts every payload and writes the slot table of the policy in one transaction. **It makes no copy of the file** (a copy opens with the credentials the rotation revokes); `--keep-copy FILE` asks for one (never overwriting, mode 0600, removed again if the rotation fails; the command says it opens with the OLD credentials and is to be destroyed once the new factors are confirmed). A rotation of a workspace that has a recovery path first asks for the **current recovery credential**: the recovery key (`--recovery-key-in-fd N` or a prompt) and, under `hardware`, the recovery authenticator (`--current-recovery-device`, default `--recovery-device`, PIN from `--old-recovery-pin-fd` or `--recovery-pin-fd`); the daily credential alone cannot rotate. A `strict` workspace has no recovery path and is not loosened. `hardware` needs the new daily authenticator (`--new-fido2-device`, default `--fido2-device`; PIN `--new-fido2-pin-fd`, or `--fido2-pin-fd` when it is the session device) and a different `--recovery-device`; each authenticator has its own PIN (`--fido2-pin-fd`, `--new-fido2-pin-fd`, `--recovery-pin-fd`, or one prompt each that names the role and the device), and the PINs are checked before any credential is made. After a lost daily authenticator the session is opened with `--unlock recovery-composite --fido2-device RECOVERY-DEVICE`: then `--fido2-device` is the current recovery authenticator, `--new-fido2-device` is required and may not be that device, and the recovery key typed for the session is presented again as the proof. Cold-role keys are re-established through their recovery wraps; a cold record that cannot be re-established refuses the rotation, naming it as `kind/label`, unless `--leave-unreachable kind/label` (repeatable) accepts leaving it under its old cold factor (the recovery credential must be presented; a `cold-left` event is audited and `store verify` fails until it is re-established). `workspace slot add-fido2` is refused in a recovery-composite session. `--unlock recovery-composite` is accepted only by `workspace rotate`, `workspace policy set` and `store slots`; another command refuses it before any prompt. `--new-passphrase-fd N` (standard table) and `--recovery-key-in-fd N` (the recovery key of the session and the proof) make the flow scriptable; a recovery-session's recovery key is used once and destroyed. A cold mnemonic made with `--account` or `--index` other than 0 records that path in its record, so a rotation re-establishes it. A record left with `--leave-unreachable` carries a left mark: `store verify` fails and `store slots` lists it until a rotation re-establishes it. `strict` needs `--yes-strict` and has no recovery key. The new recovery key is delivered as `store passphrase change` delivers it (`--recovery-key-fd`). A rekey makes a passphrase and a recovery slot, so it is refused under `hardware` and `strict` with a message that names `workspace rotate`; under `standard` `store passphrase change` and `store recovery-key new` first present the current recovery key (`--recovery-key-in-fd` or a prompt), and `passphrase change` keeps that key. A strict rotation needs `--yes-remove <slot id>` for every slot it removes.
* `workspace slot remove <id or its first characters>` removes a slot by a rotation that re-creates the others (their factors must be present; a recovery slot or composite that stays gets a new recovery key), with the same recovery presentation and flags as `rotate`, and refuses the last slot the policy needs. The removal is in the audit chain.
* `init --policy hardware|strict` creates the workspace under that policy at once (`--fido2-device`, `--recovery-device`, `--fido2-pin-fd`, `--recovery-pin-fd`, `--recovery-key-fd`, `--yes-strict`); no passphrase is asked. The file `workspace.spo.init-pending` marks it unfinished until the rotation has committed. An unknown rotation outcome is settled from the file's policy; a kill between the first workspace and the commit leaves a marker that the next `init` finds, and it removes the leftover only after confirmation (`--remove-unfinished` or `y`). SPO-Xunlock-PRE-035.
* A rotation and `workspace slot remove` write an audit event per removed slot id (`slot-removed`, kind, id). SPO-Xunlock-OUT-017.
* `node export` seals a pool's hot keys to a block producer (see [`node export`](#node-export) below).
* `store backup` prints a warning that names the offline-guessing exposure when the workspace has the `standard` policy.

Session flags: `--unlock passphrase|fido2|recovery-composite` (default: the passphrase when the workspace has a passphrase slot, else `fido2`), `--fido2-device PATH`, `--fido2-pin-fd N`. In a FIDO2 session the approval gate of `party approve` asks the authenticator again (PIN and touch) instead of the passphrase, and `store backup`/`store verify` verify through the factors. With no FIDO2 factor source in the binary (the libfido2 tools are not in the toolchain manifest) a command that needs one fails before it prompts. Cold-role keys (ADR 0011 decision 6; [how-to](../how-to/slots-policy-and-rotation.md#cold-keys-what-asks-for-the-factor-and-when)): a signing key whose identity has a cold role is sealed under a sub-key, so a command that writes, imports, migrates, signs with or rotates such a key asks for a factor at that moment: `--cold-passphrase-fd N` (the sub-key passphrase, standard; also a prompt, twice when a sub-key is made, never the workspace passphrase), `--new-cold-passphrase-fd N` (the table a rotation writes), or the daily authenticator again under `hardware` and `strict` (`--fido2-device`, `--fido2-pin-fd`; one assertion per cold key per operation). A binary that has no source for the policy refuses before asking. `store verify --deep` reports how many cold-role payloads it could not open; `--with-cold-factor` opens them read-only. `workspace import` refuses a pool whose VRF or KES verification key has the Ed25519 identity of a key the workspace knows in another role. A cold key also carries an HPKE wrap to the recovery public key (not under `strict`), so a rotation through the recovery credential re-establishes it.

### `store slots`

Lists key slots: kind (`passphrase`, `recovery`, `fido2-hmac` or `composite`), id, and the key-derivation parameters of a passphrase slot or the factors of a factor slot. A slot carried over from store format 2 says so (it binds no policy and no recovery key; a rekey replaces it). Nothing secret. When some cold-role records have no recovery wrap (a workspace migrated from store format 2 before its first rekey; never reported under `strict`, which has none by design) it ends with "N cold records without a recovery wrap" and the command that adds them (`store passphrase change`, or `store recovery-key new`). The count needs the workspace key and no cold factor: the wrap is authenticated by the outer layer of the cold record. It also lists, by `kind/label` and reason, the cold records that are out of step with the workspace (the same ones `store verify` fails on). No command adds, removes or opens through a FIDO2 slot yet (see the handoff).

### `store passphrase change`

```
spo store passphrase change [--old-passphrase-fd N] [--new-passphrase-fd N] [--recovery-key-in-fd N]
```

Replaces the passphrase. The **old passphrase is typed again**, from a prompt of its own (`Old passphrase (type it again)`) or `--old-passphrase-fd`, apart from the passphrase the session was opened with (SPO-Xunlock-PRE-036); a typing that differs, or no way to ask, refuses before anything else is asked. Then the current recovery key is presented (`--recovery-key-in-fd` or a prompt), and the new passphrase is asked for twice or read from `--new-passphrase-fd`; the 12-character minimum applies. The workspace key is replaced, the recovery key **stays the same** and no new one is made. Backups made earlier keep the old passphrase. The command is refused in a FIDO2 session and under `hardware` and `strict` (use `workspace rotate`).

### `store recovery-key new`

```
spo store recovery-key new [--recovery-key-fd N]
```

Opens with the current passphrase, replaces the workspace key and shows the new recovery key once (type-back check). **The old recovery key no longer works**: a recovery key cannot be added beside another without leaving the old one able to open the workspace, so making one always revokes the old. There is no `--remove-old`, and no command that adds a recovery key without revoking. `--recovery-key-fd` requires `--passphrase-fd`.

### `store recover`

```
spo store recover [--recovery-key-in-fd N] [--new-passphrase-fd N] [--recovery-key-fd N]
```

For a lost passphrase. Reads the recovery key without echo, or from `--recovery-key-in-fd`; the printed grouped form is accepted, in any case, with or without dashes and spaces. Then requires a new passphrase (asked twice, or `--new-passphrase-fd`; 12-character minimum), replaces the workspace key and shows the new recovery key once. The key just used no longer works. This is the only command that reads a recovery key. `--passphrase-fd` is refused here. `--recovery-key-fd` requires both `--recovery-key-in-fd` and `--new-passphrase-fd`. It re-establishes the cold-role keys under a new cold-key passphrase (`--new-cold-passphrase-fd N`, or two prompts) and refuses, naming each such record, when one cannot be re-established; `--leave-unreachable kind/label` (repeatable) accepts leaving a named record under its old cold factor. It refuses on a `hardware` or `strict` workspace and names the recovery-composite procedure above.

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

### `provider set`

```
spo provider set {koios,blockfrost} [--url URL] [--yes]
spo provider set node ADDRESS [--timeout-seconds N]
```

`node` names a cardano-node's socket (see [Online mode](#online-mode-and-the-node-provider)): it writes `[node]` with `address` and, with `--timeout-seconds` (1 to 600, default 30 per operation), `timeout_seconds`. `ADDRESS` is a socket path, `unix:PATH` or `tcp://host:port`. The node is your own, so there is no privacy statement and nothing to confirm; the node is not contacted. A `tcp://` address that is not loopback is accepted and the plain-TCP warning is printed (below). `provider token set node` is refused: the socket has no token.

Names a chain provider: writes `[koios]` or `[blockfrost]` to `spo.toml`. Koios takes the network's public endpoint, or `URL`. `blockfrost` is a Blockfrost-compatible API: the public service of the network (`https://cardano-<network>.blockfrost.io/api/v0`), or `URL` for a self-hosted Dingo; the section keeps only an override. Prints the privacy statement and asks `[y/N]` first (default no). A provider is never configured without this step. URLs must be https, except to a loopback address.

With both configured, the harmful-class reads (reward balance and deposit before a deregistration, pool registration, DRep deposit) are cross-checked: see [Two providers](#two-providers-and-the-cross-check).

### `provider order`

```
spo provider order {node,koios,blockfrost}...
```

Sets `[provider] order`: the first named provider answers reads, the next is the second source of the harmful-class reads. Every name must have its section and none may be named twice (a second source must be a different provider). Without it the order is node, koios, blockfrost (the node, when configured, first). In online mode the order also decides which web providers may be asked at all (below).

### `provider token set`, `provider token clear`

```
spo provider token set {koios,blockfrost} [--token-fd N]
spo provider token clear {koios,blockfrost}
```

Store or remove the provider's API token (for Blockfrost, the project id) as a secret record in the sealed workspace. `set` reads the token without echo or from `--token-fd`; with neither a terminal nor `--token-fd` it fails with "no terminal to ask for the token on". The token is not written to `spo.toml` and is never printed. In light mode it is loaded from the store when a command starts and given to the client. The Blockfrost record is named `blockfrost`, or by `token_record` in `[blockfrost]`.

### Two providers and the cross-check

```toml
[koios]
[blockfrost]
url = "https://cardano-preview.blockfrost.io/api/v0"   # optional; a Dingo's root for a self-hosted one
token_record = "blockfrost"                            # optional; the Secret record holding the project id
[provider]
order = "koios,blockfrost"                             # optional
```

`same_host_ok = true` under `[provider]` (not set by any command; edit `spo.toml`) acknowledges that two providers that share a host are independent. Without it a cross-check whose two sources share a normalised host (the host name lower-cased, without port; a loopback address, `localhost` and a Unix socket all count as this machine; no name is resolved) is refused when the Env is built. It weakens the check: independence means different operators running different chain followers, and `spo capabilities` says when the setting is on and which cross-checks it let through. The comparison is of names, not of machines: it does not resolve a name, so two different names for one machine (a DNS alias, a reverse proxy in front of two services) pass it. Numeric IPv4 forms (decimal, hexadecimal, octal, short), IPv4-mapped IPv6 addresses, IPv6 zones, case and trailing dots are read as one address; all of 127.0.0.0/8 and `::1` are this machine. When the setting was what let a cross-check through and the command relied on that cross-check, the transaction summary says so: "the two sources share a host (...); independence acknowledged in spo.toml (same_host_ok)". A control character or bidirectional control in a provider URL or the node address is refused when `spo.toml` is read or written.

A web provider that answers or corroborates a read of this class, as the first source or as the second, must have a tip less than ten minutes old, judged by the time the provider states for its tip (Koios `block_time`, Blockfrost `time`) against this machine's clock; otherwise its answer is Unknown with the reason, and the command refuses or, with `--single-source`, goes on with the first source (a first source that is stale has no answer to go on with: the command refuses, or needs `--allow-unverified` where that flag exists). The message gives both times. A machine clock more than ten minutes off makes every web source look stale, or hides a stale one: the message says that the local clock may be the wrong one, so check it first. A node has the sync check instead. A node used as a second source must pass the same sync check as the node used as the first.

Light mode needs at least one of the two sections. The Blockfrost adapter reads the tip, the protocol parameters, UTxOs by address and by reference, a stake account, a pool, a DRep, and submits. It has no operational certificate counter, no constitution and no governance readers, so a Blockfrost-only workspace lists those as absent, naming the reason, and a command that needs them is refused before any prompt.

The harmful-class reads take the answer of the first provider and ask the second:

| The second provider | Result |
| --- | --- |
| answers and agrees | the command goes on; the summary names both sources; no warning |
| answers and disagrees | refused, naming both providers and both answers; `--single-source` does not override it |
| does not answer (down, refused, not found, unreadable) | refused, naming both providers and the first one's answer; `--single-source` goes on with the first and the summary warns |
| not configured | refused unless `--single-source`, as before |

A field the second provider does not state is not compared. Blockfrost states neither the stake key deposit nor the open governance-action deposits of an account, nor a DRep's deposit, so those values rest on the first provider and the ledger (which rejects a certificate whose deposit differs). Blockfrost therefore cannot be the answering provider for `stake deregister` or `drep retire`: those refuse because no deposit is stated. The registration state, the reward balance, the pool and the vote delegation are compared.

The opcert counter has a second source when the node and Koios are both in play (Blockfrost has no counter); `spo capabilities` lists `reward-account-crosscheck`, `pool-state-crosscheck`, `drep-state-crosscheck` and `opcert-counter-crosscheck` with the second provider, or the reason there is none. The two counters mean different things (Koios: the counter of the pool's last block; the node: the one it enforces). Only equal readings agree. Readings exactly one apart do not (the ledger accepts a certificate numbered n when the stored counter m satisfies m <= n <= m+1, and refuses m+2, so a source one ahead of the truth could get the pool's blocks rejected): the command is refused or the verdict is `UNKNOWN`, with "the two sources differ by one: the indexer may lag the node by a block; retry in a few minutes". Any other difference is a disagreement. A disagreement is a refusal that names both answers (`pool opcert issue`) or an `UNKNOWN` verdict that does (`pool opcert check` and `counter`), and `--single-source` does not override it. If the second provider does not answer the same commands refuse unless given `--single-source`, which goes on with the first one's counter. These three commands take `--single-source` for that reason. A refusal for readings one apart may last a few minutes (an indexer is usually a block or two behind a node): retry. With one provider the counter rests on it: `pool opcert issue` (which signs) refuses unless `--single-source` is given; `check` and `counter` are informational, print the source, and need no flag.

Every use of `--single-source` that was needed (stake, pool register, drep retire, opcert, pool import) is recorded in the workspace audit log: the operation `single-source-read`, the command, what was read, the source and that the flag was given. The record is made before the effect it permits (before anything is signed, submitted, queued or written; for `pool import`, just before the first write, so a dry run or a declined import records nothing), and one record is made per accepted read: `stake deregister` reads the account twice, for the certificate and for the transaction, and writes two. If a record cannot be written the command stops with nothing done. The sealed store holds it in its MAC-chained audit log. A run that had two agreeing sources or was refused writes nothing. The summary prints the warning; when two sources agree but the second does not state deposits, `stake deregister` also says "deposit N lovelace from <first> only; <second> does not state deposits; the ledger refuses a wrong amount".

### Online mode and the node provider

```toml
mode = "online"
[node]
address = "/run/cardano/node.socket"   # a socket path, unix:PATH, or tcp://host:port
timeout_seconds = 30                   # optional, 1 to 600: bounds each operation
[koios]                                # optional: a web provider
[provider]
order = "node,koios"                   # optional: names the web providers that may be asked
```

**This mode has never been run against a real cardano-node.** The node-to-client adapter is tested only against an in-process fake node whose replies are hand-written or encoded by the library, plus one reply copied from a node. Work through [the node-socket checklist](../development/node-socket-checklist.md) on a preview node before relying on it, and treat what it prints as unconfirmed until then.

In online mode every chain read the node implements comes from the node: the tip, the sync state, the protocol parameters, UTxOs, reward accounts, pool and DRep state, the opcert counter it enforces, the governance state (committee, actions, constitution, last enacted action, stake distributions, epoch), and submission. The genesis values come from a genesis file when one is bundled or given, else from the node. The connection is made when a command first reads the chain, once, and closed when the command ends; a command that reads nothing from the chain (key generation, `capabilities`, `provider`, `mode`, a refusal for a missing capability) never connects. An unreachable node gives `unknown` readings that name the address, after at most the timeout; a node that accepts the connection and says nothing is given the timeout and no more.

What the node cannot answer is absent, with the reason in `spo capabilities` and in the refusal of a command that needs it (before any prompt): asset holders (so `ada-handle`), transaction metadata (so `poll-question` and `calidus-registrations`), the time of a pool's last update (`pool-updates`), a voting summary, script evaluation (`plutus-script-evaluation`), and the era name for the air-gap commands (`era`). `tx-queue` and `transfer-attach` are absent too: online mode submits. A Koios or Blockfrost section supplies those, and is the second source of the harmful-class reads, only if the section exists **and** `[provider] order` names it. A configured web provider that the order does not name is never asked in online mode, so no address, pool or transaction goes to a third party unless you wrote it down; `spo capabilities` then names the remedy. `spo capabilities` shows which provider answers each read, and the endpoint (for the node, the socket address). The node answers in online mode whatever the order says. In light mode the order decides: a node first answers (every configured web provider then supplies what it lacks), a node right after the answering web provider is the second source of the reward account, the pool, the DRep and the opcert counter, and a node elsewhere is unused.

**Sync refusal.** As upstream, a command that reads the chain refuses when the node is not synced: the tip of the node must be within two minutes of the clock. The address query, `pool opcert check` and the air-gap commands ask the node's sync check themselves; every other state read of the node (UTxOs, accounts, pools, DReps, the counter, governance state) is gated by the same check, once per command, so a payment, a registration or a vote on an unsynced node stops before anything is built. Light mode has no such check.

**Plain TCP.** Node-to-client has no authentication and no encryption. A `tcp://` address whose host is not loopback is accepted, with the warning `warning: the node address is plain TCP to a non-loopback host. Node-to-client has no authentication and no encryption; use an SSH or VPN tunnel and give a loopback address.` on stderr, once when `provider set node` names it and once, when the connection is first made, by a command that reads the chain. Anyone on the path can read the queries and submit transactions through the connection: forward the socket over SSH or a VPN and give the loopback end.

### `mode set`

```
spo mode set {online,light,offline}
```

Changes `mode` in `spo.toml`. `light` is refused while there is no `[koios]`, `[blockfrost]` or `[node]` section. `online` is accepted without a `[node]` section; its chain capabilities are then absent with the reason "no node address is configured".

### `capabilities`

Prints what the environment of this workspace's configuration provides, from the same `Env` the commands use. It opens no store and uses no network.

* **Chain capabilities**: for each of `tip`, `sync-check`, `opcert-counter`, `protocol-parameters`, `utxo`, `reward-account`, `pool-state`, `drep-state`, `reward-account-crosscheck`, `pool-state-crosscheck`, `opcert-counter-crosscheck`, `tx-submit`, `tx-queue`, `tx-status` (one entry for the configured providers; absent offline), and the governance readers `committee-state`, `governance-actions`, `constitution`, `last-enacted-action`, `stake-distribution`, `epoch`, `voting-summary`, `drep-state-crosscheck`, `plutus-script-evaluation` (light mode with Koios: the provider evaluates the Plutus scripts of a transaction), `ada-handle` and `poll-question`, the provider that supplies it (and its endpoint), or under **Not available** the reason and the remedy, for example "offline mode has no transaction submitter; queue to a transfer file instead" or "no chain provider is configured: spo provider set koios".
* **Local**: clock, genesis, key generation (`kes-keygen`, `vrf-keygen`, `cold-keygen`, `payment-keygen`, `stake-keygen`), `mnemonic-generation`, `wallet-derivation`, `address-building`, address inspection, minimum output, fee estimation, transaction body and assembly, `certificate-building` and `certificate-decoding`, and for the Calidus and Catalyst commands `calidus-keygen`, `voting-keygen`, `voting-key-qr` and `registration-signing` (always) and `calidus-registrations` (light mode: Koios; absent offline), and for the governance commands `drep-keygen`, `committee-cold-keygen`, `committee-hot-keygen`, `governance-derivation`, `vote-file`, `action-file` (always), `anchor-fetch` (light) and `anchor-verification` (never: no verifier is built), and for the pool commands `pool-certificate-building`, `pool-certificate-decoding`, `metadata-hash`, `tx-id` and `tx-view` (always), for the extra parameters and native assets `metadata-file`, `message-encryption` and `policy-id` (always), for the workspace commands `verification-key-derivation` (always) and `key-encryption` (upstream's gpg envelope: only where the binary has a toolchain manifest with `gpg`; needed only for upstream's encrypted keys), `transfer-file` (always: the bundle at `--transfer-file`) and `extract-sink` (always), `era` (offline with a transfer file; light, from the Koios tip), `transfer-attach` (offline, with a transfer file), `metadata-fetch` (light) and `ticker-protection` (never: see [Pool registration](#pool-registration-and-retirement)), `bls-keygen` (always) and `hardware-wallet` (only where the binary has a toolchain manifest that provides `cardano-hw-cli`, a network with a magic, and a workspace; whether a device is connected is not probed: `capabilities` never starts the tool, see [Hardware wallets](#hardware-wallets)). `ada-handle` is present in light mode and absent offline with the reason; for the token registry and the pool import, `registry-signing`, `logo-file`, `verification-key-envelope` and `vrf-verification-key` (always) and `token-registry` (light mode with a registry server: the public one on mainnet, `[registry] url` elsewhere), `pool-info` and `pool-updates` (light mode: Koios); `poll-question` is present in light mode (Koios) only.
* **Signers**: each signer with its profile (role, then the operations it can do).

Offline mode lists `utxo`, `protocol-parameters`, `tx-queue`, `reward-account` and `drep-state` only when the transfer file (`offlineTransfer.json` in the workspace directory) exists. Light mode takes the protocol parameters from the network's hosted light-mode parameters file, as upstream does, and everything else from Koios. Online mode lists the node socket as the provider of every read it implements, and under **Not available** the reads it cannot answer with the remedy (see [Online mode](#online-mode-and-the-node-provider)); with no `[node]` section it says no node address is configured. The Koios adapter reads the committee (`GET /committee_info`), the open governance actions with their votes (`/proposal_list`, `/proposal_votes`), the epoch and era (`/tip`) and the voting summary of an action (`/proposal_voting_summary`); the constitution and the last enacted action ids come from the hosted light-mode parameters document, as upstream's light mode takes them. Every field follows the three-valued rule: an empty, failed or uninterpretable answer is unknown, never none. No adapter reads the DRep and pool stake distribution (upstream's light mode does not; `stake-distribution` is absent in every mode, with the reason) or a second DRep source without a second provider (`drep-state-crosscheck`). Offline mode has none of the governance readers. Readers are picked up by type assertion when an adapter gains the interface.

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
| `online` | The node supplies the tip, the sync check, the counter it enforces and, from its genesis values unless a genesis file is given, the KES parameters. Never run against a real node. With Koios named in the order too, the counter is cross-checked (see above). |

| Option | Meaning |
| --- | --- |
| `--counter N` | Issue with `N` instead of the stored counter. |
| `--single-source` | Needed with one provider (the certificate would rest on one unchecked counter); with two providers (the node and Koios, see [Online mode](#online-mode-and-the-node-provider)) it goes on when the second does not answer. A disagreement, including readings one apart, is never overridden. The acknowledgement is recorded in the audit log and the summary warns. Also on `check` and `counter`, where it applies only to a configured second provider that does not answer. |
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
| `VERDICT: UNKNOWN` | The chain's counter is not known and no check failed: no connection, a pool the provider does not know (an unregistered pool and a wrong network look alike), two providers that disagree about the counter or a second one that did not answer (without `--single-source`), or offline mode. The reason is printed. |

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
| `online` | The transaction is submitted through the node; the output names the tx id and the node. Never run against a real node. |

| Option | Meaning |
| --- | --- |
| `--message TEXT` | CIP-20 message line, at most 64 bytes. Repeatable. |
| `--yes` | Approve without asking. |
| `--transfer-file PATH` | The offline transfer file. Default: `offlineTransfer.json` in the workspace directory. It must exist (made by `01_workOffline.sh new` on the online machine). |
| `--wait`, `--wait-confirmations N`, `--wait-timeout D`, `--no-wait` | After a submission, wait for it to be in a block: see [`tx status`](#tx-status-and---wait-after-a-submission). The wait is the default here, and `--no-wait` skips it (a pending record update, see [Pending records](#pending-records-and-spo-tx-settle)). |
| `--offline`, genesis options | As for `pool opcert issue`. The offline slot needs a Shelley genesis. |
| extra parameters | `--metadata-file`, `--encrypt-messages`, `--message-passphrase-fd`, `--utxo-limit`, `--only-utxo-with-asset`, `--skip-utxo-with-asset`, `--input`: see [Extra parameters](#extra-parameters). |

### `tx status`, and `--wait` after a submission

```
spo tx status TXID [--confirmations N] [--offline ...chain options]
```

Asks every configured provider (Koios, Blockfrost, the node socket; in online mode the web providers named in `[provider] order`) once where the transaction is, prints one line per provider, then a verdict. Needs: `tx-status`. Spec: [Xconfirm](../../spec/extensions/Xconfirm.md).

| Provider | How it knows | What it can say |
| --- | --- | --- |
| Koios | `POST /tx_status` | in a block with `num_confirmations`; a `null` is "has not seen it". No mempool view. |
| Blockfrost | `GET /txs/{hash}`, and `GET /blocks/latest` for the depth | in a block with height, slot and confirmations (latest height minus block height plus one); 404 is "has not seen it". No mempool view. |
| node socket | the transaction's own outputs by reference, then the mempool (local tx monitor) | an unspent output: in a block (no height or depth); held in the mempool: in the mempool; an input of the transaction still unspent, and not in the mempool: "has not seen it". Anything else is unknown. |

The node cannot prove that a transaction is absent from its outputs: an output that was spent after inclusion is not in the UTxO set, so "no unspent output" looks the same as "never included". It reports "has not seen it" only from an unspent **input** (a transaction in a block has spent all its inputs); `spo tx status TXID` has no inputs to give, so for a bare id the node answers "in a block", "in the mempool" or unknown, never "has not seen it". A transaction with collateral is not judged by its inputs, because one that failed phase 2 is in a block with its inputs unspent.

A provider that fails, answers something unreadable, is a web provider whose tip is more than ten minutes behind this machine's clock (checked on every call, not once per command), or is a node that is not synced, is **unknown**, never "has not seen it". The line says why.

Verdict and exit status:

| Verdict | Exit |
| --- | --- |
| confirmed: every provider has it in a block at `--confirmations` (default 1) | `0` |
| pending: seen, but in a mempool only or not yet that deep | `10` |
| not seen: every provider answered and none has seen it | `11` |
| unknown: no provider answered, one answered "has not seen it" while another did not answer, or one saw it and the rest gave no answer (partial) | `12` |
| the providers disagree: one has seen it, another has not; both answers are printed | `13` |
| any other failure (a bad id, no provider configured, offline mode) | `1` |

"Confirmed" is never "final": a rollback is possible while the block is shallow. A depth is the number of blocks from the one that holds the transaction to the provider's tip, that block counting as one; a provider that says "in a block" and not how deep (the node) counts as depth 1 and satisfies `--confirmations 1` only. Whether Koios' `num_confirmations` counts the holding block is not stated by its documentation; the number is used as given.

Every command that submits a transaction in light or online mode (`wallet send`, `send-assets`, `claim-rewards`, the stake commands, `pool register`, `pool retire`, `offline execute`, `poll submit`, `asset mint` and `burn`, and the governance commands that put a transaction on the chain) takes:

| Option | Meaning |
| --- | --- |
| `--wait` | After the command has finished its own work, wait until each transaction it submitted is in a block on every configured provider. Never resubmits and never rebuilds. Ctrl-C stops the wait, not the transaction. |
| `--wait-confirmations N` | Confirmations to wait for. Default 1. |
| `--wait-timeout DURATION` | How long to wait. Default 5 minutes, at most 24 hours. |

The wait polls with a pause of 5 seconds that grows by half each time to 30 seconds. The requests of every poll end by the time left of `--wait-timeout` plus 5 seconds, so a wait ends within 5 seconds of its timeout. The transaction id waited for is computed from the submitted bytes; a provider answer with another id is an error (exit `1`) and is not waited for. When a command submitted several transactions, every outcome is printed and the exit status is the worst: `0` confirmed, `21` expired, `20` timed out, `22` unknown, `23` disagreement, `1` an id that does not match, `130` cancelled (which also ends the wait; the rest are named). Local state the command changes on an accepted submission (the offline queue entry, the audit log, a pending update) is changed before the wait and is not undone by what the wait finds; the one thing a wait applies is a pending update, and only when it ends confirmed (see [Pending records](#pending-records-and-spo-tx-settle)). `--wait` is refused before any prompt, naming `tx-status`, in offline mode (no provider; a queued transaction is submitted later by `offline execute`, where `--wait` applies). A wait ends with one of:

| Outcome | Exit | What it says |
| --- | --- | --- |
| confirmed | `0` | in a block on every provider, with the least depth stated; "this is not final", a rollback can remove it at low depth |
| timed out | `20` | not confirmed in time; it **may still be included** and must not be built again from the same inputs until it has expired |
| expired | `21` | for every provider, on two polls in a row, a tip read before its answer is at least 900 slots (the 10 minute freshness window plus 5 minutes, at 1 s per slot) past the validity bound, and that provider then says it has not seen it: it can no longer be included, and **only this outcome says it is safe to build it again**. Needs the transaction's validity bound, which is read from the signed transaction |
| unknown | `22` | no provider gave a usable answer for the whole wait; nothing is said about the chain |
| disagreement | `23` | one provider has seen it and another has not when the time ran out |
| cancelled | `130` | the wait was stopped; the transaction was submitted and may still be included |

With the node among the providers, "expired" needs the node to say "has not seen it", which it can from the transaction's unspent inputs; with Koios or Blockfrost it needs their positive "not seen". A silent or stale provider, or one without a tip, keeps a wait from ever reaching "expired". "Expired" rests on the providers' answers. Koios and Blockfrost addresses are load-balanced, and the freshness check is a separate request from the status read, so the verdict assumes every server behind the address is within the margin above (15 minutes) of the chain; `spo` cannot check that. A rollback deeper than the margin could also overturn it. With a node you run among the providers this assumption does not apply to the node's answer.

When a submission ends with an unknown outcome (the request may have reached the provider and no answer came back) the error names `spo tx status <id>`, with the id computed from the transaction, and says not to build it again from the same inputs first. A submission is unknown, and a pending record update is kept, after the request may have been sent and: a transport failure, a cancellation or a deadline, an answer that is not a transaction id, a provider status that is not a definite refusal (a 5xx, 408, 425, 429 or anything unexpected; a 4xx other than those is a definite refusal), and a provider that accepted the transaction but answered another transaction id than the one computed from the bytes sent (the message names `spo tx status` with the computed id). The record is removed only on an error that proves the transaction did not leave: a definite refusal, or a failure before it was sent.

### Pending records, and `spo tx settle`

Upstream writes some records when a transaction is *accepted*: the asset record of a mint or burn, the registration record (`regEpoch`, `regSubmitted`) and the retirement record (`deregSubmitted`) of a pool descriptor. An accepted transaction can still never land. `spo` writes them when the transaction is *confirmed* in a block (hazard H9; [Xconfirm](../../spec/extensions/Xconfirm.md)). On an accepted submit, or a queueing, `asset mint`, `asset burn`, `pool register` and `pool retire` write a **pending update** under the transaction id (`<txid>.pending`, in the encrypted store, holding no secret): the transaction id, its validity bound, the date and the update to apply. Nothing else in the record changes. A pool registration also consumes the certificate file and the witness collection at once, and a retirement the retirement certificate, as before. A definite refusal, or a failure before the transaction was sent, removes the pending update; one whose outcome is unknown (including an accepted transaction answered under a different id) keeps it.

These four commands **wait by default** in light and online mode: they behave as with `--wait` at the default depth and timeout and apply the update when the wait ends confirmed. `--no-wait` skips the wait (it cannot be combined with `--wait-confirmations` or `--wait-timeout`); `--wait` is accepted and redundant. A wait that ends in anything but confirmed leaves the update pending, exits with the wait's code (`20` to `23`, `130`) and prints the settle command. Where no provider can say where a transaction is, the command does not wait and says so: it names each pending record, its transaction id and the command `spo tx settle`, and its exit status 0 then means "submitted or queued, the record is pending", not "confirmed". Offline, nothing is submitted, so nothing is waited for. Every other submitting command keeps `--wait` opt-in.

```
spo tx settle [--dry-run] [--confirmations N] [--transfer-file PATH] [--offline ...chain options]
```

Asks every configured provider, as `tx status` does, about each pending update of the workspace. In a block at the depth on every provider: the update is applied, once, and the pending record removed in the same commit (a crash between the two cannot apply it twice). Expired by the strict rule of `--wait` (it needs the validity bound stored with the pending update): the update is discarded with a notice and never applied. Anything else (a mempool, too shallow, not seen but not expired, no usable answer, a disagreement): kept, and reported as waiting, unknown or disagree. It is idempotent. `--dry-run` decides and changes nothing. Exit status: `0` nothing left waiting, `21` an update was discarded as expired, `20` waiting, `22` no usable answer, `23` disagreement (the worst), `1` an update that could not be applied or discarded (the others are still settled and their outcomes still recorded) or a carried record of the transfer file that was refused. It needs `tx-status` and is refused before any prompt, naming it, offline. Where a transfer file is present it also records, in the file's history, the outcome of each transaction `offline execute` submitted that has none (see `offline execute`). `spo tx status` is unchanged.

`pool descriptor show` and `pool witness status` print a `PENDING:` line for a pool with a pending registration or retirement: the descriptor does not record it yet, so the pool is not shown as registered or retired. A workspace written by the previous version, with `<txid>.asset-pending` files, still settles. A pool registration that went through a multi-party witness collection is the same command; the coordinator's "collection closed because it was submitted" notice also takes a pending registration for that body as proof that it was sent.

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

The second sources (`reward-account-crosscheck`, `pool-state-crosscheck`, `drep-state-crosscheck`) exist in light mode when two providers are configured (see [Two providers](#two-providers-and-the-cross-check)). With one provider, or in offline mode, `stake deregister` always needs `--single-source`, and so do `stake delegate` and `pool register` whenever a pool reader exists.

A new pool checked only by Koios and Blockfrost, with no node, can read Unknown: the two must both state the registration and agree, and a pool that one of them does not yet know (or states differently) gives no agreement. Registering that pool (`pool register`, or a delegation to it) then needs `--allow-unverified` (the type comes from the descriptor, the summary lists the skipped check) or a node as one of the sources.

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

`delegation-cert` (upstream `05b`) stores `DELEGATOR.deleg.cert` for a pool id (hex or `pool1...`) or a stored pool name; it needs only `certificate-building` and sends nothing. `delegate` makes that certificate and registers it (upstream `06`, no deposit); `--stored-cert` skips the first step and uses the stored file, because the registration reads the certificate from the store. `--payer` defaults to `DELEGATOR.payment`, the address `wallet new --stake` makes. Needs also: `certificate-building` (not with `--stored-cert`), `certificate-decoding`, `address-building`. The pool registration is a read where a false answer is costly: it needs a second provider that agrees (`pool-state-crosscheck`) or `--single-source`, or `--allow-unverified` when no pool reader exists.

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

The type is decided from the chain when a pool reader exists (light mode) and from the descriptor otherwise; `--type` forces it. A chain check that cannot be made refuses unless `--allow-unverified`; a registration state that rests on one source (no `pool-state-crosscheck`) refuses unless `--single-source`. In light mode the published metadata at `poolMetaUrl` is downloaded and its hash compared with `poolMetaHash` (https only, or http to the loopback; at most 3 redirects, all https; 20 seconds in all; at most 512 bytes; no credentials, cookies or proxy; the User-Agent is `spo`); offline it is not, and the summary says so. The ticker-protection lookup is not built (hazard H6: upstream sends the ticker and the protection key to a third-party URL): `ticker-protection` is absent in every mode with the reason "ticker protection lookup is not built; it will be opt-in and will never send the protection key", and the use case runs without it. After a queued registration the metadata files are attached to the transfer file.

The registration record in the descriptor (`regEpoch`, `regSubmitted`) is written when the transaction is **confirmed**, not when it is accepted or queued: `pool register` waits for the confirmation by default in light and online mode (`--wait-confirmations`, `--wait-timeout`, `--no-wait`; see [Pending records](#pending-records-and-spo-tx-settle)). The certificate file and the witness collection are consumed when the transaction is sent. Until it is confirmed `pool descriptor show` and `pool witness status` say the registration is pending; `spo tx settle` records it later.

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

### `pool import NAME POOL-ID|INFO.json`, `pool export-info POOL-ID FILE`

```
spo pool import NAME POOL-ID|INFO.json [--cold FILE] [--vrf FILE] [--account NAME:PAYMENT_SKEY[:STAKE_SKEY]]...
     [--dry-run] [--continue] [--accept-metadata-mismatch] [--yes] [--single-source] [--transfer-file PATH] [--offline] [genesis options]
spo pool export-info POOL-ID FILE [--attach] [--transfer-file PATH]
```

`import` brings a pool that was set up with other tools into the workspace (upstream `0x_importHelper`; `workspace import` copies a whole upstream directory instead). The second argument is a pool id (56 hex digits or `pool1...`), read from the chain provider, or the path of an info file; an existing regular file is an info file. From the chain (light mode) the registration (`pool_info`), the latest update (`pool_updates`) and the metadata the pool publishes are read; an info file needs no network and works in every mode, which is how an offline machine imports. `NAME` is made plain: a trailing `.json` and `.pool` are dropped and everything but letters and digits removed.

What is written, in one commit (a refusal leaves nothing): the descriptor `NAME.pool.json`; for `--cold FILE` the cold signing key, its verification key and the counter file (the chain's counter plus one; zero when the pool minted no block; an unknown chain counter is refused, never guessed); for `--vrf FILE` the VRF key and its verification key; for each `--account NAME:PAYMENT_SKEY[:STAKE_SKEY]` the payment key (with its address) and, with a stake key, the stake key, the staking address, the registration certificate (deposit from the protocol parameters, so `protocol-parameters` is needed) and, when the cold key is imported, the delegation certificate. An account whose staking address is one of the pool's owners, or its reward account, is recorded in the descriptor; any other is imported and left out of it. A key must belong to the pool: the cold key must hash to the pool id and the VRF key to the registered `vrf_key_hash`, which upstream never checks. A key that upstream encrypted is refused: decrypt it first.

The key files are read in place, never copied elsewhere, never printed and never changed: opened without following a symbolic link, regular files of at most 16 KB, read into guarded memory and sealed; a file others can read is read all the same and a warning is printed. A leading `~` is the home directory. The account name is a file-name prefix and must be a plain name.

Questions, each default shown. With no `--cold`, `--vrf` or `--account` and a terminal, the paths are asked for: `Path of the pool's cold signing key, node.skey (blank to skip)` and the VRF key (a path that fails is reported and asked again), then account names (`blank to end`), each with `payment.skey (blank to give the account up)` and `stake.skey (blank to import the payment key only)`. Upstream pre-fills `node.skey`, `vrf.skey` and `owner`; there is no readline here, so a blank answer skips and nothing is pre-filled. After the accounts, when none is the pool's rewards account: `Currently there is no rewards account included, do you wanna go back and add a payment/staking keypair for the rewards account? [Y/n]`, **default Yes** (it asks for another account); No imports without one and says so. If the published metadata does not hash to the registered `meta_hash`, both hashes are shown and `Import the pool with the published metadata anyway? [y/N]` is asked, **default No** (the metadata text goes into the descriptor); `--accept-metadata-mismatch` answers yes. With no terminal, a question that has no flag is not asked: the key prompts are skipped, the rewards question is skipped, and the mismatch is refused naming the flag.

From the chain, the reward address, owners, margin, cost, pledge, relays and the opcert counter come from one provider unless a second pool-info reader exists (the node and Koios; Blockfrost has none): the fields both state are compared and a difference is refused naming both, whatever `--single-source` says. Without a second reader, or when it does not answer, the import refuses unless `--single-source` is given (recorded in the audit log, warned in the output). In every case the registration data is shown, strings from the chain escaped, and `Import the pool with this registration data? [y/N]` is asked, **default No**; `--yes` answers yes. An info file is not corroborated but is shown and confirmed the same way.

`--dry-run` plans and checks everything, prints what would be imported and the descriptor, and writes nothing (it opens the workspace to read it). `--continue` answers upstream's "the directory exists, go on?" (default No): other artefacts of the pool may exist; the descriptor itself is never replaced. Needs: `verification-key-envelope`, `vrf-verification-key`, `address-building`, `certificate-building`; for a pool id `pool-info`, `pool-updates`, `metadata-fetch`, `metadata-hash` (light mode); `protocol-parameters` when an account has a stake key. Output lists each artefact written (names, never contents), the counter, each account's role and the descriptor.

`export-info` writes the public registration data of a pool (the same three reads, the metadata checked against its registered hash) to a new file, for `import` on an offline machine. The file holds public chain data only and is never written over an existing one. `--attach` would also add it to the offline transfer file, but that needs `transfer-attach`, which only offline mode has, and offline mode cannot read the chain: the refusal lists both reasons. Needs: `pool-info`, `pool-updates`, `metadata-fetch`, `metadata-hash`, `extract-sink`.

### `pool retire-cert`, `pool retire`

```
spo pool retire-cert POOL [--epoch N] [--transfer-file PATH] [--offline] [genesis options]
spo pool retire POOL PAYER [--message TEXT]... [--transfer-file PATH] [--offline] [genesis options]
```

`retire-cert` (upstream `07a`) stores `POOL.pool.dereg-cert` for `--epoch` (default: the next epoch); an epoch outside the window the ledger accepts is moved to the nearest edge and the output says so. `retire` (upstream `07b`) sends it in one transaction signed by `PAYER` and the cold key; no deposit moves. As for `pool register`, `--yes` is refused and the question is always asked, `deregSubmitted` is written when the transaction is confirmed (it waits by default, `--no-wait`; `spo tx settle` records it later, see [Pending records](#pending-records-and-spo-tx-settle)) and the retirement certificate is consumed when the transaction is sent. The epoch is checked again before a fee is spent. Needs: the `wallet send` needs, `pool-certificate-decoding`, `clock`.

## Governance: DReps, committee, votes, actions

Governance commands follow the stake commands: the same transaction options (`--message TEXT`, `--yes`, `--transfer-file PATH`, `--offline`, the genesis options), the same confirmation (default No; no terminal and no `--yes` refuses) and the same `wallet send` needs, checked before the passphrase is asked. Each command adds the needs named below; a refusal lists every missing capability with its reason. Key material and mnemonics are never printed. The summary names the account, the payer, the certificate, votes or proposals, the deposit paid or refunded, the fee, the valid-until slot, the sources and the checks not made. A **Details** block adds what the public files hold: the DRep id, the anchor URL and hash, each vote as voter role, action id (hex and `gov_action1...`) and decision, each proposal as kind, deposit, return address and anchor. With `--yes` the same summary is printed after signing, attachments, deposit and refund included: the use case returns the summary it prepared.

Five policy flags exist, never on by default and never implied by a mode. A refusal that one of them would lift names it and what it gives up.

| Flag | Where | Gives up |
| --- | --- | --- |
| `--anchor-unverified` | `vote create`, `action create`, `drep status`, `drep register`, `committee resign` | The check of the anchor document against CIP-100/108/119: this build has no verifier (`anchor-verification` is absent in every mode). The hash is recorded as given. The output says `NOT CHECKED`. |
| `--single-source` | `drep retire` | The corroboration of the DRep deposit the refund rests on. A second DRep source (capability `drep-state-crosscheck`, the second provider of a light workspace with two) corroborates it; with one provider the command needs the flag. A false answer from one provider can cost the deposit. The summary says the read rested on one source. |
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

Upstream `21d`. Refunds the deposit of the on-chain DRep state. "Not registered" and an unknown answer are errors. Needs `--single-source` unless a second DRep source answers and agrees (`drep-state-crosscheck`; two sources that disagree are refused, and `--single-source` does not override that). Needs also: `certificate-building`, `drep-state`. Stores `NAME.drep-ret.cert`.

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

Upstream `25a`, `25b`. `KIND` is `info`, `no-confidence`, `update-committee`, `new-constitution`, `hard-fork`, `treasury-withdrawal` or `parameter-change`. `RETURN` is a stored stake account or a stake address. Kind options: `--amount` and `--to` (treasury), `--version MAJOR[.MINOR]` (hard fork), `--threshold`, `--add-key`, `--add-script`, `--remove-key`, `--remove-script`, `--term-epoch` (committee), `--constitution-url`, `--constitution-hash`, `--param NAME=VALUE` (repeatable) and `--cost-model-file FILE` (parameter change); an option of another kind is refused by name. `create` needs `protocol-parameters`, `clock` and `action-file`, and each kind adds only what it reads: `last-enacted-action` for the kinds that name a previous action (`no-confidence`, `update-committee`, `new-constitution`, `hard-fork`, `parameter-change`), `constitution` for `treasury-withdrawal` and `parameter-change`, `epoch` for `update-committee`, `metadata-file` for `--cost-model-file`. An `info` action therefore needs no chain reader and also runs offline from the transfer file's parameters.

`parameter-change` takes the 41 parameters of upstream's 25a (`spo action create --help` lists them) and three that cardano-cli offers and upstream does not: `cost-models` (from `--cost-model-file`, a JSON file `{"PlutusV1": [...], "PlutusV2": [...], "PlutusV3": [...]}` of the languages to set), `max-tx-execution-units` and `max-block-execution-units` (`(steps,memory)`, as cardano-cli takes them). Names are case-insensitive and may be given once. Integers are checked by the width of the ledger's type (a WORD32 is at most 4294967295, a WORD16 at most 65535; the five NATURAL parameters, which upstream does not allow to be zero, are not zero); rationals may be an integer, a decimal (`0.0577`) or a fraction (`2/3`) and are at most 1, except `ref-script-cost-per-byte`, which has no bound (upstream's script applies the bound of 1 to it too, so it cannot set the mainnet value 15; and it refuses a bare integer, which this build accepts). The five `pool-voting-threshold-*` parameters, the ten `drep-voting-threshold-*` and the two `price-execution-*` are given all together or none. The action file is byte-equal to cardano-cli's. The summary of `create` and of `submit` lists every changed parameter with the value it has now, when the parameters document of the provider (the hosted light-mode file or a Koios row) gives it, and the value it will have; a parameter whose current value the document lacks is listed with the reason, never left out, and a cost-model change says how many values of each array differ from the current model.

`parameter-change` refuses a cost model that has another number of values than the current model of that language in the provider's parameters, unless `--allow-cost-model-length-change` is given (`create` and `submit`). It also refuses when the current model cannot be read as an array (a provider that serves the models keyed by name, or no parameters document), because the length cannot then be compared; with the flag it goes on and the summary says "cost model length not checked"; the summary of a cost-model change says how many values differ and lists the differing indices as `[i] old -> new` (at most 12, then a count of the rest). `min-committee-size` is a 16-bit value, like the other `uint .size 2` parameters; the widths of all integer parameters follow the Conway CDDL.

An action file is displayed only when it is the file the builder writes for what it says: a non-minimal integer, a duplicate cost-model language or treasury account, an unsorted set, a text string where the action tag belongs, or an indefinite-length array anywhere but in the cost models (cardano-cli's form) is refused, so what is shown is what is carried.

`submit` puts the proposals in one transaction paid by `PAYER` and signed by the payment key, valid for 25000 slots; the return address must be registered (checked when a `reward-account` reader answers). After success it prints the id each proposal will have.

A treasury withdrawal or parameter change must carry the constitution's guardrails script when the constitution names one (`--guardrails-script FILE`, default `./guardrails-script.plutus`, a `PlutusScriptV3` `.plutus` file). Then `submit`:

* reads the constitution's script hash from the chain and refuses unless the file's hash, the hash in each action file and the constitution's agree (an action file written before the constitution had a script is written again with `action create`);
* sets one of the payer's UTxOs aside as collateral, the smallest with no tokens and 5 to 10 ADA (upstream takes the first), and does not spend it: it stays at the address. The body always carries the total collateral (body key 17, `ceil(fee × collateralPercentage / 100)`) and a collateral return (key 16) of the rest to the payer's address, so the ledger takes at most the total collateral if the script fails on chain and a provider that misreports the UTxO cannot enlarge the loss. The summary says `collateral at risk: at most N lovelace`, read back from the encoded body. That amount is `ceil(fee × collateralPercentage / 100)` and the fee includes the script fee computed from the execution units the evaluating provider reported, which this program does not check; a provider that reports low units lowers the fee and with it the collateral at risk shown, so the figure is only as good as the evaluator's units. None qualifying is refused with the request to send 5 to 10 ADA to the address; a collateral below `collateralPercentage` of the fee is refused; a remainder below the minimum value of an output is refused with a message (send a larger pure-ADA UTxO), never dropped into the fee;
* attaches the script as a witness with a `proposing` redeemer (data `{}`) per proposal, the execution units and the script-data hash, and pays the units in the fee;
* takes the execution units from a provider that evaluates the transaction (`plutus-script-evaluation`, Koios' Ogmios-compatible endpoint in light mode): this build runs no Plutus. The body that is signed is the body that was evaluated; a provider that cannot say, or reports that the script failed, ends the command before anything is signed. The summary lists the script hash, the units of each redeemer, the script fee, the collateral and the provider, and says that the units were not evaluated by this program. Offline mode, and a light mode with Blockfrost only, cannot evaluate: the command is refused before any prompt naming `plutus-script-evaluation` (by the kind in the file name, and again once the file is read). Upstream computes the units in every mode, so no `--ex-units` option exists;
* needs `constitution` and `metadata-file` besides `action-file`; action files that need the script must come before those that do not (see [the concerns table](../development/go-reference-implementation-concerns.md), G1);
* is refused for a hardware wallet payer (upstream's rule, SPO-25b-PRE-002). Multi-party signing has no path to `action submit`, and a remote signer is never shown a body with proposals, a script-data hash or collateral.

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

Submits the `N`th queued transaction (default 1) through the chain provider (light mode). It first checks that the UTxOs of the paying address, and the rewards for a withdrawal, are as in the snapshot. It then prints a summary (the entry, the tx id computed from the signed transaction, the provider, `WARNING` lines, `checked` lines and `NOT CHECKED` lines) and asks `Submit this transaction? [y/N]`; the default is No, and no terminal without `--yes` refuses. A declined run submits nothing and leaves the queue as it was (exit `1`). `--yes` is the explicit skip of the question: the summary is still printed (after the run, from what the checks found), the skip is reported, and the exit status is as for any other run. The entry is removed from the queue only after the submission. A queued transaction that has a pending record update (a mint, a burn, a pool registration or retirement) carries it in the queue entry (the port's own field `spoAssetPending`, which upstream's readers ignore; the name is from the first version and the field holds the update of any kind). After the submit the update is added to that entry's `tx submit` history line (`spoAssetSubmitted`), and nothing is applied on the accepted submit. For such an entry the command **waits for the confirmation by default** (`--no-wait` skips it, `--wait` waits for any entry, `--wait-confirmations`, `--wait-timeout`); on a confirmed wait it adds a history entry of its own, `spoConfirmed` with the depth and the providers, and applies the update where this workspace holds the pending record or, for an asset update, a copy of the asset record. A wait that does not end confirmed leaves the file recording the submit only. Entries submitted with `--no-wait` get their confirmation recorded later by `spo tx settle` on the online machine, which asks the providers and records `spoConfirmed`, or `spoExpired` for a transaction that can no longer be included, once per transaction. The history entry of the submit also holds the signed transaction (`spoTxCbor`): `tx settle` takes the transaction id and the validity bound from those bytes and refuses a carried record that disagrees, so an edited bound cannot make a transaction look expired. A wait of this command that ends expired records `spoExpired` as a confirmation is recorded. The update carried in the queue entry is applied to a copy of the asset record only when it matches the confirmed transaction (its id, and the policy, name and amount of its mint field); otherwise it is refused. See `asset mint` and `asset settle`. Pool registrations also check the published metadata hash. Needs: transfer-file, clock, tx-submit, utxo, reward-account, tx-id.

### `offline attach FILE [--name NAME]`, `offline extract [--dir DIR] [--overwrite]`

`attach` stores a file of at most 1 MiB under `NAME` (default: the file's own name, which must be a plain file name). The transfer file travels in clear, so a secret is refused with the reason named: a name ending `.skey`, `.hwsfile` or `.mnemonics`, a cardano-cli text envelope of a signing key type, a hardware signing file, upstream's encrypted-key envelope, a bech32 private key (CIP-5 names such as `ed25519_sk`, `xprv`, `root_xsk`, `kes_sk`, `drep_xsk`, `cc_hot_sk`), a file that is only 64 or 128 hex characters, a JSON array or nested object holding a signing-key envelope, or a list of 12, 15, 18, 21 or 24 words in either case, numbered or not, separated by spaces, commas or line breaks; a leading byte order mark does not hide any of these ([Xcustody](../../spec/extensions/Xcustody.md) PRE-004; a guard against a slip, not a proof that a file is harmless). `extract` writes every attached file that was not extracted yet into `DIR`, by default the new subdirectory `extracted/` of the workspace. It never writes into the workspace directory itself (`--dir` naming it is refused), and writes only plain file names inside `DIR`: an entry whose name is a path (`../x`, an absolute path) is refused and listed, and makes the command fail. An existing file is kept (`skipped`) unless `--overwrite` is given. An extracted file is removed from the transfer file and the history records it.

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

The asset record `POLICY.ASSET` keeps the `minted` total. It is updated when the transaction is **confirmed in a block**, not when it is accepted (hazard H9): the update waits as a pending update under the transaction id (see [Pending records](#pending-records-and-spo-tx-settle)). In light and online mode the command waits for the confirmation by default and applies the update; `--no-wait`, a timeout or Ctrl-C leave it pending and `spo tx settle` applies it later. A mint or burn that is only queued (offline mode) changes no record either; the same update travels inside the queue entry of the transfer file. When `offline execute` submits the entry (on the online machine, which usually holds neither the policy key nor the record) it waits for the confirmation and records it in the file's history; carry the file back and run `asset settle` on the machine that holds the record. This is the air-gap flow of a mint:

1. offline: `policy new p`, then `asset mint p.tok 100 PAYER` (the transaction is queued);
2. carry the transfer file to the online machine and run `offline execute` (it waits for the confirmation and records it; with `--no-wait`, run `spo tx settle` there later);
3. carry the file back and run `asset settle`: the record shows the minted amount, once.

Upstream writes the record when it queues or sends the transaction; the port writes it when the transaction is confirmed. The final record is the same. Show the record with `asset show`.

### `asset settle`

```
spo asset settle [--dry-run] [--discard-unmatched] [--accept-submitted] [--transfer-file PATH]
```

Reads the history of the transfer file that came back from the online machine and applies, to the records of this workspace (asset records and pool descriptors: the one code path serves every kind of pending update; the name is from the first version), each pending update of a queued transaction that the history records as **confirmed** in a block. Each is applied exactly once: the pending update is removed in the same commit, so a second run changes nothing and says so. A transaction recorded as submitted but not as confirmed is reported as waiting, and its update is kept: an accepted submit is not a transaction in a block. `--accept-submitted` applies it anyway, on the submit alone (use it only when you know the transaction landed; the output says each such update was applied on the submit alone). A transaction the history records as expired has its update discarded with a notice, never applied, and only when the validity bound stored with the local pending update is set and equals the bound the queued entry carried; the notice says the discard rests on the online machine's report, which this machine cannot check. **What this machine trusts:** the transfer file is not authenticated (SPO-Ptransfer-SEC-002; concern E7), so a confirmation or expiry entry in it is a claim. It can cause only the locally stored update of a transaction this workspace queued to be applied or discarded, never a different amount and never an unknown transaction. An outcome for a transaction that is still in the queue or that the file does not record as submitted, and an expiry whose bound does not match, is reported as inconsistent, kept, and exits `1`. An update whose transaction is still queued is reported as waiting. An update the file knows nothing about (neither queued nor submitted) is reported as unmatched and kept, because the file may simply be the wrong one; if its transaction was removed with `offline clear transactions`, `--discard-unmatched` drops the update, which is never applied. `--dry-run` prints what would be applied or discarded and changes nothing. The output names each transaction id. Needs: transfer-file, clock. Opens the workspace; needs no chain and no provider.

### `asset show POLICY.ASSET`

Prints the asset record (a JSON document: `minted`, the identifying fields, `lastAction`, the `meta*` keys an operator edits). It holds no secret. Before anything was submitted it says there is no record yet. Opens the workspace; needs no chain.

### `asset meta generate POLICY.ASSET`, `asset meta check POLICY.ASSET|SUBJECT`

```
spo asset meta generate POLICY.ASSET [--set FIELD=VALUE]... [--out FILE]
spo asset meta check POLICY.ASSET|SUBJECT
```

The token registry (CIP-26) lists a token's name, description, ticker, decimals, URL and logo, each signed by the minting policy's key. `generate` is upstream `12a_genAssetMeta` with the external `token-metadata-creator` replaced by a native signer (`domain/tokenmeta`, signed through `RegistrySigner`); `check` is `12b_checkAssetMetaServer`.

**`generate`.** The first run only creates the asset record `POLICY.ASSET` and lists the fields to fill in: `metaName`, `metaDescription`, `metaDecimals`, `metaTicker`, `metaUrl` and `metaLogoPNG` (the path of a PNG of at most 64 KB, relative to the workspace directory unless absolute). A sealed workspace has no editor, so `--set FIELD=VALUE` (repeatable; only those six fields) sets them: it creates the record first when there is none, sets the fields, then signs in the same run. The second run signs with the policy key held in the workspace, stores `<subject>.json` (public data) and prints the subject, the sequence number (the record's plus one) and where the entry is. The entry is built and signed before anything is written; a field the use case rejects (a description of 0 characters, a logo over the limit or not a PNG) leaves the record as it was. `--out FILE` also writes the public entry to a new file (never over an existing one, checked before anything is signed) for the pull request to the registry; without it, running again signs the next sequence number, so keep the file. A policy whose key is on a hardware wallet is refused by the signing plan before the store is read or written: no device signs registry entries. Needs: `signers`, `registry-signing`, `clock`, `logo-file` (all local, so any mode). No chain.

**`check`.** Asks the registry for the entry of the subject and compares it with the record. The output names the registry host, the subject and the record's sequence, then `Status`: `published` (the registry serves the record's sequence number), `behind` (it serves an older one: the pull request is not merged), `ahead`, `not compared` (a subject was given, or the record has no entry yet) or `not found`. `not found` is a normal result and exits 0. Then `Verify`: `OK` when every property has a valid signature and the entry's policy hashes to the subject's policy id and is satisfied by the signers; `FAILED` (with the properties and the reason) is an error and exits 1. Then each property with the registry's value and `record matches`, `record differs: VALUE` or `record not compared`; the logo is compared byte for byte with the file the record names, and shown as its size. Text from the registry is not trusted: control characters are replaced and long values cut. A registry that cannot be reached, or answers something that is not an entry, is an error and never "not found". The registry's logo is not written anywhere. Needs: `token-registry` (light mode with a server: mainnet has the public one; set `[registry] url` for a test network; offline it is absent with the reason).

## Calidus pool key and Catalyst registration

Both register a key by a signed metadata record and neither submits anything: the registration is stored in the workspace (as `NAME_yymmddHHMMSS.calidus-registration.json` or `NAME_yymmddHHMMSS.vote-registration.cbor`) and put on the chain by an ordinary payment that carries it, `spo wallet send PAYER PAYER MIN --metadata-record NAME.…`, upstream's `01_sendLovelaces <wallet> <wallet> min <file>`. No command writes the record to a file. Signing goes through the signing plan (ADR 0008): the vault signer signs CIP-88 and CIP-36 registrations (capability `registration-signing`), and a pool cold key (Ledger or Keystone) or a stake key (Ledger) held on a hardware wallet signs on the device when the profile of the device says so, and is otherwise refused before anything is built (see each command). No command prints a signing key or a recovery phrase except as stated for `catalyst key qrcode`, whose output is as secret as the key.

### `pool calidus new NAME [--mnemonic-in-fd N] [--account N] [--index N]`

Derives the Calidus key (CIP-151) along `1852H/1815H/ACCOUNTH/0/INDEX` (default `0/0`) from a 24-word phrase and stores `NAME.calidus.vkey`, `.skey`, `.mnemonics` and `.id` together or not at all; existing ones are refused. `--mnemonic-in-fd N` reads the phrase from descriptor `N`; without it a fresh phrase is generated and stored sealed, never shown (there is no random-seed path, as upstream has none). Prints the Calidus id and the public key. Needs: `calidus-keygen`, and `mnemonic-generation` without `--mnemonic-in-fd`.

### `pool calidus register-metadata CALIDUS POOL [--nonce N] [--yes]`

Builds the CIP-88 version 2 registration of the Calidus key `CALIDUS` for `POOL` and signs it with the pool's cold key (upstream `15 genmeta`). Prints the Calidus id, the pool id, the nonce and the stored record's name, and the exact follow-up `spo wallet send <payer> <payer> MIN --metadata-record NAME`. `--nonce` defaults to the current slot of the work mode; where the mode has none (offline without genesis) on a testnet the command asks for `--nonce`. The command has no `--submit-with`: the follow-up is printed, not run. Needs: signers, `registration-signing`, clock.

A pool cold key on a hardware wallet (a `.node.hwsfile` beside or instead of the `.node.skey`; the hardware file wins, as upstream) signs on the device: on a Ledger or a Keystone only, a Trezor is refused before the tool is called. The device signs a CIP-8 message over the blake2b-256 of the payload (`cardano-hw-cli message sign --message-hex HASH --signing-path-hwsfile FILE --out-file FILE`, no `--hashed`). Before it is asked the command prints the pool id, the Calidus id, the nonce and the blake2b-224 hash the device displays, and asks whether to continue; `--yes` answers it, and without a terminal or `--yes` the command stops before the device is contacted (upstream's default for this question is yes; here it is no, because there is no device-side default to lean on). The device's answer is checked before anything is stored: the signed payload must be exactly this hash, the protected header must name the pool id, the COSE key must be the cold key of the signing file and hash to the pool id, and the signature must verify. A failed check stores nothing and fails the command (upstream exits 0 on some of them). The device path has run only against the stand-in tool: checklist items 14 and 15 in [the device checklist](../development/hardware-device-checklist.md).

### `pool calidus status CALIDUS-ID|KEY|POOL|NAME|all`

Lists the Calidus keys registered on chain for a pool, a Calidus id or key (upstream `15 query`), oldest first, each with the pool id, Calidus id, public key, registration time, nonce, epoch and transaction. The subject is classified in upstream's order: a Calidus id, a stored `NAME.calidus.id`, 64 hex digits, a stored `NAME.calidus.vkey`, a pool id, a stored `NAME.pool.id`, a stored `NAME.node.vkey`, or the word `all`. Light mode only: Koios `GET /pool_calidus_keys?pool_status=eq.registered&order=block_time.asc` plus one equality filter (`calidus_id_bech32`, `calidus_pub_key` or `pool_id_bech32`); a retired pool's key is not listed. No entry is an empty answer, not an error. **The shape of the Koios answer is taken from its documentation, not from a recorded response**: the adapter's test data is written by hand (`spo/internal/adapters/koios/testdata/pool_calidus_keys_documented.json`) and a live answer has not been compared with it. A full page of 1000 rows is refused as possibly truncated: name a subject. Offline the capability `calidus-registrations` is absent and the command says so.

### `pool calidus sign CALIDUS TEXT`

Signs `TEXT` with the Calidus signing key `CALIDUS` from the workspace and prints the Calidus id, the public key and the signature in hex (upstream `15 sign`). The signature is a plain Ed25519 signature over the bytes of the text, not a CIP-8 message. Nothing is written. A failed signature is an error (upstream exits 0). There is no hardware variant. Needs: signers, `registration-signing`.

`pool calidus new` takes `--hardware` only to say no: a Calidus key cannot be made on a device, because upstream suspends it until CIP-151 has a dedicated derivation path (`SPO-15-PRE-002`). The command refuses before anything is read; no table row grants a Calidus key on any device.

### `catalyst key new NAME [--mnemonic-in-fd N] [--account N] [--index N]`

Derives the voting key (CIP-36) along `1694H/1815H/ACCOUNTH/0/INDEX` and stores `NAME.voting.vkey`, `.skey`, `.pkey` and `.mnemonics`. The phrase is read or generated as for `pool calidus new`. Prints the public key (`cvote_vk`). Needs: `voting-keygen`, and `mnemonic-generation` without `--mnemonic-in-fd`.

`--hardware` makes the key on a Ledger at the same path (`cardano-hw-cli address key-gen`) and stores only `NAME.voting.vkey` and `NAME.voting.hwsfile`: no signing key, no `.pkey`, no phrase (`SPO-09a-OUT-004`, `SPO-09a-OUT-009`), and no QR code. Keystone and Trezor are refused before the device is contacted: the specs name only the Ledger for it. Needs: `hardware-wallet`.

### `catalyst key qrcode NAME [--pin-fd N] [--yes]`

Shows the QR code of the voting signing key `NAME` for the Catalyst mobile app (upstream `09a qrcode`), natively: no `catalyst-toolbox`. The key's 64-byte extended secret is encrypted with a four-digit PIN (the digits as the bytes 0 to 9, PBKDF2-HMAC-SHA512 with 12983 iterations, ChaCha20-Poly1305; version byte, 16-byte salt, 12-byte nonce, ciphertext, 16-byte tag, written as 218 lower-case hex characters) and drawn at error-correction level H.

**The code is drawn on the terminal and written to no file.** The release has no PNG writer: four digits are 10,000 guesses, so a file holding the payload is a key at rest that is effectively unencrypted, which the owner's rule does not allow ([Xcustody](../../spec/extensions/Xcustody.md) INV-001, IF-004). There is no `--out` and no `--show`; the terminal display is the only mode, and a script that passed `--out FILE` or `--show` now fails with an unknown flag. Standard output must be a terminal: a pipe or a redirect is refused before anything is asked, and so is `--yes` there. The command then states that anyone who photographs, records or shares the screen can recover the key with at most 10,000 guesses, and asks for confirmation (default no; `--yes` answers it, on a terminal only). The PIN comes from a prompt or from descriptor `N`; it is never an argument and never printed. A missing key, a hardware voting key and a PIN that is not four digits are refused before anything is drawn. The display is recorded in the workspace audit log (operation `catalyst-qr-display`, the key's name, no key material) before the payload is built, and is not made when the record cannot be written. The code is drawn on the terminal's alternate screen, and the screen is cleared when you press Enter, so it is not left in the scrollback; a terminal log, a recording or a shared screen can still hold it. The TUI wipes a command's output when its run view is left. Needs: `voting-key-qr`.

The format is implemented from the public source of the Catalyst toolbox (`cardano-foundation/catalyst-toolbox` at commit `b9910d772186dddd3593dd8b315ed38e6d7f4d15`, `src/kedqr/payload.rs`, `src/bin/cli/kedqr/mod.rs`, `doc/private-key-and-qr-code.md`; `input-output-hk/chain-wallet-libs` at `b46e4740823719c83af688e6e7c031a792978c03`, `symmetric-cipher/src/lib.rs`). **A QR code made here has not been scanned by the mobile app.** The toolbox publishes no known-answer vector (its tests use random salts), so the tests check the key derivation and the encryption against values computed independently with Python's `hashlib.pbkdf2_hmac` and PyCryptodome's ChaCha20-Poly1305, and the encoding by a round trip. Scan a code for a throw-away key before relying on the command. Four digits give no protection against an offline guess: the drawing is exactly as sensitive as the key.

### `catalyst register STAKE REWARDS --vote-key NAME[:WEIGHT]... [--nonce N] [--purpose N]`

Delegates the voting power of the stake account `STAKE` to the voting keys and signs the CIP-36 registration with its stake key (upstream `09a genmeta`). A `--vote-key` is the name of a stored voting key, a public key in hex or a `cvote_vk` text; `WEIGHT` defaults to 1; repeat the flag for several. `REWARDS` is a stored address name or a payment address of the network. `--nonce` defaults to the current slot as above; `--purpose` to 0 (Catalyst). Prints the nonce, the keys with their weights, the rewards address, the stored record's name and the follow-up send command. Needs: signers, `registration-signing`, clock.

A stake key on a Ledger (`.staking.hwsfile`) signs on the device with `cardano-hw-cli vote registration-metadata`; Keystone and Trezor are refused before the tool is called. When `REWARDS` names the payment key of the same wallet (`WALLET.payment`) and its hardware signing file exists, that file is passed as `--payment-address-signing-key-hwsfile` after the adapter has checked that it is the payment credential of the rewards address (`SPO-09a-INV-004`); with any other rewards address it is not passed. The voting keys are public keys and never decide the signer. The device's metadata is checked against the registration asked for (every field, the stake key's signature) before it is stored. The Ledger app must meet the session minimum; the 6.0.3 minimum the upstream script sets for this call is not applied (the session minimum, `[hardware] min_ledger`, always is), see checklist item 17.

## Moving between the upstream layout and the sealed workspace

### `workspace import [DIR]...`

```
spo workspace import [DIR]... [--depth N] [--only KIND:NAME[@DIR]]... [--rename KIND:NAME[@DIR]=NEW]... [--all]
                     [--dry-run] [--format table|json] [--manifest FILE | --print-manifest | --manifest-out FILE]
                     [--owner NAME]... [--password-fd N] [--defer-encrypted] [--overwrite]
```

Reads the folders (upstream-layout directories; they are opened read-only and never changed, and a symbolic link is never followed) and stores what they hold in the sealed workspace, owner by owner. Each signing key is checked against its verification key, and each address against its keys (`verification-key-derivation`, `address-inspection`). In the plain form an owner is imported whole or not at all, in one atomic update of the workspace of its own (per owner); the selective form stores every planned owner in one update, all or none, and refuses the whole run if the write fails or the workspace changed after the run read it. Files that are not artefacts of the catalogue are listed as `ignored`. The folders are only read; an `.spo-workspace-audit.json` that an earlier version left in one is listed as ignored. The behaviour beyond a single folder is specified in [Xmulti](../../spec/extensions/Xmulti.md).

One folder with no option (the plain form; `--owner NAME` keeps it) imports everything in it, every artefact and every descriptor exactly as before: byte for byte, with no examination. A descriptor that a selective import would have refused or rewritten (a path that resolves to nothing, an open `regWitness` whose names differ, a `poolName` that is not the file's) is stored as it is and its row carries a note saying so. Several folders, or `--depth N` (sub-folders to N levels, at most 4; at most 200 directories and 20000 files in all), import only what is selected: `--only KIND:NAME` (KIND is `pool`, `wallet` or `other`; add `@DIR` when two folders hold the same name; `--owner NAME` is the old spelling) or `--all`. A selector that matches nothing, or owners in several folders, is refused. `--rename KIND:NAME[@DIR]=NEW` stores a selected owner and all its artefacts under another name. Two selected owners that would get one name are refused before anything is written, naming both and their folders; names that differ only by case (`Owner`, `owner`) are one name, within a run and against the workspace. A rename to the name of an owner that was found and is not selected is refused before anything is written (a pool that names that owner would be bound to the renamed owner's keys); a rename to a name another selected owner gives up in the same run (a swap, a chain) is fine. A rename to a name the workspace already holds as an owner of any kind is refused unless `--overwrite`. An owner with an artefact the workspace already holds under its stored name is refused as before unless `--overwrite`; when its stored name is an owner the workspace already holds (any artefact of any kind under that name), the owner that results is the workspace's artefacts together with the incoming ones (nothing is deleted; with `--overwrite` the incoming one replaces an artefact of the same reference), and that result is checked as a whole whether or not `--overwrite` is given: the same owner kind, every key pair, every address and certificate against the keys of the result, every operational certificate naming the result's cold key and the KES key of its number, the issue and KES counters, and a payment key with a stake key only when a base address ties them or they came together. Anything that cannot be shown (a key kept encrypted, a hardware signing file without a stored verification key, an unknown kind) refuses the owner. **A merge into an existing workspace owner is accepted only when the result is provably one owner; otherwise import under a new name.** The merge also needs an identity anchor: a verification key (or hardware public key) that both sides have and that is the same, or an artefact of one side that names a key of the other (an issue counter or operational certificate for the cold key, a certificate or address for the stake or payment key); an unrelated source owner of the same name is refused ("nothing shows that the source owner and the workspace owner of this name are the same"). Every pool record that carries the pool id (`poolID`, `poolIDbech`, the id files, the operator in a registration or retirement certificate) must be the id of the result's cold key. A coherent addition (the next KES key and operational certificate of the same cold key, the same owner again) succeeds and its row lists what was verified and added. With `--overwrite` the artefact rows say which existing artefacts are replaced (would be, in a dry run). A pool is imported only if every wallet it names (`ownerName`, `poolOwner`, `poolRewards`, the names inside `regWitness`) is imported in the same run or is already in the workspace with the same keys: a wallet the run refuses, for any reason, refuses the pools that name it (the pool row names the wallet and its reason), wallets are written before the pools that name them, all in one update (the whole run is stored, or nothing is: a failed write, or a workspace that changed after the run read it, refuses every planned owner with the plan rows still shown). A descriptor name that no source owner has is not satisfied by another owner renamed to it. After the plan and before any write every stored pool is checked again against the planned end state, by keys: each name its descriptor carries (`ownerName`, `poolOwner`, `poolRewards`, the names inside `regWitness`) must be a wallet with a stake verification key, and the very keys of the source owner the layout names (stake, and payment where both have one); a name with no source owner must be the workspace's own wallet and carries the note. The names are read from the final descriptor with the accessors the pool commands use, and the check covers every pool that will be in the workspace and names an owner this run stores: a run that would change the stake or payment key of a workspace wallet that a workspace pool (not in the run) names is refused for that wallet, naming the pools. A descriptor with a key that occurs twice in one object, or twice apart from case, is refused in the selective form, naming the keys. A name that matches an owner of the sources or of the workspace only apart from case is refused as ambiguous, naming both spellings. A pool whose witness transfer files (`<pool>_<owner>_<id>.witness`) name an owner that this run stores under another name is refused. In the plain form `--overwrite` also prints the "replaces" notes and a note when an incoming cold key replaces those of a pool with another cold key; it refuses nothing new. The workspace is read once before the first write; the dry run and the real run share one plan, so the dry run says what the real run does.

**Limits of the selective import.** Owners beyond the given folders and depth are treated as workspace-only (with a note). Pool records and role keys are tied to an owner only through the checks above (key bytes, the cold key a counter or operational certificate names, the key hash in a certificate or address, the pool id, the names in the descriptor); a record that carries none of these is tied only by its file name. The recheck at the write covers what the run read, wrote or probed.

**Pool descriptors.** A descriptor kept apart from its wallets names them by a relative path (`"ownerName": "../wallets/owner"`). Each reference is resolved against the descriptor's own folder, lexically and among the owners found (`\` is a separator; an absolute path, a drive letter or a `..` that leaves every given folder is refused). The stored descriptor carries the flat stored name of the owner when it is selected. A bare name (`"ownerName": "owner"`) is looked up in the descriptor's own folder first; upstream resolves it against the directory the script ran in, which an import does not know, so when it is not there and exactly one owner of that name was found in the other folders of the run, it resolves to that owner (which must be selected; a rename reaches the descriptor; a note says where it was found), and several such owners refuse the pool as ambiguous, naming the folders (write the reference as a relative path, or leave the other folders out). An owner that was found and not selected is accepted only when the workspace holds a wallet of that name whose stake verification key (and payment verification key, where either has one) is byte-equal to the source owner's; with other keys the pool is refused, naming both. A name found in no source that the workspace holds as a wallet is accepted, and the descriptor row notes which workspace wallet it was bound to, with its stake key hash. The note says that no wallet of that name was found within the given folders and depth; a wallet below `--depth` cannot be known. Anything else that is not selected, or nothing, refuses the pool; the message names what to add. A leading UTF-8 byte order mark on a descriptor is kept. Every field of `<pool>.pool.json` that holds a path or a derived name is examined:

| Field | Decision |
| --- | --- |
| `poolName` | rewritten to the stored pool name when it differs (path prefix, another name, a rename) |
| `poolOwner[].ownerName`, legacy string `poolOwner`, `poolRewards` | resolved; rewritten to the owner's stored name; pool refused when unresolvable, absolute, escaping or naming an unselected owner |
| `regCertFile`, `deregCertFile` | must name `<pool>.pool.cert` / `<pool>.pool.dereg-cert` (with or without a folder); rewritten to the stored pool name, the certificate artefact is stored under it; any other value refuses the pool; a certificate named and absent is not imported and the table says so |
| `regWitness` (open multi-witness registration) | carried untouched only when no name in it (pool, owners, paying wallet) changes, each name resolved like a bare name above; otherwise the pool is refused |
| `regProtectionKey` | not a path; left alone, with the existing warning |
| `poolMeta*`, `poolExtendedMetaUrl`, `poolRelays`, pool id, hash and registration state fields | not paths; left alone |
| any other top-level string with `/` or `\` and no `://` | left alone, noted |

A descriptor that needs no rewrite is stored byte for byte; one that does has only the changed string values replaced, so field order, spacing and every other value stay as they were. Every rewrite (pool, field, old value, new value) is listed in the result.

`--dry-run` reads and checks everything, writes nothing, prints the plan and exits `1` when any selected owner would not be imported (`--format json` prints the plan for a program: owners with kind, folder, stored name, status, reason, artefacts and rewrites; it is what the TUI reads). `--manifest FILE` takes folders, depth and selection from a TOML file instead of flags (`sources`, `depth`, `all`, `only`, `rename`; the last two hold the strings the flags take; a relative folder is relative to the manifest; any other key, or two strings of an array with no comma between them, is refused; `#` comments may stand after a value or inside an array) and is refused together with folders, `--depth`, `--only`, `--rename`, `--all` or `--owner`. `--print-manifest` prints the manifest the flags stand for and `--manifest-out FILE` writes it to a new file (never replacing one); neither imports. A manifest read back and printed is the same text.

A key that upstream encrypted needs its password: `--password-fd N`, else a prompt without echo when a selected owner holds such a key. That needs `key-encryption` (gpg); without it the command names the missing tool and says gpg is needed only for upstream's encrypted keys. `--defer-encrypted` imports no such key file: each is listed as left in the source, its owner is not imported, and no password or gpg is needed. `--keep-encrypted` was removed and is refused with a message that names `--defer-encrypted`; no import creates a record in upstream's encrypted form any more. Existing artefacts are kept and their owner refused unless `--overwrite`.

The result is a table; the folder and stored-name columns and the rewrite list are part of it:

```
OWNER   KIND   FOLDER        STORED AS  ARTEFACT          STATUS  REASON
mypool  pool   /src/pool     q          mypool.pool.json  done
owner   wallet /src/wallets  boss       owner.addr.skey   done

descriptor rewrites (pool, field, old -> new):
  q: poolOwner[0].ownerName: "../wallets/owner" -> "boss"
```

It holds owners, folders, artefact names, statuses and reasons, never key material; names and paths taken from a source are printed through the text-safe writer. The exit status is `1` when any owner was not imported.

### `workspace export DIR`

```
spo workspace export DIR (--password-fd N | --generate-password [--password-out-fd N]) [--owner NAME]... [--overwrite] [--reason TEXT]
```

Writes the pools and wallets of the sealed workspace into `DIR` in the upstream layout, with the same names and modes the upstream scripts expect. `DIR` must be new or empty (`--overwrite` allows a directory that is not). Every signing key is encrypted in upstream's gpg form (needs `key-encryption`) and is checked to decrypt again before it is written. The gpg parameters are pinned: `--cipher-algo AES256 --s2k-mode 3 --s2k-digest-algo SHA512 --s2k-count 65011712 --force-mdc`, so the message is a symmetric session key packet with an iterated-and-salted S2K and an integrity-protected data packet, and the destination refuses an envelope whose OpenPGP packets are anything else. The password is read from `--password-fd N`, and must be strong in upstream's sense and **at least 20 characters** long; or `--generate-password` draws 160 random bits and writes them as eight hyphen-separated base32 groups (for example `abcd-EFGH-...`, 39 characters), uses them, and shows the password once on the terminal (standard output must be a terminal) or writes it to a pipe or socket on `--password-out-fd N` (any other descriptor is refused before a key is read or a file written; see [Xcustody](../../spec/extensions/Xcustody.md) OUT-005). The password is delivered **before** any file is written, so a failed delivery leaves no encrypted file whose password is lost. `--password-fd` and `--generate-password` are mutually exclusive; the password is not stored anywhere. There is no option to write a key in clear. Mnemonics, the Catalyst QR code, keys kept in upstream's encrypted form and this program's own records are never written; the table lists each skipped artefact with the reason, and a kept key names `key convert`.

The audit record is written to the workspace (operation, owners, count of keys written, `--reason`) **before** any key is written; if it cannot be made, nothing is exported. `store verify` covers it like any other change. The output is the table of `import`, with `encrypted` for each signing key, and the exit status is `1` when any owner was not exported. A refused or failed export leaves no empty directory behind. The destination refuses any secret that is not an encrypted signing key envelope ([Xcustody](../../spec/extensions/Xcustody.md) INV-001, OUT-003).

**An export is a transport form.** gpg's iterated-and-salted S2K is not memory-hard, so the export is weaker against offline guessing than the sealed workspace, whose passphrase goes through Argon2id. That is why the password must be long, why `--generate-password` exists, and why the directory and the password are to be deleted once the keys have been used. Keep the files only as long as the move takes. To give a block producer its hot keys, see [Deliver keys to a block producer](../how-to/deliver-keys-to-a-block-producer.md).

### `key convert KEY`

```
spo key convert KEY [--password-fd N]
```

Turns a key that an import of an older release (`--keep-encrypted`, removed) stored in upstream's password-encrypted form into an ordinary sealed signing key. `KEY` is the key file's stem with or without `.skey` (`mypool.node`, `mywallet.payment.skey`). The upstream password is read from `--password-fd N`, else asked for without echo. The key is decrypted in protected memory only, checked against the verification key in the workspace (import the `.vkey` file too; a key with no verification key here is refused), and stored sealed while the kept record is removed, in one transaction: both happen or neither. The key is never written in clear. A wrong password changes nothing and is not retried. A KES or VRF key is checked in its exact form (the Sum6 root verification key of the KES key, the public half of the VRF seed) against the verification key of its number; a BLS key has no verification key this program can derive and is refused, so a kept-encrypted one cannot be converted: import it again from its directory with `workspace import --password-fd N` (without `--keep-encrypted`), which decrypts and seals it. There is no in-place `key protect` or `key unprotect` on a plain directory any more: a plain directory is not a workspace. To encrypt or decrypt a key file that lives in an upstream-layout directory, use the upstream script `01_protectKey.sh`, which does that job. Needs: key-encryption (gpg), verification-key-derivation.

### `node export`

```
spo node export POOL --recipient FILE --out DIR [--kes N] [--no-tpm-identity] [--reason TEXT]
```

Reads the pool's KES signing key, VRF signing key and operational certificate from the sealed workspace and writes only `age` ciphertext into `DIR` (new or empty): `kes.skey.age`, `vrf.skey.age` and `node.cert.age`, each sealed to the one X25519 public key in `FILE` (one `age1...` line, comments allowed; a secret key, several recipients or none are refused before the workspace is opened), mode 0600, created exclusively. No plaintext leaves the command (SPO-Xcustody-OUT-006).

Before anything is sealed (SPO-Xcustody-PRE-007 to PRE-010): the role history of the KES key and of the VRF key must contain `kes` and `vrf` respectively and no cold role, and a missing or unreadable history is refused; the certificate of the KES number must name that KES key, be signed by the pool's own cold key and be the newest the issue counter has made (PRE-016), and the Ed25519 identities of the VRF public key and the KES leaf must carry no other role (PRE-017); the verification key derived from each signing key (the Sum6 root key for KES, the public half of the seed for VRF) must be the stored one; and each file must be of its exact form (envelope type and members, a `cborHex` of exactly 608 or 64 bytes, a certificate of the exact structure). `--kes N` names the KES key; by default it is the newest one that has a certificate. The delivery is recorded in the audit log (operation `node-export`, the pool, the KES number, an identifier of the recipient, the file names and the TPM statement) before any file is given its name (written under temporary names, recorded, renamed). `--no-tpm-identity` records that the producer's identity is not a TPM-bound credential; without it the report says the command cannot see the host. A refusal creates no directory, no file and no audit event. Needs the sealed workspace and the capabilities of a normal session; no `--upstream-layout`.

### `spo-node-keys deliver`

```
spo-node-keys deliver --from DIR --to DIR
```

The block producer's start-up helper: a separate program that cannot open a workspace (its import graph holds no sealed store, slot code or factor source; SPO-Xcustody-INV-007) and the only writer of a signing key in clear. It reads the producer's age identity from the systemd credential `spo-node-age-identity` in `$CREDENTIALS_DIRECTORY`, decrypts the three files of `--from`, checks each by its kind and the KES key against the certificate, and writes `kes.skey`, `vrf.skey` and `node.cert` into `--to`: an existing directory on `ramfs` owned by the user it runs as (never root), mode 0400, created with `openat(O_CREAT|O_EXCL|O_NOFOLLOW)` relative to the checked directory descriptor, never replacing a file (SPO-Xcustody-PRE-012 to PRE-014, MODE-001, MODE-002, PR-002). A disk file system is refused, and so is a `tmpfs` whose mount has no `noswap` (checked in `/proc/self/mountinfo`); the same rule applies to the credentials directory. Each file carries a header (pool id, KES number, certificate counter); a mixed set is refused (SPO-Xcustody-PRE-015, OUT-008). It prints the three paths and asks nothing. How to set it up: [Deliver keys to a block producer](../how-to/deliver-keys-to-a-block-producer.md).

## Multi-party signing

Several people sign one transaction, a pool registration with more than one owner being the reference case, without passing unauthenticated files around. The design is [ADR 0005](../explanation/adr/0005-party-envelope-and-signing-policy.md); the requirement ids (`SPO-Xparty-*`) are in [spec/extensions/Xparty.md](../../spec/extensions/Xparty.md). Everything here needs a **sealed workspace** (a plain directory is not one) and the capability `multi-party-signing`.

**Terms.** A *party* is one enrolled machine with its own sealed workspace. The *coordinator* builds the transaction and collects the signatures; a *signer* is asked for one; one machine can be both. Every message between two machines is an *envelope*: encrypted to its recipient with `age` and signed by its sender with Ed25519, so a carried file and a message over tailcat go through the same checks. A party's identity is two key pairs in the sealed store; its *fingerprint* is eight groups of four base32 characters (160 bits).

### Identities and enrollment

| Command | What it does |
| --- | --- |
| `party init [--label TEXT] [--tailcat]` | Creates this workspace's identity and prints the fingerprint. `--tailcat` also makes the tailcat node key and publishes its public half in the signed identity document; it cannot be added later without a new identity. The label is shown to peers and not trusted by them. |
| `party show` | Label, fingerprint, tailcat node key. |
| `party export FILE [--overwrite]` | Writes the public identity document (no secret, no address). Give it to the other operator, and read them the **first four groups** of the fingerprint over a separate channel. |
| `party enroll FILE --as NAME --role ROLE... [--key-role R]... [--pool P]... [--unscoped]` | Records another party. The signature of the document is checked, then you see its label, the roles you give it and the **last four groups** of its fingerprint, and you **type the first four groups** the other operator reads out. They are never on the screen, there is no flag for them, and with no terminal nothing is enrolled. Roles: `coordinator` (may send you requests), `signer` (you may send it requests), `machine` (your own other machine). `--unscoped` explains what it permits and asks (default No). Enrollment is not mutual by itself: the other operator enrolls you the same way. |
| `party list` | Name, state, roles, label (quoted), fingerprint, scope, node key. |
| `party revoke NAME [--yes]` | From the commit on, its envelopes are refused, including ones created before; unfilled slots assigned to it become unassigned, filled slots keep their verified witnesses. A tailcat server running in this process stops serving its node key and closes its connections at once; a server in another process follows the registry within seconds. |
| `party scope NAME --key-role R... [--pool P]... [--unscoped]` | Replaces the scope of a coordinator with exactly what you give. Narrowing applies at once; widening asks, and widening to `--unscoped` says what it permits. A request you have not approved yet is checked against the scope as it is when you approve it. |
| `party rotate [--label TEXT] [--yes]` | Replaces this workspace's own party identity: a new signing and encryption key (the tailcat node key stays), the old private keys **replaced** in the store with the commit (a backup made earlier still holds them), and one announcement, signed by the old and the new key, sealed for each enrolled party and queued in the outbox. It asks first (default No). It also drops everything that waited in the outbox (it was sealed by the old identity), closes the requests waiting for your decision (outcome `rotated`) and voids the outstanding requests of the collections you coordinate: **in-flight requests must be made again**. **If the old key is lost there is no rotation**: the statement must be signed by it, the command says so, and the way forward is a new identity that every peer enrolls from scratch (`party enroll`). Read the first four groups of the new fingerprint to each peer over a separate channel. **It is refused while the announcements of an earlier rotation are undelivered** (still waiting in the outbox and not expired; nothing changes, and there is no override), and the message says how to deliver them (`outbox export`, `serve`). After the commit the store is asked to fold its write-ahead log so the replaced keys are not left in it; **earlier backups of the workspace still contain the old keys**. |
| `party rotation list` | The announcements that wait for your confirmation: the local name, the old fingerprint, the new label (quoted, not trusted) and the **last four groups** of the new fingerprint. |
| `party rotation accept NAME` | Replaces NAME's enrollment by the announced identity, after you **type the first four groups** of the new fingerprint (never on the screen, no flag, no terminal means nothing changes) and answer whether NAME's scope carries over (default No: the new identity then has a scope that allows nothing; set one with `party scope`). In one store transaction the old identity is revoked and kept under a name that cannot be an enrollment name, the new one is enrolled under NAME with the same roles, the slot requests sent to the old identity are voided and the envelopes queued for it dropped (**request again**), and requests the old identity sent that wait for you are closed. A statement naming an identity that was never enrolled, one already revoked (which is what a replay of an accepted statement is), one whose new identity is already enrolled, an expired one, or one whose node key is another party's is refused. |
| `party rotation reject NAME` | Drops the announcement; the enrollment is unchanged. |
| `party events [--noise] [--limit N]` | The audit log. `--noise` is the small ring of refusals that failed before the signature step, which can never push a security event out. |

A coordinator's **scope** says what it may ask of this machine: the key roles (`--key-role`: `stake`, `payment`, `pool-cold`, ...), the pools a body may name (`--pool`, pool id `pool1...` or 56 hexadecimal characters) and `--unscoped`. There is no default: a coordinator is enrolled with at least one key role and a pool or `--unscoped`. The scope is checked per part of the body, at the signer, when the request arrives and again at approval. Parts that name no pool (a withdrawal, a stake registration, a vote delegation, a DRep or committee certificate, and every payment-key request) need `--unscoped`.

### Requests, review and approval (signer)

| Command | What it does |
| --- | --- |
| `party requests` | The requests waiting for a decision, with how each arrived (`file` or `network`). Nothing from the body. Requests that were **closed** before you decided (the coordinator's closing notice, or a rotation) are listed apart, as `closed (outcome)`, and are not waiting for you. |
| `party review ID [--full]` | The request in full, decoded from its own bytes: how it arrived; **whose money moves**, worked out here from this workspace's own keys and its own view of the chain (own inputs, own outputs, withdrawals, refunds, deposits, the net that leaves you, the value that goes to others, the fee); the scope parts; every input, output and certificate; the metadata. When the inputs could not be resolved, the words `inputs not checked: ...` are printed as the domain states them. What the coordinator says the request is for is shown quoted and labelled a claim; nothing is derived from it. Long lists, the decoded body and the metadata are **folded** to their first entries (`... N more (use --full)`); `--full` shows everything. The review **ends with a summary block** that states what the witness authorises, with and without `--full`: the full request id and body hash (each on its own line, the hash in two halves when the terminal is narrower than 74 columns, never clipped), who asks and how it arrived, the key asked for, the **net** with its direction and the **net assets** (policy, name, amount) leaving or arriving, the outputs to others (addresses shortened to their first and last 12 characters; the full ones are in the body above), **one entry per certificate** (kind and target: the pool id in bech32 with the retirement epoch, the DRep id or `always-abstain` / `always-no-confidence`, the credential it acts on marked `(this key)`, `(another key of yours)` or `(not yours)`, deposit or refund, and the anchor of a certificate or a vote, its URL quoted and its hash in full; a pool registration is described in the next section), **one per vote** (voter, action id, decision), every **required signer**, every **withdrawal** (account, amount, yours or not), any mint or burn (a body with a mint is refused before it reaches a review), and a short fixed warning line for each of `inputs not checked` (it points to the verbatim text printed above, which stays in the review), the payment witness that must come from elsewhere, and deposits not stated in the body. `this key` is the key this witness is for; `another key of yours` is any other payment or stake key of this workspace's store (a pool's reward account and owners, DRep and withdrawal credentials are marked against all of them); everything else is `not yours`. The block also states the **fee**, the **TTL** (`ttl slot N`, or `ttl none`) and, when the body carries metadata, `metadata attached: N label(s) [labels]` (the first 8 label numbers: what a poll answer signed by the cold key is). Each category lists at most 6 certificates, 4 votes, 4 required signers, 4 withdrawals, 4 outputs to others, 4 net assets, 4 mint entries and, per pool registration, 4 owners and 3 relays. A category with more prints `!! N certificates: more than this summary shows ... run spo party review ID --full and read all of them`, and **`party approve` then refuses to ask unless `--full` is given**: every item of a category is in the summary, or the operator is sent through the full review and told so in the block. The block is laid out for the width of the terminal (80 columns when none is reported) and bounded in **screen rows**, not lines: `party approve` computes it before printing anything and refuses when it is longer than the terminal's rows minus the rows the question takes (the question as wrapped at the terminal's width, plus the answer line and one more: 4 when the question fits two rows; 24 rows when no size is reported), so the block is never printed with its top scrolled off. The refusal says the exact figure: `this request needs a terminal at least N rows tall; yours has M`, and to enlarge the terminal or to read `spo party review ID --full | less` and approve in a larger one. The terminal size is read **again immediately before the question** (after the block was printed): when it was made shorter, so the block no longer fits, or narrower, `approve` refuses with nothing asked and nothing signed. The yes/no line itself restates the net, the request id prefix and the first 8 hex characters of the body hash. In `spo tui` the terminal reports the output area it draws in; the question is wrapped whole and the pane above it has exactly the rows that leave (the same figure the command used), the last lines of the output stay visible above it, and page up and page down scroll the pane while the question is open. **The default review prints the certificates, votes, withdrawals, mint, required signers, treasury and donation first**, then the outputs, the fee and validity, the inputs and the metadata, so the fold of the long tail cannot hide them; `party approve` refuses to ask when the default review still folded or clipped any line of those first sections (`... N more (use --full)` inside them), and then needs `--full`. When the default review folded or clipped a line of the certificates, votes, withdrawals, mint, required signers, treasury or donation, `party review` says so on a line of its own **after the summary**, naming the sections that were folded and that `approve` will refuse to ask until `--full` is given. Reviewing is recorded in `party events` (`request-reviewed`). Nothing is signed. `ID` is the whole request id or a prefix of at least 6 characters that **no other request of this workspace shares**, pending or not (answered, refused and closed requests count). |
| `party approve ID [--full]` | Shows the same review again, ends it with the summary block (its first line carries the full request id and the body hash follows; it says `first time this body is shown here` when no earlier review of this body is in the log) and asks `NET ...; request ID body HASH8. Sign this transaction? [y/N]`. It refuses, before printing, when a category exceeds the summary's bound and `--full` is not given, or when the block does not fit the terminal's rows (see `party review`). `party connect --interactive` takes `--full` and follows the same rules. **There is no `--yes`** (it is refused), the default is No, and with no terminal the command refuses. Typed-ahead input is discarded before the question and before the passphrase. On yes, the workspace passphrase is asked again, for every key role (the prompt names the request id prefix and the net), and only then does the key sign. If the coordinator was revoked, its scope narrowed, or your own view of the inputs changed since you read it, nothing is signed and you are told to review again. |
| `party refuse ID [--reason TEXT]` | Declines. The coordinator is told only that you declined; the reason is kept in your own log and never sent. |

Everything a peer chose (labels, purposes, metadata, reasons, and in the review body the relay hosts, the pool metadata URL and the anchor URLs) is written quoted, with control characters, escape sequences, bidirectional overrides and line or paragraph separators as escapes. These commands take `--own-snapshot PATH`, `--inbox DIR`, `--outbox DIR` and the usual `--offline` and genesis options.

**The signer's chain view is its own.** A request is judged by resolving every input by reference through a resolver of this machine's own: in light mode, the provider the workspace is configured with; in any mode, `--own-snapshot PATH`, an offline snapshot (transfer file) that **you took on this machine**. The offline transfer file of the workspace is never used by itself: it is a snapshot only when you name it with `--own-snapshot`, and a file a coordinator sent is never a source. The file is opened once, without following a link, judged on the open descriptor and **read once**; the resolver is handed those bytes (a private copy that is removed when the command ends), never the path. `--own-snapshot` is refused for a path inside the sealed workspace (its head and lock files included), the party directory, the inbox or the outbox in effect **and the inbox or outbox that `spo.toml` configures, even when another `--inbox` is given**, a symbolic link, a file that is not a regular file, one that is not owned by you, one writable by its group or others, **one with more than one hard link** (it may be the same file as one in an inbox under another name; copy it and name the copy), and one with an ancestor directory that others can replace (the inbox parent-directory rule below). A request for a non-payment key role that arrived by file can still be reviewed and approved when its inputs are unresolved, under the `inputs not checked` text; a payment-key request cannot. **What this cannot detect:** a file a peer's bundle wrote somewhere else on the disk (`offline extract` and a copy from a stick leave no record of where a file came from), a transfer file whose history was written by another party, or a snapshot taken on another machine. The path is your statement that this machine took it. Without a resolver, a request that arrived over a network is refused automatically and in silence for every key role, and a payment-key request is refused on every transport.

### Closing notices and rotation messages

**Closing notice** (SPO-Xparty-INV-035 to INV-037). When a collection ends, the coordinator seals a `CollectionClosed` to each party it sent a request of that collection to and queues it in the outbox, to be carried like anything else (`outbox export`, or `serve` over tailcat). A collection ends when it is submitted (`pool register` recorded a submission after the first request **and the id of the transaction it submitted, which is this collection's own body id**: a collection that was replaced and then discarded while the pool was registered with another body is announced as discarded; the notice names the transaction id), discarded (`pool witness clear`) or expired (its TTL slot passed; needs the chain time). The coordinator notices at its next `outbox export`, `request export`, `request queue` or, in `party serve`, at start and every minute. The notice is **advisory**: it marks the signer's requests of that collection closed (`party requests` lists them apart, `party review` and `party approve` refuse them naming the outcome, and the claim of an approval does too, before the passphrase is asked) and does nothing else; it cannot make a signer sign, approve or send anything. The first outcome stays. A notice from a party that did not ask this signer for that collection, about a collection nobody asked about, naming a transaction that is not the body hash of the requests, repeated, or from a party that is not a coordinator is dropped and recorded in `party events`.

**Rotation messages** (SPO-Xparty-INV-031). The announcement of `party rotate` is a `Rotation` message sealed by the old identity. Any enrolled, active party may send one. Receiving it, by file or over tailcat, only stores it as pending (one per sender, at most 16) and records `rotation-received`; the enrollment changes only through `party rotation accept`. Carry the announcements by file: a rotated party cannot open a tailcat connection to a peer that has not accepted yet (its first frame is sealed by the new identity), and a peer cannot reach it either, since its old encryption key is gone. The tailcat node key is not rotated: a statement whose new identity has another node key (or gains or loses one) is refused at receipt and at acceptance. A revoked record keeps its node key but does not hold it, so a party can rotate any number of times and the key can be enrolled again, under a new local name, after the party was revoked.

**Rotation operating conditions** (SPO-Xparty-IF-008). The announcement is sealed and signed once, by the old identity, and is valid for **7 days**. It stays in the outbox, sealed, for that time: `party outbox export DIR --resend-rotation` writes the ones already written again (a file lost on the way). After the 7 days it cannot be made again, because the old private key is gone, and a peer that never got it must enroll the new identity from scratch (`party enroll`). The tool does not know which peers accepted: rotate again only after every peer has, because a peer still holding the first identity does not know the second. After the commit the replaced keys may stay in a backup made earlier, and in the store's write-ahead log only if the checkpoint failed (the command then says so).

**What an approval re-checks at the end** (SPO-Xparty-INV-038). The operator may sit at the passphrase prompt for a long time. When the signature is stored, the signer reads again whether the request is closed, whether its sender is still an active enrolled party with the fingerprint the request came from, and whether this machine's identity is still the one loaded before the prompt. If not, the answer is dropped (nothing is queued, `approval-dropped` in `party events`) and the command says nothing was signed. The outbox is a second line: it lists and sends only items for an active enrolled party and sealed by this machine's current identity; anything else is dropped with `outbox-item-dropped`. **Operating conditions of revocation, scope and rotation.** An item already handed to the transport when a revocation or rotation commits in another `spo` process still leaves: the window is one flush (seconds under `serve`/`connect`). The scope is not re-checked after the approval's claim (SPO-Xparty-INV-025): narrowing a coordinator's scope while the operator is at the passphrase prompt does not undo that signature. A peer that never collects its announcement blocks `party rotate` until the announcement expires (up to 7 days), with no override. A checkpoint warning after `party rotate` means the write-ahead log was not folded: close every `spo` process on the workspace and open it once more. A collection whose registration was only queued offline is announced as `queued`, not `submitted`: the signer is told the transaction may never have reached the chain. **Terminal size** (SPO-Xparty-INV-039): `party approve` reads the size again after the answer and signs nothing when the terminal is narrower or shorter than at the question. A resize and a resize back during the question is not detected.

### File transport

| Command | What it does |
| --- | --- |
| `party request export POOL [--out DIR] [--purpose TEXT] [--renew]` | Coordinator. For the open witness collection of `POOL` (`spo pool register POOL PAYER --allow-pending`), seals one request per open slot that belongs to an enrolled signer and writes it as `SigningRequest-<collection>-<slot>.spo` in `DIR` (default: the outbox). **Only the requests of this pool's collection are written**; everything else waiting in the outbox (responses, invitations, other collections' requests, for other parties) stays queued. A request for the pool cold key may go by file. |
| `party inbox import FILE\|DIR... [--as coordinator\|signer]` | Copies each file into the inbox and reads it. A signer's request becomes pending; a coordinator's response fills its slot, and when the collection is complete it says so: finish with `spo pool register POOL PAYER`, which asks the operator and submits or queues. `--as` is needed only when this machine is both. A file that fails a check is refused and recorded, and nothing goes back. |
| `party outbox export DIR [--yes] [--resend-rotation]` | First announces, to the signers that were asked, the collections of this machine that ended without a notice (see the closing notice below). Then writes **everything** waiting here (responses, refusals, invitations, closing notices, requests not yet carried) as files in `DIR`, and says so. Before it writes anything it lists what goes out per recipient (the local name of the party); when the envelopes are for more than one recipient it asks to confirm (default No; `--yes` answers for scripts), because one directory would carry another party's files. The names say what a file is (`<type>-<collection>-<slot>.spo`, or `envelope-<hash>.spo`), not who it is for, and no longer carry the recipient's fingerprint; carry each file to the party it is for. To write one pool's requests only, use `request export`. |

**Operating conditions of the file transport** (ADR 0005, obligation 5; SPO-Xparty-IF-004). The inbox is a local directory that only the operator can write to. It defaults to `party/inbox` in the workspace, created `0700`; `--inbox` or `[party] inbox` in [spo.toml](./spo-toml.md) names another. It is refused when it is a symbolic link, not a directory, not owned by the user running `spo`, writable by its group or by others, or, on Linux, on a network or FUSE file system (NFS, SMB/CIFS, 9p, Ceph, OpenAFS, kAFS, Coda, ncpfs, FUSE: checked against `golang.org/x/sys/unix` and `linux/magic.h`; GPFS: found only in another project's table; vboxsf, BeeGFS, Lustre and `0x6a656a63`: in the list but **not verified**, found in neither the kernel headers nor `x/sys/unix`, Lustre's value being from memory. An earlier table gave Lustre `0x19800202`, which is the POSIX message queue file system). **The parent-directory rule** is the one `sshd` applies under `StrictModes`: every directory above the inbox, up to the filesystem root, after links are resolved, must be owned by root or by you and must not be writable by group or others unless it has the sticky bit (`/tmp`); whoever can rename a parent can swap the inbox for another directory. The directory is judged through one descriptor (opened as a directory, not following a link) and the transport reads through that same directory (device and inode checked). `--own-snapshot` follows the same ancestor rule. In a user namespace (rootless container, sandbox) the root directory may be owned by an id with no mapping; that is accepted for `/` only. Any other directory above the inbox or snapshot must be owned by root or you: a bind mount owned by another host user is refused. **It must never be a synced folder** (Dropbox, Syncthing, a cloud drive's folder): whoever can write into it feeds envelopes to the signer as if delivered by the operator's own hand, and a file is the more trusted kind (a pool cold key request is allowed by file and refused over a network); `spo` cannot tell a local directory that a sync client copies. Files you name are read as regular files of at most one envelope (1 MiB), never through a link. An export target (`--out`, `outbox export DIR`) may be a mounted stick. Envelopes carried by file have **no forward secrecy**: someone who later obtains the recipient's X25519 key can read old files (witnesses and bodies become public on chain; the exposure is the request metadata). A file is not tied to the connection that carried it: the same checks run as over a network.

**What the summary lists for a pool registration** (one entry per registration certificate; the same in the review, with or without `--full`): the operator pool id (marked `(this key)` when it is the key asked for); the **VRF key hash in full** (64 hex characters on its own row: a re-registration that swaps it stops the pool producing blocks); pledge, cost and margin; the reward account and every owner, each marked `(this key)`, `(another key of yours)` or `(not yours)`; the relay count and the first 3 relays (`relay 1 of N dns "host":port`, host or address quoted); and the **metadata URL quoted in full** with the **metadata hash in full**, or `no metadata`. Text taken from the body is quoted with spaces, quotes and control characters escaped (`\u{20}`), so it is one word and cannot forge a row. More than 4 owners or 3 relays in one registration prints `!! N pool owners of certificate K: more than this summary shows (first 4 listed, and M more not shown)` and approve then needs `--full`.

**Minimum terminal size for `party approve`.** The block is laid out at the terminal's width, at least 44 columns (narrower is refused). The registration the workbench itself builds for a pool with two owners (the registration, and one stake delegation per owner, with the unchecked-inputs and deposit warnings) is **26 rows at 80 columns on a testnet** (about 24 at 100 and 23 at 120), so `party approve` needs a terminal **at least 30 rows tall** at 80 columns (the block, plus the question and the lines kept below it). A registration alone with two owners and one relay, no delegations, is 18 rows (22 tall). Each further owner (up to 4), relay (up to 3) or certificate adds rows, and a longer question (a net with assets, in a narrow terminal) adds rows to the reserve. A 24-row terminal, or a size that is not reported (24 is assumed), therefore refuses a real pool registration, saying `this request needs a terminal at least N rows tall; yours has M`: enlarge the window, or read the request with `spo party review ID --full | less` first and approve in a larger one. The block is never printed with its top scrolled off. In `spo tui` the same figure applies to the pane (the screen minus the header, help line and status rows), so the terminal must be 5 rows taller than the figure: **35 rows** for that registration at 80 columns.

**Do not run under a root directory owned by another unprivileged user.** The ancestor rule above accepts the filesystem root only when it is owned by root or by you, or, in a user namespace, an unmapped id. A workspace, inbox or snapshot under a directory tree whose root is owned by a different unprivileged user (a bind mount, a container root, a shared home) is not a supported operating condition: that user can rename the directory above the inbox and swap it. Run `spo` on a tree you own.

A request that arrived by file is answered again only by file: a duplicate of the same request id over another kind of transport gets no answer.

### tailcat transport

| Command | What it does |
| --- | --- |
| `party serve [--invite NAME]... [--outbox DIR]` | Coordinator. Listens on the tailcat port, admits only the node keys of active enrolled `signer` and `machine` parties (a party is admitted with the `signer` role) (an empty allow-list is refused: tailcat would admit everyone), sends each connected signer its open requests, takes responses in. Runs until stopped. `--invite NAME` writes the sealed invitation for that signer as a file in `--outbox`; do it while nothing else waits in the outbox. The address contains the pre-shared key: it is a sealed record, **never printed**, and given only inside an invitation sealed to that signer. A response that completes a collection submits nothing. Needs an identity made with `--tailcat`. |
| `party request queue POOL [--purpose TEXT] [--renew]` | Like `request export`, but the requests stay in the outbox for `serve` to deliver. Refuses a pool cold key slot. |
| `party connect COORDINATOR [--interactive]` | Signer. Dials the coordinator named in an invitation you imported, says Hello, sends queued responses and receives requests into the pending list. The server drops an idle connection after 30 seconds: it reconnects with a fresh Hello and a backoff (1 s doubling to 30 s). The backoff is reset only when a frame was received on a connection; after 5 connections in a row that close before any frame it prints the likely causes (revoked by the coordinator, clocks more than five minutes apart, wrong coordinator) and keeps backing off to the cap. Receiving never signs: approval is `party review` and `party approve` in another terminal, or `--interactive`, which runs the same review and the same prompts (default No, then the passphrase) in this process. At startup a signer with no chain view of its own says that every request that arrives over tailcat will be refused automatically and in silence (SPO-Xparty-PRE-007). |

Neither command is available in offline mode. [spo.toml](./spo-toml.md) has `[tailcat] port` and `derp_map_url`; the node key, the pre-shared key and the coordinator's address are sealed records, never settings, and there is no tailcat auth key in any argument, variable or file.

**Operating conditions of the tailcat transport** (ADR 0005; SPO-Xparty-IF-005, IF-006, INV-018, INV-019, INV-021):

* A tailcat node key proves possession of a WireGuard key, not who is acting. The envelope inside is checked again in full, whatever the tunnel said.
* **Clocks must agree to within five minutes** for tailcat: a `Hello` has a five-minute lifetime and one outside it is refused, and an envelope dated more than 10 minutes in the future is refused whatever the transport. A signer whose clock is off sees its connection closed before any frame.
* The first frame of every connection is a fresh `Hello` (new message id, five-minute expiry) from an active enrolled `signer` whose enrolled node key is the one tailcat authenticated for the connection, and not in the replay log; otherwise the connection is closed with no bytes written. A later frame on the connection is bound to nothing but its own signature. Two parties cannot share one node key.
* Limits per connection: 64 frames, 30 seconds idle, 16 concurrent connections, 6 connections per node key per minute, 2 live connections per node key, a connection lives at most 10 minutes.
* **One pre-shared key serves every signer of a coordinator** (it is in each invitation's address), and a revoked signer still knows it. What stops a revoked signer is the allow-list of node keys and the `Hello` check (an active enrolled `signer` whose enrolled node key is the one authenticated), not the secrecy of the key.
* tailcat cannot remove a key from its allow-list while running: a revoked party's node key can still open a tunnel until the server restarts without it. Our listener refuses it and closes its connections.
* **A pool cold key is never requested or accepted over tailcat**: the coordinator does not send it and a signer refuses one that arrives (the refusal is sent). Use the file transport.
* A request that arrived over a network is refused in silence unless the signer's own resolver resolved every input and every input address could be read (see above). A refusal that depends on what the signer holds, owns or trusts (no such key, out of scope, no input of it, inputs unresolved) is recorded in `party events` and never sent, so an enrolled coordinator cannot use the answers to probe the signer.
* The tailcat node key and the coordinator's address are held in ordinary memory by tailcat while it runs.
* Revocation takes effect for the envelope check the moment it commits; for the connection, within the sync interval of the serving process (seconds).

### Walkthrough: a pool registration with two owners, by file

Alice's machine is the coordinator (cold key, payer, the first owner); Bob's machine holds the second owner's stake key. The descriptor names Bob's slot as `--owner second:bob`, where `bob` is the local name Alice's machine gave him.

1. Both: `spo party init --label "..."`, then `spo party export FILE`. Swap the files, read each other the first four groups of the fingerprint by phone.
2. Alice: `spo party enroll bob.id --as bob --role signer`, and type Bob's four groups. Bob: `spo party enroll alice.id --as alice --role coordinator --key-role stake --pool POOLID`, and type Alice's.
3. Alice: `spo pool register POOL PAYER --allow-pending` (the second slot stays open), then `spo party request export POOL --out DIR --purpose "register POOL"`. Carry `DIR/SigningRequest-*.spo` to Bob.
4. Bob: `spo party inbox import FILE`, `spo party requests`, `spo party review ID`, then `spo party approve ID`: answer `y`, type the passphrase. `spo party outbox export DIR2`. Carry `DIR2/SigningResponse-*.spo` back.
5. Alice: `spo party inbox import FILE` (it says the collection is complete), then `spo pool register POOL PAYER`: the transaction is assembled from the stored body and the stored witnesses and submitted or queued. Its id is the body hash Bob reviewed.

### Walkthrough: the same over tailcat

Both identities were made with `--tailcat`, and both machines are in light or online mode (`--offline` stays on the commands that read the transfer file). Steps 1 and 2 are as above.

3. Alice: `spo party serve --invite bob --outbox DIR` (leave it running). Carry the invitation file in `DIR` to Bob: Bob runs `spo party inbox import FILE`.
4. Alice: `spo pool register POOL PAYER --allow-pending --offline`, then `spo party request queue POOL --purpose "..."`.
5. Bob: `spo party connect alice --own-snapshot SNAPSHOT` (leave it running; light mode needs no `--own-snapshot`). The request arrives; nothing is signed.
6. Bob, in another terminal: `spo party review ID --own-snapshot SNAPSHOT`, `spo party approve ID --own-snapshot SNAPSHOT`.
7. `serve` prints that the collection is complete. Alice stops it and runs `spo pool register POOL PAYER`.

### What is not built

* No command closes a collection to the signers (`CollectionClosed`) when `spo pool register` submits it: the signers' requests stay pending until they expire.
* Collections that are not a pool registration have no command; the coordinator library supports them.
* A hardware-wallet signer holds keys but is untested on devices (see the device checklist).

## Hardware wallets

> **Untested on real devices.** The hardware path is built and tested against a stand-in for `cardano-hw-cli`, not against a Ledger, Trezor or Keystone. Before relying on it, work through the [device checklist](../development/hardware-device-checklist.md) with throw-away keys on a test network.

The device is driven by the release set's pinned `cardano-hw-cli` (a Node tool). It is wired only when the binary has a toolchain manifest that provides it (`nix run .#spo`); otherwise capability `hardware-wallet` is absent with that reason and every `--hardware` command refuses, listing it, before anything is asked. The device is not opened to describe the environment or to start a command: the first step that needs it (the signing plan) opens it, and a software-only command never touches it. While waiting for the device, `spo` prints on stderr `Connect and unlock your device and open the Cardano app` with the time left (default 60 seconds, `[hardware] wait_seconds` in [spo.toml](./spo-toml.md)).

What a device may hold is decided by its vendor and app version, before anything is built or shown ([ADR 0008](../explanation/adr/0008-capability-typed-ports.md)): for example a Trezor is refused for a pool cold key with one message and is never asked to generate one. Only the public key and the derivation path of a hardware key are stored (the hardware signing file); a private key never leaves the device.

**Which signer answers.** A key is named by its identity (the hash of its verification key) and its role, never by who holds it. A signing command takes no flag that says a key is on hardware: the directory of connected signers decides, from what the workspace stores for that key (a signing key for the vault, a hardware signing file for a device) and from what is connected now. A key with both a signing key and a hardware signing file is signed on the device (upstream's rule), except an operational certificate, which the software key signs; with no device connected the plan refuses rather than falling back to the signing key. An owner the pool descriptor leaves to another signer (`ownerWitness` not `local`) is never signed here, even when its key is also in this workspace. When a key answers through another name the confirmation says so and names the record that signs. A key that is on a device while no device is connected is refused by the plan with `no hardware signer is configured`. A key that was ever a pool cold or committee cold key is never asked for over a network transport, whatever role the request names. The `--hardware` flags below keep working, and mean only where a NEW key is generated; `spo pool calidus sign` and the other signing commands have none. The Calidus signing command no longer reports a suspended hardware path: a Calidus key has no hardware form, so a hardware signing file alone is "no signing key".

**Key generation** takes `--hardware` (the new key is made on the device) and the variants of the key:

| Command | Hardware flags |
| --- | --- |
| `wallet new NAME` | `--hardware`, `--account N`, `--index N`, `--multisig` (purpose 1854H for the payment key), `--hybrid` (with `--stake`: payment key on the device, stake key in the workspace). Not with `--mnemonic`. |
| `pool keys generate POOL` | `--hardware`, `--index N` (path `1853H/1815H/0H/NH`) |
| `drep keys generate`, `committee keys generate-cold`, `committee keys generate-hot` | `--hardware`, `--account N`, `--index N` |
| `policy new NAME` | `--hardware` |
| `catalyst key new NAME` | `--hardware`, `--account N`, `--index N` (path `1694H/1815H/NH/0/N`); Ledger only. Not with `--mnemonic-in-fd`. |
| `pool calidus new NAME` | `--hardware` is refused: a Calidus key has no hardware path (`SPO-15-PRE-002`). |

`--multisig`, `--hybrid` and the path numbers without `--hardware` are refused.

**Signed messages and registrations.** A pool cold key on a Ledger or Keystone signs the Calidus registration (`pool calidus register-metadata`), and a stake key on a Ledger signs a Catalyst registration (`catalyst register`); see their sections. The profile of each device is one table in `spo/internal/domain/custody/hardware.go`, and what a row does not state is refused before the device is asked: Calidus keys on any device, Catalyst voting keys and CIP-36 signing on a Keystone or a Trezor, a message signed with a payment, stake or DRep key, and a Trezor for anything a Ledger-only row names. The Trezor derivation type (`cardano-hw-cli`'s `--derivation-type`) is not set: the specs do not mention it, so Trezor keys are made with the tool's default (checklist item 20).

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

Text that a chain, a provider, a peer or a file chose (anchor URLs, pool tickers and names, action titles, provider error bodies, the lines of a transaction summary) is printed through one scheme, `platform/textsafe`: control characters (C0, DEL and C1), bidirectional and other invisible format characters, line separators and bytes that are not UTF-8 are written as `\u{hex}`. `Quote` (used by the party commands) also escapes the space, quote and backslash so a value is one word; `Text` (used by the summaries and provider errors) leaves them. Not yet covered: the Blockfrost adapter's error-body prefix, which still replaces only C0 controls.

## Exit status

`0` on success, `1` on any error. The message is on stderr, prefixed `spo:`. `spo tx status` and `--wait` use other non-zero codes for their outcomes, listed under [`tx status`](#tx-status-and---wait-after-a-submission). A check whose verdict is not OK (`pool opcert check`: FALSE or UNKNOWN) is an error, unlike upstream `04e`, which exits `0` after a FALSE verdict.
