# Convert a workspace to a sealed layout

Reference: [`spo-cli.md`](../reference/spo-cli.md#store-convert). Background: [ADR 0012](../explanation/adr/0012-server-backup-and-deployment.md), decisions 4 and 6, and "Implementation notes, stage 3" at its end. Spec: [Xlayout](../../spec/extensions/Xlayout.md).

**This has not been run on a real authenticator or on a network file system.** The tests use stand-ins for the libfido2 tools and local temporary directories. Try it on a throw-away workspace first.

## What it is for

`spo store convert --to-layout DIR` writes the workspace into a directory as a set of sealed files: one file for every record and every audit row, a few small files that list them (the manifest), a plaintext file with the key slots, and one small plaintext head note that names the manifest. Every sealed file is padded to a fixed size (4 KiB up to 4 MiB) and is named by the hash of its bytes. It is a copy to keep and to check against later. It is the format a later stage will serve from a server.

Run it again and only what changed is written. A record that did not change has the same name as before, so nothing is written for it.

## What it is not

* **It is not a second workspace.** You cannot open it, write to it or sign with it. The SQLite file (`workspace.spo`) stays the only store you can write to. Nothing was retired, renamed or marked.
* **It does not replace `store backup`.** A backup is the whole sealed file and restores with `store restore`. A layout is read back with `store verify --layout` and `store convert --from-layout` (below).
* **It cannot sign with a cold key.** Cold-role records are carried exactly as they are stored. Nothing here opens one.
* **You can read it, not write it.** `spo -C DIR --pin PIN` opens a layout read-only for the few commands that only read ([below](#open-a-layout-read-only-spo--c-dir---pin-pin)). To write, or to sign with a key, import the layout into a workspace first.

## Before you run it

* `DIR` must be a local directory on a local file system, empty or new (the tool creates it with mode 0700), or already a layout of this workspace. It must not be the workspace directory, inside it or above it, must be owned by you, and must not be writable by its group or by others. An `s3://` URL is refused: this version writes to a directory only. `dir:/absolute/path` is accepted, as is a relative path.
* A directory that holds anything else (a file of your own, a layout of another workspace) is refused, and nothing is made in it.
* The workspace is unlocked the normal way: a `standard` workspace asks for its passphrase, a `hardware` or `strict` workspace for its daily authenticator (`--fido2-device`, `--fido2-pin-fd`). `--unlock recovery-composite` is refused. The authenticator is presented once, as for `store verify`: the keys are taken from the one verified private copy of the file.
* Every refusal that needs no secret is made first, so nothing is asked of you for a run that would be refused. The one thing that is known only after unlocking is whether the workspace has a checkpoint key, so a layout without a pin is refused (or accepted) after the unlock.

## Run it

```
spo -C ws store convert --to-layout /srv/spo-layout
```

The command prints the number of objects written and reused, the head and a pin line:

```
Pin: <workspace id>:layout:<sequence>:<head hash>
```

**Keep the pin somewhere else**, not in the workspace directory and not in the layout directory. This machine also keeps it in a file beside the workspace file (`workspace.spo.layout-<16 hex>.pin`, one for each layout directory), and from then on refuses to write to a directory that is behind it: a layout that was rolled back or replaced. The file only moves forward. If it is damaged the tool says so and does not replace it; look at it, move it away if you are sure, and run the command again.

**What the pin file means.** It lives beside the workspace file, one for each layout directory. It is how this machine knows which head it last wrote there. With it, the tool chains a new head only onto the pinned head and the heads after it, each linked to the one before, none missing, and, when the workspace has a checkpoint key, each signed with it. Heads above the pin that fail this are not chained onto: the run names the first one and says to use a fresh directory. **If you delete the pin file** (or run on another machine, or restore the workspace directory from a backup that lacks it), the tool no longer knows what it wrote. For a directory that already has heads it then does this:

* with a checkpoint key enrolled, it trusts the layout only if every head in it carries a signature that verifies against the key, says so, and records the pin. A head that does not verify is refused by name, and **`--adopt-layout` does not override it**: the key is the authority, and the only remedy is a fresh directory;
* with no key, it refuses and prints the newest head it would be trusting (sequence, audit sequence, hash, time). `--adopt-layout` is your statement that this layout is yours; it is for a workspace with no checkpoint key. The tool says what it trusts before it records the pin.

Every head the new head builds on must also be this workspace's history: the audit position and MAC in each head must be the workspace's at that sequence, and, since the last rotation, the epoch and the recovery key must be the current ones. A layout of a workspace that diverged (restored from a diverged backup) is refused by name.

Without a key a layout can be forged by anyone who can write to the directory, as long as they link the heads and leave no gap; a key is what makes the check mean something.

Run it again after the workspace changed and a new head is written, naming the old one. Run it with nothing changed and the command says the layout is already up to date and writes nothing.

## Sign the head

A head with no signature is protected against accidents (a half-written directory, a damaged file), not against forgery: whoever can write to the directory can write a head of their own. If the workspace has a checkpoint key ([Back up to a sink](./back-up-to-a-sink.md#the-checkpoint-key-and-the-long-lived-pin)), the command signs the head note with it, after everything else has been written and read back and before the head is put: one PIN and one touch (`--checkpoint-device`, `--checkpoint-pin-fd`). The signature is a standard SSH signature in the namespace `spo/head-provisional/v1`, kept as `heads/<sequence>.sig`, and stock `ssh-keygen -Y verify -n spo/head-provisional/v1` checks it. The command also prints the long-lived pin (`<workspace id>:ck:<key hash>`).

* `--no-checkpoint` skips signing; the head names no key.
* If signing fails, no head is written. The command says "objects written, no head written" and exits non-zero. The objects are in the directory and are not written again when you run it again. The newest earlier head, if any, is still complete.
* If the newest head is current but has no signature and you ask for one, the command signs that head and writes only the signature.

## What someone who can read the directory sees

The command prints this paragraph with every run. In short:

* the number of objects, and how many there are of each size (4 KiB, 8 KiB and so on), so roughly how many records and audit rows there are, and which objects are new since the last run;
* the slots object, in plaintext: the workspace id, the policy, the key slots (salts, wrapped keys, key-derivation settings) and the recovery public key. The workspace file shows the same;
* the head notes, in plaintext: sequence numbers, hashes, the position of the audit chain, the time of each run;
* when each file was written, and in what order.

They do not see record kinds, names, labels, anchors, ids or sizes (only the bucket). Every object is sealed and padded to its bucket. A `standard` workspace is only as strong as its passphrase, as for a backup; the slots object lets someone with the directory guess it offline, so keep the directory where only you can read it, or use the `hardware` policy.

## What the tool checks in the directory

Every object a head will name is read and hashed in the run that writes the head. A file under an object's name that does not hash to that name (damaged, cut short, longer, or replaced) stops the export, naming the object. The tool never overwrites or deletes anything in a layout, so the remedy is a fresh directory. "Already up to date" is said only after every object has been read back this way, so a re-export reads the whole layout (about a second for 50,000 audit rows on a local disk; time grows with the size). The newest head's manifest and slots object are also checked before anything is asked.

A signature file counts only after it verifies against the workspace's checkpoint key; one that does not is reported and never called a signature. Anything in the directory that is not a regular file of a layout's names (a link, a FIFO, a socket, a device, a stray file) is refused by name before anything is asked, and the tool never waits on one. Each directory is read in chunks and abandoned at a cap of 1,000,000 entries (a scan costs about 1.6 s per million entries when the file system is warm), so a directory with an enormous number of names cannot make the tool read it whole. The tool's own stale temporary files (older than an hour) are removed. The directory is opened once and everything is done relative to it, so replacing it during a run cannot redirect a write.

## If a run stops

The order is: the slots object, the records, the audit rows, the manifest pages, the manifest root, and last the head. A head is never written before what it names. A stopped run (a full disk, a lost lock, Ctrl-C, a failed signature) leaves the newest earlier head complete. If the run stopped between putting the head and putting its signature, run the same command again: it signs that head and puts only the signature, provided the workspace has not changed since, the head is the only one above the pin, and the head's time is sane (not before the pinned head's, not more than five minutes ahead). If the workspace changed since, that head can never be signed and the directory cannot be extended: use a fresh directory. Otherwise run the same command again: objects already there are found, not written again. The tool never deletes or replaces anything in the directory; a file in `heads/` that is not a valid head, or a signature with no head, blocks the directory: move it away yourself or use a fresh directory.

Only one export can run on a directory at a time: the command holds a lock file (`.spo-export.lock`) in it and a second one is refused. The directory is checked again before every write; if it is replaced meanwhile (moved, or swapped for a link), the run stops and writes no head.

## Check a layout: `store verify --layout`

```
spo -C ws store verify --layout /srv/spo-layout --pin PIN [--at SEQ] [--locked]
```

It changes nothing: not the directory, not any workspace. **A pin is required.** Without one the command refuses and says how to get one: it never checks a layout by trusting the directory. There are three forms, and they prove different things.

| Pin | What it proves |
| --- | --- |
| `<workspace id>:layout:<sequence>:<head hash>` (what the export printed) | That head, and through the `previous` hashes the chain below it. It does **not** authenticate a later head. If the pinned head names a checkpoint key, every later head must be signed by that same key; if it names none, later heads are accepted as chained by hash only and the output says nothing authenticates them (`--at <that sequence>` uses only the pinned head). |
| `<workspace id>:ck:<key hash>[:<minimum sequence>]` (the long-lived pin) | Every head from 1 to the one used carries a signature of that key. With no minimum sequence it proves the head is authentic, not that it is the newest; with one, an older copy is refused. |
| `local` | The pin this machine keeps beside the workspace file for a layout it exported itself. It is read as an exact pin. |

The check has two passes.

* **The locked pass asks for nothing.** It walks the heads by number, checks the pin, the links, the workspace id and the signatures, fetches the slots object and the manifest root by hash, checks their sizes, epoch and hashes, and runs the unlock-policy check on the slot table. It says what it proved and what it cannot: it cannot open a sealed object, so it does not know that the records are what the head says. `--locked` stops here and touches no authenticator.
* **The unlocked pass** opens the manifest and every object with the credential of the workspace (the passphrase of a `standard` workspace; the daily authenticator of `hardware` and `strict`, never a passphrase, never the recovery composite). It checks every object against its manifest entry, each record's anchor and number against its owner blob, the last audit row against the manifest root, the slot table against the newest slot-table audit row and the epoch MAC. It then writes the rows into a private scratch store file, which has to pass the store's own full verification (the audit chain, every record hash it recorded, the policy), and removes the file. No record is decrypted and no cold-role factor is asked for.

**The slot table decides the credential, so the pin must vouch for it.** With an exact pin (or `local`) the pinned head's slots object is fetched and checked, and a later head's table is used only if its policy is not weaker, its recovery key is the same and it names only this workspace's own authenticator RP id. Otherwise the check refuses before asking for anything and says to pin a newer head, use a key pin or use `--at <pinned sequence>`. **After a rotation that changes the recovery key or lowers the policy, take a newer pin.** A signature counts only for a key the pin vouches for, and a later head that names a key the pinned head did not is refused: after you enrol a checkpoint key, pin the first head that names it, or use the key pin. With an exact pin the output says the head used is the newest the directory offers, not necessarily the newest there is: a head deleted above the pin cannot be detected.

**A head that fails stops the check.** The command names it, says why, names the newest head below it that did verify, and says that you may use that one with `--at SEQ` if you accept that state; the pin still has to accept it. A directory with junk in the next head's name is such a case. `--at` naming a head that is not in the directory is refused.

**Limits.** At most 100,000 heads; an object is at most 4 MiB; a manifest that claims more than 100,000 records or 500,000 audit rows is refused before anything is fetched; at most eight objects are read at once. A layout at those limits needs under 1 GiB of memory (the snapshot is held in memory, up to 256 MiB of fields, twice while the scratch file is written and read back). Measured on a layout with 50,000 audit rows and 200 records (199 MiB, warm cache): checking the objects took about 0.3 s and 81 MiB of heap, and writing and verifying the scratch file 0.75 s and 205 MiB; the whole process peaked at 271 MiB. The worst case at the limits (about 600,000 rows) is estimated, not measured.

## Open a layout read-only: `spo -C DIR --pin PIN`

```
spo -C /srv/spo-layout --pin PIN store slots
```

When `-C` names a directory that is a sealed layout (it has `heads/` and no `workspace.spo`), `spo` opens it read-only. **A pin is required**, in the forms above except `local` (that is the pin this machine keeps for a layout it exported, and here the layout is the directory itself, so give the printed pin or the long-lived pin). Without one the command refuses, before it asks for anything, and says how to get one.

**The top-level `--pin` is only for a layout.** If `-C` names a directory that holds a workspace file (`workspace.spo`), with or without a `heads/` directory, or one with no `heads/` directory, the command is refused first, before the pin is looked at, with an error that says what the directory holds. A sink that planted a `workspace.spo` among the objects of your layout cannot get a command to open it as a workspace. The mode is decided once at the start of the command; a file that appears later changes nothing. `store verify --layout DIR --pin PIN`, `store restore` and `store backups` have a `--pin` of their own and work from an ordinary workspace as before.

A damaged or forged directory is refused as `store verify --layout` refuses it, and nothing runs.

**How it works.** The command runs the two passes of `store verify --layout`, writes the checked rows into a private scratch store file (a directory of mode 0700 in your temporary directory), and opens that file read-only. The layout directory is never written: its files, modes and times are the same after every command. The scratch file is removed when the command ends, on success, on a refusal, on Ctrl-C and on a crash; one that a killed process left behind (a day old or more, named `spo-layout-open-*`) is removed by the next open. Nothing in it is your workspace.

**Read-only is not a convention.** The handle refuses every write with one error: "this is a sealed layout opened read-only; convert it into a workspace to change it: spo store convert --from-layout DIR --pin PIN".

**What works:**

| Command | Result |
| --- | --- |
| `store slots` | Lists the slots (and the cold records that are out of step). |
| `store verify` | The same as `store verify --layout DIR --pin PIN`, byte for byte. `--at` and `--locked` apply. `--deep` also opens the scratch file and decrypts every record (a cold-role record only as far as the workspace key goes). `--locked` with `--deep` is refused. |
| `workspace slot list`, `workspace policy show` | Print what the slots object says. |
| `workspace checkpoint-key show` | Prints the checkpoint key record, or says there is none. |
| `version`, `toolchain check` | Do not use the directory. |

**What is refused, and why.** Every other command is refused with the error above, before the terminal, the credential or an authenticator is asked. They write (a key, a certificate, a counter, an audit event), or they need the configuration `spo.toml` or the transfer file or a place for their own files, and a layout holds none of these. This includes `pool opcert issue`, `pool kes generate`, `wallet send`, `store backup`, `workspace export` and `node export`. A test walks the command tree, so a command added later is refused until it is classified.

**Keys.**

* **Cold-role records are never opened from a layout.** Opening one would change the salt of its cold factor in the file, and a read-only open cannot, so every open would show the authenticator the same salt. Opening one through the handle fails with a message that says so and names the conversion, and **no cold factor (no passphrase, no touch) is ever asked for**.
* A hot secret can be opened through the handle without any write, but no command in this release offers it: signing with a hot key records a counter or an audit row, and the commands that sign need the configuration. So **signing, with a hot key or a cold one, is not possible from a layout**: convert it into a workspace first (`store convert --from-layout`, below).

**Not audited.** A read-only open writes no audit row, so what you read from a layout is not in the audit chain. The command prints a note that says so.

**Touches.** The credential is presented **once** for a read-only open: the unlock of the slot table keeps its key, and the scratch file and the read-only handle are made from it. For a `hardware` or `strict` layout that costs the authenticator the same assertions as one presentation for a `store verify` of a workspace (the tests count the assertions of the stand-in tools). `store verify` of a layout without `--deep` presents the credential twice (the store verifies the scratch file through it again); with `--deep` once. A passphrase never opens a hardware or strict layout, and `--unlock recovery-composite` is refused. None of this has been run on a real authenticator.

**Recovery on a new machine.** With only the directory, the pin and your credential you can look first: `spo -C /media/backup/spo-layout --pin PIN store slots` and `store verify --deep`. Then convert it into a workspace as in the next section. The layout stays a read-only artefact; the SQLite file is the only store you write to.

## Recover on a new machine from only the layout and a pin

You need the directory (a copy of it is enough), the pin, and the credential of the workspace: the passphrase, or the daily authenticator. Nothing else from the old machine.

```
spo -C newws store verify --layout /media/backup/spo-layout --pin PIN
spo -C newws store convert --from-layout /media/backup/spo-layout --pin PIN --network mainnet
spo -C newws store verify --deep
```

The first command is optional (the second runs the same checks). The second writes `workspace.spo` and `spo.toml` (a layout does not hold `spo.toml`, so `--network` is needed in an empty directory; the mode is offline) and records the pin beside the new workspace file, so that `store convert --to-layout` from the new machine continues the layout's chain. Cold-role records are carried exactly as stored; to sign with one you need the cold factor, as always.

## Import a layout: `store convert --from-layout`

```
spo -C ws store convert --from-layout DIR --pin PIN [--at SEQ] [--force] [--allow-older] ...
```

It runs both passes, then installs the verified scratch file with the same path as `store restore`, so every rule of a restore applies: an existing workspace needs `--force`; an older layout, or one that has diverged, needs `--allow-older` and the operational certificate and KES counters of the replaced workspace are carried forward, never lowered; a weaker unlock policy is refused without `--allow-weaker-policy` and the current recovery credential; a layout of another workspace needs `--allow-other-workspace`. A failed or refused import leaves the workspace as it was. The layout is not changed and is not retired: the workspace file is the only store you can write to. A refusal that needs no secret is made before anything is asked, including flags that belong to the other direction. The pin of the head used is recorded beside the new workspace only when that head's note is one the workspace would have written; otherwise the output says the next export needs a fresh directory or `--adopt-layout`. Into an empty directory no counter is compared, and the output says so and names `spo pool opcert counter POOL`.

**Authenticator touches.** Under `hardware` and `strict` the daily authenticator is presented once to open the layout's slot table, once more for the store's verification of the scratch file, and once more by the restore: `store verify --layout` asks for two touches (the PIN is read once), an import for three. (Counted by the end-to-end test with the repository's FIDO2 stand-in.) A `standard` workspace types its passphrase once. The three could be merged only if the store's verification and the restore accepted an already-derived key; that is not done, because the restore verifies its own private copy on purpose.
