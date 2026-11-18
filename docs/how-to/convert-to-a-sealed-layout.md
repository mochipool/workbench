# Convert a workspace to a sealed layout

Reference: [`spo-cli.md`](../reference/spo-cli.md#store-convert). Background: [ADR 0012](../explanation/adr/0012-server-backup-and-deployment.md), decisions 4 and 6, and "Implementation notes, stage 3" at its end. Spec: [Xlayout](../../spec/extensions/Xlayout.md).

**This has not been run on a real authenticator or on a network file system.** The tests use stand-ins for the libfido2 tools and local temporary directories. Try it on a throw-away workspace first.

## What it is for

`spo store convert --to-layout DIR` writes the workspace into a directory as a set of sealed files: one file for every record and every audit row, a few small files that list them (the manifest), a plaintext file with the key slots, and one small plaintext head note that names the manifest. Every sealed file is padded to a fixed size (4 KiB up to 4 MiB) and is named by the hash of its bytes. It is a copy to keep and to check against later. It is the format a later stage will serve from a server.

Run it again and only what changed is written. A record that did not change has the same name as before, so nothing is written for it.

## What it is not

* **It is not a second workspace.** You cannot open it, write to it or sign with it. The SQLite file (`workspace.spo`) stays the only store you can write to. Nothing was retired, renamed or marked.
* **It does not replace `store backup`.** A backup is the whole sealed file and restores with `store restore`. A layout cannot be restored yet.
* **It cannot sign with a cold key.** Cold-role records are carried exactly as they are stored. Nothing here opens one.
* **Verify, read-only open and import do not exist yet.** They arrive in later work packages of stage 3. Until then nothing in this tool reads a layout back, and the only checks of one are the tests of this repository and the read-back each run makes of what it wrote.

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
