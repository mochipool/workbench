# Import pools and wallets kept in separate folders

This guide brings an upstream scripts layout that keeps pools and wallets in separate folders, with pool descriptors that name their wallets by a relative path, into the sealed workspace. It uses `spo workspace import`; the full option list is in the [CLI reference](../reference/spo-cli.md#workspace-import-dir) and the behaviour is specified in [Xmulti](../../spec/extensions/Xmulti.md).

## Prerequisites

* A sealed workspace (`spo init`).
* The folders, for example:

  ```
  ~/scripts/pool/mypool.pool.json     "ownerName": "../wallets/owner", "poolRewards": "../wallets/owner"
  ~/scripts/pool/mypool.node.skey ... (and the other pool files)
  ~/scripts/wallets/owner.staking.vkey ... (and the other wallet files)
  ```

* `gpg` only if some keys are in upstream's encrypted form.

## Steps

1. See what would happen. This reads and checks everything and writes nothing:

   ```sh
   spo workspace import ~/scripts/pool ~/scripts/wallets --all --dry-run
   ```

   The table lists each owner with its folder and the name it would have, and below it every change to a pool descriptor, for example `"../wallets/owner" -> "owner"`. A pool is refused, with the reason, when a reference leaves the folders you gave, names a wallet you did not select, or names nothing. Sub-folders are read with `--depth N`.

   A bare name in a descriptor (`"ownerName": "owner"`) is looked up in the descriptor's own folder first. Upstream looks it up in the directory the script ran in, which the import cannot know; so when the name is not in the descriptor's folder and exactly one owner of that name is in the other folders you gave, the import takes that one (it must be selected, and the table notes where it was found). When several folders hold one, the pool is refused as ambiguous: write the reference as a relative path, or leave the other folders out.

2. Choose what to import. Nothing is imported only because it was found:

   ```sh
   spo workspace import ~/scripts/pool ~/scripts/wallets \
     --only pool:mypool --only wallet:owner --dry-run
   ```

   Use `@DIR` when two folders hold the same name (`--only wallet:owner@/home/me/scripts/wallets`).

3. Resolve name collisions. Two owners that would be stored under one name are refused before anything is written, and the message names both folders. Store one under another name:

   ```sh
   --rename wallet:owner@/home/me/scripts/old-wallets=owner-old
   ```

   A rename may not take the name of an owner that was found and is not selected, and may not take a name the workspace already holds unless you add `--overwrite` (then the table lists what is replaced). Names that differ only by case count as one name. A rename of a wallet is carried into every selected pool descriptor that names it; a rename of a pool changes its `poolName` and `regCertFile`/`deregCertFile` and stores its keys, counters and certificates under the new name.

4. Keep the selection for later, or for another machine:

   ```sh
   spo workspace import ~/scripts/pool ~/scripts/wallets --only pool:mypool --only wallet:owner \
     --manifest-out import.toml
   spo workspace import --manifest import.toml --dry-run
   ```

   A manifest holds folders, depth, selection and renames; it is refused together with those flags. It accepts only those keys, needs a comma between the strings of an array, and may carry `#` comments, also inside an array.

5. Import. Drop `--dry-run`. If a selected owner holds an encrypted key, give the password with `--password-fd N` or type it at the prompt:

   ```sh
   spo workspace import --manifest import.toml
   ```

6. Check the pool:

   ```sh
   spo pool descriptor show mypool
   ```

   `ownerName` and `poolRewards` carry the flat wallet names. Every other byte of the descriptor is as it was.

In the TUI, open the form of `workspace import` and press `ctrl+g`: the guided flow picks the folders with the file picker, lists what was found, shows the same descriptor changes before you confirm, and can save the manifest ([TUI reference](../reference/spo-tui.md#guided-import)).

## What it does not carry

* A pool with an open multi-witness registration (`regWitness`) is refused when any name in it would change (a rename, or a path turned into a flat name). Each name inside it is resolved like a bare name. Finish or discard the registration in the source first, or import without a rename.
* A pool is imported only if every wallet it names is imported in the same run or is already in the workspace with the same keys. A wallet that this run refuses (a rename onto a workspace owner, the case rule, a conflict, a failed check, a wrong password) refuses every pool that names it, and the pool row says which wallet and why; a failed write refuses the whole run (see the end of this page). A descriptor name that no source owner has is not satisfied by another owner renamed to it.
* A pool that names a wallet you did not select is refused, unless the workspace already holds a wallet of that name with the same stake (and payment) verification keys. A name found nowhere in the sources that the workspace holds as a wallet is accepted, and the table says which wallet it was bound to. That note says that no wallet of that name was found within the given folders and depth: a wallet of that name that sits below `--depth` cannot be known, so raise `--depth` if it exists. A name that differs from an owner's name (in the sources or the workspace) only by case is refused as ambiguous, naming both spellings.
* One folder with no option (the plain form) imports every descriptor as it is, byte for byte, as it always did; where the examination described above would have refused or rewritten it, the row carries a note. A byte order mark at the start of a descriptor is accepted and kept.
* `regCertFile` and `deregCertFile` must name this pool's own certificate. Any other value refuses the pool.
* Absolute paths in a descriptor are refused, never followed. Symbolic links are never followed.
* **A descriptor with a key that occurs twice in one object, or twice apart from case (`regPayName` and `REGPAYNAME`), anywhere in it, is refused** in the selective form, naming the keys: the pool commands read exact keys and the last of a repeated one, so the descriptor would name more than the import checks. The plain form stores it and notes it.
* **A merge into an existing workspace owner is accepted only when the result is provably one owner.** When the stored name of an owner is a name the workspace already holds (any artefact under it), nothing of the workspace is deleted, so the owner that results is the workspace's artefacts together with the incoming ones. Whether or not you pass `--overwrite`, that result is checked as a whole before anything is written: the same kind (a wallet is never merged into a pool, or the reverse); every key pair matches; every address, certificate and operational certificate is shown to belong to the keys of the result (an operational certificate must name the result's cold key and the KES key of its number); a payment key and a stake key belong together only when a base address ties them, or they came together from the workspace, or together from one source owner. Anything that cannot be shown (a key kept encrypted, a hardware signing file that stores no verification key, an artefact of a kind the check does not know) refuses the owner. Every pool record that carries the pool id (`poolID`, `poolIDbech`, the id files, the pool id inside a registration or retirement certificate) must be the id of the result's cold key. The merge also needs an identity anchor: a verification key (or hardware public key) both sides have and that is the same, or an artefact of one side that names a key of the other (an issue counter or operational certificate for the cold key, a certificate or address for the stake or payment key). An unrelated source owner of the same name that shares nothing is refused: nothing shows that the two are the same owner. Adding the next KES key and operational certificate of the same cold key, or importing the same owner again with `--overwrite`, passes, and the row notes what was verified and added. Otherwise import under a new name (`--rename`).
* **Every pool that is stored is checked once more against the end state.** After the plan and before any write, each name a stored descriptor carries (`ownerName`, `poolOwner`, `poolRewards`, the names inside `regWitness`) must be a wallet that will exist with a stake key, and, when the layout names a source owner for it, with that owner's stake (and payment) verification keys. The names are read from the final descriptor with the accessors the pool commands use. The check covers every pool that will be in the workspace and names an owner this run stores, those this run does not store included: a run that would replace the stake or payment key of a workspace wallet that a workspace pool names is refused for that wallet, naming the pools, unless the keys are unchanged. A pool that fails is refused with a row naming the field, the name and the failed condition.
* A pool whose witness transfer files (`<pool>_<owner>_<id>.witness`) name an owner, or the pool itself, that this run stores under another name is refused: finish or discard the registration in the source first, or import without that rename.

The owners that pass are written together in one update of the workspace: all of them, or none. An owner that was refused in the plan (a conflict, a failed check, a refused wallet) is not written and does not stop the others. If the write itself fails, or the workspace changed after the run read it (an artefact the run had read now differs, or one it would write now exists), nothing is stored: every row of an owner that was to be written says that nothing of the run was imported and why, and the plan rows stay in the table. Run it again. A name collision among the selected owners stops the whole run before anything is written. The plain form (one folder, no option) still writes each owner in an update of its own.

**Limits.**

* Owners beyond the folders and depth you give are not known. A name that no source owner has is bound to the workspace's wallet of that name, with a note; an owner below the depth is treated as workspace-only.
* Pool records and role keys are tied to an owner only through the checks above: key bytes, the cold key an issue counter or operational certificate names, the key hash in a certificate or address, the pool id (`poolID`, `poolIDbech`, the id files, the operator in a registration or retirement certificate), and the names in the descriptor. A record that carries none of these (`kes-expire.json`, metadata files, witness files, Calidus registration files) is tied only by its file name.
* The recheck at the write covers the artefacts the run read, wrote or probed. A new pool that names a wallet the run replaces, created by another process after the run read the workspace, is not seen.
* A `regWitness` is read for the names in it; it is not validated as a transaction.
* A pool with an open registration whose payer is named `<wallet>.payment`, or is an enterprise wallet with no stake key, is refused by a selective import. Finish or discard the registration first (`spo pool witness clear`), or import that folder on its own with no selection flags. The payer wallet of an open registration already in the workspace is not protected when a run replaces it; such a registration fails later, at signing or at the node.
* These checks catch mistakes. They do not make a folder from someone you do not trust safe to import: the keys and addresses the checks compare are public and can be copied.
* A `pool.json` that starts with a byte-order mark is stored unchanged by a selective import, and the pool commands refuse it until the mark is removed.
