# Migrate a workspace

A workspace made by an earlier version keys every record by the name of its owner (store format 1). This version keys a record by the identity of its owner and keeps a name as a label (store format 2; [ADR 0010](../explanation/adr/0010-object-identity.md), decisions 2 and 4). A command on an old workspace refuses and names `spo workspace migrate`.

## Before you start

* Close every other `spo` process on the workspace.
* You need the workspace passphrase (or give it with `--passphrase-fd N`). The master key does not change: this is not a rekey, and your recovery key and every backup that is in the new format stay valid.
* Old backups stay in the old format. Migrate a restored old backup the same way.

## Migrate

```
spo -C <workspace> workspace migrate
```

The command first copies the workspace file beside it (`spo.workspace.pre-migrate-v1`, mode 0600, sealed bytes only; a number is added when that name exists) and prints where. Then it converts every record in one transaction. If anything fails, the original file is as it was. The report says how many records were converted, merged and added, which pool descriptors now name their owners and reward account by key hash, and which witness slots lost their party.

What it does, in the order the ADR gives:

* Finds each owner from the keys the workspace holds: a pool by its cold key hash, a wallet by its payment key hash (else its stake key hash), a DRep by its key hash, a committee member by its cold key hash, a policy by its id. The stems `<wallet>` and `<wallet>.payment` are one wallet.
* Writes a label, an owner record, an owner manifest and a role history per owner and key, and re-seals every record under the same master key with the anchor identity in place of the name.
* Rewrites each pool descriptor's `poolOwner[].ownerName`, `poolRewards` and `regPayName` from names to key hashes, and the slots of an open witness collection to the fingerprint of their party. A party that is no longer enrolled leaves its slot unassigned and is listed.
* Merges two records that map to one reference when their bytes are identical.
* Keeps an upstream-encrypted signing key under the identity of its verification key; with none the key is quarantined (kept, found by its stem, usable by no signer).

## When it refuses

It refuses with a list, writes nothing and makes no copy when:

* a name in a descriptor resolves to no wallet, or to a wallet without the key the reference needs (an owner or the reward account needs a stake key; the payer needs a payment key);
* a descriptor records a pool id that is not the hash of the cold key stored under the pool's name;
* one key would belong to two owners (the same key under two names);
* two records that become one differ (for example `w.vkey` and `w.payment.vkey` hold different keys);
* a verification key record does not parse, or a record is of a kind this version does not know.

Fix the workspace and run it again. If the problems are a pool's own and you accept leaving that pool unusable, name it:

```
spo -C <workspace> workspace migrate --quarantine pool1
```

The pool's keys and other records are migrated and stay usable; only its descriptor is left unresolved (it still names owners by name, and the problems are listed as quarantined). Fix the descriptor with `spo pool descriptor set`. Only a pool's own descriptor problems can be quarantined: a collision of a wallet's records, or a key under two owners, always refuses.

## After

```
spo -C <workspace> store verify
spo -C <workspace> wallet rename old new
```

`store verify` checks the new format, including the owners, manifests, labels and role histories. A rename replaces one label record and nothing else.

If the workspace holds a pool cold key or a committee cold key, the migration to store format 3 seals it under a sub-key and asks for a **cold-key passphrase** (`--cold-passphrase-fd N`, or a prompt, twice): it must not be the workspace passphrase. Without one the migration is refused and the file is unchanged. See [the cold-key factor](slots-policy-and-rotation.md#cold-keys-what-asks-for-the-factor-and-when). **The migrated cold keys have no recovery path yet.** The slots of a format 2 workspace bind no recovery key, so a cold key sealed by the migration carries no recovery wrap: if the cold-key passphrase is lost, the key is lost, and the recovery key does not help. The migration ends with a warning that says so. Run `spo store passphrase change` (it keeps the recovery key; or `spo store recovery-key new`): the rekey binds the recovery key and adds the wrap to every cold key, and asks for the cold-key passphrase once, before it writes anything. `spo store slots` and `spo store verify` report "N cold records without a recovery wrap" until that is done. **The copies hold the cold key sealed the old way.** The `.pre-migrate-v1` and `.pre-migrate-v2` copies are in the old format: a pool cold key or a committee cold key in them is sealed under the master key alone, with no cold-key passphrase. Anyone who holds a copy and the workspace passphrase can read it. Delete the copies when you have checked the migrated workspace; deletion on a modern file system or SSD is best effort (blocks may stay), so a passphrase that protected a copy should be changed. `spo workspace migrate` prints this warning, and `--remove-copies` unlinks the copies after the migrated file verifies and opens (it keeps them and says so when either check fails). No overwrite is attempted before the unlink. Keep the `.pre-migrate-v1` copy until you have used the workspace; it is the old format and cannot be opened by this version, only migrated.
