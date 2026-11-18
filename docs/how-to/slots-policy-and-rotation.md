# Unlock slots, the unlock policy, rotation, restore and node export

Reference: [`spo-cli.md`](../reference/spo-cli.md). Background: [ADR 0011](../explanation/adr/0011-key-custody-and-unlock.md). A real FIDO2 authenticator has not been used with this code yet; the device checklist is in [the handoff](../development/handoff.md).

## Know what protects the workspace

A workspace has a policy. Read it without any key:

```
spo -C ws workspace policy show
spo -C ws workspace slot list
```

* `standard`: a passphrase slot and a recovery slot. Whoever holds a copy of the file can guess the passphrase offline, bounded by the Argon2id cost. Keep such a workspace on your machine. `store backup` reminds you.
* `hardware`: nothing opens without a FIDO2 authenticator. The daily authenticator opens it; the recovery path is the recovery key AND a second authenticator. You need two physically separate tokens, each with its own PIN.
* `strict`: as `hardware`, with no recovery key. Losing the authenticator loses the workspace.

`slot list` shows, for each FIDO2 factor, the result of the touch probe made when it was enrolled. "touch not enforced" means the token gave its secret to a request without a touch; it still protects the file, but the touch is then not a guarantee.

"Two different authenticators" is checked by device path and by credential. The tool cannot tell two tokens apart in any other way: one token that you unplug and plug in again as the second would pass. Do not do that; the second token is the point.

## Move to the hardware policy

```
spo -C ws workspace rotate --policy hardware \
  --fido2-device /dev/hidraw3 --recovery-device /dev/hidraw4
```

(`fido2-token -L` lists the paths; `workspace policy set` is the same command.) The command asks, in this order:

1. the **current recovery key** (typed, or `--recovery-key-in-fd N`). A rotation changes the recovery key, and the tool takes that change only from someone who holds the current one: the daily passphrase alone cannot rotate;
2. the PIN of each authenticator, separately and naming the device (`--fido2-pin-fd` for the daily one, `--recovery-pin-fd` for the recovery one). The recovery token never gets the daily PIN. Both PINs are checked before any credential is made, so a typing error leaves nothing on either token;
3. a touch on each token, twice each (credential, then secret).

It then replaces the workspace key and every data key, writes the new table and shows the **new recovery key once**. Write it down. The old one stops working.

A rotation makes **no copy of the file**: a copy would still open with the credentials the rotation revokes. If you want one anyway (for example to compare after the change), give `--keep-copy FILE`. It is written with mode 0600, never over an existing file, removed again if the rotation fails, and the command tells you that it opens with the OLD credentials. Destroy it once you have opened the rotated workspace with the new factors.

What a rotation cannot delete: backups and file-system snapshots taken earlier, remnants on an SSD, and any copy someone already holds. Rotate the hot keys (KES, VRF), tokens and party identities that a removed factor could read; payment, stake and cold keys cannot be rotated without moving funds.

A `strict` workspace cannot be loosened by this tool (it has no recovery credential that could authorise that).

## Add or remove a slot

```
spo -C ws workspace slot add-fido2 --fido2-device /dev/hidraw3
spo -C ws workspace slot remove 3f9a      # the first characters of the id in `slot list`
```

Adding needs no rotation. **Removing is a rotation**: removing a slot revokes nothing unless the keys change, so `slot remove` asks for the same current recovery credential as `rotate`, needs the factors of every slot that stays (the passphrase, the daily token, the recovery token), replaces every key, and gives you a new recovery key when a recovery slot stays. It refuses to remove the last slot the policy needs (the last passphrase or recovery slot of `standard`; under `hardware` and `strict` the last slot besides the recovery composite). The removal is written to the audit chain.

A rekey (`store passphrase change`, `store recovery-key new`) makes a passphrase slot and a recovery slot. Under `hardware` and `strict` it is refused; use `workspace rotate`.

A rotation, and a slot removal, write an audit event for each slot they remove, naming its id (`slot-removed`, the kind and the id). A `strict` rotation by one daily factor removes every other holder's slot too, and each of them is in the audit trail as well as in the `--yes-remove` list you had to give.

## Change the passphrase

```
spo -C ws store passphrase change
```

It asks for the **old passphrase again** (a prompt of its own, or `--old-passphrase-fd N`; the passphrase the session was opened with is not reused, so a session left open cannot change it), then the current recovery key, then the new passphrase twice. The recovery key stays the same.

## Restore a backup

```
spo -C ws store restore backup.spo --force
```

A backup whose policy is weaker than the workspace's is refused: an older `standard` copy of a workspace that you moved to `hardware` would undo the move, and `--force --allow-older` does not change that. If you mean it, add `--allow-weaker-policy` (it needs `--force`) and present the current workspace's recovery credential: the recovery key (`--recovery-key-in-fd` or a prompt) and, under `hardware`, the second authenticator (`--current-recovery-device`, `--recovery-pin-fd`). A `strict` workspace has no recovery credential and is never replaced by a weaker backup. A backup of a `hardware` or `strict` workspace is verified through its authenticators, so you need the daily token (`--fido2-device`, `--fido2-pin-fd`) and not a passphrase.

## A new workspace under a policy

```
spo -C ws init --network mainnet --policy hardware \
  --fido2-device /dev/hidraw3 --recovery-device /dev/hidraw4 --recovery-key-fd 5
```

No passphrase is asked. If anything fails the files the run created are removed.

While the command runs, the file `workspace.spo.init-pending` marks the workspace as unfinished; it is removed once the rotation has committed. If the rotation's outcome is unknown (the store could not tell whether the commit took effect), the command reads the policy of the file: if it is the new policy the workspace is complete and its recovery key is delivered; if it is still `standard` the first workspace is removed and you run `init` again; if the file cannot be read nothing is removed, the recovery key is shown marked as valid only if the change took effect, and `workspace policy show` tells you which. If the command is killed between creating the file and the commit, the file is a `standard` workspace whose random passphrase is gone, and the marker stays. The next `init` in that directory finds the marker and asks before it removes the leftover (answer `y`, or pass `--remove-unfinished`; with no terminal and no flag nothing is removed). A workspace that already has the new policy is never removed by this.

## Sign under the hardware policy

There is no passphrase to type again. `party approve` asks the authenticator for a fresh presentation (PIN, unless it came on a descriptor, and a touch) before each signature, and signs nothing when it is refused. `store backup` and `store verify` verify the copy through the same factors.

## Deliver the hot keys to a block producer

```
spo -C ws node export mypool --recipient producer.pub --out /tmp/delivery
```

`node export` reads the pool's KES key, VRF key and operational certificate and writes only `age` ciphertext (`kes.skey.age`, `vrf.skey.age`, `node.cert.age`), sealed to the one X25519 public key in `producer.pub`. It refuses a key that was ever recorded in a cold role, a key with no stored role history, a certificate that does not name the KES key, a certificate that is not signed by the pool's cold key or is not the newest, and a signing key that does not derive the stored verification key. Each delivered file carries a header with the pool id, KES number and certificate counter, and the helper refuses a mixed set. A removal re-creates the kept authenticator slots only from authenticators that open them (an impostor token is refused). On the producer the helper `spo-node-keys deliver --from DIR --to DIR` decrypts the files into a `ramfs` directory, mode 0400, as the node's own user, and is the only program that writes a signing key in clear; it cannot open a workspace. The recipient's identity should be a TPM-bound systemd credential, which `spo` cannot check from the workspace host (`--no-tpm-identity` records that it is not). The full procedure, the unit sketch and what stays in clear are in [Deliver keys to a block producer](./deliver-keys-to-a-block-producer.md).

## What the recovery check is

A rotation, a slot removal, a passphrase change and a new recovery key all replace the recovery path, so each asks for the current recovery key (and, under hardware, the recovery authenticator) first. That check is made by the program you run. The cryptographic guarantee is narrower: an existing slot's bound recovery hash cannot change without that slot's factors. Someone holding the daily factor who runs their own code can re-create their own slot and drop the recovery slot. You would see it (the recovery key stops opening the workspace), but it is not prevented. (The recovery wraps of cold keys are made to the recovery public key whose hash the slots bind, and a key that is wrapped to another public key is refused, but a holder of the daily factor who rebuilds the table is not stopped by that.) A strict rotation by one daily factor removes the other holders' slots; the command names each and needs `--yes-remove <slot id>` for each.

`store passphrase change` presents the recovery key and keeps it; no new recovery key is made. `store recovery-key new` presents the current key first. The approval gate under hardware asks for the PIN on the terminal each time and refuses when there is no terminal.

## Cold keys: what asks for the factor, and when

A key whose identity has a cold role in the workspace (a pool's cold key, a committee member's cold key, and any other key that was ever recorded in one of those roles) is sealed so that the unlocked workspace alone does not read it. Opening the workspace gives a program the workspace key; it does not give it a cold signing key. What opens one is a factor presented again for that key:

* under `standard`: the **cold-key passphrase**, which is not the workspace passphrase and must not be a passphrase of any slot (the command refuses one that is). Give it with `--cold-passphrase-fd N` or at the prompt; the first time (when the cold key is made, imported or migrated) it is asked twice. Write it down apart from the workspace passphrase: nothing else opens the key, except the recovery path below;
* under `hardware` and `strict`: the **daily authenticator again** (its PIN, as at unlock, and a touch). One touch when a cold key is made or imported, one touch for each signing operation that uses it (an operational certificate, a pool registration or retirement, a vote by the pool, a multi-party signature), and none for any other key.

The command asks at the moment the key is needed, and not before; it never asks while the workspace is being written. For a **new** cold key (a pool's cold key, a cold key import, the migration) the command first works out how many cold keys it will create, asks for the factor with the workspace unlocked for others to write, and then writes; a second writer is not held up by the prompt. If the binary has no factor source for the policy, the command fails before it asks for anything. Opening the key writes the workspace: it rotates the key's salt, so the record changes with each use and each use is in the audit chain; the key is handed to the signer only after that write has committed.

What does not need the factor: `store verify`, `store backup`, `store restore`, listing, opening the workspace, `workspace import --dry-run`. `store verify --deep` reads a cold key's outer layer, which proves the record was not edited, but it cannot tell you the key can be decrypted; it says how many cold-role records it left unopened. `store verify --deep --with-cold-factor` presents the factor once for each cold-role record, decrypts it and writes nothing.

`workspace rotate` and `workspace slot remove` re-seal every cold key under the new table's factor, so they ask for the old factor (or the recovery credential) and the new one for each cold-role record; with `--policy standard` the new cold-key passphrase is `--new-cold-passphrase-fd N` or two prompts. A rotation or recovery that would leave a cold key under its old factor (it cannot be opened through its recovery wrap and the old factor is not available) is refused before anything is written, and the keys are named (`kind/label`, for example `node.skey/mypool`). You can accept leaving one with `--leave-unreachable kind/label` (once per key; it needs the recovery credential presented): that key keeps its old factor and still opens with it, and carries a left mark in its sealed record. `store verify` fails, and `store slots` lists it, for as long as the mark is set (through every later rekey, under any policy, without any factor), until a rotation re-establishes it with a factor that opens it (`spo store verify --deep --with-cold-factor` shows which records open with the factor you hold). The rotation also writes a `cold-left` event naming it to the audit chain. A left record is not compared when the cold passphrase of a new cold key is checked, so leaving one does not block creating others. What is asked: under `standard` the new cold passphrase once (and the old one once, only if some record needs it); under `hardware` and `strict` two touches of the new daily authenticator for each cold key sealed again (the answer is verified), and one more touch per record that is opened with the old authenticator. `workspace migrate` of a workspace that holds a pool cold key asks for a cold-key passphrase, because the migration seals the key under it.

### Recovering cold keys

Every cold key under `standard` or `hardware` also carries a copy of its data key sealed to a recovery public key (HPKE, RFC 9180). The private half exists only in the recovery key, or, under `hardware`, in the recovery composite (the recovery key AND the second authenticator). So after the daily authenticator or the cold-key passphrase is lost, you can still re-establish the keys:

1. open the workspace through the recovery path (`--unlock recovery-composite` under `hardware`; `spo store recover` under `standard`). The recovery authenticator is never used as a cold factor: the cold keys are reached through their recovery wraps, not through the old factor, so a lost cold passphrase or a lost daily authenticator does not stop you. No slot is added in such a session (`workspace slot add-fido2` is refused), and `store recover` does not apply to a `hardware` or `strict` workspace (it says so and names the next step);
2. re-establish the keys. Under `hardware`, after the daily authenticator is lost:

   ```
   spo --unlock recovery-composite --fido2-device RECOVERY-DEVICE \
       workspace rotate --policy hardware \
       --new-fido2-device NEW-DAILY --recovery-device NEW-RECOVERY
   ```

   In that session `--fido2-device` is the **current recovery authenticator** (its PIN is `--fido2-pin-fd`), `--new-fido2-device` is required and may not be the recovery authenticator, the new recovery authenticator is `--recovery-device` (PIN `--recovery-pin-fd`), and the recovery key typed to open the session is presented again as the proof without being asked twice. The lost authenticator's slot is removed and nothing is enrolled on it. Under `standard`: `spo store recover` asks for the new workspace passphrase and **a new cold-key passphrase** (`--new-cold-passphrase-fd N`, or two prompts), and seals every cold key again under it; afterwards the lost cold passphrase no longer opens them. Both unwrap each cold key with the recovery credential, **check that the key they find derives the key identity the record belongs to**, and seal it again under the new factor. A cold mnemonic (`cc-cold.mnemonics`) is checked by deriving the committee cold verification key from its words, with the generator's derivation at the account and index recorded in the record (a mnemonic made with `--account` or `--index` other than 0 records them; one without them is checked at 0, 0), and comparing its identity with that of the signing key beside it. All of this is done before anything is written, with only the recovery key. A record that fails the check (planted, or a legacy mnemonic made at another path that recorded none) is not trusted: the old cold factor is tried, and a record that opens with it is sealed again under the new factor (someone holding only the workspace key cannot produce that). If the old factor is not available or does not open it either, the record is named in the refusal (the error names the record and says the identity check failed) and is left only with `--leave-unreachable kind/label`. A cold key that has no recovery wrap, or is an upstream-encrypted key (which cannot be checked), needs its old factor; if you cannot give it the operation is refused with the key named unless you pass `--leave-unreachable` for it. Every key the old factor opens is sealed again under the new factor, so the workspace never ends with two cold passphrases.

Under `standard` the recovery key alone can re-establish every cold key under a cold-key passphrase its holder chooses, so it is as sensitive as the workspace passphrase and the cold-key passphrase together: keep it where neither of them is.

A `strict` workspace has no recovery key, so a lost authenticator loses its cold keys. A cold key made before a migrated workspace bound a recovery key has **no recovery copy, and using it does not add one**; a migrated workspace therefore has no recovery path for its cold keys until a rekey. Any rekey that leaves the workspace binding a recovery key (`store passphrase change`, `store recovery-key new`, `store recover`) or a rotation (`workspace rotate`) adds the missing copy to every cold key. A rekey needs the cold factor for that, once per such key, asked before anything is written (`--cold-passphrase-fd`, or a prompt); without it the rekey is refused and nothing changes. `store slots` and `store verify` say how many cold keys still lack the copy. A rekey that makes a new recovery key needs the current one presented and moves existing copies to the new key.

**A faulty authenticator and the next salt.** Each time a hardware cold key is opened, the authenticator answers two salts in one touch: the current one, which opens the key, and the next one, under which the key is sealed again. Nothing can check the second answer. So the record keeps the previous wrap beside the new one. If the authenticator answered wrongly, the key still opens (one more touch, with the previous salt), the next good open renews the current wrap, and `hardware` and `strict` workspaces do not lose the key. A copy of the output for the previous salt opens the key until the next open that succeeds with the current wrap. When the previous wrap has to be used, the authenticator is asked a third time to confirm its answer for the new salt. If the two answers differ the key is still released but is **not** rewritten, and every such open prints "the authenticator returned an inconsistent answer; the record was not rotated": a persistent fault is visible instead of being worked around silently. `store verify` shows how many times a record had to be healed.

**Two touches per new key.** When a hardware cold key is made, imported, or re-sealed by a rotation, the authenticator is asked for the new salt twice and the two answers are compared before the key is sealed, because one wrong answer would otherwise leave a key nobody can open (for good under `strict`). A mismatch refuses the operation and writes nothing.

`workspace migrate --remove-copies` does not delete the copies while some cold key has no recovery wrap, unless the cold-key passphrase is typed again at the terminal (not given on `--cold-passphrase-fd`) and the key opens.

The recovery credential authorises one operation. Once a rekey, rotation or slot removal has finished, refused or not, the handle holds no trace of it, and the next one needs the recovery key presented again.

Under `standard` a workspace has one cold-key passphrase. Creating a second cold key with a different passphrase is refused, and so is creating one in a workspace whose records already differ (the error names `spo store verify --deep --with-cold-factor`); the way to change it is `workspace rotate`. `store recover` also changes the cold-key passphrase: it asks for a new one and seals every cold key it can reach under it. Records marked left are not part of the comparison.

A cold key is bound to the authenticator it was made with (its credential is stored in the key's header). A second daily authenticator that you add later opens the workspace but not that key. Make a cold key, or rotate, with the authenticator you will sign with.

A cold key opens with the factor its own header names, whatever the workspace policy is now. So a key left under a cold passphrase in a `hardware` workspace (by `--leave-unreachable`) still opens with that passphrase.

**Which commands take `--unlock recovery-composite`:** `workspace rotate` (and `workspace policy set`, the same command) and `store slots`. Any other command refuses it before it asks for anything and names these; the recovery key typed for the session is kept only by `workspace rotate`, used once as its proof and destroyed there. To script the procedure without a terminal: `--recovery-key-in-fd N` (the recovery key, used for the session and the proof), `--fido2-pin-fd N` (the recovery token's PIN), `--new-fido2-pin-fd N`, `--recovery-pin-fd N`, `--recovery-key-fd N` (the new recovery key out); for a standard table `--new-passphrase-fd N` and `--new-cold-passphrase-fd N`. The old recovery token may be named again as the new `--recovery-device`: the rotation presents the composite and enrols a new credential on it; the check that the daily and the recovery authenticator differ is by device path and credential, so a token plugged in under another path passes it. A kept-encrypted pool cold key (an `UpstreamEncryptedSKey` record) cannot be checked against its identity, so a hardware recovery cannot re-establish it from the recovery credential: the recovery is refused and names it, and if you leave it (`--leave-unreachable`) it is lost once the old factor is gone. `store verify` fails, and `store slots` lists, every cold key whose header kind does not match the policy, whose authenticator credential belongs to no current daily slot, or that a rotation or recovery left behind (named by a `cold-left` event since the last rekey). It cannot see that two keys are sealed under different cold-key passphrases without the passphrase: a workspace that is already split that way refuses a new cold key with an error that names `store verify`, and `workspace rotate` is how it is joined again.

### Losing the recovery authenticator or the recovery key

Under `hardware`, daily use and cold signing keep working while the recovery key or the recovery authenticator is gone, because the daily slot opens the workspace and the cold keys open with the daily authenticator. But every rotation, slot removal and policy change needs the recovery composite (the recovery key and the recovery authenticator) presented, so each of them is refused for good. You cannot replace the daily authenticator, add or remove a slot, change the policy or recover a cold key. If the daily authenticator is then lost too, the cold keys are lost. The only way out is a new workspace: make one, import the keys into it from their original files (or from a copy of the old workspace's keys that you hold elsewhere), and destroy the old file. There is no command that rebuilds the recovery composite from the daily slot, because that would let the daily factor replace the recovery path (see the first section above).

A `strict` workspace has no recovery path. Losing its authenticator loses the workspace and every key in it; there is nothing to present and nothing to rotate.

## Not built

Vault and KMS factors. The node-delivery path was built from the ADR's text and has not run against a real host, TPM, `systemd` credentials directory or `cardano-node`; the cold-key factor has not run against a real authenticator. The checklists are in the [handoff](../development/handoff.md). See the handoff for the rest.
