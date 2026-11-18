# Back up to a sink: a directory or an S3 bucket

Reference: [`spo-cli.md`](../reference/spo-cli.md#store-backup). Background: [ADR 0012](../explanation/adr/0012-server-backup-and-deployment.md), decisions 4, 9 and 13, stages 1 and 2. Spec: [Xbackup](../../spec/extensions/Xbackup.md).

**Nothing here has been run against a real bucket or a real authenticator.** The S3 adapter was tested only against an in-process fake on 127.0.0.1, and the checkpoint key only against a stand-in for the libfido2 tools. Treat the first real upload, and the first real checkpoint signature, as a test: do it with a throw-away workspace, then restore it.

The file that goes to the sink is the sealed backup `spo store backup` already makes. The tool adds no encryption. A sink holder sees the workspace id, the file size, the object name and the time, and can try to open the file only with what unlocks the workspace.

## Which sink

| Workspace policy | Directory sink (`dir:/absolute/path`) | S3 sink (`s3://bucket/prefix`) |
| --- | --- | --- |
| `standard` | Allowed, with the warning that a copy can be guessed offline | Refused before any request |
| `hardware`, `strict` | Allowed | Allowed when the bucket meets the rules below |

A `standard` workspace and a bucket do not go together: whoever can read the bucket could guess the passphrase offline. Rotate first (`spo workspace rotate --policy hardware`, see [slots, policy and rotation](./slots-policy-and-rotation.md)), or use a directory.

A directory sink must be on a local file system, not group- or world-writable (the tool refuses it, `chmod 700`), and not behind a symbolic link. The tool creates it with mode 0700 when it is missing.

## Set up the bucket

The tool reads these properties before it sends anything and refuses the bucket when one is missing:

* **Versioning** is on.
* **Object Lock** is on, with a default rule in **COMPLIANCE** mode and a retention period (days or years). Object Lock can only be switched on for a new bucket or by AWS support steps for an old one; make a new bucket.
* **Credentials are short-lived** (next section).

Set these too. **The tool cannot check them:**

* The bucket is in a **separate AWS account** from anything the workspace's machine can administer. Otherwise a compromised machine can reach the bucket's settings.
* The **bucket policy denies deletes** (`s3:DeleteObject`, `s3:DeleteObjectVersion`) and `s3:PutBucketObjectLockConfiguration` changes to the principal the operator uses, and allows `s3:PutObject`, `s3:GetObject`, `s3:ListBucket` and `s3:GetBucketVersioning`, `s3:GetBucketObjectLockConfiguration` only. Compliance-mode locks stop deletes before the retention ends, but a policy keeps the day-to-day principal from shortening anything else.
* Server-side encryption is optional. The objects are already sealed; SSE-KMS adds a key policy, not confidentiality this design relies on.
* **S3-compatible stores other than AWS are unconfirmed.** The tool relies on `If-None-Match: *` on `PutObject` to refuse overwrites. AWS documents it; MinIO, Ceph and R2 may or may not. A store that ignores the header would overwrite an object. The tool reads every object back and compares it, so a changed object is noticed after the fact, not prevented. Use AWS S3 unless you have tested the store.
* Access logs are another observer of who wrote what and when. Send them to a bucket you control.

Compliance-mode objects cannot be deleted by anyone, including you, until the retention ends. Choose the period with that in mind, and note each backup stays and is billed until then.

## Credentials

Credentials come only from the AWS SDK's default chain. The tool **refuses** credentials that cannot expire, have no session token, or expire more than **12 hours** ahead (a `credential_process` can assert any expiry, so a far-future one is no better than a static key). It says so before it contacts the bucket, and before the workspace is unlocked.

| Source | Accepted | Note |
| --- | --- | --- |
| AWS IAM Identity Center (SSO), `aws sso login` | Yes | The SSO token cache under `~/.aws/sso/cache` is a **long-lived file on disk**; anyone who can read it can use the session until it expires. Keep the session short and run `aws sso logout` afterwards. |
| `credential_process` that returns an `Expiration` (for example the IAM Roles Anywhere signing helper) | Yes, up to 12 hours | The output must include `SessionToken` and an `Expiration` no more than 12 hours ahead. Without `Expiration`, or with a later one, it is refused. |
| Web identity (IRSA, or Workload Identity federation) | Yes | For a server in a cluster, later stages. |
| Container or instance role credentials | Yes | They expire and carry a session token. |
| `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in the environment | **No** | Refused even with `AWS_SESSION_TOKEN`: the SDK cannot tell when they expire. |
| Keys in `~/.aws/credentials` or the shared config | **No** | Static access keys. |

The SDK configuration is the only place to override the endpoint (`AWS_ENDPOINT_URL`, `AWS_ENDPOINT_URL_S3`, a config-file setting). **The endpoint must be https**; a plain-http endpoint is refused. Set `AWS_REGION` or a region in the profile. No credential is printed by this tool.

**A CA bundle is an operator trust decision.** `AWS_CA_BUNDLE`, or `ca_bundle` in a profile, makes the tool trust that CA for the endpoint: a proxy that holds it sees the sealed bytes and can fake a read-back. The sealed file stays sealed, and restore integrity rests on the pin, not on the read-back. The timeouts of the tool apply with a CA bundle too.

Versioning and Object Lock are **reported by the endpoint itself**. The tool reads them to catch a misconfigured bucket; they do not protect against a hostile or lying store. Whatever the endpoint is, it can also lie about whether an object exists: if a sink says an object exists and cannot return it, the tool says the sink is faulty or hostile and stops.

## Back up

```
spo -C ws store backup --sink dir:/srv/spo-backups
spo -C ws store backup --sink s3://my-backup-bucket/mainnet
```

The tool makes the backup into a private temporary directory in the workspace directory, verifies it, sends it with a checksum, reads it back and compares it, and removes the temporary directory on every path. It prints the object name and a pin:

```
Pin: <workspace id>:<head sequence>:<head hash>:<sha256 of the file>
```

**Keep the pin somewhere other than the sink**: a note, a password manager, another host. Restore needs it, and it is what shows that the sink was not rolled back to an older backup or the file changed. The sink cannot supply it.

List what the sink holds for this workspace (no passphrase, nothing downloaded):

```
spo -C ws store backups --sink s3://my-backup-bucket/mainnet
```

## Restore

```
spo -C newws store restore --sink s3://my-backup-bucket/mainnet --pin <the pin> --network mainnet
```

The tool downloads the object the pin names to a private partial file, and uses it only when its SHA-256, workspace id and head are exactly the pin's. Then the built restore runs on it unchanged, so all its refusals apply: a backup with a weaker policy, another workspace, an older head. A hardware backup is verified through the daily authenticator (`--fido2-device`, `--fido2-pin-fd`).

`--allow-older` works with `--sink` and follows the counter rule: a restore never lowers an operational-certificate or KES counter. Whenever a workspace is being replaced and can be opened, it is opened read-only (with the credential given for the backup, or its own recovery key if that no longer opens it: `--recovery-key-in-fd`, and under hardware `--current-recovery-device` and `--recovery-pin-fd`; the recovery key is asked for only then) and, for each pool, the larger issue counter and KES counter-next are written into the restored copy before it is installed. The command lists what it carried. This also holds for a backup that contains the workspace's head, because `pool opcert issue --counter N` can lower a stored counter inside one chain. If a workspace's credentials changed and neither the backup's nor its recovery key opens it, the restore refuses and names those flags; `--accept-lower-counters` is not honoured for that. If its credentials are lost, move `workspace.spo` aside and restore into the empty directory: no comparison is possible then, so check every pool's counter on chain before issuing a certificate. `--accept-lower-counters` is only for a workspace file that is unusable. A file that does not parse or fails verification compares nothing; replacing a file that is not a workspace at all (`--allow-other-workspace`) needs `--allow-weaker-policy` and `--accept-lower-counters` together, and the first refusal names both. A file that unlocks but is older than its head file (rolled back, or someone rewrote the head file) still has its own counters carried as a floor, with a warning that the true counters may be higher: check every pool's counter on chain before issuing a certificate. The refusal for a changed credential is always a refusal, also without `--allow-older` and also for a backup that contains the workspace's head, because `pool opcert issue --counter N` can lower a counter inside one chain.

## The checkpoint key and the long-lived pin

The pin above fixes one exact file, so it has to be written down again after every backup. A **checkpoint key** lets you keep one pin that does not change and still restore the newest authentic backup from a sink nobody trusts.

The checkpoint key is a FIDO2 credential on an authenticator of yours, used as an OpenSSH security-key signing key (`sk-ecdsa-sha2-nistp256@openssh.com`). After a backup is in the sink and has been read back, the key signs a short statement of it (workspace id, head sequence and MAC, hash of the slot table, SHA-256 and size of the file, time, key hash). The statement and its signature go to the sink as `<object name>.checkpoint`. The signature is a standard SSH signature (`PROTOCOL.sshsig`).

### Enrol the key

```
spo -C ws workspace checkpoint-key enroll --checkpoint-device /dev/hidraw3
```

The authenticator asks for its PIN and a touch. The command prints the key hash, the SSH public key line and the long-lived pin. Rules:

* The checkpoint authenticator is **not the daily authenticator** of any slot. The command refuses the token the session unlocked with, after resolving both (a missing `--fido2-device` auto-picks a token, and a path with symbolic links is followed), and before it makes a credential it asks the candidate token, without a touch, whether it holds any daily slot's credential, and refuses if it does. Under `standard` there is no daily credential, so only the first rule applies. The probe has not been run on a real authenticator.
* It **may be the recovery authenticator** of a `hardware` workspace. The trade-off is yours: the recovery token is then used at every backup (a PIN and a touch each time), and a backup machine that holds it holds the recovery composite's second factor. A token kept only for checkpoints costs one more token.
* The first key needs only the unlocked workspace. **Replacing or removing** a key needs the current recovery credential under `standard` and `hardware` (`--recovery-key-in-fd`, and under `hardware` also `--recovery-device` and `--recovery-pin-fd`). A `strict` workspace has no recovery path, so it needs a signature by the existing key on its own authenticator (`--old-checkpoint-device`, `--old-checkpoint-pin-fd`); if that token is lost, the key cannot be changed.
* The record (public key, credential id, key hash) is sealed with everything else, in the audit chain, and a workspace rotation keeps it. `spo workspace checkpoint-key show` prints it again.
* **A restore keeps the key.** `store restore` over a workspace that has a checkpoint key, of a backup made before the key was enrolled, carries the key into the restored workspace (an audited write, said in the output). A backup that holds a *different* key keeps its own, because that file was sealed with it; the output warns, naming both key hashes, and pins made with the replaced key no longer match new backups. A restore from the long-lived pin says whether the restored file's key hash equals the pin's and warns if not. `init --policy hardware|strict` and `workspace migrate` say that no checkpoint key is enrolled yet.
* `spo store verify` says a checkpoint key record is present; `store verify --deep` parses it and fails, naming it, when it is malformed.

The flag is `--checkpoint-device` because `--fido2-device` already names the authenticator that unlocks a `hardware` or `strict` workspace.

### Back up with a checkpoint

```
spo -C ws store backup --sink s3://my-backup-bucket/mainnet --checkpoint-device /dev/hidraw3
```

The sink's own checks, the upload and the read-back come first, with no prompt for the checkpoint authenticator. Then it asks for the PIN and one touch, signs, puts `<name>.checkpoint` (never overwriting) and reads it back. It prints **both pins**:

```
Pin: <workspace id>:<head sequence>:<head hash>:<sha256 of the file>
Long-lived pin: <workspace id>:ck:<checkpoint key hash>
```

Record the long-lived pin from the output of `checkpoint-key enroll` (or from `show`, at a time you trust the workspace), not from a later backup's output: the key record is sealed inside the workspace, and whoever holds the daily factor and a modified build could rewrite it, which would change the pin a later backup prints. The backup output shows the key hash and enrolment date beside the pin so you can compare them with what you recorded.

If signing fails after the upload (a wrong PIN, an authenticator not touched in time), the command says "uploaded and verified, but NOT signed", prints the exact pin of the verified object and exits non-zero. Run it again: it finds the object, does not upload it again and signs. `--no-checkpoint` skips signing (the pin of stage 1 only). A backup to a file (`store backup FILE`) writes `FILE.checkpoint` beside it.

### What each pin proves

| Pin | Restore with it | What it proves |
| --- | --- | --- |
| `<ws>:<seq>:<head hash>:<sha256>` | That one file, no checkpoint needed | The bytes are exactly the file you pinned. Re-record it after every backup. |
| `<ws>:ck:<key hash>` | The newest backup whose checkpoint verifies | The backup was signed by your checkpoint key, so it is a backup you made. **It does not prove the backup is the newest the sink ever held.** |
| `<ws>:ck:<key hash>:<sequence>` | The newest verifying backup of at least that head sequence | Authentic, and not older than that sequence. |

**Without a sequence the pin proves authenticity, not freshness.** A sink that hides your newer backups and offers an older checkpoint and object that were once valid is accepted by `<ws>:ck:<key hash>`, and refused by a pin whose sequence is newer. Raise the sequence in the pin from time to time (after a backup, note its head sequence from the `Pin:` line); the tests show both outcomes.

### Restore from the long-lived pin

```
spo -C newws store restore --sink s3://my-backup-bucket/mainnet --pin <ws>:ck:<key hash> --network mainnet
```

The tool lists the workspace's objects and looks at the newest first, at most 16. For each it reads the checkpoint (at most 16 KiB), verifies the signature against the key hash in your pin (the public key travels inside the signature and is trusted only because its hash is the pinned one, never because it is in the sink), and checks that the statement names your workspace, a sequence at least the pin's minimum and the object's own name. Only then does it download the object, check its size, SHA-256, workspace id, head and slot-table hash against the statement and run the built restore. A candidate that fails is printed (with what the sink supplied escaped) and skipped, and nothing is downloaded for a candidate whose checkpoint does not verify. A network failure or a refusal of the restore itself stops the search: it never restores an older backup because a newer one could not be fetched. If no candidate verifies the restore is refused and nothing changes.

If a checkpoint **verified** for sequence N but its object is missing from the sink or does not match, the restore **refuses and names N**: a backup that existed is not quietly replaced by an older one. Restore an older one only with `--below N` (`spo store restore ... --pin <ws>:ck:<key hash> --below N`), which you give knowing sequence N existed. A search that stops at a limit (at most 16 candidates with a checkpoint, 256 names) says how many candidates it did not examine and that a valid backup may exist below them; `--below SEQ` starts it lower, and `store backups --below SEQ` lists from there. Candidates with no checkpoint do not use up the 16. The `time` in a statement is informational: no decision uses it.

`spo store backups --sink URL --pin <ws>:ck:<key hash>` shows per backup whether its checkpoint verifies. `spo store verify --backup FILE --checkpoint FILE.checkpoint --pin <ws>:ck:<key hash>` checks a local pair with no passphrase.

### Check a checkpoint with stock OpenSSH

The checkpoint is a statement, a blank line and an armored SSH signature. Split it, put the key line from `checkpoint-key show` in an `allowed_signers` file, and verify:

```
sed '/^$/,$d' name.checkpoint > statement              # the statement: the lines before the blank line
sed '1,/^$/d' name.checkpoint > statement.sig          # the signature: the lines after it
echo 'operator namespaces="spo/checkpoint/v1" sk-ecdsa-sha2-nistp256@openssh.com AAAA...' > allowed_signers
ssh-keygen -Y verify -f allowed_signers -I operator -n spo/checkpoint/v1 -s statement.sig < statement
```

(These commands were run against a checkpoint made by the tests and printed `Good "spo/checkpoint/v1" signature`.) **Stock `ssh-keygen -Y verify` accepts a signature without the user-presence flag and without the user-verification flag** (confirmed against OpenSSH 10.6, and `allowed_signers` has no option to require them), so it proves the signature is by that key and no more. `spo store verify --checkpoint` and every restore check both flags themselves.

### Limits

* No real authenticator was used. The `fido2-cred` and `fido2-assert` options that make and use the credential are read from libfido2's documentation and have been run only against a stand-in; the signature layout is confirmed against stock `ssh-keygen`.
* The key type is ECDSA P-256 (every FIDO2 authenticator has it); Ed25519 security keys are not supported.
* A checkpoint says the backup is a backup you made; it does not say the workspace in it is good, or the newest (see the table).
* Losing the checkpoint authenticator does not lose backups: the exact pins still restore, and the key can be replaced with the recovery credential (not under `strict`, which needs the old key).

## When a transfer is interrupted

Every failure leaves the sink and the workspace as they were and says so in its last sentence. Running the command again is safe. Names and messages a sink supplies are escaped before they reach the terminal. Leftovers of a crashed run (`.spo-backup-*` directories, `.spo-fetch-*.partial` files of other pins) are removed at the next push or fetch once they are over an hour old; nothing else is touched.

| Failure | What state is left | What to do |
| --- | --- | --- |
| A refusal (standard workspace to S3, bucket rules not met, static credentials) | Nothing was sent; nothing changed | Fix the cause, run again |
| The backup file fails verification | Nothing was sent; the temporary file is removed | Run again; if it repeats, run `spo store verify` |
| Ctrl-C or a dropped connection before or during the upload | No object, or the complete object; never a partial one. The temporary file is removed | Run again |
| The upload finished but the answer was lost | The object may be in the sink | Run again: it finds the object, does not upload twice, reads it back and verifies |
| The upload finished but the read-back failed: "uploaded but not verified" | The object is in the sink, not yet verified. Exit status is non-zero | Run again: it verifies the object without uploading again. Do not rely on the backup before it prints a pin |
| The read-back found different bytes | A bad object is in the sink and **cannot be deleted** while locked. Exit status is non-zero | Treat this backup as not made; list the sink, and make a new backup. Check the bucket policy and the store's conditional-write support |
| The sink says the object exists but cannot return it | Nothing uploaded; exit status non-zero | The sink is faulty or hostile; do not rely on it until checked. Running again will not help |
| Another object of the same head is in the sink under a different hash | Nothing special: only the object that this file's hash names is looked at, so a second object is made | None; list the sink to see both. Two backups of an unchanged workspace were byte-identical in a test, which is not guaranteed |
| A name is already taken by different bytes | Nothing changed | Names carry the file's hash, so this means the sink was altered; investigate before backing up again |
| Expired credentials | Nothing changed | Re-authenticate (for example `aws sso login`) and run again |
| A transfer that stalls | Abandoned after one minute without data; at most three attempts per request | Check the network and run again |
| A restore download is cut | The workspace is unchanged; a private partial file `.spo-fetch-<sha256>.partial` (mode 0600) stays in the workspace directory | Run the same command with the same pin: it resumes from the partial file's length |
| The finished download does not match the pin | The partial file is deleted; the workspace is unchanged | Check the pin; it may be for another backup, or the object was changed |
| The restore refuses because of the file (older, weaker, other workspace) | The downloaded file is removed; the workspace is unchanged | Read the refusal; it is the built restore's |
| The restore refuses for another reason after a verified download (wrong passphrase or PIN, cancelled prompt) | The verified file is kept as `.spo-fetch-<sha256>.partial`; the workspace is unchanged | Run again with the same pin; it does not download again. Flags that can be checked without the file (`--force`, `--allow-weaker-policy` needs `--force`) are checked before any download |
| The machine dies while the restore installs the file | The new `workspace.spo` is in place and the head file is still the old one | See the next section |

### The machine dies during the install

The restore writes `workspace.spo.head.next` (the head record it is about to write), renames the new file into place, writes `workspace.spo.head`, and removes the sidecar. If the machine dies after the rename and before the head file, the next open finds the new file beside the old head file. When the sidecar names exactly the head the file itself verifies to, the open adopts it: it writes the head file, removes the sidecar and prints a `note:` line, and nothing else is needed. `spo store verify` in that state does not fail: it says that a matching `workspace.spo.head.next` is present and that opening the workspace (any command that opens it) completes the restore; verify itself stays read-only and adopts nothing. A sidecar that does not match the file is ignored and named in the error; the open is then refused with the rollback message ("the workspace file is older than the last recorded state", naming `--accept-rollback`), as it is for an older file with no sidecar. In that case open it once with `--accept-rollback` (the file is the backup you asked for). Repeating the restore needs `--accept-lower-counters` in that state: a file older than its head file has no recorded counters to compare (with the sidecar of a real crash no flag is needed).

Someone who can write the workspace directory gains nothing from the sidecar: they could already replace the head file. Tests build the states after a crash for an older backup (with `--allow-older`) and a newer one; no real power loss was tried.
