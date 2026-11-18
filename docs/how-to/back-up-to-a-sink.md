# Back up to a sink: a directory or an S3 bucket

Reference: [`spo-cli.md`](../reference/spo-cli.md#store-backup). Background: [ADR 0012](../explanation/adr/0012-server-backup-and-deployment.md), decisions 4 and 9, stage 1. Spec: [Xbackup](../../spec/extensions/Xbackup.md).

**Nothing here has been run against a real bucket.** The S3 adapter was tested only against an in-process fake on 127.0.0.1. Treat the first real upload as a test: do it with a throw-away workspace, then restore it.

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

`--allow-older` is **refused** with `--sink`: the built restore replaces the whole file, so an older backup would lower the operational-certificate counters, and a restore does not guard against that yet. Restore an older backup by downloading it by hand and using `spo store restore FILE --allow-older`, and check the counters afterwards.

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

The restore writes `workspace.spo.head.next` (the head record it is about to write), renames the new file into place, writes `workspace.spo.head`, and removes the sidecar. If the machine dies after the rename and before the head file, the next open finds the new file beside the old head file. When the sidecar names exactly the head the file itself verifies to, the open adopts it: it writes the head file, removes the sidecar and prints a `note:` line, and nothing else is needed. A sidecar that does not match the file is ignored and named in the error; the open is then refused with the rollback message ("the workspace file is older than the last recorded state", naming `--accept-rollback`), as it is for an older file with no sidecar. In that case open it once with `--accept-rollback` (the file is the backup you asked for) or repeat the restore.

Someone who can write the workspace directory gains nothing from the sidecar: they could already replace the head file. Tests build the states after a crash for an older backup (with `--allow-older`) and a newer one; no real power loss was tried.
