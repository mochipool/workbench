# Deliver keys to a block producer

This guide moves a pool's hot keys (the KES signing key, the VRF signing key and the operational certificate) from the sealed workspace to a block producer. There are two ways: `spo node export` with the start-up helper `spo-node-keys` ([ADR 0011](../explanation/adr/0011-key-custody-and-unlock.md) decision 2), which this guide describes first, and the older gpg way at the end, which needs no helper on the producer.

`cardano-node` reads these three files in clear. That is a requirement of the node, not of `spo`: the files are plaintext on the block producer for as long as the node runs. The operational certificate is public. The cold key must never reach a block producer.

## With `spo node export` and the start-up helper

`node export` writes only `age` ciphertext, sealed to one recipient key that belongs to the block producer. The helper `spo-node-keys` runs on the producer, decrypts the three files into a `ramfs` directory for the node, mode 0400, and does nothing else. It is a separate program that cannot open a workspace, and `spo` cannot write a plaintext key.

**On the block producer, once.**

1. Make an age identity and keep it out of reach of the disk. With `age-keygen` (from the `age` package) and `systemd-creds`:

   ```sh
   age-keygen -o /dev/stdout 2>/dev/null | grep -v '^#' \
     | systemd-creds encrypt --name=spo-node-age-identity --with-key=tpm2 - /etc/credstore.encrypted/spo-node-age-identity
   age-keygen -y <(systemd-creds decrypt /etc/credstore.encrypted/spo-node-age-identity -)
   ```

   The first command makes the credential bound to the host's TPM 2.0; the second prints the public key (`age1...`), which is what you give `spo`. The exact `systemd-creds` options and their behaviour without a TPM are unconfirmed here: without a TPM `systemd-creds` falls back to a key file of the host, which protects against nothing that can read the disk. Never keep the identity (`AGE-SECRET-KEY-...`) as a file in clear.

2. Mount a `ramfs` for the keys, owned by the node's user. A `tmpfs` is accepted only when its mount has the `noswap` option (Linux 6.4 and later; the helper finds the mount in `/proc/self/mountinfo` and refuses otherwise), because an ordinary tmpfs can be swapped to disk:

   ```sh
   mkdir /run/spo-keys && mount -t ramfs -o mode=0700,uid=cardano,gid=cardano ramfs /run/spo-keys
   ```

3. Run the helper as the node's user from a unit that loads the identity as a credential, before `cardano-node` starts. A sketch:

   ```ini
   [Service]
   User=cardano
   LoadCredentialEncrypted=spo-node-age-identity:/etc/credstore.encrypted/spo-node-age-identity
   ExecStartPre=/usr/bin/spo-node-keys deliver --from /var/lib/spo/delivery --to /run/spo-keys
   ExecStopPost=/bin/rm -f /run/spo-keys/kes.skey /run/spo-keys/vrf.skey /run/spo-keys/node.cert
   ```

   The helper never replaces a file, so the output directory must hold none of the three names at start. The `ExecStopPost` line removes them when the service stops (also after a crash), so a restart delivers again; the alternative is a fresh mount of the `ramfs` for each start. Do not use `RuntimeDirectory=` for this: it lives on `/run`, an ordinary `tmpfs` that the helper refuses unless that mount has `noswap`. The helper does not remember earlier deliveries: it cannot refuse an older complete set that someone put into the delivery directory (see the handoff).

   The helper reads the identity from `$CREDENTIALS_DIRECTORY`; it refuses to run as root, and it refuses a credentials directory or an output directory that is not on `ramfs` (whether systemd's credentials directory is always `ramfs` is unconfirmed: the helper checks, so a `tmpfs` one without `noswap` stops the delivery with a message). The credential file must be owned by the service user or root with no access for others; group read is accepted only for the helper's own primary group, so a `0440 root:root` credential is refused unless the service runs with group root. Whether systemd creates credentials that way is unverified on a real host. Point the node at `/run/spo-keys/kes.skey`, `vrf.skey` and `node.cert`.

**On the machine with the workspace, for each delivery (a new KES key, a new certificate):**

1. Put the producer's public key in a file and export:

   ```sh
   spo node export mypool --recipient producer.pub --out /tmp/delivery-mypool --reason "KES rotation 004"
   ```

   `--kes N` names the KES key (default: the newest one that has a certificate). Before anything is sealed the command checks that the role history of the KES and VRF key has the hot role and no cold role (a key with no stored history is refused), that no Ed25519 key of the same public key is recorded in another role, that the certificate is signed by the pool's own cold key, is the newest the issue counter has made and names this KES key, and that each signing key derives the verification key stored with it (for a KES key the whole Sum6 structure is checked against its seeds). It writes the three files under temporary names, records the delivery in the workspace's audit log, and then gives them their names (`kes.skey.age`, `vrf.skey.age`, `node.cert.age`). `--no-tpm-identity` records that the producer's identity is not held in a TPM-bound credential; without it the command says it cannot check.

2. Copy the three files to the producer (`/var/lib/spo/delivery` above) over any channel: they are ciphertext. Restart the unit. The helper writes nothing if a file is missing, was sealed to another key, was changed, is not the kind its name says, carries a header of another delivery (each file names its pool, KES number and certificate counter, and the three must agree), or the certificate does not verify or does not name the delivered KES key; the output directory must be empty of those names (the helper never replaces a file: remove the old files when the service stops, or use a fresh `ramfs` per start).

3. Delete `/tmp/delivery-mypool` when it has been copied.

What stays in clear, and where: the KES key, the VRF key and the certificate on the producer's `ramfs` for as long as the service runs and in the node's memory; the age identity in the helper's memory while it decrypts and in the credentials directory of its service. Nothing is on a disk. Rotate the KES key before the certificate expires (`pool kes generate`, `pool opcert issue`) and deliver again. See the real-device checklist in the [handoff](../development/handoff.md): none of this was run against a real host, TPM or `cardano-node`.

## Without the helper: `workspace export` and gpg

The steps below deliver the same three files through `spo workspace export` and a gpg decryption by hand. They need no helper on the producer, and their export also encrypts the pool's cold key, so the export directory is never copied as a whole.

## Prerequisites

* A sealed workspace that holds the pool (its KES signing key `<pool>.kes-NNN.skey`, its VRF signing key `<pool>.vrf.skey` and its operational certificate `<pool>.node-NNN.opcert`). If you rotated the KES key with the upstream scripts, import the result first with `spo workspace import`.
* gpg on the machine that exports (`spo capabilities` lists `key-encryption`) and on the block producer, with `bash`, `jq` and `xxd` there too.
* A terminal on the machine that exports (the generated password is shown on it once), and a way to carry three small files to the block producer.

## Steps

1. Export the pool with a generated password:

   ```sh
   spo workspace export /tmp/export-mypool --owner mypool --generate-password --reason "KES rotation 004"
   ```

   The password is shown once, as eight hyphen-separated groups. Write it down where the block producer's operator can read it, not in the same place as the files. The export also holds the pool's encrypted cold key (`mypool.node.skey`); that directory is never copied as a whole.

2. Copy only the three hot-key files to the block producer, over a channel you control:

   ```sh
   scp /tmp/export-mypool/mypool.kes-004.skey /tmp/export-mypool/mypool.vrf.skey /tmp/export-mypool/mypool.node-004.opcert bp:/tmp/incoming/
   ```

3. On the machine that exported, delete the whole export directory, which still holds the encrypted cold key:

   ```sh
   rm -r /tmp/export-mypool
   ```

4. On the block producer, decrypt each signing key straight into the node's key directory. These steps need `bash` (process substitution, `read -s`, `pipefail`), `gpg`, `jq` and `xxd`. The message was made with `gpg --symmetric --cipher-algo AES256 --s2k-mode 3 --s2k-digest-algo SHA512 --s2k-count 65011712 --force-mdc`; decryption needs none of those options, because gpg reads them from the message.

   ```bash
   umask 077
   read -rs -p 'Export password: ' PW; echo
   decrypt_key() {   # decrypt_key ENCRYPTED.skey DESTINATION.skey
     local src=$1 dst=$2
     set -o pipefail
     jq -r .encrHex "$src" | xxd -r -p \
       | gpg --decrypt --batch --pinentry-mode loopback --passphrase-fd 3 3< <(printf '%s' "$PW") \
       | jq --rawfile c /dev/stdin '{type, description: (.description | gsub("Encrypted "; "")), cborHex: ($c | rtrimstr("\n"))}' "$src" > "$dst" \
       || { rm -f "$dst"; echo "decrypting $src failed" >&2; return 1; }
   }
   decrypt_key /tmp/incoming/mypool.kes-004.skey /path/to/keys/kes.skey
   decrypt_key /tmp/incoming/mypool.vrf.skey     /path/to/keys/vrf.skey
   ```

   The secret key text goes from gpg to `jq` through a pipe. It is never an argument of any command (an argument is visible in `/proc/PID/cmdline`), and the password reaches gpg on a descriptor from `printf`, a shell built-in, so it is not an argument either. No intermediate file is written: the only plaintext file is the final `kes.skey` (and `vrf.skey`), created with mode 0600 by the `umask`, which `cardano-node` requires. A wrong password or a damaged file leaves no output file. The result is the cardano-cli text envelope `{"type": ..., "description": ..., "cborHex": ...}` that the node reads. The upstream script `01_protectKey.sh dec` does the same on a key file if the upstream scripts are installed there.

5. Copy the certificate into the key directory unchanged, set the file modes, point the node at the files (`--shelley-kes-key`, `--shelley-vrf-key`, `--shelley-operational-certificate`) and restart `cardano-node`:

   ```sh
   cp /tmp/incoming/mypool.node-004.opcert /path/to/keys/node.opcert
   chmod 400 /path/to/keys/kes.skey /path/to/keys/vrf.skey
   ```

6. Delete what is left once the node runs on the new keys, and forget the password:

   ```sh
   rm /tmp/incoming/mypool.kes-004.skey /tmp/incoming/mypool.vrf.skey /tmp/incoming/mypool.node-004.opcert
   unset PW
   ```

## Things to know

* An export is a transport form. gpg's key derivation is not memory-hard, so the files are weaker against offline guessing than the sealed workspace. The generated password (160 bits) and the 20-character minimum are what make them hold; keep the files only for as long as the move takes.
* A kept-encrypted KES or VRF key (a record of an import made before `--keep-encrypted` was removed) cannot be exported until it is converted (`spo key convert`, which now checks it against its verification key) or imported again with `spo workspace import DIR --password-fd N` , which decrypts and seals it. A kept-encrypted BLS key can only be imported again.
* `spo key protect` and `spo key unprotect` are gone. A plain directory is not a workspace; the upstream script `01_protectKey.sh` encrypts and decrypts a key file there.

## If something goes wrong

* `gpg: decryption failed: Bad session key` means a wrong password. The password is exactly the one the export showed, with its hyphens and its letter case.
* `the export password is too short` or `not strong` is a password given with `--password-fd`; use `--generate-password`.
* `a generated password is shown once, on a terminal` means standard output is not a terminal; pass `--password-out-fd N` to receive the password on a pipe you opened (for example `4> >(pass insert -m export-pw)`). A regular file, a terminal, a closed descriptor and descriptors 0, 1 and 2 are refused before anything is written: a secret is never written to a file. The password is delivered before any export file is written, so a failed delivery leaves nothing behind.

Related: [CLI reference](../reference/spo-cli.md#workspace-export-dir), [Rotate KES keys](./rotate-kes-keys.md).
