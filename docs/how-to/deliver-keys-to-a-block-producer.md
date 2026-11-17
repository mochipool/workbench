# Deliver keys to a block producer

This guide moves a pool's hot keys (the KES signing key, the VRF signing key and the operational certificate) from the sealed workspace to a block producer, until the `node export` of [ADR 0011](../explanation/adr/0011-key-custody-and-unlock.md) is approved and built.

`cardano-node` reads these three files in clear. That is a requirement of the node, not of `spo`: the files are plaintext on the block producer for as long as the node runs. The operational certificate is public. The cold key must never reach a block producer.

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
* A kept-encrypted KES, VRF or BLS key (an import with `--keep-encrypted`) cannot be exported or converted: `spo` cannot derive its verification key to check it. Import the directory again with `spo workspace import DIR --password-fd N` (without `--keep-encrypted`), which decrypts and seals the key, then export.
* `spo key protect` and `spo key unprotect` are gone. A plain directory is not a workspace; the upstream script `01_protectKey.sh` encrypts and decrypts a key file there.

## If something goes wrong

* `gpg: decryption failed: Bad session key` means a wrong password. The password is exactly the one the export showed, with its hyphens and its letter case.
* `the export password is too short` or `not strong` is a password given with `--password-fd`; use `--generate-password`.
* `a generated password is shown once, on a terminal` means standard output is not a terminal; pass `--password-out-fd N` to receive the password on a pipe you opened (for example `4> >(pass insert -m export-pw)`). A regular file, a terminal, a closed descriptor and descriptors 0, 1 and 2 are refused before anything is written: a secret is never written to a file. The password is delivered before any export file is written, so a failed delivery leaves nothing behind.

Related: [CLI reference](../reference/spo-cli.md#workspace-export-dir), [Rotate KES keys](./rotate-kes-keys.md).
