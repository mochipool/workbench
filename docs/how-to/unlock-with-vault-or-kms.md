# Unlock with a Vault or KMS key

Reference: [`spo-cli.md`](../reference/spo-cli.md) and [`spo-toml.md`](../reference/spo-toml.md). Background: [ADR 0011](../explanation/adr/0011-key-custody-and-unlock.md), decisions 5 and 6.

**Not tested against a real service.** The Vault and KMS clients were run only against stand-ins inside the tests (an in-process Transit, KMS and STS on 127.0.0.1). Nobody has used them with a real Vault, OpenBao or AWS account yet. Try them on a throw-away workspace first.

## What it gives you

A Vault or KMS key is one factor of a `composite` slot. The slot needs two things to open:

* the backend, which unwraps a random 32-byte secret stored in the slot, and
* a factor the backend does not control: a passphrase for this slot only, or a FIDO2 authenticator.

Whoever runs the backend has the first half and not the second. A stolen copy of the workspace with the passphrase has the second half and not the first. The wrap at the backend is bound to this workspace and this slot, so it cannot be moved to another one.

Under the `standard` policy the passphrase slot and the recovery slot still open the workspace alone. A backend slot there is another way in, not more strength. Under `hardware` and `strict` the backend must be paired with a FIDO2 authenticator; a backend with a passphrase is refused there.

Your credential stays yours. The tool never stores a Vault token or an AWS key in the workspace or in `spo.toml`, never puts one on a command line, and never passes one to another program.

## `spo.toml` decides where your credential goes

The slot stores the backend's kind, address, namespace and key. That copy is only a claim: anyone who can write the workspace file or a backup could change it. So at every unlock, `store verify`, backup check and restore, the tool compares the slot's backend with `[vault]` or `[kms]` in `spo.toml` first. If any field differs, it stops before it reads your token, before it asks for the slot's passphrase and before it contacts anything. The error shows both values and says the workspace file may have been altered.

Keep `spo.toml` as the record of your backend. If you move Vault to a new address, the old slots no longer open through it: open with `--unlock passphrase` (or `fido2`), remove the backend slot and add it again.

## Vault Transit

You need Vault 1.13 or later, or OpenBao: Transit must support `associated_data`. An older server ignores the parameter. The tool refuses an encrypt or decrypt answer that warns about an ignored parameter, and when it adds a slot it checks that an unwrap under another slot id is refused. A server that ignores the binding is refused at that point and no slot is added.

1. Make a Transit key that takes associated data and is not derived:

   ```
   vault secrets enable transit
   vault write -f transit/keys/spo-unlock type=aes256-gcm96
   ```

   Give your policy `read` on `transit/keys/spo-unlock` and `update` on `transit/encrypt/spo-unlock` and `transit/decrypt/spo-unlock`.

2. Name it in `spo.toml`:

   ```toml
   [vault]
   address = "https://vault.example:8200"
   key = "spo-unlock"
   ca_file = "/etc/spo/vault-ca.pem"   # if your CA is not in the system roots
   ```

   The address must use `https`. Plain `http` is accepted only to a loopback IP address (`http://127.0.0.1:8200`, a local agent or a test server) and only with `allow_loopback_http = true` in the section.

3. Log in the way you normally do. `vault login` keeps the token in `~/.vault-token`, which the tool reads. `VAULT_TOKEN` in the environment works too. For a JWT or OIDC token in a file, set `auth = "jwt"`, `jwt_role` and `jwt_file`.

   Token and JWT files must be regular files that you own and only you can read (`chmod 600`). A symbolic link or a pipe is refused; name the file itself.

   The tool asks Vault about the token first (`auth/token/lookup-self`). A token that never expires (TTL 0) or has the `root` policy is refused. Use a token with a TTL, for example `vault token create -policy=spo-unlock -ttl=1h`, or a JWT login. Your policy needs `read` on `auth/token/lookup-self`, which the `default` policy grants.

4. Add the slot:

   ```
   spo -C ws workspace slot add-backend --backend vault --with passphrase
   ```

   It opens the workspace with its current factors, asks twice for a new passphrase for this slot, and prints the slot id.

## AWS KMS

1. Use a symmetric key (`SYMMETRIC_DEFAULT`). Allow `kms:Encrypt` and `kms:Decrypt` for your role. You can require the context in the key policy with the condition keys `kms:EncryptionContext:spo-genesis` and `kms:EncryptionContext:spo-slot`.

2. Name it by its key ARN (not an alias):

   ```toml
   [kms]
   key_arn = "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
   ```

   The tool talks to the public KMS and STS endpoints of the ARN's region (`kms.eu-west-1.amazonaws.com`, `sts.eu-west-1.amazonaws.com`) and trusts the system roots. Your web identity token goes to that STS endpoint and nowhere else.

3. Give short-lived credentials. Either a web identity (set `role_arn` and `web_identity_token_file`, or `AWS_ROLE_ARN` and `AWS_WEB_IDENTITY_TOKEN_FILE`), or temporary credentials in the environment with `AWS_SESSION_TOKEN`, for example:

   ```
   aws sso login
   eval "$(aws configure export-credentials --format env)"
   ```

   Only a temporary key id (`ASIA...`) with a session token is accepted. Static access keys (`AKIA...`) and any other key id are refused. The web identity token file follows the same file rules as the Vault token file.

4. Add the slot:

   ```
   spo -C ws workspace slot add-backend --backend kms --with passphrase
   ```

### Private endpoints only

If you reach KMS or STS through a VPC endpoint, name it explicitly. These settings are for private endpoints only; leave them out otherwise.

```toml
[kms]
key_arn = "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
private_endpoint = "https://vpce-0abc.kms.eu-west-1.vpce.amazonaws.com"
private_ca_file = "/etc/spo/kms-ca.pem"          # only if that endpoint's CA is not in the system roots
private_sts_endpoint = "https://vpce-0def.sts.eu-west-1.vpce.amazonaws.com"
private_sts_ca_file = "/etc/spo/sts-ca.pem"      # the CA of private_sts_endpoint only
```

Each CA file applies to its own endpoint only. A CA file without its endpoint is refused. A plain-http private endpoint also needs `allow_loopback_http = true` and a loopback IP address.

## With a FIDO2 authenticator instead of a passphrase

```
spo -C ws --fido2-device /dev/hidraw3 workspace slot add-backend --backend vault --with fido2
```

This makes a new credential on the authenticator for this slot only. Under `hardware` and `strict` this is the only form allowed. Every check that could refuse the slot (the policy, a workspace that needs a rekey first) runs before the authenticator is asked, so a refusal leaves no credential on it.

## Unlock through it

```
spo -C ws --unlock backend store verify
```

The tool checks the slot's backend against `spo.toml`, asks for the slot's passphrase (or reads `--passphrase-fd N` once for the whole command), or for the authenticator, and then asks the backend. If the backend fails (refused token, network, wrong key), the command stops at that slot and says which slot and backend failed and what kind of failure it was. It does not try other slots after a backend failure. Your other ways in (`--unlock passphrase`, `fido2` or `recovery-composite`) are not affected. It never shows the token or what the backend answered.

Signing in a session opened this way asks for the composite again: the backend, and the slot's passphrase typed at the terminal. `--passphrase-fd` does not count for that step; with no terminal nothing is signed. A backend with a passphrase can sign in a build without FIDO2 support.

## List and remove

```
spo -C ws workspace slot list
spo -C ws workspace slot remove <slot id>
```

The listing shows the backend's kind, address and key name. Removing a slot is a rotation and asks for the recovery key, as for any slot.

A rotation (`workspace rotate`, `policy set`) does not re-create a backend slot, because the wrap at the backend is bound to the slot id. Removing another slot while a backend slot exists is refused for the same reason. Remove the backend slot first, do the change, then add it again.

## What this does not cover

* Cold-role keys (pool cold, committee cold) are sealed under their own sub-key factor: the sub-key passphrase under `standard`, the authenticator under `hardware`. A backend does not take part in that yet.
* Vault policy denials, token expiry during a long command and KMS key policies were not tested against a real service. The minimum Vault version above is taken from Vault's changelog as recalled, not checked against a server.
* The token and the AWS session token are sent as HTTP headers. Go's HTTP and TLS code keeps copies of them that the tool cannot zero; see SPO-Xunlock-SEC-008 for the full list.
