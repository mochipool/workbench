+++
id = "Ckey"
kind = "common"
title = "Key encryption and reading"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["key-custody"]
use_cases = []
depends_on = ["Cui", "Cconf"]

upstream_path = "cardano/mainnet/00_common.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "9490fae84352a491bbded9bd4a14587521336364f9814a2df5aff6b86266bfba"
upstream_lines = 2966

[functions]
is_strong_password = "1b50e696492336d1e629472dd48b90a71a93cf7d74d04cc720343fe29b650b66"
encrypt_skeyJSON = "0e8221f4c8b530b187a70d1ee59c70b4c158926c3d1c4c3e189bb5567db3e7c5"
decrypt_skeyJSON = "402c0e6528811444b00f212652870784100669e26f4372a159c98a691e31248c"
read_skeyFILE = "90ef475ee26713efb0652cd2896312bd50f8a6e120be603660b93d3674863081"
+++

# Ckey: key encryption and reading

How signing keys are protected at rest and read back. A signing key file is a cardano-cli text envelope (`type`, `description`, `cborHex`). Upstream can replace it with an *encrypted envelope* in which the `cborHex` has been encrypted with a passphrase through `gpg`. `encrypt_skeyJSON` and `decrypt_skeyJSON` convert between the two forms in memory. `read_skeyFILE` is what every signing script calls to obtain the plaintext key JSON, prompting for the passphrase when the file is encrypted. The password-strength rule lives here, too.

All of the functions end failures with `exit 1` and print their message on **stdout**. Every caller uses them as `x=$(f ...)` and, on a non-zero status, prints `$x` as the error text. The `exit` therefore ends only the subshell and the caller observes the status. Called directly, they would kill the script.

## is_strong_password

- **SPO-Ckey-INV-001** A password is strong when all of these hold: it contains at least one lower-case letter `a-z`; at least one upper-case letter `A-Z`; at least one digit; at least one character that is not `a-zA-Z0-9`; and it is at least 10 characters long. (src: L2805-L2807)
- **SPO-Ckey-IF-001** `is_strong_password <password>` prints `true` on stdout and returns 0 when SPO-Ckey-INV-001 holds. Otherwise it prints nothing and returns 1. Callers compare the **output** with `true`. It never calls `exit`. (src: L2806)

> **Upstream quirk:** "Special" means anything outside `a-zA-Z0-9`, so spaces and non-ASCII letters count. The classes and the length are evaluated per the shell's locale. The rule is a gate for passwords created by the scripts and for those typed to decrypt; it cannot make a weak password pass. (src: L2806)

## encrypt_skeyJSON

Called as `encrypt_skeyJSON <skeyJsonText> <password>`.

- **SPO-Ckey-PRE-001** Needs `gpg`: when it is not installed, prints an install hint to the terminal (`termTTY`) and exits 1. This check applies identically to `decrypt_skeyJSON` and `read_skeyFILE` (the latter only for an encrypted file). (src: L2824, L2862, L2911)
- **SPO-Ckey-PRE-002** Exits 1 with "It is already encrypted!" when the text contains `encrHex` or `Encrypted` on any line. (src: L2827)
- **SPO-Ckey-PRE-003** Reads `.type`, `.description` and `.cborHex` with `jq -r`. A `jq` failure is **not** detected: each read is written `local x=$(jq ...); if [[ $? -ne 0 ]]`, and `$?` is the status of the `local` builtin (always 0), so the "Can't read the .<field> field!" exit never runs and the variable keeps whatever `jq` printed (possibly nothing). The text must also contain the substring `SigningKey` anywhere, not necessarily in `.type`, or it exits 1. A missing field is not detected either: `jq -r` returns the word `null`, which is then used as the value. (src: L2830-L2833)
  > **Upstream quirk:** a malformed envelope is not refused by any `jq` check; encryption proceeds on the partial or empty values. A port refuses a malformed envelope (see Port notes).
- **SPO-Ckey-INV-002** The function does not check the strength of the password or that it is non-empty. Callers enforce that (SPO-Ckey-INV-001). (src: L2817-L2845)
- **SPO-Ckey-EXT-001** Runs `gpg --symmetric --yes --batch --quiet --cipher-algo AES256 --passphrase <password> --log-file /dev/null` with the `cborHex` string, followed by a newline, on stdin and stderr discarded. The binary (not ASCII-armoured) output is turned into lower-case hex on one line (`xxd -ps -c 1000000`). The salt and session key are random, so every run gives a different `encrHex`. The S2K mode, hash, compression and integrity packet are gpg's defaults. (src: L2837)
- **SPO-Ckey-PRE-004** Exits 1 with "Couldn't encrypt the data via gpg!" when the hex output is empty. (src: L2840)
- **SPO-Ckey-OUT-001** On success, prints on stdout the **encrypted key envelope**, a JSON object formatted by `jq -M .` (two-space indent, no colour) with exactly these members in this order: `type`, the original `.type`; `description`, the original description prefixed with `Encrypted ` (capital E, one trailing space); `encrHex`, the lower-case hex of the gpg symmetric output of SPO-Ckey-EXT-001 over `cborHex` plus a newline. There is no `cborHex` member. Status is that of `jq` (0). (src: L2837, L2843)
- **SPO-Ckey-INV-003** To interoperate, an envelope written by a port must decrypt with the passphrase through `gpg --decrypt`, and one written by upstream must decrypt in the port. This means an OpenPGP symmetric-key encrypted message (an SKESK packet followed by an encrypted-data packet), AES-256, whose plaintext is the ASCII hex text of the original `cborHex` plus one newline. (gpg 2.4.9 as observed: SKESK v4, cipher 9, iterated-and-salted S2K with SHA-512, an integrity-protected data packet.) (src: L2837, L2875)

> **Upstream quirk:** The envelope is assembled by `echo -e` from unescaped text. A `type` or `description` containing a double quote or a backslash sequence yields invalid or altered JSON. cardano-cli's fixed descriptions never contain them. (src: L2843)

## decrypt_skeyJSON

Called as `decrypt_skeyJSON <encryptedEnvelopeText> <password>`. It has no caller that opens a signing file; only `01_protectKey` uses it, to turn an encrypted key file back into a plain one.

- **SPO-Ckey-PRE-005** Exits 1 with "It is already decrypted!" when the text contains neither `encrHex` nor `Encrypted`. (src: L2865)
- **SPO-Ckey-PRE-006** Reads `.type`, `.description` and `.encrHex` with `jq -r`, and requires the substring `SigningKey` somewhere in the text, exactly as in SPO-Ckey-PRE-003: a `jq` failure is not detected (the status tested is that of `local`), and a missing field yields the word `null`. A `jq` failure therefore falls through to the decryption step with empty or partial input, which fails there (SPO-Ckey-PRE-007). (src: L2868-L2871)
- **SPO-Ckey-EXT-002** Converts `encrHex` from hex to bytes and runs `gpg --decrypt --yes --batch --quiet --passphrase <password> --log-file /dev/null`, stderr discarded. The decrypted text is taken as the `cborHex`. The trailing newline of the plaintext is removed by command substitution. (src: L2875)
- **SPO-Ckey-PRE-007** Exits 1 with "Couldn't decrypt the data via gpg! Wrong password?" when the decrypted text is empty. A wrong passphrase makes gpg fail, so this is the wrong-password path. The plaintext is not checked to be valid hex or CBOR. (src: L2878)
- **SPO-Ckey-OUT-002** On success, prints the plain key envelope, `jq -M .` formatted: `type`, `description` with **every** occurrence of `Encrypted ` removed, and `cborHex`, in that order. (src: L2881)

## read_skeyFILE

Called as `read_skeyFILE <path>`. This is the single entry point through which the signing scripts obtain a signing key.

- **SPO-Ckey-IF-002** Prints the **plaintext** key JSON on stdout and returns 0, or prints a message on stdout and exits 1. The caller captures the output into a variable and must never write it to a file, to the terminal or to a log. (src: L2895-L2965)
- **SPO-Ckey-PRE-008** Exits 1 with "Given SKEY-File does not exist!" when the path is not a regular file. (src: L2903)
- **SPO-Ckey-IN-001** A file is treated as encrypted when `encrHex` or `Encrypted` appears on any line (case-sensitive). No other check is made. (src: L2907)
- **SPO-Ckey-OUT-003** An unencrypted file is returned verbatim (`cat`), with status 0, and nothing else on stdout. The text is not parsed or validated at all: no JSON, `type` or `SigningKey` check is made. A "Reading unencrypted file" line goes to the terminal as display only. (src: L2907)
- **SPO-Ckey-IN-002** For an encrypted file, the environment variable `ENV_DECRYPT_PASSWORD` is read. When it is non-empty, it is used as the password without any prompt. (src: L2918, L2929-L2934)
- **SPO-Ckey-PRE-009** With `ENV_DECRYPT_PASSWORD` set, exits 1 when it is not a strong password (SPO-Ckey-INV-001), and exits 1 on the first failed decryption, with no retry. (src: L2932, L2953)
- **SPO-Ckey-PR-001** With no `ENV_DECRYPT_PASSWORD`, asks for the password with the hidden prompt `Enter the Password to decrypt '<file>' (empty to abort)`. An empty answer prints "Aborted" and exits 1, at every prompt. (src: L2920-L2921, L2925-L2926)
- **SPO-Ckey-PR-002** A password that is not strong is not tried; a message says it cannot be the right one, and the prompt repeats. This relies on every encrypted file having been created with a strong password. (src: L2922-L2927)
- **SPO-Ckey-PR-003** A wrong (but strong) password prints "Couldn't decrypt the data! Wrong password?" on the terminal (`$(tty)`) and asks again, with no limit on attempts. Only an empty answer leaves the loop. (src: L2952-L2957)
- **SPO-Ckey-PRE-010** The field reads and the decryption inside the loop are those of SPO-Ckey-PRE-006 and SPO-Ckey-EXT-002 (the same `jq` reads and the same gpg call, with `2>/dev/null` also on the `xxd` step). A missing `SigningKey` substring exits 1 with a message on stdout, and no retry follows. A `jq` failure is **not** detected (the status tested is that of `local`, as in SPO-Ckey-PRE-003): a corrupted encrypted file passes the substring test, gpg receives empty input, `cborHex` stays empty, and the operator is asked for a password again and again until an empty answer (SPO-Ckey-PR-003). With `ENV_DECRYPT_PASSWORD` the same file exits 1 with the wrong-password message (SPO-Ckey-PRE-009). (src: L2939-L2949, L2952-L2957)
  > **Upstream quirk:** a corrupted file is reported as a wrong password, and without `ENV_DECRYPT_PASSWORD` it loops. A port reports the malformed envelope.
- **SPO-Ckey-OUT-004** On success, prints on stdout the single-line plain key envelope `{ "type": "<t>", "description": "<d>", "cborHex": "<h>" }` (the description with every `Encrypted ` removed) and no trailing newline, then returns 0. Unlike SPO-Ckey-OUT-002 it is not reformatted by `jq`, and it is written with `printf` using the text as the **format string**, so `%` and backslash sequences in `type` or `description` would be interpreted. (src: L2962)
- **SPO-Ckey-INV-004** The plaintext key is never written to a file by this function; it exists only in the shell variable and on stdout. (src: L2939-L2963)

> **Upstream quirk:** The detection in SPO-Ckey-IN-001 is a text search. A plaintext key whose description contains `Encrypted` is mistaken for an encrypted one; it then fails `jq .encrHex` (value `null`), the decrypt step fails, and the user is asked for a password until they give an empty one. (src: L2907, L2943, L2949)

> **Upstream quirk:** The wrong-password message uses an unquoted `$(tty)` redirect, which is an "ambiguous redirect" error when there is no terminal (`not a tty`); the message is lost, and the loop repeats. (src: L2954)

## Security

- **SPO-Ckey-SEC-001** The passphrase is passed to gpg on its **command line** (`--passphrase <password>`), in `encrypt_skeyJSON`, `decrypt_skeyJSON` and `read_skeyFILE`. It is visible to every local user in the process table (`ps`, `/proc/<pid>/cmdline`) for as long as gpg runs. (src: L2837, L2875, L2949)
- **SPO-Ckey-SEC-002** `read_skeyFILE` returns the plaintext signing key on stdout for the caller to keep in a variable (`skeyJSON=$(read_skeyFILE ...)`), and `decrypt_skeyJSON` prints it. Anything that captures that output holds the secret. An unencrypted file is returned as is, so key files without protection still work. (src: L2907, L2962, L2881)
- **SPO-Ckey-SEC-003** `ENV_DECRYPT_PASSWORD` keeps the passphrase in the process environment, readable by the same user and inherited by child processes. It is meant for unattended use. (src: L2918, L2929-L2934)
- **SPO-Ckey-SEC-004** The encrypted envelope has no integrity binding to the `type` and `description` members: only the `cborHex` is encrypted and authenticated (by the gpg integrity packet). The members outside the ciphertext can be changed without the decryption noticing. (src: L2837, L2843)

## Domain mapping

| Port | Operation | Purpose |
| --- | --- | --- |
| `Vault` | `seal(secret, policy)` | `encrypt_skeyJSON` (policy: passphrase); policy `none` is the plaintext key file |
| `Vault` | `unseal(ref, passphrase?)` | `read_skeyFILE` and `decrypt_skeyJSON`; returns an in-memory handle, never text |
| `Vault` | `exportPlaintext(ref, destination)` | The `01_protectKey` decrypt-to-file action |
| `UI` | `askPassword(prompt)` | The decrypt prompt and re-prompt loop |

The password policy of SPO-Ckey-INV-001 belongs to the `Vault` seal policy; the unseal side keeps the "weak passwords are not tried" shortcut (SPO-Ckey-PR-002) only for legacy envelopes.

## Port notes

* Keep the envelope of SPO-Ckey-OUT-001 as the file-system adapter's import and export format. New adapters (SQLite, KMS) can use their own envelope; the use case sees only `seal` and `unseal`.
* Pass the passphrase to gpg through a file descriptor or implement OpenPGP natively, which removes SPO-Ckey-SEC-001.
* `unseal` should hand the signing step an opaque handle. Returning the key as text (SPO-Ckey-SEC-002) is an artefact of shell scripting.
* A raw-input password reader must still reproduce the backslash handling of upstream's `ask_pass` (see SPO-Cui-SEC-001) when opening legacy files, or it derives a different passphrase.
* Authenticate `type` and `description` with the ciphertext in any new envelope (SPO-Ckey-SEC-004).
* Refuse a malformed envelope (unparsable JSON, missing `type`, `description` or `cborHex`/`encrHex`) with a distinct error before any decryption attempt, so a corrupted file is not reported as a wrong password or retried forever (SPO-Ckey-PRE-003, SPO-Ckey-PRE-006, SPO-Ckey-PRE-010).

## Open questions

* The gpg version range in which `--passphrase` works without `--pinentry-mode loopback` is not stated by upstream. The packet structure quoted in SPO-Ckey-INV-003 was observed by encrypting with gpg 2.4.9.
* Whether `[a-z]` and `[A-Z]` match non-ASCII letters under some locales is not settled by the source; a port should use ASCII classes.
