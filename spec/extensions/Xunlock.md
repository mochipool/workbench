+++
id = "Xunlock"
kind = "extension"
title = "Unlock factors: FIDO2 through libfido2, slot-key derivation, unlock policy"
status = "draft"
contexts = ["key-custody"]
use_cases = ["EnrolFactor", "UnlockWorkspace"]
depends_on = ["Xcustody"]
+++

# Xunlock: unlock factors, slot-key derivation and unlock policy

This spec is not upstream behaviour. It specifies the parts of [ADR 0011](../../docs/explanation/adr/0011-key-custody-and-unlock.md) decisions 3, 4, 6, 8 and 9 that do not touch the store file: the factor port, the adapter that drives the libfido2 command-line tools, the slot-key and sub-key derivations, and the policy check of a slot table. The slot table on disk, the store format version, the cold-role sub-key use, rotation and the Vault and KMS clients are not in this spec.

Terms: a **factor** is a secret a person holds or a device reproduces; a **factor output** is its 32 bytes. A **factor id** names a factor inside a slot (for FIDO2, `ports.FactorIDOf` of the credential id). A **slot** wraps the master key under a key derived from factor outputs. A **table** is the slots of a workspace with its policy (`standard`, `hardware`, `strict`). The **libfido2 tools** are `fido2-token`, `fido2-cred` and `fido2-assert`, pinned in the toolchain manifest; the behaviour below is read from their man pages and source at libfido2 1.16.0 (the version the flake pins; 1.17.0 was read as well) and has not been run against a device.

## Interface

- **SPO-Xunlock-IF-001** `ports.FactorSource` has `Profile`, `Enrol` and `Assert`. `Enrol` takes a relying-party id, an optional device and an optional PIN (user verification is always required), and returns the credential id, the credProtect level the authenticator confirmed, the `getInfo` version strings, the factor id and the result of the touch probe. `Assert` takes a credential id, a relying-party id, a current 32-byte salt, an optional next 32-byte salt, a presence flag and an optional device and PIN (user verification is always required and cannot be switched off), and returns the output for each salt together with the UP and UV flags.
- **SPO-Xunlock-IF-002** A source reports a `FactorProfile` read from the device (for the libfido2 tools, `fido2-token -I`: the extension, version and option lines): hmac-secret, two salts, credProtect, CTAP 2.1, a PIN set, built-in verification. `Enrol` and `Assert` check it with `ports.CheckFactorProfile` before `fido2-cred` or `fido2-assert` runs. `ports.CheckFactorProfile` names every capability an operation needs that the profile lacks, and the caller runs it before it asks for a PIN or a touch.
- **SPO-Xunlock-IF-003** The adapter `adapters/fido2cli` runs `fido2-token -L` (device choice), `fido2-token -I` (getInfo), `fido2-cred -M` (enrolment) and `fido2-assert -G` (assertion) through `platform/execx`, from the paths of the toolchain manifest. With no device given it uses the one device `fido2-token -L` lists and refuses none or several.
- **SPO-Xunlock-IF-004** The unlock policies are `standard`, `hardware` and `strict`; any other value is refused.
- **SPO-Xunlock-IF-005** `unlock.Check` checks a whole slot table against its policy and returns every violated rule, each with a rule code and the slot it concerns. It is the one check that slot add, policy change, rekey and the opener use.

## Inputs

- **SPO-Xunlock-IN-001** A salt is 32 bytes. An assertion with a next salt sends both to the authenticator as one 64-byte value (the current salt first), which libfido2 passes as the two salts of the hmac-secret extension, and splits the 64-byte answer into the output for the current salt and the output for the next. An assertion with one salt sends 32 bytes and gets 32.
- **SPO-Xunlock-IN-002** The factor id of a FIDO2 credential is SHA-256 over the label `spo/factor-id/fido2-credential`, a zero byte and the credential id: 32 bytes, the same wherever the credential id is known.
- **SPO-Xunlock-IN-003** The inputs of a slot key are factor outputs of exactly 32 bytes each, given in the canonical order: ascending by factor kind code (passphrase 1, recovery 2, fido2 3, backend 4), then by factor id bytes, with no repeat. Another length, another order or a repeated factor is refused.

## Outputs

- **SPO-Xunlock-OUT-001** The key of a `fido2-hmac` or `composite` slot is HKDF-SHA-256 (RFC 5869) with IKM the concatenation, in order, of `uint32_be(len) || output`; salt the 16-byte genesis nonce; info the canonical CBOR of `["spo/slot-key", format version, slot id, slot kind, [[factor kind, factor id], ...]]`. A `fido2-hmac` slot is the one-factor case. The derivation matches fixed vectors computed in Python by a second implementation.
- **SPO-Xunlock-OUT-002** The associated data of such a slot is the canonical CBOR of `["spo/slot-ad", format version, genesis nonce, slot id, slot kind, [[factor kind, factor id, params], ...], hash of the recovery public key, commitment]`, where the params are the Argon2id parameters and salt of a passphrase factor, the credential id, relying-party id and hmac-secret salt of a FIDO2 factor, and the key reference of a backend factor. The commitment is the HMAC-SHA-256 of the slot key over the slot-commit label, as for the older kinds, and is compared before the AEAD. A change of any bound value makes the slot fail to open.
- **SPO-Xunlock-OUT-003** The cold-role sub-key is HKDF-SHA-256 with IKM one 32-byte factor output, salt the genesis nonce, info `uint32_be(format version) || "cold-subkey" || len(identity) as one byte || identity`, where the record identity is 28 or 32 bytes. It matches a fixed vector computed in Python.
- **SPO-Xunlock-OUT-004** `Enrol` returns the credential id read from `fido2-cred -M`, the credProtect level read from the extension map of its authenticator data, the version strings read from `fido2-token -I`, `ports.FactorIDOf` of the credential id, and the touch-probe result.
- **SPO-Xunlock-OUT-006** The touch probe records "touch not enforced" for an answer that returns an output, whatever its flags; "touch enforced" only for a named refusal of the request (`FIDO_ERR_UP_REQUIRED`, `FIDO_ERR_OPERATION_DENIED`); a PIN error or a missing device ends the enrolment; any other failure (a deadline, a usage error, malformed output) records "touch enforcement not confirmed", which a listing shows as not confirmed enforced. Without a PIN the probe does not run.
- **SPO-Xunlock-OUT-007** The cold-role sub-key under a Vault or KMS composite is HKDF-SHA-256 with IKM the ordered factor outputs each as `uint32_be(len) || output`, salt the genesis nonce and the info of OUT-003, the factors in canonical order and distinct; it matches a fixed vector computed in Python.
- **SPO-Xunlock-OUT-005** `Assert` returns the UP and UV flags read from the authenticator data of the assertion, not the flags asked for.

## External tools

- **SPO-Xunlock-EXT-001** Enrolment runs `fido2-cred -M -h -c 3 [-v -q] -i /dev/fd/N <device> es256`: hmac-secret and credProtect 3 requested, the parameters (client data hash, relying-party id, user name, user id) on a pipe, and the answer on standard output (a credential id and authenticator data hold no secret). The verification path follows `getInfo`: with a PIN, no `-v` is passed, because with `-v` the tool asks for built-in verification first and prompts for a PIN only when the authenticator answers PIN_REQUIRED, which a PIN-only authenticator does not do for a request carrying uv=true; the PIN is on the tool's standard input. An authenticator with built-in verification and no PIN is enrolled with `-v -q`. A PIN-only authenticator with no PIN given is refused unless the tool may prompt on the terminal.
- **SPO-Xunlock-EXT-002** An assertion runs `fido2-assert -G -h [-p] <verify> -i /dev/fd/N -o /dev/fd/M <device>`: the parameters (client data hash, relying-party id, credential id, salt) on a pipe, the answer (client data hash, relying-party id, authenticator data, signature, hmac secret, one base64 line each) on a pipe read into guarded memory. `-p` asks for user presence. `<verify>` is always present: `-v` with a PIN on standard input, or `-t uv=true -t pin=false` for built-in verification, or `-v` with the tool's own terminal prompt.
- **SPO-Xunlock-EXT-003** `fido2-token -I <device>` is read for the lines `version strings:` and `extension strings:`.
- **SPO-Xunlock-EXT-004** The touch probe is an assertion with `-t up=false -v` and the PIN on standard input. It runs only when a PIN was given.
- **SPO-Xunlock-EXT-005** The authenticator data the tools print is a CBOR byte string around the raw data: 32 bytes of relying-party hash, a flags byte (bit 0 UP, bit 2 UV, bit 6 attested credential data, bit 7 extension data), a 4-byte counter, then for an enrolment the attested credential data and an extension map. The adapter decodes it strictly and refuses any other shape.

## Refusals

- **SPO-Xunlock-PRE-001** Enrolment refuses an authenticator whose makeCredential output does not confirm credProtect 3, whatever versions it reports.
- **SPO-Xunlock-PRE-002** Enrolment refuses an authenticator whose `getInfo` versions list neither `FIDO_2_1` nor `FIDO_2_1_PRE`, or whose extensions lack `hmac-secret`, or whose credential does not report hmac-secret.
- **SPO-Xunlock-PRE-003** An assertion without the UV flag when verification is required, or without the UP flag when presence is required, is refused by `Assertion.Require`, which destroys the outputs. The adapter applies it before it returns.
- **SPO-Xunlock-PRE-004** An answer with no hmac-secret line, with an output of the wrong length, with two equal outputs for two different salts, or with authenticator data that does not decode is refused as malformed.
- **SPO-Xunlock-PRE-005** An assertion for a credential the authenticator does not hold is `ErrFactorNoCredential`; an expired touch is `ErrFactorTimeout`; a wrong PIN is `ErrFactorPIN`; a blocked PIN is `ErrFactorPINBlocked`; none of them carries the tool's output.
- **SPO-Xunlock-PRE-006** `Check` refuses an empty table, an unknown policy, a slot with no id, a repeated slot id and a slot whose factors do not fit its kind.
- **SPO-Xunlock-PRE-007** `Check` refuses a `standard` table without a passphrase slot or without a recovery slot.
- **SPO-Xunlock-PRE-008** `Check` refuses, under `hardware` and `strict`, a slot that a passphrase alone opens.
- **SPO-Xunlock-PRE-009** `Check` refuses, under `hardware` and `strict`, a slot that the recovery key alone opens.
- **SPO-Xunlock-PRE-010** `Check` refuses, under `hardware`, a recovery composite that is not the recovery key and a hardware factor, or whose hardware factor also has a standalone slot (by factor id).
- **SPO-Xunlock-PRE-011** `Check` refuses a Vault or KMS factor in a slot with no other factor, in every policy, and under `hardware` and `strict` a slot with such a factor and no FIDO2 factor.
- **SPO-Xunlock-PRE-012** `Check` refuses a composite slot with a factor that is also a standalone slot, matched by factor id for recovery, FIDO2 and backend factors. Passphrases are not compared.
- **SPO-Xunlock-PRE-013** `Check` refuses a recovery slot under `strict`.
- **SPO-Xunlock-PRE-014** `Check` refuses a table whose slots bind different recovery public key hashes.
- **SPO-Xunlock-PRE-015** `Check` refuses, under `hardware` and `strict`, a slot that has no FIDO2 factor.
- **SPO-Xunlock-PRE-017** Enrolment refuses a credential whose authenticator data has the UV flag clear, an authenticator that can neither verify with a PIN nor with built-in verification, a PIN given to an authenticator with none set, and no PIN where one is needed and the tool may not prompt; each before `fido2-cred` runs where `getInfo` shows it.
- **SPO-Xunlock-PRE-018** `Check` refuses a `hardware` table with no recovery composite (a table with no recovery path is `strict`).
- **SPO-Xunlock-PRE-019** `Check` refuses a `hardware` recovery composite whose FIDO2 credential also appears in any other slot, standalone or inside another composite.
- **SPO-Xunlock-PRE-020** `Check` refuses a table with more than one distinct recovery factor.
- **SPO-Xunlock-PRE-021** `Check` refuses a slot with no recovery public key hash under `standard` and `hardware`, and a slot with one under `strict`, whose slots bind none.
- **SPO-Xunlock-PRE-016** `Derive` and the slot functions refuse a slot with the wrong factor count for its kind, a salt or credential of the wrong size, and parameters of another factor kind.

## Invariants

- **SPO-Xunlock-INV-001** A slot key changes with the order of its factors, a factor id, the slot id, the slot kind, the genesis nonce, the format version and any factor output. Two factor outputs cannot be shifted into one another.
- **SPO-Xunlock-INV-002** The `passphrase` and `recovery` slot derivations are unchanged: the committed vectors of the seal package still pass.
- **SPO-Xunlock-INV-003** A refused assertion holds no secret afterwards, and a source that cannot do what an operation needs is refused by `CheckFactorProfile` before any prompt.

## Security

- **SPO-Xunlock-SEC-001** No factor output, PIN or salt-derived secret is in an argument vector, in the environment, in a file or in a log line. A PIN reaches the tools on standard input through a pipe; the outputs come back through a pipe into guarded memory; the parameters go through a pipe.
- **SPO-Xunlock-SEC-002** A tool that is given a PIN on standard input is started without a controlling terminal, because libfido2's PIN prompt reads `/dev/tty` first. Without a PIN, the tool prompts on the terminal itself and the process never sees the PIN.
- **SPO-Xunlock-SEC-003** The error of a failed tool call carries a typed reason and the exit status, never the tool's output.
- **SPO-Xunlock-SEC-005** What a tool writes back is bounded: the captured standard output and standard error of a call, and each secret pipe, have a maximum (64 KiB and 8 KiB for the libfido2 calls; 128 MiB and 16 MiB by default for any other tool), and a tool that exceeds it is stopped and the call fails.
- **SPO-Xunlock-SEC-004** An authenticator that returns an output to an assertion with user presence off is recorded as "touch not enforced" in the enrolment; the touch requirement of the cold-role sub-key is then a stated residual risk, not a guarantee.
