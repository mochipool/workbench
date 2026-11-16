+++
id = "15"
kind = "script"
title = "Calidus pool key: generate, register, query, sign"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["pool-operations", "key-custody", "chain-access"]
use_cases = ["GenerateCalidusKey", "BuildCalidusRegistration", "QueryCalidusKeys", "SignWithCalidusKey"]
depends_on = ["Cui", "Ckey", "Chw", "Cchain", "Cconv", "Cconf", "Pfiles"]

upstream_path = "cardano/mainnet/15_calidusPoolKey.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "7f72c6f23123843e0e492ecc94dfc5a915547010783e0f11820b18d69a42d769"
upstream_lines = 703
uses_common = [
  "ask",
  "checkError",
  "exists",
  "file_lock",
  "get_currentTip",
  "majorError",
  "read_skeyFILE",
  "showProcessAnimation",
  "start_HwWallet",
  "stopProcessAnimation",
  "to_cbor",
  "trimString",
  "versionCheck",
]
cli_commands = []
hwcli_commands = [
  "address key-gen",
  "message sign",
]
signer_commands = [
  "keygen",
  "sign",
  "verify",
]
http_endpoints = [
  "koiosAPI",
  "koiosAPI/pool_calidus_keys",
]
env_vars = []
+++

# 15_calidusPoolKey: Calidus pool key: generate, register, query, sign

Manages the Calidus pool key of CIP-151, a hot key an SPO can use to sign messages on behalf of the pool without touching the cold key, and its on-chain registration as CIP-88 version 2 transaction metadata (label 867). Four sub-commands: `new` generates a Calidus key pair (from a mnemonic, with `cardano-signer`); `genmeta` builds and signs the registration metadata with the pool's cold key (software key through `cardano-signer`, hardware key through `cardano-hw-cli` and a hand-built CBOR payload), ready to be attached to a transaction by `01_sendLovelaces`; `query` looks Calidus keys up at Koios; `sign` signs a text with the Calidus key. The script submits nothing itself. `cardano-signer` is a required external tool, at least the version in `minCardanoSignerVersion` (1.35.0).

## Interface

- **SPO-15-IF-001** The first argument selects the sub-command, case-insensitively: `new`, `genmeta`, `query`, `sign`. Any other value, or none, prints usage to stderr and exits 1. (src: L21-L57, L68, L700-L701)
- **SPO-15-IF-002** `new cli|hw <name> ["<24 words>"]`: at least three arguments, else usage and exit 1; the name has a leading `./` stripped. The optional fourth argument (cli only) is a mnemonic of exactly 24 words. (src: L73-L77, L103, L107-L112)
- **SPO-15-IF-003** `genmeta <calidus name> <pool name> [nonce]`: at least three arguments, else usage and exit 1. Both names are normalised: the calidus argument loses a `.vkey` and then a `.calidus` suffix, the pool argument loses `.skey` or `.hwsfile` and then `.node`, and a leading `./` is dropped. (src: L207, L210, L214)
- **SPO-15-IF-004** The `genmeta` nonce is honoured only when exactly four arguments are given; it must be digits only and above zero, else exit 1. Further arguments are ignored. (src: L218-L221)
- **SPO-15-IF-005** `query <subject>`: exactly two arguments, else usage and exit 1. The subject is classified in this order, the first match wins: (1) a string of 61 characters starting `calidus1`, valid bech32 whose first data byte is `a1`; (2) an existing `<s>.calidus.id` file, with the same validation of its content; (3) 64 hex digits, a Calidus public key; (4) an existing `<s>.calidus.vkey` file, public key = its `cborHex` without the first four hex digits; (5) 56 characters starting `pool1`, valid bech32; (6) an existing `<s>.pool.id` file holding 56 hex digits; (7) an existing `<s>.node.vkey` file, pool id = blake2b-224 of its key bytes; (8) the word `all` (case-insensitive); (9) anything else exits 1. An invalid form exits 1. (src: L460-L548)
- **SPO-15-IF-006** `sign <calidus name> "<text>"`: exactly three arguments, else usage and exit 1. The calidus name is normalised like SPO-15-IF-003 and `<name>.calidus.skey` must exist, else exit 1. A hardware Calidus key (`.hwsfile`) is not accepted. (src: L643-L647)

## Inputs

- **SPO-15-IN-001** `cardano-signer` is located from `cardanosigner`; when that is not resolvable and `<scriptDir>/cardano-signer` exists it is used. Neither: exit 1. The `--version` call must succeed (else exit 1) and its second word must be at least `minCardanoSignerVersion` (else exit 1, SPO-Cconf-OUT-003). This runs in `new` (before the method is examined), `genmeta` and `sign`; not in `query`. (src: L89-L98, L232-L241, L656-L665)
- **SPO-15-IN-002** `genmeta` reads `<calidus>.calidus.vkey`; the pool's `<pool>.node.skey` or `<pool>.node.hwsfile`; and, for a hardware pool key, one of `<pool>.pool.id-bech`, `<pool>.pool.id`, `<pool>.node.vkey`. (src: L211, L215, L250-L282)

## Behaviour: `new`

1. **Refuse to overwrite.**
   - **SPO-15-PRE-001** Exits 1 when `<name>.calidus.vkey`, `<name>.calidus.skey` or `<name>.calidus.hwsfile` exists. (src: L79-L81)
2. **Generate (`cli`).**
   - **SPO-15-EXT-001** With a mnemonic given: lower-cases and trims it, exits 1 unless it has exactly 24 words, and runs `cardano-signer keygen --path calidus --mnemonics "<mnemonic>" --json-extended --out-skey <name>.calidus.skey --out-vkey <name>.calidus.vkey`. (src: L107-L118)
   - **SPO-15-EXT-002** Without a mnemonic: runs the same command without `--mnemonics`; `cardano-signer` generates a new 24-word mnemonic, which is read from the JSON field `mnemonics`. (src: L121-L124)
   - **SPO-15-OUT-001** Locks the `.skey` and `.vkey`; writes the mnemonic (one line) to `<name>.calidus.mnemonics` and locks it; writes the JSON field `calidusIdBech` to `<name>.calidus.id` and locks it. A write failure ends the script (SPO-Cui-INV-001). (src: L129, L134, L140-L142, L148-L151)
   - **SPO-15-INV-001** The Calidus key pair is derived by `cardano-signer`'s own `calidus` path alias; the path the script prints, `1852H/1815H/0H/0/0`, is display only and does not select the derivation. See Open questions. (src: L66, L85, L117, L121)
3. **Hardware (`hw`).**
   - **SPO-15-PRE-002** `hw` is suspended: after the checks of SPO-15-IN-001 and SPO-15-PRE-001 it prints that deriving the key from a hardware wallet is suspended until a dedicated derivation path exists, prints usage and exits 1. The code below it (a `cardano-hw-cli address key-gen --path 1852H/1815H/0H/0/0` flow with description rewrites) is unreachable. (src: L160-L191)
   - **SPO-15-PRE-003** A method other than `cli`/`hw` exits 1 with usage. (src: L193-L195)

## Behaviour: `genmeta`

1. **Checks.**
   - **SPO-15-PRE-004** Exits 1 when `<calidus>.calidus.vkey` does not exist, or when neither `<pool>.node.skey` nor `<pool>.node.hwsfile` exists. (src: L211, L215)
   - **SPO-15-PRE-005** Exits 1 when the output file `<dir of pool argument>/<pool>_<yymmddHHMMSS>.calidus-registration.json` (local time) already exists. (src: L224-L226)
   - **SPO-15-INV-002** A hardware cold key takes precedence: when `<pool>.node.hwsfile` exists the hardware flow is used, even if a `.node.skey` also exists (the opposite order to SPO-04d-INV-004). (src: L246, L405)
2. **Software cold key.**
   - **SPO-15-EXT-003** Reads the cold signing key with `read_skeyFILE` (SPO-Ckey-PR-001; failure exits 1) and runs `cardano-signer sign --cip88 --calidus-public-key <name>.calidus.vkey --secret-key <process substitution of the key> [--nonce <n>] --json-extended`. Without a nonce `cardano-signer` chooses one. A failing signer prints its output and exits **0** (`echo ...; exit $?` at L419, the status of the `echo`). (src: L411-L420)
   - **SPO-15-OUT-002** Reads `poolIdBech`, `poolIdHex`, `calidusPublicKey`, `calidusIdBech`, `nonce` and `output.json` from the signer's JSON and writes the pretty-printed `output.json` to the registration file. A failed write prints the error and exits **0** (the same `echo ...; exit $?` form, L435); a missing file after it ends with a message. (src: L423-L445)
3. **Hardware cold key.**
   - **SPO-15-INV-003** Pool id resolution, first match wins: (1) `<pool>.pool.id-bech`, 56 characters starting `pool1` and valid bech32, hex derived by `bech32`; (2) `<pool>.pool.id`, 56 hex digits, bech32 derived; (3) `<pool>.node.vkey`, id = blake2b-224 of its key bytes (the `cborHex` without its first four hex digits), then bech32; none present exits 1. (src: L250-L299)
   - **SPO-15-INV-004** The Calidus public key is the `cborHex` of `<calidus>.calidus.vkey` without its first four hex digits. The Calidus id is `a1` followed by blake2b-224 of the public key, in bech32 with human-readable part `calidus`; a malformed result exits 1. (src: L304-L320)
   - **SPO-15-MODE-001** The nonce is the given value, else the current tip slot from `get_currentTip` in the active work mode (online: `cardano-cli`; light: Koios; offline: local clock, SPO-Cchain-OUT-003). This is the only chain dependence of `genmeta`. (src: L323)
   - **SPO-15-INV-005** The payload is CBOR (SPO-Cconv-OUT-001 to SPO-Cconv-OUT-004): map of 5 entries `{1: [1, <pool id bytes>], 2: [], 3: [2], 4: <nonce>, 7: <calidus public key bytes>}`. (src: L333-L347)
   - **SPO-15-INV-006** The message to sign is blake2b-256 of the payload CBOR; its blake2b-224 is shown as the hash the hardware wallet displays. (src: L350-L353)
   - **SPO-15-PR-001** Asks "Signing message via Pool-Cold-Key on the Hardware-Wallet, continue?" with default Yes; No exits 2. (src: L360)
   - **SPO-15-EXT-004** Opens a session restricted to Ledger or Keystone (`start_HwWallet "Ledger|Keystone"`, SPO-Chw-IF-001) and runs `cardano-hw-cli message sign --message-hex <message> --signing-path-hwsfile <pool>.node.hwsfile --out-file <tempDir>/<calidus name>.signedMessage`; output containing `ERROR` or `DISCONNECT` exits 1. The signed-message file stays in the temp directory. (src: L363-L368)
   - **SPO-15-EXT-005** Reads `COSE_Key_hex` and `COSE_Sign1_hex` from the signed-message file and runs `cardano-signer verify --cip8 --cose-key <..> --cose-sign1 <..> --json-extended --include-maps`. A verify failure, or a result other than `true`, prints a message and exits with the status of the preceding `echo`, which is 0 (see the quirk below). (src: L371-L381)
   - **SPO-15-OUT-003** Writes the registration metadata: label `867` with `{"0": 2, "1": <payload JSON>, "2": [ {"1": <COSE_Key map>, "2": <COSE_Sign1 map>} ]}`, where the payload JSON is `{"1":[1,"0x<pool hex>"],"2":[],"3":[2],"4":<nonce>,"7":"0x<calidus public key>"}` and every `{"hashed":false}` / `{"hashed":true}` in the COSE_Sign1 map is replaced by `0` / `1`. The file has the default mode, is not locked, and is checked for existence afterwards. (src: L383-L402)
4. **Both.**
   - **SPO-15-OUT-004** The script prints the instruction to submit the file as transaction metadata with `01_sendLovelaces.sh <wallet> <wallet> min <file>`; it submits nothing and does not touch any key file. (src: L398, L441)

> **Upstream quirk:** in `genmeta` and `sign` the failure handlers have the form `if [ $? -ne 0 ]; then echo ...; exit $?; fi`. Inside the `then` block `$?` is the status of the `echo`, so these exits are **0**. Affected: SPO-15-EXT-005, the `sign` failure of SPO-15-EXT-006, and the failures at L419 and L435 (signer or write failure in the software flow). A caller cannot rely on the exit status for these.

## Behaviour: `query`

- **SPO-15-PRE-006** Exits 1 in offline mode, before the arguments are examined. (src: L457)
- **SPO-15-EXT-007** Sends `GET <koiosAPI>/pool_calidus_keys?pool_status=eq.registered&order=block_time.asc<filter>` with the `authorization` header, `Accept: application/json`, `-L`, 30-second timeout, retried up to 5 times on a curl failure, with the HTTP status carried as in SPO-Clight-INV-003. The filter is `&calidus_pub_key=eq.<hex>`, `&calidus_id_bech32=eq.<bech>` or `&pool_id_bech32=eq.<bech>` according to the subject (public key, Calidus id, pool id); `all` adds none. (src: L552-L572)
- **SPO-15-PRE-007** Exits 1 when the five attempts fail, when the status is not 200, when the body is not JSON, or when the array is empty ("no entries found"). Finding no entry is an error status. (src: L572-L593)
- **SPO-15-OUT-005** For each entry prints the date (`block_time`), `pool_id_bech32`, `calidus_id_bech32`, `calidus_pub_key`, `calidus_nonce`, `epoch_no` and `tx_hash` (missing values as `-`), oldest first; with more than one entry prints the number of unique Calidus ids. Exit 0. (src: L609-L635)
- **SPO-15-INV-007** Only registered pools are listed (`pool_status=eq.registered`); a retired pool's key is not returned. (src: L567)

## Behaviour: `sign`

- **SPO-15-EXT-006** Reads the Calidus signing key with `read_skeyFILE` (failure exits 1) and runs `cardano-signer sign --data-text "<text>" --secret-key <process substitution of the key> --json-extended`; a failure prints a message and exits 0 (the quirk above). (src: L668-L673)
- **SPO-15-OUT-006** Takes `signature` and `publicKey` from the signer's JSON; exits 1 unless the signature is a non-empty hex string. Prints the Calidus id (derived as in SPO-15-INV-004), the public key and the signature on stdout. Nothing is written to a file. The signature is a plain ed25519 signature over the text, not a CIP-8 message. (src: L677-L694)

## Work modes

- **SPO-15-MODE-002** `new`, `sign` and `genmeta` with a software key are mode-independent: no chain access. `genmeta` with a hardware cold key needs the tip only when no nonce is given (SPO-15-MODE-001). `query` needs online or light mode (SPO-15-PRE-006) and uses Koios in both. In full online mode `koiosAuthorizationHeader` may be empty (SPO-Cconf-MODE-004). (src: L323, L457, L567)

## Prompts

| Prompt | Default | Effect |
| --- | --- | --- |
| Hardware signing confirmation (SPO-15-PR-001) | Yes | No exits 2 |
| Decryption password for an `enc` cold key or Calidus key | none | See SPO-Ckey-PR-001 |

## Outputs

**Upstream file contract:**

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<name>.calidus.skey` | `cardano-signer` JSON-extended text envelope, plaintext | `0400` | created (`new cli`) |
| `<name>.calidus.vkey` | verification key envelope | `0400` | created |
| `<name>.calidus.mnemonics` | 24 words, one line, plaintext | `0400` | created |
| `<name>.calidus.id` | bech32 Calidus id (`calidus1...`) | `0400` | created |
| `<dir>/<pool>_<yymmddHHMMSS>.calidus-registration.json` | CIP-88 v2 metadata (label 867), pretty-printed JSON | default (`0644`) | created (`genmeta`) |
| `<tempDir>/<calidus>.signedMessage` | `cardano-hw-cli` COSE output, public | default | created (hardware `genmeta`) |

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Unknown sub-command or too few arguments | 1 | SPO-15-IF-001 to SPO-15-IF-006 |
| `cardano-signer` missing, not working or too old | 1 | SPO-15-IN-001 |
| Calidus key file exists (`new`) | 1 | SPO-15-PRE-001 |
| Mnemonic not 24 words | 1 | SPO-15-EXT-001 |
| `new hw` | 1 | SPO-15-PRE-002 |
| Key or pool files missing, output file exists, bad nonce (`genmeta`) | 1 | SPO-15-PRE-004, SPO-15-PRE-005, SPO-15-IF-004 |
| Pool id or Calidus id cannot be resolved (hardware `genmeta`) | 1 | SPO-15-INV-003, SPO-15-INV-004 |
| Hardware signing declined | 2 | SPO-15-PR-001 |
| Hardware tool error | 1 | SPO-15-EXT-004 |
| Signature verify or signer failure; registration file not written | 0 (quirk) | SPO-15-EXT-003, SPO-15-OUT-002, SPO-15-EXT-005, SPO-15-EXT-006 |
| `query` in offline mode, no entries, HTTP or transport failure | 1 | SPO-15-PRE-006, SPO-15-PRE-007 |
| `sign` without a valid signature | 1 | SPO-15-OUT-006 |

## Security

- **SPO-15-SEC-001** `new cli` prints the Calidus signing key file, the mnemonic and the id to stdout. The key and the mnemonic are secrets; a caller must never capture, log or tee the output. (src: L115, L124, L130-L131, L143-L144)
- **SPO-15-SEC-002** The mnemonic is passed to `cardano-signer` on its command line, and a supplied mnemonic is also visible in the caller's shell history and process list. (src: L108, L117)
- **SPO-15-SEC-003** The Calidus key and the mnemonic file are plaintext at rest (mode `0400`); there is no `enc` option for them. `genmeta` and `sign` can decrypt an encrypted key if one is placed there. (src: L129, L140-L142, L414, L668)
- **SPO-15-SEC-004** `genmeta` with a software cold key decrypts the **pool cold signing key** on the machine that runs it; it is held in memory and a process substitution, and unset after use. (src: L414-L420)

## Domain mapping

Use cases: `GenerateCalidusKey(name, mnemonic?)`, `BuildCalidusRegistration(calidusKey, pool, nonce?)`, `QueryCalidusKeys(subject)`, `SignWithCalidusKey(calidusKey, text)`; aggregate `StakePool` (its `CalidusKey`) and, for registration, the metadata handed to the shared pipeline of `01_sendLovelaces`.

| Port | Operation | Purpose |
| --- | --- | --- |
| `KeyGen` | `generate(Calidus, mnemonic?)` | cardano-signer `keygen --path calidus`; returns mnemonic and id |
| `Vault` | `seal(calidusSigningKey)`, `seal(mnemonic)` | Plaintext upstream |
| `Store` | `put(CalidusKey, CalidusId, Mnemonics, CalidusRegistration)`, `exists`, `lock` | Artefacts |
| `Signer` | `signCip88(coldKeyRef, calidusPub, nonce?)` *(new)* | Software cold key: cardano-signer `sign --cip88` |
| `Signer` | `signMessage(payload, keyRef)` | Hardware cold key: `message sign` (CIP-8) |
| `Signer` | `verifyCip8(coseKey, coseSign1)` *(new)* | Check the hardware signature |
| `Signer` | `signText(text, keyRef)` | `sign` command |
| `Ledger` | `encodeCbor(value)` *(new)* | Payload CBOR (see SPO-Cconv-OUT-001 to -004); `poolId`, `calidusId(pubKey)` *(new)* |
| `ChainQuery` | `tip()`, `calidusKeys(filter)` *(new)* | Nonce default; Koios lookup |
| `UI` | `confirm`, `askPassword`, `show` | Prompts |

## Port notes

* Return a typed `CalidusRegistration` and attach it directly to the transaction builder instead of a file named by the clock and the pool argument.
* Seal the Calidus key and the mnemonic by default; show the mnemonic once at creation, never write it as a plaintext file.
* Make verify failures and signer failures fail the use case (the exit-0 quirk).
* Make `genmeta` with a hardware cold key and with a software cold key share one payload definition (SPO-15-INV-005) and test that the signer's `output.json` and the hand-built JSON agree.
* The registration is a signing request whose inputs are public (pool id, Calidus public key, nonce), which suits remote or multi-party cold-key signing.
* `query` should treat "no entries" as an empty result, not an error status.

## Open questions

* The derivation path of `cardano-signer keygen --path calidus` is not in the script (the printed `1852H/1815H/0H/0/0` is not what is used, and the disabled hardware flow used the same path). Settle with `cardano-signer keygen --path calidus` on a fixed mnemonic and compare with the CIP-151 path.
* The nonce that `cardano-signer sign --cip88` picks when none is given is not visible here. Settle with its documentation or by running it.
* The exact text-envelope `type`/`description` of the Calidus files is produced by `cardano-signer --json-extended` and is not in the script.
* Whether `pool_calidus_keys` returns only the latest registration per pool is not visible; the script lists every returned entry and the unique-key count suggests several may exist.
* Behaviour of `query` in full online mode when `koiosAPI` or the authorization header is empty is not specified by the script.

## Observations (2026-11-16, cardano-signer 1.35.0)

Recorded from the pinned tool and compared byte for byte by `spo/test/parity/cip_oracle_test.go` and `cip_scripts_test.go`. Ids are unchanged.

* **Calidus derivation (open question of INV-001 settled).** `keygen --path calidus` derives along `1852H/1815H/0H/0/0`, the printed path is the real one, not display only: for the public test phrase the Calidus verification key equals the payment key `0/0` (`63c5d695...2179`). The signing key is `PaymentExtendedSigningKeyShelley_ed25519_bip32` with description `Calidus Pool Signing Key`, the verification key `PaymentVerificationKeyShelley_ed25519` with `Calidus Pool Verification Key`; both files are indented by two spaces. Calidus id: `a1` plus blake2b-224 of the public key, bech32 prefix `calidus` (`calidus15yqt0pru382hy9vjlsxv3ye02z50sfvt8xunscg5pgden7czfjdjq` for that phrase). The `.id` file is the id and one newline.
* **Default nonce (open question settled).** Without `--nonce`, `sign --cip88` uses the mainnet slot of the machine clock whatever the network: `unix - 1596059091 + 4492800` (at Unix time 1794832332 it chose 203266041). A port without a tip reader does the same.
* **CIP-88 v2 layout.** Payload `{1: [1, pool_id(28)], 2: [], 3: [2], 4: nonce, 7: calidus_pub(32)}`; payload hash blake2b-256 of that CBOR; witness COSE_Sign1 `[ {1:-8, "address": pool_id(28)}, {"hashed": false}, payload_hash(32), signature ]`, the signature over `["Signature1", protected, h'', payload_hash]` (so `hashed` is false although the payload is a hash); COSE_Key of the cold public key `{1:1, 3:-8, -1:6, -2:pub}`; metadata `{867: {0: 2, 1: payload, 2: [{1: COSE_Key, 2: COSE_Sign1}]}}`. Inside the metadata the unprotected `{"hashed": false}` is the integer `0` (CBOR and JSON), as SPO-15-OUT-003 says for the hardware flow: the software flow writes the same. The header "address" is the pool id hash, not a Shelley address. A normal and an extended cold key both sign; `--secret-key` takes a file path, which a pipe serves.
* **Registration file (SPO-15-OUT-002).** The JSON is the compact `output.json` (keys in the order above) passed through `jq`: two-space indent, final newline. The file mode is the default `0644` and the name uses the local time, `<pool>_<yymmddHHMMSS>`.
* **genmeta without a chain.** With a software cold key it runs in offline mode and needs no tip; a given nonce of `0` or a non-number exits non-zero.
* **hw flow checked only by reading.** Not run: no hardware tool in the pinned toolchain.
