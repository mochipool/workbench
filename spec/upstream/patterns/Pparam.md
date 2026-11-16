+++
id = "Pparam"
kind = "pattern"
title = "The free-form extra-parameter grammar of transaction scripts"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["transaction-construction", "wallet", "native-assets"]
use_cases = ["ComposeTransactionMetadata", "SelectInputUtxos"]
depends_on = ["Cui", "Cutxo", "Cconv", "Ptx", "Pfiles"]
sources = [
  "01_sendLovelaces.sh",
  "01_sendAssets.sh",
  "01_claimRewards.sh",
  "03b_regStakingAddrCert.sh",
  "05c_regStakepoolCert.sh",
  "06_regDelegationCert.sh",
  "07b_deregStakepoolCert.sh",
  "08b_deregStakingAddrCert.sh",
  "11a_mintAsset.sh",
  "11b_burnAsset.sh",
  "21b_regDRepCert.sh",
  "21d_retDRepCert.sh",
  "22b_regVoteDelegCert.sh",
  "23c_regComAuthCert.sh",
  "23e_retComColdKeys.sh",
  "24b_regVote.sh",
  "25b_regAction.sh",
  "03a_genStakingPaymentAddr.sh",
  "21a_genDRepKeys.sh",
  "23a_genComColdKeys.sh",
  "23b_genComHotKeys.sh",
  "24a_genVote.sh",
  "25a_genAction.sh",
  "00_common.sh",
]
+++

# Pparam: the free-form extra-parameter grammar of transaction scripts

Every script that builds a transaction accepts, after its positional arguments, any number of *extra parameters*. They are not options in the `getopts` sense: each is one shell word, classified by what it looks like. A word of the form `key:value` (key case-insensitive, quoted so the shell keeps spaces) selects a behaviour; a word that looks like a file name is a metadata file; a word that looks like `txhash#index` restricts the inputs. Every script re-implements the same parsing loop, with a different set of accepted keys and a different start index. This pattern records the grammar once, token by token, and says which script accepts what. Per-script specs say "extra parameters follow SPO-Pparam-..., accepting tokens X, Y".

The tokens fall into four families: transaction metadata (`msg:`, `enc:`, `pass:`, metadata files), input selection (`utxolimit:`, `skiputxowithasset:`, `onlyutxowithasset:`, `txhash#index`), a few script-specific switches (`type:`, `keeppolicy:`, `url:`, `hash:`, `.vote`/`.action` files), and the key-derivation tokens of the key-generation scripts (`acc:`, `idx:`, `mnemonics:`).

## Classification of a word

- **SPO-Pparam-IF-001** The extra parameters of a transaction script are the words after its positional arguments, processed left to right. The start index differs per script: 3 positional words (`01_sendLovelaces`, `11a`, `11b`, `23c`), 2 (`01_claimRewards`, `03b`, `05c`, `06`, `07b`, `08b`, `21b`, `21d`, `22b`, `23e`, `24b`), 1 (`25b`). `01_sendAssets` starts at the 5th word, or at the 4th when the asset and amount were given together in one quoted word. (src: 01_sendLovelaces.sh:L79-L84, 06_regDelegationCert.sh:L77-L81, 25b_regAction.sh:L94-L96, 01_sendAssets.sh:L247-L249, 11a_mintAsset.sh:L85, 23c_regComAuthCert.sh:L91, 24b_regVote.sh:L164)
- **SPO-Pparam-IF-002** A keyed token is recognised by lower-casing the whole word and matching `^key:`. The value is the substring after the key and colon, taken from the original-case word. `MSG:Hi`, `Msg: Hi` and `msg:Hi` are the same token. (src: 01_sendLovelaces.sh:L108-L109, 01_sendLovelaces.sh:L126-L127, 01_sendLovelaces.sh:L157-L158)
- **SPO-Pparam-IF-003** Classification order, first match wins: (1) a *file word*; (2) a *UTxO list* (`txhash#index`); (3) `msg:`; (4) `utxolimit:`; (5) `skiputxowithasset:`; (6) `onlyutxowithasset:`; (7) `enc:`; (8) `pass:`. A script that does not implement a token omits it from the chain, see the acceptance table below. (src: 01_sendLovelaces.sh:L88-L164)
- **SPO-Pparam-IF-004** A word is a *file word* when it is none of the keys the script knows, is not a UTxO list, is not empty, and contains at least one non-digit character. Purely numeric words are never file words. (src: 01_sendLovelaces.sh:L88, 06_regDelegationCert.sh:L85, 11a_mintAsset.sh:L91)
- **SPO-Pparam-IF-005** A keyed word whose key the script does not know (a typo such as `mesage:` or a token meant for a sibling script such as `utxolimit:` given to `11a`) is classified as a file word. It then fails with the missing-file refusal of SPO-Pparam-PRE-005 and exits 1. (src: 11a_mintAsset.sh:L91-L105, 05c_regStakepoolCert.sh:L80-L94)
- **SPO-Pparam-IF-006** Purely numeric words are silently ignored by every script except `01_sendAssets`, where a numeric word in the optional zone is the amount of lovelaces to send along with the assets. (src: 01_sendLovelaces.sh:L88, 01_sendAssets.sh:L255-L256)
- **SPO-Pparam-IF-007** A word that matches a key the script knows only as "recognised but ignored" has no effect and raises no error. This applies to `utxolimit:`, `skiputxowithasset:`, `onlyutxowithasset:` and the UTxO list in `03b`, `06`, `07b`, `08b`, `21b`, `21d`, `22b`, `23c`, `23e`, `24b`, `25b`. (src: 03b_regStakingAddrCert.sh:L86, 06_regDelegationCert.sh:L85, 07b_deregStakepoolCert.sh:L108, 08b_deregStakingAddrCert.sh:L89, 21b_regDRepCert.sh:L96, 21d_retDRepCert.sh:L94, 22b_regVoteDelegCert.sh:L93, 23c_regComAuthCert.sh:L97, 23e_retComColdKeys.sh:L96, 24b_regVote.sh:L170, 25b_regAction.sh:L100)
- **SPO-Pparam-IF-030** In `01_claimRewards` a file word is first tried as the name of a payment address (`<word>.addr`, extension optional): if that file exists the word names the fee-payment address and is not treated as metadata. Only if it does not exist is it tried as a metadata file. (src: 01_claimRewards.sh:L94-L97)

**Acceptance table.** "E" = takes effect, "I" = recognised and ignored, "F" = not recognised (falls into the file word branch, SPO-Pparam-IF-005), "-" = not applicable. The right-hand columns give the script-specific tokens.

| Script | msg/enc/pass | metadata files | UTxO list | utxolimit / skiputxowithasset / onlyutxowithasset | `enc:` mode validated | Script-specific |
| --- | --- | --- | --- | --- | --- | --- |
| 01_sendLovelaces | E | E | E | E | no | |
| 01_sendAssets | E | E | E | E | no | `keeppolicy:`, numeric lovelaces word |
| 01_claimRewards | E | E | E | E | no | |
| 03b_regStakingAddrCert | E | E | I | I | yes | |
| 05c_regStakepoolCert | E | E | I | F | yes | `type:` |
| 06_regDelegationCert | E | E | I | I | yes | |
| 07b_deregStakepoolCert | E | E | I | I | yes | |
| 08b_deregStakingAddrCert | E | E | I | I | yes | |
| 11a_mintAsset | E | E | E | F | no | |
| 11b_burnAsset | E | E | E | F | no | |
| 21b_regDRepCert | E | E | I | I | yes | `url:`, `hash:` |
| 21d_retDRepCert | E | E | I | I | yes | |
| 22b_regVoteDelegCert | E | E | I | I | yes | |
| 23c_regComAuthCert | E | E | I | I | yes | |
| 23e_retComColdKeys | E | E | I | I | yes | `url:`, `hash:` |
| 24b_regVote | E | E | I | I | yes | `.vote` files |
| 25b_regAction | E | E | I | I | yes | `.action` files |

## Transaction message (CIP-20): `msg:`

- **SPO-Pparam-IF-008** `msg:<text>` adds transaction messages. The value is trimmed of leading and trailing blanks and then split at `|`; each piece is one message line. The pieces themselves are not trimmed. Several `msg:` words accumulate in order. (src: 01_sendLovelaces.sh:L108-L123, 06_regDelegationCert.sh:L102-L117, 11a_mintAsset.sh:L113-L128)
- **SPO-Pparam-OUT-001** Messages are collected as metadata label `674`: `{"674": {"msg": [line1, line2, ...]}}`. (src: 01_sendLovelaces.sh:L119, 06_regDelegationCert.sh:L113)
- **SPO-Pparam-PRE-001** A message line longer than 64 **bytes** (UTF-8 byte length, not character count) is refused with exit 1 before anything is built or queried. (src: 01_sendLovelaces.sh:L118, 01_sendLovelaces.sh:L121, 06_regDelegationCert.sh:L112, 06_regDelegationCert.sh:L115, 00_common.sh:L2697-L2699)
- **SPO-Pparam-PRE-002** A message line that the JSON builder cannot embed (for example one containing a double quote) is refused with exit 1. (src: 01_sendLovelaces.sh:L119-L120, 06_regDelegationCert.sh:L113-L114)
  > **Upstream quirk:** the line is spliced into a `jq` program by string interpolation, so any character with meaning to `jq` string syntax breaks or alters the message. A port encodes the line as a JSON string value instead.
- **SPO-Pparam-IF-009** `msg:` with an empty value, or with only blanks, adds no message line and therefore no metadata. An empty piece inside the value (`a||b`) adds an empty line. (src: 01_sendLovelaces.sh:L109-L123, 00_common.sh:L378-L381)
- **SPO-Pparam-OUT-002** When at least one message line exists, the metadata is written to `<tempDir>/<paymentName>.transactionMessage.json`, where `<paymentName>` is the basename of the paying address name (for `07b` the de-registration payer, for `23e` the retirement payer). It is appended to the metadata file list after all user metadata files, as `--metadata-json-file`. The file is overwritten by the next run with the same payment name and is never deleted. (src: 01_sendLovelaces.sh:L202-L220, 01_sendAssets.sh:L351-L372, 01_claimRewards.sh:L220-L241, 03b_regStakingAddrCert.sh:L134-L155, 05c_regStakepoolCert.sh:L135-L160, 06_regDelegationCert.sh:L133-L158, 07b_deregStakepoolCert.sh:L156-L181, 08b_deregStakingAddrCert.sh:L137-L159, 11a_mintAsset.sh:L144-L165, 11b_burnAsset.sh:L141-L162, 21b_regDRepCert.sh:L158-L179, 21d_retDRepCert.sh:L142-L163, 22b_regVoteDelegCert.sh:L141-L166, 23c_regComAuthCert.sh:L145-L170, 23e_retComColdKeys.sh:L158-L183, 24b_regVote.sh:L299-L320, 25b_regAction.sh:L409-L430)
- **SPO-Pparam-IF-010** Without `enc:basic`, the messages are sent as plain text lines. (src: 01_sendLovelaces.sh:L202-L220)

## Message encryption (CIP-83): `enc:` and `pass:`

- **SPO-Pparam-IF-011** `enc:<mode>` selects the message encryption mode. The value is trimmed and compared case-insensitively. Only `basic` is supported. (src: 01_sendLovelaces.sh:L157-L158, 01_sendLovelaces.sh:L208, 06_regDelegationCert.sh:L139)
- **SPO-Pparam-PRE-003** In `03b`, `05c`, `06`, `07b`, `08b`, `21b`, `21d`, `22b`, `23c`, `23e`, `24b`, `25b` an `enc:` mode other than `basic` (when messages exist and the value is non-empty) is refused with exit 1. (src: 06_regDelegationCert.sh:L153-L154, 03b_regStakingAddrCert.sh:L151-L152, 05c_regStakepoolCert.sh:L155-L156, 07b_deregStakepoolCert.sh:L176-L177, 08b_deregStakingAddrCert.sh:L154-L155, 21b_regDRepCert.sh:L175-L176, 21d_retDRepCert.sh:L159-L160, 22b_regVoteDelegCert.sh:L161-L162, 23c_regComAuthCert.sh:L165-L166, 23e_retComColdKeys.sh:L178-L179, 24b_regVote.sh:L316-L317, 25b_regAction.sh:L426-L427)
- **SPO-Pparam-INV-001** In `01_sendLovelaces`, `01_sendAssets`, `01_claimRewards`, `11a` and `11b` an unsupported `enc:` mode is not detected: the messages are sent in plain text although the operator asked for encryption. (src: 01_sendLovelaces.sh:L202-L220, 01_sendAssets.sh:L351-L372, 01_claimRewards.sh:L220-L241, 11a_mintAsset.sh:L144-L165, 11b_burnAsset.sh:L141-L162)
  > **Upstream quirk:** a typo such as `enc:basci` silently leaks the messages in clear. A port refuses any unsupported mode in every script.
- **SPO-Pparam-IF-012** `pass:<passphrase>` sets the encryption passphrase. The value is **not** trimmed (spaces are part of the passphrase). The default is `cardano`. It has no effect without `enc:basic` and at least one message. (src: 01_sendLovelaces.sh:L77, 01_sendLovelaces.sh:L161-L162, 06_regDelegationCert.sh:L124-L125)
- **SPO-Pparam-IF-013** `enc:` without any `msg:` has no effect and no error. (src: 01_sendLovelaces.sh:L202, 01_sendLovelaces.sh:L208)
- **SPO-Pparam-EXT-001** With `enc:basic`, the message list is serialised as compact JSON (`jq -crM '."674".msg'`), encrypted with `openssl enc -e -aes-256-cbc -pbkdf2 -iter 10000 -a -k <passphrase>` (the compact JSON is fed through a here-string, so it carries a trailing newline), and the base64 output is split on whitespace so that each base64 line becomes one message line. The metadata becomes `{"674": {"enc": "basic", "msg": [<base64 line>, ...]}}`; the plain lines are dropped. (src: 01_sendLovelaces.sh:L208-L218, 06_regDelegationCert.sh:L139-L151)
- **SPO-Pparam-PRE-004** `enc:basic` without `openssl` on the path is refused with exit 2. A failing `jq` or `openssl` call ends the script with that tool's exit code. (src: 01_sendLovelaces.sh:L210-L217, 06_regDelegationCert.sh:L141-L151)
- **SPO-Pparam-SEC-001** The passphrase is printed on the terminal in clear together with the original messages when encryption is used, and it is passed to `openssl` on the command line (visible in the process list). (src: 01_sendLovelaces.sh:L213, 01_sendLovelaces.sh:L415-L418, 06_regDelegationCert.sh:L147, 06_regDelegationCert.sh:L526-L529)

## Metadata files

- **SPO-Pparam-IF-014** A file word whose extension is `json` (case-insensitive) and which exists must parse as JSON; its first top-level key must consist only of digits and lie in 0..65535. Only the first key is checked. On success it is passed to `cardano-cli` as `--metadata-json-file`. (src: 01_sendLovelaces.sh:L90-L98, 06_regDelegationCert.sh:L87-L95, 25b_regAction.sh:L104-L110)
- **SPO-Pparam-IF-015** A file word whose extension is `cbor` (case-insensitive) and which exists is passed as `--metadata-cbor-file`, with no content check. (src: 01_sendLovelaces.sh:L99-L100, 06_regDelegationCert.sh:L96-L97)
- **SPO-Pparam-PRE-005** A file word that does not exist, or whose extension is neither `json` nor `cbor`, is refused with exit 1. An unparsable `.json` file or an out-of-range first key is refused with exit 1. (src: 01_sendLovelaces.sh:L93-L101, 06_regDelegationCert.sh:L90-L98)
- **SPO-Pparam-IF-016** Any number of metadata files may be given. All are passed to `cardano-cli` in command-line order, before the message file of SPO-Pparam-OUT-002. Merging, and the refusal of a duplicated label, is `cardano-cli`'s behaviour. (src: 01_sendLovelaces.sh:L98, 01_sendLovelaces.sh:L220)
  > **Observed 2026-11-16 (cardano-cli 11.2.3.0, `spo/test/parity/assets_oracle_test.go`):** `cardano-cli` does not refuse a duplicated label. It merges the files by label in ascending order and, when two sources carry the same label, keeps the first source's value and drops the second without a word (for two `.json` files, a `.json` and the message file of OUT-002 alike); inside one `.cbor` file the last occurrence of a label wins. A message and a user file with label 674 therefore lose the message silently. A port refuses a label given twice (`ErrDuplicateLabel`). The conversion rules of the no-schema JSON, as the tool applies them: an object key is an integer when it matches `[+-]?(0|[1-9][0-9]*)` (`-0` and `+5` are integers, `007` is text), bytes when it is `0x` and lower-case hex (`0xAb` is text), else text; a string value is bytes under the same `0x` rule; an object's entries are sorted by the CBOR bytes of the converted key and a repeated key keeps its first value; numbers must be integers (`1.0` and `2e2` are fine) within -(2^64-1)..2^64-1; `null`, booleans, text over 64 UTF-8 bytes and bytes over 64 are refused; a `.cbor` file must be one map from unsigned label to metadatum, with nothing after it, and its nested maps keep their order and duplicates. The detailed schema is a flag of the whole command (`--json-metadata-detailed-schema`) that these scripts never pass.
- **SPO-Pparam-OUT-003** The names of the user metadata files are shown in the summary before the confirmation (display only). The files are read in place, never copied or modified. (src: 01_sendLovelaces.sh:L410-L411)
- **SPO-Pparam-IF-017** `24b` additionally accepts `.vote` files and `25b` `.action` files in the file-word position (extension compared case-insensitively). They are read through `cardano-cli governance vote view` / `governance action view`, a failure to read them is refused with exit 1, and they are attached to the transaction. The content rules belong to the per-script specs. (src: 24b_regVote.sh:L185-L190, 25b_regAction.sh:L115-L120)
- **SPO-Pparam-IF-018** `05c` refuses any metadata (files or messages) once a witness collection has been opened for the pool: the metadata is fixed when the collection is created. (src: 05c_regStakepoolCert.sh:L316-L322)

## Input selection

These tokens apply to the wallet scripts of the acceptance table only.

- **SPO-Pparam-IF-019** A UTxO list word has the form `hash#index` repeated with `|` as separator (`[hex]+#[digits]`, one or more). A later UTxO list word replaces an earlier one. After the mode-specific gathering of SPO-Ptx-MODE-001 .. SPO-Ptx-MODE-003, the candidate set is reduced to those listed entries that exist; unknown entries are silently dropped. It applies in all three work modes. (src: 01_sendLovelaces.sh:L105, 01_sendLovelaces.sh:L288-L289, 00_common.sh:L1130-L1143, 11a_mintAsset.sh:L110, 11a_mintAsset.sh:L236)
- **SPO-Pparam-IF-020** `utxolimit:<n>` limits the number of input UTxOs. The value is trimmed; a value less than or equal to zero is refused with exit 1. It is applied in online and light mode by keeping the first n UTxO rows of the query text (after the skip/only filters); **in offline mode it is not applied**. (src: 01_sendLovelaces.sh:L126-L128, 01_sendLovelaces.sh:L265, 01_sendLovelaces.sh:L276, 01_sendLovelaces.sh:L282-L285)
  > **Upstream quirk:** a non-numeric value is not validated reliably, and the limit is silently dropped offline. A port validates a positive integer and applies the limit in every mode.
  > **Observed 2026-11-16 (`spo/test/parity/assets_scripts_test.go`):** offline, `01_sendLovelaces` with `utxolimit:1`, `skiputxowithasset:` or `onlyutxowithasset:` spends every UTxO of the snapshot; the explicit `txhash#index` list is applied. The port filters in every mode, in the order skip, only, limit (the first n in cardano-cli's order: transaction id, then index), list. The asset filters compare the asset id exactly; upstream greps the text of each UTxO row, so a shorter name also matches every longer one, and a 56-character entry could match a transaction hash that contains it.
- **SPO-Pparam-IF-021** `skiputxowithasset:<id>[|<id>...]` and `onlyutxowithasset:<id>[|<id>...]` take a `|` separated list of hex strings of 28 to 60 bytes (56 to 120 hex characters), case-insensitive, normalised to lower case. An entry longer than 56 characters is a policy id plus asset name and is rewritten to `policy.assetnamehex`; a 56-character entry is a policy id only. A list that does not match this shape is refused with exit 1. (src: 01_sendLovelaces.sh:L131-L141, 01_sendLovelaces.sh:L144-L154)
- **SPO-Pparam-IF-022** The skip filter removes every UTxO row whose text contains any listed identifier; the only filter then keeps only the rows that contain at least one. The skip filter runs first. After the only filter the two header lines of the raw query text are rebuilt, so a filter that matches nothing yields an empty candidate set and the "no funds" refusal of SPO-Ptx-PRE-001. Both filters are applied in online and light mode only. (src: 01_sendLovelaces.sh:L263-L264, 01_sendLovelaces.sh:L274-L275, 01_sendLovelaces.sh:L282-L285)
- **SPO-Pparam-IF-023** `keeppolicy:<policyid>[|<policyid>...]` (`01_sendAssets` only) is a `|` separated list of 56-hex-character policy ids, lower-cased, naming assets that an `ALLASSETS` transfer keeps on the source address. Any other shape is refused with exit 1. (src: 01_sendAssets.sh:L331-L336)

## Script-specific keyed tokens

- **SPO-Pparam-IF-024** `type:REG` or `type:REREG` (`05c` only; value trimmed, upper-cased) forces a new registration or a re-registration of the pool; any other value is refused with exit 1. It is refused with exit 1 when a witness collection already exists. (src: 05c_regStakepoolCert.sh:L123-L127, 05c_regStakepoolCert.sh:L309-L310, 05c_regStakepoolCert.sh:L316-L320)
- **SPO-Pparam-IF-025** `url:<anchor-url>` (`21b`, `23e`; also `24a`, `25a`) sets a governance anchor URL. The value is trimmed; it must start with `https://` or `ipfs://` and be at most 128 characters, otherwise exit 1. (src: 21b_regDRepCert.sh:L139-L142, 23e_retComColdKeys.sh:L139-L142, 25a_genAction.sh:L118-L122)
- **SPO-Pparam-IF-026** `hash:<hex>` (`21b`, `23e`; also `24a`, `25a`) sets the anchor data hash. The value is trimmed and lower-cased; it must be exactly 64 hex characters, otherwise exit 1. In `21b`/`23e` it is only needed to override the value in offline mode. (src: 21b_regDRepCert.sh:L145-L151, 23e_retComColdKeys.sh:L145-L151, 25a_genAction.sh:L124-L130)

## Key-derivation tokens (key-generation scripts)

These belong to non-transaction scripts and are recorded here because they use the same token syntax.

- **SPO-Pparam-IF-027** `acc:<n>` and `idx:<n>` (`03a`, `21a`, `23a`, `23b`) are the account number and the address index of the derivation path. Each is trimmed and must be an integer in 0..2147483647, otherwise exit 1. (src: 03a_genStakingPaymentAddr.sh:L75-L83, 21a_genDRepKeys.sh:L76-L84, 23a_genComColdKeys.sh:L73-L81, 23b_genComHotKeys.sh:L73-L81)
- **SPO-Pparam-IF-028** `mnemonics:<24 words>` (`03a`, `21a`, `23a`, `23b`) is trimmed, lower-cased and has repeated blanks squeezed to one. Anything other than 24 words is refused with exit 1. (src: 03a_genStakingPaymentAddr.sh:L85-L90, 21a_genDRepKeys.sh:L86-L91, 23a_genComColdKeys.sh:L83-L88, 23b_genComHotKeys.sh:L82-L87)
- **SPO-Pparam-IF-029** `epoch:<n>`, `amount:<n>`, `addr:<stake address>`, `constitution-url:`, `constitution-hash:` are accepted by `25a_genAction` (governance action generation) and `24a` takes `url:`/`hash:` only; their validation is specified in the `25a` and `24a` script specs. (src: 25a_genAction.sh:L132-L136, 25a_genAction.sh:L304-L316)

## Domain mapping

Use cases `ComposeTransactionMetadata` (messages, encryption, metadata files) and `SelectInputUtxos` (filters) feed the `TxDraft` of the shared kernel (see `SPO-Ptx`).

| Port | Operation | Purpose |
| --- | --- | --- |
| `Ledger` | `buildRaw(txSpec)` | Carries the metadata files and the message metadata as part of the draft |
| `Ledger` | `encryptMessage(lines, passphrase)` *(new)* | CIP-83 `basic` encryption of the message lines (AES-256-CBC, PBKDF2, 10000 iterations, base64) |
| `Store` | `get(MetadataFile)` | Read user metadata `.json` / `.cbor` files |
| `ChainQuery` | `utxos(address)` | Candidate set that the input-selection tokens filter |
| `UI` | `show(view)` | Summary of attached metadata (display only) |

## Port notes

* Parse extra parameters into a typed request (`messages`, `encryption`, `passphrase`, `metadataFiles`, `utxoFilter`, `utxoLimit`, `skipAssets`, `onlyAssets`), validated once and shared by every transaction use case; refuse unknown keys instead of treating them as file names (SPO-Pparam-IF-005).
* Encode message lines as JSON values (SPO-Pparam-PRE-002), validate the encryption mode everywhere (SPO-Pparam-INV-001), apply input filters in every work mode (SPO-Pparam-IF-020).
* The 64-byte limit is a CIP-20 rule on each array element; the port should count UTF-8 bytes of each element, as upstream does.
* Do not print the passphrase and do not pass it on a command line; use a library AES/PBKDF2 implementation that is byte-compatible with `openssl enc -pbkdf2` (salted format: `Salted__` header, 8-byte salt).

## Open questions

* ~~The exact base64 line width and salt format of `openssl enc -a`~~ Resolved 2026-11-16: 64 characters per line, `Salted__` and the 8-byte salt in front of the ciphertext, key and IV from PBKDF2-HMAC-SHA256 (10 000 iterations, 48 bytes: 32 of key then 16 of IV), PKCS#7 padding. `openssl enc -S <salt>` leaves the `Salted__` header out of its output, so a test that fixes the salt has to put it back. `native.CIP83` is byte-equal to `openssl` with a fixed salt, `openssl` decrypts its output and it decrypts `openssl`'s (`TestMessageEncryptionMatchesOpenSSL`). The plaintext is what `jq -crM` prints for the array: no spaces, non-ASCII as it is, DEL as `\u007f`, and not the HTML-escaped form of `encoding/json`.
* Whether a message array element that is an empty string is accepted by wallets is not settled by source.
