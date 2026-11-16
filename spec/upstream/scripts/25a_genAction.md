+++
id = "25a"
kind = "script"
title = "Generate a governance action file"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["governance"]
use_cases = ["BuildGovernanceAction"]
depends_on = ["Cconf", "Cchain", "Cconv", "Cui", "Coffline", "Pparam", "Pfiles"]

upstream_path = "cardano/mainnet/25a_genAction.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "0004e496a15589cd01d936c70aef59b17aa378c8f64783789224d579f7a016a1"
upstream_lines = 814
uses_common = [
  "checkError",
  "convertToADA",
  "file_lock",
  "file_unlock",
  "get_currentEpoch",
  "readOfflineFile",
  "showProcessAnimation",
  "stopProcessAnimation",
  "trimString",
]
cli_commands = [
  "governance action create-constitution",
  "governance action create-hardfork",
  "governance action create-info",
  "governance action create-no-confidence",
  "governance action create-protocol-parameters-update",
  "governance action create-treasury-withdrawal",
  "governance action update-committee",
  "query constitution",
  "query gov-state",
  "query protocol-parameters",
]
hwcli_commands = []
signer_commands = [
  "verify",
]
http_endpoints = []
env_vars = []
+++

# 25a_genAction: Generate a governance action file

Builds one Conway governance *proposal* and writes it to a `.action` file. Nothing is signed and nothing reaches the chain: [25b](./25b_regAction.md) later attaches one or more `.action` files to a transaction, pays the deposit, and submits it. The script supports all seven governance action types a Conway ledger knows: `InfoAction`, `TreasuryWithdrawals`, `NewConstitution`, `NoConfidence`, `ParameterChange`, `UpdateCommittee` and `HardForkInitiation`.

Every action carries the same four common values: the **deposit-return stake address** (where the deposit goes back to when the action is ratified, expires or is dropped), the **action deposit** (the chain's current `govActionDeposit`), and an **anchor** (URL plus blake2b-256 hash of an off-chain justification document). On top of these each type adds its own parameters (the table below). Types that continue a chain of earlier actions of the same *purpose* (new constitution, no confidence, update committee, hard fork, parameter change) also reference the **previous action id** that the chain reports as the last enacted one; treasury withdrawals and info actions have no such link.

The assembly of the proposal is entirely `cardano-cli governance action create-*`; this script validates the operator's tokens, fetches and hashes the anchor documents, reads the chain's governance state, and picks the right cli subcommand and arguments.

| Action type (case-insensitive) | cli subcommand | Own parameters | Previous-action purpose | Guardrails script hash | Needs protocol major |
| --- | --- | --- | --- | --- | --- |
| `InfoAction` | `create-info` | none | none | no | 9 |
| `TreasuryWithdrawals` | `create-treasury-withdrawal` | `amount:`, `addr:` | none | yes, when the constitution has one | 10 |
| `NewConstitution` | `create-constitution` | `constitution-url:`, `constitution-hash:` | `Constitution` | no | 10 |
| `NoConfidence` | `create-no-confidence` | none | `Committee` | no | 10 |
| `ParameterChange` | `create-protocol-parameters-update` | up to 41 named parameters | `PParamUpdate` | yes, when the constitution has one | 9 |
| `UpdateCommittee` | `update-committee` | `threshold:`, `add-hash:`, `add-script:`, `rem-hash:`, `rem-script:`, `epoch:` | `Committee` | no | 10 |
| `HardForkInitiation` | `create-hardfork` | `ver:` | `HardFork` | no | 9 |

## Interface

- **SPO-25a-IF-001** Takes at least two positional words: the deposit-return stake account (a name or a bech32 stake address) and the action type; every further word is an extra parameter, processed left to right from the third word. With fewer than two words it prints usage on stderr and exits 1. (src: L24-L64)
  > **Upstream quirk:** the usage text shows the anchor URL as a third mandatory positional word, but it is an ordinary `url:` parameter in any position from the third word on; only its absence is checked later (SPO-25a-PRE-006).
- **SPO-25a-IF-002** The action type is lower-cased and must be one of the seven names above. The membership test is a substring test against the comma-separated list of names, so any substring of that list (`committee`, `info`, an empty word, ...) passes it. Such a value is refused later by the final dispatch (exit 1) after the anchor and chain queries have already run. A value that is not a substring of the list is refused at once with exit 1. (src: L20-L21, L77-L78, L682-L685)
- **SPO-25a-IF-003** The first word names the deposit-return stake address in one of two forms. (1) A stake account name: `<name>` with an optional directory part, with or without the `.staking` extension (see SPO-Pfiles-IN-001); when `<name>.staking.addr` exists its content is the address; it is checked as bech32 in lower case (L86) but passed on to `cardano-cli` exactly as stored, **not** lower-cased (L84, used at L701). (2) Otherwise, a word that starts with `stake` (case-insensitive) is taken as a literal bech32 stake address and lower-cased (L91, the only form that is lower-cased). A word that is neither is refused with exit 1. (src: L82-L94, L701)
- **SPO-25a-IF-004** The deposit-return address must decode as bech32. Nothing else is checked: neither the `stake`/`stake_test` prefix against the configured network, nor the credential type (key or script). (src: L86-L87, L89-L90)
- **SPO-25a-IF-005** `url:<anchor-url>` sets the anchor URL, required for every action type (SPO-25a-PRE-006). The word is matched case-insensitively on its key, the value is trimmed and keeps its case. The value must contain `https://` or `ipfs://` and be at most 128 characters, otherwise exit 1; a later `url:` word replaces an earlier one. See SPO-Pparam-IF-025. (src: L118-L122)
  > **Upstream quirk:** the scheme test is an unanchored substring match, not a prefix test, so `ftp://x/https://y` is accepted.
- **SPO-25a-IF-006** `hash:<hex>` sets the anchor data hash. The value is trimmed, lower-cased, and must be exactly 64 hexadecimal characters, otherwise exit 1. See SPO-Pparam-IF-026. (src: L124-L129)
- **SPO-25a-IF-007** `epoch:<n>` is parsed for every action type and must consist of digits only, otherwise exit 1; it is used by `UpdateCommittee` only (SPO-25a-IF-020), and the value `0` means "not given". (src: L132-L137)
- **SPO-25a-IF-008** Words of the first pass that are not `url:`, `hash:` or `epoch:` are ignored by it. Each action type then makes its own pass over the same words, as listed below; the unknown-word handling differs per type (SPO-25a-IF-011, SPO-25a-IF-017, SPO-25a-IF-021). (src: L113-L141)
- **SPO-25a-IF-009** `TreasuryWithdrawals`: `amount:<lovelaces>` (required) must consist of digits only (and must not be zero, see SPO-25a-PRE-012); a later `amount:` replaces an earlier one. (src: L304-L309, L326)
- **SPO-25a-IF-010** `TreasuryWithdrawals`: `addr:<stake address>` names the account that receives the funds. The value is trimmed, must start with `stake` (case-insensitive) and decode as bech32, otherwise exit 1. Without it the funds go to the deposit-return address. The value is **not** lower-cased, so an upper-case or mixed-case address later fails the bech32 decode of SPO-25a-EXT-011 (exit 1). (src: L296, L312-L317, L717-L718)
- **SPO-25a-IF-011** `TreasuryWithdrawals` ignores every word other than `amount:` and `addr:` (and the first-pass words), including unknown ones. (src: L299-L321)
- **SPO-25a-IF-012** `HardForkInitiation`: `ver:<major>.<minor>` (required) with one or two digits for each part, for example `10.0`; any other shape is refused with exit 1. A later `ver:` word replaces an earlier one. (src: L352-L357, L364)
- **SPO-25a-IF-013** `UpdateCommittee`: `threshold:<rational>` (required, at most once) is a rational number from 0 to 1 written as a fraction (`2/3`) or a decimal (`0.66`), see SPO-25a-PRE-017. (src: L412-L418, L466)
- **SPO-25a-IF-014** `UpdateCommittee`: `add-hash:<hex>` adds a committee member by cold **key** hash and `add-script:<hex>` by cold **script** hash; `rem-hash:<hex>` and `rem-script:<hex>` remove one. Each value is trimmed, lower-cased and must be 56 hexadecimal characters, otherwise exit 1. Any number of these words may be given, in any order; they are passed on in the order given. (src: L420-L454)
- **SPO-25a-IF-015** `UpdateCommittee`: a hash value that already occurs anywhere in the collected arguments (as an add or a remove, key or script) is refused with exit 1, so the same hash cannot be added and removed in one action. `threshold:` given twice is also refused with exit 1. (src: L415, L424, L433, L442, L451)
- **SPO-25a-IF-016** `UpdateCommittee`: no add or remove word is needed; `threshold:` alone changes only the threshold. (src: L466)
- **SPO-25a-IF-017** `UpdateCommittee` refuses any other word, including a word without a colon, with exit 1 (the `url`, `hash` and `epoch` keys are skipped). (src: L410, L457-L459)
- **SPO-25a-IF-018** `NewConstitution`: `constitution-url:<url>` (required) is the location of the constitution document. It is trimmed and must contain `https://` or `ipfs://`, otherwise exit 1. (src: L487-L490, L505)
  > **Upstream quirk:** the 128-character limit is tested against an unset variable (`${#constitution}`), so it is never enforced; and the scheme test is unanchored like SPO-25a-IF-005.
- **SPO-25a-IF-019** `NewConstitution`: `constitution-hash:<hex>` is trimmed, lower-cased and must be exactly 64 hexadecimal characters, otherwise exit 1. It is only needed offline. (src: L493-L498)
- **SPO-25a-IF-020** `UpdateCommittee`: the term end epoch of **every added member** is `epoch:<n>` when given (SPO-25a-PRE-016), else the current epoch plus `committeeMaxTermLength`. (src: L387-L395, L426, L444)
- **SPO-25a-IF-021** `ParameterChange` accepts the 41 parameter names of the table in SPO-25a-IF-022 as `<name>:<value>` words (name case-insensitive, both parts trimmed, split at the first colon) and ignores `url:` and `hash:`. Any other word, including `epoch:` and a word without a colon, is refused with exit 1 listing the supported names. A name given twice is refused with exit 1. (src: L572-L615, L618-L637, L627)
- **SPO-25a-IF-022** The value of each `ParameterChange` parameter is checked by its type, then passed to cardano-cli as `--<name> <value>` in the order given. Types: `RATIONAL`: only characters `0-9 . /`, at least one `.` or `/`, not starting or ending with `.`, and numerically not greater than 1.0 (`bc` with 18 decimals), otherwise exit 1. `NATURAL`: digits only and not zero, otherwise exit 1. `LOVELACE`, `WORD32`, `WORD16`, `INT`: digits only (zero allowed), otherwise exit 1; no range is checked. The parameter-to-type table is the `PARAMETER_LIST` associative array of the script, which holds the 41 names of IF-021 and their type. (src: L572-L615, L639-L663)

  | Parameter | Type |
  | --- | --- |
  | `min-fee-linear`, `min-fee-constant`, `utxo-cost-per-byte`, `drep-deposit` | LOVELACE |
  | `max-block-body-size`, `max-tx-size`, `pool-retirement-epoch-interval`, `committee-term-length`, `governance-action-lifetime`, `drep-activity` | WORD32 |
  | `max-block-header-size` | WORD16 |
  | `key-reg-deposit-amt`, `pool-reg-deposit`, `number-of-pools`, `min-pool-cost`, `new-governance-action-deposit` | NATURAL |
  | `max-value-size`, `collateral-percent`, `max-collateral-inputs`, `min-committee-size` | INT |
  | `pool-influence`, `treasury-expansion`, `monetary-expansion`, `price-execution-steps`, `price-execution-memory`, `ref-script-cost-per-byte` | RATIONAL |
  | `pool-voting-threshold-motion-no-confidence`, `-committee-normal`, `-committee-no-confidence`, `-hard-fork-initiation`, `-pp-security-group` | RATIONAL (5) |
  | `drep-voting-threshold-motion-no-confidence`, `-committee-normal`, `-committee-no-confidence`, `-update-to-constitution`, `-hard-fork-initiation`, `-pp-network-group`, `-pp-economic-group`, `-pp-technical-group`, `-pp-governance-group`, `-treasury-withdrawal` | RATIONAL (10) |

  > **Upstream quirk:** the `RATIONAL` rule applies the "at most 1.0" bound to every rational parameter, so `ref-script-cost-per-byte` (15 on mainnet) cannot be set to a realistic value through this script, and a bare integer such as `1` is refused for lack of a `.` or `/`.
- **SPO-25a-IF-023** `ParameterChange` threshold groups are all-or-nothing: when any `pool-voting-threshold-*` parameter is given all 5 must be given, and for `drep-voting-threshold-*` all 10; otherwise exit 1. At least one parameter is required, otherwise exit 1. (src: L667-L675)

## Inputs

- **SPO-25a-IN-001** Reads `<stake>.staking.addr` (see SPO-Pfiles-OUT-001) when the first word names a file. A read failure is refused with exit 1. (src: L83-L85)
- **SPO-25a-IN-002** From the protocol parameters document of the work mode it reads `protocolVersion.major`, `protocolVersion.minor`, `govActionDeposit` and `committeeMaxTermLength` (each defaulting to -1 when absent), `constitution.script` (default none) and, for the previous-action ids, `prevActionIDs.<Purpose>.txId` and `.govActionIx` with `<Purpose>` one of `Committee`, `Constitution`, `HardFork`, `PParamUpdate` (default none). (src: L255, L721, L733, L744, L755, L766, L777)
- **SPO-25a-IN-003** Settings read: the work mode, the era for `cardano-cli`, the network option (the first nine characters of `magicparam`, which is `--mainnet` or `--testnet`), the temp directory, and the paths of the `bech32` binary and `cardano-signer`. (src: L67, L147, L150, L511, L701)

## Behaviour

1. **Era gate.**
   - **SPO-25a-PRE-001** When the configured era is `shelley`, `allegra`, `mary`, `alonzo` or `babbage` it prints a notice and **exits 0** without doing anything. (src: L67-L71)
2. **Validate the action type and the deposit-return address** (SPO-25a-IF-002, SPO-25a-IF-003, SPO-25a-IF-004).
   - **SPO-25a-PRE-002** An unsupported action type is refused with exit 1. (src: L78)
   - **SPO-25a-PRE-003** An unresolvable stake account (neither an existing `.staking.addr` file nor a `stake...` literal) is refused with exit 1. (src: L93)
   - **SPO-25a-PRE-004** A deposit-return address that is not valid bech32 is refused with exit 1. (src: L87, L90)
   - **SPO-25a-OUT-001** When the address comes from a literal, the output file prefix is the lower-cased action type instead of an account name (SPO-25a-OUT-006). (src: L91)
3. **First pass over the extra words** (SPO-25a-IF-005 .. SPO-25a-IF-007). Violations exit 1.
   - **SPO-25a-PRE-005** A malformed `url:`, `hash:` or `epoch:` value is refused with exit 1. (src: L121, L128-L129, L135-L136)
   - **SPO-25a-PRE-006** A missing `url:` is refused with exit 1. (src: L144)
4. **Fetch and hash the anchor** (online and light mode only; offline see SPO-25a-MODE-004).
   - **SPO-25a-EXT-001** The anchor document is fetched with an HTTP GET (`curl -sL -m 30`, redirects followed, body saved to `<tempDir>/AnchorURLContent.tmp` byte for byte), with up to 5 attempts one second apart when curl itself fails. An `ipfs://<cid>` URL is fetched from `https://ipfs.io/ipfs/<cid>`. (src: L149-L163)
   - **SPO-25a-PRE-007** The anchor fetch is refused with exit 1 when curl failed on all 5 attempts, when the HTTP status could not be determined, when the status is 4xx, or when it is anything but 200. (src: L205-L215)
   - **SPO-25a-EXT-002** On HTTP 200 whose body parses as JSON, the anchor hash is the blake2b-256 digest of the raw downloaded bytes (`b2sum -l 256`), 64 lower-case hexadecimal characters. A `b2sum` failure ends the script with its exit code. (src: L173, L181-L182, L185)
   - **SPO-25a-INV-001** The hash computed from the download always replaces a `hash:` value; when the two differ, a warning is shown and the given value is discarded. (src: L184-L185)
   - **SPO-25a-INV-002** When the body of an HTTP 200 answer is **not** valid JSON, the downloaded file is deleted, a message is shown, and the script continues with whatever `hash:` value the operator supplied (possibly none, see SPO-25a-PRE-008). No hash is computed. (src: L173-L177)
     > **Upstream quirk:** a non-JSON anchor with a user-supplied `hash:` therefore produces an action that commits to an unverified hash. A port refuses it.
   - **SPO-25a-EXT-003** For a JSON anchor, `cardano-signer verify --cip100 --data-file <anchor> --json-extended` is run; its verdict (document structure, an error message, one line per author signature) is display only and never stops the script. (src: L190-L199)
   - **SPO-25a-PRE-008** After this step an empty anchor hash is refused with exit 1 (in practice: offline without `hash:`, or a non-JSON anchor without `hash:`). (src: L227)
5. **Read protocol parameters and governance state** (SPO-25a-MODE-001 .. SPO-25a-MODE-003).
   - **SPO-25a-PRE-009** A protocol major version below 9 is refused with exit 1 (the chain is not in the Conway era's bootstrap phase yet). (src: L258-L259)
   - **SPO-25a-PRE-010** A `govActionDeposit` that is absent from the document (read as -1) is refused with exit 1, and so is an unreadable `committeeMaxTermLength`, whatever the action type. (src: L261-L262, L266-L267)
   - **SPO-25a-INV-003** The deposit written into the action is the chain's current `govActionDeposit`, unmodified. It is never taken from the operator. (src: L255, L701)
6. **Per-type parameters.** Each type runs its own validation pass before anything is generated.
   - **SPO-25a-PRE-011** `TreasuryWithdrawals`, `NewConstitution`, `NoConfidence` and `UpdateCommittee` are refused with exit 1 while the protocol major version is below 10 (the Conway bootstrap phase): `InfoAction`, `ParameterChange` and `HardForkInitiation` are allowed from 9. (src: L284-L285, L293-L294, L382-L383, L477-L478)
   - **SPO-25a-PRE-012** `TreasuryWithdrawals` without a non-zero `amount:` is refused with exit 1. (src: L326)
   - **SPO-25a-PRE-013** `HardForkInitiation` without `ver:` is refused with exit 1. (src: L364)
   - **SPO-25a-PRE-014** `HardForkInitiation` refuses, with exit 1, a target version that is lower than the current one (lower major, or equal major with a lower minor), a major version more than one above the current, and a major version exactly one above with a non-zero minor. The same version as the current one is accepted. (src: L367-L371)
   - **SPO-25a-PRE-015** `NewConstitution` without `constitution-url:` is refused with exit 1. (src: L505)
   - **SPO-25a-PRE-016** `UpdateCommittee` with an `epoch:` value that is not greater than the current epoch or is greater than the current epoch plus `committeeMaxTermLength` is refused with exit 1. The current epoch comes from the work mode (SPO-Cchain-OUT-001); offline it is computed from the wall clock. (src: L388-L395)
   - **SPO-25a-PRE-017** `UpdateCommittee` and `ParameterChange` refuse malformed values as given in SPO-25a-IF-013 .. SPO-25a-IF-023 with exit 1, and `UpdateCommittee` without `threshold:` too. The rational test is a heuristic (a character class plus a `bc` comparison): a value it lets through but cardano-cli rejects ends with exit 1 at generation (SPO-25a-EXT-012). (src: L413, L466, L646-L657, L669-L675)
   - **SPO-25a-EXT-004** `NewConstitution`: in online and light mode the constitution document is fetched and hashed exactly as the anchor (SPO-25a-EXT-001, SPO-25a-PRE-007, SPO-25a-EXT-002) into `<tempDir>/ConstitutionURLContent.tmp`, except that no JSON check and no CIP-100 verification takes place, a 404 and every other failure all end with exit 1, and a given `constitution-hash:` that differs is discarded with a notice. The computed hash replaces any given one. Offline neither a fetch nor a warning happens and the given `constitution-hash:` is used. (src: L507-L555)
   - **SPO-25a-PRE-018** `NewConstitution` with an empty constitution hash after this step (offline without `constitution-hash:`) is refused with exit 1. (src: L559)
7. **Generate and write the action file.**
   - **SPO-25a-EXT-005** The common arguments of every subcommand are `<network option> --deposit-return-stake-address <addr> --governance-action-deposit <deposit> --anchor-url <url> --anchor-data-hash <hash> --out-file /dev/stdout`: the proposal text is captured from standard output. cardano-cli's standard error is **also** captured into the same text. (src: L701, L711, L727, L735-L737, L746-L748, L757-L759, L768-L770, L787)
     > **Upstream quirk:** a cardano-cli warning on a successful run ends up inside the `.action` file and corrupts it. A port keeps the streams apart.
   - **SPO-25a-EXT-006** `InfoAction`: `governance action create-info <common>`. (src: L711)
   - **SPO-25a-EXT-007** `TreasuryWithdrawals`: `governance action create-treasury-withdrawal <common> [--constitution-script-hash <h>] --funds-receiving-stake-key-hash <hash> --transfer <amount>`. The receiving key hash is the bech32 payload of the `addr:` address (or the deposit-return address) with its one-byte header removed (SPO-25a-EXT-011). The script hash is added when `constitution.script` is present in the protocol parameters document. No previous action id is passed. (src: L717-L727)
   - **SPO-25a-EXT-008** `NoConfidence`: `governance action create-no-confidence <common> [--prev-governance-action-tx-id <txid> --prev-governance-action-index <ix>]`, with the previous id read from `prevActionIDs.Committee`; the flags are left out when the chain has no previous committee action. (src: L733-L738)
   - **SPO-25a-EXT-009** `NewConstitution`: `governance action create-constitution <common> --constitution-url <url> --constitution-hash <hash> [--prev-governance-action-tx-id <txid> --prev-governance-action-index <ix>]`, with the previous id from `prevActionIDs.Constitution`. No constitution script hash is ever passed, so a new constitution cannot carry a guardrails script through this script. (src: L744-L749)
   - **SPO-25a-EXT-010** `HardForkInitiation`: `governance action create-hardfork <common> --protocol-major-version <M> --protocol-minor-version <m> [--prev-governance-action-tx-id <txid> --prev-governance-action-index <ix>]`, previous id from `prevActionIDs.HardFork`. (src: L755-L760)
   - **SPO-25a-EXT-011** The receiving key hash for a treasury withdrawal is obtained by decoding the bech32 stake address (`bech32` binary, address in on stdin) and dropping the first two hexadecimal characters (the header byte). A decode failure is refused with exit 1. The header byte is not inspected, so a script-credential stake address is silently treated as a key hash. (src: L717-L719)
   - **SPO-25a-EXT-012** `UpdateCommittee`: `governance action update-committee <common> [--prev-governance-action-tx-id <txid> --prev-governance-action-index <ix>] <committee args>`, previous id from `prevActionIDs.Committee` (the same chain as `NoConfidence`). The committee arguments are, in the order given: `--threshold <v>`, `--add-cc-cold-verification-key-hash <h> --epoch <E>`, `--add-cc-cold-script-hash <h> --epoch <E>`, `--remove-cc-cold-verification-key-hash <h>`, `--remove-cc-cold-script-hash <h>`, with `E` the term end epoch of SPO-25a-IF-020. (src: L417, L426, L435, L444, L453, L764-L771)
   - **SPO-25a-EXT-013** `ParameterChange`: `governance action create-protocol-parameters-update <common> [--constitution-script-hash <h>] [--prev-governance-action-tx-id <txid> --prev-governance-action-index <ix>] --<name> <value> ...`, the script hash from `constitution.script`, the previous id from `prevActionIDs.PParamUpdate`. (src: L775-L788)
   - **SPO-25a-INV-004** A previous-action id is passed when the `txId` for its purpose is present in the protocol parameters document (the index is not checked separately); the id used is whatever the chain reports as last enacted for that purpose, not an action still being voted on. (src: L733-L738, L744-L749, L755-L760, L766-L771, L777-L785)
   - **SPO-25a-PRE-019** A non-zero cardano-cli exit is refused with exit 1 and the captured text as the message; nothing is written. (src: L792)
   - **SPO-25a-OUT-002** The proposal text is written to the action file. The file is unlocked first (so an existing file can be replaced), written, and then locked read-only. A write failure is refused with exit 1. (src: L793-L797)
   - **SPO-25a-OUT-003** The file is shown after writing, with the referenced previous action id and constitution script hash when present, and a hint to run `25b` (display only). (src: L800-L810)

## Work modes

- **SPO-25a-MODE-001** *Online.* Protocol parameters come from `cardano-cli <era> query protocol-parameters`; the constitution from `query constitution` (stderr discarded; an empty result is refused with exit 1); the previous-action ids from `query gov-state` at `.nextRatifyState.nextEnactState.prevGovActionIds` (an empty result is refused with exit 1). The three results are merged into one document with the constitution under `constitution` and the ids under `prevActionIDs`. A failure of the first query is not checked on its own; it appears to surface only as the version refusal of SPO-25a-PRE-009 (see Open questions). (src: L233-L241, L253)
- **SPO-25a-MODE-002** *Light.* The document is the Light-Mode parameters document fetched at start (SPO-Clight-OUT-001), used as is. It must itself contain `constitution` and `prevActionIDs`; the script does not check this. (src: L244-L246)
- **SPO-25a-MODE-003** *Offline.* The document is `.protocol.parameters` of the transfer file (SPO-Coffline-PRE-001 .. SPO-Coffline-PRE-004 apply). It holds `constitution` and `prevActionIDs` only when the snapshot was made by `01_workOffline` against a governance-capable node (src: 01_workOffline.sh:L153-L161, 01_workOffline.sh:L178). Governance state in the snapshot may be stale, so the previous-action ids, the deposit and the committee limit are those of the snapshot time. (src: L248-L251)
- **SPO-25a-MODE-004** *Offline anchor.* No download and no hash verification happens; the given `hash:` is used as is, with a warning that it cannot be verified. (src: L218-L223)
- **SPO-25a-MODE-005** `UpdateCommittee` needs the current epoch: online from the node, light from Koios, offline from the wall clock and the genesis files (SPO-Cchain-OUT-001, SPO-Cchain-MODE-003, SPO-Cchain-MODE-004). (src: L388)

## Prompts

No prompts.

## Outputs

- **SPO-25a-OUT-004** Writes exactly one action file, or none. No other artefact is created or changed except the temp files of SPO-25a-OUT-005. (src: L793-L797)
- **SPO-25a-OUT-005** During the downloads of SPO-25a-EXT-001 and SPO-25a-EXT-004 the temp files `<tempDir>/AnchorURLContent.tmp` and `<tempDir>/ConstitutionURLContent.tmp` exist; they are deleted after a successful hash, and left behind when the script exits on a failure after creating them. (src: L150, L201, L511, L539)
- **SPO-25a-OUT-006** The action file is named `<stakeName>_<actionType>_<yymmddHHMMSS>.action` with the local time of the run, where `<stakeName>` is the first word as resolved by SPO-25a-IF-003 (including its directory part). When the first word was a literal address (SPO-25a-OUT-001) the file is `<actionType>_<yymmddHHMMSS>.action`. `<actionType>` is the lower-cased type as typed (so `infoaction`, `parameterchange`). Two runs in the same second overwrite the file. (src: L693-L698)

**Upstream file contract:**

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<stake>_<type>_<ts>.action` or `<type>_<ts>.action` | cardano-cli text envelope of the governance proposal (see SPO-Pfiles-OUT-030): deposit, deposit-return credential, anchor, action | `0400` | created |
| `<tempDir>/AnchorURLContent.tmp`, `<tempDir>/ConstitutionURLContent.tmp` | raw downloaded document | umask default | created, normally deleted |

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Fewer than two words | 1 | SPO-25a-IF-001 |
| Era before Conway | **0** | SPO-25a-PRE-001 |
| Unsupported action type | 1 | SPO-25a-PRE-002 |
| Stake address unresolved or invalid | 1 | SPO-25a-PRE-003, SPO-25a-PRE-004 |
| Malformed `url:`, `hash:`, `epoch:` | 1 | SPO-25a-PRE-005 |
| No `url:` | 1 | SPO-25a-PRE-006 |
| Anchor or constitution fetch fails | 1 | SPO-25a-PRE-007, SPO-25a-EXT-004 |
| No anchor hash | 1 | SPO-25a-PRE-008 |
| Governance state not queryable (online) | 1 | SPO-25a-MODE-001 |
| Protocol major below 9, or below 10 for the types of SPO-25a-PRE-011 | 1 | SPO-25a-PRE-009, SPO-25a-PRE-011 |
| Deposit or committee limit unreadable | 1 | SPO-25a-PRE-010 |
| Missing or malformed type-specific parameter | 1 | SPO-25a-PRE-012 .. SPO-25a-PRE-018, SPO-25a-IF-009 .. SPO-25a-IF-023 |
| `b2sum` failure | its code | SPO-25a-EXT-002 |
| cardano-cli generation failure | 1 | SPO-25a-PRE-019 |
| Action file not writable | 1 | SPO-25a-OUT-002 |

## Real-tool notes

* Observed 2026-11-16 (cardano-cli 11.2.3.0): the proposal procedure is `[deposit, reward account, governance action, anchor]` in type `Governance proposal`; the action is `[6]` (info), `[3, prev]` (no confidence), `[1, prev, [major, minor]]` (hard fork), `[5, prev, [[url, hash], script | null]]` (constitution), `[2, {account => lovelace}, script | null]` (treasury withdrawal) and `[4, prev, {removed}, {added => epoch}, tag-30 threshold]` (update committee), with `prev` `[tx id, index]` or `null`. The credentials of the committee sets are ordered as the ledger orders them, **script before key**, then by hash; the threshold is reduced (`0.66` is `33/50`). The descriptions are `Info proposal`, `Motion of no confidence proposal`, `Hardfork initiation proposal`, `Update to the Constitution or policy proposal`, `New constitutional committee and/or threshold and/or terms proposal` and `Treasury withdrawal proposal`. The six kinds are byte-equal to the port's (`TestGovActionFilesMatchCardanoCLI`); the parameter-change file is not built by the port yet.

## Security

- **SPO-25a-SEC-001** The anchor hash commits the action to whatever bytes the URL served at the moment of the run. A hash the operator supplied is overridden by the computed one in online and light mode (SPO-25a-INV-001), and trusted unchecked offline (SPO-25a-MODE-004) and for non-JSON documents (SPO-25a-INV-002). IPFS content is fetched through the third-party gateway `ipfs.io`. (src: L153, L173-L185, L220-L221)
- **SPO-25a-SEC-002** No secret material is read, written or printed. The action file is public data (it is submitted on chain). (src: L793-L805)

## Domain mapping

Use case `BuildGovernanceAction(returnStakeAddress, kind, params, anchor)` on aggregate `GovernanceAction` (a draft proposal: deposit, return address, anchor, a typed body, an optional previous-action id).

| Port | Operation | Purpose |
| --- | --- | --- |
| `ChainQuery` | `protocolParameters()` | Version, deposit, committee limit |
| `ChainQuery` | `constitution()` *(new)* | Guardrails script hash |
| `ChainQuery` | `lastEnactedActionIds()` *(new)* | Previous action id per purpose (`Committee`, `Constitution`, `HardFork`, `PParamUpdate`) |
| `ChainQuery` / `Clock` | `tip()`, `epochAt(...)` | Current epoch for committee terms |
| `Store` | `get(StakeAddress)` | Deposit-return address from the stake account |
| `Directory` | `fetchUrl(url)` | Anchor and constitution documents (HTTP, IPFS gateway) |
| `Ledger` | `anchorHash(bytes)` *(new)* | blake2b-256 of the raw document |
| `Ledger` | `verifyAnchorDocument(bytes)` *(new)* | CIP-100 structure and author signatures (informational) |
| `Ledger` | `buildGovernanceAction(kind, params)` *(new)* | `cardano-cli governance action create-*` |
| `Ledger` | `addressInfo(address)` | Decode a stake address to its credential |
| `Store` | `put(GovernanceActionFile)`, `lock` | The `.action` file |

## Port notes

- Keep the cli's stdout and stderr apart (SPO-25a-EXT-005); a warning must not enter the proposal text.
- Anchor handling should fail closed: when a document is not JSON, or the operator's hash disagrees with the download, refuse instead of continuing (SPO-25a-INV-002, SPO-25a-INV-001). Use an anchored scheme test and enforce the 128-character limit for the constitution URL too.
- The `RATIONAL` bound of 1.0 is wrong for `ref-script-cost-per-byte`; validate each parameter against its real type and range, or hand the value to the ledger library and report its error.
- `TreasuryWithdrawals` and `ParameterChange` do not depend on a guardrails script in 25a, but 25b does (SPO-25b-PRE-014); a port should read the constitution script once and carry it in the draft, so that the generation and the submission cannot disagree.
- The draft should carry the deposit-return address as a credential (key or script) rather than a bech32 string, which also removes the header-byte guesswork of SPO-25a-EXT-011.
- The anchor and constitution hashes must be recorded together with the fetched bytes' length and the time of fetching, so a later change of the document is detectable.
- Remote or multi-party signing is not involved: the draft has no signer.

## Open questions

- Whether the hosted Light-Mode parameters document always contains `constitution` and `prevActionIDs` (SPO-25a-MODE-002). Settle by fetching it for a governance-capable network and inspecting the keys.
- That a failed `query protocol-parameters` in online mode really ends in the version refusal of SPO-25a-PRE-009 rather than another path (SPO-25a-MODE-001). Settle by running the script against a stopped node.
- The exact semantics of `.nextRatifyState.nextEnactState.prevGovActionIds` as "last enacted" versus "last ratified in the current epoch" (SPO-25a-INV-004). Settle against the cardano-cli `query gov-state` documentation of the pinned release.
- How cardano-cli treats a `--threshold` or other rational that passes the heuristic (SPO-25a-PRE-017) but is not a valid fraction, for example `1/0` or `0.5.5`; settle by running the pinned cli.
