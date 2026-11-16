+++
id = "Cutxo"
kind = "common"
title = "UTxO parsing, filtering and minimum output value"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["transaction-construction"]
use_cases = []
depends_on = ["Cconv", "Cconf"]

upstream_path = "cardano/mainnet/00_common.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "9490fae84352a491bbded9bd4a14587521336364f9814a2df5aff6b86266bfba"
upstream_lines = 2966

[functions]
generate_UTXO = "7f16d2cb76ec16a149b0dc6c1943c3ebcbe21177f8f619747a886749c591211d"
filterFor_UTXO_old = "134ccc59f689421b4af364ddf582f4ddcd9d5ff49731f06098369ddccf21a8c0"
filterFor_UTXO = "4bbbe0ad17634272fe18bff0044f693b13b3bb63ac67e4e779b231f56731a0d4"
calc_minOutUTXOcli = "cfde2421c898e007f6b4f3cf21d61b7abf128b447be164c6a939c1bab64391b7"
calc_minOutUTXO = "8fed607dbcea68e7be2f594a2bf1ca52facc3696f51bf39d07f570f5b48e26e7"
+++

# Cutxo: UTxO parsing, filtering and minimum output value

The shared kernel of transaction construction needs three things from this group. First, a canonical JSON form of an address's UTxO set (`generate_UTXO`), parsed from the text that `cardano-cli query utxo --output-text` prints. The same JSON is what the offline transfer file stores per address, so it is a persisted-state contract as well as an internal one. Second, a way to narrow that set to chosen inputs (`filterFor_UTXO`). Third, the minimum lovelace an output must carry (`calc_minOutUTXO`), which upstream computes natively instead of asking cardano-cli. The result decides how much is sent, returned as change, or refused as too small, so a reimplementation must match it exactly. All five functions are pure: they touch no file, they never prompt, and apart from the two noted below they never call `exit`.

Every caller in the tree invokes these functions as `x=$(f ...)`, so an `exit` inside a function only ends that command-substitution subshell. The `exit` calls are flagged below because they would kill a caller that invoked the function directly.

## generate_UTXO

Called as `generate_UTXO <rawUtxoText> <address>`. Used after every online or light UTxO query and by the offline snapshot code.

- **SPO-Cutxo-IF-001** Takes two arguments: the raw UTxO text of one address, and that address as a string. The address is copied into every output entry unchanged. It is not converted to base16 and not validated. (src: L1013-L1018, L1036)
- **SPO-Cutxo-IF-002** Discards the first two lines of the raw text (column header and dashed separator) unconditionally, then treats each remaining line as one UTxO. The text is fed through `printf "%s\n"`, so backslash sequences in it are not interpreted. (src: L1098)
- **SPO-Cutxo-IN-001** Splits each line on spaces (runs of spaces count as one separator). Token 0 is the transaction hash and token 1 the output index; the entry key is `<hash>#<index>`. (src: L1022-L1024)
- **SPO-Cutxo-IN-002** The lovelace amount is token 2 when token 3 equals the literal `lovelace` **or** the line has exactly three tokens. Token scanning for assets then starts at token 5, which skips the `+` separator at token 4. Otherwise the lovelace amount is `0` and asset scanning starts at token 2. (src: L1027-L1033, L1041, L1046)
- **SPO-Cutxo-IN-003** Scans the remaining tokens left to right. A token that is entirely decimal digits is an asset amount; the next token is the asset id `<policyHex>[.<assetNameHex>]`. The id is split on `.`: part 0 is the policy id, part 1 (empty when absent) is the asset name, and any further parts are discarded. The scan advances three tokens (amount, id, the `+` after it). Any other token that is not a datum marker advances one token, which is how stray `+` tokens are skipped. (src: L1048-L1056, L1066-L1069, L1083-L1085)
- **SPO-Cutxo-IN-004** A token `TxOutDatumHash` whose next token contains the substring `Data` (for example `ScriptDataInConwayEra`) starts a datum-hash field. The datum hash is the token after that, with all double quotes removed, and the scan advances four tokens. (src: L1072-L1078)
- **SPO-Cutxo-IN-005** Any other token whose upper-cased form contains `DATUM` (for example `TxOutDatumInline`, `TxOutDatumNone`) stops the scan for that line. Nothing from that token onward is recorded, so inline datums and reference scripts do not appear in the output. (src: L1081)
- **SPO-Cutxo-OUT-001** Returns, on stdout, one JSON object whose keys are the `<hash>#<index>` strings in input line order. Each value is an object `{ "address": <address>, "value": { "lovelace": "<n>", "<policyHex>": { "<assetNameHex>": "<amount>", ... }, ... } }`, with `"datumhash": "<hex>"` added as a sibling of `value` when SPO-Cutxo-IN-004 applied. Every number, lovelace and token amounts alike, is a JSON string. The value object holds the `lovelace` key first and then one key per policy. Whitespace in the output is not significant; consumers read it with `jq`. (src: L1011, L1036, L1059-L1068, L1073-L1077, L1093-L1096)
- **SPO-Cutxo-OUT-002** Consecutive assets with the same policy id go under one policy object, in input order. The policy object opens on the first asset whose policy differs from the previous one. A policy that reappears non-adjacently opens a second object with a duplicate key, so the output is not valid-unique JSON in that case. cardano-cli prints assets sorted by policy, so the case does not arise in practice. (src: L1042-L1043, L1059-L1064, L1090)
- **SPO-Cutxo-OUT-003** Returns `{}` when no UTxO line follows the two header lines. (src: L1101)
- **SPO-Cutxo-INV-001** Always returns status 0 and never calls `exit`. Unparseable lines are not refused. (src: L1013-L1103)
- **SPO-Cutxo-INV-002** Nothing is validated or escaped: hashes, address and asset names are pasted into the JSON text as found. (src: L1036, L1068, L1077)

> **Upstream quirk:** A blank or whitespace-only line after the two header lines is not skipped. It produces an entry with key `#` and lovelace `0`. `$(...)` callers strip trailing newlines, so this only shows with an interior blank line. (src: L1021-L1036)

> **Upstream quirk:** Asset amounts are never summed per asset id. A repeated asset id would produce a repeated key. cardano-cli does not emit one. (src: L1068)

## filterFor_UTXO

- **SPO-Cutxo-IF-003** Takes a UTxO JSON object (the shape of SPO-Cutxo-OUT-001) and a string of one or more `<hash>#<index>` references separated by `|`. (src: L1130-L1136)
- **SPO-Cutxo-OUT-004** Returns an object that holds, in the order of the references given, exactly those entries of the input whose key equals a reference (exact, whole-key string match). Entries are copied verbatim. References that are not in the input are dropped silently and the filter does not complain. It does not check that every reference was found. (src: L1134-L1143)
- **SPO-Cutxo-OUT-005** Returns the literal `{}` when no reference matches; otherwise the result is pretty-printed by `jq` (multi-line, two-space indent). Only the JSON content matters to callers. (src: L1134, L1142, L1144)
- **SPO-Cutxo-INV-003** Always returns status 0 and never calls `exit`. A reference containing a double quote, or a non-JSON input, makes `jq` fail and the function can then print an empty string. This is not guarded. (src: L1141-L1144)

The callers (`01_sendLovelaces`, `01_sendAssets`, `11a`) apply it only when the user gave a UTxO filter, and a result of `{}` then ends in "No funds on the Source Address".

## filterFor_UTXO_old

Not called anywhere in the tree. Listed because it owns lines of the file.

- **SPO-Cutxo-IF-004** Takes a UTxO JSON object and an `egrep` pattern (references joined with `|` as alternation). (src: L1110-L1115)
- **SPO-Cutxo-OUT-006** Returns the input with every entry deleted whose key does not match the pattern. The match is an unanchored regular-expression match, so the reference `abc#1` also keeps `abc#10`. Order is the input order, and with nothing deleted the input text is returned unchanged. (src: L1114-L1122)

## calc_minOutUTXOcli

Not called anywhere in the tree. It is the cardano-cli reference implementation that `calc_minOutUTXO` replaces, and it is useful as the oracle for differential tests of SPO-Cutxo-INV-005 onward.

- **SPO-Cutxo-IF-005** Takes the protocol-parameters JSON text and a tx-out string. (src: L1262-L1268)
- **SPO-Cutxo-EXT-001** Runs `cardano-cli <cliEra> transaction calculate-min-required-utxo --protocol-params-file <params> --tx-out <txOut>`, with stderr merged into the captured output. (src: L1270)
- **SPO-Cutxo-PRE-001** A non-zero cardano-cli status prints the tx-out and the CLI error on stderr and calls `exit 1`. (src: L1272)
- **SPO-Cutxo-OUT-007** Returns the second space-separated field of the CLI output (`Coin 969750` gives `969750`). (src: L1273)

## calc_minOutUTXO

Called as `calc_minOutUTXO <protocolParametersJson> <txOutString>`. Callers use it with `1000000` as a placeholder lovelace amount and read the result as the lowest lovelace an output carrying those assets may hold. Two algorithms exist, selected by the protocol major version.

### Interface and inputs

- **SPO-Cutxo-IF-006** The tx-out string is `<address>+<lovelace>` optionally followed by `+<amount> <policyHex>[.<assetNameHex>]` once per asset entry (single space between amount and id; the policy id is its first 56 characters and the name is everything after character 57, hex). The string is split on `+`. Entry 0 is the address, entry 1 the lovelace amount, and entries 2 and up are assets. Exactly two entries means "no assets". Datums and reference scripts cannot be expressed. (src: L1286, L1301-L1303, L1326-L1341)
- **SPO-Cutxo-IN-006** Reads `protocolVersion.major` from the parameters. An absent value counts as 0. (src: L1290, L1293)
- **SPO-Cutxo-IN-007** Reads the global `nodeEraParam` to choose the output encoding, via the era resolution at L661-L673. It is `--<era>-era` taken from the node tip, the offline file's `protocol.era` or the light-mode tip, overridden by `ENV_USEERA`, and empty when no era is known. Only its lower-cased text is tested, for the substrings `babbage` and `conway`. (src: L1305, L1356, L661-L673)
- **SPO-Cutxo-IN-008** For the Babbage-or-later method, the cost per byte is the first present, non-null value of `utxoCostPerByte` and `coinsPerUTxOByte` in the parameters. When neither is present it is `floor(utxoCostPerWord / 8)`. (src: L1403-L1407)
- **SPO-Cutxo-INV-005** The method switch is `protocolVersion.major >= 7` (Babbage, Conway and later) for the byte-size method, and any smaller or absent major for the word method of SPO-Cutxo-INV-011 onward. (src: L1293, L1415)

### Babbage and later (CIP-55 byte-size rule)

- **SPO-Cutxo-INV-006** The result is `(S + 160) * costPerByte`, with integer arithmetic. `S` is the number of bytes of the CBOR-encoded output built below (hex length divided by two, rounded down), and `160` is the constant overhead. Lovelace and asset amounts are the values in the tx-out string, so the result depends on the lovelace placeholder's size class (see SPO-Cutxo-INV-010). (src: L1296, L1409-L1411)
- **SPO-Cutxo-EXT-002** Obtains the address bytes by running `cardano-cli address info --address <address>` (no era argument) and taking `.base16`. This handles bech32 Shelley addresses and base58 Byron addresses. stderr is discarded. (src: L1300)
- **SPO-Cutxo-PRE-002** A cardano-cli failure is not detected. The address hex is then empty and `S` is computed with a zero-length address, so a wrong address yields a silently lower minimum instead of a refusal. (src: L1300)
- **SPO-Cutxo-INV-007** The encoding form depends on `nodeEraParam` (SPO-Cutxo-IN-007). For `babbage` or `conway` the output is built in the post-Alonzo **map** form. For every other value, including empty, it is built in the legacy **array** form. The map form is exactly two bytes larger than the array form for the same content, because of the two one-byte keys `0` and `1`. (src: L1305-L1321, L1356-L1371)
- **SPO-Cutxo-OUT-008** With no assets, the encoded output is, in order: map form: `map(2)`, `unsigned 0`, `bytes(address)`, `unsigned 1`, `unsigned(lovelace)`. Array form: `array(2)`, `bytes(address)`, `unsigned(lovelace)`. (src: L1307-L1321)
- **SPO-Cutxo-OUT-009** With assets, the encoded output is, in order: map form: `map(2)`, `unsigned 0`, `bytes(address)`, `unsigned 1` (array form: `array(2)`, `bytes(address)`); then `array(2)`, `unsigned(lovelace)`, `map(P)` where `P` is the number of distinct policy ids. Then, for each distinct policy id in ascending lexicographic order: `bytes(policyId)`, `map(n)` where `n` is the number of asset entries with that policy, and for each such entry in input order `bytes(assetName)`, `unsigned(amount)`. (src: L1358-L1398)
- **SPO-Cutxo-INV-008** Entries are not merged: an asset id that appears twice in the tx-out string is encoded twice and counted twice in `n`. An asset with no name is `bytes` of length 0. Asset names in the encoding are the hex bytes of the name, and the policy id is the 56 hex characters. (src: L1340-L1349, L1385-L1396)
- **SPO-Cutxo-INV-009** Distinct policy ids and the per-policy counts come from `sort | uniq -c` over the policy list. Ascending order affects only the order of the encoded bytes, not `S`, because sizes do not depend on position. (src: L1352-L1353, L1381-L1383)
- **SPO-Cutxo-INV-010** `S` is the sum of the element sizes, where each element's size follows the encodings of `to_cbor` (see SPO-Cconv-OUT-001 to SPO-Cconv-OUT-004). Tabulated for reimplementation: (src: L1309-L1320, L1361-L1394)

  | Element | Size in bytes |
  | --- | --- |
  | `unsigned v` | 1 when v < 24; 2 when v < 256; 3 when v < 65 536; 5 when v < 2^32; 9 when v < 2^64; otherwise bignum: 1 (tag 2) + bytes header + byte length of v |
  | `bytes` of length L | header + L, where the header is 1 when L < 24, 2 when L < 256, 3 when L < 65 536 |
  | `array(n)` / `map(n)` | 1 when n < 24; 2 when n < 256; 3 when n < 65 536 |

  A policy id (28 bytes) therefore costs 30 bytes, and a 57-byte base address costs 59. The `1000000` placeholder costs 5 bytes. (src: L1309-L1313, L1361-L1396, L1409-L1410)

  Test vectors, with `costPerByte = 4310`, a 57-byte address, lovelace `1000000`:

  | Output | Map form | Array form |
  | --- | --- | --- |
  | no assets | 978 370 | 969 750 |
  | one policy, one 5-byte name, amount 1 | 1 150 770 | 1 142 150 |
  | policy A with an empty name, amount 1, plus policy B with a 32-byte name, amount 10^12 | 1 448 160 | 1 439 540 |

- **SPO-Cutxo-OUT-010** On this path the function prints the integer and then calls a bare `exit`, so the process (or the enclosing `$(...)` subshell) ends with status 0 and the shell variable `minOutUTXO` is set globally but lost with the subshell. It does not `return`. (src: L1410-L1412)

> **Upstream quirk:** When the era is unknown (`nodeEraParam` empty, for example an offline file or light-mode tip without an era), a Babbage-or-later protocol is sized with the array form, two bytes smaller than the map form that the same function uses once the era is known. For the same parameters the minimum therefore differs by `2 * costPerByte` (8 620 lovelace at 4 310). The array form matches the well-known mainnet minimum of 969 750 for a plain base-address output, so the map form is probably the over-estimate. Settling which form the ledger uses needs a differential test against SPO-Cutxo-EXT-001's oracle (see Open questions).

### Shelley, Allegra, Mary, Alonzo (word rule)

- **SPO-Cutxo-INV-011** Constants: coin size `k0 = 0`, `k1 = 6`, asset size `k2 = 12`, policy-id size `k3 = 28`, word `k4 = 8`, `utxoEntrySizeWithoutVal = 27`, and `adaOnlyUTxOSize = 27 + k0 = 27`. (src: L1419-L1425)
- **SPO-Cutxo-INV-012** The base minimum is `minUTxOValue` from the parameters. When `protocolVersion.major >= 5` (Alonzo) `adaOnlyUTxOSize` becomes 29 and the base minimum is `utxoCostPerWord * 29` instead. A missing parameter counts as 0 in the arithmetic. With no assets, the base minimum is the result. (src: L1427-L1439, L1445)
- **SPO-Cutxo-INV-013** With assets, the result is `floor(base / adaOnlyUTxOSize) * (27 + tokenBundleSize)`, where `tokenBundleSize = 6 + floor((numAssets*12 + sumAssetNameLengths + numPIDs*28 + 7) / 8)`. `numPIDs` is the number of distinct policy ids. `numAssets` is the number of distinct `(policyId, assetName)` pairs. `sumAssetNameLengths` is half the total hex length of the **distinct asset names taken on their own**, with empty names ignored. The same name under two policies is counted once. (src: L1451-L1482)
- **SPO-Cutxo-INV-014** The `max(base, computed)` the code seems to intend is dead: after setting the result to the larger value, the next statement unconditionally sets it to `computed` again. The result is always the computed value when assets are present. It is always larger than the base because `27 + tokenBundleSize >= 38 > 27`. (src: L1484-L1487)
- **SPO-Cutxo-OUT-011** On this path the function prints the integer with `echo` and returns normally, with no `exit`. Asset amounts and the address are not used. (src: L1491)

Test vectors: Mary (`major = 4`, `minUTxOValue = 1000000`), one asset with a 5-byte name: `floor(1000000/27) = 37037`; `tokenBundleSize = 6 + floor((12+5+28+7)/8) = 12`; result `37037 * (27+12)` = 1 444 443. Alonzo (`major = 5`, `utxoCostPerWord = 34482`), no assets: `34482 * 29` = 999 978. Alonzo with the same asset: `34482 * 39` = 1 344 798.

## Domain mapping

| Port | Operation | Purpose |
| --- | --- | --- |
| `ChainQuery` | `utxos(address)` | Returns structured UTxOs; only the cardano-cli adapter parses the SPO-Cutxo-IN-001 text form |
| `Ledger` | `parseUtxoText(raw, address)` *(new)* | The text-to-canonical-JSON conversion of `generate_UTXO`, kept inside the cardano-cli adapter; the canonical JSON also fills the transfer file |
| `Ledger` | `minOutputValue(output)` | `calc_minOutUTXO` (native) or `calc_minOutUTXOcli` (oracle) |
| `Ledger` | `addressInfo(address)` | The `.base16` bytes for SPO-Cutxo-EXT-002 |
| `Ledger` | `cborEncode(value)` *(new)* | Encoding primitives shared with Cconv |

Selecting UTxOs by reference (`filterFor_UTXO`) is plain domain logic on the `TxDraft` input set and needs no port.

## Port notes

* The text parser belongs only in the cardano-cli adapter. Domain code should hold structured UTxOs with exact integer amounts, and serialise to this JSON shape only for the transfer-file adapter.
* Compute `minOutputValue` from structured values, with exact integer arithmetic, and return an error when the address cannot be decoded (SPO-Cutxo-PRE-002).
* Resolve the encoding form from the protocol version, not from the node era string, so that an unknown era does not silently change the minimum (SPO-Cutxo-INV-007). If the oracle shows the ledger uses the array form, drop the map form altogether.
* Keep `calc_minOutUTXOcli` as a differential test oracle only.

## Open questions

* Which form does the ledger use for Babbage and Conway outputs: map or array? Run `calc_minOutUTXOcli`'s CLI call for a plain base-address output and for one with assets, and compare with SPO-Cutxo-INV-010's vectors.
* The result when neither `utxoCostPerByte`, `coinsPerUTxOByte` nor `utxoCostPerWord` is present: `$(( / 8 ))` is an arithmetic syntax error, and what bash does next is not specified in the source. A test against the real shell would settle it.
