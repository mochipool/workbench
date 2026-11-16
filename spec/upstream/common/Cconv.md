+++
id = "Cconv"
kind = "common"
title = "Asset names, governance ids, CBOR and ADA formatting"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["native-assets", "governance", "transaction-construction"]
use_cases = []
depends_on = ["Cutxo"]

upstream_path = "cardano/mainnet/00_common.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "9490fae84352a491bbded9bd4a14587521336364f9814a2df5aff6b86266bfba"
upstream_lines = 2966

[functions]
convert_tokenName2BECH = "500b30428c21c929325431e5875e780ab400e69ed4ea565d498baa285cdcf6e2"
convert_assetNameASCII2HEX = "2015a22bc62c91329f74e57ea91c1612f958a802d45accc82cf0c27d75dcade8"
convert_assetNameHEX2ASCII = "28f07b9293d02864a2e7541e5a0c66d53ee26c3e56704754fd18edc23d8d0647"
convert_assetNameHEX2ASCII_ifpossible = "9ad48be89d670947fca8658ad171a72b4559a73548ab2266d9e6b1bcf1e07e69"
convert_actionUTXO2Bech = "9400d896314fc24eb5af7545578f30574ae14b04b22a1cf6c75865df4ef1b8b6"
convert_actionBech2UTXO = "5b069972745d14fe3db3f6f59289a226e278d7af7a9e6f0235914ab6f661bb8b"
convert_actionBech2CIP129 = "41f456f090cf933aff69516d8316967fc01289904c7c6e6d67035472424572ad"
convert_actionCIP1292Bech = "137c686d51be92dc4a63a79f149346873745b32f828262b49ab36c86884ed35b"
to_cbor = "f34c8c744b0731b01309697faa38b87ab8085e00cb324747c6100f78b0203c03"
int_from_cbor = "66c1755366569f45e35995f774130c6b09e99d46a4903d0f483164afe1f98879"
convertToADA = "c0fc5d97966297987cf461593707954dfd35f13189f992c11707ced61ee927a1"
convertToShortADA = "2b39cdf79dc9b23cab478072f28bcbfeb99dc47d2ad5761fd07d8453d7d79ba9"
byteLength = "9534ab9df06087e90f4ab073cd1af46159b83509bdc1511420caa94770c4e50f"
+++

# Cconv: asset names, governance ids, CBOR and ADA formatting

Pure conversion helpers: asset-name hex and text forms, the CIP-14 asset fingerprint, CIP-129 governance identifiers, a small CBOR encoder and decoder, and lovelace-to-ADA formatting. They have no side effects. Two things need care when reimplementing. The CBOR encoder is the building block of the native minimum-output calculation ([Cutxo](./Cutxo.md)), and its size behaviour is normative there. The governance conversions defer the actual bech32 work to the external `bech32` binary (`${bech32_bin}`, default `./bech32`, L37), whose command-line contract is the following:

* `bech32 <hrp>` with hex on stdin prints the bech32 (BIP-173, not bech32m) string for that human-readable part and data.
* `bech32` with no argument and a bech32 string on stdin prints the data as lower-case hex.

Both print a trailing newline. A failure prints nothing on stdout (stderr varies per call below).

## to_cbor

`to_cbor <type> <value>` builds a CBOR fragment. It is used with `unsigned`, `bytes`, `array` and `map` by `calc_minOutUTXO`; the other types are implemented "for the future" and unused.

- **SPO-Cconv-OUT-001** `unsigned`: `value` is a decimal natural number, encoded as CBOR major type 0 with the shortest of these forms: below 24 one byte `0x00`-`0x17`; below 256 `0x18` plus one byte; below 65 536 `0x19` plus two bytes; below 2^32 `0x1A` plus four bytes; below 2^64 `0x1B` plus eight bytes. From 2^64 upward it is tag 2 followed by a byte string holding the big-endian bytes of the value (`0xC2`, then the SPO-Cconv-OUT-002 form), padded to an even number of hex digits. (src: L2332-L2339)
- **SPO-Cconv-OUT-002** `bytes`: `value` is a hex string. The output is a definite-length byte-string header (major type 2) followed by the hex unchanged: `0x40 + n` for `n` below 24; `0x58 n` below 256; `0x59 nn nn` below 65 536, where `n` is half the number of hex digits, rounded down. (src: L2343-L2347)
- **SPO-Cconv-OUT-003** `array`: `value` is the element count. The output is a definite-length header (major type 4): `0x80 + n` below 24; `0x98 n` below 256; `0x99 nn nn` below 65 536. No elements are written. (src: L2351-L2355)
- **SPO-Cconv-OUT-004** `map`: `value` is the pair count. The output is a definite-length header (major type 5): `0xA0 + n` below 24; `0xB8 n` below 256; `0xB9 nn nn` below 65 536. No pairs are written. (src: L2358-L2362)
- **SPO-Cconv-OUT-005** `tag`: `value` is the tag number. The output is a major-type-6 header: `0xC0 + n` below 24; `0xD8 n` below 256; `0xD9 nn nn` below 65 536. (src: L2381-L2385)
- **SPO-Cconv-OUT-006** `negative`: `value` is a negative number, or its absolute value, with every `-` character removed. It is encoded as major type 1 of `|value| - 1`, using the same width ladder as SPO-Cconv-OUT-001 with base `0x20`. From 2^64 it is tag 3 plus a byte string. (src: L2369-L2377)
- **SPO-Cconv-OUT-007** `string`: `value` is converted with `echo -ne`, so backslash escapes in it are interpreted, to its UTF-8 bytes. The output is a major-type-3 header (`0x60 + n`, `0x78 n`, `0x79 nn nn`, with `n` the byte count) followed by those bytes in hex. (src: L2388-L2393)
- **SPO-Cconv-OUT-008** The output is a single upper-case hex string without trailing newline. (src: L2399)
- **SPO-Cconv-PRE-001** Unsupported input produces an **empty output and status 0**, never an error: an unknown type; a `bytes`, `string`, `array`, `map` or `tag` size of 65 536 or more. A malformed `value` surfaces only as `bc` or arithmetic errors on stderr. (src: L2343-L2347, L2351-L2362, L2381-L2393, L2329-L2399)
- **SPO-Cconv-INV-001** Never calls `exit`; the status is that of the final `echo` (0). Encoding is definite-length only and has no 5-byte or 9-byte forms for lengths, counts and tags. (src: L2309-L2400)

> **Upstream quirk:** `bytes` does not validate its hex. An odd digit count is rounded down in the length header while the full string is still appended, so the fragment is malformed.

## int_from_cbor

- **SPO-Cconv-IF-001** `int_from_cbor <cborHex> [n]` decodes one unsigned integer from the start of the hex string, case-insensitively. With `n` greater than 0 it first skips `n` unsigned integers and decodes the one after them. (src: L2410-L2417, L2431-L2432)
- **SPO-Cconv-OUT-009** Accepted initial bytes are `00`-`17` (value in the byte), `18` (one more byte), `19` (two), `1A` (four) and `1B` (eight). On success it prints the decimal value without newline and calls `exit 0`. (src: L2421-L2425, L2429-L2430)
- **SPO-Cconv-PRE-002** Any other initial byte (another major type, or `1C`-`1F`) prints the **remaining upper-cased hex string from the point of failure** and calls `exit 1`. The output is not an error message. (src: L2426, L2433-L2434)
- **SPO-Cconv-INV-002** It always ends with `exit`, so it is only safe inside `$(...)`; with `n` greater than 0 it recurses in a subshell and exits with the inner status. Values of 2^63 and above are decoded by `printf %d` and are unreliable. (src: L2421-L2434)

> **Upstream quirk:** The first byte is compared as a **string** (`"0x$value" < "0x18"`), not as a number. For valid two-digit hex that coincides with numeric order, so the quirk is latent. A truncated hex string is not detected and decodes whatever the shell's `printf` makes of it. (src: L2421)

## convertToADA, convertToShortADA, byteLength

- **SPO-Cconv-OUT-010** `convertToADA <lovelace>` prints the amount divided by 10^6 with exactly six decimals and no trailing newline (`printf "%'.6f" "<n>e-6"`). The `'` flag adds the digit grouping of the current `LC_NUMERIC` locale, so `1234567890` prints `1,234.567890` in `en_US` and `1234.567890` in the C locale; the decimal separator is also locale-dependent. A non-numeric argument prints `0.000000` with status 1. Display only. (src: L2670-L2673)
- **SPO-Cconv-OUT-011** `convertToShortADA <lovelace>` prints a right-aligned, 10-character string: `<value> <unit>`. The unit is chosen from the first rule that holds: at least 10^15 lovelace gives `B₳` (value = lovelace / 10^15); at least 10^12 gives `M₳` (/10^12); at least 10^9 gives `k₳` (/10^9); at least 10^6 gives `₳` (/10^6); at least 10^3 gives `m₳` (/10^3). Otherwise it prints `0.000 ₳`. The value has exactly three decimals and is **truncated**, not rounded (`bc scale=3`). The text is left-padded with spaces to 10 characters; a longer string loses its left characters. A non-numeric or negative argument gives the `0.000 ₳` result. Display only. (src: L2677-L2692)
- **SPO-Cconv-OUT-012** `byteLength <string>` prints the number of UTF-8 bytes in the string, as `wc --bytes` does. It is used to check length limits on UTF-8 text. (src: L2697-L2699)

> **Upstream quirk:** `convertToShortADA` and `byteLength` pass the argument through `echo -n`, so an argument that consists only of echo options (`-n`, `-e`, `-E` and combinations) is swallowed. The padding step `${s: -10}` counts characters in a UTF-8 locale but bytes in the C locale, where the three-byte `₳` is cut. Neither is reachable with numeric input. (src: L2691, L2698)

## Asset names and the CIP-14 fingerprint

- **SPO-Cconv-OUT-013** `convert_tokenName2BECH <policyIdHex> [<assetNameAscii>]` prints the CIP-14 asset fingerprint: bech32 with human-readable part `asset` of the 20-byte BLAKE2b digest (160 bits) of the bytes `policyId || assetName`. Both arguments have leading and trailing spaces and tabs trimmed. The optional second argument is the asset name as **text**, converted to hex before hashing; when it is empty the first argument may already carry the name hex after the policy id. (src: L1151-L1159, L378-L381)
- **SPO-Cconv-OUT-014** `convert_assetNameASCII2HEX <text>` prints the lower-case hex of the text's bytes, on one line. (src: L1166-L1168)
- **SPO-Cconv-OUT-015** `convert_assetNameHEX2ASCII <hex>` prints the raw bytes the hex stands for, without newline. Non-printable bytes, including NUL, are written as they are. (src: L1174-L1176)
- **SPO-Cconv-OUT-016** `convert_assetNameHEX2ASCII_ifpossible <hex>` prints a display form of an asset name. It prints the hex unchanged when any byte-aligned byte is `00`. Otherwise it decodes the bytes and prints `.` followed by the text when every decoded character is alphanumeric (`[[:alnum:]]`, locale-dependent). In every other case it prints the hex unchanged. An empty name therefore prints `.`. The dot-prefixed form is the readable `policy.name` suffix used for display. (src: L1182-L1188)
- **SPO-Cconv-INV-003** None of these functions validates its input or calls `exit`. A bad hex string is handled as `xxd` handles it, and the status is that of the last command in the pipeline. (src: L1151-L1188)

> **Upstream quirk:** `convert_assetNameHEX2ASCII_ifpossible` decodes through `$(...)`, which strips trailing newline bytes. The name `6162630a` therefore prints `.abc` and loses the newline. (src: L1185-L1186)

## Governance action ids (CIP-129)

- **SPO-Cconv-IF-002** A governance action id is accepted by `convert_actionUTXO2Bech` only as `<64 hex digits>#<decimal digits>`. Any other form prints an error text on **stdout** and calls `exit 1`, which in a `$(...)` caller returns the error text as the value with status 1. (src: L1197, L1203-L1204)
- **SPO-Cconv-OUT-017** `convert_actionUTXO2Bech` prints, without newline, the bech32 string with human-readable part `gov_action` whose data is the 32 transaction-id bytes (lower-cased) followed by the action index as a big-endian integer in the **minimum number of whole bytes, at least one**: `0` is `00`, `255` is `FF`, `256` is `0100`. The result is the CIP-129 governance action id, which starts with `gov_action1`. Index text is evaluated as a shell arithmetic number. (src: L1198-L1202)
- **SPO-Cconv-OUT-018** `convert_actionBech2UTXO` is the inverse: given a string starting with `gov_action1`, it prints `<first 32 bytes as 64 hex digits>#<remaining bytes read as a big-endian integer, in decimal>`, without newline. Input that does not start with `gov_action1` ends with a silent `exit 1` and no output. (src: L1211-L1218)
- **SPO-Cconv-INV-004** The index conversions rely on `bc`, and `bech32` failures are not detected: an undecodable string yields `#` or `<hash>#` as the result with status 0. (src: L1214-L1218)

> **Upstream quirk:** The index is evaluated by `$(( idx + 0 ))`, and bash treats a leading `0` as octal. `#08` and `#09` therefore fail with an arithmetic error and `#010` means 8, although the code comment says it is meant to cope with `#00`, `#01`. The pattern `{64}+` also accepts hex runs whose length is a multiple of 64 in glibc, but only a length of exactly 64 is processed correctly. (src: L1197-L1199)

- **SPO-Cconv-OUT-019** `convert_actionBech2CIP129 <bech>` converts a legacy (CIP-105) identifier to its CIP-129 form: bech32 of the decoded hash with one header byte put in front. The header byte and output human-readable part are in the table below. (src: L1224-L1237)
- **SPO-Cconv-OUT-020** `convert_actionCIP1292Bech <bech>` is the inverse. It decodes the string, reads its first byte, and selects by that byte together with the **prefix** of the input string (for example `22drep`, `13cc_cold`). It prints the legacy bech32 string of the rest of the bytes (header removed) with the output human-readable part in the table. (src: L1242-L1255)

  | Legacy input prefix | Header byte | CIP-129 human-readable part | Legacy human-readable part |
  | --- | --- | --- | --- |
  | `cc_hot1` | `02` | `cc_hot` | `cc_hot` |
  | `cc_hot_script1` | `03` | `cc_hot` | `cc_hot_script` |
  | `cc_cold1` | `12` | `cc_cold` | `cc_cold` |
  | `cc_cold_script1` | `13` | `cc_cold` | `cc_cold_script` |
  | `drep1` | `22` | `drep` | `drep` |
  | `drep_script1` | `23` | `drep` | `drep_script` |

  The high nibble of the header byte is the credential role (0 hot, 1 cold, 2 DRep) and the low nibble the credential type (2 key hash, 3 script hash).
- **SPO-Cconv-PRE-003** Both functions refuse an input that does not match one of their table rows: they print `ERROR - cannot convert ...` on **stdout** and call `exit 1`. Pool ids are not handled despite the upstream comment. (src: L1234, L1252)

> **Upstream quirk:** A CIP-129 DRep or committee id starts with the same `drep1` / `cc_hot1` prefix as a legacy one. `convert_actionBech2CIP129` neither checks the hash length nor detects an input that is already CIP-129, and would prefix a second header byte. (src: L1228-L1233)

## Domain mapping

| Port | Operation | Purpose |
| --- | --- | --- |
| `Ledger` | `cborEncode(value)` *(new)* | `to_cbor` / `int_from_cbor`, shared with the native minimum-output calculation |
| `Ledger` | `assetFingerprint(policyId, assetName)` *(new)* | CIP-14 fingerprint (`convert_tokenName2BECH`) |
| `Ledger` | `convertGovernanceId(id, form)` *(new)* | CIP-129 and legacy conversion for action, DRep and committee ids |
| `UI` | `show(view)` | The ADA formatting functions are display only |

All are pure functions. A native library replaces the `bech32`, `xxd`, `b2sum` and `bc` dependencies.

## Port notes

* Implement the conversions with typed values: `Fingerprint`, `GovActionId(txId, index)`, `DRepId`, `CommitteeId` in both legacy and CIP-129 encodings, and parse `#<index>` as plain decimal (fixing the octal quirk).
* Return an error value instead of empty output for unsupported CBOR input.
* Format ADA with a fixed locale. A locale-dependent decimal separator is an upstream artefact.

## Open questions

* `int_from_cbor` for values of 2^63 or more and for truncated input depends on the shell's `printf`; only a run against bash settles it. Nothing in the tree decodes such values.
* Whether glibc accepts `{64}+` as "repeated 64-digit groups" (SPO-Cconv-IF-002) needs a test with a 128-digit input.
