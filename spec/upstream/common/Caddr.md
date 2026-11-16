+++
id = "Caddr"
kind = "common"
title = "Address inspection and ADA Handle resolution"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["wallet", "chain-access"]
use_cases = ["ResolveAdaHandle"]
depends_on = ["Cconf", "Cchain", "Clight", "Cconv", "Cui", "Cutxo"]

upstream_path = "cardano/mainnet/00_common.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "9490fae84352a491bbded9bd4a14587521336364f9814a2df5aff6b86266bfba"
upstream_lines = 2966

[functions]
check_address = "b4909805a1c2340004c7c7697b0e01768d968063fa803457d0c30693267913d1"
get_addressType = "81d9a26540f9997b1920230f22a30337ed050a9b60d0d5114a6bed44b3e83352"
get_addressEra = "630ff2ffdef572775b13a0acb56ddc3a0d7df227c2eeeeca79108e0904aac446"
checkAdaRootHandleFormat = "1f96912f8c6d1d79c754e109766e83d47a0366c5b304fd61bd410ec9f1444f73"
checkAdaSubHandleFormat = "4204850522955a30c3fbd8baa0df9fcd721b7ba811b51b66853e557c568208ef"
checkAdaHandleFormat = "ad493827d6804645684ee0af5ec2baf2114ee9879adbc28165a5870110959ac0"
resolveAdahandle = "e2dccd96b6150f80beefe878b72412b050b1f8a36043fab1747da5dcb94ae9be"
+++

# Caddr: Address inspection and ADA Handle resolution

Two small groups. The first asks cardano-cli what an address is (type and era) and refuses unknown formats. The second recognises ADA Handle names (`$name`, `$sub@name`) and **resolves a handle to the payment address that currently holds it**, with checks that the answer is trustworthy: the address is a payment address, the handle's native asset is really on that address, and for virtual sub-handles a second source (the on-chain datum) agrees with the Handle API. Handles resolve in online and light mode only.

## Address inspection

### check_address

Argument 1: an address in any format cardano-cli accepts.

- **SPO-Caddr-EXT-001** Runs `cardano-cli address info --address <addr>` (stderr discarded). The era argument is not used. (src: L718)
- **SPO-Caddr-PRE-001** When cardano-cli exits non-zero (unknown or malformed address) the function prints an error line on stdout and calls `exit 1`. Callers call it directly, so the whole script ends with status 1; the error is not on stderr. (src: L719)
- **SPO-Caddr-OUT-001** On success it returns 0 and writes nothing, except that an address whose `era` field is `byron` (any letter case) produces an informational line (display only) that Byron addresses are supported only as a destination. The function does not itself forbid Byron addresses; callers that need a shelley source address check the era with `get_addressEra`. (src: L720-L721)
- **SPO-Caddr-INV-001** It leaves the cardano-cli JSON in the shell-global variable `tmp`. Nothing relies on it. (src: L718)

### get_addressType

- **SPO-Caddr-OUT-002** Prints the `type` field of `cardano-cli address info --address <addr>` (the values the scripts rely on are `payment` and `stake`, see `addrTypePayment`/`addrTypeStake` in SPO-Cconf-INV-009). For an address the cli rejects it prints nothing. It always returns 0 and never exits, so an unknown address looks like an empty type. (src: L724-L726)

### get_addressEra

- **SPO-Caddr-OUT-003** Prints the `era` field (`shelley` or `byron` as far as the scripts use it) of the same cli output, nothing for an address the cli rejects; always returns 0 and never exits. (src: L728-L730)

## ADA Handle format checks

These three functions print nothing and signal by return code: 0 when the argument matches, 1 otherwise. They lowercase the argument first, so matching is case-insensitive. The argument must begin with a literal `$`.

- **SPO-Caddr-OUT-004** `checkAdaRootHandleFormat`: matches `$` followed by 1 to 15 characters of `[a-z0-9_.-]` and nothing else (a root handle, no `@`). (src: L735-L738)
- **SPO-Caddr-OUT-005** `checkAdaSubHandleFormat`: matches `$<part1>@<part2>` where each part is 1 to 15 characters of `[a-z0-9_.-]` (a sub or virtual handle). (src: L740-L743)
- **SPO-Caddr-OUT-006** `checkAdaHandleFormat`: matches either of the two forms above. (src: L745-L748)

## resolveAdahandle

Arguments: 1 = the handle (`$name` or `$sub@name`, any letter case), 2 = the **name of a shell variable** that receives the resolved address.

### Interface and contract

- **SPO-Caddr-IF-001** The handle is lowercased before any use. (src: L2067)
- **SPO-Caddr-IF-002** On success the resolved payment address is stored in the variable named by argument 2 (assigned at the caller's level). (src: L2296)
- **SPO-Caddr-OUT-007** On success, when the lookup went through the UTxO check (root handles and CIP-68 sub-handles), the global variable `utxo` additionally holds the cardano-cli style UTxO text of the resolved address (header, separator, rows), so the caller can skip its own UTxO query. For virtual sub-handles `utxo` is not set by this function. (src: L2155-L2158, L2226-L2229)
- **SPO-Caddr-INV-002** Every failure path prints a message on stdout and calls `exit 1`; there is no non-zero return. Callers call the function directly (not in `$(...)`), because the result travels through the named variable, so a failure ends the calling script with status 1. Success returns 0. (src: L2062, L2065, L2088, L2100, L2138, L2147, L2162, L2290)
- **SPO-Caddr-PRE-002** Offline mode: exits 1 immediately ("only supported in online and light mode"). No lookup is attempted and the transfer file is not consulted. (src: L2062)
- **SPO-Caddr-PRE-003** Exits 1 when `koiosAPI` is empty for the network, in every mode and for every handle kind. (src: L2065)
- **SPO-Caddr-PRE-004** Exits 1 when the (lowercased) handle matches neither the root nor the sub-handle format. (src: L2073, L2170, L2290)

Handle kinds and the path each takes:

| Kind | Format | Source of the holder | Verification |
| --- | --- | --- | --- |
| Root, classic (CIP-25) | `$name` | Koios `asset_addresses` for the asset name `hex(name)` | the asset is on a UTxO of that address |
| Root, CIP-68 | `$name` | Koios `asset_addresses` for the asset name `000de140` + `hex(name)` | the asset is on a UTxO of that address |
| Sub-handle, CIP-68 (on-chain) | `$sub@name`, API reports asset name starting `000de140` | Handle API | the asset is on a UTxO of that address |
| Sub-handle, virtual | `$sub@name`, API reports asset name starting `00000000` | Handle API | second opinion from the inline datum of the asset's UTxO (Koios) |
| Sub-handle, other asset-name prefix | `$sub@name` | Handle API | none (see quirk) |

`policy` below is `adahandlePolicyID` from the network profile (see Cconf endpoint table). `hex(name)` is the lowercase hexadecimal of the handle name's bytes without the leading `$`.

### Root handles

- **SPO-Caddr-EXT-002** Classic lookup: `GET <koiosAPI>/asset_addresses?_asset_policy=<policy>&_asset_name=<hex(name)>`, headers authorization (see SPO-Clight-INV-004), `Accept` and `Content-Type` JSON, 30-second timeout, retried up to 5 times on curl failure. (src: L2083)
- **SPO-Caddr-PRE-005** For both root lookups a transport failure after 5 attempts, a status other than 200 or a non-JSON body exits 1. A failure of the classic lookup does not fall back to the CIP-68 lookup. (src: L2088-L2103)
- **SPO-Caddr-INV-003** The classic lookup is accepted when the response array has exactly one element (one address holds the asset). Zero or more than one element means "not found as classic" and triggers the CIP-68 lookup. (src: L2106)
- **SPO-Caddr-EXT-003** CIP-68 lookup: the same request with `_asset_name` equal to `000de140` followed by `hex(name)`; same retry, status and JSON handling as the classic lookup. (src: L2108, L2115-L2135)
- **SPO-Caddr-PRE-006** Exits 1 ("could not resolve") when the CIP-68 lookup also does not return exactly one element. (src: L2138)
- **SPO-Caddr-INV-004** The resolved address is the `payment_address` of the first element. Asset quantity is not inspected. (src: L2143)

### Sub-handles and virtual handles

- **SPO-Caddr-PRE-007** Exits 1 when `adahandleAPI` is empty for the network (only Mainnet, PreProd and Preview have one). Root handles do not need it. (src: L2174)
- **SPO-Caddr-EXT-004** `GET <adahandleAPI>/handles/<handle without leading $>` (the name includes the `@`), headers `Accept` and `Content-Type` JSON, **no authorization**, 30-second timeout, retried up to 5 times on curl failure. (src: L2181)
- **SPO-Caddr-PRE-008** Status handling of the Handle API: `200` continues; `202` exits 1 ("found, but the API is not synced to the tip, try later"); `404` exits 1 ("not found"); any other status exits 1 with the API's `message` field and the status code. A transport failure after 5 attempts or an unreadable status exits 1. (src: L2186-L2202)
- **SPO-Caddr-INV-005** The resolved address is `resolved_addresses.ada` of the response; an invalid JSON body exits 1, an absent field is the text `null` and fails the payment-address check. The API's `hex` field is the handle's asset name. (src: L2205-L2206, L2215)

### Shared verification

- **SPO-Caddr-PRE-009** The resolved address must have address type `payment` (see `get_addressType`); otherwise exits 1 ("not a valid payment address"). This applies to root and sub-handles, before any holder check. (src: L2146-L2147, L2209-L2210)
- **SPO-Caddr-PRE-010** In online (full) mode the node must report `synced` (`get_currentSync`, see Cchain) before the holder UTxO is queried; otherwise exits 1. In light mode there is no sync check. For virtual sub-handles there is no sync check in either mode. (src: L2150, L2221)
- **SPO-Caddr-EXT-005** Holder UTxO query, by mode: online runs `cardano-cli <cliEra> query utxo --output-text --address <resolvedAddr>` with stderr merged into stdout; light calls `queryLight_UTXO` (see Clight). A failure exits 1 with the captured text. The result is stored in `utxo` (SPO-Caddr-OUT-007). (src: L2155-L2158, L2226-L2229)
- **SPO-Caddr-INV-006** Holder check: the handle is considered held when exactly one line of the UTxO text matches the pattern `<policy>.<assetNameHex> ` (policy, any single character, asset name hex, a trailing space). Zero lines, or more than one line, exit 1 ("address does not hold the handle"). `assetNameHex` is the name that matched: `hex(name)` for classic, `000de140` + `hex(name)` for CIP-68 roots, the API's `hex` for sub-handles. (src: L2162, L2233)

> **Upstream quirk:** The `.` in the pattern is a regular-expression wildcard, not a literal dot, and matching counts lines, not UTxOs; one UTxO holding the asset twice would still pass (an NFT is held once, so this is benign).

### Virtual sub-handles (asset name starts with `00000000`)

- **SPO-Caddr-EXT-006** Second opinion from Koios: `POST <koiosAPI>/asset_utxos?select=inline_datum`, headers authorization, `Accept`, `Content-Type` JSON, 30-second timeout, body `{"_asset_list":[["<policy>","<assetNameHex>"]],"_extended":true}`, retried up to 5 times on curl failure. (src: L2246)
- **SPO-Caddr-PRE-011** Exits 1 on transport failure, status other than 200, non-JSON body, or when the response array does not have exactly one element ("could not query asset_utxos"). (src: L2251-L2269)
- **SPO-Caddr-INV-007** The address in the datum is read from `inline_datum.bytes` (the hex of the CBOR datum): locate the key text `resolved_addresses` (hex `7265736f6c7665645f616464726573736573`), then the CBOR key `ada` plus a 57-byte byte-string header (hex `436164615839`), both taken at their last occurrence, and read the next 114 hex characters (57 bytes). Only 57-byte (base) addresses can be read this way. (src: L2272)
- **SPO-Caddr-INV-008** Those bytes are bech32-encoded with prefix `addr` when `magicparam` contains `mainnet`, else `addr_test`, using the `bech32` tool. (src: L2275-L2277)
- **SPO-Caddr-PRE-012** Exits 1 when that address differs from the Handle API's `resolved_addresses.ada` (including when nothing could be extracted). A match is the verification. (src: L2280-L2281)

### Unverified sub-handle prefix

- **SPO-Caddr-SEC-001** A sub-handle whose API-reported asset name starts with neither `000de140` nor `00000000` receives **no verification at all**: the Handle API's address (after the payment-type check) is returned as resolved. (src: L2216-L2288)

> **Upstream quirk:** That silent no-verification branch has no message and no error; the trust decision depends only on the Handle API.

### Other behaviour

- **SPO-Caddr-INV-009** Policy trust: only `adahandlePolicyID` of the network profile is used, both in the Koios queries and in the holder check. The API's own claims about its policy are not checked. (src: L2083, L2162, L2233, L2246)
- **SPO-Caddr-MODE-001** Online mode makes the Koios calls without a token (the authorization header is only set in light mode, see SPO-Cconf-MODE-004), uses the node for the holder UTxO, and requires a synced node for root and CIP-68 handles. Light mode makes the Koios calls with the configured token and uses Koios for the UTxOs. Offline mode refuses (SPO-Caddr-PRE-002). (src: L2062, L2150, L2155-L2158)

Display only: the progress animation while waiting, and the "Found $handle on Address" lines.

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| `check_address`: cli rejects the address | 1 | SPO-Caddr-PRE-001 |
| Offline mode | 1 | SPO-Caddr-PRE-002 |
| No Koios API for the network | 1 | SPO-Caddr-PRE-003 |
| Handle format invalid | 1 | SPO-Caddr-PRE-004 |
| Koios root lookup failed or non-200 or non-JSON | 1 | SPO-Caddr-PRE-005 |
| Neither classic nor CIP-68 root lookup unique | 1 | SPO-Caddr-PRE-006 |
| No Handle API for the network (sub-handles) | 1 | SPO-Caddr-PRE-007 |
| Handle API status 202, 404, or other | 1 | SPO-Caddr-PRE-008 |
| Resolved address not a payment address | 1 | SPO-Caddr-PRE-009 |
| Full-mode node not synced | 1 | SPO-Caddr-PRE-010 |
| Holder check failed | 1 | SPO-Caddr-INV-006 |
| Virtual-handle datum lookup failed | 1 | SPO-Caddr-PRE-011 |
| Datum address differs from the API address | 1 | SPO-Caddr-PRE-012 |

## Domain mapping

Use case `ResolveAdaHandle(handle) -> (address, utxos?)`, used by the wallet scripts (query, send lovelace, send assets) and Catalyst registration to accept a handle wherever an address is accepted.

| Port | Operation | Purpose |
| --- | --- | --- |
| `Ledger` | `addressInfo(address)` | `check_address`, `get_addressType`, `get_addressEra` |
| `Ledger` | `encodeAddress(bytes, network)` *(new)* | bech32 `addr` / `addr_test` from datum bytes |
| `Directory` | `resolveHandle(handle)` | Handle API call for sub and virtual handles |
| `ChainQuery` | `assetHolders(policy, assetName)` *(new)* | Koios `asset_addresses` for root handles |
| `ChainQuery` | `assetUtxos(policy, assetName)` *(new)* | Koios `asset_utxos` inline datum for virtual handles |
| `ChainQuery` | `utxos(address)` | Holder check, returned to the caller |
| `ChainQuery` | `syncStatus()` *(new)* | Full-mode sync gate |

## Port notes

* Return a typed `ResolvedHandle { address, kind, verifiedBy }` or a typed error instead of exiting; the caller decides what a failure means. Make `utxo` an explicit field of the result, not a global.
* Count UTxOs holding the asset exactly (asset quantity 1 at exactly one address) rather than matching text lines with a wildcard; use a literal separator.
* Verify unknown sub-handle prefixes or reject them rather than trusting the API silently (SPO-Caddr-SEC-001).
* A CIP-68 holder with a non-payment address (for example a script) is rejected today; keep that behaviour explicit and tested.
* The checks that the first query result is unique (SPO-Caddr-INV-003) hide ambiguity; report "ambiguous" separately from "not found".
* Offline handle resolution can be offered from a transfer-file snapshot made on an online machine; upstream refuses.
* Datum parsing by regular expression is brittle; decode the CBOR datum properly and support non-base addresses.

## Open questions

* The `type` and `era` strings cardano-cli prints for Byron, script-enterprise and pointer addresses are assumed to be `payment`/`stake`/`byron`/`shelley`; a recorded `address info` output per address kind from the release-set cli would settle the exact vocabulary.
* Whether the Handle API ever returns `resolved_addresses` for chains other than `ada`, or `202` for a handle that is otherwise resolvable, is a service question.

> **Observed 2026-11-16 (Preview, public data):** the Handle API's record of a virtual sub-handle (`$00f@hal`, asset name `000000003030664068616c`) and the inline datum of its asset's output (`asset_utxos`, `_extended` true) state the same address; the datum holds the map key `resolved_addresses` followed by `a1 43 616461 5839` and 57 address bytes, exactly the markers of SPO-Caddr-INV-007. A CIP-68 root (`$........`, asset name `000de1402e2e2e2e2e2e2e2e`) is held by one address at `asset_addresses`; its classic name is held by none. The port refuses a sub-handle whose asset name has neither label, or whose label is not followed by the handle's own name, instead of trusting the directory (SPO-Caddr-SEC-001); recorded in `spo/internal/adapters/koios/testdata`.
