+++
id = "23d"
kind = "script"
title = "Check a committee key hash on chain"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["governance", "chain-access"]
use_cases = ["CheckCommitteeKeyOnChain"]
depends_on = ["Cconf", "Clight", "Cconv", "Cui", "Pfiles"]

upstream_path = "cardano/mainnet/23d_checkComOnChain.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "d7d4753a6066fd792d9b46238c4cfe365e0ba342b3bdf891048f8795df8962cd"
upstream_lines = 229
uses_common = [
  "queryLight_committeeState",
  "showProcessAnimation",
  "stopProcessAnimation",
]
cli_commands = [
  "governance committee key-hash",
  "query committee-state",
]
hwcli_commands = []
signer_commands = []
http_endpoints = []
env_vars = []
+++

# 23d_checkComOnChain: Check a committee key hash on chain

Read-only lookup of a committee credential. The input is resolved to a 28-byte credential hash, and the chain is asked for committee members whose **cold** credential matches it or, when none does, whose authorised **hot** credential matches it. The script therefore answers both "is this cold key a member and which hot key is authorised?" and "which member does this hot key vote for?". It builds no transaction and writes no file.

Mode: online and light only. Offline mode is refused.

## Interface

- **SPO-23d-IF-001** Takes exactly one argument; any other count prints usage on stderr and exits 1. (src: L19-L26)
- **SPO-23d-IF-002** The argument is a 56-hex-digit credential hash, a bech32 committee id (see SPO-23d-IN-001), or a name that resolves to a file. A trailing `.hash` is dropped from the name. The argument is lower-cased for the id forms. (src: L19-L21, L41-L143)
- **SPO-23d-PRE-001** On a chain not yet in Conway era (configured era Shelley through Babbage) the script prints a notice and exits 0. (src: L28-L33)
- **SPO-23d-PRE-002** In offline mode the script refuses with exit 1 (online or light required). (src: L35-L36)

## Inputs

- **SPO-23d-IN-001** Resolution order, first match wins. (1) 56 hex digits: the hash. (2) A string starting `cc_cold1` or `cc_hot1` of length 59 or 58 (legacy, CIP-105): decoded by the bech32 tool, which prints the 28-byte hash as hex; an invalid bech32 exits 1. (3) A string starting `cc_cold1` or `cc_hot1` of length 62 or 61 (meant as CIP-129): decoded and its first byte (two hex digits, the header) removed. (4) A file `<name>.hash`, (5) `<name>.cc-cold.hash`, (6) `<name>.cc-hot.hash`: the content must be exactly 56 hex digits, otherwise exit 1. (7) A file `<name>.vkey`, (8) `<name>.cc-cold.vkey`, (9) `<name>.cc-hot.vkey`: the hash is `cardano-cli <era> governance committee key-hash --verification-key-file <file>`; a failure exits 1. (10) Otherwise exit 1. (src: L41-L143)
- **SPO-23d-INV-001** The id forms follow CIP-105 (legacy, 28-byte hash, hrp `cc_cold`/`cc_hot`) and CIP-129 (29 bytes: a header byte, `12` cold key, `13` cold script, `02` hot key, `03` hot script, followed by the hash; see the table of SPO-Cconv-OUT-019). The prefix test `cc_cold1`/`cc_hot1` matches key and CIP-129 ids of both kinds, but not the legacy script ids `cc_cold_script1` and `cc_hot_script1`. (src: L47, L56, L64)
- **SPO-23d-INV-002** The length tests are `59|58` for legacy and `62|61` for CIP-129. A CIP-129 `cc_cold1` id has 61 characters and a CIP-129 `cc_hot1` id has 60, so the `62` alternative never matches and a CIP-129 **hot** id is not recognised by rule 3; it falls through to the file rules and ends at rule 10 (exit 1). The same length arithmetic gives 59 and 58 for the legacy ids. (src: L47, L56)
- **SPO-23d-INV-003** The script does not distinguish cold from hot or key from script in the resolved hash: it queries both roles for the same hash (SPO-23d-EXT-001). A cold-versus-hot choice in the id's prefix, and a script header byte, are ignored after decoding. (src: L52, L64, L148-L149)

## Behaviour

1. **Resolve** as in SPO-23d-IN-001.
2. **Query the state.**
   - **SPO-23d-EXT-001** Online: requires no sync check; runs `cardano-cli <era> query committee-state --cold-verification-key-hash <hash> --cold-script-hash <hash>`. When the result's `committee` has no entries, runs a second query `... --hot-key-hash <hash> --hot-script-hash <hash>`. A failure of either query prints the error and exits **0** (status of the `echo` in `echo ...; exit $?`; L157 first, L163 second). The same hash is passed as key hash and script hash, so a match in either credential type is found. (src: L154-L165)
   - **SPO-23d-EXT-002** Light: calls `queryLight_committeeState <hash>`, which keeps the members whose cold or hot hash equals it (SPO-Clight-IN-003); a failure exits **0** in the same way (L170). (src: L167-L171)
     > **Upstream quirk:** a failed committee-state query looks like success to a caller. A port exits non-zero.
   - **SPO-23d-INV-004** The result's `committee` object is listed entry by entry in document order. An entry is keyed `keyHash-<hash>` or `scriptHash-<hash>`; the displayed cold hash is the last 56 characters of the key. (src: L177-L202)
3. **Report.**
   - **SPO-23d-PRE-003** When the state has no entries the script reports "0 entries" and "not on the chain" and exits 0. (src: L181-L185)
   - **SPO-23d-OUT-001** For each entry it displays: the cold hash (marked RESIGNED when the authorisation tag is `MemberResigned`), the authorising hot hash (`keyHash`, else `scriptHash`, else `-`), the status and the tag, the expiration epoch and the next-epoch change tag (`-` for absent values). The entry whose cold or hot hash equals the searched hash is highlighted. Display only. (src: L193-L225)

## Work modes

- **SPO-23d-MODE-001** Online and light as above; offline refused (SPO-23d-PRE-002). In light mode the status of every entry is the constant `Active` and `nextEpochChange` is `null` whatever Koios reports (SPO-Clight-OUT-019). (src: L35-L36, L152-L173)

## Prompts

No prompts.

## Outputs

No files are written. The result is the report; exit 0 also when nothing is found.

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Wrong argument count | 1 | SPO-23d-IF-001 |
| Pre-Conway era (configured) | 0 | SPO-23d-PRE-001 |
| Offline mode | 1 | SPO-23d-PRE-002 |
| Invalid bech32, bad hash file, unresolvable input, cardano-cli failure while hashing a vkey | 1 | SPO-23d-IN-001 |
| CIP-129 hot id (length 60) | 1 | SPO-23d-INV-002 |
| Query failure | **0** (status of the `echo`) | SPO-23d-EXT-001, SPO-23d-EXT-002 |
| Nothing found | 0 | SPO-23d-PRE-003 |

> **Upstream quirk:** the error message for a bad hash file says "not a valid Bech32 Committee-HASH" although the file must hold hex. Display only. (src: L75-L76)

## Security

No secrets are read or printed; only verification keys and hashes.

## Domain mapping

Use case `CheckCommitteeKeyOnChain(credentialRef)` on aggregate `CommitteeMember` (read side).

| Port | Operation | Purpose |
| --- | --- | --- |
| `Ledger` | `convertGovernanceId(id, form)` | CIP-105 and CIP-129 decoding, header byte removal |
| `Ledger` | `credentialHash(CommitteeCold \| CommitteeHot verification key)` *(new)* | `committee key-hash` for vkey inputs |
| `ChainQuery` | `committeeState({cold? \| hot?})` | Two-step node query, one Koios query |
| `Store` | `get(CommitteeHash / VerificationKey)` | File inputs |

## Port notes

* Accept every CIP-105 and CIP-129 spelling, including `cc_hot` CIP-129 ids and the script variants, and keep the credential type; query by credential, not by bare hash.
* Offline: serve the committee state from the transfer snapshot instead of refusing (see 23c).
* The hot-key search is a second round trip online; a native query can search both roles at once.

## Open questions

* None that source alone cannot settle. SPO-23d-INV-002 is arithmetic on bech32 lengths (28 bytes give 59 and 58 characters, 29 bytes give 61 and 60 for the `cc_cold` and `cc_hot` prefixes); a CIP-129 hot id on a real run would confirm it.
