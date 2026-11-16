+++
id = "Clight"
kind = "common"
title = "Light-mode queries (Koios) and transaction submission"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["chain-access"]
use_cases = []
depends_on = ["Cconf", "Cconv", "Cchain"]

upstream_path = "cardano/mainnet/00_common.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "9490fae84352a491bbded9bd4a14587521336364f9814a2df5aff6b86266bfba"
upstream_lines = 2966

[functions]
queryLight_protocolParameters = "956f531777b6e0d4dbb7b5b043f6c181a60f52d9eb88be6cbe189b0c845284fc"
queryLight_tip = "ec3fe5896a119ce3344a58058708274e01fb3e484f565c614f3e2549707aea94"
queryLight_epoch = "aa195dfcef06e8b414ba8f4aaa495b39fae9655856214e4d0f39b47605fe54f6"
queryLight_UTXO = "1e14ce72845c689255c4034e432d242c1521bdd619e91106336f7afcab61ff32"
queryLight_stakeAddressInfo = "77f8503e9427c8741adb8af4831c48932bfcd84611c579533d748ae4bcac5cc8"
queryLight_drepInfo = "1e9f7f0720d4b844976045a95bf11689fc25b97d3735ab98ba48d5dc8bc483cc"
queryLight_committeeState = "351ac68dad6842ac141c087cd0787942699864c907ced32f3582167c9c9c480e"
queryLight_actionState = "fe3516697ee7352a9408bebfb3318202f750a1921770af26523b1f7dd0380725"
queryLight_actionVotes = "46dc8c33cb6907ee0568aec85e84969a426ef3dac1bef7e63d17bfda20aa210d"
queryLight_actionVotesSummary = "11fc23e93686fe7bbebaa4c76e453eb7c5bb0b06269fdeef7003ec12f3095d7d"
submitLight = "c06794821c4f2da19b9c383daad06a83740da683bea3c819e5b6552c7571970a"
+++

# Clight: Light-mode queries (Koios) and transaction submission

In **light** work mode (see [Cconf](./Cconf.md)) the machine has no local node. Chain state comes from the Koios REST API and a hosted "light-mode parameters" file, and transactions are submitted through Koios. The ten `queryLight_*` functions each make one or two HTTP calls and **reshape the Koios answer into the text or JSON that the equivalent cardano-cli query prints**, so the calling scripts do not care which mode produced the data. An adapter that serves `ChainQuery` and `Submitter` from Koios must reproduce those shapes field by field; they are specified below. `submitLight` posts a signed transaction and returns its id.

All endpoints are relative to `koiosAPI` from the network profile (see SPO-Cconf-IN-005, SPO-Cconf-INV-007). Which networks have one is in the Cconf endpoint table.

## Shared behaviour

These apply to every function in this spec unless a function says otherwise.

- **SPO-Clight-INV-001** On any failure a function prints a human-readable message to **stdout** (not stderr) and calls `exit 1`. Callers invoke them as `x=$(queryLight_...)`, so `exit` ends only the substitution subshell; the caller receives the message in `x` and status 1, and typically passes it to `majorError`. A direct (non-substituted) call would end the calling script. (src: L402, L409, L415, L418, L443, L450, L456, L459, L1513, L1519, L1526, L1529, L2005, L2015, L2021, L2028, L2035)
- **SPO-Clight-INV-002** Transport retry: each HTTP call is attempted up to 5 times, and a retry happens only when curl itself fails (non-zero curl exit: DNS, connection, timeout). An HTTP error status is never retried. After the fifth failure the message says the query failed after 5 attempts. There is no delay between attempts, except in `queryLight_protocolParameters`, which sleeps 1 second after a curl failure. (src: L396-L402, L437-L443, L477-L483, L1507-L1513, L1551-L1557, L1586-L1592, L1661-L1667, L1719-L1725, L1819-L1832, L1908-L1914, L1960-L1966, L2009-L2015)
- **SPO-Clight-INV-003** The HTTP status is captured by appending a marker and the status code to the body (`-w "---spo-scripts---%{http_code}"`) and splitting on it. When the marker cannot be found the function exits 1. The expected status is `200` (submit: `202`); any other status exits 1 with a message that includes the status code. (src: L405-L416, L446-L457, L486-L497, L1515-L1527, L1560-L1571, L1595-L1606, L1670-L1681, L1728-L1739, L1835-L1846, L1917-L1928, L1969-L1980, L2017-L2029)
- **SPO-Clight-INV-004** Every Koios request carries the header value in `koiosAuthorizationHeader` (see SPO-Cconf-INV-021): `authorization: Bearer <token>` with a token in light mode, an empty value otherwise (curl sends nothing for an empty header). The light-mode parameter file request and the ADA Handle API request carry no authorization. (src: L439, L479, L1509, L1553, L1588, L1663, L1721, L1823, L1826, L1910, L1962, L2011)
- **SPO-Clight-INV-005** Except `submitLight`, the response body must parse as JSON, otherwise the function exits 1 ("not a JSON response"). A JSON body of the wrong shape is not detected unless a later jq step fails. (src: L417-L418, L458-L459, L498-L499, L1528-L1529, L1573-L1574, L1683-L1684, L1741-L1742, L1848-L1849, L1930-L1931, L1982-L1983)
- **SPO-Clight-INV-006** On success the result is written to stdout **without a trailing newline**. Callers capture it with `$(...)`. (src: L421, L462, L502, L1533, L1640, L1699, L1798, L1883, L1940, L1986, L2039)
- **SPO-Clight-INV-007** Request parameters (address, stake address, DRep id, proposal id) are placed into the URL or JSON body by plain string interpolation, with no validation and no escaping. Callers validate beforehand. (src: L1509, L1553, L1588, L1663, L1823, L1910, L1962)

> **Upstream quirk:** Most functions print their result with `printf "${result}"`, which uses the JSON as the printf *format string*. A `%` or a backslash sequence in a value (for example a percent-encoded anchor URL in a DRep record) is interpreted and can corrupt the output. `queryLight_actionState` uses `echo -ne`, which interprets backslash escapes (`\n`, `\\`). A port must emit the JSON verbatim. (src: L421, L462, L502, L1533, L1640, L1699, L1798, L1883, L1940, L1986, L2039)

> **Upstream quirk:** Koios pagination and row limits are not handled anywhere: each query reads one response. See Open questions.

## queryLight_protocolParameters

Fetches the hosted light-mode parameters file. It is called once by the prologue (see SPO-Cconf-EXT-001) and the result is kept for the whole run.

- **SPO-Clight-EXT-001** Sends `GET <lightModeParametersURL>?rnd=<current Unix seconds>` with `--compressed`, follow-redirects, 30-second timeout and the header `Cache-Control: no-cache, no-store`. The `rnd` parameter is a cache buster and is appended with `?` regardless of the URL. No Koios authorization. (src: L398)
- **SPO-Clight-IN-001** Takes no meaningful argument; an argument is lowercased into an unused variable. (src: L393)
- **SPO-Clight-OUT-001** On success prints the response re-formatted by `jq -r .` (pretty-printed JSON). The document is a cardano-cli protocol-parameters JSON that additionally contains an object `sposcriptsLightMode` with `lastUpdate` (date string), `magic` (network magic as text, `mainnet` for Mainnet), `versionCLI` (minimum cardano-cli version for light mode) and `lastTip.era`. Scripts pass the whole document to cardano-cli as the protocol-parameters file. (src: L417, L421)
- **SPO-Clight-PRE-001** Exits 1 with the URL and the status code in the message on any status other than 200 (see SPO-Clight-INV-003). (src: L415)

## queryLight_tip

- **SPO-Clight-EXT-002** Sends `GET <koiosAPI>/tip` with headers `Accept` and `Content-Type` set to `application/json` plus the authorization header, 30-second timeout. (src: L439)
- **SPO-Clight-OUT-002** Prints the `abs_slot` of the first element of the response array, as text. An empty array or absent field prints the text `null` and still succeeds. (src: L458, L462)

> **Upstream quirk:** The text `null` is returned as a successful tip; the callers then use it in arithmetic. A port should treat an absent `abs_slot` as an error.

## queryLight_epoch

- **SPO-Clight-EXT-003** Makes the same request as SPO-Clight-EXT-002 (`GET <koiosAPI>/tip`). (src: L479)
- **SPO-Clight-OUT-003** Prints the `epoch_no` of the first element of the response array, as text; `null` when absent. The JSON error message wrongly says "Query-Tip". (src: L498-L499, L502)

## queryLight_UTXO

Argument 1: a payment address (bech32).

- **SPO-Clight-EXT-004** Sends `POST <koiosAPI>/address_utxos?select=tx_hash,tx_index,value,asset_list` with headers authorization, `Accept` and `Content-Type` of `application/json`, 120-second timeout and body `{"_addresses":["<addr>"], "_extended": true}`. (src: L1509)
- **SPO-Clight-PRE-002** Status `504` exits 1 with a message that Koios took too long and that the full online mode may be used instead; any other non-200 status exits 1 with the code (see SPO-Clight-INV-003). (src: L1525-L1526)
- **SPO-Clight-OUT-004** Prints the cardano-cli `query utxo` text table: a first line `TxHash TxIx Amount`, a second line `---`, then one line per UTxO. The rows are sorted ascending by `tx_hash` (string order; rows with the same hash keep the response order). (src: L1528, L1530)
- **SPO-Clight-OUT-005** Each row is `<tx_hash> <tx_index> <value> lovelace` followed, for every entry of `asset_list` in response order, by ` + <quantity> <policy_id>.<asset_name>`, with a single trailing space at the end of the row. `value` and `quantity` are printed as received. `asset_name` is the hex name as Koios gives it. An asset with an empty name prints as `<policy_id>` without the dot (the text `. ` is replaced by a space). A UTxO without assets prints `<tx_hash> <tx_index> <value> lovelace ` only. Datum information is not printed. (src: L1528, L1530)
- **SPO-Clight-OUT-006** With no UTxOs (`[]`) the output is exactly the two header lines. Callers drop the two header lines to read rows. (src: L1528, L1530)

> **Upstream quirk:** A UTxO whose `asset_list` is `null` (not an array) makes jq fail, and the function reports "not a JSON response".

## queryLight_stakeAddressInfo

Argument 1: a stake address (bech32). Output is compatible with the `cardano-cli stake-address-info` JSON of cli 10.14, which scripts read directly.

- **SPO-Clight-EXT-005** First request: `POST <koiosAPI>/account_info`, headers authorization, `Accept` and `Content-Type` JSON, 30-second timeout, body `{"_stake_addresses":["<stakeaddr>"]}`. (src: L1553)
- **SPO-Clight-OUT-007** When the first element's `status` is not `registered`, prints `[]` and calls `exit 0` (success status, no second request). Called directly this would end the caller with status 0. (src: L1577)
- **SPO-Clight-EXT-006** Second request, only for registered accounts: `GET <koiosAPI>/proposal_list?return_address=eq.<stakeaddr>&dropped_epoch=is.null&enacted_epoch=is.null&expired_epoch=is.null&select=proposal_tx_hash,proposal_index,deposit,return_address,dropped_epoch,enacted_epoch,expired_epoch`, headers authorization and `Accept`, 30-second timeout. It lists the still-open governance actions whose deposit-return address is this account. (src: L1588)
- **SPO-Clight-OUT-008** Output for a registered account is the one-element array `[ { "address": <stake address>, "stakeDelegation": ..., "stakeRegistrationDeposit": ..., "rewardAccountBalance": ..., "voteDelegation": ..., "govActionDeposits": ... } ]` composed as text. (src: L1638)
- **SPO-Clight-OUT-009** `stakeDelegation` is `null` when `delegated_pool` is absent; otherwise `{ "stakePoolBech32": "<delegated_pool>", "stakePoolHex": "<bech32-decoded pool id as hex>" }`. (src: L1581, L1609)
- **SPO-Clight-OUT-010** `rewardAccountBalance` is `rewards_available` (number), default `0`. (src: L1581, L1638)
- **SPO-Clight-OUT-011** `stakeRegistrationDeposit` is the Koios `deposit` (number) or, when absent, `2000000` lovelace (the pre-Conway constant). (src: L1581, L1616)
- **SPO-Clight-OUT-012** `govActionDeposits` is an object mapping `"<proposal_tx_hash>#<proposal_index>"` to that proposal's `deposit`, merged over all returned proposals; `{}` when there are none. (src: L1612)
- **SPO-Clight-OUT-013** `voteDelegation` maps Koios `delegated_drep` as follows. A value beginning `drep1` is a CIP-129 id: it is first converted to the legacy form (CIP-129 header `22` gives a legacy `drep1...` id, header `23` gives `drep_script1...`, see Cconv `convert_actionCIP1292Bech`), and the original value is kept as `cip129Bech32`. Then: legacy `drep1...` gives `{ "cip129Bech32": <original>, "cip129Hex": "22<hash hex>", "keyHash": "<hash hex>" }`; `drep_script1...` gives `{ "cip129Bech32": <original>, "cip129Hex": "23<hash hex>", "scriptHash": "<hash hex>" }`; `drep_always_abstain` gives the JSON string `"alwaysAbstain"`; `drep_always_no_confidence` gives `"alwaysNoConfidence"`; anything else (including no delegation) gives `null`. `<hash hex>` is the bech32-decoded 28-byte hash. (src: L1619-L1636)

> **Upstream quirk:** A Koios `delegated_drep` that already is a legacy `drep_script1...` id does not start with `drep1`, so `cip129Bech32` is taken from a variable that was never set and is emitted empty (or stale from an earlier call in the same shell). (src: L1619, L1626-L1627)

> **Upstream quirk:** A governance deposit-return address held by a script credential is not distinguished anywhere in this function; see `queryLight_actionState` for the same gap.

## queryLight_drepInfo

Argument 1: a DRep id. Output imitates `cardano-cli conway query drep-state`.

- **SPO-Clight-IN-002** An id of exactly 56 characters (legacy `drep1...`) or 63 characters (legacy `drep_script1...`) is converted to CIP-129 form first (Cconv `convert_actionBech2CIP129`); other lengths, including a 58-character CIP-129 id, are used as given. (src: L1657)
- **SPO-Clight-EXT-007** Sends `POST <koiosAPI>/drep_info`, headers authorization and JSON `Accept`/`Content-Type`, 30-second timeout, body `{"_drep_ids":["<drepId>"]}`. (src: L1663)
- **SPO-Clight-OUT-014** When the first element's `drep_status` is not `registered`, prints `[]` and succeeds. (src: L1687-L1688)
- **SPO-Clight-OUT-015** For a registered DRep prints `[ [ { "<hashType>": "<hex>" }, { "anchor": { "url": "<meta_url>", "dataHash": "<meta_hash>" }, "deposit": <deposit>, "expiry": <expires_epoch_no>, "stake": <amount> } ] ]`. `hex` is the Koios `hex`; `hashType` is `keyHash` when `has_script` is exactly `false`, otherwise `scriptHash`; `deposit`, `expiry` and `stake` are the Koios `deposit`, `expires_epoch_no` and `amount`, with `null` when absent. (src: L1692-L1697)
- **SPO-Clight-OUT-016** When the DRep has no anchor, `url` and `dataHash` are the placeholder text `-` rather than `null`. (src: L1692, L1697)

> **Upstream quirk:** The cli emits `"anchor": null` for a DRep without an anchor; this function emits an anchor object with `-` placeholders.

## queryLight_committeeState

Argument 1 (optional): a committee credential hash (hex) used as a filter. Output imitates `cardano-cli conway query committee-state`.

- **SPO-Clight-EXT-008** Sends `GET <koiosAPI>/committee_info`, headers authorization and JSON `Accept`/`Content-Type`, 30-second timeout, no parameters. (src: L1721)
- **SPO-Clight-IN-003** When the filter is non-empty only members whose `cc_cold_hex` or `cc_hot_hex` equals it are kept; empty keeps every member of the first element's `members`. (src: L1745-L1749)
- **SPO-Clight-OUT-017** Output is `{ "epoch": <current epoch>, "threshold": <t>, "committee": { <entries> } }`. `epoch` comes from `get_currentEpoch` in the current mode (an extra call; in light mode another Koios `tip` request, see Cchain). (src: L1763)
- **SPO-Clight-OUT-018** `threshold` is `quorum_numerator / quorum_denominator` computed with two decimals by truncation (`scale=2`, for example 2/3 gives `0.66`), or `null` when either number is absent (the no-confidence state). (src: L1753-L1760)
- **SPO-Clight-OUT-019** Each committee entry is keyed `scriptHash-<cc_cold_hex>` when `cc_cold_has_script` is `true`, else `keyHash-<cc_cold_hex>`, with value `{ "expiration": <expiration_epoch>, "hotCredsAuthStatus": <s>, "nextEpochChange": null, "status": "Active" }`. `nextEpochChange` is always `null` and `status` is always `Active`, whatever Koios reports. (src: L1790, L1793)
- **SPO-Clight-OUT-020** `hotCredsAuthStatus` from the Koios `status`: `authorized` gives `{ "contents": { "scriptHash"|"keyHash": <cc_hot_hex> }, "tag": "MemberAuthorized" }` with `scriptHash` when `cc_hot_has_script` is `true`, else `keyHash`; `not_authorized` gives `{ "tag": "MemberNotAuthorized" }`; `resigned` gives `{ "tag": "MemberResigned" }`. (src: L1773-L1788)

> **Upstream quirk:** A member `status` outside those three leaves the status variable from the previous member (or empty on the first); an empty value makes the jq edit fail and the whole result becomes empty. (src: L1773-L1793)

> **Upstream quirk:** Expired members and members not yet enacted are reported as `Active` with no pending change, unlike the cli.

## queryLight_actionState

Arguments: 1 = governance action transaction id (hex), 2 = action index, 3 = optional voter id. Output imitates the entries of `cardano-cli conway query gov-state` `.proposals`, as a JSON array.

- **SPO-Clight-EXT-009** When argument 3 begins with `drep`, `cc_hot` or `pool` the request is `GET <koiosAPI>/voter_proposal_list?_voter_id=<voterId>&dropped_epoch=is.null&enacted_epoch=is.null&expired_epoch=is.null`; otherwise `GET <koiosAPI>/proposal_list?dropped_epoch=is.null&enacted_epoch=is.null&expired_epoch=is.null`. Headers authorization, `Accept` and `Content-Type` JSON, 30-second timeout. Only open (not dropped, enacted or expired) proposals come back. (src: L1821-L1828)
- **SPO-Clight-IN-004** When both argument 1 and argument 2 are non-empty, the result is filtered to the proposal with `proposal_tx_hash` equal to argument 1 and `proposal_index` equal to argument 2 (numeric comparison). (src: L1853-L1855)
- **SPO-Clight-OUT-021** Each proposal becomes `{ "actionId": { "govActionIx": <proposal_index>, "txId": <proposal_tx_hash> }, "dRepVotes": {}, "committeeVotes": {}, "stakePoolVotes": {}, "expiresAfter": <expiration - 1>, "proposedIn": <proposed_epoch>, "proposalProcedure": { "anchor": { "dataHash": <meta_hash>, "url": <meta_url> }, "deposit": <deposit>, "govAction": { "contents": <proposal_description.contents>, "tag": <proposal_description.tag> }, "returnAddr": <r> } }`. The three vote objects are empty; callers fill them from `queryLight_actionVotes`. (src: L1858)
- **SPO-Clight-OUT-022** `returnAddr` (the Koios `return_address`, a bech32 stake address) is replaced by a credential object: the address is bech32-decoded and its first byte (two hex characters) dropped, leaving the 28-byte hash. An address beginning `stake1` gives `{ "credential": { "keyHash": "<hash>" }, "network": "Mainnet" }`; one beginning `stake_test1` gives the same with `"network": "Testnet"`. (src: L1862-L1879)

> **Upstream quirk:** A return address that is a script credential is reported as `keyHash` (the source notes "scriptaddresses ???"). An address with neither prefix leaves an empty replacement; the jq edit fails and the whole result becomes empty.

## queryLight_actionVotes

Arguments: 1 = governance action transaction id, 2 = action index. Output is one JSON object that callers merge into an action-state entry.

- **SPO-Clight-EXT-010** The action id is converted to CIP-129 bech32 (`gov_action1...`) with Cconv `convert_actionUTXO2Bech`, then `GET <koiosAPI>/proposal_votes?_proposal_id=<gov_action id>` is sent with authorization and JSON `Accept`, 30-second timeout. (src: L1906, L1910)
- **SPO-Clight-OUT-023** Output is `{ "dRepVotes": {...}, "stakePoolVotes": {...}, "committeeVotes": {...} }` in that order, each `{}` when empty, built from the response rows: rows with `voter_role` `DRep` fill `dRepVotes`, `SPO` fill `stakePoolVotes`, `ConstitutionalCommittee` fill `committeeVotes`. The value is the row's `vote` (for example `Yes`). (src: L1935-L1937)
- **SPO-Clight-OUT-024** Keys: for `DRep` and `ConstitutionalCommittee` rows `scriptHash-<voter_hex>` when `voter_has_script` is true, else `keyHash-<voter_hex>`; for `SPO` rows the bare `voter_hex` (pool id). When one voter appears in several rows the later row wins. (src: L1935-L1937)

## queryLight_actionVotesSummary

Argument 1: the governance action id in CIP-129 bech32.

- **SPO-Clight-EXT-011** Sends `GET <koiosAPI>/proposal_voting_summary?_proposal_id=<id>` with authorization and JSON `Accept`, 30-second timeout. (src: L1962)
- **SPO-Clight-OUT-025** Prints the Koios response unchanged in content (re-formatted by `jq -r .`): the DRep, pool and committee voting tallies and percentages in Koios' own field names. No reshaping. (src: L1982, L1986)

## submitLight

Argument 1: path to a signed transaction file (cardano-cli text envelope).

- **SPO-Clight-IN-005** Reads the `cborHex` field of the file; an unreadable file exits 1. An absent `cborHex` is read as the text `null` and is not detected. (src: L2004-L2005)
- **SPO-Clight-EXT-012** Sends `POST <koiosAPI>/submittx` with headers authorization and `Content-Type: application/cbor`, 120-second timeout, and the **binary** transaction (the hex decoded to bytes) as the body. (src: L2011)
- **SPO-Clight-OUT-026** On HTTP `202` the body is the transaction id, possibly in quotes. The function strips every `"` and prints the id. (src: L2026, L2031, L2039)
- **SPO-Clight-PRE-003** Exits 1 when the id after quote removal is not exactly 64 hexadecimal characters. (src: L2034-L2036)
- **SPO-Clight-PRE-004** On HTTP `400` exits 1 with the Koios error body and advice to wait for the next block and retry; any other status other than `202` exits 1 with the code and the body. (src: L2027-L2028)
- **SPO-Clight-INV-008** A transport failure on submit is retried up to 5 times (SPO-Clight-INV-002); the same signed transaction is therefore sent again, which is harmless because submission is idempotent on the chain. (src: L2009-L2015)

## Failures

| Condition | Result | Id |
| --- | --- | --- |
| curl failed 5 times | message on stdout, exit 1 | SPO-Clight-INV-002 |
| Status marker missing in response | message, exit 1 | SPO-Clight-INV-003 |
| Status other than 200 (submit: 202) | message with code, exit 1 | SPO-Clight-INV-003 |
| Parameter file, status != 200 | message with URL and code | SPO-Clight-PRE-001 |
| UTxO query status 504 | message advising online mode | SPO-Clight-PRE-002 |
| Body not JSON | message, exit 1 | SPO-Clight-INV-005 |
| Stake account not registered | `[]`, exit 0 | SPO-Clight-OUT-007 |
| DRep not registered | `[]`, success | SPO-Clight-OUT-014 |
| Submit returned an invalid tx id | exit 1 | SPO-Clight-PRE-003 |
| Submit status 400 or other | exit 1 | SPO-Clight-PRE-004 |

## Domain mapping

The Koios adapter of `ChainQuery` and `Submitter` implements these. The reshaping is an adapter concern; the domain sees `ProtocolParameters`, `Utxo`, `RewardAccount`, `DRepState`, `CommitteeState`, `GovActionState`, `Votes`.

| Port | Operation | Upstream function |
| --- | --- | --- |
| `Directory` | `fetchUrl(lightModeParametersURL)` | `queryLight_protocolParameters` |
| `ChainQuery` | `protocolParameters()` | `queryLight_protocolParameters` (the same file carries `sposcriptsLightMode` metadata used by configuration) |
| `ChainQuery` | `tip()` (slot, epoch) | `queryLight_tip`, `queryLight_epoch` |
| `ChainQuery` | `utxos(address)` | `queryLight_UTXO` |
| `ChainQuery` | `rewardAccount(stakeAddress)` | `queryLight_stakeAddressInfo` (also open-proposal deposits) |
| `ChainQuery` | `drepState(drepId)` | `queryLight_drepInfo` |
| `ChainQuery` | `committeeState(filter?)` | `queryLight_committeeState` |
| `ChainQuery` | `govActionState(actionId?, voterId?)` | `queryLight_actionState` |
| `ChainQuery` | `votes(actionId)` | `queryLight_actionVotes` |
| `ChainQuery` | `votesSummary(actionId)` *(new)* | `queryLight_actionVotesSummary` |
| `Submitter` | `submit(signedTx) -> txId` | `submitLight` |

## Port notes

* Return typed results and errors (`HttpStatus`, `NotRegistered`, `Unavailable`) instead of text on stdout plus exit codes; the not-registered cases are an empty result, not an error.
* Emit JSON verbatim; do not repeat the `printf` format-string behaviour.
* Retry with backoff and only for transport failures and 5xx; add Koios pagination (see Open questions).
* Fix `nextEpochChange`/`status` for committee members, the `-` anchor placeholder, script-credential return addresses and the unset `cip129Bech32`.
* Keep the cli-compatible shapes behind the adapter so that online (cardano-cli) and light (Koios) adapters can be swapped and compared with a contract test per shape.
* The submit body is raw CBOR; the Koios token is a secret and must not be logged.

## Notes from recorded responses (2026-11-16, Koios preview)

Settled by recording real responses (`spo/internal/adapters/koios/testdata/`); no id changes.

* The light-mode parameters file (`preview-parameters.json`) has these fields beyond cardano-cli's: `sposcriptsLightMode.lastUpdate` is an RFC 1123 date with numeric zone (`Mon, 16 Nov 2026 09:51:02 +0100`), `magic` is the string `"2"`, `versionCLI` is `"10.14.0.0"`, and `lastTip` carries `block`, `epoch`, `era`, `hash`, `slot`, `slotInEpoch`, `slotsToEpochEnd` and `syncProgress`. The protocol-parameters part is cardano-cli's camelCase JSON (`txFeePerByte`, `txFeeFixed`, `utxoCostPerByte`, `stakeAddressDeposit`, `stakePoolDeposit`, `dRepDeposit`, `govActionDeposit`, `maxTxSize`, `maxValueSize`, `protocolVersion{major,minor}`, `minFeeRefScriptCostPerByte`, ...). This answers the second Open question.
* `/account_info` answers one element with `"status":"not registered"` for an unregistered stake address; it does not answer `[]`. SPO-Clight-OUT-007 therefore fires on the status text, and an empty array means Koios gave no answer. `delegated_drep` was seen as `drep_always_abstain`; amounts (`rewards_available`, `deposit`, `value`) are strings, `tx_index` is a number.
* `/pool_info` for a syntactically valid but never-registered pool id answers `[]`; for an id with a bad checksum it answers an error object (HTTP 400-class body with `code` and `message`). A pool with no block has `op_cert_counter` null (spec for SPO-04d-MODE-003); a retired pool keeps its counter.
* `/address_utxos` with `select=` returns only the selected columns; the port also selects `datum_hash`, `inline_datum` and `reference_script` to learn which outputs carry them. An empty `asset_list` is `[]`.
* `/epoch_params` (not used by upstream, which reads the hosted file) returns the same numbers: `min_fee_a`, `min_fee_b`, `coins_per_utxo_size`, `key_deposit`, `pool_deposit`, `drep_deposit`, `gov_action_deposit`, `max_tx_size`, `max_val_size`, `protocol_major`, `protocol_minor`, `min_fee_ref_script_cost_per_byte`; deposits are strings, the rest numbers.

## Open questions

* Koios applies a default row limit (commonly 1000) to list endpoints such as `address_utxos`, and upstream never pages. Whether an address with more UTxOs is silently truncated needs a live test with a large address.
* The exact shape of the light-mode parameters file beyond `sposcriptsLightMode` (the protocol-parameters part) is whatever the hosting service publishes; a recorded sample would settle it.
* Whether Koios returns `delegated_drep` for script DReps as a CIP-129 `drep1...` id or a legacy `drep_script1...` id (this decides whether the unset-variable quirk in SPO-Clight-OUT-013 is reachable).
