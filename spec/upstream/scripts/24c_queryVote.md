+++
id = "24c"
kind = "script"
title = "Query the voting state of governance actions"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["governance", "chain-access"]
use_cases = ["QueryGovernanceVotes"]
depends_on = ["Cconf", "Cchain", "Clight", "Cconv", "Cui", "Pfiles"]

upstream_path = "cardano/mainnet/24c_queryVote.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "8517dc25adb68139d2eddf7e44ba1de5cedd3e84ab6455ca999141a2974a5763"
upstream_lines = 1183
uses_common = [
  "checkError",
  "convertToADA",
  "convertToShortADA",
  "convert_actionBech2UTXO",
  "convert_actionUTXO2Bech",
  "exists",
  "get_currentEpoch",
  "get_currentSync",
  "majorError",
  "queryLight_actionState",
  "queryLight_actionVotes",
  "queryLight_actionVotesSummary",
  "queryLight_committeeState",
  "showProcessAnimation",
  "stopProcessAnimation",
  "versionCheck",
]
cli_commands = [
  "query committee-state",
  "query drep-stake-distribution",
  "query drep-state",
  "query gov-state",
  "query protocol-parameters",
  "query spo-stake-distribution",
]
hwcli_commands = []
signer_commands = [
  "verify",
]
http_endpoints = []
env_vars = []
+++

# 24c_queryVote: Query the voting state of governance actions

Read-only report on open governance actions. The operator filters by voter (DRep, committee hot key, pool, or a stake account that is the deposit-return address), by action id, by action type, or asks for all. For every matching action the script shows the proposal, the vote counts, and a **derived tally**: the approval percentage of each voting body, the ratification threshold that applies to this action type under the current protocol parameters, and whether the threshold is met. The derivation is the script's own model of ledger ratification and is the normative core of this spec (see *Derived tally*). It changes no state and needs no signing key. [24a](./24a_genVote.md) shows the same panel before it asks for a vote and the voting files it writes are consumed by [24b](./24b_regVote.md).

Online mode computes everything from the node; light mode takes the three percentages from Koios and computes only the thresholds locally. Offline mode is refused.

## Interface

- **SPO-24c-IF-001** Takes one or more words. With none it prints usage to stderr and exits 1. (src: L20-L59)
- **SPO-24c-IF-002** Words are classified left to right, first matching form wins (the forms are in SPO-24c-IF-003 to SPO-24c-IF-008). A word matching no form ends the script with exit 1 and a hint to use `all`. (src: L85-L92, L286-L288)
- **SPO-24c-IF-003** *Action id.* Either `<64 hex>#<digits>` (case-insensitive, lower-cased, the index normalised to a plain number) or a CIP-129 bech32 id starting `gov_action1` (converted with SPO-Cconv-OUT-018; a decoding failure exits 1). A second action id in the hex form exits 1; a second one in the bech form silently replaces the first. Giving an action id sets the light-mode voter filter to empty (see SPO-24c-MODE-003). (src: L90-L108)
- **SPO-24c-IF-004** *Voter by identifier.* A bare 56-hex-digit word is a voter hash of unknown type (type `Hash`); a second one exits 1. A bech32 DRep id (`drep1…` of 56 characters, `drep_script1…` of 63, or CIP-129 `drep1…` of 58, of which the last 56 hex digits are the hash) gives type `DRep`; a committee hot id (`cc_hot1…` 58, `cc_hot_script1…` 65, CIP-129 `cc_hot1…` 60) gives `Committee-Hot`; a pool id (`pool1…` of 56 characters) gives `Pool`. A bech32 string that fails decoding exits 1. For all of these the voter hash is the decoded hash, the key or script distinction in a CIP-129 header is dropped, and a later voter word silently replaces an earlier one. (src: L111-L182, L194-L200)
- **SPO-24c-IF-005** *Voter by file.* In this order: `<word>.drep.id` (a bech32 DRep id, read and decoded; type `DRep`), `<word>.cc-hot.hash` (56 hex digits, otherwise exit 1; type `Committee-Hot`), `<word>.pool.id` (56 hex digits, otherwise exit 1; type `Pool`), then `<word>.vkey` whose name ends `.drep`, `.cc-hot` or `.node` (any other ending exits 1), then `<word>.drep.vkey`, `<word>.cc-hot.vkey`, `<word>.node.vkey`. The hash of a verification key is blake2b-224 of its 32 key bytes, taken from `cborHex` after the 2-byte CBOR header (`cut -c 5-69`); an unreadable key or a result that is not 56 hex digits exits 1. The `.drep.id` form sets the light-mode voter id directly (`voterType="DRep"; voterID=<id>`, L154), so in light mode it acts like a bech32 DRep word (SPO-24c-MODE-003) and, unlike the other file forms, stays an active filter even when an action id is present, provided it comes after it. Its content is decoded **without** the CIP-129 trim that the bech words get (`${hash: -56}` at L141 and L181): a file holding a 58-character CIP-129 id yields a 58-hex-digit hash that never matches online. See SPO-Pfiles-OUT-018, SPO-Pfiles-OUT-024, SPO-Pfiles-OUT-027. (src: L145-L154, L185-L191, L203-L209, L212-L250)
- **SPO-24c-IF-006** *Deposit-return stake account.* A word beginning `stake` is taken as a bech32 stake address (a decoding failure exits 1) and a word `<word>.staking.addr` as a file holding one. The filter value is the decoded hash without its one-byte header. **Upstream quirk:** the `stake` test precedes the file tests, so a wallet name that merely begins with `stake` is never tried as a file and exits 1 as an invalid stake address. (src: L253-L272)
- **SPO-24c-IF-007** *Action type.* One of `HardForkInitiation`, `InfoAction`, `NewConstitution`, `NoConfidence`, `ParameterChange`, `TreasuryWithdrawals`, `UpdateCommittee`, case-insensitive. A second type word exits 1. (src: L275-L278)
- **SPO-24c-IF-008** *`all`.* Clears every filter (voter, action id, action type, light-mode voter id) and stops reading further words. (src: L281-L283)
- **SPO-24c-IF-009** Filters combine: voter, stake account, action id and action type may all be given; an entry must satisfy every one. (src: L325-L336, L464-L473)

## Inputs

- **SPO-24c-IN-001** Reads `<name>.drep.id`, `<name>.cc-hot.hash`, `<name>.pool.id`, `<name>.{drep,cc-hot,node}.vkey` and `<name>.staking.addr` as named in SPO-24c-IF-005 and SPO-24c-IF-006. Nothing else is read from the workspace. (src: L145-L272)
- **SPO-24c-IN-002** Needs the `cardano-signer` binary (path setting `cardanosigner`, falling back to `<scriptDir>/cardano-signer`) in online and light mode, at least the pinned minimum (SPO-Cconf-INV-008). A missing or too old binary stops the script (exit 1, via the fatal-error banner). It is only used for the display-only anchor check. (src: L295-L310)
- **SPO-24c-IN-003** Reads the era from the prologue; for `babbage`, `alonzo`, `mary`, `allegra` and `shelley` it prints that the chain is not yet in Conway and exits 0. (src: L65-L69)

## Behaviour

1. **Refuse offline.**
   - **SPO-24c-PRE-001** Offline mode exits 1: governance state cannot be read from the transfer file. (src: L62)
2. **Resolve filters.** As in SPO-24c-IF-002 to SPO-24c-IF-008. The resolved voter hash, when present, is displayed with its type. (src: L85-L292, L312)
3. **Read the governance state.**
   - **SPO-24c-MODE-001** *Online.* Requires the node to be synced (exit 1 otherwise, SPO-Cchain-OUT-004). Runs `cardano-cli <era> query gov-state`; a failure exits 1. The proposals are `.proposals[*]` values. (src: L317-L322)
   - **SPO-24c-MODE-002** *Online filter order,* each step narrowing the previous result: (a) when an action id was given, keep the proposal with that `actionId.txId` and `govActionIx`, and **exit 1** with a notice when none matches; (b) when a voter hash is set, keep proposals in which any key of `committeeVotes`, `dRepVotes` or `stakePoolVotes` **contains** the hash as a substring; (c) keep only proposals with `expiresAfter >= currentEpoch`, the epoch from `get_currentEpoch`; (d) the action type filter; (e) the deposit-return filter. **Upstream quirk:** the voter filter of (b) is `select( (.committeeVotes, .dRepVotes, .stakePoolVotes) | keys[] | contains(hash) )`, which emits the proposal once per matching key, so a credential that voted under two roles (the same key hash as DRep and as committee hot key) makes the proposal appear twice in the report and in the count. Also, an action that is on chain but already expired passes step (a) and is removed at step (c), so the script reports "no matching votes" with exit 0 instead of the exit 1 given for an unknown id. 24a applies the expiry filter first. (src: L324-L342, L464-L473)
   - **SPO-24c-MODE-003** *Light.* The open proposals come from Koios through `queryLight_actionState` (SPO-Clight-EXT-009, SPO-Clight-OUT-021), which already applies the action id and the voter id; there is no expiry filter because Koios lists only proposals that are not dropped, enacted or expired. The voter id handed to Koios starts as a placeholder `-`. A bech32 DRep, committee hot or pool id word sets it to that id; an action id word or `all` resets it to empty. Afterwards, only while the placeholder is untouched, a voter given by file or hash is converted to its bech32 id (`drep`, `cc_hot` or `pool` prefix by type), and a voter of type `Hash` is refused with exit 1 (hash filtering is unsupported in light mode); with no voter the id becomes empty. The action type and deposit-return filters of SPO-24c-MODE-002 (d) and (e) are applied afterwards, locally. **Upstream quirk:** whether the voter filter is active therefore depends on word order when a bech32 voter and an action id are both given, and a voter given by a `cc-hot.hash`, `pool.id` or verification-key file is silently unfiltered when an action id is present anywhere on the command line (the action id sets the voter id to empty and those file forms do not set it again). A `.drep.id` file is the exception, as it behaves like a bech32 DRep word (SPO-24c-IF-005). (src: L77, L96, L108, L123, L154, L405-L419, L463-L473)
- **SPO-24c-MODE-004** *Light, votes.* For each remaining proposal the votes are fetched separately with `queryLight_actionVotes` (SPO-Clight-OUT-023) and merged into the entry. (src: L520-L527)
   - **SPO-24c-INV-001** The deposit-return filter keeps proposals whose `returnAddr.credential.keyHash` equals the decoded hash of the given stake address. A proposal whose return account is a script never matches. (src: L469-L473)
   - **SPO-24c-INV-002** When no proposal remains the script prints "no matching votes" and exits 0 after the final blank line; there is no non-zero exit for an empty result. (src: L475-L478, L513, L1183)
4. **Gather the voting power inputs (online).**
   - **SPO-24c-EXT-001** Reads protocol parameters with `cardano-cli <era> query protocol-parameters`. The status is **not checked**: on failure the parameters are empty and every threshold reads 0 (SPO-24c-INV-004), so every test `pct >= 0` passes and every proposal is reported as accepted, while a `ParameterChange` exits 1 through SPO-24c-PRE-002. (src: L345)
     > **Upstream quirk:** a failed protocol-parameters query silently turns every vote into "accepted". A port stops with an error.
   - **SPO-24c-EXT-002** *Active DRep distribution.* `cardano-cli <era> query drep-state --all-dreps --include-stake`, keeping DReps whose `expiry >= currentEpoch`, as a list of `[ "drep-<keyHash|scriptHash>-<hex>", stake ]` with missing stake as 0. A failure of the query is **not detected**: the query is piped into `jq` and the script sets no `pipefail`, so the status tested at L351 is that of `jq`. After a failed query the distribution is empty, `A` is empty, the `bc` division of SPO-24c-OUT-001 fails and `dRepPct` silently becomes 0 (L566-L569). `A` (active DRep power) is the sum of all stakes in this list; the always-abstain and always-no-confidence pseudo-DReps are not in it. (src: L350-L354)
     > **Upstream quirk:** a failed `drep-state` query degrades the DRep tally to 0% without any error; only a failure of `gov-state` (L319) and of `spo-stake-distribution` (L362) exits 1. A port stops with an error.
   - **SPO-24c-EXT-003** `N` (always-no-confidence power) is `drep-alwaysNoConfidence` from `cardano-cli <era> query drep-stake-distribution --all-dreps`, or 0 when absent. A failure of the query is not detected (no status test, and the next `jq` runs on empty input), so `N` is then empty and the `bc` formulas of SPO-24c-OUT-001 fail. (src: L357-L358)
   - **SPO-24c-EXT-004** *Pool distribution.* `cardano-cli <era> query spo-stake-distribution --all-spos` (needs cardano-cli 10.2 or newer): a list of rows `[ poolId, stake, defaultDRep ]` in which the third element, when present, is the DRep delegation of the pool's reward account (`drep-alwaysAbstain`, `drep-alwaysNoConfidence`, or other). A failure exits 1. `P` (pool power total) is the sum of all stakes (0 when empty). (src: L362-L366)
   - **SPO-24c-EXT-005** *Committee.* `cardano-cli <era> query committee-state`; the active members are the entries whose `hotCredsAuthStatus.tag` is `MemberAuthorized` and `status` is `Active`. Each active member has power 1, identified as `<keyHash|scriptHash>-<hot hex>`. `T` (committee total) is the count of active members. Resigned, unauthorized and non-active members have no power and are not in `T`. A failure of the query is **not detected**: it is piped into `jq` and no status is tested, so `T` is empty and `committeePct` becomes 0 (SPO-24c-OUT-003, L619). (src: L369-L374)
     > **Upstream quirk:** a failed `committee-state` query shows the committee at 0% without any error. A port stops with an error.
   - **SPO-24c-EXT-006** *Committee threshold.* From `gov-state` `.committee.threshold`. Online, a number `t` gives `trunc2(100.00 * t)` and an object gives `trunc2(100.00 * numerator / denominator)` (L382, L386); in light mode the expressions are `bc "scale=2; 100 * ..."` without the `.00` (L442, L446), which gives the same results for typical inputs; `null` is the no-confidence state and is represented as `-1`; any other type exits 1. In light mode the same mapping applies to the threshold of the Koios committee info (SPO-Clight-EXT-008, SPO-Clight-OUT-018, which is already truncated to two decimals). `trunc2` is `bc` with `scale=2`. (src: L377-L397, L437-L456)
   - **SPO-24c-INV-003** Committee member display names come from the configuration table `ccMemberColdHashNames`, looked up by cold key, and are keyed by hot credential for display; an unknown member shows `Unknown?`. Display only. (src: L399-L400, L427-L428, L1156-L1165)

## Derived tally

For one proposal of type `tag`, with the votes `dRepVotes`, `stakePoolVotes`, `committeeVotes` (maps from voter key to a vote value containing `Yes`, `No` or `Abstain`), the script derives three percentages, a threshold per body, and an approval flag. All divisions are `bc` with `scale=2`: the quotient is **truncated** to two decimals, never rounded. An empty `bc` result (for example a zero denominator, whose error is discarded) is replaced by 0 for the DRep and pool percentages. Votes are counted by **substring** (`Yes`, `No`, `Abstain`), so the vote value spelling `VoteYes` or `Yes` both count. Every percentage is a percent number in 0 to 100.

- **SPO-24c-OUT-001** *DRep percentage, online.* Let `Y` and `Ab` be the summed stake, taken from the active distribution of SPO-24c-EXT-002, of the DReps whose key `drep-<key>` voted Yes and Abstain on this proposal (a voting DRep that is not in the active list adds 0). For every tag except `NoConfidence`, `dRepPct = trunc2(100.00 * Y / (A + N - Ab))`. For `NoConfidence`, `dRepPct = trunc2(100.00 * (Y + N) / (A + N - Ab))`. Non-voters and `No` voters are not subtracted: they stay in the denominator, and `N` is in the denominator but counts as a Yes only for `NoConfidence`. (src: L557-L571)
- **SPO-24c-OUT-002** *Pool percentage, online.* Let `Vy`, `Vn`, `Va` be the summed stake of the pools whose id voted Yes, No, Abstain on this proposal. Let the *not-voted rows* be the rows of the pool distribution whose pool id voted none of these; `NV` the sum of stake of the not-voted rows **excluding** rows whose default DRep is `drep-alwaysAbstain` or `drep-alwaysNoConfidence`; `NC` the sum of stake of the not-voted rows whose default DRep is `drep-alwaysNoConfidence` (0 when none). Then: for `NoConfidence`, `poolPct = trunc2(100.00 * (Vy + NC) / (NV + NC + Vy + Vn))`; for `HardForkInitiation`, `poolPct = trunc2(100.00 * Vy / (P - Va))`; for every other tag, `poolPct = trunc2(100.00 * Vy / (NV + NC + Vy + Vn))`. So a non-voting pool counts as No (it is in `P` or `NV`), a pool with a default abstain is dropped from the denominator except under `HardForkInitiation` (where it stays in `P` and so counts as No), and a pool with a default no-confidence counts as Yes only for `NoConfidence` and as No otherwise. (src: L573-L606)
- **SPO-24c-OUT-003** *Committee percentage, online.* Let `Cy`, `Ca` be the number of active members (SPO-24c-EXT-005) whose hot credential voted Yes and Abstain on this proposal; a vote cast by a credential that is not an active member adds nothing. `committeePct = 0` when `T - Ca = 0`, else `trunc2(100.00 * Cy / (T - Ca))`. (src: L608-L619)
- **SPO-24c-MODE-005** *Light percentages.* The three percentages are not computed: they are taken as given from the Koios proposal voting summary (SPO-Clight-EXT-011, SPO-Clight-OUT-025): `drep_yes_pct`, `pool_yes_pct`, `committee_yes_pct`, each defaulting to 0 when absent. The displayed powers come from the summary fields `drep_always_no_confidence_vote_power`, `pool_passive_always_no_confidence_vote_power`, `drep_yes_vote_power`, `drep_active_no_vote_power`, `drep_active_abstain_vote_power`, `pool_yes_vote_power`, `pool_active_no_vote_power`, `pool_active_abstain_vote_power`. The Koios summary is requested with the CIP-129 bech32 action id (SPO-Cconv-OUT-017). (src: L622-L651)
- **SPO-24c-INV-004** *Thresholds are read from the protocol parameters* (online: SPO-24c-EXT-001; light: the Light-Mode parameters document): `dRepVotingThresholds.<key>` and `poolVotingThresholds.<key>`, each a fraction such as `0.67`, defaulting to 0 when absent, converted with `trunc2(100.00 * v)`. The protocol major version is `protocolVersion.major` (-1 when absent). (src: L461, L841-L849, L886-L936, L960, L1017-L1026, L1036-L1042, L1109-L1112)
- **SPO-24c-INV-005** An *accept* test for a body is `pct >= threshold` as a `bc` numeric comparison of two-decimal numbers. The overall approval (`totalAccept`) collects one failure marker per participating body that fails; an `InfoAction` yields "N/A" and no other marker can override it. The overall result is N/A if any "N/A" is present, failed if any failure marker is present, passed otherwise. (src: L656-L658, L814-L822, L1168-L1173)
- **SPO-24c-OUT-004** *Which thresholds and bodies apply, per action type.* (src: L807-L1120)

  | Action type | DRep threshold key | Pool threshold key | Committee | Notes |
  | --- | --- | --- | --- | --- |
  | `InfoAction` | none (N/A) | none (N/A) | `committeePct >= committee threshold` unless no-confidence | overall result N/A: an info action can never be ratified |
  | `HardForkInitiation` | `dRepVotingThresholds.hardForkInitiation` | `poolVotingThresholds.hardForkInitiation` | tested | DRep test only when major version >= 10 |
  | `ParameterChange` | maximum over the matching groups (see SPO-24c-OUT-005) | `poolVotingThresholds.ppSecurityGroup`, only when the change touches a security-group parameter | tested | DRep test only when major version >= 10 |
  | `NewConstitution` | `dRepVotingThresholds.updateToConstitution` | none, pools are not tested | tested | |
  | `UpdateCommittee` | `committeeNormal` when a committee exists, else `committeeNoConfidence` | same keys in `poolVotingThresholds` | not tested | the committee cannot vote on this |
  | `NoConfidence` | `dRepVotingThresholds.committeeNoConfidence` | `poolVotingThresholds.committeeNoConfidence` | not tested | see the quirk below |
  | `TreasuryWithdrawals` | `dRepVotingThresholds.treasuryWithdrawal` | none | tested | |

  Where the committee is tested: in the no-confidence state (committee threshold `-1`) the committee body adds a failure marker for every type except `InfoAction`, because without a committee nothing can pass; for `InfoAction` it just shows no icon. When the major version is below 10 the DRep test of `HardForkInitiation` and `ParameterChange` is skipped and the DRep row shows dashes. **Upstream quirk:** for `NoConfidence` the script reads the `committeeNoConfidence` thresholds. The `motionNoConfidence` keys, which the protocol parameters also carry, are never read by 24a or 24c. Whether `committeeNoConfidence` is what the ledger applies to a `NoConfidence` action is not settled here; see *Open questions*.
- **SPO-24c-OUT-005** *ParameterChange groups.* The proposed parameter update (`govAction.contents[1]`) is rendered to JSON text and tested by glob for the substrings below, **all** groups being tested in turn (a parameter can belong to several). Each matching group raises the DRep threshold to `max(current, dRepVotingThresholds.<groupKey>)`, starting from 0. (src: L877-L919)

  | Group | Substrings | Effect |
  | --- | --- | --- |
  | Security | `maxBlockBodySize`, `maxTxSize`, `maxBlockHeaderSize`, `maxValueSize`, `maxBlockExecutionUnits`, `txFeePerByte`, `txFeeFixed`, `utxoCostPerByte`, `govActionDeposit`, `minFeeRefScriptCostPerByte` | pools must vote; pool threshold `ppSecurityGroup`; no DRep key |
  | Network | `maxBlockBodySize`, `maxTxSize`, `maxBlockHeaderSize`, `maxValueSize`, `maxTxExecutionUnits`, `maxBlockExecutionUnits`, `maxCollateralInputs` | DRep key `ppNetworkGroup` |
  | Economic | `txFeePerByte`, `txFeeFixed`, `stakeAddressDeposit`, `stakePoolDeposit`, `monetaryExpansion`, `treasuryCut`, `minPoolCost`, `utxoCostPerByte`, `executionUnitPrices` | DRep key `ppEconomicGroup` |
  | Technical | `poolPledgeInfluence`, `poolRetireMaxEpoch`, `stakePoolTargetNum`, `costModels`, `collateralPercentage` | DRep key `ppTechnicalGroup` |
  | Governance | `govActionLifetime`, `govActionDeposit`, `dRepDeposit`, `dRepActivity`, `committeeMinSize`, `committeeMaxTermLength`, `VotingThresholds` | DRep key `ppGovGroup` |

- **SPO-24c-PRE-002** When the group scan leaves the DRep threshold at 0 or empty, the script prints an internal error and exits 1, even though the proposal is valid. This happens for a change containing only parameters absent from the DRep groups (for example only `minFeeRefScriptCostPerByte`) and when the selected group threshold is itself 0. **Upstream quirk:** the matching is by substring on the whole update text, so a parameter value or a nested key can also match. (src: L920-L925)
- **SPO-24c-OUT-006** For each proposal the report gives: the CIP-129 bech32 action id (SPO-Cconv-OUT-017), type, proposed-in epoch, expiry epoch, anchor URL and hash, the deposit-return account, the action content (previous action id, and per type the target version, parameter changes, new constitution anchor and guardrail script, committee changes with new threshold, or treasury withdrawals), the vote counts per body (number of votes with Yes, No, Abstain), the powers (online: `Y`, `No`, `Ab`, `N`; for pools `Vy`, `Vn`, `Va`, `NC`), the percentages, thresholds and accept flags of SPO-24c-OUT-001 to SPO-24c-OUT-005, the committee members by name per vote, and an alert in the no-confidence state. The vote counts are derived by substring: a vote counts as Yes, No or Abstain when its text contains `Yes`, `No` or `Abstain` (`with_entries(select(.value | contains(...))) | length`). (src: L530-L548, L563-L1176)
- **SPO-24c-OUT-007** When a voter hash is set, the answer of that voter on each proposal is looked up as `dRepVotes[keyHash-<h>]`, else `committeeVotes[keyHash-<h>]`, else the `scriptHash-<h>` forms of both, else `stakePoolVotes[<h>]`, and shown as YES, NO or ABSTAIN by testing the substrings `Yes`, then `No`, then `Abstain`; no answer shows nothing. (src: L1123-L1132)
- **SPO-24c-OUT-008** The deposit-return account is converted to a bech32 address by prefixing the header byte `e1` (mainnet key), `e0` (testnet key), `f1` (mainnet script) or `f0` (testnet script) to the 28-byte hash and encoding with the human-readable part `stake` or `stake_test`. A network value other than Mainnet and Testnet, or a failed encoding, exits 1. For treasury withdrawals the same applies to each withdrawal target; an entry without target network means "paid directly to the deposit-return account". (src: L763-L788, L1056-L1094)
- **SPO-24c-EXT-007** *Anchor check, display only.* In online and light mode, for every proposal with an anchor URL: downloads the document (an `ipfs://<cid>` URL is fetched as `https://ipfs.io/ipfs/<cid>`; `curl` with 30-second timeout, 10 MB maximum, up to 5 attempts with a 1-second pause), expects HTTP 200 and JSON, computes its blake2b-256 hash and compares it with the on-chain hash, then runs `cardano-signer verify --cip100 --data-file <file> --json-extended` and lists author signatures. It also reads `body.title`, `body.onChain.depositReturnAddress` and the sum of `body.onChain.withdrawals[].withdrawalAddress` for comparison with the on-chain values. `cardano-signer verify` runs only when the content hash matches the on-chain hash. Every download, status, JSON and hash failure here is shown and continues without changing the exit status; the exception is `checkError` after `touch` and after `b2sum` (L681, L717), which can end the script with the failing command's status. The temporary file is created before the download and is removed only on the HTTP-200 path (L712, L736); after a 404, another status or a failed download it stays in `<tempDir>`. (src: L674-L759, L790-L802)

## Work modes

- **SPO-24c-MODE-006** Online and light are supported and differ as in SPO-24c-MODE-001 to SPO-24c-MODE-005: gov-state and the node's stake distributions versus Koios proposals, votes and summary. Offline is refused (SPO-24c-PRE-001). (src: L62, L315-L457)

## Prompts

No prompts.

## Outputs

Read-only. No file is written except a temporary download of each anchor (`<tempDir>/actionAnchorUrlContent.tmp`), deleted after the check of an HTTP-200 answer; after any other outcome it stays (SPO-24c-EXT-007). Output is a report on stdout; the structured content of that report is given by SPO-24c-OUT-006 to SPO-24c-OUT-008.

**Upstream file contract:** none, except the temporary file above.

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| No arguments | 1 | SPO-24c-IF-001 |
| Word matches no form; second action id (hex), voter hash or action type | 1 | SPO-24c-IF-002 to SPO-24c-IF-007 |
| Bech32 or hash file content invalid; unreadable vkey | 1 | SPO-24c-IF-003 to SPO-24c-IF-006 |
| Offline mode | 1 | SPO-24c-PRE-001 |
| Chain pre-Conway | 0 | SPO-24c-IN-003 |
| Node not synced (online) | 1 | SPO-24c-MODE-001 |
| Query of gov-state or spo-stake-distribution fails | 1 | SPO-24c-MODE-001, SPO-24c-EXT-004 |
| Query of drep-state, protocol-parameters, committee-state or drep-stake-distribution fails | none: not detected, the tally degrades (DRep 0%, thresholds 0, committee 0%) | SPO-24c-EXT-001, SPO-24c-EXT-002, SPO-24c-EXT-003, SPO-24c-EXT-005 |
| Action id not in gov-state (online) | 1 | SPO-24c-MODE-002 |
| Voter of type `Hash` in light mode | 1 | SPO-24c-MODE-003 |
| Light query (Koios) fails | 0 (the exit status is that of the preceding `echo`) | SPO-24c-MODE-003 |
| Committee threshold of unknown JSON type | 1 | SPO-24c-EXT-006 |
| ParameterChange threshold resolves to 0 | 1 | SPO-24c-PRE-002 |
| Deposit-return or withdrawal address cannot be encoded | 1 | SPO-24c-OUT-008 |
| `cardano-signer` missing or too old | 1 | SPO-24c-IN-002 |
| Nothing matches | 0 | SPO-24c-INV-002 |

## Security

No secret material is read or written.

- **SPO-24c-SEC-001** The anchor download fetches an operator-controlled URL and an `ipfs.io` gateway; the downloaded text is untrusted: it is displayed and parsed with `jq` but never executed, and a hash mismatch is displayed and not fatal. (src: L692-L757)

## Domain mapping

Use case `QueryGovernanceVotes(filter)` returns, per open action, a `GovernanceActionStatus` made of the `Proposal`, its `Vote`s, and a `RatificationEstimate` computed by the domain service `GovernanceTally` (SPO-24c-OUT-001 to SPO-24c-OUT-005).

| Port | Operation | Purpose |
| --- | --- | --- |
| `ChainQuery` | `govActionState(actionId)` / `govActions()` *(new)* | open proposals with votes, expiry |
| `ChainQuery` | `votes(actionId)` | light mode votes |
| `ChainQuery` | `drepStakeDistribution(includeStake)` *(new)* | active DRep power and always-no-confidence power |
| `ChainQuery` | `spoStakeDistribution()` *(new)* | pool power with default DRep per pool |
| `ChainQuery` | `committeeState()` | active authorized members and threshold |
| `ChainQuery` | `protocolParameters()` | thresholds, major version |
| `ChainQuery` | `voteSummary(actionId)` *(new)* | Koios summary used in light mode |
| `ChainQuery` | `tip()` | current epoch for expiry |
| `Directory` | `fetchUrl(url)` | anchor document |
| `Ledger` | `verifyCip100(document)` *(new)* | anchor author signatures (cardano-signer) |
| `Ledger` | `addressInfo(address)` | encode stake address from hash and network |
| `Store` | `get(DRepId \| CommitteeHotHash \| PoolId \| StakeAddress)` | voter and account resolution |

## Port notes

* Do the arithmetic in exact rational numbers and decide rounding once, at display; truncation to two decimals before the threshold comparison can flip a result at the boundary (for example 66.666 shown as 66.66 against a 66.67 threshold).
* The tally is an estimate: the ledger ratifies at an epoch boundary on a stake snapshot, while this derivation uses the live distribution. A port should label it as an estimate.
* Treat `committeeNoConfidence` for `NoConfidence` (SPO-24c-OUT-004), the missing `minFeeRefScriptCostPerByte` in the DRep groups, and the substring group matching of SPO-24c-OUT-005 as defects to settle against the ledger's actual rules, and decide group membership from the changed parameter names, not from rendered text.
* Failed light-mode queries should exit non-zero.
* The voter filter by substring (SPO-24c-MODE-002) is better as an exact key match.

## Open questions

* Whether the ledger's threshold for a `NoConfidence` action is `motionNoConfidence` (this script reads `committeeNoConfidence`). Settle against the Conway ledger specification and a live `ratification` result for such an action.
* Exact column layout and the shape of the `spo-stake-distribution` rows (the script indexes element 2 as the default DRep). Settle with a captured `cardano-cli 11` output.
* `bc` semantics of `100.00 * t` when `t` has more than two decimals: bc multiplication keeps the larger operand scale, so the comparison may use more than two decimals for a committee threshold given as a long decimal number. Settle by running the expression in GNU bc.
