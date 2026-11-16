# Recorded Koios responses

Recorded on 2026-11-16 with `curl` from the public Koios preview API
(`https://preview.koios.rest/api/v1`) and the hosted parameters file
(`https://uptime.live/data/cardano/parms/preview-parameters.json`). Only public
chain data was sent: pool ids and addresses found through `/pool_list` and
`/account_list`. Nothing is edited except as noted. Tests replay them through a
fake `http.RoundTripper`; no test touches the network.

| File | Request |
| --- | --- |
| `tip.json` | `GET /tip` |
| `epoch_params.json` | `GET /epoch_params?order=epoch_no.desc&limit=1` |
| `pool_list.json` | `GET /pool_list?limit=1` (source of the first pool id) |
| `pool_info_retired.json` | `POST /pool_info` `{"_pool_bech32_ids":["pool16h8ugt8k..."]}`: a retired pool with `op_cert_counter` 4 |
| `pool_info_registered.json` | the same for `pool1a7h89sr6...`: registered, counter 17 |
| `pool_info_unknown.json` | the same for a valid but never-registered pool id (`pool1qypqxpq9...`, bytes 1..28): Koios answers `[]` |
| `account_info_registered.json` | `POST /account_info` for a registered, delegated stake address |
| `account_info_unregistered.json` | the same for an unregistered one: Koios answers an element with `"status":"not registered"`, not `[]` |
| `pool_info_retiring.json` | `POST /pool_info` for `pool1pazw8u9t...` (found with `GET /pool_list?pool_status=eq.retiring&limit=2`): `pool_status` `retiring`, `retiring_epoch` 1484 (recorded 2026-11-16, epoch 1483) |
| `drep_info_registered.json` | `POST /drep_info` `{"_drep_ids":["drep1ygqqupvw653m83jgv5yftq83vp8px9u0thetaefcuxukyqcdjrjaa"]}` (found with `GET /drep_list?limit=5`): `drep_status` `registered`, deposit `"500000000"` |
| `drep_info_script.json` | the same for the script DRep `drep1yvps7mh8xnnnpw2m3nx695uysjey56xl9ysrel6uy3lq32cgwk0xs` (`has_script` true; found in `GET /drep_list?limit=2000`) |
| `drep_info_deregistered.json` | the same for `drep1ygqq33rjavhwwynp2pzj478fea67dxeelq2ylfwum0txhhqy8p3fn`: `drep_status` `deregistered`, `deposit` null |
| `drep_info_unknown.json` | the same for a valid CIP-129 id never registered (hash bytes 1..28): Koios answers `[]`. Koios also accepts the legacy `drep1...` form and echoes CIP-129 |
| `account_info_drep.json` | `POST /account_info` for `stake_test1ursa8keg...` (from `GET /drep_delegators?_drep_id=drep1ygqqupvw...`): `delegated_drep` is a key DRep id, `delegated_pool` null |
| `account_info_proposer.json` | the same for `stake_test1uql3k3v9...`, the return address of the proposal below: `delegated_drep` null |
| `proposal_list_open_none.json` | `GET /proposal_list?return_address=eq.stake_test1uql3k3v9...&dropped_epoch=is.null&enacted_epoch=is.null&expired_epoch=is.null&select=proposal_tx_hash,proposal_index,deposit,return_address,dropped_epoch,enacted_epoch,expired_epoch` (SPO-Clight-EXT-006): `[]` |
| `proposal_list_closed.json` | the same without the three `is.null` filters and with `&limit=2`: one proposal, expired in epoch 1483 |
| `address_utxos.json` | `POST /address_utxos?select=tx_hash,tx_index,value,asset_list,datum_hash,inline_datum,reference_script` with `_extended:true` |
| `utxo_info_unspent.json` | `POST /utxo_info?select=tx_hash,tx_index,address,value,asset_list,is_spent` with `{"_utxo_refs":["6b028c5a...#0"],"_extended":true}` (recorded 2026-11-16 from preview, the output of `address_utxos.json`): one row with `is_spent` false. Koios omits a reference it does not know from the answer (an unknown ref answers `[]`, checked by hand), so a missing row is Unknown, not None. A spent output was not recorded: the test derives it from this file by setting `is_spent` to true by hand. |
| `light_parameters.json` | `GET ...preview-parameters.json?rnd=<unix>` |
| `committee_info.json` | `GET /committee_info` (SPO-Clight-EXT-008): one element with `quorum_numerator` 2, `quorum_denominator` 3 and three members, each with `status` `authorized` and script cold and hot credentials (`cc_cold_has_script`, `cc_hot_has_script` true) |
| `proposal_list_kinds.json` | `GET /proposal_list?proposal_id=in.(<seven ids>)&select=proposal_tx_hash,proposal_index,proposal_type,proposal_description,deposit,return_address,proposed_epoch,expiration,meta_url,meta_hash,dropped_epoch,enacted_epoch,expired_epoch`: one expired proposal of each of the seven kinds (found with `GET /proposal_list?proposal_type=eq.<kind>&limit=3`). The `proposal_description.tag` of a committee update is `UpdateCommittee` while `proposal_type` says `NewCommittee`; a ParameterChange description is `[prev id or null, {camelCase parameter: value}, guardrails script]` |
| `proposal_votes_hardfork.json` | `GET /proposal_votes?_proposal_id=gov_action1lg4j2tyav3dnwmhx372w4pmkfkkk2y8zq9exjg0qedenzcw2dmuqql0r99d` (SPO-Clight-EXT-010): an enacted hard fork with three SPO, three ConstitutionalCommittee (script) and two DRep votes, newest first |
| `proposal_votes_constitution.json` | the same for `gov_action1x2j56d9k...`: one DRep abstain |
| `proposal_votes_info.json` | the same for `gov_action18uh2e6d...` (the InfoAction): `[]`, no votes |
| `proposal_voting_summary_info.json` | `GET /proposal_voting_summary?_proposal_id=gov_action18uh2e6d...` (SPO-Clight-EXT-011) |
| `proposal_voting_summary_constitution.json` | the same for `gov_action1x2j56d9k...` |
| `proposal_voting_summary_hardfork.json` | the same for the enacted hard fork `gov_action1lg4j2ty...`: non-zero percentages (`drep_yes_pct` 79.86, `pool_yes_pct` 52.23, `committee_yes_pct` 37.50) |

Governance reads, recorded 2026-11-16 (epoch 1483) with `curl` from the same API. `GET /tip` answers `era` `Conway`
(`Era`). `/proposal_votes` and `/proposal_voting_summary` take `_proposal_id` as a query parameter (a path of the
spec's form fails with `Query not Found`). `proposal_voting_summary` answered an empty body, not `[]`, for a proposal
Koios had no summary of; percentages are JSON numbers (`79.86`, `0.00`, `0`), powers are strings. The constitution and
the last enacted action ids are not read from Koios: upstream takes them from the light-mode parameters document
(`constitution`, `prevActionIDs`, SPO-25a-MODE-002), which is `light_parameters.json`. No endpoint was invented for the
DRep and pool stake distribution: upstream's light mode does not read them (SPO-24c-MODE-005).

No proposal was open on preview when these were recorded (the same query
with no `return_address` also answered `[]`), so the open-proposal tests
derive their row from `proposal_list_closed.json` by setting `expired_epoch`
to null in the test (hand-derived, not recorded). `account_info` also carries
`proposal_refund`; the adapter ignores it and follows Clight (the proposal
list).

Hand-derived, not recorded: the open-proposal rows of the governance tests are `proposal_list_kinds.json` with
`expired_epoch` and `dropped_epoch` set to null (and, in the end-to-end test, `expiration` moved to 1485 so the epoch-1483
tip still sees them open); the end-to-end test also points the info action's `meta_url` and `meta_hash` at a loopback
document and nulls the registered DRep's anchor, so no request leaves the machine. The vote-row cases with a voter in
several rows, every error case and every malformed-row case are hand-written in `governance_test.go`.

Not recorded (hand-written in the tests from the spec text): a UTxO carrying
native assets and datum flags, a pool with `op_cert_counter` null, and every
error case. The recorded data ages: `light_parameters.json` carries
`lastUpdate` 2026-11-16, so tests fix the clock instead of using `time.Now`.
To re-record, repeat the requests above and update the expected values in
`koios_test.go`.

ADA Handle (recorded 2026-11-16, Preview, public data): `handle_asset_addresses_cip68.json` and
`handle_asset_addresses_none.json` are `GET /asset_addresses` for the CIP-68 root `$........`
(asset name `000de140` + `2e2e2e2e2e2e2e2e`) and for its classic name (nobody holds it);
`handle_api_virtual_subhandle.json` is the Handle API's record of the virtual sub-handle `$00f@hal`
(`GET https://preview.api.handle.me/handles/00f@hal`) and `handle_asset_utxos_virtual.json` is
`POST /asset_utxos?select=inline_datum` for its asset name (`_extended` true), whose inline datum states
the same address the API does. The error cases are hand-written in `handles_test.go`.

Pool import (recorded 2026-11-16, preview): `pool_updates_registered.json` is
`GET /pool_updates?_pool_bech32=pool1a7h89sr6...` (the pool of `pool_info_registered.json`):
nine registration updates, newest first. The `PoolInfo` tests reuse `pool_info_registered.json`,
`pool_info_retiring.json`, `pool_info_retired.json` and `pool_info_unknown.json`; every other
case (null or absent `op_cert_counter`, malformed rows) is hand-edited in `poolimport_test.go`.
