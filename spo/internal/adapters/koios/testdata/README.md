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
| `light_parameters.json` | `GET ...preview-parameters.json?rnd=<unix>` |

No proposal was open on preview when these were recorded (the same query
with no `return_address` also answered `[]`), so the open-proposal tests
derive their row from `proposal_list_closed.json` by setting `expired_epoch`
to null in the test (hand-derived, not recorded). `account_info` also carries
`proposal_refund`; the adapter ignores it and follows Clight (the proposal
list).

Not recorded (hand-written in the tests from the spec text): a UTxO carrying
native assets and datum flags, a pool with `op_cert_counter` null, and every
error case. The recorded data ages: `light_parameters.json` carries
`lastUpdate` 2026-11-16, so tests fix the clock instead of using `time.Now`.
To re-record, repeat the requests above and update the expected values in
`koios_test.go`.
