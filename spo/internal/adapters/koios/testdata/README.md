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
| `address_utxos.json` | `POST /address_utxos?select=tx_hash,tx_index,value,asset_list,datum_hash,inline_datum,reference_script` with `_extended:true` |
| `light_parameters.json` | `GET ...preview-parameters.json?rnd=<unix>` |

Not recorded (hand-written in the tests from the spec text): a UTxO carrying
native assets and datum flags, a pool with `op_cert_counter` null, and every
error case. The recorded data ages: `light_parameters.json` carries
`lastUpdate` 2026-11-16, so tests fix the clock instead of using `time.Now`.
To re-record, repeat the requests above and update the expected values in
`koios_test.go`.
