# Air-gap fixtures

Recorded on 2026-11-16 from the live public services of the Cardano preview
network, with the pinned upstream scripts (`spo-scripts` Update-2026-04,
cardano-cli 11.2.3.0) in a light-role workspace. Only public data is in them.

| File | What it is |
| --- | --- |
| `exchanges.json` | Every request the scripts made to the two third-party services and the answer, byte for byte: the light-mode parameters file (`GET /params.json`, from `uptime.live`), the Koios tip, `address_utxos`, `account_info` and `proposal_list`. |
| `new.json` | `offlineTransfer.json` after `01_workOffline.sh new`. |
| `add_payment.json` | after `01_workOffline.sh add w` (the payment address below: 9 UTxOs, one asset). |
| `add_stake.json` | after `01_workOffline.sh add w.staking` (a registered stake address that is delegated, has rewards and votes always-abstain). |

Addresses: `addr_test1qp75ksqk2kzqrnvtac5nrerhffygdrgwnyg84hwtlnke7ftps0dzgscfxwag3pv57ezwq9xllhasn0pcrz8wsa9u5xtqjk3u25`
and `stake_test1uqeezcegh25rcskmmn0gy5fzenczfj34n8qeefhmz6taeycqg9wts` (both taken from the public chain; neither is ours).

## How they were recorded

`TestRecordAirgapFixtures` (`../../workoffline_test.go`) starts a loopback
proxy that forwards to the real services and records every exchange. The
workspace's `[scripts]` table points `koiosAPI` and `lightModeParametersURL`
at the proxy, so the real scripts ran against the real services through it:

```sh
S=<scratch>; source $S/env.sh          # SPO_PARITY_WORKBENCH, SPO_TOOLCHAIN
cd spo/test/parity
SPO_PARITY_RECORD_AIRGAP=$PWD/testdata/airgap go test -count=1 -run TestRecordAirgapFixtures .
```

`01_workOffline.sh new`, `add w` and `add w.staking` were run, in that order,
and the file was copied after each.

## How the tests use them

* `TestWorkOfflineSnapshotMatchesRecordedUpstream` needs no tools and no
  network. The Go `NewSnapshot` and `AddAddress` read the recorded exchanges
  (through the Koios adapter's and the light-parameters reader's injectable
  HTTP client, against a loopback server) and must write the three files above,
  byte for byte except the `date` values. The adapter clock is set to a minute
  after the recorded `lastUpdate`, so the six-hour freshness rule holds.
* `TestWorkOfflineLightSnapshotMatchesUpstream` (parity environment) runs the
  upstream scripts again against a loopback server that replays the same
  exchanges, and the Go use cases against the same server, and compares the two
  files after each step. The server serves the parameters file with one fixed
  `lastUpdate` of "now", because the scripts refuse a file older than six hours.
  Both sides therefore read identical bytes.

The time-dependent fields are exactly the `date` of every entry (history,
address, DRep). `protocol.parameters.sposcriptsLightMode.lastUpdate` is not
time-dependent in the replay: it is the recorded value in the recorded-file
test and one fixed value per test in the differential test.

Koios answers `address_utxos` for the Go adapter's request (which asks for the
datum and reference-script columns as well) with the answer recorded for the
script's request (which does not), so both sides see the same outputs on a
chain that moves. The address was chosen for being active, which is why the
first attempt, with two separate recordings, saw two different chains.
