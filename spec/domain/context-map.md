# Context map

The bounded contexts the reimplementation is organised into. Every spec's `contexts` front-matter field uses these slugs. The upstream scripts mix several contexts per file; a script spec lists every context it touches, primary first.

| Slug | Context | Owns | Upstream scripts (primary) |
| --- | --- | --- | --- |
| `configuration` | Network profile, work mode, toolchain compatibility, era selection | `NetworkProfile`, `WorkMode`, `ToolchainRequirements` | `00_common.sh` prologue |
| `chain-access` | Reading chain state and submitting transactions, independent of the access method | `ChainSnapshot`, `Tip`, `ProtocolParameters` | `00_common.sh` (`queryLight_*`, `get_current*`) |
| `key-custody` | Generation, sealing, unsealing and export of secret keys; hardware-wallet sessions | `KeyPair`, `SealedKey`, `HardwareKeyRef` | `01_protectKey`, `00_common.sh` (`*_skeyJSON`, `start_HwWallet`) |
| `transaction-construction` | Shared kernel: inputs, outputs, fees, minimum output value, metadata, change, TTL, witness count | `TxDraft`, `TxBody`, `Witness`, `SignedTx` | `00_common.sh` (`generate_UTXO`, `calc_minOutUTXO`, `autocorrect_*`); every transaction script |
| `wallet` | Payment addresses, balances, payments, multi-asset transfers, reward withdrawal | `PaymentAccount`, `Balance` | `01_queryAddress`, `01_sendLovelaces`, `01_sendAssets`, `01_claimRewards`, `02`, `03a` |
| `stake-delegation` | Stake address lifecycle, pool delegation, vote delegation | `StakeAccount`, `Delegation` | `03a`–`03c`, `05b`, `06`, `08a`–`08b`, `22a`–`22b` |
| `pool-operations` | Pool cold keys, VRF, KES rotation, operational certificates, pool registration, update, owner witnesses, retirement, Calidus key | `StakePool`, `KesPeriod`, `OperationalCertificate`, `PoolRegistration` | `04a`–`04f`, `05a`, `05c`–`05e`, `07a`–`07b`, `15` |
| `governance` | DReps, constitutional committee keys, votes, governance actions | `DRep`, `CommitteeMember`, `Vote`, `GovernanceAction` | `21a`–`21d`, `23a`–`23e`, `24a`–`24c`, `25a`–`25b` |
| `native-assets` | Minting policies, minting and burning, token registry metadata | `Policy`, `Asset`, `AssetMetadata` | `10`, `11a`–`11b`, `12a`–`12b` |
| `air-gap-transfer` | Moving chain snapshots and signed transactions between online and offline machines | `TransferBundle` | `01_workOffline`, `00_common.sh` (`readOfflineFile`, `showOfflineFileInfo`) |
| `workspace-import` | Bringing an existing upstream file layout into the store | `ImportPlan` | `0x_importHelper` |
| `community` | Catalyst voting registration, SPO polls | `CatalystRegistration`, `PollResponse` | `09a`, `13a`–`13b` |

## Relationships

* `transaction-construction` is a **shared kernel**. `wallet`, `stake-delegation`, `pool-operations`, `governance`, `native-assets` and `community` all produce a `TxDraft` and hand it to the shared pipeline (`Ptx`).
* `chain-access` and `air-gap-transfer` are **upstream** of everything that queries state. In offline mode, `air-gap-transfer` acts as the `ChainQuery` adapter: it serves a snapshot that an online machine made.
* `key-custody` is a **conformist supplier** to every signing context. Signing contexts ask for a witness by key reference. They never read key material.
* `configuration` is consumed by all contexts as read-only **published language** (network profile, work mode).

This map is refined in [domain-model.md](./domain-model.md) once every script spec exists.
