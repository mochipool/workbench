# Go library coverage

What the Go implementation (`spo/`) needs from outside its own code, which library provides it, and what nobody provides. It is the working list behind [ADR 0007](../explanation/adr/0007-native-first-with-blink-labs.md) (native first) and [ADR 0006](../explanation/adr/0006-chain-access-providers.md) (chain providers).

Surveyed 2026-11-16 at: `bursa` v0.25.0, `gouroboros` v0.220.2, `plutigo` v0.12.3, `go-bip39` v0.2.1, `cardano-models` v0.7.2 (Blink Labs, Apache-2.0 except `go-bip39`, MIT); Apollo v2.2.1 (`github.com/Salvionied/apollo/v2`, MIT); `utxorpc/go-sdk` v0.2.0; `blockfrost-go` v0.5.0; `koios-go-client` v4.0.0. All build with `CGO_ENABLED=0`.

How to read the *Evidence* column: **run** means a program exercised it during the survey; **read** means it was found in the source or `go doc` only; **oracle** means a test in `spo/test/parity` compares it with the pinned cardano-cli. Nothing is trusted on the signing path until it reaches **oracle**.

Only `bursa`'s root package, `bursa/bip32` and `bursa/kesagent/wire` can be imported. Its certificate commands, transaction builder and signer service are under `cmd/` and `internal/`.

## Keys, addresses and identifiers

| Need | Provided by | Evidence | Notes |
| --- | --- | --- | --- |
| KES and VRF key pairs | `bursa.GetKESKeyPair`, `GetVRFKeyPair` and their envelope functions | oracle | Use a random seed. `bursa`'s mnemonic-derived KES and VRF seeds use a private derivation that no other tool reproduces. |
| Mnemonic generation and validation | `go-bip39` word list with our own entropy and checksum step (`native.SoftwareKeys.GenerateMnemonic`); validation by `bursa.GetRootKeyFromMnemonicBytes` | oracle | `bursa.GenerateMnemonic` returns a Go string, which cannot be wiped, so the phrase is built directly in guarded memory from `crypto/rand` and the word list. The phrase derives to the same keys under `cardano-signer` and `cardano-cli` (2026-11-16). `go-bip39` is an indirect dependency in `go.mod` and now imported directly: drop the `// indirect` at the next `go mod tidy`. |
| Derivation from a mnemonic: payment and stake (CIP-1852, `03a`) | `bursa.GetRootKeyFromMnemonicBytes`, `GetAccountKey`, `GetPaymentKey`, `GetStakeKey`, `GetPaymentVKey`, `GetStakeVKey`, `GetPaymentExtendedSKey`, `GetStakeExtendedSKey` | oracle | Byte-equal to `03a mnemonics` (cardano-signer 1.35.0 plus `cardano-cli key non-extended-key`) for account 0 index 0, 1/3 and 17/4000: payment `1852H/1815H/<acc>H/0/<idx>`, stake `.../2/<idx>`. The signing key is bursa's extended envelope with the description changed to `Payment Signing Key` / `Stake Signing Key`; files are indented by two spaces, as cardano-signer and jq write them. `bursa`'s own description is `... Extended Signing Key (BIP32)`, which differs from upstream. |
| Derivation from a mnemonic: DRep, committee cold and hot, pool cold, policy, Calidus | `bursa.GetRootKeyFromMnemonic`, `GetAccountKey`, `GetPaymentKey`, `GetStakeKey`, `GetDRepKey`, `GetCommitteeColdKey`, `GetCommitteeHotKey`, `GetPoolColdKey`, `GetPolicyKey`, `GetCalidusKey` | run | Compare the paths with upstream's (`03a`, `21a`, `23a`, `10`, `15`) under the oracle before use. |
| Extended and non-extended key envelopes | `bursa.Get*SKey`, `Get*ExtendedSKey`, `Get*VKey` | oracle for payment and stake | `cardano-cli key verification-key` turns our extended signing key into an extended verification key whose `key non-extended-key` is our stored verification key. Other roles: run. |
| BLS keys | `bursa.NewBLSKey` | run | |
| Text envelopes for every key type; loading a key | `bursa.KeyFile`, `LoadKeyFromBytes` | run | |
| Verification key and key hash from a signing key | `bursa.PublicKeyOf`, `bip32.PublicKey.Hash`, `common.Blake2b224Hash` | run | |
| Pool id, DRep id, CIP-129 ids, CIP-14 asset fingerprint | `gouroboros/ledger/common`: `Blake2b224.Bech32`, `Drep.String`, `GovActionId.String`, `NewAssetFingerprint` | run | |
| Addresses: build and inspect | `common.NewAddressFromParts`, `NewAddress` and its accessors | oracle for build | Enterprise, base and stake addresses on testnet and mainnet are byte-equal to `cardano-cli address build` and `stake-address build`. cardano-cli writes `<name>.addr` without a trailing newline and the stake address file with one (observed 2026-11-16). |
| Random non-derived payment, stake and cold keys | **ours**: `crypto/ed25519` plus an envelope (`native.SoftwareKeys`) | oracle | The seed is drawn into guarded memory and the envelope is written straight into guarded memory. `cardano-cli key verification-key` derives the same verification key from our signing key; `stake-pool id` over the cold key equals `chain.PoolIDOf`. Types and descriptions are those `address key-gen`, `stake-address key-gen` and `node key-gen` write. |
| Opcert issue-counter envelope | **ours** | | |
| Bech32 with an arbitrary prefix | `btcutil/bech32` (already a dependency of `gouroboros`) | read | |
| Calidus id (CIP-151) | **ours** | | A blake2b-224 hash with a header byte. |

## Certificates and operational certificates

| Need | Provided by | Evidence | Notes |
| --- | --- | --- | --- |
| Every Conway certificate we use: stake registration, deregistration and delegation, vote delegation, pool retirement, DRep registration, update and retirement, committee authorisation and resignation | structs in `gouroboros/ledger/common`, wrapped in `CertificateWrapper` | run for six kinds, read for the rest | Data types with CBOR encoding. There are no builders: we fill the fields. |
| Pool registration and retirement certificates | ours (`native/poolcert.go`), by hand, as the body is | oracle | **Correction (2026-11-16):** `common.PoolRegistrationCertificate` (needs `SetRewardAccountCredential`) is not used. Byte-equal to cardano-cli 11.2.3.0, envelope included, for one and three owners (a tag-258 set in key-hash order, repeats dropped), every relay type and a mix, margins as tag-30 fractions in lowest terms, with and without metadata, mainnet and testnet reward accounts, and the retirement certificate (`spo/test/parity/pool_oracle_test.go`). Relay addresses are little-endian words; cardano-cli refuses an IPv4 relay next to an IPv6 one and has no BLS option (see spec 05a notes). |
| Decoding a certificate | `CertificateWrapper`, `ConwayTransaction.Certificates()` | oracle | The adapter decodes the four stake certificates structurally and refuses the legacy types 0 and 1 (no deposit). `native/certificates.go`, `TestStakeCertificatesMatchCardanoCLI`. |
| Certificate text envelopes | ours (`native/certificates.go`) on `common.RegistrationCertificate`, `DeregistrationCertificate`, `StakeDelegationCertificate`, `VoteDelegationCertificate` and `cbor.Encode` | oracle | **Correction (2026-11-16):** byte-equal to `stake-address registration-certificate`, `deregistration-certificate`, `stake-delegation-certificate` (pool id in hex, in bech32 and by cold key) and `vote-delegation-certificate` (DRep key hash, script hash, key file, always-abstain, always-no-confidence), text envelope included: type `Certificate`, descriptions `Stake Address Registration Certificate`, `Stake Address Deregistration Certificate`, `Stake Delegation Certificate` and `Vote Delegation Certificate`, four-space indent and a trailing newline. cardano-cli's `--drep-key-hash` takes hex and legacy `drep1...` but not a CIP-129 id. |
| Issue an operational certificate | `bursa.CreateOperationalCertificate` | run | Takes a 32- or 64-byte cold key. Must be byte-equal to cardano-cli's under the oracle. |
| Decode and verify an operational certificate | `bursa.DecodeOpCert`, `gouroboros` `VerifyOpCertSignature`, `ValidateKesPeriod` | read | |

## Transactions

| Need | Provided by | Evidence | Notes |
| --- | --- | --- | --- |
| Conway body with inputs, multi-asset outputs, fee, TTL, certificates, withdrawals, mint, required signers, collateral, votes, proposals | `gouroboros/ledger/conway`: `ConwayTransactionBody`, `ConwayTransaction` and the output and value types | run | Plain structs. An encode and decode round trip preserved the body. **Not byte-equal to cardano-cli when built from scratch (2026-11-16):** the input set is encoded without tag 258 unless it was decoded from one (the flag is unexported), and outputs are encoded in the map form where cardano-cli writes the legacy array form. `native.Ledger.BuildBody` therefore encodes the body by hand and uses the library to check the result (decode, transaction id) and to size outputs. An input index above 65535 does not decode in the library. |
| Governance actions and votes | `common.New*GovAction`, `conway.NewConwayProposalProcedure`, `common.VotingProcedures` | run for two action kinds and votes | Parameter change has no constructor, only the struct. |
| Metadata from JSON and CBOR; CIP-20 | `common.ParseCardanoCLIMetadataJSON*`, `cardano-models` | run | |
| Transaction id | `ConwayTransaction.Id`, `bursa.TransactionID` | oracle | Equal to `cardano-cli transaction txid`. |
| Minimum output value | `conway.MinCoinTxOut` | oracle | Equal to `calculate-min-required-utxo` (hazard H5) when the output is encoded in the legacy array form and the amount is found as a fixed point: cardano-cli ignores the lovelace of the tx-out text. Sized from the output's own wire bytes, so decode a hand-encoded output, do not hand over a struct (2026-11-16). |
| Minimum fee | `bursa.EstimateWitnessedTxSize` then `bursa.MinFee` | oracle | `conway.MinFeeTx` on an unsigned transaction leaves the witnesses out. `bursa.MinFee` ignores script and reference-script cost. **Correction (2026-11-16):** the estimate counts the one-byte `is_valid` flag, which the ledger's fee size leaves out, so it is 44 lovelace too high at today's `txFeePerByte`; subtract one byte before `MinFee`. Equal to `calculate-min-fee` for 1 to 3 witnesses after that. |
| Assemble a body and witnesses | `bursa.AssembleTransaction` | oracle | Byte-equal to `transaction assemble` and `transaction sign`. **Correction (2026-11-16):** the witness set is ordered by the hash of the verification key, not by the order given: with two witnesses (payment and stake) our `Assemble` sorts by key hash to equal cardano-cli's bytes. |
| Body with certificates and withdrawals | ours: hand-encoded in `native/tx.go` | oracle | Body key 4 is tag 258 over the certificates in the order given, key 5 a map from reward-address bytes to lovelace, keys ascending. Byte-equal to `build-raw --certificate-file` and `--withdrawal`, with the same id, the same fee at two witnesses (`calculate-min-fee`) and the same estimated size, for each certificate kind and a combination. `TestStakeTransactionsMatchCardanoCLI`. |
| Decode a body for review by a signer (M2) | `gouroboros` decoding plus **ours** for presentation | run | `bursa.InspectTransaction` gives totals only, so the per-certificate view is ours. |
| Native scripts and policy ids | `bursa.NewScript*`, `GetScriptHash` | run | |
| Plutus script cost (guardrails script, `25b`) | `conway.EvaluatePlutusScripts` on `plutigo` | read | We supply the UTxO lookup. Not run. |
| Protocol parameters from a provider into `ConwayProtocolParameters` | **ours**, one converter per chain adapter | | Concern N5. |
| The pipeline itself: gather inputs, change, fee iteration, TTL | **ours**, in `domain/txbuild` | | See *Transaction builder* below. |
| Canonical CBOR for hardware wallets (CIP-21) | nobody in Go | | Needed only by the hardware adapter; cardano-hw-cli's `transaction transform` does it. |

### Transaction builder

Apollo v2.2.1 is a complete builder on the same `gouroboros` and `bursa` types, with coin selection and fee balancing, and it builds offline. We do not adopt it for the pipeline. Upstream's pipeline has its own rules that parity depends on: it spends every UTxO of the paying address (SPO-Ptx-INV-002), computes the fee with a fixed witness count per script (SPO-Ptx-INV-006) and returns all change to the payer. Those rules are a small amount of domain code over `gouroboros` structs, and a builder with different rules underneath would have to be fought at each step. Apollo remains the candidate for the optional selection strategy of hazard H4. Blink Labs' fork of Apollo does not build against the current `gouroboros` and `bursa`.

## Signing

| Need | Provided by | Evidence | Notes |
| --- | --- | --- | --- |
| Witness with a normal or extended key | `bursa.CreateWitness`, `WitnessTransaction` | oracle | Byte-equal to `transaction witness` for both key forms. A normal key is expanded with `ed25519.NewKeyFromSeed`; an extended key becomes the 96-byte `XPrv` (key 64, chain code 32). cardano-cli's witness text envelope holds `[vkey, signature]` only, without a leading witness-type element. |
| Verify a witness against a body and a key hash (M3) | `common.VerifyVKeySignature` plus **ours** for the key-hash match | run | |
| CIP-8 message signing and verification | `bursa.SignData`, `VerifyData` | run | Not yet compared with cardano-signer. |
| CIP-36 Catalyst registration, CIP-88 v2 Calidus registration | nobody in Go | | Ported last (D9). cardano-signer stays as the adapter until we write them. |
| CIP-83 encrypted message metadata | nobody in Go | | Small; ours when `Pparam` is ported. |
| CIP-100, CIP-108 and CIP-119 anchor document verification | nobody in Go | | Needs JSON-LD canonicalisation. cardano-signer stays as the adapter. The anchor hash itself is `common.Blake2b256Hash`. |

## Chain access

Summarised in [ADR 0006](../explanation/adr/0006-chain-access-providers.md), which has the provider table. In short: `gouroboros` over the node's client protocol answers nearly everything but needs the node's socket; Koios by plain HTTP is the socket-less source that includes the opcert counter; `blockfrost-go` covers governance and also works against Dingo; UTxO RPC covers parameters, UTxOs and submission only.

## Hardware wallets

No Go library drives a Ledger, Trezor or Keystone for Cardano. `bursa` has no hardware code in its Go module.

| Device | What exists | To go native |
| --- | --- | --- |
| Ledger | Reference client in TypeScript (`ledgerjs-cardano-shelley`); public APDU documentation in `LedgerHQ/app-cardano` | Our own client for the Cardano app: the app takes the transaction as a structured stream, not as CBOR. Plus a USB HID transport without CGO; the one candidate found comes from an archived repository and was not tried on a device. |
| Trezor | Public protobuf messages; a bridge daemon that needs CGO | Generated messages plus the signing state machine, through a bridge process or a USB transport we did not find. |
| Keystone | npm packages only | UR and CBOR registry types, a QR or USB transport, signature parsing. |

So the hardware signer is an adapter over the pinned cardano-hw-cli (X6). The upstream scripts use seven of its subcommands (`transaction witness`, `address key-gen`, `node key-gen`, `node issue-op-cert`, `message sign`, `transaction policyid`, `vote registration-metadata`) and two probes (`version`, `device version`). Under [ADR 0008](../explanation/adr/0008-capability-typed-ports.md) it is one signer with its own profile; no use case knows it exists, and a native Ledger client can replace it later behind the same interfaces.

## What stays external, and when it is needed

| Tool | Needed for | Needed on |
| --- | --- | --- |
| cardano-cli | Test oracle only | Build and CI machines |
| cardano-hw-cli | Hardware-wallet signing and key export | A machine that signs with a device |
| cardano-signer | CIP-36, CIP-88 and CIP-100 operations, until written natively | A machine that runs those use cases |
| gpg | Reading and writing upstream `enc` key files | A machine that imports or exports them |
| cardano-node | Nothing at run time; the `n2c` adapter talks to a node the operator already runs | |

A software-key operator who imports no `enc` files needs the `spo` binary and nothing else.
