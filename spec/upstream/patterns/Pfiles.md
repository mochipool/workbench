+++
id = "Pfiles"
kind = "pattern"
title = "The workspace artefact catalogue: file names, content, modes, secrecy"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["key-custody", "wallet", "stake-delegation", "pool-operations", "governance", "native-assets", "community", "workspace-import", "air-gap-transfer"]
use_cases = ["ImportWorkspace", "StoreArtefact", "SealKey"]
depends_on = ["Cui", "Ckey", "Ptx", "Ptransfer", "Pparam"]
sources = [
  "00_common.sh",
  "01_protectKey.sh",
  "02_genPaymentAddrOnly.sh",
  "03a_genStakingPaymentAddr.sh",
  "03b_regStakingAddrCert.sh",
  "04a_genNodeKeys.sh",
  "04b_genVRFKeys.sh",
  "04c_genKESKeys.sh",
  "04d_genNodeOpCert.sh",
  "05a_genStakepoolCert.sh",
  "05b_genDelegationCert.sh",
  "05c_regStakepoolCert.sh",
  "05d_poolWitness.sh",
  "07a_genStakepoolRetireCert.sh",
  "07b_deregStakepoolCert.sh",
  "08a_genStakingAddrRetireCert.sh",
  "09a_catalystVote.sh",
  "0x_importHelper.sh",
  "10_genPolicy.sh",
  "11a_mintAsset.sh",
  "11b_burnAsset.sh",
  "12a_genAssetMeta.sh",
  "15_calidusPoolKey.sh",
  "21a_genDRepKeys.sh",
  "21b_regDRepCert.sh",
  "21d_retDRepCert.sh",
  "22a_genVoteDelegCert.sh",
  "23a_genComColdKeys.sh",
  "23b_genComHotKeys.sh",
  "23c_regComAuthCert.sh",
  "23e_retComColdKeys.sh",
  "24a_genVote.sh",
  "25a_genAction.sh",
]
+++

# Pfiles: the workspace artefact catalogue

The upstream scripts keep all state as flat files in the working directory, named `<name>.<role>.<kind>`. The *name* is chosen by the operator (a wallet, a pool, a DRep, a policy); the *role* and *kind* are fixed by the scripts. A script receives the name (with or without its extension), derives every file name from it, and finds the other scripts' output purely by naming convention. This is the contract of the file-system `Store` and `Vault` adapters and of the import use case (`0x_importHelper`, and importing an existing upstream workspace).

This pattern lists every artefact family: file-name pattern, content, mode, whether it holds secret material, and which scripts create, read, modify or delete it. Content types are `cardano-cli` text envelopes (JSON with `type`, `description`, `cborHex`); the `type` string is given only where a script sets or tests it. The scripts do not assert the other envelope types: they are what the pinned `cardano-cli` or `cardano-signer` writes. Per-script specs cite the families by id.

## Naming and path rules

- **SPO-Pfiles-IN-001** A name argument is accepted with or without its role extension and with an optional directory part; a leading `./` is dropped. The same artefact is therefore reached as `mywallet`, `mywallet.addr` or `./mywallet.addr`. The extension that is stripped differs per role: `.addr` for payment addresses, `.staking` for stake accounts, `.json` then `.pool` for pool names, `.asset` for assets. (src: 01_sendLovelaces.sh:L20-L21, 01_claimRewards.sh:L20-L21, 05a_genStakepoolCert.sh:L20, 11a_mintAsset.sh:L23-L24, 06_regDelegationCert.sh:L61-L62)
- **SPO-Pfiles-IN-002** A destination that is not an existing `<name>.addr` file may be a literal bech32 payment address or an ADA Handle; the script then writes it as `<tempDir>/tempTo.addr` or `<tempDir>/adahandle-resolve.addr` and continues as if it were a file. (src: 01_sendLovelaces.sh:L174-L197, 01_claimRewards.sh:L181-L203)
- **SPO-Pfiles-IN-003** Scripts that take a wallet name for an owner, DRep or committee member build all further names from the single name: payment account `<name>.payment.*`, stake account `<name>.staking.*`. A pool is addressed by `<pool>.pool.json`; its node key files use the `poolName` field of that json, which equals the pool base name. (src: 05a_genStakepoolCert.sh:L20-L30, 05c_regStakepoolCert.sh:L212-L214)
- **SPO-Pfiles-INV-001** *Hardware marker.* A verification key whose `.description` contains the word `Hardware` marks a hardware-wallet-backed key; the key scripts rewrite the description of an imported hardware verification key accordingly (`Payment Hardware Verification Key`, `Stake Hardware Verification Key`, `Hardware Delegate Representative Verification Key`, `Mint Hardware Verification Key`, `Hardware Calidus Pool Verification Key`, `Hardware Catalyst Vote Verification Key`). `05c` uses the marker on `<owner>.staking.vkey` to decide that a hardware wallet is involved. (src: 02_genPaymentAddrOnly.sh:L191, 03a_genStakingPaymentAddr.sh:L300, 03a_genStakingPaymentAddr.sh:L457, 21a_genDRepKeys.sh:L280, 10_genPolicy.sh:L162, 05c_regStakepoolCert.sh:L346)
- **SPO-Pfiles-INV-002** The presence of `<name>.skey` / `.<role>.skey` versus `.hwsfile` selects the signer: a script that needs a signature accepts either and refuses when neither exists. When both exist the hardware file wins in most scripts. (src: 01_sendLovelaces.sh:L171, 01_sendLovelaces.sh:L583, 06_regDelegationCert.sh:L66-L70)

## Write protection

- **SPO-Pfiles-INV-003** `file_lock` sets mode `0400` and `file_unlock` mode `0600`, each only when the path is an existing regular file. Created keys, certificates and ids are locked immediately; a file that is rewritten (`.pool.json`, counters, asset files, signing keys when encrypted) is unlocked, written and locked again. (src: 00_common.sh:L811-L819, 04a_genNodeKeys.sh:L65-L69, 05a_genStakepoolCert.sh:L197-L200)
- **SPO-Pfiles-INV-004** Not every artefact is locked. These stay at the default mode of the creating process (normally `0644`): `<pool>.pool.json` when first created from the template, `<pool>.additional-metadata.json`, witness transfer files, `.vote` files, `.calidus-registration.json`, `.vote-registration.cbor`, `.catalyst-qrcode.png`, token-registry submission json files, `offlineTransfer.json`, and everything in the temp directory. (src: 05a_genStakepoolCert.sh:L25-L54, 05a_genStakepoolCert.sh:L277, 24a_genVote.sh:L1175-L1176, 15_calidusPoolKey.sh:L434, 09a_catalystVote.sh:L272, 12a_genAssetMeta.sh:L279-L281)
- **SPO-Pfiles-INV-005** Pool metadata files that are meant to be published (`<pool>.metadata.json`, `<pool>.extended-metadata.json`) get mode `0444`. (src: 05a_genStakepoolCert.sh:L314, 05a_genStakepoolCert.sh:L325)

## Addresses and keys of wallets

- **SPO-Pfiles-OUT-001** `<name>.addr`, or `<name>.payment.addr` and `<name>.staking.addr`: plain text, one bech32 address, produced by `cardano-cli address build` or `stake-address build`. Mode `0400`. Not secret. *(Observed 2026-11-16, cardano-cli 11.2.3.0: `address build` writes no trailing newline, `stake-address build` writes one; see the open questions.)* Created by `02` and `03a` (and `0x` for imported owners); read by every transaction and query script; the first line is the address. (src: 02_genPaymentAddrOnly.sh:L91-L93, 03a_genStakingPaymentAddr.sh:L473-L475, 03a_genStakingPaymentAddr.sh:L483-L485, 0x_importHelper.sh:L494-L503)
- **SPO-Pfiles-OUT-002** `<name>.vkey` / `<name>.skey` (script `02`, enterprise payment address) and `<name>.payment.vkey` / `.skey`, `<name>.staking.vkey` / `.skey` (script `03a`): cardano-cli text envelopes for payment and stake keys; derived-from-mnemonics signing keys are extended keys and the matching verification key is converted to a non-extended one. Mode `0400`. The `.skey` is secret. (src: 02_genPaymentAddrOnly.sh:L78-L81, 03a_genStakingPaymentAddr.sh:L138-L141, 03a_genStakingPaymentAddr.sh:L198-L207, 03a_genStakingPaymentAddr.sh:L324-L327, 03a_genStakingPaymentAddr.sh:L354-L362)
- **SPO-Pfiles-OUT-003** With key type `enc` the `.skey` is not the cardano-cli envelope but `{"type": <original type>, "description": "Encrypted <original description>", "encrHex": <hex of gpg --symmetric AES256 over the original cborHex>}`. Any signing key file in the catalogue can be in this form; readers detect it by the substring `encrHex` or `Encrypted` and decrypt in memory. `01_protectKey` converts a signing key file between the two forms in place (it rewrites the file and locks it). Mode `0400`. Secret. (src: 00_common.sh:L2817-L2843, 00_common.sh:L2895-L2905, 01_protectKey.sh:L150-L153, 01_protectKey.sh:L214-L217)
- **SPO-Pfiles-OUT-004** `<name>.hwsfile` / `<name>.payment.hwsfile` / `<name>.staking.hwsfile` (and `.node.`, `.policy.`, `.drep.`, `.cc-cold.`, `.cc-hot.`, `.voting.`, `.calidus.`): the hardware-wallet signing file written by `cardano-hw-cli`: JSON holding the derivation path and public key material of the device account (content as written by that tool, not asserted by the scripts), no private key. Mode `0400`. Sensitive (it identifies the account) but not secret. The committee hot key script sets its `type` to `ConstitutionalCommitteeHotHWSigningFile_ed25519`. (src: 02_genPaymentAddrOnly.sh:L186-L194, 03a_genStakingPaymentAddr.sh:L295-L304, 03a_genStakingPaymentAddr.sh:L452-L461, 23b_genComHotKeys.sh:L295-L302)
- **SPO-Pfiles-OUT-005** `<name>.payment.mnemonics`: plain text, the 24 mnemonic words of the mnemonic-derived wallet (one line). The stake account is derived from the same words. Mode `0400`. **Secret in clear.** Same shape for `<drep>.drep.mnemonics`, `<com>.cc-cold.mnemonics`, `<com>.cc-hot.mnemonics`, `<vote>.voting.mnemonics`, `<calidus>.calidus.mnemonics`. (src: 03a_genStakingPaymentAddr.sh:L188, 03a_genStakingPaymentAddr.sh:L205, 21a_genDRepKeys.sh:L176-L184, 23a_genComColdKeys.sh:L173, 23a_genComColdKeys.sh:L181, 23b_genComHotKeys.sh:L191, 23b_genComHotKeys.sh:L199, 09a_catalystVote.sh:L207-L209, 15_calidusPoolKey.sh:L140-L142)
- **SPO-Pfiles-OUT-006** `<name>.staking.cert`: the stake address registration certificate (cardano-cli certificate envelope; in Conway era it carries the deposit). Created by `03b` itself from the stake address on every run, replaces an existing one, mode `0400`. Read by `03b` as `--certificate`. Not secret. (src: 03b_regStakingAddrCert.sh:L334-L352)
- **SPO-Pfiles-OUT-007** `<name>.deleg.cert`: stake delegation certificate (stake key to pool id), created by `05b`, read by `05c` (checked against the pool id) and `06`. Mode `0400`, not secret. (src: 05b_genDelegationCert.sh:L37-L40, 05b_genDelegationCert.sh:L60-L63, 06_regDelegationCert.sh:L166-L168)
- **SPO-Pfiles-OUT-008** `<name>.vote-deleg.cert`: vote delegation certificate (stake key to DRep, or to always-abstain / always-no-confidence), created by `22a`, read by `22b`. Mode `0400`, not secret. (src: 22a_genVoteDelegCert.sh:L45-L48, 22a_genVoteDelegCert.sh:L119-L131)
- **SPO-Pfiles-OUT-009** `<name>.staking.dereg-cert`: stake address de-registration certificate (in Conway era it carries the deposit amount, which `08b` reads back by decoding the certificate), created by `08a`, read by `08b`. Mode `0400`, not secret. (src: 08a_genStakingAddrRetireCert.sh:L211-L224, 08b_deregStakingAddrCert.sh:L322-L334)

## Pool artefacts

- **SPO-Pfiles-OUT-010** `<pool>.node.vkey`, `<pool>.node.skey`, `<pool>.node.counter` (script `04a`) or `<pool>.node.vkey`, `<pool>.node.hwsfile`, `<pool>.node.counter` (hardware cold key): the pool's cold keys and the operational-certificate issue counter. Mode `0400`. The `.skey` is secret (the pool's identity). (src: 04a_genNodeKeys.sh:L65-L69, 04a_genNodeKeys.sh:L83-L86, 04a_genNodeKeys.sh:L186-L191)
- **SPO-Pfiles-OUT-011** `<pool>.node.counter` is a cardano-cli `NodeOperationalCertificateIssueCounter` envelope whose `description` reads `Next certificate issue number: <n>`. `04d` rewrites it on every opcert issue (unlock, issue, lock), and recreates it with `node new-counter` (patching the description) when asked. (src: 04d_genNodeOpCert.sh:L63-L71, 04d_genNodeOpCert.sh:L83-L96, 04d_genNodeOpCert.sh:L150-L155)
- **SPO-Pfiles-OUT-012** `<pool>.vrf.vkey` / `<pool>.vrf.skey`: VRF key pair from `04b`; mode `0400`; the `.skey` is secret and, with key type `enc`, encrypted. (src: 04b_genVRFKeys.sh:L53-L56, 04b_genVRFKeys.sh:L67-L69, 04b_genVRFKeys.sh:L123-L126)
- **SPO-Pfiles-OUT-013** `<pool>.kes-<NNN>.vkey` / `.skey`: KES key pair number NNN (three digits at least), envelope type `KesVerificationKey_ed25519_kes_2^6` for the verification key; `<pool>.kes.counter` and `<pool>.kes.counter-next`: plain decimal numbers, zero-padded to three digits, the newest generated KES number and the number the next key must have; all mode `0400`. `04c` creates and advances them, `04d` reads both and advances the second. The `.skey` is secret. Details in the `04c` spec. (src: 04c_genKESKeys.sh:L59-L70, 04c_genKESKeys.sh:L93-L96, 04c_genKESKeys.sh:L177-L179, 04d_genNodeOpCert.sh:L35-L40, 04d_genNodeOpCert.sh:L300-L302)
- **SPO-Pfiles-OUT-014** `<pool>.node-<NNN>.opcert`: the operational certificate for KES number NNN (envelope `NodeOperationalCertificate`), created by `04d` from the KES verification key, the cold signing key and the counter; mode `0400`. `04d` deletes it again when the issued counter turns out wrong. Not secret on its own (it is shipped to the block producer). (src: 04d_genNodeOpCert.sh:L139, 04d_genNodeOpCert.sh:L150-L155, 04d_genNodeOpCert.sh:L162-L167, 04d_genNodeOpCert.sh:L258-L261)
- **SPO-Pfiles-OUT-015** `<pool>.kes-expire.json`: JSON `{"latestKESfileindex", "currentKESperiod", "expireKESperiod", "expireKESdate"}`, all values strings, rewritten by every `04d` run (unlock, write, lock); read by the status tooling. Not secret. (src: 04d_genNodeOpCert.sh:L135-L137)
- **SPO-Pfiles-OUT-016** `<pool>.bls.vkey` / `<pool>.bls.skey`: BLS key pair (testnet script `04f`, not present in the mainnet tree), required by `05a` as input for the registration certificate when the protocol major version is 12 or higher, otherwise `05a` refuses with exit 1. Mode `0400`; the `.skey` is secret. (src: 05a_genStakepoolCert.sh:L405-L412)
- **SPO-Pfiles-OUT-017** `<pool>.pool.json`: the pool descriptor, a JSON object edited by the operator and extended by the scripts. Operator fields: `poolName`, `poolOwner` (array of `{ownerName, ownerWitness}`; a plain string is converted to a one-element array by `05a`), `poolRewards`, `poolPledge`, `poolCost`, `poolMargin`, `poolRelays` (array of `{relayType, relayEntry, relayPort}`), `poolMetaName`, `poolMetaDescription`, `poolMetaTicker`, `poolMetaHomepage`, `poolMetaUrl`, `poolExtendedMetaUrl`. Script fields: `poolID`, `poolIDbech`, `poolMetaHash`, `regCertCreated`, `regCertFile`, `regProtectionKey`, `regEpoch`, `regSubmitted`, `regWitness` (the witness collection, deleted on registration), `deregCertCreated`, `deregCertFile`, `deregEpoch`, `deregSubmitted`. Locked `0400` after each script update. Not secret, but `regProtectionKey` is a private service key. (src: 05a_genStakepoolCert.sh:L25-L54, 05a_genStakepoolCert.sh:L197-L216, 05a_genStakepoolCert.sh:L336-L340, 05a_genStakepoolCert.sh:L344-L350, 05a_genStakepoolCert.sh:L426-L437, 05c_regStakepoolCert.sh:L1059-L1062, 07a_genStakepoolRetireCert.sh:L101-L104, 07b_deregStakepoolCert.sh:L517-L520)
- **SPO-Pfiles-OUT-018** `<pool>.pool.id` (hex pool id) and `<pool>.pool.id-bech` (bech32 pool id): plain text, mode `0400`, created by `05a`, read by the query scripts and by `0x`. Not secret. (src: 05a_genStakepoolCert.sh:L203-L212)
- **SPO-Pfiles-OUT-019** `<pool>.pool.cert`: the pool registration certificate, created by `05a`, mode `0400`, named in `.pool.json.regCertFile`. `05c` **deletes** it after a successful registration (online, light) and after a successfully queued offline transaction, so it cannot be submitted twice. (src: 05a_genStakepoolCert.sh:L414-L430, 05c_regStakepoolCert.sh:L1065-L1066, 05c_regStakepoolCert.sh:L1100-L1101, 05c_regStakepoolCert.sh:L1178-L1179)
- **SPO-Pfiles-OUT-020** `<pool>.pool.dereg-cert`: the pool retirement certificate, created by `07a`, mode `0400`, named in `.pool.json.deregCertFile`, read by `07b`. (src: 07a_genStakepoolRetireCert.sh:L94-L107, 07b_deregStakepoolCert.sh:L83-L87)
- **SPO-Pfiles-OUT-021** `<pool>.metadata.json` (name, description, ticker, homepage, and optionally `extended`) and `<pool>.extended-metadata.json`: the published pool metadata, written by `05a` at mode `0444`; the metadata hash stored in `.pool.json.poolMetaHash` is computed over `<pool>.metadata.json`. `<pool>.additional-metadata.json` is the editable source of the extended part. (src: 05a_genStakepoolCert.sh:L277, 05a_genStakepoolCert.sh:L310-L340)
- **SPO-Pfiles-OUT-022** `<pool>.itn.skey` / `<pool>.itn.vkey`: optional Incentivized-Testnet key pair; if both exist `05a` signs the pool id with `cardano-signer` and embeds the witness in the extended metadata. Input only; the `.skey` is secret. (src: 05a_genStakepoolCert.sh:L282-L303)
- **SPO-Pfiles-OUT-023** `<pool>_<slot>_<witnessId>.witness` (witness transfer file, where `<slot>` is the witness slot name without a `.staking` suffix): JSON `{id, date-created, ttl, type, metadataFilesList, poolFile, poolMetaTicker, signing-name, signing-vkey, txBody, signedWitness, date-signed}` written by `05c` for **every** witness slot that is still empty, not only for a pool owner who signs elsewhere: an owner staking key (`<pool>_<owner>_<id>.witness`), an unsigned payer slot (`<pool>_<pay>_<id>.witness`) and an unsigned cold-key slot (`<pool>_<pool>.node_<id>.witness`). An existing file is not overwritten. `05d sign` fills `signedWitness`, `05d add` imports it into `.pool.json.regWitness.witnesses` and removes the file. Mode default. Contains the unsigned transaction body, not secret. (src: 05c_regStakepoolCert.sh:L923-L944, 05d_poolWitness.sh:L284, 05d_poolWitness.sh:L455-L462)
  > **Upstream quirk:** `05d` offers to attach `<pool>.<witnessName>.witness` (a different name pattern, 05d_poolWitness.sh:L79), which is never created. A port uses one name pattern.

## Governance artefacts

- **SPO-Pfiles-OUT-024** `<name>.drep.vkey` / `<name>.drep.skey` / `<name>.drep.hwsfile` and `<name>.drep.id`: DRep keys (cli, enc, hardware, or mnemonic-derived at path 1852H/1815H/acc/3/idx) and the DRep id text produced by `cardano-cli governance drep id`. A hardware DRep verification key gets type `DRepVerificationKey_ed25519`. Mode `0400`; the `.skey` is secret. `21b`, `21d`, `22a`, `24a`, `24b`, `01_workOffline add` read them. (src: 21a_genDRepKeys.sh:L126-L129, 21a_genDRepKeys.sh:L162-L186, 21a_genDRepKeys.sh:L275-L287, 21a_genDRepKeys.sh:L299-L301)
- **SPO-Pfiles-OUT-025** `<drep>.drep-reg.cert` (registration or update certificate, created by `21b` on each run, replacing the previous) and `<drep>.drep-ret.cert` (retirement certificate, created by `21d`): certificate envelopes, mode `0400`, not secret. (src: 21b_regDRepCert.sh:L347-L366, 21d_retDRepCert.sh:L244-L249)
- **SPO-Pfiles-OUT-026** `<com>.cc-cold.vkey` / `.skey` / `.hwsfile` and `<com>.cc-hot.vkey` / `.skey` / `.hwsfile` (committee member cold and hot keys): created by `23a` and `23b`; mode `0400`; the `.skey` is secret; the hot verification key of a hardware key gets type `ConstitutionalCommitteeHotVerificationKey_ed25519`. (src: 23a_genComColdKeys.sh:L125-L126, 23a_genComColdKeys.sh:L283-L284, 23b_genComHotKeys.sh:L141-L144, 23b_genComHotKeys.sh:L295-L302)
- **SPO-Pfiles-OUT-027** `<com>.cc-cold.hash` and `<com>.cc-hot.hash`: plain text key hash of the committee key (`governance committee key-hash`), mode `0400`; read when composing authorisations and votes. Not secret. (src: 23a_genComColdKeys.sh:L296-L301, 23b_genComHotKeys.sh:L316-L321)
- **SPO-Pfiles-OUT-028** `<hot>.cc-hot.cert` (hot-key authorisation certificate, created by `23c` each run) and `<cold>.cc-cold-ret.cert` (cold-key resignation certificate, created by `23e`): certificate envelopes, mode `0400`, not secret. (src: 23c_regComAuthCert.sh:L281-L286, 23e_retComColdKeys.sh:L342-L347)
- **SPO-Pfiles-OUT-029** `<voter>_<yymmddHHMMSS>.drep.vote`, `.cc-hot.vote`, `.pool.vote`: vote file written by `24a` (the `cardano-cli governance vote create` json plus an injected `description` with the action title), consumed by `24b` as an extra parameter. The time stamp is local time `%y%m%d%H%M%S`. Mode default. Not secret. (src: 24a_genVote.sh:L1152-L1176, 24b_regVote.sh:L185-L190)
- **SPO-Pfiles-OUT-030** `<stake>_<yymmddHHMMSS>.action` or `<stake>_<actionType>_<yymmddHHMMSS>.action`: governance action file written by `25a` (with the deposit-return stake address and the anchor), consumed by `25b`; mode `0400`. Not secret. (src: 25a_genAction.sh:L693-L699, 25a_genAction.sh:L793-L796, 25b_regAction.sh:L115-L120)

## Native assets

- **SPO-Pfiles-OUT-031** `<policy>.policy.vkey` / `.skey` / `.hwsfile`: the minting policy key (hardware path 1855H/1815H/0H); mode `0400`; the `.skey` is secret. (src: 10_genPolicy.sh:L67-L70, 10_genPolicy.sh:L138-L141, 10_genPolicy.sh:L157-L165)
- **SPO-Pfiles-OUT-032** `<policy>.policy.script`: the native script JSON, either `{"keyHash": <hash>, "type": "sig"}` (unlimited) or `{"type": "all", "scripts": [{"slot": N, "type": "before"}, {"keyHash": <hash>, "type": "sig"}]}` (valid before slot N); `<policy>.policy.id`: the policy id, plain text. Both mode `0400`, not secret. `11a`/`11b` read the `before` slot as the transaction TTL. (src: 10_genPolicy.sh:L186-L194, 10_genPolicy.sh:L212-L214, 11a_mintAsset.sh:L185-L188)
- **SPO-Pfiles-OUT-033** `<policy>.<assetname>.asset`: JSON asset record; keys `metaName`, `metaDescription`, `metaTicker`, `metaUrl`, `metaDecimals`, `metaLogoPNG`, `minted` (decimal string, running total), `name`, `hexname`, `bechName`, `policyID`, `policyValidBeforeSlot`, `subject` (policy id plus hex name), `lastUpdate`, `lastAction`, plus the two marker keys `---` and `===`; `12a` adds `sequenceNumber`. Created or updated by `11a` (mint adds), `11b` (burn subtracts) and `12a`; mode `0400` after each write; read by `01_sendAssets` (policy id, name, hex name) and `12a`. In offline mode `11a`/`11b` update it when the transaction is queued, not when it is submitted. Not secret. (src: 11a_mintAsset.sh:L555-L593, 11a_mintAsset.sh:L678-L717, 11b_burnAsset.sh:L554-L593, 12a_genAssetMeta.sh:L43, 12a_genAssetMeta.sh:L143-L145, 12a_genAssetMeta.sh:L274-L276, 01_sendAssets.sh:L210-L213)
- **SPO-Pfiles-OUT-034** `<subject>.json` in the asset's directory: the token-registry submission file produced by `token-metadata-creator` and finalised by `12a`; mode default; published by the operator. Not secret. (src: 12a_genAssetMeta.sh:L232-L262, 12a_genAssetMeta.sh:L279-L288)

## Community and pool identity keys

- **SPO-Pfiles-OUT-035** `<vote>.voting.skey` / `.vkey` / `.hwsfile`, `<vote>.voting.pkey` (bech32 public key, plain text) and `<vote>.voting.mnemonics`: Catalyst voting key material from `09a` (CIP-36, derived with `cardano-signer`); mode `0400`; `.skey` and `.mnemonics` are secret. `<vote>.catalyst-qrcode.png`: the QR code for the app (PIN protected), mode default, **secret** (it encodes the voting key). `<stake>_<yymmddHHMMSS>.vote-registration.cbor`: the voting registration metadata for `01_sendLovelaces` as extra parameter. (src: 09a_catalystVote.sh:L174-L209, 09a_catalystVote.sh:L112-L114, 09a_catalystVote.sh:L272, 09a_catalystVote.sh:L395)
- **SPO-Pfiles-OUT-036** `<calidus>.calidus.skey` / `.vkey` / `.hwsfile` / `.mnemonics` / `.id`: the Calidus pool key (CIP-151) generated by `15`; `.id` is the bech32 Calidus id as plain text; mode `0400`; `.skey` and `.mnemonics` are secret. `<pool>_<yymmddHHMMSS>.calidus-registration.json`: the registration metadata json, written next to the given path, mode default. (src: 15_calidusPoolKey.sh:L117-L151, 15_calidusPoolKey.sh:L172-L179, 15_calidusPoolKey.sh:L225, 15_calidusPoolKey.sh:L434)

## Transfer, import and temporary files

- **SPO-Pfiles-OUT-037** `offlineTransfer.json` (default path `./offlineTransfer.json`): the carry bag between online and offline machines; schema and mutation rules in `Ptransfer`. Mode not managed. Confidential, not secret. (src: 00_common.sh:L59, 00_common.sh:L510)
- **SPO-Pfiles-OUT-038** `0x_importHelper` creates a directory `<pool>/` (the pool name stripped of non-alphanumerics) and writes into it, all locked `0400`: `<pool>.node.skey`, `<pool>.node.vkey`, `<pool>.node.counter`, `<pool>.vrf.skey`, `<pool>.vrf.vkey`, per owner `<owner>.payment.skey`/`.vkey`/`.addr`, `<owner>.staking.skey`/`.vkey`/`.addr`/`.cert`/`.deleg.cert`, and `<pool>.pool.json` (assembled from the on-chain pool info). The signing keys are **copied** from the paths the operator supplies. Optionally the pool info is exported to an operator-chosen file for transport. (src: 0x_importHelper.sh:L173, 0x_importHelper.sh:L285-L309, 0x_importHelper.sh:L350-L357, 0x_importHelper.sh:L391-L442, 0x_importHelper.sh:L494-L528, 0x_importHelper.sh:L573-L574, 0x_importHelper.sh:L131-L139)
- **SPO-Pfiles-OUT-039** Transaction scripts keep their intermediate files in the temp directory (the directory of `mktemp -ut`, normally `/tmp`), named from the base name of the paying address, pool or policy: `dummy.txbody`, `<name>.txbody`, `<name>.tx`, `<name>.txwitness` (also `.txwitness2`, `-payment`, `-staking`, `-coldkey`, `-node`, `.pay_txwitness`, `<policy>.witness`, `<voter>.vote_txwitness`), `<name>.transactionMessage.json`, `<name>.tmp.txfile` (from `execute`), `<pool>.witness_<n>.tx`, `tempTo.addr`, `adahandle-resolve.addr`, `<calidus>.signedMessage`, `opcert.query`, `tmpmetadata.json`, and anchor-content downloads (`AnchorURLContent.tmp` and siblings). They are mode default, overwritten by the next run with the same name, and mostly never deleted. They hold unsigned or signed transactions and message metadata, never signing keys. (src: 01_sendLovelaces.sh:L464, 01_sendLovelaces.sh:L556-L558, 05c_regStakepoolCert.sh:L1001-L1003, 03b_regStakingAddrCert.sh:L550, 03b_regStakingAddrCert.sh:L579-L582, 11a_mintAsset.sh:L422, 00_common.sh:L645)
- **SPO-Pfiles-IN-004** Configuration is read from `common.inc` files (script directory, `~/.common.inc`, `./common.inc`, later ones override), `00_common.sh` defaults, and the environment; binaries `cardano-cli`, `cardano-hw-cli`, `cardano-signer`, `bech32`, `token-metadata-creator`, `catalyst-toolbox` and the file `guardrails-script.plutus` are located by configured paths, with a fallback to the script directory for `bech32`. These are configuration, not workspace artefacts. (src: 00_common.sh:L164-L166, 00_common.sh:L50-L60, 25b_regAction.sh:L669)

## Secret material

- **SPO-Pfiles-SEC-001** The files that hold secret material, and so must be sealed by the `Vault` port: every `*.skey` (plain or `encrHex` form), `*.mnemonics`, `<pool>.itn.skey`, `<pool>.bls.skey`, the QR code `*.catalyst-qrcode.png`, and `<pool>.kes-<NNN>.skey`. The following hold no secret key but identify an account and are confidential: `*.hwsfile`, `offlineTransfer.json` with attached witness files, witness transfer files, and `<pool>.pool.json` (`regProtectionKey`). (src: 04c_genKESKeys.sh:L93-L96, 03a_genStakingPaymentAddr.sh:L205-L207, 09a_catalystVote.sh:L112, 05a_genStakepoolCert.sh:L282-L303)
- **SPO-Pfiles-SEC-002** The plain `.skey` files are the default protection: mode `0400` and nothing else. Encryption (`enc`) is opt-in per key and per script run. See SPO-Ckey-SEC-001 for the password handling and SPO-Ckey-OUT-001 for the encrypted envelope. (src: 00_common.sh:L811-L819, 00_common.sh:L2817-L2843)

- **SPO-Pfiles-SEC-003** The key-generation scripts for mnemonic-derived keys print the 24 mnemonic words on stdout when they create or accept them, in addition to writing the `.mnemonics` file. A caller must not capture or log their output. (src: 21a_genDRepKeys.sh:L163, 21a_genDRepKeys.sh:L173, 21a_genDRepKeys.sh:L176-L181)

## Artefact table

Mode `L` = `0400` through `file_lock`; `D` = creating process default. "Secret" = holds secret material. Ids refer to the requirements above.

| Pattern | Id | Mode | Secret | Created by | Read by | Modified or deleted by |
| --- | --- | --- | --- | --- | --- | --- |
| `<n>.addr`, `<n>.payment.addr`, `<n>.staking.addr` | OUT-001 | L | no | 02, 03a, 0x | all tx scripts, 01_queryAddress, 01_workOffline | |
| `<n>.vkey`, `<n>.skey`, `<n>.payment.*`, `<n>.staking.*` | OUT-002 | L | skey | 02, 03a, 0x | all signing scripts | 01_protectKey (skey) |
| encrypted `.skey` | OUT-003 | L | yes | any key script with `enc` | read_skeyFILE | 01_protectKey |
| `*.hwsfile` | OUT-004 | L | no | 02, 03a, 04a, 10, 15, 21a, 23a, 23b, 09a | signing scripts | |
| `*.mnemonics` | OUT-005 | L | yes | 03a, 21a, 23a, 23b, 09a, 15 | operator | |
| `<n>.staking.cert` | OUT-006 | L | no | 03b | 03b | 03b (replaces) |
| `<n>.deleg.cert` | OUT-007 | L | no | 05b, 0x | 05c, 06 | |
| `<n>.vote-deleg.cert` | OUT-008 | L | no | 22a | 22b | |
| `<n>.staking.dereg-cert` | OUT-009 | L | no | 08a | 08b | |
| `<p>.node.*`, `<p>.node.counter` | OUT-010, OUT-011 | L | skey | 04a, 0x | 04d, 05a, 05c, 07b | 04d (counter) |
| `<p>.vrf.*` | OUT-012 | L | skey | 04b, 0x | 05a | |
| `<p>.kes-NNN.*`, `<p>.kes.counter`, `<p>.kes.counter-next` | OUT-013 | L | skey | 04c | 04d, 04e | 04c, 04d |
| `<p>.node-NNN.opcert` | OUT-014 | L | no | 04d | 04e | 04d (delete on bad counter) |
| `<p>.kes-expire.json` | OUT-015 | L | no | 04d | status tools | 04d |
| `<p>.bls.*` | OUT-016 | L | skey | 04f (testnet) | 05a | |
| `<p>.pool.json` | OUT-017 | D then L | no (`regProtectionKey`) | 05a, 07a, 0x | 05a-05e, 07b, 0x | 05a, 05c, 05d, 07a, 07b |
| `<p>.pool.id`, `<p>.pool.id-bech` | OUT-018 | L | no | 05a | queries, 0x | 05a |
| `<p>.pool.cert` | OUT-019 | L | no | 05a | 05c | 05c (delete) |
| `<p>.pool.dereg-cert` | OUT-020 | L | no | 07a | 07b | |
| `<p>.metadata.json`, `.extended-metadata.json` | OUT-021 | 0444 | no | 05a | 05a, 05c (attach) | 05a |
| `<p>.itn.*` | OUT-022 | input | skey | operator | 05a | |
| `<pool>_<slot>_<id>.witness` | OUT-023 | D | no | 05c | 05d | 05d (fill, delete) |
| `<d>.drep.*`, `<d>.drep.id` | OUT-024 | L | skey | 21a | 21b-21d, 22a, 24a, 24b | |
| `<d>.drep-reg.cert`, `<d>.drep-ret.cert` | OUT-025 | L | no | 21b, 21d | 21b, 21d | replaced per run |
| `<c>.cc-cold.*`, `<c>.cc-hot.*` | OUT-026 | L | skey | 23a, 23b | 23c-23e, 24a, 24b | |
| `<c>.cc-*.hash` | OUT-027 | L | no | 23a, 23b | 23c, 23d, 24a | |
| `<h>.cc-hot.cert`, `<c>.cc-cold-ret.cert` | OUT-028 | L | no | 23c, 23e | 23c, 23e | replaced per run |
| `<v>_<ts>.<kind>.vote` | OUT-029 | D | no | 24a | 24b | |
| `<s>_<ts>.action` | OUT-030 | L | no | 25a | 25b | |
| `<policy>.policy.*` key files | OUT-031 | L | skey | 10 | 11a, 11b | |
| `<policy>.policy.script`, `.policy.id` | OUT-032 | L | no | 10 | 11a, 11b | |
| `<policy>.<asset>.asset` | OUT-033 | L | no | 11a, 12a | 01_sendAssets, 11a, 11b, 12a | 11a, 11b, 12a |
| `<subject>.json` | OUT-034 | D | no | 12a | operator | |
| `<v>.voting.*`, `.catalyst-qrcode.png`, `.vote-registration.cbor` | OUT-035 | L / D | skey, mnemonics, png | 09a | 01_sendLovelaces (cbor) | |
| `<k>.calidus.*`, `.calidus-registration.json` | OUT-036 | L / D | skey, mnemonics | 15 | 15 | |
| `offlineTransfer.json` | OUT-037 | not managed | no | 01_workOffline | all offline scripts | all offline writers |
| `<pool>/…` import tree | OUT-038 | L | skey (copies) | 0x | later scripts | |
| temp files | OUT-039 | D | no | tx scripts | same | overwritten |

## Domain mapping

The catalogue is the contract of the file-system `Store` and `Vault` adapters; other adapters keep the same artefact *types* and ignore the names.

| Port | Operation | Purpose |
| --- | --- | --- |
| `Store` | `get(artefact)` / `put(artefact)` / `exists(artefact)` / `delete(artefact)` | Typed access for the non-secret rows |
| `Store` | `lock(artefact)` / `unlock(artefact)` | `file_lock` / `file_unlock` (SPO-Pfiles-INV-003) |
| `Vault` | `seal(secret, policy)` / `unseal(ref, passphrase?)` | The secret rows (SPO-Pfiles-SEC-001), including the `encrHex` form |
| `Vault` | `exportPlaintext(ref, destination)` | Named export of plaintext signing keys where a node needs them |
| `Store` | `importWorkspace(path)` *(new)* | Reads an upstream tree by these naming rules into typed artefacts (`ImportWorkspace`) |
| `Store` | `listByRole(role)` *(new)* | Enumerate wallets, pools, DReps, policies by role extension |

## Port notes

* Model artefacts by type and identity (`PaymentAccount`, `StakeAccount`, `StakePool`, `KesKey[n]`, `Policy`, `DRep`, `CommitteeMember`, `VoteFile`, `ActionFile`, ...) and map them to these names only in the file adapter and the importer.
* The mnemonic files and the Catalyst QR code are plaintext secrets at rest; the port stores them sealed, or not at all.
* The temp-directory files are an implementation detail of the cardano-cli pipeline; a port that builds transactions in memory needs none of them.
* The importer must accept both locked (`0400`) and unlocked trees, detect encrypted keys by the `encrHex` marker, and use the `Hardware` description marker to recognise hardware keys.

## Open questions

* The exact `type` strings written by `cardano-cli` / `cardano-signer` / `cardano-hw-cli` for each key and certificate are not asserted by the scripts; an inventory run against the pinned tool versions settles them for the importer's validation. **Partly resolved 2026-11-16** (cardano-cli 11.2.3.0, cardano-signer 1.35.0; `spo/test/parity/software_keys_test.go`):

  | File | `type` | `description` | `cborHex` |
  | --- | --- | --- | --- |
  | `.node.vkey` / `.node.skey` | `StakePoolVerificationKey_ed25519` / `StakePoolSigningKey_ed25519` | `Stake Pool Operator Verification Key` / `... Signing Key` | `5820` + 32 bytes |
  | `.node.counter` | `NodeOperationalCertificateIssueCounter` | `Next certificate issue number: 0` | `82005820` + cold vkey |
  | `.vkey` / `.skey` (`02`), `.payment.vkey` / `.skey` (`03a cli`) | `PaymentVerificationKeyShelley_ed25519` / `PaymentSigningKeyShelley_ed25519` | `Payment Verification Key` / `Payment Signing Key` | `5820` + 32 bytes |
  | `.staking.vkey` / `.skey` (`03a cli`) | `StakeVerificationKeyShelley_ed25519` / `StakeSigningKeyShelley_ed25519` | `Stake Verification Key` / `Stake Signing Key` | `5820` + 32 bytes |
  | `.payment.skey`, `.staking.skey` (`03a mnemonics`) | `PaymentExtendedSigningKeyShelley_ed25519_bip32` / `StakeExtendedSigningKeyShelley_ed25519_bip32` | `Payment Signing Key` / `Stake Signing Key` | `5880` + key 64, public key 32, chain code 32 |

  Files written by cardano-cli are indented by four spaces; the `03a mnemonics` files (cardano-signer and jq) by two. The `03a mnemonics` verification keys keep the `cli` types and descriptions (`SPO-03a-OUT-002`).
* ~~Whether `<n>.addr` always ends with a newline~~ Resolved 2026-11-16 on cardano-cli 11.2.3.0: `address build` writes the address **without** a trailing newline (`<name>.addr`, `<name>.payment.addr`), while `stake-address build` writes `<name>.staking.addr` **with** one. SPO-Pfiles-OUT-001's "trailing newline" holds for the stake address only; the readers use `cat` and tolerate either.
