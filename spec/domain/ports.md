# Ports

The hexagonal boundary of the reimplementation. Use cases (see [use-cases.md](./use-cases.md)) depend only on these ports. Each upstream behaviour that touches the outside world is specified in `spec/upstream/` and maps to an operation here; the *Domain mapping* section of every spec names the operations it needs.

Operation names are stable identifiers. When a spec needs an operation that is missing, it lists it as *(new)*. The operation is then added here with the spec codes that use it.

| Port | Responsibility | Upstream equivalent | Adapters |
| --- | --- | --- | --- |
| `Store` | Non-secret state: addresses, verification keys, certificates, counters, pool configuration, metadata files, run history, audit log | Flat files in the working directory, `chmod 400/600` | file-system (upstream layout, for parity and import), SQLite, PostgreSQL |
| `Vault` | Secret material. Accepts and returns only sealed objects; plaintext exists only inside a signing or export operation, in memory | `*.skey` files, plaintext or gpg-wrapped (`encrypt_skeyJSON`) | file-system (upstream formats), SQLite envelope-encrypted, PostgreSQL envelope-encrypted, KMS/HSM |
| `KeyGen` | Create key pairs and key-derived artefacts | `cardano-cli ... key-gen*`, `cardano-signer keygen` | cardano-cli, cardano-signer, native library |
| `Ledger` | Build, inspect, hash, and assemble transactions, certificates, and addresses; compute fees and minimum output values; encode CBOR | `cardano-cli transaction/stake-address/stake-pool/governance/address ...`, `to_cbor`, `calc_minOutUTXO` | cardano-cli (release-set pinned), native library |
| `ChainQuery` | Read chain state: tip, era, epoch, protocol parameters, UTxOs, reward accounts, pool, DRep, committee and governance state | `cardano-cli query ...` (online), Koios (light), `offlineTransfer.json` (offline) | node socket, Koios, offline snapshot |
| `Submitter` | Submit a signed transaction and return its id | `cardano-cli transaction submit`, Koios `submittx`, queueing in the transfer file | node socket, Koios, queue-to-transport |
| `Signer` | Produce witnesses or signatures for a transaction body, certificate, or message | `cardano-cli transaction sign/witness`, `cardano-hw-cli transaction witness`, `cardano-signer sign` | vault key, hardware wallet (cardano-hw-cli), remote signer |
| `Transport` | Move requests, snapshots, and signed artefacts between machines and parties | `offlineTransfer.json` carried by hand | file carry bag, secure channel (server mode) |
| `Directory` | Third-party lookups that are not chain state: ADA Handle resolution, token registry, pool metadata URLs, Catalyst API, light-mode parameter file | `curl` to `adahandleAPI`, `tokenMetaServer`, metadata URLs, `catalystAPI`, `lightModeParametersURL` | HTTP, offline snapshot |
| `Clock` | Wall-clock time and slot/time conversion | `date`, genesis arithmetic | system clock, fixed clock (tests) |
| `Toolchain` | Locate external tools and report their versions, for compatibility gates | `exists`, `versionCheck`, `<tool> version` | release-set manifest (Nix), PATH probe |
| `UI` | Prompts, confirmations, password entry, display | `ask`, `ask_pass`, `$(tty)` | CLI, TUI, server API |

## Operations

Seed list, extended with every operation a spec marked *(new)*. The *Specs* column names where an added operation came from.

| Port | Operation | Purpose |
| --- | --- | --- |
| `Toolchain` | `locate(tool)` / `version(tool)` | Presence and version gates (Cconf) |
| `Store` | `get(Settings)` / `get(Genesis)` | Operator settings (`common.inc`) and genesis parameters (Cconf, Cchain) |
| `Store` | `importWorkspace(dir)` / `listByRole(role)` | Import an upstream directory; enumerate artefacts by role (Pfiles) |
| `Clock` | `now()` / `slotAt(instant, genesis)` / `epochAt(instant, genesis)` / `timeUntilNextEpoch(genesis)` | Offline time arithmetic (Cchain) |
| `ChainQuery` | `syncStatus()` / `votesSummary(actionId)` / `assetHolders(policy, name)` / `assetUtxos(policy, name)` | Sync gate, vote summary, ADA Handle verification (Cchain, Clight, Caddr) |
| `Ledger` | `encodeAddress(bytes, network)` | Bech32 address from raw bytes (Caddr) |
| `Ledger` | `parseUtxoText(raw)` | Canonical UTxO set from cli text, Koios or snapshot form (Cutxo) |
| `Ledger` | `cborEncode(value)` (also called `encodeCbor`) / `assetFingerprint(policy, name)` / `convertGovernanceId(id, form)` | Encodings: CBOR, CIP-14, CIP-129 (Cconv) |
| `Ledger` | `canonicalizeBody(body)` / `canonicalizeForHardware(body)` / `auxDataHash(aux)` | Hardware-wallet canonical CBOR, auxiliary-data hash correction (Ctx, Ptx) |
| `Ledger` | `encryptMessage(msg, passphrase)` | CIP-83 basic message encryption (Pparam) |
| `Signer` | `openHardwareSession()` | Device detection, app and firmware version gates (Chw) |
| `Transport` | `clear(tx \| history \| files)` | Transfer-bag housekeeping (Ptransfer) |
| `Directory` | `checkTickerProtection(ticker)` | Pool ticker protection lookup (Pfiles, 05a) |
| `KeyGen` | `generate(BLS)` / `deriveFromMnemonics(words, path)` / `exportHardwareKey(path)` / `deriveVerificationKey(skey)` | BLS (testnet), CIP-1852 derivation, hardware public keys (04f, 03a, 21a, 23a) |
| `Ledger` | `poolId(coldVkey)` / `convertPoolId(id, form)` / `vrfKeyHash(vkey)` / `keyHash(vkey)` / `credentialHash(vkey)` / `deriveId(vkey, kind)` / `calidusId(vkey)` | Identifiers (04a, 05a, 0x, 10, 21a, 23a, 15) |
| `Ledger` | `newCounter(coldVkey)` / `decodeOpCert(opcert)` | Opcert counter and decoding (04a, 04d, 04e, 0x) |
| `Ledger` | `decodeCertificate(cert)` | Read pool id, DRep, deposit from a certificate (06, 08b, 22b, 05c) |
| `Ledger` | `metadataHash(bytes)` / `anchorHash(bytes)` / `blake2b256(bytes)` / `verifyAnchorDocument(bytes)` / `verifyCip100(doc)` | Pool metadata and governance anchors (05a, 0x, 21b, 21c, 23e, 24a, 25a) |
| `Ledger` | `makeNativeScript(spec)` / `policyId(script)` | Minting policies (10) |
| `Ledger` | `makeVote(spec)` / `viewVote(file)` / `buildGovernanceAction(kind, params)` / `viewGovernanceAction(file)` / `scriptCost(body, utxos, params, eraHistory)` | Governance artefacts and Plutus cost (24a, 25a, 25b) |
| `Ledger` | `validateFingerprint(text)` / `bech32Convert(data, hrp)` | CIP-14 checks, bech32 re-encoding (01sendAssets, 10) |
| `Signer` | `signOpCert(coldKeyRef, kesVkey, counter, period)` | Operational certificate issue (04d) |
| `Signer` | `signCip88(payload, keyRef)` / `verifyCip8(signature)` / `signRegistryEntry(entry, keyRef)` / `signCip36(registration, keyRef)` | Calidus, token registry and Catalyst signatures (15, 12a, 09a) |
| `Signer` | `witness(body, keyRef, {unrestricted})` | Hardware signing of a body whose certificate the device does not own (21b, 24b) |
| `ChainQuery` | `opCertCounter(poolId)` / `kesPeriodInfo(opcert)` / `calidusKeys(poolId)` | Pool operation reads (04d, 04e, 15) |
| `ChainQuery` | `constitution()` / `lastEnactedActionIds()` / `eraHistory()` / `govActions(filter)` / `drepStakeDistribution()` / `spoStakeDistribution()` | Governance reads (24a, 24c, 25a, 25b) |
| `Clock` | `kesPeriod(slot, genesis)` / `kesExpiry(startPeriod, genesis)` | KES arithmetic (04d, 04e) |
| `Store` | `latest(OperationalCertificate, pool)` / `get/put/delete(WitnessCollection)` / `get/put(WitnessTransferFile)` / `get(GuardrailsScript)` | Typed artefacts (04d, 05c, 05d, 25b) |
| `Directory` | `poolInfo(poolId)` / `poolUpdates(poolId)` / `txMetadata(txId)` / `catalystVoter(key)` / `catalystDelegation(key)` / `registryEntryBuilder()` | Koios, Catalyst API, token-metadata-creator (0x, 13a, 09a, 12a) |
| `UI` | `choose(options)` / `askText(prompt)` / `show(qr)` | Selection, free text, QR display (24a, 0x, 09a) |
| `Store` | `get(artefact)` / `put(artefact)` / `exists(artefact)` / `delete(artefact)` | Typed artefact access; the file adapter maps an artefact to a file name per `Pfiles` |
| `Store` | `lock(artefact)` / `unlock(artefact)` | Upstream write protection (`chmod 400/600`); other adapters may make it a no-op or an immutability flag |
| `Vault` | `seal(secret, policy)` / `unseal(ref, passphrase?)` | Store and retrieve signing keys; `unseal` returns an in-memory handle only |
| `Vault` | `exportPlaintext(ref, destination)` | Named, audited export (for example the block-producer KES key) |
| `KeyGen` | `generate(keyKind)` | Payment, stake, cold, VRF, KES, DRep, committee, policy, Calidus keys |
| `Ledger` | `buildRaw(txSpec)` / `minFee(body, witnessCount)` / `minOutputValue(output)` / `assemble(body, witnesses)` / `txId(tx)` | Transaction construction |
| `Ledger` | `makeCertificate(kind, params)` | Stake, pool, DRep, committee, vote-delegation certificates |
| `Ledger` | `addressInfo(address)` / `buildAddress(credentials)` | Address inspection and derivation |
| `ChainQuery` | `tip()` / `protocolParameters()` / `utxos(address)` / `rewardAccount(stakeAddress)` | Core reads |
| `ChainQuery` | `poolState(poolId)` / `drepState(drepId)` / `committeeState()` / `govActionState(actionId)` / `votes(actionId)` | Pool and governance reads |
| `Submitter` | `submit(signedTx) -> txId` | Online or light submission; offline mode queues through `Transport` instead |
| `Signer` | `witness(body, keyRef) -> witness` / `signTx(body, keyRefs) -> signedTx` / `signMessage(payload, keyRef)` | Signing |
| `Transport` | `snapshot(addresses, extras)` / `importSnapshot()` / `enqueueTx(signedTx)` / `dequeueTx(n)` / `attach(file)` / `extract(file)` | Air-gap bag operations (`01_workOffline`) |
| `Directory` | `resolveHandle(handle)` / `tokenMetadata(subject)` / `fetchUrl(url)` | Third-party lookups |
| `UI` | `confirm(prompt, default)` / `askPassword(prompt)` / `show(view)` | Interaction |
