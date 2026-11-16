+++
id = "Ptx"
kind = "pattern"
title = "The shared transaction pipeline"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["transaction-construction", "wallet", "stake-delegation", "pool-operations", "governance", "native-assets", "chain-access", "key-custody", "air-gap-transfer"]
use_cases = ["BuildAndSignTransaction", "SubmitOrQueueTransaction"]
depends_on = ["Cconf", "Cchain", "Clight", "Caddr", "Cutxo", "Cconv", "Coffline", "Chw", "Ckey", "Cui", "Ctx", "Pparam", "Pfiles", "Ptransfer"]
sources = [
  "01_sendLovelaces.sh",
  "01_sendAssets.sh",
  "01_claimRewards.sh",
  "03b_regStakingAddrCert.sh",
  "05c_regStakepoolCert.sh",
  "06_regDelegationCert.sh",
  "07b_deregStakepoolCert.sh",
  "08b_deregStakingAddrCert.sh",
  "11a_mintAsset.sh",
  "11b_burnAsset.sh",
  "21b_regDRepCert.sh",
  "21d_retDRepCert.sh",
  "22b_regVoteDelegCert.sh",
  "23c_regComAuthCert.sh",
  "23e_retComColdKeys.sh",
  "24b_regVote.sh",
  "25b_regAction.sh",
  "00_common.sh",
]
+++

# Ptx: the shared transaction pipeline

Seventeen scripts build, sign and submit a Cardano transaction that spends the UTxOs of one *paying address*, returns the change to it (or to a destination), and attaches something: nothing (a payment), a withdrawal, a certificate, a mint, a vote or a governance action. They all run the same pipeline. The canonical instance is `01_sendLovelaces.sh`; the others differ at a small, enumerable set of **variation points**. This pattern specifies the pipeline once, stage by stage, and lists the variation points per script in the tables at the end. Per-script specs say "follows SPO-Ptx-... except ..." and add only what the table does not cover.

The pipeline, in order:

1. **Prepare**: parse extra parameters (see `Pparam`), resolve names to addresses, check key files exist.
2. **Clock**: current slot from the work mode's source; TTL = slot + `defTTL`.
3. **Gather inputs**: UTxOs of the paying address from node, Koios or the transfer file; filters; refusal when empty.
4. **Collect assets**: totals of lovelaces and native assets over all inputs; registry names for display.
5. **Parameters**: protocol parameters from the work mode's source.
6. **Dummy body and fee**: build a body with a placeholder fee, ask `cardano-cli` for the minimum fee with a fixed witness count.
7. **Balance**: compute the change output, check minimum output values, refuse when funds are short.
8. **Final body**: rebuild with the real fee and change.
9. **Sign**: hardware-wallet witness plus assemble, or key-file signing in memory.
10. **Size check**: refuse a transaction above `maxTxSize`.
11. **Confirm**: operator confirmation.
12. **Submit or queue**: node, Koios, or append to the transfer file with read-back.

## Interface

- **SPO-Ptx-IF-001** The positional words name the paying address first or second (see the variation table) and, depending on the script, a stake account, pool, DRep, policy, destination or amount. All remaining words are *extra parameters* with the grammar and acceptance table of `Pparam` (SPO-Pparam-IF-001). A name is normalised as in SPO-Pfiles-IN-001. (src: 01_sendLovelaces.sh:L19-L23, 01_sendLovelaces.sh:L75-L84, 06_regDelegationCert.sh:L60-L62, 25b_regAction.sh:L70-L72)
- **SPO-Ptx-IF-002** With too few positional words a script prints usage on stderr and exits 1. (src: 01_sendLovelaces.sh:L19-L70, 06_regDelegationCert.sh:L21-L58)

## Inputs

- **SPO-Ptx-IN-001** The paying address is read from `<pay>.addr` and checked as a valid address; the destination likewise. (src: 01_sendLovelaces.sh:L228-L232, 06_regDelegationCert.sh:L360-L361)
- **SPO-Ptx-IN-002** The script requires `<pay>.addr` and either `<pay>.skey` or `<pay>.hwsfile`, and refuses with exit 1 before any query if one is missing. `01_claimRewards`, `08b` and `11a`/`11b` refuse missing signing files for the stake key, the stake account files or the policy key with exit 2, and so does `01_claimRewards` for the payer's signing file; `25b` refuses a hardware payment wallet outright (exit 1) and requires `<pay>.skey`. (src: 01_sendLovelaces.sh:L170-L171, 06_regDelegationCert.sh:L66-L70, 01_claimRewards.sh:L177-L178, 01_claimRewards.sh:L215, 08b_deregStakingAddrCert.sh:L67-L72, 11a_mintAsset.sh:L70-L72, 25b_regAction.sh:L73-L77)
- **SPO-Ptx-IN-003** Settings read: the work mode (`online`, `light`, `offline`), the era for `cardano-cli`, `defTTL` (100000 slots by default), `cropTxOutput`, `queryTokenRegistry`, `transactionExplorer`, `offlineFile`, and the environment variable `ENV_SKIP_PROMPT`. (src: 00_common.sh:L353, 00_common.sh:L94-L96, 00_common.sh:L319-L332, 00_common.sh:L510-L513, 01_sendLovelaces.sh:L658)
- **SPO-Ptx-IN-004** The protocol-parameter fields the pipeline itself reads are `maxTxSize` (size check), `protocolVersion.major` (minimum output value method, certificate format), `stakeAddressDeposit` (`03b`), `stakePoolDeposit` (`05c`) and `dRepDeposit` (`21b`); everything else is passed on to `cardano-cli` as a file. (src: 01_sendLovelaces.sh:L651, 03b_regStakingAddrCert.sh:L332, 05c_regStakepoolCert.sh:L670, 21b_regDRepCert.sh:L216, 00_common.sh:L1280-L1294)

## Behaviour

### Stage 2: clock and TTL

- **SPO-Ptx-MODE-001** The current slot is taken from the work mode's source: online from `cardano-cli query tip` (up to three attempts, then a fatal error), light from Koios, offline computed from the Byron and Shelley genesis files and the wall clock (so the offline machine's clock must be right). (src: 00_common.sh:L900-L965)
- **SPO-Ptx-INV-001** The transaction's validity end (`--invalid-hereafter`) is `slot + defTTL` with the default 100000 slots (about 27.8 hours on a network with one-second slots). Exceptions: `11a` and `11b` use the `before` slot of the policy script when one exists (refusing with exit 2 when it is not after the current slot), `05c` keeps the TTL stored in an open witness collection (refusing with exit 1 when that TTL is already below the current slot), and `25b` uses a fixed 25000 slots (SPO-25b-INV-003). (src: 01_sendLovelaces.sh:L240-L243, 11a_mintAsset.sh:L185-L194, 11b_burnAsset.sh:L181-L190, 05c_regStakepoolCert.sh:L376-L385)

### Stage 3: input gathering

- **SPO-Ptx-MODE-002** *Online.* The script refuses with exit 1 unless the node reports fully synced, then reads the paying address's UTxOs with `cardano-cli <era> query utxo --output-text --address <addr>`, applies the filters of `Pparam` (SPO-Pparam-IF-020 .. SPO-Pparam-IF-022) to the raw rows where the script supports them, and converts the rows to the UTxO JSON form (see `Cutxo`). A failing query prints the error and exits **0**: the line is `echo ...; exit $?`, so the exit status is that of the preceding `echo`. The same line is in `01_sendLovelaces.sh:L262`, `11a:L215`, `11b:L213`, `22b:L375`, `23e:L383`, `24b:L385` and `25b:L491`. (src: 01_sendLovelaces.sh:L257-L268, 06_regDelegationCert.sh:L376-L383)
  > **Upstream quirk:** a failed UTxO query looks like success to a caller. A port exits non-zero. (src: 01_sendLovelaces.sh:L256-L268, 06_regDelegationCert.sh:L374-L382)
- **SPO-Ptx-MODE-003** *Light.* The UTxOs come from Koios (`queryLight_UTXO`), then the same filters and conversion as online. A failing query exits **0** exactly as in SPO-Ptx-MODE-002 (`01_sendLovelaces.sh:L273`, `11a:L223`, `11b:L221`, `22b:L382`, `23e:L390`, `24b:L392`, `25b:L498`). (src: 01_sendLovelaces.sh:L270-L279, 06_regDelegationCert.sh:L384-L389)
- **SPO-Ptx-MODE-004** *Offline.* The transfer file is validated (SPO-Ptransfer-IN-001) and the UTxOs are read from `address."<bech32>".utxoJSON`. If the address is not in the file the script refuses with exit 1 and tells the operator to include it online first (`01_workOffline.sh add`). The `utxolimit`/`skiputxowithasset`/`onlyutxowithasset` filters are not applied offline. `01_claimRewards` also needs the stake address in the file (`address."<stake bech32>".rewardsJSON`) and refuses with exit 0 if it is missing. (src: 01_sendLovelaces.sh:L282-L285, 06_regDelegationCert.sh:L391-L394, 01_claimRewards.sh:L294-L297, 01_claimRewards.sh:L460-L463)
- **SPO-Ptx-PRE-001** A candidate set with zero UTxOs (after any `txhash#index` restriction, SPO-Pparam-IF-019) is refused with exit 1: no funds on the source address. (src: 01_sendLovelaces.sh:L289-L292, 06_regDelegationCert.sh:L397-L398)
- **SPO-Ptx-INV-002** Every UTxO in the candidate set is spent: there is no coin selection. The body has one `--tx-in` per UTxO, so a wallet with many UTxOs yields a large transaction, which the size check of SPO-Ptx-PRE-006 may refuse. The operator's levers are the input-selection tokens of `Pparam`. (src: 01_sendLovelaces.sh:L291-L292, 01_sendLovelaces.sh:L370)
- **SPO-Ptx-OUT-001** A UTxO that carries a datum hash shows it (display only); no script input is ever added, so spending from script addresses is not supported. (src: 01_sendLovelaces.sh:L314)

### Stage 4: asset collection and registry

- **SPO-Ptx-INV-003** Totals are the sum of lovelaces over all inputs, and per asset type (policy id plus hex asset name) the sum of amounts over all inputs, using arbitrary-precision arithmetic. (src: 01_sendLovelaces.sh:L294-L343)
- **SPO-Ptx-INV-004** The assets that return to the change output are written as `+<amount> <policyid>[.<assetnamehex>]` per asset type with an amount greater than zero; types with a zero or negative total are omitted. All assets of the inputs end up in exactly one output (the change output, or the destination for send-all variants). (src: 01_sendLovelaces.sh:L403)
- **SPO-Ptx-MODE-005** *Token registry (display only).* When `queryTokenRegistry` is on, a name and ticker per asset are fetched: online and light from the registry URL, offline from `tokenMetaServer."<subject>"` of the transfer file. A failed or missing lookup shows nothing and never stops the script. (src: 01_sendLovelaces.sh:L395-L398, 06_regDelegationCert.sh:L505-L508)
- **SPO-Ptx-OUT-002** The summary (ADA handle labels, tokens, metadata, message text, TTL) is display only. The one display item that is a security matter is the clear-text passphrase of SPO-Pparam-SEC-001.

### Stage 5: protocol parameters

- **SPO-Ptx-MODE-006** Protocol parameters come from the work mode's source: online from `cardano-cli <era> query protocol-parameters`, light from the Light-Mode parameters document fetched at start, offline from `.protocol.parameters` of the transfer file. A failing query ends the script with its exit code. In the transaction-building scripts this happens after the UTxO stage, except in `21b`, `21d`, `24b` and `25b` where it happens before it (the order has no effect on the result). (src: 01_sendLovelaces.sh:L423-L429, 06_regDelegationCert.sh:L534-L540, 21b_regDRepCert.sh:L196-L205, 24b_regVote.sh:L333-L342, 25b_regAction.sh:L443-L452)
- **SPO-Ptx-MODE-007** The era used for `cardano-cli` is the node's era (online), the Light-Mode document's era (light), or `.protocol.era` of the transfer file (offline). (src: 00_common.sh:L650-L663)

### Stage 6: dummy body and fee

- **SPO-Ptx-EXT-001** A dummy transaction body is built with `cardano-cli <era> transaction build-raw` into `<tempDir>/dummy.txbody`: one `--tx-in` per UTxO; the outputs with placeholder amounts of the same number and shape as the final ones (for the certificate, mint, vote and action scripts one output holding the full input lovelace total, not yet reduced by fee or deposit); `--invalid-hereafter <ttl>`; `--fee 200000`; every metadata file; and the script's attachments (`--certificate`, `--withdrawal`, `--mint` and `--minting-script-file`, vote or action files, proposal script and collateral). A build failure ends the script with `cardano-cli`'s exit code (`checkError`), except the final build of `01_claimRewards` (SPO-Ptx-EXT-004). (src: 01_sendLovelaces.sh:L463-L474, 06_regDelegationCert.sh:L547-L551, 01_claimRewards.sh:L607-L617, 11a_mintAsset.sh:L398-L401)
- **SPO-Ptx-INV-005** The placeholder fee is 200000 lovelaces on purpose: any value between 65536 and 4294967296 has the same five-byte CBOR encoding, so the real fee does not change the body size and the fee estimate stays valid. A port must use a placeholder with the same encoding length, or compute the fee by body length. (src: 01_sendLovelaces.sh:L467, 01_sendLovelaces.sh:L471)
- **SPO-Ptx-EXT-002** The minimum fee comes from `cardano-cli <era> transaction calculate-min-fee --output-text --tx-body-file <dummy> --protocol-params-file <params> --witness-count <N> --reference-script-size 0`; the fee is the first whitespace-separated word of the output. A failing call prints the output and exits 1. (src: 01_sendLovelaces.sh:L476-L479, 06_regDelegationCert.sh:L553-L556)
- **SPO-Ptx-INV-006** The witness count `N` is a constant per script, not derived from the inputs: 1 for `01_sendLovelaces`, `01_sendAssets` and `25b` (non-guardrail actions); 2 for `01_claimRewards`, `03b`, `06`, `07b`, `08b`, `11a`, `11b`, `21b`, `21d`, `22b`, `23c`, `23e`, `24b` and `25b` (guardrail actions: treasury withdrawal, parameter change); and `2 + number of pool owners` for `05c`. The extra witnesses of a pool owner who is also the reward account are not counted separately. (src: 01_sendLovelaces.sh:L477, 01_sendAssets.sh:L680, 01_claimRewards.sh:L620, 03b_regStakingAddrCert.sh:L556, 06_regDelegationCert.sh:L554, 07b_deregStakepoolCert.sh:L406, 08b_deregStakingAddrCert.sh:L540, 11a_mintAsset.sh:L404, 11b_burnAsset.sh:L401, 21b_regDRepCert.sh:L574, 21d_retDRepCert.sh:L452, 22b_regVoteDelegCert.sh:L550, 23c_regComAuthCert.sh:L497, 23e_retComColdKeys.sh:L558, 24b_regVote.sh:L553, 25b_regAction.sh:L752, 25b_regAction.sh:L767, 05c_regStakepoolCert.sh:L331, 05c_regStakepoolCert.sh:L345, 05c_regStakepoolCert.sh:L662)

### Stage 7: balance and minimum values

- **SPO-Ptx-INV-007** The change output pays `inputs − fee ∓ (deposit or refund) [+ withdrawal]` to the paying address together with all assets, in one output (`rxcnt=1`), for every certificate, mint, vote and action script. The per-script amounts are in the variation table. (src: 06_regDelegationCert.sh:L565-L568, 03b_regStakingAddrCert.sh:L567-L575, 08b_deregStakingAddrCert.sh:L556-L558, 05c_regStakepoolCert.sh:L688-L691)
- **SPO-Ptx-EXT-003** The minimum lovelaces an output with the change's assets must hold comes from `calc_minOutUTXO` over the output text `<address>+1000000<assets>` and the protocol parameters (CIP-55 byte-length rule from protocol major version 7 on). (src: 06_regDelegationCert.sh:L542, 00_common.sh:L1280-L1300)
- **SPO-Ptx-PRE-002** When the change output would hold fewer lovelaces than that minimum, the script refuses with the gist "not enough funds on the source address, minimum UTxO value is N". The exit code is 1 in `01_sendLovelaces` and `01_sendAssets`, but **0** in every other pipeline script (a bare `exit` after the message). (src: 01_sendLovelaces.sh:L495, 01_sendAssets.sh:L695, 06_regDelegationCert.sh:L572, 03b_regStakingAddrCert.sh:L577, 05c_regStakepoolCert.sh:L694, 01_claimRewards.sh:L634, 01_claimRewards.sh:L645, 11a_mintAsset.sh:L415, 24b_regVote.sh:L573, 25b_regAction.sh:L791)
  > **Upstream quirk:** a caller (the workbench orchestrator, a script wrapper) sees success. A port exits non-zero.
- **SPO-Ptx-PRE-003** In `01_sendLovelaces` and `01_sendAssets` the amount to the destination must itself reach the minimum output value, and the returned remainder (with assets) must reach it too; otherwise exit 1. The keyword amounts (`ALL`, `ALLFUNDS`, `MIN`) change which output is the remainder. The amount grammar belongs to the `01_sendLovelaces` and `01_sendAssets` specs. (src: 01_sendLovelaces.sh:L436-L554, 01_sendAssets.sh:L668, 01_sendAssets.sh:L693-L695)
- **SPO-Ptx-PRE-004** `01_claimRewards` exits 1 when the reward balance is zero, and `01_sendLovelaces` with `ALLFUNDS` refuses when the total minus the fee is below the minimum. (src: 01_claimRewards.sh:L421-L422, 01_sendLovelaces.sh:L490-L495)

### Stage 8: final body

- **SPO-Ptx-EXT-004** The final body is built with the same `build-raw` call as SPO-Ptx-EXT-001 but with the real fee and the computed change amount, into `<tempDir>/<payName>.txbody`, and a failure ends the script with `cardano-cli`'s code. **Upstream quirk:** in `01_claimRewards` the final build is unchecked and the previous body file is not removed first, so a failed build leaves the body of an earlier run to be signed and submitted (SPO-01claimRewards-PRE-009). (src: 01_sendLovelaces.sh:L556-L573, 06_regDelegationCert.sh:L574-L585, 01_claimRewards.sh:L659-L663)
- **SPO-Ptx-OUT-003** The body, witness and signed-transaction files are `<tempDir>/<payName>.txbody`, `.txwitness` (also `.txwitness2`, `-payment`, `-staking`, ...) and `.tx`, replaced on every run (see SPO-Pfiles-OUT-039). The body and the signed transaction are printed, cropped to 4000 characters when `cropTxOutput` is on (display only). (src: 01_sendLovelaces.sh:L556-L558, 01_sendLovelaces.sh:L575, 01_sendLovelaces.sh:L645)

### Stage 9: signing

- **SPO-Ptx-INV-008** A payment address is signed by hardware when `<pay>.hwsfile` exists, and with a key file otherwise. For combined scripts (payment plus stake, node, DRep, committee or voter key) the hardware path is taken only when **all** needed keys are hardware files (and, for wallet-plus-stake scripts, belong to the same wallet name); the key-file path needs all `.skey` files. The mixed combinations are listed in the signing table below. (src: 01_sendLovelaces.sh:L583, 06_regDelegationCert.sh:L592-L596, 06_regDelegationCert.sh:L628, 07b_deregStakepoolCert.sh:L442, 07b_deregStakepoolCert.sh:L475)
- **SPO-Ptx-EXT-005** *Hardware path.* In order: (1) `autocorrect_TxBodyFile` rewrites the body in canonical (hardware-wallet) form with `cardano-hw-cli transaction transform`, failure exits 1; (2) the hardware session is started (`start_HwWallet`, see `Chw`); (3) `cardano-hw-cli transaction witness --tx-file <body> --hw-signing-file <file>... [--change-output-key-file <file>...] <network magic> --out-file <witness>...` produces one witness per signing file; (4) `cardano-cli <era> transaction assemble --tx-body-file <body> --witness-file <w>... --out-file <tx>`. (src: 01_sendLovelaces.sh:L583-L626, 06_regDelegationCert.sh:L595-L625, 00_common.sh:L2704-L2731)
- **SPO-Ptx-INV-009** For the hardware path the change output keys are declared with `--change-output-key-file` so the device does not show the change as an unknown output: for wallet-plus-stake scripts both the payment and stake hwsfile are declared; in `01_sendLovelaces` only when the change is a second output and `<name>.staking.hwsfile` exists. (src: 01_sendLovelaces.sh:L598-L610, 06_regDelegationCert.sh:L609, 03b_regStakingAddrCert.sh:L619)
- **SPO-Ptx-PRE-005** The output of `cardano-hw-cli` is classified case-insensitively: `REJECTED` (the user declined on the device), `DISCONNECT` and `ERROR` stop the script with exit 1; `WARNING` is shown and signing continues. (src: 01_sendLovelaces.sh:L610-L622, 06_regDelegationCert.sh:L609-L621)
- **SPO-Ptx-EXT-006** *Key-file path.* Each needed signing key is read into memory with `read_skeyFILE` (decrypting an encrypted key, see `Ckey`); a read failure prints the error and exits 1. The transaction is signed with `cardano-cli <era> transaction sign --tx-body-file <body> --signing-key-file <(echo "<key json>")... --out-file <tx>` using process substitution, and the variables holding the keys are unset afterwards. (src: 01_sendLovelaces.sh:L630-L640, 06_regDelegationCert.sh:L630-L643)
- **SPO-Ptx-SEC-001** A signing key never touches the disk during signing: decrypted key text lives in shell variables and is handed to `cardano-cli` through an anonymous pipe. The password prompt and the way the password reaches `gpg` are specified in `Ckey` (SPO-Ckey-SEC-001). (src: 01_sendLovelaces.sh:L631-L640, 06_regDelegationCert.sh:L631-L643)
- **SPO-Ptx-PRE-006** Mixed combinations are refused with exit 1: a hardware key together with a key-file key in `01_claimRewards`, `03b`, `06`, `07b`, `08b`, `22b`, `23c`, `23e` and (payment hardware, voter key file) in `24b`. A hardware wallet can only pay for its own stake, node or committee operation. (src: 01_claimRewards.sh:L720-L722, 03b_regStakingAddrCert.sh:L653-L655, 06_regDelegationCert.sh:L645-L647, 07b_deregStakepoolCert.sh:L490-L494, 08b_deregStakingAddrCert.sh:L634-L638, 22b_regVoteDelegCert.sh:L642-L644, 23c_regComAuthCert.sh:L594-L596, 23e_retComColdKeys.sh:L655-L657, 24b_regVote.sh:L705-L708)
- **SPO-Ptx-PR-001** Scripts that sign with separate witnesses ask before each hardware witness: `11a` and `11b` ("adding the policy witness / payment witness from a local hardware wallet, continue?", default Yes, declining exits 2); `24b` and `05c` ask the same before their hardware witnesses; `21b`, `21d`, `24b` also ask whether to allow `--allow-unrestricted-mode` on the device when a hardware wallet pays for a transaction with a key-file DRep or voter (default Yes, declining aborts). (src: 11a_mintAsset.sh:L455-L460, 11a_mintAsset.sh:L489-L492, 24b_regVote.sh:L291-L293, 24b_regVote.sh:L618, 21b_regDRepCert.sh:L676-L678, 21d_retDRepCert.sh:L553-L555, 05c_regStakepoolCert.sh:L753)

### Stage 10: size check

- **SPO-Ptx-PRE-007** The signed transaction's size is `len(cborHex) / 2` bytes. A size above `maxTxSize` of the protocol parameters is refused with exit 1 before the confirmation. `01_claimRewards` has no such check. (src: 01_sendLovelaces.sh:L648-L653, 06_regDelegationCert.sh:L653-L658, 05c_regStakepoolCert.sh:L1015-L1020, 01_claimRewards.sh:L723-L731)
  > **Upstream quirk:** `01_claimRewards` can produce a transaction that the node rejects as too large. A port applies the check everywhere.

### Stage 11: confirmation

- **SPO-Ptx-PR-002** Before anything is submitted or queued the operator is asked "Does this look good for you, continue?" with default **No** (an empty answer is No; other answers repeat the question). A refusal ends the script with exit 0 and nothing is submitted, queued or changed. (src: 01_sendLovelaces.sh:L656-L658, 00_common.sh:L754-L786)
- **SPO-Ptx-PR-003** When the environment variable `ENV_SKIP_PROMPT` equals `YES`, the prompt of SPO-Ptx-PR-002 is skipped, but only in `01_sendLovelaces`, `01_sendAssets`, `01_claimRewards`, `03b`, `11a`, `11b`, `21b`, `21d`, `24b` and `25b`. `05c`, `06`, `07b`, `08b`, `22b`, `23c` and `23e` ignore it and always ask, and so does `01_workOffline execute`. (src: 01_sendLovelaces.sh:L658, 01_sendAssets.sh:L791, 01_claimRewards.sh:L731, 03b_regStakingAddrCert.sh:L670, 11a_mintAsset.sh:L537, 11b_burnAsset.sh:L536, 21b_regDRepCert.sh:L786, 21d_retDRepCert.sh:L663, 24b_regVote.sh:L728, 25b_regAction.sh:L893, 06_regDelegationCert.sh:L661, 07b_deregStakepoolCert.sh:L507, 08b_deregStakingAddrCert.sh:L653, 22b_regVoteDelegCert.sh:L658, 23c_regComAuthCert.sh:L610, 23e_retComColdKeys.sh:L671, 00_common.sh:L22)
- **SPO-Ptx-PR-004** `05c` asks twice, both default No: once after building the body ("does this look good, continue?", declining exits 1) and once before submitting ("do you have enough pledge in your owner account(s), continue and register on chain?"). In offline mode it additionally asks, default No, whether to attach the pool metadata file and the extended metadata file to the transfer file. It never honours `ENV_SKIP_PROMPT`. A "no" at the second prompt does not submit; it offers, default No, to delete the witness collection from `<pool>.pool.json`. (src: 05c_regStakepoolCert.sh:L720, 05c_regStakepoolCert.sh:L1046, 05c_regStakepoolCert.sh:L1139-L1155)

### Stage 12: submit or queue

- **SPO-Ptx-MODE-008** *Online.* The signed transaction is submitted with `cardano-cli <era> transaction submit --tx-file <tx>`; on success the transaction id is read with `transaction txid --output-text` and shown, with a link `<transactionExplorer>/<txid>` when an explorer is configured. A failed submit ends the script with `cardano-cli`'s code in most scripts (`checkError`), but with exit 0 in `06`, `08b`, `22b`, `23c`, `23e` and the light-mode branch of every script (`exit $?` after an `echo`); `05c` exits 1 (SPO-Ptx-MODE-009). (src: 01_sendLovelaces.sh:L662-L673, 05c_regStakepoolCert.sh:L1055-L1068, 06_regDelegationCert.sh:L665-L676, 08b_deregStakingAddrCert.sh:L657-L667, 22b_regVoteDelegCert.sh:L665-L666, 23c_regComAuthCert.sh:L617-L618, 23e_retComColdKeys.sh:L678-L679)
- **SPO-Ptx-MODE-009** *Light.* The signed transaction's `cborHex` is posted to Koios (`submitLight`, up to five attempts, HTTP 202 required, the returned id must be 64 hex characters); the id is shown with the explorer link. A failure prints the error and exits with the status of the preceding `echo` (0), except `05c`, which exits 1. (src: 01_sendLovelaces.sh:L675-L682, 05c_regStakepoolCert.sh:L1089-L1104, 00_common.sh:L2000-L2050)
  > **Upstream quirk:** failed light-mode submissions exit 0. A port exits non-zero.
- **SPO-Ptx-MODE-010** *Offline.* The signed transaction is not submitted. It is appended to the transfer file as specified in SPO-Ptransfer-OUT-010 .. SPO-Ptransfer-OUT-012: `transactions[]` entry with `type` per the table, `history` entry, `general.offlineCLI`, whole-file rewrite, read-back comparison of `transactions[-1].txJSON`, and the file summary on success. A read-back mismatch prints an error and still exits 0. (src: 01_sendLovelaces.sh:L684-L707, 06_regDelegationCert.sh:L689-L713)
- **SPO-Ptx-INV-010** Submission uses exactly the transaction that was shown and confirmed; nothing is rebuilt after the prompt. (src: 01_sendLovelaces.sh:L644-L665)

### Variation: `05c`, the witness collection

- **SPO-Ptx-INV-011** `05c` replaces stages 9 to 12 by a witness collection stored in `<pool>.pool.json` under `regWitness` (id, type, ttl, paying-address name, body, hardware flag, metadata list, and one witness slot per signer: the pool cold key, the paying address and every owner staking key). The first run builds the body (stages 3 to 8, certificates: the pool registration certificate plus one delegation certificate per owner; with any hardware owner, or a hardware cold key, only the registration certificate) and fills the slots it can sign locally; later runs with the same paying address reuse the stored body and TTL, and refuse a different paying address, new metadata, or a `type:` override with exit 1. When all slots are filled the transaction is assembled, size-checked, confirmed (SPO-Ptx-PR-004) and submitted or queued. (src: 05c_regStakepoolCert.sh:L176-L184, 05c_regStakepoolCert.sh:L328-L367, 05c_regStakepoolCert.sh:L376-L390, 05c_regStakepoolCert.sh:L486-L501, 05c_regStakepoolCert.sh:L720-L746, 05c_regStakepoolCert.sh:L990-L1020)
- **SPO-Ptx-OUT-004** On a successful online or light submit `05c` records `regEpoch` and `regSubmitted` in `<pool>.pool.json`, deletes `regWitness`, and deletes `<pool>.pool.cert`; after a successful offline queueing it does the same with `regSubmitted` marked "only offline, no proof". `11a` and `11b` update `<policy>.<asset>.asset` after a successful submit and, offline, after queueing; `07b` records `deregSubmitted` in `<pool>.pool.json` online and light, and offline after a verified queueing. (src: 07b_deregStakepoolCert.sh:L543-L546, 07b_deregStakepoolCert.sh:L580-L584, 05c_regStakepoolCert.sh:L1055-L1070, 05c_regStakepoolCert.sh:L1089-L1103, 05c_regStakepoolCert.sh:L1163-L1182, 11a_mintAsset.sh:L555-L593, 11b_burnAsset.sh:L554-L593, 07b_deregStakepoolCert.sh:L517-L520)

## Work modes

Summary of the mode differences (each has its own requirement above): input source (SPO-Ptx-MODE-002 .. SPO-Ptx-MODE-004), clock (SPO-Ptx-MODE-001), registry (SPO-Ptx-MODE-005), parameters and era (SPO-Ptx-MODE-006, SPO-Ptx-MODE-007), submission (SPO-Ptx-MODE-008 .. SPO-Ptx-MODE-010). Chain-state preconditions of the certificate scripts (stake address registered, pool registered, DRep state) run in online and light mode only in `03b`, `06` and `08b`; `21b` and `21d` read the DRep state from the transfer file offline (refusing with exit 0 when the DRep is not in it); `23c` and `23e` do not support offline mode at all and exit 0 with a notice.

## Variation points

**Table A: what each script attaches and how the balance works.** "Witnesses" is the constant of SPO-Ptx-INV-006. `Skip` is whether `ENV_SKIP_PROMPT` is honoured (SPO-Ptx-PR-003). `Size` is whether the size check exists. "Offline type" is the `type` of the queued entry (SPO-Ptransfer-OUT-010).

| Script | Attaches | Witnesses | Change output | Skip | Size | Offline type | Pre-pipeline checks (online/light unless noted) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `01_sendLovelaces` | nothing | 1 | amount to destination, rest returned with assets (keywords `ALL`, `ALLFUNDS`, `MIN`) | yes | yes | `Transaction` | destination resolved from file, address or ADA Handle |
| `01_sendAssets` | nothing | 1 | selected assets plus minimum lovelaces to destination, rest returned | yes | yes | `Transaction` | asset selectors, `keeppolicy:` |
| `01_claimRewards` | `--withdrawal <stake addr>+<rewards>` | 2 | rewards plus inputs minus fee to destination; fee payer may differ (then two outputs) | yes | **no** | `Withdrawal` | stake address must be registered; rewards must be non-zero; protocol 10+ requires a DRep delegation (exit 1 otherwise) |
| `03b_regStakingAddrCert` | `--certificate <stake>.cert` | 2 | inputs minus fee minus key deposit (`stakeAddressDeposit`) | yes | yes | `StakeKeyRegistration` | exits 0 without a transaction if the stake address is already registered (online, light); the certificate is built here |
| `05c_regStakepoolCert` | pool registration cert plus one delegation cert per owner (or only the registration cert with a hardware owner) | 2 + owners | inputs minus fee minus pool deposit (`stakePoolDeposit`, zero for a re-registration) | **no** | yes | `PoolRegistration` or `PoolReRegistration` | witness collection (SPO-Ptx-INV-011), ticker protection check, metadata hash, owner certificate pool ids |
| `06_regDelegationCert` | `--certificate <stake>.deleg.cert` | 2 | inputs minus fee | **no** | yes | `DelegationCertRegistration` | pool must be registered; stake address must be registered |
| `07b_deregStakepoolCert` | `--certificate <pool.json deregCertFile>` | 2 | inputs minus fee (deposit refund goes to the reward account) | **no** | yes | `PoolRetirement` | none beyond file checks |
| `08b_deregStakingAddrCert` | `--certificate <stake>.dereg-cert` | 2 | inputs minus fee plus deposit refund (deposit decoded from the certificate; 2000000 for pre-Conway certificates) | **no** | yes | `StakeKeyDeRegistration` | rewards must be zero (exit 1), stake address registered |
| `11a_mintAsset` | `--mint "<n> <policy>.<name>"`, `--minting-script-file` | 2 | inputs minus fee, assets plus minted amount | yes | yes | `Asset-Minting` | policy not expired; TTL from policy |
| `11b_burnAsset` | `--mint "-<n> <policy>.<name>"`, `--minting-script-file` | 2 | inputs minus fee, assets minus burned amount | yes | yes | `Asset-Burning` | refuses burning more than held; TTL from policy |
| `21b_regDRepCert` | `--certificate <drep>.drep-reg.cert` | 2 | inputs minus fee minus DRep deposit (`dRepDeposit`, zero for an update) | yes | yes | `DRepIDRegistration` | DRep state (node, Koios or transfer file); anchor checks |
| `21d_retDRepCert` | `--certificate <drep>.drep-ret.cert` | 2 | inputs minus fee plus DRep deposit | yes | yes | `DRepIDRetirement` | DRep state from node, Koios or transfer file; exits 0 without a transaction when the DRep is not registered |
| `22b_regVoteDelegCert` | `--certificate <stake>.vote-deleg.cert` | 2 | inputs minus fee | **no** | yes | `VoteDelegationCertRegistration` | a DRep target and the stake address must be registered on chain (exit 1) |
| `23c_regComAuthCert` | `--certificate <hot>.cc-hot.cert` | 2 | inputs minus fee | **no** | yes | none: offline mode exits 0 with a notice | committee member state; the certificate is built here; exits 0 if the hot key already authorized |
| `23e_retComColdKeys` | `--certificate <cold>.cc-cold-ret.cert` | 2 | inputs minus fee | **no** | yes | none: offline mode exits 0 with a notice | committee member state; anchor url and hash |
| `24b_regVote` | one or more `.vote` files | 2 | inputs minus fee | yes | yes | `Transaction` | vote files read and shown; unrestricted-mode prompt for hardware |
| `25b_regAction` | one or more `.action` files; for treasury withdrawal and parameter-change actions also the guardrails proposal script, a collateral UTxO (a pure-lovelace UTxO of 5 to 10 ADA, removed from the inputs) and execution units | 1 (2 with guardrails) | inputs minus fee minus sum of action deposits (minus the collateral UTxO for guardrail actions) | yes | yes | `Transaction` | refuses a hardware payer; guardrail script file must exist |

All seventeen scripts accept extra metadata files and `msg:`/`enc:`/`pass:` messages (the acceptance table of `Pparam`); the attachment column lists only the transaction-specific parts. Scripts that touch the same artefacts but do **not** follow this pipeline: `01_workOffline execute` (submits a queued transaction, SPO-Ptransfer-EXT-001), `05d_poolWitness` (witness collection only), `09a_catalystVote` and `24a`/`25a` (build metadata, vote and action files that the pipeline scripts consume).

(src for the table: 01_sendLovelaces.sh:L436-L554, 01_claimRewards.sh:L604-L663, 03b_regStakingAddrCert.sh:L552-L590, 05c_regStakepoolCert.sh:L658-L703, 06_regDelegationCert.sh:L547-L585, 07b_deregStakepoolCert.sh:L402-L437, 08b_deregStakingAddrCert.sh:L536-L575, 11a_mintAsset.sh:L398-L436, 11b_burnAsset.sh:L395-L433, 21b_regDRepCert.sh:L568-L610, 21d_retDRepCert.sh:L446-L488, 22b_regVoteDelegCert.sh:L544-L581, 23c_regComAuthCert.sh:L491-L528, 23e_retComColdKeys.sh:L552-L589, 24b_regVote.sh:L547-L586, 25b_regAction.sh:L680-L831)

**Table B: signing.** Witness slots in the order the script signs.

| Script | Hardware path (all needed keys on hardware) | Key-file path | Refused combinations |
| --- | --- | --- | --- |
| `01_sendLovelaces`, `01_sendAssets` | `<pay>.hwsfile` | `<pay>.skey` | none |
| `25b_regAction` | not supported (payer hardware refused) | `<pay>.skey` | hardware payer |
| `01_claimRewards`, `03b`, `08b` | `<pay>.hwsfile` plus `<stake>.hwsfile`, same wallet name | `<pay>.skey` plus `<stake>.skey` | any mix |
| `06`, `22b` | `<pay>.hwsfile` plus `<delegName>.staking.hwsfile`, same wallet name | `<pay>.skey` plus `<delegName>.staking.skey` | any mix |
| `07b` | `<pay>.hwsfile` plus `<pool>.node.hwsfile` | `<pay>.skey` plus `<pool>.node.skey` | any mix |
| `23c`, `23e` | `<pay>.hwsfile` plus `<cold>.cc-cold.hwsfile` | `<pay>.skey` plus `<cold>.cc-cold.skey` | any mix |
| `11a`, `11b` | each of payment and policy independently, with a prompt per hardware witness | each independently | none (witnesses assembled separately) |
| `21b`, `21d` | `<pay>.hwsfile` plus `<drep>.drep.hwsfile`, and both mixed forms (hardware payer with key-file DRep uses unrestricted mode; key-file payer with hardware DRep) | `<pay>.skey` plus `<drep>.drep.skey` | none (an unmatched state reports an internal error, exit 1) |
| `24b` | payer and voter hardware, or voter hardware with key-file payer | payer and voter key files | hardware payer with key-file voter |
| `05c` | node cold key, payer and each owner independently into the collection | same | see SPO-Ptx-INV-011 |

(src for the table: 01_claimRewards.sh:L671-L722, 03b_regStakingAddrCert.sh:L601-L655, 06_regDelegationCert.sh:L595-L647, 07b_deregStakepoolCert.sh:L442-L494, 08b_deregStakingAddrCert.sh:L586-L638, 11a_mintAsset.sh:L442-L522, 21b_regDRepCert.sh:L619-L770, 21d_retDRepCert.sh:L496-L647, 22b_regVoteDelegCert.sh:L591-L644, 23c_regComAuthCert.sh:L538-L596, 23e_retComColdKeys.sh:L599-L657, 24b_regVote.sh:L592-L712, 25b_regAction.sh:L837-L877)

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Too few positional arguments | 1 | SPO-Ptx-IF-002 |
| Payment address file or signing file missing | 1 (2 for stake, policy or dereg files in `01_claimRewards`, `08b`, `11a`, `11b`, and for the payer's signing file in `01_claimRewards`) | SPO-Ptx-IN-002 |
| Node not synced (online) | 1 | SPO-Ptx-MODE-002 |
| Address missing from the transfer file (offline) | 1 | SPO-Ptx-MODE-004 |
| Transfer file missing, malformed or without protocol parameters | 1 | SPO-Ptransfer-IN-001 |
| UTxO query fails (online or light) | **0** (status of the `echo`) | SPO-Ptx-MODE-002, SPO-Ptx-MODE-003 |
| No UTxOs on the paying address | 1 | SPO-Ptx-PRE-001 |
| Not enough funds for the minimum output | 1 in `01_sendLovelaces`, `01_sendAssets`; **0** elsewhere | SPO-Ptx-PRE-002 |
| `build-raw` fails | `cardano-cli`'s code; the final build in `01_claimRewards` is unchecked | SPO-Ptx-EXT-001, SPO-Ptx-EXT-004 |
| Fee calculation fails | 1 | SPO-Ptx-EXT-002 |
| Hardware wallet rejected, disconnected or errored | 1 | SPO-Ptx-PRE-005 |
| Signing key unreadable | 1 | SPO-Ptx-EXT-006 |
| Unsupported hardware and key-file mix | 1 | SPO-Ptx-PRE-006 |
| Transaction larger than `maxTxSize` | 1 | SPO-Ptx-PRE-007 |
| Confirmation declined | 0 (`05c` first prompt: 1) | SPO-Ptx-PR-002 |
| Online submit fails | `cardano-cli`'s code (0 in `06`, `08b`, `22b`, `23c`, `23e`; 1 in `05c`) | SPO-Ptx-MODE-008 |
| Light submit fails | 0 (1 in `05c`) | SPO-Ptx-MODE-009 |
| Offline read-back mismatch | 0 | SPO-Ptx-MODE-010 |

## Security

- **SPO-Ptx-SEC-002** The scripts print the signed transaction and message passphrase but never a signing key. The signed transaction and the transaction body are written to world-readable temporary files that are not deleted. They are not secret but are private financial data. (src: 01_sendLovelaces.sh:L575, 01_sendLovelaces.sh:L644-L646, 01_sendLovelaces.sh:L556-L558)
- **SPO-Ptx-SEC-003** `ENV_SKIP_PROMPT=YES` removes the last human check before an irreversible submission, in ten of the seventeen scripts. A port makes skipping an explicit, audited policy and never the default of a non-interactive caller. (src: 01_sendLovelaces.sh:L656-L658, 00_common.sh:L22)

## Domain mapping

Use cases: `BuildAndSignTransaction` (stages 1 to 10) and `SubmitOrQueueTransaction` (stages 11 and 12), parameterised by a *TxIntent* (attachments, witness requirements, deposit/refund effects, post-submit effects) supplied by the calling use case (SendLovelaces, SendAssets, ClaimRewards, RegisterStakeKey, RegisterPool, ...). Aggregate: `TxDraft` (inputs, outputs, fee, TTL, metadata, attachments) in the transaction-construction kernel; `SignedTx` after signing.

| Port | Operation | Purpose |
| --- | --- | --- |
| `ChainQuery` | `tip()`, `protocolParameters()`, `utxos(address)` | Stages 2, 3, 5; the offline adapter serves them from `Ptransfer` |
| `Ledger` | `buildRaw(txSpec)` | Dummy and final body (SPO-Ptx-EXT-001, SPO-Ptx-EXT-004) |
| `Ledger` | `minFee(body, witnessCount)` | SPO-Ptx-EXT-002 |
| `Ledger` | `minOutputValue(output)` | SPO-Ptx-EXT-003 |
| `Ledger` | `canonicalizeForHardware(body)` *(new)* | `cardano-hw-cli transaction transform` (SPO-Ptx-EXT-005) |
| `Ledger` | `assemble(body, witnesses)`, `txId(tx)` | Hardware path, id display |
| `Signer` | `witness(body, keyRef)`, `signTx(body, keyRefs)` | Hardware witness or in-memory signing |
| `Vault` | `unseal(ref, passphrase?)` | In-memory key for signing (SPO-Ptx-EXT-006) |
| `Submitter` | `submit(signedTx) -> txId` | Online node or light Koios submission |
| `Transport` | `enqueueTx(signedTx)` | Offline queueing with read-back |
| `Directory` | `tokenMetadata(subject)` | Registry display |
| `UI` | `confirm(prompt, default)`, `show(view)` | Confirmation and summary |
| `Clock` | `now()` | Offline slot calculation |
| `Store` | `get/put(PoolDescriptor)`, `put(AssetRecord)` | Post-submit effects of `05c`, `07b`, `11a`, `11b` |

## Port notes

* Treat the pipeline as one use case with a *TxIntent* instead of seventeen copies; the variation tables are the intent catalogue. Keep the per-script prechecks (stake registered, rewards zero, pool registered) in the intent, not in the pipeline.
* Build the placeholder body with a fee of identical CBOR size, or compute fee from body length; do not hard-code 200000.
* Compute the witness count from the signer set of the intent rather than from constants, and keep the constants as the parity oracle.
* Exit non-zero for every refusal and failed submission (SPO-Ptx-PRE-002, SPO-Ptx-MODE-008, SPO-Ptx-MODE-009, SPO-Ptransfer-OUT-012). Apply the size check everywhere (SPO-Ptx-PRE-007).
* In server mode, move the signing stage behind the `Signer` port so a remote signer or hardware wallet returns witnesses and the vault never exposes keys; `ENV_SKIP_PROMPT` becomes an explicit approval policy.
* The coin selection is "spend everything"; a port may add selection, but then it differs from upstream in body content and fee.
* Resolve the second output of the send scripts as a function of the keyword amount, not by file layout (see the `01_sendLovelaces` spec).

## Open questions

* `calc_minOutUTXO` for protocol major version below 7 follows a different, older rule in `00_common.sh`; the `Cutxo` spec settles it. All current networks are above that, so the pipeline spec does not cover the old rule.
* The `cardano-hw-cli transaction transform` output format (canonical ordering rules) is whatever the tool implements; a test with a recorded hardware witness is the only settling evidence.
* Whether `25b` collateral selection (first pure-lovelace UTxO of 5 to 10 ADA) is stable across node versions depends on the order of the query output; it is specified in the `25b` spec.
