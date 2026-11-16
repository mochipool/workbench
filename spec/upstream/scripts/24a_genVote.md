+++
id = "24a"
kind = "script"
title = "Generate a vote file for a governance action"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["governance", "chain-access"]
use_cases = ["CreateVoteFile"]
depends_on = ["Cconf", "Cchain", "Clight", "Cconv", "Cui", "Pparam", "Pfiles"]

upstream_path = "cardano/mainnet/24a_genVote.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "9e0b690507477c0abc0bb512ffe5ec97a0a2419ca4f02d5848f54390a4c9f700"
upstream_lines = 1191
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
  "trimString",
  "versionCheck",
]
cli_commands = [
  "governance vote create",
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

# 24a_genVote: Generate a vote file for a governance action

Creates a signed-later vote for one or all open governance actions on behalf of one voter: a DRep, a constitutional committee hot key, or a stake pool (its cold key). For each action the script shows the proposal and the live tally (the same derivation as [24c](./24c_queryVote.md), display only here), checks that this kind of voter may vote on this kind of action, asks for the decision, and writes a `.vote` file. The vote file is not a signed transaction: [24b](./24b_regVote.md) wraps one or more vote files in a transaction, signs it with the voter key and submits it.

Online and light only: offline mode is refused because the action state is read from the chain.

## Interface

- **SPO-24a-IF-001** Takes two positional arguments, the voter name and the action id or `all`, and optional words after them. With fewer than two arguments it prints usage to stderr and exits 1. (src: L20-L43, L57-L60)
- **SPO-24a-IF-002** The voter argument is the stem of a verification key file: `<name>.drep`, `<name>.cc-hot` or `<name>.node`, with or without `.vkey`, or the bare `<name>`. A trailing `.` is dropped. The name used for the output file strips, in this order and each at most once, a trailing `.drep`, `.cc-hot`, `.node` and `.vkey`, keeping the directory part. An argument given as `x.drep.vkey` therefore keeps `.drep` in the output name (`x.drep_<ts>.drep.vote`), while `x.drep` gives `x_<ts>.drep.vote`. (src: L57-L59)
- **SPO-24a-IF-003** The action id is one of: `<64 hex>#<digits>` (case-insensitive, the index normalised to a plain number), a CIP-129 bech32 id starting `gov_action1` (converted with SPO-Cconv-OUT-018; a decoding failure exits 1), or `all` (every open action in turn). Anything else exits 1. (src: L60, L97-L110)
- **SPO-24a-IF-004** Words after the second are optional anchors: `url:<anchor-url>` and `hash:<hex>` (case-insensitive key), with the rules of SPO-Pparam-IF-025 and SPO-Pparam-IF-026: the URL is trimmed, must start with `https://` or `ipfs://` and be at most 128 characters; the hash is trimmed, lower-cased and must be exactly 64 hex digits; otherwise exit 1. Any other word is ignored without an error. (src: L63-L89)

## Inputs

- **SPO-24a-IN-001** Reads the voter's verification key: `<voter>.drep.vkey`, `<voter>.cc-hot.vkey` or `<voter>.node.vkey` (the pool's cold key). It never reads a signing key. See SPO-Pfiles-OUT-010, SPO-Pfiles-OUT-024, SPO-Pfiles-OUT-026. (src: L114-L162)
- **SPO-24a-IN-002** Needs the `cardano-signer` binary, resolved and version-checked as in SPO-24c-IN-002, before any anchor or action is processed. (src: L173-L187)
- **SPO-24a-IN-003** Reads the era; for `babbage`, `alonzo`, `mary`, `allegra` and `shelley` it prints that the chain is not yet in Conway and exits 0. (src: L49-L53)

## Behaviour

1. **Refuse offline.**
   - **SPO-24a-PRE-001** Offline mode exits 1 with a note that signing and submitting can be done offline later. (src: L46)
2. **Identify the voter from its key file.**
   - **SPO-24a-IN-004** The voter's verification key file is chosen by the first match of: `<argument without .vkey>.vkey` exists, in which case its name must end `.drep.vkey` (voter type `DRep`), `.cc-hot.vkey` (`Committee-Hot`) or `.node.vkey` (`Pool`), anything else exits 1; else `<name>.drep.vkey`; else `<name>.cc-hot.vkey`; else `<name>.node.vkey`; else exit 1 because none exists. A name for which several files exist resolves to the first in this order, silently. (src: L59, L114-L162)
   - **SPO-24a-INV-001** The voter hash is blake2b-224 of the 32 key bytes of the verification key (`cborHex` after the 2-byte CBOR header). A key that is unreadable or yields something other than 56 hex digits exits 1. For a `Pool` voter this is the pool id. The hash is used only to look up the voter's earlier vote on each action. (src: L168-L170)
3. **Resolve the anchor (optional).**
   - **SPO-24a-EXT-001** When an anchor URL is given, the document is downloaded: an `ipfs://<cid>` URL is read from `https://ipfs.io/ipfs/<cid>`, `curl` with a 10-second timeout and a 10 MB limit, up to 5 attempts with a pause of 1 second. A transport failure, HTTP 404, or any status other than 200 exits 1; so does a body that is not valid JSON. (src: L190-L256)
   - **SPO-24a-INV-002** The anchor data hash is the blake2b-256 hash of the raw downloaded bytes. A `hash:` word given together with the URL is discarded with a notice and replaced by the computed hash. Because offline mode is refused, a `hash:` word never changes the result. (src: L221-L226)
   - **SPO-24a-EXT-002** The document is checked with `cardano-signer verify --cip100 --data-file <file> --json-extended`; the structure result, a notice, and each author signature are shown. A failed check is shown and does not stop the script. (src: L228-L238)
   - **SPO-24a-PRE-002** A `hash:` word without a `url:` word exits 1 (L267). The reverse branch, a `url:` word with no hash available (L266), cannot be reached: in online and light mode a given URL either yields a hash or exits 1 in the download step (SPO-24a-EXT-001), and offline mode is refused at the start (SPO-24a-PRE-001), so no test is needed for it. Otherwise the vote carries `--anchor-url <url> --anchor-data-hash <hash>`; with neither word it carries no anchor. (src: L263-L268)
4. **Read the open actions and the tally inputs.**
   - **SPO-24a-MODE-001** *Online.* Requires a synced node (exit 1 otherwise), runs `cardano-cli <era> query gov-state` (failure exits 1), and keeps proposals with `expiresAfter >= currentEpoch`. When a specific action id was given and no proposal matches, it prints that the action is not on chain or has expired and exits 1. For `all`, every unexpired proposal is processed. The voter is **not** used as a filter. (src: L274-L296)
   - **SPO-24a-MODE-002** *Online tally inputs.* The same queries as SPO-24c-EXT-001 to SPO-24c-EXT-006 (protocol parameters, active DRep stake, always-no-confidence power, pool stake with default DRep, committee state, committee threshold), with the same failure behaviour: only `gov-state` (L278) and `spo-stake-distribution` (L315) failures exit 1; failures of `drep-state` (L302, status of the trailing `jq`), `committee-state` (L322, piped into `jq`), `drep-stake-distribution` (L309) and `protocol-parameters` (L355) are not detected and degrade the tally (DRep 0%, committee 0%, thresholds 0), see SPO-24c-EXT-001, SPO-24c-EXT-002 and SPO-24c-EXT-005. (src: L299-L355)
   - **SPO-24a-MODE-003** *Light.* The proposals come from Koios through `queryLight_actionState` with the action id and an empty voter id (SPO-Clight-EXT-009, SPO-Clight-OUT-021), the committee state from Koios (SPO-Clight-EXT-008), the protocol parameters from the Light-Mode document, and the committee threshold as in SPO-24c-EXT-006. A failed Koios query ends the script after printing the error. An action id that is not found yields no entries and exit 0, with no "not on chain" refusal. (src: L359-L404)
   - **SPO-24a-INV-003** For each proposal the script shows what SPO-24c-OUT-006 lists and derives the tally of SPO-24c-OUT-001 to SPO-24c-OUT-005 (online) or takes the Koios percentages of SPO-24c-MODE-005 (light), with the thresholds of SPO-24c-OUT-004. This display gates nothing: no tally value decides whether a vote is offered. The one difference to 24c is the anchor download timeout of 10 seconds and the display of the voter's earlier answer (SPO-24a-OUT-002). The deposit-return and treasury-withdrawal accounts are converted as in SPO-24c-OUT-008, and a failed conversion or an unknown network exits 1 for the whole run. (src: L408-L1076)
   - **SPO-24a-EXT-003** For each proposal with an anchor, the on-chain anchor is downloaded and checked as in SPO-24c-EXT-007, display only; the verified document's `body.title` becomes the action title, only when the content hash matches and the CIP-100 check succeeds. (src: L576-L660)
5. **Check that this voter type may vote on this action type.**
   - **SPO-24a-PRE-003** After the panel of an action and before the prompt, the script exits 1 (ending the whole run, also in `all` mode, without visiting further actions) when the pair is: voter `Committee-Hot` with action `NoConfidence` or `UpdateCommittee`; voter `Pool` with action `NewConstitution` or `TreasuryWithdrawals`. (src: L1092-L1097)
   - **SPO-24a-PRE-004** Voter `DRep` with action `ParameterChange` or `HardForkInitiation` exits 1 while the protocol major version is below 10 (Conway bootstrap phase). (src: L1103-L1107)
   - **SPO-24a-INV-004** Voter `Pool` on a `ParameterChange` is meant to be refused unless the change touches a security-group parameter, but the variable that carries this decision is never assigned in the script, so the refusal never fires: a pool can create a vote for any parameter change. **Upstream quirk:** the intended rule is shown in the panel (SPO-24c-OUT-005, security group). (src: L1099-L1101, L790-L795)
   - **SPO-24a-INV-005** Allowed pairs therefore are: `DRep` on all seven action types (two of them only from major version 10); `Committee-Hot` on `InfoAction`, `HardForkInitiation`, `ParameterChange`, `NewConstitution`, `TreasuryWithdrawals`; `Pool` on `InfoAction`, `HardForkInitiation`, `NoConfidence`, `UpdateCommittee`, `ParameterChange`. (src: L1092-L1109)
6. **Ask for the decision** (see *Prompts*).
7. **Write the vote file.**
   - **SPO-24a-EXT-004** Runs `cardano-cli <era> governance vote create <--yes|--no|--abstain> --governance-action-tx-id <txid> --governance-action-index <ix> <key option> <vkey file> [--anchor-url … --anchor-data-hash …] --out-file /dev/stdout`, the key option being `--drep-verification-key-file`, `--cc-hot-verification-key-file` or `--cold-verification-key-file` for `DRep`, `Committee-Hot` and `Pool`. The action id used is the one of the proposal entry, not the one typed. A failure exits 1. (src: L1153-L1171)
   - **SPO-24a-OUT-001** The vote JSON has its `description` field set to the action title, with every character outside a fixed set deleted (letters, digits, white space and `-_/!§$%&()?<>@|.,:;=*'` survive; notably the double quote does not, so the title cannot break the JSON). With no verified title the description is empty; a verified document without a title gives `-`. The result is written to `<voterName>_<yymmddHHMMSS>.<drep|cc-hot|pool>.vote` in the current directory with local time, and shown. (src: L1152-L1180)
   - **SPO-24a-INV-006** The file name carries no action id: two votes created by the same voter within the same second overwrite each other. **Upstream quirk:** only reachable by scripted input, because each vote waits for a prompt. (src: L1152-L1176)
   - **SPO-24a-OUT-003** A closing hint prints the 24b command for the new file. Display only. (src: L1183-L1185)

## Work modes

- **SPO-24a-MODE-004** Online and light differ as in SPO-24a-MODE-001 to SPO-24a-MODE-003. Offline exits 1 (SPO-24a-PRE-001). Signing and submitting the vote file (24b) works in all three modes. (src: L46, L273-L406)

## Prompts

- **SPO-24a-PR-001** For each action asks "Yes/No/Abstain/Skip/CANCEL?" on the terminal, reading `/dev/tty` even when stdin is redirected. The first letter decides, case-insensitive: `y` is `--yes`, `n` is `--no`, `a` is `--abstain`, `s` skips this action (no file), `c` ends the script with exit 0. An empty reply is Cancel (default). Any other reply repeats the question. Files already written for earlier actions stay. (src: L1111-L1143)
- **SPO-24a-OUT-002** When the voter's key already voted on the action, the earlier answer is shown (YES, NO or ABSTAIN, tested by substring `Yes`, `No`, `Abstain` in that order) before the prompt; the lookup keys are `keyHash-<h>` and `scriptHash-<h>` in the DRep and committee votes and the bare hash in the pool votes. Display only. A new vote is still offered. (src: L1080-L1089)

| Prompt | Default | Effect |
| --- | --- | --- |
| Decision per action (SPO-24a-PR-001) | Cancel (exit 0) | yes/no/abstain write a vote file; skip writes nothing |

## Outputs

**Upstream file contract:**

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<voterName>_<yymmddHHMMSS>.drep.vote`, `.cc-hot.vote`, `.pool.vote` | cardano-cli vote envelope with `description` set (SPO-24a-OUT-001); see SPO-Pfiles-OUT-029 | process default (not locked) | created per decision |
| `<tempDir>/anchorURLContent.tmp`, `<tempDir>/actionAnchorUrlContent.tmp` | downloaded anchor, deleted after the check | default | temporary |

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Fewer than two arguments | 1 | SPO-24a-IF-001 |
| Bad action id, bad `url:`, bad `hash:` | 1 | SPO-24a-IF-003, SPO-24a-IF-004 |
| Offline mode | 1 | SPO-24a-PRE-001 |
| Chain pre-Conway | 0 | SPO-24a-IN-003 |
| No voter key file or unusable key | 1 | SPO-24a-IN-004, SPO-24a-INV-001 |
| Anchor download or JSON failure | 1 | SPO-24a-EXT-001 |
| `hash:` without `url:` | 1 | SPO-24a-PRE-002 |
| Node not synced (online) | 1 | SPO-24a-MODE-001 |
| Specified action absent or expired (online) | 1 | SPO-24a-MODE-001 |
| Koios query fails (light) | 0 (status of the preceding `echo`) | SPO-24a-MODE-003 |
| Query of drep-state, committee-state, drep-stake-distribution or protocol-parameters fails (online) | none: not detected, the tally degrades | SPO-24a-MODE-002 |
| Voter type not allowed on action type | 1 | SPO-24a-PRE-003, SPO-24a-PRE-004 |
| Deposit-return or withdrawal address not encodable | 1 | SPO-24a-INV-003 |
| `vote create` fails | 1 | SPO-24a-EXT-004 |
| Cancel | 0 | SPO-24a-PR-001 |

## Real-tool notes

* Observed 2026-11-16 (cardano-cli 11.2.3.0): the vote file is type `Governance voting procedures`, a one-voter, one-action map `{[type, hash] => {[tx id, index] => [vote, anchor | null]}}` with voter type 0 (committee hot key), 1 (hot script), 2 (DRep key), 3 (DRep script), 4 (pool) and vote 0 (no), 1 (yes), 2 (abstain); cardano-cli writes it with four-space indent and an empty description, and the script's `jq` rewrite (SPO-24a-OUT-001) turns it into two-space indent with the description in place. `TestGovVoteFilesMatchCardanoCLI` compares both. A transaction merges the vote files into one voting-procedures map (body key 19) ordered committee hot, DRep, pool, then by action id (`TestGovTransactionsMatchCardanoCLI`).
* Port decision (SPO-24a-INV-004): the role rule for a pool on a parameter change is applied as the ledger applies it (a vote of a pool on a change that touches no security-group parameter is disallowed), from the governance state's own statement of the security group; a state that does not say is refused.

## Security

- **SPO-24a-SEC-001** No secret is read or written: only verification keys are used and the vote file contains no key material. (src: L169, L1170)
- **SPO-24a-SEC-002** The action title comes from a remote document and is injected into a `jq` program; the character filter of SPO-24a-OUT-001 is what stops that injection and must be kept (or replaced by passing the title as a `jq` argument). (src: L1174)
- **SPO-24a-SEC-003** Anchor documents are fetched from arbitrary URLs and an IPFS gateway; they are parsed and hashed, never executed. (src: L193-L240)

## Domain mapping

Use case `CreateVoteFile(voter, actionSelector, anchor?)` on aggregate `Vote` (value object `VoterIdentity` = role plus key hash). It produces one `VoteFile` per decided action.

| Port | Operation | Purpose |
| --- | --- | --- |
| `Store` | `get(VerificationKey)` | voter key |
| `Store` | `put(VoteFile)` | result, default-mode file |
| `ChainQuery` | `govActionState`, `govActions()` *(new)*, `drepStakeDistribution` *(new)*, `spoStakeDistribution` *(new)*, `committeeState`, `protocolParameters`, `voteSummary` *(new)* | proposals and the display-only tally, as in 24c |
| `Directory` | `fetchUrl(url)` | anchor |
| `Ledger` | `verifyCip100(document)` *(new)* | anchor check |
| `Ledger` | `makeVote(decision, actionId, voterKey, anchor?)` *(new)* | `cardano-cli governance vote create` |
| `UI` | `choose(prompt, options, default)` *(new)* | decision |

## Port notes

* Enforce the voter-versus-action table in the domain (SPO-24a-INV-005) as a pure function before any prompt, including the missing security-group test for pools and the "no confidence" state for the committee, and do not stop the whole run for one forbidden action in `all` mode: skip it.
* Give a vote file the action id in its name or store votes as records; a timestamp-only name loses votes.
* A vote is a small, non-secret, signable intent; it can be sent to a remote signer or a co-signing party unchanged.
* Pass the title as data, not inside a program.
* Failed Koios queries should exit non-zero.
* The anchor hash must be computed over the raw bytes, which this script does correctly; keep that.

## Open questions

* The exact character set of the description filter: the bracket expression contains `[:space:]-_`, whose range semantics are shell- and locale-dependent. Settle by running the substitution on a string containing every ASCII character.
* Whether `cardano-cli governance vote create` accepts a committee hot or cold key file in a script-credential form; the script only handles key files.
