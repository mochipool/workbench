+++
id = "05a"
kind = "script"
title = "Generate the pool registration certificate and metadata"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["pool-operations"]
use_cases = ["GeneratePoolRegistrationCertificate"]
depends_on = ["Cui", "Cconf", "Cconv", "Coffline", "Pfiles"]

upstream_path = "cardano/mainnet/05a_genStakepoolCert.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "3523be77f58e787e763372833675c36b5459f76bf8212297f1bbcae17935437c"
upstream_lines = 466
uses_common = [
  "ask",
  "checkError",
  "convertToADA",
  "exists",
  "file_lock",
  "file_unlock",
  "majorError",
  "readOfflineFile",
  "showProcessAnimation",
  "stopProcessAnimation",
  "versionCheck",
]
cli_commands = [
  "query protocol-parameters",
  "stake-pool id",
  "stake-pool metadata-hash",
  "stake-pool registration-certificate",
]
hwcli_commands = []
signer_commands = [
  "sign",
]
http_endpoints = []
env_vars = []
+++

# 05a_genStakepoolCert: Generate the pool registration certificate and metadata

Turns the operator-edited pool descriptor `<pool>.pool.json` into the three artefacts that registration needs: the published metadata file (and optionally an extended-metadata file), the metadata hash, and the stake-pool registration certificate. It validates every descriptor field against the limits the ledger and the metadata services impose, derives the pool id from the cold verification key, and records all derived values back into `<pool>.pool.json`. It builds no transaction and talks to no chain service: [05c](./05c_regStakepoolCert.md) later consumes the certificate. The same certificate serves a first registration and a re-registration (pool update); the distinction is made by 05c, not here.

If the descriptor does not exist, the script writes a template for the operator to edit and stops.

Mode-independent except for the protocol-parameter source (see Work modes).

## Interface

- **SPO-05a-IF-001** Takes one required positional argument, the pool name. It is accepted with or without a `.json` and `.pool` suffix and with an optional directory part; a leading `./` is dropped (see SPO-Pfiles-IN-001). Without an argument, or with an empty one, prints usage to stdout and exits 1. (src: L20)
- **SPO-05a-IF-002** Takes an optional second positional argument, the *registration protection key*. It is read only when exactly two arguments are given; with three or more arguments it is ignored without a message. (src: L21)
- **SPO-05a-IF-003** When `<pool>.pool.json` does not exist, writes the template of the schema table below to it (default file mode, not locked), prints it, and exits 1 so the operator edits it and retries. Nothing else is created. (src: L24-L60)

## Inputs

**The pool descriptor `<pool>.pool.json`.** One JSON object. The operator edits the fields marked *operator*; the scripts write the fields marked *script*. The template of SPO-05a-IF-003 pre-fills the placeholder values shown.

| Field | Writer | Type and meaning | Template value | Validation in 05a |
| --- | --- | --- | --- | --- |
| `poolName` | operator | pool name; also the path stem of every pool file | the normalised argument | must equal the normalised argument (SPO-05a-PRE-002) |
| `poolOwner` | operator | array of `{ownerName, ownerWitness}`; legacy form: a string | one entry, `ownerWitness` `"local"` | non-empty; each owner's `<ownerName>.staking.vkey` exists (SPO-05a-PRE-013) |
| `poolOwner[].ownerName` | operator | name of an owner stake account | placeholder | file check only |
| `poolOwner[].ownerWitness` | operator or script | `"local"` or any other word (conventionally `"external"`); see SPO-05a-OUT-005 | `"local"` | none; added as `"local"` when absent |
| `poolRewards` | operator | name of the reward account (`<name>.staking.vkey`) | placeholder | non-empty; vkey exists (SPO-05a-PRE-003) |
| `poolPledge` | operator | lovelaces, decimal string | `"100000000000"` | non-empty only (SPO-05a-INV-002) |
| `poolCost` | operator | fixed cost per epoch, lovelaces, decimal string | `"10000000000"` | at least `minPoolCost` (SPO-05a-PRE-004, SPO-05a-PR-001) |
| `poolMargin` | operator | fraction as decimal string | `"0.10"` | 0.00 to 1.00 inclusive (SPO-05a-PRE-005) |
| `poolRelays` | operator | array of `{relayType, relayEntry, relayPort}` | one placeholder | each entry per SPO-05a-PRE-006 to SPO-05a-PRE-008 |
| `poolMetaName` | operator | metadata `name` | placeholder | at most 50 characters |
| `poolMetaDescription` | operator | metadata `description` | placeholder | at most 255 characters |
| `poolMetaTicker` | operator | metadata `ticker` | placeholder | 3 to 5 characters after sanitising (SPO-05a-PRE-010, SPO-05a-PR-002) |
| `poolMetaHomepage` | operator | metadata `homepage` | placeholder URL | `http(s)://` form, at most 128 characters |
| `poolMetaUrl` | operator | URL where `<pool>.metadata.json` will be published; goes into the certificate | placeholder `.../<pool>.metadata.json` | `http(s)://` form, at most 128 characters |
| `poolExtendedMetaUrl` | operator | URL of the extended-metadata file; empty disables it | `""` | see SPO-05a-INV-003 |
| `"---"` | template | marker line "DO NOT EDIT OR DELETE BELOW THIS LINE" | present | none |
| `poolID`, `poolIDbech` | script | hex and bech32 pool id | absent | written by SPO-05a-OUT-001 |
| `poolMetaHash` | script | hash of `<pool>.metadata.json` | absent | written by SPO-05a-OUT-008 |
| `regCertCreated`, `regCertFile` | script | creation date (RFC-5322) and path of `<pool>.pool.cert` | absent | written by SPO-05a-OUT-011 |
| `regProtectionKey` | script | the second argument of SPO-05a-IF-002 | absent | written by SPO-05a-OUT-012 |
| `regEpoch`, `regSubmitted`, `regWitness` | 05c | registration record and open witness collection | absent | not touched by 05a |
| `deregCertCreated`, `deregCertFile`, `deregEpoch`, `deregSubmitted` | 07a, 07b | retirement record | absent | not touched by 05a |

- **SPO-05a-IN-001** The required fields `poolName`, `poolOwner`, `poolRewards`, `poolPledge`, `poolCost`, `poolMargin`, `poolRelays`, `poolMetaName`, `poolMetaTicker`, `poolMetaHomepage`, `poolMetaUrl` and `poolMetaDescription` must each exist and be non-empty. A missing, `null` or empty field, or an unparsable file, exits 1 naming the field. (src: L63-L79, L123, L163, L166, L184, L187, L190)
- **SPO-05a-IN-002** `poolOwner` is either an array of objects or, in the legacy format, a single string. A string is converted by SPO-05a-OUT-004. Any other shape is processed as an array and fails at the first missing `ownerName` (SPO-05a-PRE-013). (src: L344-L353)
- **SPO-05a-IN-003** `poolExtendedMetaUrl` is optional. An absent or non-URL value means "no extended metadata". (src: L222-L225)
- **SPO-05a-IN-004** Optional files read when present: `<pool>.additional-metadata.json` (the editable source of the extended metadata) and the pair `<pool>.itn.skey` / `<pool>.itn.vkey` (Incentivized Testnet identity). (src: L228-L230, L282-L303)
- **SPO-05a-IN-005** Required key files: `<pool>.node.vkey`, `<pool>.vrf.vkey`, `<poolRewards>.staking.vkey` and, per owner, `<ownerName>.staking.vkey`. Only verification keys are read; signing keys are not needed. (src: L85-L87, L372)
- **SPO-05a-IN-006** The protocol parameters come from the work mode's source, with the transfer file read through `readOfflineFile` in offline mode (see SPO-Coffline-PRE-001). The fields used are `minPoolCost` and `protocolVersion.major` (default -1 when absent). (src: L90-L98, L406)

## Behaviour

1. **Resolve the descriptor and the pool name.**
   - **SPO-05a-PRE-001** A descriptor that cannot be parsed as JSON exits 1. (src: L64-L69)
   - **SPO-05a-PRE-002** Exits 1 when `poolName` differs from the normalised argument, with the hint that the pool may have been imported from another path. (src: L81-L82)
   - **SPO-05a-PRE-003** Exits 1 when `<pool>.node.vkey`, `<pool>.vrf.vkey` or `<poolRewards>.staking.vkey` is missing, naming the script that generates it (04a, 04b, 03a). (src: L85-L87)
2. **Check the pool cost.**
   - **SPO-05a-PRE-004** When `poolCost` is lower than the protocol parameter `minPoolCost`, asks whether to raise it to `minPoolCost` (SPO-05a-PR-001); a refusal exits 1 with the instruction to edit `poolCost`. The comparison is a bash numeric comparison, so a non-numeric `poolCost` is read as 0 and counts as too low. (src: L97-L113)
   - **SPO-05a-OUT-002** After the operator accepts, `poolCost` in the descriptor is rewritten to `minPoolCost` (as a string), and this value is used for the certificate. (src: L103-L106)
3. **Check the margin.**
   - **SPO-05a-PRE-005** Exits 1 unless `poolMargin` is a number in the closed interval 0.00 to 1.00, evaluated by `bc`; any value `bc` does not evaluate to 1 (letters, empty, out of range) is refused. The percentage shown is display only. (src: L115-L119)
4. **Build the relay list.** Every entry of `poolRelays` is checked and converted in array order. An empty array is accepted and produces a certificate without relays.
   - **SPO-05a-PRE-006** Exits 1 when `relayEntry` is absent, empty or longer than 128 characters, or when `relayType` is absent or empty. (src: L128-L135)
   - **SPO-05a-EXT-001** The relay type is upper-cased and mapped to the certificate option as follows; the option and the entry are passed to cardano-cli in array order (src: L138-L154):

     | `relayType` (case-insensitive) | cardano-cli option | Port required |
     | --- | --- | --- |
     | `IP`, `IP4`, `IPV4` | `--pool-relay-ipv4 <entry> --pool-relay-port <port>` | yes |
     | `IP6`, `IPV6` | `--pool-relay-ipv6 <entry> --pool-relay-port <port>` | yes |
     | `DNS` | `--single-host-pool-relay <entry> --pool-relay-port <port>` (an A or AAAA record) | yes |
     | `MULTISRV`, `SRV` | `--multi-host-pool-relay <entry>` (a DNS SRV record) | no |

   - **SPO-05a-PRE-007** Exits 1 when the relay type needs a port and `relayPort` is absent or empty. The port value itself is not validated; the entry is not checked to be a well-formed address or name. (src: L141, L145, L149)
   - **SPO-05a-PRE-008** Exits 1 for any other relay type, listing the supported ones. (src: L156-L157)
5. **Check the metadata fields.**
   - **SPO-05a-PRE-009** Exits 1 when `poolMetaName` is longer than 50 characters, `poolMetaDescription` longer than 255, `poolMetaHomepage` or `poolMetaUrl` longer than 128 characters or not matching `https?://` anywhere in the value. The match is unanchored, so a value with `http://` in the middle passes. (src: L163-L164, L184-L191)
   - **SPO-05a-PRE-010** The ticker is sanitised: every character that is not alphanumeric (locale-dependent classification) becomes `_`; the result must be 3 to 5 characters long, otherwise exit 1. It is not upper-cased. (src: L166-L169)
   - **SPO-05a-PR-002** When sanitising changed the ticker, asks whether the corrected ticker is acceptable (default No). Yes rewrites `poolMetaTicker` in the descriptor to the corrected value; No exits 1 with the instruction to edit the ticker. (src: L170-L182)
6. **Derive and record the pool id.**
   - **SPO-05a-EXT-002** The pool id is derived from `<pool>.node.vkey` with `cardano-cli <era> stake-pool id --cold-verification-key-file <vkey> --output-hex`, and again with `--output-bech32`. A cardano-cli failure ends the script with its exit code. (src: L195-L196, L207-L208)
   - **SPO-05a-OUT-001** Writes the hex id to `<pool>.pool.id` and the bech32 id to `<pool>.pool.id-bech` (each followed by a newline, locked `0400`) and records them as `poolID` and `poolIDbech` in the descriptor. This happens before the metadata checks of steps 7 and 8, so these three writes persist even when a later check refuses. (src: L197-L216)
7. **Extended metadata (optional).**
   - **SPO-05a-INV-003** Extended metadata is produced only when `poolExtendedMetaUrl` is at most 128 characters (otherwise exit 1) **and** matches `https?://` **and** is shorter than 65 characters. A URL of 65 to 128 characters is silently treated as "no extended metadata". (src: L222-L226)
   - **SPO-05a-PRE-011** An existing `<pool>.additional-metadata.json` that is not valid JSON exits 1. When it is valid, the metadata gets an `extended` entry with the extended URL. (src: L228-L231)
   - **SPO-05a-OUT-003** When `<pool>.additional-metadata.json` does not exist, writes a dummy (default mode) holding the `info` structure (icon and logo URLs, location, social handles, company, about, rss), `telegram-admin-handle`, and `my-pool-ids` and `when-satured-then-recommend` pre-filled with the hex pool id, and prints that the file must be edited. The script does **not** stop: it continues without the `extended` entry, so the first run produces metadata without extended metadata and the operator has to run 05a again. (src: L232-L279)
   - **SPO-05a-EXT-003** When both `<pool>.itn.skey` and `<pool>.itn.vkey` exist, the ITN witness is produced with `cardano-signer sign --jcli --secret-key <pool>.itn.skey --data-file <pool>.pool.id`, taking the first whitespace-separated word of the output, after the binary is located (the configured path, else `<scriptDir>/cardano-signer`; exit 1 otherwise) and its version is at least `minCardanoSignerVersion` (exit 1 otherwise). The extended metadata then contains `itn: {owner: <content of itn.vkey>, witness: <signature>}`, and the `extended` entry is set even when no additional-metadata file existed. (src: L282-L307)
     > **Upstream quirk:** the error test after the signer call (L301) reads the status of `stopProcessAnimation`, not of the signer; a failed signature yields an empty witness without an error.
   - **SPO-05a-OUT-006** When the `extended` entry is set, writes `<pool>.extended-metadata.json` as the deep merge (`*`) of the ITN object and the additional metadata, the latter winning on conflicts, then sets mode `0444`. (src: L310-L315)
8. **Write the metadata file and hash it.**
   - **SPO-05a-OUT-007** Writes `<pool>.metadata.json` with the keys `name`, `description`, `ticker`, `homepage` and, when set, `extended`, in this order, then sets mode `0444`. Values are interpolated textually: quotes or backslashes in a field are not escaped and a `\` sequence is interpreted by `echo -e`. (src: L317-L325)
   - **SPO-05a-PRE-012** Exits 1 when `<pool>.metadata.json` is larger than 512 bytes, the ledger limit for pool metadata. The file stays on disk. (src: L327-L329)
   - **SPO-05a-EXT-004** The metadata hash is `cardano-cli <era> stake-pool metadata-hash --pool-metadata-file <pool>.metadata.json`; a failure (for example invalid JSON from unescaped values) ends the script with cardano-cli's code. (src: L333-L334)
   - **SPO-05a-OUT-008** Records the hash as `poolMetaHash`. The hash covers `<pool>.metadata.json` only, never the extended file. The script does not fetch `poolMetaUrl`; the comparison with the published file is done by 05c (SPO-05c-EXT-002). (src: L336-L340)
9. **Normalise and check the owners.**
   - **SPO-05a-OUT-004** A string `poolOwner` is rewritten as `[{"ownerName": <string>}]`, and the owner count is 1. (src: L344-L350)
   - **SPO-05a-OUT-005** An owner entry without `ownerWitness` gets `"ownerWitness": "local"`. The value tells 05c whether it signs that owner's witness itself (`"local"`, or empty) or leaves the slot for an external signer (any other word); see SPO-05c-INV-005. (src: L360-L370)
   - **SPO-05a-PRE-013** Exits 1 when an owner's `<ownerName>.staking.vkey` is missing. Duplicate owner names are not detected. (src: L372-L375)
10. **Create the certificate.**
    - **SPO-05a-EXT-005** The certificate is created with `cardano-cli <era> stake-pool registration-certificate --cold-verification-key-file <pool>.node.vkey --vrf-verification-key-file <pool>.vrf.vkey --pool-pledge <poolPledge> --pool-cost <poolCost> --pool-margin <poolMargin> --pool-reward-account-verification-key-file <poolRewards>.staking.vkey` followed by one `--pool-owner-stake-verification-key-file <owner>.staking.vkey` per owner in array order, the relay options of SPO-05a-EXT-001, `--metadata-url <poolMetaUrl> --metadata-hash <poolMetaHash> --out-file <pool>.pool.cert`. Pledge, cost and margin are passed verbatim from the descriptor. (src: L414, L419)
    - **SPO-05a-INV-001** With protocol major version 12 or higher the certificate additionally carries the BLS key: `--bls-signing-key-file <pool>.bls.skey`. Both `<pool>.bls.skey` and `<pool>.bls.vkey` must exist, else the script exits 1 with the instruction to run `04f_genBLSKeys.sh`. Below version 12 no BLS option is passed. (src: L405-L421)
    - **SPO-05a-INV-002** `poolPledge` is never validated: any non-empty string reaches cardano-cli. The same holds for the owner and reward accounts' relation to the pledge. (src: L77, L414, L419)
11. **Record the certificate.**
    - **SPO-05a-OUT-011** On success, records `regCertCreated` (current time, RFC-5322) and `regCertFile` (`<pool>.pool.cert`) in the descriptor, and locks the certificate `0400`. (src: L413, L418, L423-L431)
    - **SPO-05a-OUT-012** When the second argument was given, records it as `regProtectionKey`, so 05c and offline execution can use it later. (src: L433-L439)
    - **SPO-05a-OUT-013** Re-running the script overwrites the certificate, the metadata files and the derived descriptor fields, but never removes `regWitness`, `regEpoch` or `regSubmitted`. A witness collection opened before the re-run keeps the old transaction body (see SPO-05c-INV-003). (src: L413-L439)

## Work modes

- **SPO-05a-MODE-001** Only the protocol-parameter source differs: online runs `cardano-cli <era> query protocol-parameters`, light uses the Light-Mode parameters document, offline reads `.protocol.parameters` of the transfer file. A failure of the online query exits with its code. (src: L90-L95)

## Prompts

| Prompt | Default | Effect |
| --- | --- | --- |
| Raise `poolCost` to `minPoolCost` (SPO-05a-PR-001) | No | Yes rewrites the descriptor; No exits 1 |
| Accept the corrected ticker (SPO-05a-PR-002) | No | Yes rewrites the descriptor; No exits 1 |

- **SPO-05a-PR-001** The cost prompt of SPO-05a-PRE-004 defaults to No. (src: L102)

## Outputs

**Upstream file contract:**

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<pool>.pool.json` | descriptor, fields per the schema table | `0644` when first created from the template, then `0400` after each script update (`0600` between an unlock and the next lock) | created (template) or updated |
| `<pool>.pool.id` | hex pool id and newline | `0400` | created or replaced |
| `<pool>.pool.id-bech` | bech32 pool id and newline | `0400` | created or replaced |
| `<pool>.metadata.json` | pool metadata, at most 512 bytes | `0444` | created or replaced |
| `<pool>.extended-metadata.json` | merged ITN and additional metadata | `0444` | created or replaced when extended metadata applies |
| `<pool>.additional-metadata.json` | editable dummy, see SPO-05a-OUT-003 | default | created when absent and an extended URL is set |
| `<pool>.pool.cert` | `CertificateConway` text envelope | `0400` | created or replaced |

- **SPO-05a-OUT-009** The descriptor is rewritten as a whole by shell redirection after each field update; it is locked `0400` after the pool-id, hash, owner and certificate updates, but stays `0600` after a cost or ticker update that is followed by a refusal, and `0644` for a template-created file until the first lock. (src: L24-L54, L104-L106, L173-L175, L197-L200, L337-L340, L346-L349, L426-L428)
- **SPO-05a-OUT-010** The script prints the certificate, the whole descriptor (including `regProtectionKey` when set) and the metadata file(s) on stdout, plus a reminder to upload `<pool>.metadata.json` (and the extended file) to `poolMetaUrl` / `poolExtendedMetaUrl` before running 05b and 05c. Display only apart from SPO-05a-SEC-001. (src: L441-L463)

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| No argument | 1 | SPO-05a-IF-001 |
| Descriptor missing (template written) | 1 | SPO-05a-IF-003 |
| Required field missing, empty or unparsable | 1 | SPO-05a-IN-001, SPO-05a-PRE-001 |
| `poolName` mismatch | 1 | SPO-05a-PRE-002 |
| Key file missing | 1 | SPO-05a-PRE-003, SPO-05a-PRE-013 |
| Cost too low and not raised | 1 | SPO-05a-PRE-004 |
| Margin out of range | 1 | SPO-05a-PRE-005 |
| Relay entry or type invalid | 1 | SPO-05a-PRE-006 to SPO-05a-PRE-008 |
| Metadata field limit exceeded | 1 | SPO-05a-PRE-009, SPO-05a-PRE-010, SPO-05a-PRE-012 |
| Ticker correction declined | 1 | SPO-05a-PR-002 |
| `additional-metadata.json` invalid | 1 | SPO-05a-PRE-011 |
| `cardano-signer` missing, old or failing to start | 1 | SPO-05a-EXT-003 |
| BLS keys missing (protocol 12+) | 1 | SPO-05a-INV-001 |
| cardano-cli failure | cardano-cli's code | SPO-05a-EXT-002, SPO-05a-EXT-004, SPO-05a-EXT-005 |

## Security

- **SPO-05a-SEC-001** Prints the descriptor to stdout, which includes `regProtectionKey`, a private key for the ticker-protection service. A caller must not log the output. (src: L447-L449)
- **SPO-05a-SEC-002** The ITN signing key and the BLS signing key are read by the external tool from plaintext files named on its command line; there is no encrypted (`enc`) variant for either. (src: L299, L414)
- **SPO-05a-SEC-003** No pool or owner signing key is read. The pool cold signing key is never needed here. (src: L85-L87)

## Domain mapping

Use case `GeneratePoolRegistrationCertificate(pool, regProtectionKey?)` on aggregate `PoolRegistration` (descriptor, metadata, certificate, derived ids) of the `StakePool`.

| Port | Operation | Purpose |
| --- | --- | --- |
| `Store` | `get/put(PoolDescriptor)`, `exists`, `lock` | Descriptor read, template, derived fields |
| `Store` | `put(PoolMetadata)`, `put(ExtendedPoolMetadata)`, `put(PoolId)`, `put(PoolRegistrationCertificate)` | Artefacts of the file contract |
| `Store` | `get(StakeVerificationKey)`, `get(ColdVerificationKey)`, `get(VrfVerificationKey)` | Key reads |
| `ChainQuery` | `protocolParameters()` | `minPoolCost`, protocol major version |
| `Ledger` | `poolId(coldVkey, format)` *(new)* | `stake-pool id` hex and bech32 |
| `Ledger` | `metadataHash(metadataFile)` *(new)* | `stake-pool metadata-hash` |
| `Ledger` | `makeCertificate(poolRegistration, params)` | Registration certificate, with BLS from major 12 |
| `Signer` | `signMessage(payload, keyRef)` | ITN witness (`cardano-signer --jcli`) |
| `UI` | `confirm(prompt, default)` | Cost and ticker corrections |

## Port notes

* Model the descriptor as a typed `PoolDescriptor` value object with the limits of the table above as invariants, validated once. The file adapter keeps the upstream field names.
* Escape metadata values (SPO-05a-OUT-007) by serialising JSON rather than interpolating text. The hash is over the bytes written, so the port must hash the serialised form it publishes.
* The 65-character extended-URL threshold (SPO-05a-INV-003) turns a long URL into silently absent extended metadata; a port warns.
* Generation of the extended-metadata dummy should stop the run, as its message says (SPO-05a-OUT-003).
* The id, hash and owner writes before later refusals (SPO-05a-OUT-001) are harmless but a transactional port writes nothing on refusal.
* Registration protection keys belong in a secret store, not in a descriptor that is printed and published.

## Open questions

* The 65-character and 128-character URL thresholds: whether the ledger's limit on the pool-metadata URL (128 bytes) is the reason for 128, and what the 65 limit protects, is not stated in the source.
* Whether cardano-cli accepts a certificate with zero owners (`poolOwner: []`) is decided by cardano-cli; a test against the pinned release settles it.
* `poolMetaTicker` alphanumeric classification depends on the shell locale; a recorded test with a non-ASCII ticker settles the intended behaviour.
