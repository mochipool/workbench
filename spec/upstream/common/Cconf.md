+++
id = "Cconf"
kind = "common"
title = "Configuration, networks, work mode, tool checks and era"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["configuration"]
use_cases = ["LoadConfiguration"]
depends_on = ["Clight"]

upstream_path = "cardano/mainnet/00_common.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "9490fae84352a491bbded9bd4a14587521336364f9814a2df5aff6b86266bfba"
upstream_lines = 2966

[functions]
majorError = "2bd3b7d74b89dc0b3bbd2331f4df533da2c5856d35840ea0db19324699d593e5"
trimString = "81d09a67fa9fc6e2333c9dd23c0a63b164b89a10a1715959b7fd30c06cde9508"
versionCheck = "443de03d3b06c773ebb692ba89c40e5737fb75801f8000e9b128eef397dafeac"
exists = "8303075abf39923fe2b7dc64e8aa59fff60314c44fe26409737ace452e631a4d"
get_NodeEra = "f86c237637d598335d45562d36cb0aac68cdeda1f1b18af95cd80cc98f748abd"
+++

# Cconf: Configuration, networks, work mode, tool checks and era

`00_common.sh` is not a library of functions only. It is **sourced at the top of every script**, and its top-level code (the *prologue*, L1-L708) builds the run configuration before the script's own code starts: which network, which work mode, where the tools live, which tool versions are acceptable, which era to build transactions for. This spec covers the prologue and the five small helper functions it uses (`majorError`, `trimString`, `versionCheck`, `exists`, `get_NodeEra`). There is no top-level code after L708 other than function definitions (verified: every non-comment line after L720 is inside a function).

In the reimplementation the prologue becomes the `LoadConfiguration` use case, which produces three read-only values for every other context: a `NetworkProfile` (magic, address format, Byron-to-Shelley epochs, service endpoints), a `WorkMode` (online, light, offline) and `ToolchainRequirements` (pinned min/max versions). It also decides the *era* used for transaction building.

Because the prologue runs in the caller's shell, every fatal condition below ends the **calling script** with the stated exit code (see Execution model).

## Execution model

- **SPO-Cconf-INV-001** The prologue runs in the shell of the script that sources it, so every `exit` in it terminates that script. Nothing of the calling script has run yet except its own preamble. (src: L1-L708)
- **SPO-Cconf-INV-002** The prologue performs its steps in this order: (1) discard inherited `magicparam`, `network`, `addrformat`; (2) load settings files; (3) lowercase aliases; (4) testnet/mainnet consistency check; (5) network preset; (6) apply preset values where the user gave none; (7) URL trailing-slash normalisation; (8) required chain parameters check; (9) pin tool versions; (10) defaults and exports; (11) boolean settings; (12) cardano-cli presence and version; (13) work-mode setup (light-mode checks happen here); (14) cardano-node check (online only); (15) bech32 check; (16) curl/jq/bc/xxd checks; (17) temp dir; (18) era selection. The first failing step decides the exit. (src: L2, L163-L172, L178, L183-L337, L340-L371, L510-L513, L528-L533, L539-L605, L614-L622, L628-L632, L637-L640, L645, L661-L673)

> **Upstream quirk:** The light-mode setup (step 13) calls `jq`, `curl`, `date` and `bc` before the tool-presence checks of step 16, so a machine without `jq` or `bc` in light mode fails with a raw shell error instead of the friendly exit-2 message. (src: L552, L556, L585, L638-L639)

## Settings, defaults and sources

The settings below are plain shell variables set in `00_common.sh` itself and overridable by settings files (see SPO-Cconf-IN-003). Values are the defaults at the pinned tag.

| Setting | Default | Meaning | Used when |
| --- | --- | --- | --- |
| `workMode` | `online` | `online` (full: local node), `light` (online, no node, Koios and other APIs), `offline` (cold machine) | always |
| `cardanocli` | `./cardano-cli` | path to cardano-cli | always |
| `cardanosigner` | `./cardano-signer` | path to cardano-signer | signing scripts (not checked here) |
| `bech32_bin` | `./bech32` | path to bech32 tool | always (checked here) |
| `cardanonode` | `./cardano-node` | path to cardano-node | online mode only |
| `socket` | `db/node.socket` | node socket path | online mode |
| `genesisfile` | `$HOME/cardano/mainnet-shelley-genesis.json` | Shelley genesis | offline arithmetic, `get_timeUntilNextEpoch` |
| `genesisfile_byron` | `$HOME/cardano/mainnet-byron-genesis.json` | Byron genesis | offline arithmetic |
| `cardanohwcli` | `cardano-hw-cli` | path to cardano-hw-cli | hardware wallet scripts (not checked here) |
| `offlineFile` | `./offlineTransfer.json` | air-gap transfer file | offline/online transfer (empty value is reset to this default) |
| `catalyst_toolbox_bin` | `./catalyst-toolbox` | path to catalyst-toolbox | Catalyst scripts (not checked here) |
| `cardanometa` | `./token-metadata-creator` | path to token-metadata-creator | asset metadata script (not checked here) |
| `koiosApiToken` | empty | Koios JWT; empty means the public tier | light mode only |
| `guardrailsScriptFile` | `./guardrails-script.plutus` | guardrails script | governance scripts |
| `showVersionInfo` | `yes` | print the version/mode banner | display only |
| `queryTokenRegistry` | `yes` | query the token registry live | consumed elsewhere |
| `cropTxOutput` | `yes` | crop transaction file output to 4000 characters | consumed elsewhere |

- **SPO-Cconf-IN-001** The settings in the table take their default unless a settings file (SPO-Cconf-IN-003) or an earlier assignment changes them. (src: L29, L35-L37, L45-L46, L50-L51, L55, L59, L63, L67, L71, L94-L96, L325)
- **SPO-Cconf-IN-002** `network` defaults to `mainnet` when unset. The values of `magicparam`, `network` and `addrformat` inherited from the process environment are discarded first, so only settings files or the edited script body can set them. (src: L2, L159)
- **SPO-Cconf-IN-003** Settings files are sourced in this order, each only if it is a regular file, and a later file overrides an earlier one: `<scriptDir>/common.inc`, then `$HOME/.common.inc`, then `./common.inc` (the current directory). `<scriptDir>` is the directory part of the invoking script's path. (src: L163-L166)
- **SPO-Cconf-IN-004** After the settings files are loaded, a non-empty lowercase `workmode` replaces `workMode`, and a non-empty lowercase `koiosapitoken` replaces `koiosApiToken`. (src: L169, L172)
- **SPO-Cconf-IN-005** For each of `magicparam`, `addrformat`, `byronToShelleyEpochs`, `tokenMetaServer`, `transactionExplorer`, `koiosAPI`, `adahandlePolicyID`, `adahandleAPI`, `catalystAPI`, `lightModeParametersURL`, `ccMemberColdHashNames`: a non-empty user value wins over the network preset's value, per variable; an empty user value takes the preset. (src: L315-L324, L326)
- **SPO-Cconf-IN-006** `offlineFile` falls back to `./offlineTransfer.json` when empty. (src: L510)
- **SPO-Cconf-IN-007** `showVersionInfo`, `queryTokenRegistry` and `cropTxOutput` become false when their value equals `NO` in any letter case, and true for every other value including empty. (src: L511-L513)
- **SPO-Cconf-IN-008** `ENV_USEERA` (environment) forces the era, see SPO-Cconf-INV-020. `ENV_MINLEDGERCARDANOAPPVERSION` (environment) overrides the minimum Ledger Cardano-app version, see SPO-Cconf-INV-012. `ENV_SKIP_PROMPT` and `ENV_DECRYPT_PASSWORD` are documented in the header but consumed by other functions and scripts, not by the prologue. (src: L20-L23, L344, L673)
- **SPO-Cconf-INV-003** The terminal output device `termTTY` is `$(tty)` when that device is writable, else the literal `/dev/tty`. Prompt code elsewhere uses it. (src: L157)

## Network selection

- **SPO-Cconf-INV-004** The preset is selected by `network` compared case-insensitively against the alias table below. On a match, `network` is rewritten to the canonical display name. (src: L183-L309)
- **SPO-Cconf-INV-005** A `network` value that matches no alias selects no preset. The preset variables stay empty, so `magicparam`, `addrformat` and `byronToShelleyEpochs` must come from the user (SPO-Cconf-PRE-002). Endpoint settings (`koiosAPI`, `adahandleAPI`, `lightModeParametersURL`, `catalystAPI`, `tokenMetaServer`, `transactionExplorer`, `adahandlePolicyID`) stay empty unless the user sets them, which disables the features that depend on them. (src: L183-L326, L337)
- **SPO-Cconf-PRE-001** Exits 1 when `network` (lowercased) is `mainnet` and `magicparam` or `addrformat` contains the text `testnet`. This runs before the preset is applied. (src: L178)
- **SPO-Cconf-PRE-002** Exits 1 when `magicparam`, `addrformat` or `byronToShelleyEpochs` is still empty after the preset and user values are merged. (src: L337)

Alias table (reference data, case-insensitive match):

| Aliases | Canonical `network` | `magicparam` and `addrformat` | `byronToShelleyEpochs` |
| --- | --- | --- | --- |
| `mainnet` | `Mainnet` | `--mainnet` | 208 |
| `preprod`, `pre-prod` | `PreProd` | `--testnet-magic 1` | 4 |
| `preview`, `pre-view` | `Preview` | `--testnet-magic 2` | 0 |
| `guildnet`, `guild-net` | `GuildNet` | `--testnet-magic 141` | 2 |
| `sancho`, `sancho-net`, `sanchonet` | `SanchoNet` | `--testnet-magic 4` | 0 |
| `legacy`, `testnet` | `Legacy` (documentation only, inactive chain) | `--testnet-magic 1097911063` | 74 |

Endpoint table (values before slash normalisation; empty cell = empty value):

| Network | `tokenMetaServer` | `transactionExplorer` | `koiosAPI` | `adahandleAPI` | `catalystAPI` | `lightModeParametersURL` |
| --- | --- | --- | --- | --- | --- | --- |
| Mainnet | `https://tokens.cardano.org/metadata/` | `https://cardanoscan.io/transaction/` | `https://api.koios.rest/api/v1` | `https://api.handle.me` | `https://api.projectcatalyst.io/api/v1` | `https://uptime.live/data/cardano/parms/mainnet-parameters.json` |
| PreProd | `https://metadata.cardano-testnet.iohkdev.io/metadata` | `https://preprod.cardanoscan.io/transaction` | `https://preprod.koios.rest/api/v1` | `https://preprod.api.handle.me` | `https://api.testnet.projectcatalyst.io/api/v1` | `https://uptime.live/data/cardano/parms/preprod-parameters.json` |
| Preview | same as PreProd | `https://preview.cardanoscan.io/transaction` | `https://preview.koios.rest/api/v1` | `https://preview.api.handle.me` | | `https://uptime.live/data/cardano/parms/preview-parameters.json` |
| GuildNet | same as PreProd | | `https://guild.koios.rest/api/v1` | | | |
| SanchoNet | same as PreProd | | `https://sancho.koios.rest/api/v1` | | | `https://uptime.live/data/cardano/parms/sanchonet-parameters.json` |
| Legacy | same as PreProd | | | | | |

`adahandlePolicyID` is `f0ff48bbb7bbe9d59a40f1ce90e9e9d0ff5002ec48f232b49ca0fb9a` for every network except Legacy, which uses `8d18d786e92776c824607fd8e193ec535c79dc61ea2405ddf3b09fe3`.

Constitutional-committee member names (`ccMemberColdHashNames`) are a JSON object mapping a cold credential (`scriptHash-<hex>` or `keyHash-<hex>`) to a display name. Mainnet and PreProd carry the same 14 names; Preview, GuildNet, SanchoNet and Legacy carry `{}`. The text is inlined into jq programs by the governance scripts.

| Cold credential | Name |
| --- | --- |
| `scriptHash-84aebcfd3e00d0f87af918fc4b5e00135f407e379893df7e7d392c6a` | ECC |
| `scriptHash-9cc3f387623f45dae6a68b7096b0c2e403d8601a82dc40221ead41e2` | CJC |
| `scriptHash-9752e4306e5ae864441d21064f791174c8b626199b8e7a45f9e03b45` | Ace |
| `scriptHash-1980dbf1ad624b0cb5410359b5ab14d008561994a6c2b6c53fabec00` | Ting |
| `keyHash-13493790d9b03483a1e1e684ea4faf1ee48a58f402574e7f2246f4d4` | Phil |
| `keyHash-dc0d6ef49590eb6880a50a00adde17596e6d76f7159572fa1ff85f2a` | KtorZ |
| `scriptHash-16feefc225e06f75a3c917f4aa50acffde7631ea0355721f2ac12542` | Curia |
| `keyHash-c46a3789d71bc0a27d1c381909289978797a60c5f67aa8bc2b26ab92` | Xtina |
| `---` | `old ones` (a separator entry, not a credential) |
| `scriptHash-349e55f83e9af24813e6cb368df6a80d38951b2a334dfcdf26815558` | CAC |
| `scriptHash-b6012034ba0a7e4afbbf2c7a1432f8824aee5299a48e38e41a952686` | CF |
| `scriptHash-ce8b37a72b178a37bbd3236daa7b2c158c9d3604e7aa667e6c6004b7` | Emurgo |
| `scriptHash-df0e83bde65416dade5b1f97e7f115cc1ff999550ad968850783fe50` | IOG |
| `scriptHash-e8165b3328027ee0d74b1f07298cb092fd99aa7697a1436f5997f625` | CJC |
| `scriptHash-f0dc2c00d92a45521267be2d5de1c485f6f9d14466d7e16062897cf7` | ICC |

- **SPO-Cconf-INV-006** The preset values are exactly those of the three tables above. (src: L183-L309)
- **SPO-Cconf-INV-007** A single trailing `/` is removed from `tokenMetaServer`, `koiosAPI`, `transactionExplorer`, `catalystAPI` and `adahandleAPI` after the merge (so user-set values are normalised too). `lightModeParametersURL` is not normalised. (src: L330-L334)

> **Upstream quirk:** The inactive Legacy network is reachable through the alias `testnet`, which is easy to confuse with a generic "a testnet".

## Pinned versions

- **SPO-Cconf-INV-008** The pinned versions are assigned after the settings files are sourced, so a settings file cannot change them: cardano-cli min `11.0.0`, max `99.99.9`; cardano-node min `11.0.0`, max `99.99.9`; cardano-hw-cli min `1.20.0`; cardano-signer min `1.35.0`; catalyst-toolbox min `0.5.0`; Trezor Cardano app min `2.7.2`; Keystone Cardano app min `1.7.7`. `99.99.9` means "no upper limit so far". (src: L339-L343, L345-L349)
- **SPO-Cconf-INV-012** The minimum Ledger Cardano-app version is `8.0.8`, or the value of the environment variable `ENV_MINLEDGERCARDANOAPPVERSION` when non-empty. This is the only pinned value that the environment can change. (src: L344)

## Defaults, exports and derived values

- **SPO-Cconf-INV-009** Constants: `defEra` is `latest` (era used for commands that do not depend on the era); `defTTL` is `100000` (seconds a transaction stays valid, added to the tip slot, see SPO-Cchain-INV-009); `addrTypePayment` is `payment`; `addrTypeStake` is `stake`. `lightModeParametersJSON` starts empty and `koiosAuthorizationHeader` starts empty (public tier). (src: L352-L357)
- **SPO-Cconf-INV-010** `CARDANO_NODE_SOCKET_PATH` is exported with the value of `socket` for every child process. (src: L361)
- **SPO-Cconf-INV-011** `CARDANO_NODE_NETWORK_ID` is exported: the literal `mainnet` when `magicparam` (lowercased) contains `mainnet`; otherwise the text after the first space in `magicparam` (the decimal magic, e.g. `1`). `magicparam` itself stays in use for explicit cardano-cli arguments. (src: L364-L368)
- **SPO-Cconf-INV-013** `BC_LINE_LENGTH` is exported as `1000` so `bc` never wraps long numbers. (src: L371)
- **SPO-Cconf-INV-014** `tempDir` is the directory in which the system would create a temporary file (honours `TMPDIR`, usually `/tmp`). Transaction scratch files live there. (src: L645)

## Work mode

- **SPO-Cconf-MODE-001** `workMode` is lowercased and then must be `online`, `light` or `offline`. It sets exclusive flags: online gives `onlineMode`, `fullMode`; light gives `onlineMode`, `lightMode`; offline gives `offlineMode`. (src: L539-L542, L545-L546, L598-L599)
- **SPO-Cconf-PRE-003** Exits 1 on any other `workMode`. (src: L602-L604)
- **SPO-Cconf-MODE-002** Only in `online` (full) mode is the cardano-node binary located and version-checked (SPO-Cconf-PRE-009 to PRE-011). Light and offline never touch cardano-node. (src: L614-L622)
- **SPO-Cconf-MODE-003** Only in `offline` mode is `curl` not required. (src: L637)
- **SPO-Cconf-MODE-004** The Koios API token is read, validated and turned into an authorization header only in `light` mode. In `online` and `offline` mode the token is ignored and `koiosAuthorizationHeader` stays empty, so Koios calls made from online mode (for example ADA Handle root lookups) use the public tier. (src: L357, L569-L594)

### Light-mode setup

- **SPO-Cconf-PRE-004** Exits 1 in light mode when `lightModeParametersURL` or `koiosAPI` is empty ("no Light-Mode for this network"). (src: L549)
- **SPO-Cconf-EXT-001** In light mode the prologue fetches the light-mode parameters JSON once through `queryLight_protocolParameters` (see Clight) and keeps it in memory as `lightModeParametersJSON`, so later calls do not refetch it. (src: L552)
- **SPO-Cconf-PRE-005** Exits 1, printing the function's error text, when that fetch fails. (src: L552-L553)
- **SPO-Cconf-IN-009** The parameters JSON contributes three fields to the prologue: `.sposcriptsLightMode.lastUpdate` (a date string), `.sposcriptsLightMode.magic`, `.sposcriptsLightMode.versionCLI`. (src: L556)
- **SPO-Cconf-PRE-006** Exits 1 when `now(UTC seconds) - epochSeconds(lastUpdate) > 21600` (more than 6 hours). The comparison is one-sided: a `lastUpdate` in the future (local clock behind) passes. (src: L559-L560)

> **Upstream quirk:** An unparsable or missing `lastUpdate` makes the `date` call produce an empty value and the arithmetic fail; what the shell then does is not specified in the source (see Open questions).

- **SPO-Cconf-PRE-007** Exits 1 when `.sposcriptsLightMode.magic` differs (string comparison) from `CARDANO_NODE_NETWORK_ID` (SPO-Cconf-INV-011). (src: L563)
- **SPO-Cconf-PRE-008** Exits 1 when the local cardano-cli version is lower than `.sposcriptsLightMode.versionCLI` (same version ordering as SPO-Cconf-INV-015). (src: L566-L567)
- **SPO-Cconf-IN-010** The Koios token is trimmed of leading and trailing blanks (via `trimString`) before use. (src: L570)
- **SPO-Cconf-INV-016** Defaults when no token is set: tier `Public-Tier`, project id `---`, expiry text `no expire date`, empty authorization header. (src: L573-L576)
- **SPO-Cconf-INV-017** A non-empty token is decoded as a JWT: the second dot-separated segment is base64-decoded and parsed as JSON. Fields read: `exp` (default `-1`), `tier`, `projID` (default `---`). (src: L580, L582)
- **SPO-Cconf-PRE-012** Exits 1 when the token cannot be decoded that way ("not a valid one"). (src: L580-L581)
- **SPO-Cconf-INV-018** `tier` `1`, `2`, `3` map to `Free-Tier`, `Pro-Tier`, `Premium-Tier`; any other value `v` becomes `Tier v`. (src: L587-L592)
- **SPO-Cconf-INV-019** A token with `exp > 0` is flagged `expired` in the display text when `exp < now`; this never stops the run. The token is still sent. (src: L583-L586)
- **SPO-Cconf-INV-021** With a token, `koiosAuthorizationHeader` is the exact string `authorization: Bearer <token>`. All Koios calls in Clight send it. (src: L593)

### Tool presence and version checks

- **SPO-Cconf-PRE-013** Exits 1 when `cardanocli` is not resolvable as a command (relative paths such as `./cardano-cli` must be an executable file). (src: L528)
- **SPO-Cconf-EXT-002** The cardano-cli version is the second whitespace-separated field of the first line printed by `<cardanocli> version`. (src: L529)
- **SPO-Cconf-PRE-014** Exits 1 when the cli version is below the pinned minimum. (src: L530-L531)
- **SPO-Cconf-PRE-015** Exits 1 when the cli version is above the pinned maximum. (src: L532-L533)
- **SPO-Cconf-PRE-009** In online mode, exits 1 when `cardanonode` is not resolvable. (src: L615)
- **SPO-Cconf-EXT-003** The cardano-node version is read like the cli version, from `<cardanonode> version`. (src: L616)
- **SPO-Cconf-PRE-010** In online mode, exits 1 when the node version is below the pinned minimum. (src: L617-L618)
- **SPO-Cconf-PRE-011** In online mode, exits 1 when the node version is above the pinned maximum. (src: L619-L620)
- **SPO-Cconf-PRE-016** Exits 1 when `bech32_bin` is not resolvable and no regular file named `bech32` exists in `<scriptDir>`. When that file exists, `bech32_bin` is silently set to it (file existence only, not executability). (src: L628-L631)
- **SPO-Cconf-PRE-017** Exits 2 (message on stdout, not stderr) when `curl` is missing, checked only outside offline mode. (src: L637)
- **SPO-Cconf-PRE-018** Exits 2 when `jq` is missing. (src: L638)
- **SPO-Cconf-PRE-019** Exits 2 when `bc` is missing. (src: L639)
- **SPO-Cconf-PRE-020** Exits 2 when `xxd` is missing. (src: L640)
- **SPO-Cconf-INV-015** Version comparison is GNU version-sort ordering ("is A less than or equal to B"), see `versionCheck`. A cli or node version that cannot be read (empty string) sorts lowest and therefore fails the minimum check. (src: L517, L530, L617)

The prologue does not check that `cardano-signer`, `cardano-hw-cli`, `catalyst-toolbox` or `token-metadata-creator` exist, nor that `socket` or the genesis files exist; those checks happen where each is first used (offline arithmetic checks the genesis files, see Cchain).

## Era selection

- **SPO-Cconf-INV-022** `get_NodeEra` is evaluated once, at prologue time, after the work mode is lowercased. Its result is not refreshed during the run. (src: L539, L661)
- **SPO-Cconf-INV-023** When the evaluated era is not `auto`, `nodeEraParam` is `--<era>-era` (for cardano-cli before 8.12) and `cliEra` is `<era>` (lowercase, used as the era argument of cardano-cli 8.12+). When it is `auto`, `nodeEraParam` is empty and `cliEra` is `latest` (`defEra`). (src: L661-L668)
- **SPO-Cconf-INV-020** When the environment variable `ENV_USEERA` is non-empty it overrides both: `nodeEraParam` is `--<lowercased value>-era` and `cliEra` is the lowercased value. The value is not validated. (src: L673)

> **Upstream quirk:** In online mode an unreachable node makes `get_NodeEra` return `auto` silently, so the run proceeds with `cliEra=latest`. The failure surfaces later, at the first real query.

## Display

When `showVersionInfo` is true the prologue prints a banner with cli (and node) version, mode, era, network and, in offline mode, the local time; in light mode the Koios project id, tier and token expiry; in online mode a warning when the socket file does not exist. This is display only: the socket warning does not stop the run. (src: L609, L621, L677-L708)

## Functions

### majorError

- **SPO-Cconf-OUT-001** Writes a decorative banner, the given message, and a footer inviting the operator to check GitHub for a newer version, all to **stderr**. (src: L148-L152)
- **SPO-Cconf-INV-024** Then calls `exit 1`. It terminates the calling shell (or only the command-substitution subshell when invoked inside `$(...)`); callers add a redundant `exit 1` after it. It never returns. (src: L151)

### trimString

- **SPO-Cconf-OUT-002** Writes its single argument to stdout with leading blanks and trailing blanks removed. "Blank" is space or tab; for a multi-line argument only the start of the first line and the end of the last line are trimmed, and inner lines are untouched. Exit status 0. (src: L378-L381)

### versionCheck

- **SPO-Cconf-OUT-003** `versionCheck MIN CURRENT` writes nothing and returns 0 when `MIN <= CURRENT` in GNU version-sort ordering (equality passes), else non-zero (1). The caller passes the pair as (minimum, current) for a lower bound and (current, maximum) for an upper bound. (src: L517)

### exists

- **SPO-Cconf-OUT-004** `exists NAME` writes nothing and returns 0 when `NAME` resolves to a command, builtin or executable path, else non-zero. (src: L521-L523)

### get_NodeEra

- **SPO-Cconf-OUT-005** Writes the era name in lowercase to stdout, or the word `auto` when the era query printed nothing (an unreadable or absent offline file, a failed online query, an empty light-mode document); always returns 0. In offline and light mode a present transfer file or light-mode document whose era field is absent yields the literal `null`, not `auto`, because `jq -r` prints `null` for a missing field and only the online read filters it out (SPO-Cconf-MODE-005). The prologue then treats `null` as an era: `nodeEraParam` becomes `--null-era` and the `cardano-cli` era argument `null`, so every later `cardano-cli <era> ...` call fails. (src: L650-L658, L663-L664)
  > **Upstream quirk:** a transfer file without `protocol.era` (accepted by SPO-Coffline-OUT-001, and produced by the `cleartx`/`clearhistory` quirk of SPO-Ptransfer-IN-002) or a light-mode document without `lastTip.era` breaks every era-qualified call. A port falls back to `auto` for a null or missing era.
- **SPO-Cconf-MODE-005** Online: runs `<cardanocli> latest query tip <magicparam>` and reads `.era` (null ignored). The CLI's stderr is discarded. (src: L652)
- **SPO-Cconf-MODE-006** Light: reads `.sposcriptsLightMode.lastTip.era` from the in-memory light-mode parameters JSON, without a null filter: a missing field gives the text `null` (SPO-Cconf-OUT-005). (src: L654)
- **SPO-Cconf-MODE-007** Offline: reads `.protocol.era` from the transfer file `offlineFile`, without a null filter: a missing field gives the text `null` (SPO-Cconf-OUT-005). (src: L653)

> **Upstream quirk:** With an unknown `workMode` none of the branches runs; the prologue has rejected that case already (SPO-Cconf-PRE-003) so the result is `auto`.

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Mainnet selected with testnet magic/format | 1 | SPO-Cconf-PRE-001 |
| Missing magic/format/Byron epochs | 1 | SPO-Cconf-PRE-002 |
| Unknown work mode | 1 | SPO-Cconf-PRE-003 |
| Light mode unavailable (no Koios or parameter URL) | 1 | SPO-Cconf-PRE-004 |
| Light parameter fetch failed | 1 | SPO-Cconf-PRE-005 |
| Light parameters older than 6 h | 1 | SPO-Cconf-PRE-006 |
| Light parameters magic mismatch | 1 | SPO-Cconf-PRE-007 |
| Local cli older than light parameters ask | 1 | SPO-Cconf-PRE-008 |
| cardano-node missing, too old, too new (online) | 1 | SPO-Cconf-PRE-009, PRE-010, PRE-011 |
| Koios token invalid | 1 | SPO-Cconf-PRE-012 |
| cardano-cli missing, too old, too new | 1 | SPO-Cconf-PRE-013, PRE-014, PRE-015 |
| bech32 missing | 1 | SPO-Cconf-PRE-016 |
| curl, jq, bc, xxd missing | 2 | SPO-Cconf-PRE-017 to PRE-020 |

## Domain mapping

Use case `LoadConfiguration(settingsLayers, env) -> RunContext` produces `NetworkProfile`, `WorkMode`, `ToolchainRequirements`, `eraSelection`.

| Port | Operation | Purpose |
| --- | --- | --- |
| `Store` | `get(Settings)` for each layer *(new)* | The three `common.inc` layers plus the base defaults |
| `Toolchain` *(new port)* | `locate(tool)`, `version(tool)` *(new)* | Binary presence and version probes (cli, node, bech32, curl, jq, bc, xxd) |
| `Directory` | `fetchUrl(lightModeParametersURL)` | Light-mode parameters (through `queryLight_protocolParameters`) |
| `Clock` | `now()` *(new)* | 6-hour freshness check |
| `ChainQuery` | `tip()` | Node era (online); light and offline serve the era from their snapshot |
| `UI` | `show(view)` | Banner, warnings |

## Port notes

* `NetworkProfile` should be one immutable value built from the preset plus validated overrides. The alias table, endpoint table and CC names are data, not code.
* Exit codes 1 and 2 are a CLI adapter concern. The domain returns a typed configuration error (`ConfigInvalid`, `ToolMissing`, `ToolVersionOutOfRange`, `LightModeUnavailable`, `ParametersStale`, `NetworkMismatch`).
* The 6-hour freshness check should be symmetric (absolute difference), and the tool-presence checks should come before light-mode use of `jq`/`curl`/`bc`; a native port needs none of them.
* The Koios token should be validated for expiry, not just flagged. A native port decodes base64url without `jq`.
* Era selection should be re-evaluated when the node reports a hard-fork rather than frozen at start.
* `ENV_USEERA` should be validated against the known era names.

## Open questions

* What does bash do when the `$(( ... ))` at L559 sees an empty `date` result (missing `lastUpdate`)? Settle by running the prologue against a parameter file without that field.
* Does `jq`'s `@base64d` accept the base64url alphabet (`-`, `_`) and missing padding that JWTs use? It depends on the jq version; settle with a real token.
