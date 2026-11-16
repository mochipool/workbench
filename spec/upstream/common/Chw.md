+++
id = "Chw"
kind = "common"
title = "Hardware wallet session"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["key-custody"]
use_cases = []
depends_on = ["Cconf", "Cui"]

upstream_path = "cardano/mainnet/00_common.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "9490fae84352a491bbded9bd4a14587521336364f9814a2df5aff6b86266bfba"
upstream_lines = 2966

[functions]
start_HwWallet = "59a4a0955efe77477b26e50dc4b494a00cc82a0ceaf8da3c09f74179e17ceebe"
+++

# Chw: hardware wallet session

`start_HwWallet` gets a hardware wallet ready before any action that needs the device to witness or sign. It checks that `cardano-hw-cli` is installed and new enough, waits (with no time limit) until a device with its Cardano app open answers, identifies the vendor, optionally restricts the action to some vendors, and checks that the device's app or firmware version is new enough. It does not sign anything: the caller runs `cardano-hw-cli` for the actual witness afterwards, and the user approves on the device at that point. The final prompt it prints ("Please approve the action on your Hardware-Wallet") is display only.

It is called as a plain statement, never inside `$(...)`, so each `exit 1` below ends the whole calling script. Every caller follows the call with `checkError "$?"` and an `if [ $? -ne 0 ]; then exit $?; fi` test; both are dead code, because the function never returns a non-zero status (see SPO-Chw-INV-002).

## Interface

- **SPO-Chw-IF-001** Takes four optional positional arguments. Argument 1 restricts the action to certain vendors: it is upper-cased and then used as a string that must contain the detected vendor name (see SPO-Chw-PRE-004). Callers pass `Ledger|Keystone` (the key-generation, opcert, committee and Calidus operations), `Ledger` (voting, `24b`), or nothing. Arguments 2, 3 and 4 override the minimum Ledger app version, Trezor firmware version and Keystone firmware version for this call. An empty string selects the default, which is how `15_calidusPoolKey` calls it (`"" "" ""`). `09a_catalystVote` passes `"" "6.0.3" ""`, which sets the Ledger minimum to 6.0.3. (src: L2605-L2608)

## Inputs

- **SPO-Chw-IN-001** Reads the path of the cardano-hw-cli binary from `cardanohwcli` (default `cardano-hw-cli`, L55). (src: L2610, L2612, L2617)
- **SPO-Chw-IN-002** Reads the minimum versions as follows. The Ledger minimum can also be raised or lowered with the environment variable `ENV_MINLEDGERCARDANOAPPVERSION`. (src: L344-L347, L2606-L2608)

  | Setting | Default | Meaning |
  | --- | --- | --- |
  | `minHardwareCliVersion` | `1.20.0` | cardano-hw-cli |
  | `minLedgerCardanoAppVersion` | `8.0.8` (from `ENV_MINLEDGERCARDANOAPPVERSION`) | Cardano app on a Ledger |
  | `minTrezorCardanoAppVersion` | `2.7.2` | Trezor firmware |
  | `minKeystoneCardanoAppVersion` | `1.7.7` | Keystone firmware |

## Behaviour

1. **Find the tool.**
   - **SPO-Chw-PRE-001** Exits 1 with a message when the `cardanohwcli` binary cannot be found (`which` returns nothing). (src: L2610)
2. **Check the tool's version.**
   - **SPO-Chw-EXT-001** Runs `cardano-hw-cli version` and takes the **sixth space-separated word of the first output line** as `versionHWCLI`. stderr is discarded. (src: L2612)
   - **SPO-Chw-INV-001** A version passes a minimum when the minimum sorts at or before it in GNU `sort -V` order (equal passes), as `versionCheck` computes (L517). An **empty** current version passes: with nothing to compare, `sort -C` sees a single line. (src: L2613, L517)
   - **SPO-Chw-PRE-002** Exits 1 through `majorError` when `versionHWCLI` is older than `minHardwareCliVersion`. The message names both versions and goes to stderr. (src: L2614, L148-L152)
3. **Wait for the device.**
   - **SPO-Chw-EXT-002** Runs `cardano-hw-cli device version`, merging stderr into the captured text. It repeats until the text contains `app version` and does not contain `undefined`. (src: L2617, L2619, L2629)
   - **SPO-Chw-PR-001** While waiting, shows the first 64 characters of the CLI's answer (the text `General error` is replaced by "Cardano App not opened?") and retries every 6 seconds. There is no retry limit and no abort other than the user's interrupt (Ctrl+C). The message is display only. (src: L2616, L2621-L2629)
4. **Identify the device.**
   - **SPO-Chw-EXT-003** Reads the first line of the device answer. The first word is the vendor (`walletManu`) and the **fourth** word is the app or firmware version (`versionApp`). Vendor comparison is case-insensitive. (src: L2633-L2634, L2639)
5. **Apply the vendor restriction.**
   - **SPO-Chw-PRE-003** When argument 1 is non-empty and does not contain the upper-cased vendor name as a substring, exits 1 with a message that the function is only available on the named vendors. This check runs before the version check. (src: L2637)
6. **Check the device version, per vendor.**
   - **SPO-Chw-PRE-004** `LEDGER`: exits 1 when `versionApp` is older than the Ledger minimum, with advice on enabling a newer app through Ledger Live's experimental features. `TREZOR`: exits 1 when older than the Trezor minimum. `KEYSTONE`: exits 1 when older than the Keystone minimum. All three use the ordering of SPO-Chw-INV-001. (src: L2641-L2657)
   - **SPO-Chw-PRE-005** Any other vendor exits 1 through `majorError` ("Only Ledger and Trezor Hardware-Wallets are supported"). The message omits Keystone, which is supported. (src: L2659-L2661)
7. **Hand back.**
   - **SPO-Chw-OUT-001** On success, prints the found vendor, version and cardano-hw-cli version and the "please approve" prompt, and returns status 0. It leaves the global shell variable `versionHWCLI` set, which later code does not read. (src: L2644, L2650, L2656)
   - **SPO-Chw-INV-002** Every failure path ends in `exit 1`; there is no `return` with a non-zero status. A calling script can therefore never observe a failure and carry on. (src: L2603-L2664)

> **Upstream quirk:** An empty `versionHWCLI` passes the check (SPO-Chw-INV-001). If a new cardano-hw-cli changes the first line of `version` so that the sixth word is not the version, the check silently stops protecting against old versions instead of failing. (src: L2612-L2613)

> **Upstream quirk:** `onlyForManu` is matched as a substring of the upper-cased argument, so `Ledger|Keystone` works only because the vendor name happens to appear inside it, and an empty vendor name matches every restriction. (src: L2637)

## External calls

| Call | Id | Purpose |
| --- | --- | --- |
| `cardano-hw-cli version` | SPO-Chw-EXT-001 | Tool version |
| `cardano-hw-cli device version` | SPO-Chw-EXT-002, SPO-Chw-EXT-003 | Device answer: `<vendor> ... app version <x>`; vendor is word 1, version word 4 |

## Work modes

Mode-independent. It needs a locally attached device and does not touch the chain.

## Prompts

None gate an effect. The wait loop of SPO-Chw-PR-001 is display only, and the approval itself happens on the device when the caller runs the signing command.

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| cardano-hw-cli not found | 1 | SPO-Chw-PRE-001 |
| cardano-hw-cli too old | 1 | SPO-Chw-PRE-002 |
| Vendor not allowed for this action | 1 | SPO-Chw-PRE-003 |
| Device app or firmware too old | 1 | SPO-Chw-PRE-004 |
| Unknown vendor | 1 | SPO-Chw-PRE-005 |

## Domain mapping

| Port | Operation | Purpose |
| --- | --- | --- |
| `Signer` | `openHardwareSession(allowedVendors?, minVersions?)` *(new)* | Wait for a device, identify it, and enforce the vendor and version gates; the hardware adapter of `Signer` wraps cardano-hw-cli |
| `UI` | `show(view)` | Wait and approval messages |

The aggregate rule is on `HardwareKeyRef`: a key kept on a device is usable only through a session that passed these gates. Version minima are `ToolchainRequirements` (context `configuration`).

## Port notes

* Return a typed failure (`ToolMissing`, `ToolTooOld`, `VendorNotAllowed`, `DeviceTooOld`, `UnsupportedVendor`) instead of exiting. A reimplementation should make an unreadable version a failure, not a pass.
* Replace the endless wait with a bounded wait or a cancellable one, so a server or TUI adapter can time out.
* A remote-signing adapter satisfies the same port without these gates by delegating them to the remote signer.

## Open questions

* The exact output format of `cardano-hw-cli version` and `device version` (words 6 and 1/4) is fixed only by the pinned hw-cli release (1.20.0). It should be confirmed against that release when the adapter is written.
