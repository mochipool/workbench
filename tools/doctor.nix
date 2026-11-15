# `workbench-doctor`: verifies the installed tools and (optionally) the
# connected hardware wallet against the requirements this flake enforces.
# Requirement values are baked in from the same data that generates the
# readme's requirements table (versions.nix + the SPO scripts' 00_common.sh).
{ pkgs
, requirements
, tools # versions.nix `tools`
, cardano-node
, cardano-cli
, cardano-hw-cli
, cardano-signer
}:
let
  orDefault = d: v: if v == null then d else v;
in
pkgs.writeShellApplication {
  name = "workbench-doctor";
  runtimeInputs = [
    pkgs.coreutils
    pkgs.gnugrep
    pkgs.gawk
    cardano-node
    cardano-cli
    cardano-hw-cli
    cardano-signer
  ];
  text = ''
    usage() {
      echo "Usage: workbench-doctor [--no-device]"
      echo "  Checks tool versions against the SPO scripts' requirements and, unless"
      echo "  --no-device is given, the connected hardware wallet."
    }

    check_device=1
    for arg in "$@"; do
      case "$arg" in
        --no-device) check_device=0 ;;
        -h|--help) usage; exit 0 ;;
        *) usage; exit 2 ;;
      esac
    done

    fails=0
    warns=0
    ok()   { printf '  \033[32mOK\033[0m    %s\n' "$*"; }
    warn() { printf '  \033[33mWARN\033[0m  %s\n' "$*"; warns=$((warns + 1)); }
    fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

    # first dotted version number in a string
    semver() { grep -oE '[0-9]+(\.[0-9]+)+' | head -n1; }
    # ver_ge A B  =>  A >= B
    ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

    # check_tool NAME ACTUAL PINNED MIN MAX
    check_tool() {
      local name=$1 actual=$2 pinned=$3 min=$4 max=$5
      if [ -z "$actual" ]; then fail "$name: could not determine version"; return; fi
      if ! ver_ge "$actual" "$min"; then
        fail "$name $actual is older than the required minimum $min"
      elif ! ver_ge "$max" "$actual"; then
        fail "$name $actual is newer than the allowed maximum $max"
      elif [ "$actual" != "$pinned" ]; then
        warn "$name $actual satisfies the requirements but differs from the pinned $pinned"
      else
        ok "$name $actual (required ≥ $min)"
      fi
    }

    echo "Tools (SPO scripts ${tools.spo-scripts.version}):"
    node_v=$(cardano-node --version 2>/dev/null | head -n1 | semver || true)
    cli_v=$(cardano-cli --version 2>/dev/null | head -n1 | semver || true)
    hw_v=$(cardano-hw-cli version 2>/dev/null | head -n1 | semver || true)
    signer_v=$(cardano-signer version 2>/dev/null | head -n1 | semver || true)
    check_tool cardano-node   "$node_v"   "${tools.cardano-node.version}"   "${orDefault "0" requirements.minNodeVersion}"           "${orDefault "99.99.9" requirements.maxNodeVersion}"
    check_tool cardano-cli    "$cli_v"    "${tools.cardano-cli.version}"    "${orDefault "0" requirements.minCliVersion}"            "${orDefault "99.99.9" requirements.maxCliVersion}"
    check_tool cardano-hw-cli "$hw_v"     "${tools.cardano-hw-cli.version}" "${orDefault "0" requirements.minHardwareCliVersion}"    "99.99.9"
    check_tool cardano-signer "$signer_v" "${tools.cardano-signer.version}" "${orDefault "0" requirements.minCardanoSignerVersion}" "99.99.9"

    # Linux only: USB access rules for Ledger/Trezor
    if [ "$(uname -s)" = "Linux" ]; then
      echo
      echo "USB access:"
      found=0
      for d in /etc/udev/rules.d /run/udev/rules.d /usr/lib/udev/rules.d /lib/udev/rules.d /run/current-system/sw/lib/udev/rules.d; do
        if grep -qsr -m1 'idVendor.*2c97' "$d" 2>/dev/null; then found=1; break; fi
      done
      if [ "$found" = 1 ]; then
        ok "udev rules for Ledger devices are installed"
      else
        warn "no udev rules for Ledger devices found; run: nix run .#install-udev-rules"
      fi
    fi

    if [ "$check_device" = 1 ]; then
      echo
      echo "Hardware wallet (connect, unlock, and open the Cardano app on Ledger):"
      out=$(timeout 20 cardano-hw-cli device version 2>&1 || true)
      line=$(printf '%s\n' "$out" | head -n1)
      if ! printf '%s' "$out" | grep -q 'app version' || printf '%s' "$out" | grep -q undefined; then
        warn "no usable device found (''${line:-no output}); skipping device checks"
      else
        manu=$(printf '%s' "$line" | awk '{print tolower($1)}')
        ver=$(printf '%s' "$line" | semver || true)
        case "$manu" in
          ledger)   check_tool "Ledger Cardano app"   "$ver" "$ver" "${orDefault "0" requirements.minLedgerCardanoAppVersion}"   "99.99.9" ;;
          trezor)   check_tool "Trezor firmware"      "$ver" "$ver" "${orDefault "0" requirements.minTrezorCardanoAppVersion}"   "99.99.9" ;;
          keystone) check_tool "Keystone firmware"    "$ver" "$ver" "${orDefault "0" requirements.minKeystoneCardanoAppVersion}" "99.99.9" ;;
          *) warn "unrecognised device '$manu': $line" ;;
        esac
      fi
    fi

    echo
    if [ "$fails" -gt 0 ]; then
      echo "$fails problem(s), $warns warning(s)."
      exit 1
    fi
    echo "All checks passed ($warns warning(s))."
  '';
}
