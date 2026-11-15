# Parses the version requirements that the SPO scripts enforce at runtime
# (00_common.sh) and validates the workbench release set against them at
# evaluation time, so an incompatible pin fails `nix flake check` instead of
# failing on an operator's machine.
{ lib
, src # spo-scripts source tree
, tools # versions.nix `tools` attrset
}:
let
  commonSh = builtins.readFile "${src}/cardano/mainnet/00_common.sh";
  lines = lib.splitString "\n" commonSh;

  # Extract the first quoted version from a `name=...` shell assignment (first
  # matching line wins). Handles both `name="1.2.3"` and the env-overridable
  # `name=${ENV:-"1.2.3"}` form.
  getVar = name:
    let
      matching = builtins.filter (l: lib.hasPrefix "${name}=" l) lines;
      m = if matching == [ ] then null
          else builtins.match ''[^"]*"([0-9][0-9.]*)".*'' (builtins.head matching);
    in
      if m == null then null else builtins.head m;

  requirements = {
    minCliVersion = getVar "minCliVersion";
    maxCliVersion = getVar "maxCliVersion";
    minNodeVersion = getVar "minNodeVersion";
    maxNodeVersion = getVar "maxNodeVersion";
    minHardwareCliVersion = getVar "minHardwareCliVersion";
    minCardanoSignerVersion = getVar "minCardanoSignerVersion";
    # Hardware wallet device-side requirements (not bundled; operator-managed)
    minLedgerCardanoAppVersion = getVar "minLedgerCardanoAppVersion";
    minTrezorCardanoAppVersion = getVar "minTrezorCardanoAppVersion";
    minKeystoneCardanoAppVersion = getVar "minKeystoneCardanoAppVersion";
  };

  requireAtLeast = tool: actual: min:
    lib.optional (min != null && !lib.versionAtLeast actual min)
      "${tool} ${actual} is older than the minimum ${min} required by spo-scripts ${tools.spo-scripts.version}";

  requireAtMost = tool: actual: max:
    lib.optional (max != null && !lib.versionAtLeast max actual)
      "${tool} ${actual} is newer than the maximum ${max} allowed by spo-scripts ${tools.spo-scripts.version}";

in {
  inherit requirements;

  failures =
    requireAtLeast "cardano-cli" tools.cardano-cli.version requirements.minCliVersion
    ++ requireAtMost "cardano-cli" tools.cardano-cli.version requirements.maxCliVersion
    ++ requireAtLeast "cardano-node" tools.cardano-node.version requirements.minNodeVersion
    ++ requireAtMost "cardano-node" tools.cardano-node.version requirements.maxNodeVersion
    # hw-cli artifacts may be pinned per platform, so validate every one
    ++ lib.concatMap
      (platform:
        requireAtLeast "cardano-hw-cli (${platform})"
          tools.cardano-hw-cli.platforms.${platform}.version
          requirements.minHardwareCliVersion)
      (builtins.attrNames tools.cardano-hw-cli.platforms)
    ++ requireAtLeast "cardano-signer" tools.cardano-signer.version requirements.minCardanoSignerVersion;
}
