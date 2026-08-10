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

  # Extract `name="value"` shell assignments (first match wins).
  getVar = name:
    let
      prefix = "${name}=\"";
      matching = builtins.filter (l: lib.hasPrefix prefix l) lines;
    in
      if matching == [ ] then null
      else builtins.head (lib.splitString "\"" (lib.removePrefix prefix (builtins.head matching)));

  requirements = {
    minCliVersion = getVar "minCliVersion";
    maxCliVersion = getVar "maxCliVersion";
    minNodeVersion = getVar "minNodeVersion";
    maxNodeVersion = getVar "maxNodeVersion";
    minHardwareCliVersion = getVar "minHardwareCliVersion";
    minCardanoSignerVersion = getVar "minCardanoSignerVersion";
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
    ++ requireAtLeast "cardano-hw-cli" tools.cardano-hw-cli.version requirements.minHardwareCliVersion
    ++ requireAtLeast "cardano-signer" tools.cardano-signer.version requirements.minCardanoSignerVersion;
}
