# Packages Martin Lang's StakePool Operator Scripts and generates the
# common.inc configuration that wires them to the nix-provided binaries.
{ pkgs
, lib
, src # spo-scripts flake input (locked in flake.lock)
, cardano-node-pkgs
, cardano-cli-pkgs
, cardano-hw-cli
, cardano-signer
}:
let

  validators = import ../validators.nix {
    inherit lib;
  };

  # Cardano Configs
  # TODO: pass overrides for customization
  cardano-cfg = import ./cardano-configs.nix {
    inherit pkgs;
  };

  # Executables configuration; the attribute names match the variables
  # expected by 00_common.sh.
  exes = {
    cardanonode = cardano-node-pkgs.cardano-node;
    bech32_bin = cardano-node-pkgs.bech32;
    cardanocli = cardano-cli-pkgs.cardano-cli;
    cardanohwcli = cardano-hw-cli;
    cardanosigner = cardano-signer;
  };

  buildInputs = [
    pkgs.jq
    pkgs.curl
    pkgs.bc
    pkgs.xxd
  ];

  # The upstream repo keeps mainnet and testnet script variants in
  # separate directories.
  getCommonNetwork = network:
    if validators.network.isMainnet network then "mainnet" else "testnet";

  mkScripts = { overrides ? {} }:
    let commonNetwork = getCommonNetwork (overrides.network or "Mainnet");
    in pkgs.stdenvNoCC.mkDerivation {
      name = "spo-scripts-${commonNetwork}";
      inherit src;

      networkPath = "cardano/${commonNetwork}";

      installPhase = ''
        runHook preInstall
        mkdir -p $out/bin
        cp $networkPath/* $out/bin/
        chmod +x $out/bin/*
        runHook postInstall
      '';

      meta = {
        description = "StakePool Operator Scripts (${commonNetwork} variant)";
        homepage = "https://github.com/gitmachtl/scripts";
        license = lib.licenses.gpl3Only;
        platforms = lib.platforms.unix;
      };
    };

  # Default params (can be overridden)
  defaultParams = { network ? "Mainnet" }:
    let
      normalizedNetwork = validators.network.normalize network;
      networkConfigs = cardano-cfg.configs.${normalizedNetwork}
        or (throw "spo-scripts: no bundled genesis configs for network '${network}'");
    in
    {
      inherit network;
      workMode = "light";
      genesisfile = networkConfigs.shelley.genesisFile;
      genesisfile_byron = networkConfigs.byron.genesisFile;
    } // lib.mapAttrs (name: pkg: lib.getExe pkg) exes;

  # Merge user param overrides with defaults (overrides take precedence)
  mkParams = { overrides ? {} }:
    defaultParams { network = overrides.network or "Mainnet"; } // overrides;

  # Configuration file generator
  mkCommonInc = { overrides ? {} }:
    let cfg = mkParams { inherit overrides; };
    in pkgs.writeText "common.inc" (
      lib.concatStringsSep "\n" (
        lib.mapAttrsToList (name: value: ''${name}="${toString value}"'') cfg
      )
    );

in {
  mkCommon = { overrides ? {} }: {
    derivation = mkScripts { inherit overrides; };
    commonInc = mkCommonInc { inherit overrides; };
  };

  # Provides a common set of buildInputs to run the scripts
  buildInputs = buildInputs ++ builtins.attrValues exes;
}
