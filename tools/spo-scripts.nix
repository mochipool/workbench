# spo-scripts.nix
{  pkgs
  ,lib
  , cardano-node-pkgs
  , cardano-cli-pkgs
  , cardano-hw-cli
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

  spo-scripts = builtins.fetchGit {
    url = "https://github.com/gitmachtl/scripts";
    rev = "4d3a03285e3eb856948cfcfd37c829ef572a4037";
  };

  # Executables configuration
  exes = {
    cardanonode = cardano-node-pkgs.cardano-node;
    bech32_bin = cardano-node-pkgs.bech32;
    cardanocli = cardano-cli-pkgs.cardano-cli;
    cardanohwcli = cardano-hw-cli.cli;
  };

  buildInputs = [
    pkgs.jq
    pkgs.curl
    pkgs.bc
    pkgs.xxd
  ];

  getCommonNetwork = network:
    if validators.network.isMainnet network then "mainnet" else "testnet";

  mkScripts = { overrides ? {} }:
    let commonNetwork = getCommonNetwork overrides.network or "Mainnet";
    in pkgs.stdenv.mkDerivation {
      name = "spo-scripts-${commonNetwork}";
      src = spo-scripts;

      networkPath = "cardano/${commonNetwork}";

      installPhase = ''
        mkdir -p $out/bin
        cp $networkPath/* $out/bin/
        chmod +x $out/bin/*
      '';
    };


  # Default params (can be overridden)
  defaultParams = { network ? "Mainnet" }:
    let
      inherit network;
      normalizedNetwork = validators.network.normalize network;
    in
    {
      network = network;
      workMode = "light";
      genesisfile = cardano-cfg.configs.${normalizedNetwork}.shelley.genesisFile;
      genesisfile_byron = cardano-cfg.configs.${normalizedNetwork}.byron.genesisFile;
    } // lib.mapAttrs (name: pkg: lib.getExe pkg) exes;

  # Merge user param overrides with defaults
  mkParams = { overrides ? {} }:
    let
      # Get network from overrides if it exists, otherwise use default
      effectiveNetwork = overrides.network or "Mainnet";
      # Create base params with the effective network
      baseParams = defaultParams { network = effectiveNetwork; };
      # Merge with overrides (overrides will take precedence)
      finalParams = baseParams // overrides;
    in
      finalParams;

  # Configuration file generator
  mkCommonInc = { overrides ? {} }:
    let cfg = mkParams { inherit overrides; };
    in pkgs.writeText "common.inc" (
      lib.concatStringsSep "\n" (
        lib.mapAttrsToList (name: value: ''${name}="${value}"'') cfg
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
