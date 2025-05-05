{
  description = "Cardano SPO Tools";

  # This uses IOG cache to avoid rebuilding all artifacts
  # see: https://github.com/input-output-hk/iogx/blob/main/doc/api.md#flakenixnixconfig
  nixConfig = {
    extra-substituters = [
      "https://cache.iog.io"
    ];
    extra-trusted-public-keys = [
      "hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ="
    ];
    allow-import-from-derivation = true;
  };

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    cardano-node = {
      url = "github:IntersectMBO/cardano-node?ref=master";
      flake = true;
    };
    spo-scripts = {
      url = "github:gitmachtl/scripts";
      flake = false;
    };
  };
  outputs = { self, nixpkgs, cardano-node, spo-scripts, ... } @ inputs:
    let
      system = "x86_64-linux"; # Change if needed for your system

      # Import nixpkgs with our overlay
      pkgs = import nixpkgs {
        inherit system;
      };

      # Cardano Packages
      cardano-pkgs = import cardano-node {
        inherit system;
      };

      spoScriptsCfg = rec {
        # Define all required packages here. These will be added to the PATH.
        exes = {
          cardanonode = cardano-pkgs.cardano-node;
          cardanocli = cardano-pkgs.cardano-cli;
          bech32_bin = cardano-pkgs.bech32;
          # TODO: cardano-signer = CHANGE_ME
          # TODO: cardano-hw-cli = CHANGE_ME
        };
        
        # Define all other parameters here.
        # see: https://github.com/gitmachtl/scripts/blob/master/cardano/mainnet/00_common.sh
        cfg = {
          workMode = "online";
        } // pkgs.lib.mapAttrs (name: pkg: pkgs.lib.getExe pkg) exes;

        # Automatically generate quoted key="value" lines
        # This fill wil be linked to ~/.common.inc and removed on exit of dev shell
        commonInc = pkgs.writeText "common.inc" (
          pkgs.lib.concatStringsSep "\n" (
            pkgs.lib.mapAttrsToList (name: value: ''${name}="${value}"'') cfg
          )
        );
      };

    in
    {
      devShells.${system}.default = pkgs.mkShell {
        name = "cardano-spo-workspace";
        
        buildInputs = builtins.attrValues spoScriptsCfg.exes;
        
        shellHook = ''
          export PATH=$PATH:${spo-scripts}/cardano/mainnet
          echo "Using cardano-node from branch: ${inputs.cardano-node.rev or "unknown"}"
          echo "gitmachtl scripts from cardano/mainnet added to PATH"

          # Create temp dir and symlink
          export COMMON_INC_TMPDIR=$(mktemp -d)
          ln -sf ${spoScriptsCfg.commonInc} "$COMMON_INC_TMPDIR/.common.inc"
          ln -sf "$COMMON_INC_TMPDIR/.common.inc" ~/.common.inc
          echo "Linked config to ~/.common.inc"

          # Cleanup on exit
          cleanup() {
            rm -f ~/.common.inc
            rm -rf "$COMMON_INC_TMPDIR"
          }
          trap cleanup EXIT
        '';
      };
    };
}
