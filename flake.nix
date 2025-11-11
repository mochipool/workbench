{
  description = "Cardano SPO Workbench";

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
      url = "github:IntersectMBO/cardano-node?ref=10.5.1";
      flake = true;
    };
    # CLI is kept in its own repo and updates async from cardano-node
    cardano-cli = {
      url = "github:IntersectMBO/cardano-cli?ref=cardano-cli-10.12.0.0";
      flake = true;
    };
  };
  outputs = { self, nixpkgs, cardano-node, cardano-cli, ... }:
    let
      system = "x86_64-linux"; # Change if needed for your system

      # Import nixpkgs with our overlay
      pkgs = import nixpkgs {
        inherit system;
      };

      # Cardano Packages
      cardano-node-pkgs = cardano-node.packages.${system};
      cardano-cli-pkgs = cardano-cli.legacyPackages.${system};

      # Cardano HW CLI
      cardano-hw-cli = import ./tools/cardano-hw-cli.nix {
          inherit pkgs system;
          # inherit (pkgs) pkgs lib stdenv fetchurl autoPatchelfHook;
          version = "1.18.2";
      };

      # SPO Scripts
      spo-scripts = import ./tools/spo-scripts.nix {
        inherit (pkgs) pkgs lib;
        inherit cardano-node-pkgs cardano-cli-pkgs cardano-hw-cli;
      };

      # Base system packages to include
      basePkgs = [
        cardano-node-pkgs.cardano-node
        cardano-node-pkgs.bech32
        cardano-cli-pkgs.cardano-cli
        cardano-hw-cli.cli
      ];

      # Shell generator function
       mkNetworkShell = network:
          let
            spoConfig = spo-scripts.mkCommon {
              overrides = {
                inherit network;
                workMode = "light";
              };
            };
          in pkgs.mkShell {
            name = "workspace-${network}";

            buildInputs = basePkgs ++ spo-scripts.buildInputs ++ [
              spoConfig.derivation
            ];

            shellHook = ''
              # autocomplete for cardano-hw-cli
              source ${cardano-hw-cli.autocomplete}/share/cardano-hw-cli/autocomplete.sh

              # Set up common.inc
              ln -sf ${spoConfig.commonInc} ~/.common.inc
              # Clean up on exit
              trap "rm -f ~/.common.inc" EXIT 0
              echo "Configured for ${network} network"
            '';
          };

    in
    {
      devShells.${system} = {
        default = self.devShells.${system}.mainnet;
        mainnet = mkNetworkShell "Mainnet";
        preprod = mkNetworkShell "PreProd";
        preview = mkNetworkShell "Preview";
        # sancho = mkNetworkShell "Sancho";
      };

    };
}
