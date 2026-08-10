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
    # Determinate Nix enables lazy-trees by default, which breaks
    # import-from-derivation in haskell.nix (sources fail to materialize with
    # "path ... does not exist and cannot be created").
    lazy-trees = false;
  };

  # NOTE: input refs must stay in lockstep with versions.nix (the release-set
  # manifest); checks.<system>.version-manifest enforces this.
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    cardano-node = {
      url = "github:IntersectMBO/cardano-node?ref=11.0.1";
      flake = true;
    };
    # CLI is kept in its own repo and updates async from cardano-node
    cardano-cli = {
      url = "github:IntersectMBO/cardano-cli?ref=cardano-cli-11.0.0.0";
      flake = true;
    };
    # StakePool Operator Scripts (plain source tree, not a flake)
    spo-scripts = {
      url = "github:gitmachtl/scripts?ref=Update-2026-03";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, cardano-node, cardano-cli, spo-scripts, ... }@inputs:
    let
      inherit (nixpkgs) lib;

      versions = import ./versions.nix;
      forAllSystems = lib.genAttrs versions.supportedSystems;

      # Assemble the full toolset for one system.
      workbenchFor = system:
        let
          pkgs = import nixpkgs { inherit system; };

          # Cardano Packages
          cardano-node-pkgs = cardano-node.packages.${system};
          cardano-cli-pkgs = cardano-cli.legacyPackages.${system};

          # Cardano HW CLI (prebuilt release binaries)
          cardano-hw-cli = import ./tools/cardano-hw-cli.nix {
            inherit pkgs;
            inherit (versions.tools.cardano-hw-cli) version hashes autocompleteHash;
          };

          # Cardano Signer (prebuilt release binaries)
          cardano-signer = import ./tools/cardano-signer.nix {
            inherit pkgs;
            inherit (versions.tools.cardano-signer) version hashes;
          };

          # SPO Scripts
          spo = import ./tools/spo-scripts.nix {
            inherit pkgs lib cardano-node-pkgs cardano-cli-pkgs cardano-signer;
            src = spo-scripts;
            cardano-hw-cli = cardano-hw-cli.cli;
          };

          # Base system packages to include
          basePkgs = [
            cardano-node-pkgs.cardano-node
            cardano-node-pkgs.bech32
            cardano-cli-pkgs.cardano-cli
            cardano-hw-cli.cli
            cardano-signer
          ];

          # Shell generator function
          mkNetworkShell = network:
            let
              spoConfig = spo.mkCommon {
                overrides = {
                  inherit network;
                  workMode = "light";
                };
              };
            in pkgs.mkShell {
              name = "workspace-${network}";

              buildInputs = basePkgs ++ spo.buildInputs ++ [
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
        in {
          inherit pkgs cardano-node-pkgs cardano-cli-pkgs
            cardano-hw-cli cardano-signer spo mkNetworkShell;
        };

      workbench = forAllSystems workbenchFor;

      # Fail a check with a readable message list instead of an eval-time throw
      # (keeps `nix flake show` working while `nix flake check` still fails).
      mkAssertion = pkgs: name: failures:
        pkgs.runCommand name { } (
          if failures == [ ] then "echo ok > $out"
          else ''
            echo "${name} failed:"
            ${lib.concatMapStrings (f: "echo \"  - ${f}\"\n") failures}
            exit 1
          ''
        );

      # Drift detection between flake.lock and versions.nix.
      manifestFailures = lib.concatLists (map
        (name:
          let
            declared = versions.tools.${name}.rev;
            locked = inputs.${name}.rev or "unknown";
          in lib.optional (declared != locked)
            "flake input ${name} is locked to ${locked} but versions.nix declares ${declared}")
        [ "cardano-node" "cardano-cli" "spo-scripts" ]);

      # SPO scripts' own runtime version requirements, checked at eval time.
      spoCompat = import ./tools/spo-compat.nix {
        inherit lib;
        src = spo-scripts;
        inherit (versions) tools;
      };

    in
    {
      devShells = forAllSystems (system:
        let wb = workbench.${system};
        in {
          default = self.devShells.${system}.mainnet;
          mainnet = wb.mkNetworkShell "Mainnet";
          preprod = wb.mkNetworkShell "PreProd";
          preview = wb.mkNetworkShell "Preview";
        });

      packages = forAllSystems (system:
        let wb = workbench.${system};
        in rec {
          cardano-hw-cli = wb.cardano-hw-cli.cli;
          cardano-signer = wb.cardano-signer;
          spo-scripts-mainnet = (wb.spo.mkCommon { overrides.network = "Mainnet"; }).derivation;
          spo-scripts-testnet = (wb.spo.mkCommon { overrides.network = "PreProd"; }).derivation;
          # Re-exports for convenience (built by upstream flakes / IOG cache)
          inherit (wb.cardano-node-pkgs) cardano-node bech32;
          inherit (wb.cardano-cli-pkgs) cardano-cli;
          # Everything bundled into one profile-installable environment
          default = wb.pkgs.buildEnv {
            name = "spo-workbench-tools";
            paths = [
              cardano-node
              bech32
              cardano-cli
              cardano-hw-cli
              cardano-signer
              spo-scripts-mainnet
            ];
          };
        });

      # Lightweight checks: these deliberately avoid depending on the haskell
      # toolchain so they stay cheap on every system (including aarch64-linux,
      # where upstream provides no native binary cache for cardano-cli).
      checks = forAllSystems (system:
        let wb = workbench.${system};
        in {
          version-manifest = mkAssertion wb.pkgs "version-manifest" manifestFailures;
          spo-compat = mkAssertion wb.pkgs "spo-compat" spoCompat.failures;
        });

      formatter = forAllSystems (system: workbench.${system}.pkgs.nixfmt-rfc-style);
    };
}
