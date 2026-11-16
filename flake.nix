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
      url = "github:IntersectMBO/cardano-node?ref=11.1.3";
      flake = true;
    };
    # CLI is kept in its own repo and updates async from cardano-node
    cardano-cli = {
      url = "github:IntersectMBO/cardano-cli?ref=cardano-cli-11.2.3.0";
      flake = true;
    };
    # StakePool Operator Scripts (plain source tree, not a flake)
    spo-scripts = {
      url = "github:gitmachtl/scripts?ref=Update-2026-04";
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
            inherit (versions.tools.cardano-hw-cli) version platforms autocompleteHash;
          };

          # Cardano Signer (prebuilt release binaries)
          cardano-signer = import ./tools/cardano-signer.nix {
            inherit pkgs;
            inherit (versions.tools.cardano-signer) version hashes;
          };

          # Trezor CLI (firmware updates)
          trezorctl = import ./tools/trezorctl.nix {
            inherit pkgs;
            inherit (versions.tools.trezorctl) version hash;
          };

          # Hardware wallet health check
          doctor = import ./tools/doctor.nix {
            inherit pkgs;
            inherit (spoCompat) requirements;
            inherit (versions) tools;
            cardano-node = cardano-node-pkgs.cardano-node;
            cardano-cli = cardano-cli-pkgs.cardano-cli;
            cardano-hw-cli = cardano-hw-cli.cli;
            inherit cardano-signer;
          };

          # udev rules for Ledger/Trezor (Linux only)
          udevRules = lib.optionalAttrs pkgs.stdenv.isLinux {
            udev-rules = import ./tools/udev-rules.nix { inherit pkgs; };
          };

          # SPO Scripts
          spo = import ./tools/spo-scripts.nix {
            inherit pkgs lib cardano-node-pkgs cardano-cli-pkgs cardano-signer;
            src = spo-scripts;
            cardano-hw-cli = cardano-hw-cli.cli;
          };

          # Workflow orchestrator, bound to this release set's toolchain
          workbench = import ./tools/workbench.nix {
            inherit pkgs lib spo versions;
          };

          # Base system packages to include
          basePkgs = [
            cardano-node-pkgs.cardano-node
            cardano-node-pkgs.bech32
            cardano-cli-pkgs.cardano-cli
            cardano-hw-cli.cli
            cardano-signer
            trezorctl
            doctor
            workbench
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

                # Point ~/.common.inc at this network's settings, but never
                # clobber an operator's own file. (`workbench` does not use
                # it: it writes a workspace-local ./common.inc instead.)
                if [ ! -e ~/.common.inc ] || [[ "$(readlink ~/.common.inc)" == /nix/store/* ]]; then
                  ln -sfn ${spoConfig.commonInc} ~/.common.inc
                  # Remove it on exit only if it is still the link we made
                  # (another shell may have re-pointed it meanwhile).
                  trap '[ "$(readlink ~/.common.inc)" = "${spoConfig.commonInc}" ] && rm -f ~/.common.inc' EXIT
                  echo "Configured for ${network} network"
                else
                  echo "warning: ~/.common.inc is your own file; leaving it in place (scripts will use it)" >&2
                fi
              '';
            };
        in {
          inherit pkgs cardano-node-pkgs cardano-cli-pkgs
            cardano-hw-cli cardano-signer trezorctl doctor udevRules spo workbench mkNetworkShell;
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

      requirementsDoc = import ./tools/release-docs.nix {
        inherit lib versions;
        inherit (spoCompat) requirements;
      };

      beginMarker = "<!-- BEGIN generated:requirements -->";
      endMarker = "<!-- END generated:requirements -->";

      # Prints the block currently embedded in a readme (between the markers).
      extractBlock = pkgs: pkgs.writeShellScript "extract-block" ''
        ${pkgs.gawk}/bin/awk '
          $0 == "${endMarker}" { on = 0 }
          on { print }
          $0 == "${beginMarker}" { on = 1 }
        ' "$1"
      '';

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
          trezorctl = wb.trezorctl;
          doctor = wb.doctor;
          workbench = wb.workbench;
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
              trezorctl
              doctor
              workbench
              spo-scripts-mainnet
            ];
          };
        } // wb.udevRules);

      # Lightweight checks: these deliberately avoid depending on the haskell
      # toolchain so they stay cheap on every system (including aarch64-linux,
      # where upstream provides no native binary cache for cardano-cli).
      checks = forAllSystems (system:
        let wb = workbench.${system};
        in {
          version-manifest = mkAssertion wb.pkgs "version-manifest" manifestFailures;
          spo-compat = mkAssertion wb.pkgs "spo-compat" spoCompat.failures;
          # Orchestrator unit tests against stand-in scripts (no haskell toolchain).
          workbench-tests = wb.workbench.tests;
          # The readme's generated requirements section must match the nix data.
          readme-sync = wb.pkgs.runCommand "readme-sync" { } ''
            ${extractBlock wb.pkgs} ${self}/readme.md > actual
            cat > expected <<'EOF_DOC'
            ${requirementsDoc}
            EOF_DOC
            if ! diff -u actual expected; then
              echo "readme.md requirements section is stale; run: nix run .#update-readme"
              exit 1
            fi
            echo ok > $out
          '';
        });

      # Rewrites the generated requirements section of ./readme.md in place.
      apps = forAllSystems (system:
        let pkgs = workbench.${system}.pkgs;
        in {
          doctor = {
            type = "app";
            program = "${workbench.${system}.doctor}/bin/workbench-doctor";
          };
          workbench = {
            type = "app";
            program = "${workbench.${system}.workbench}/bin/workbench";
          };
        } // lib.optionalAttrs pkgs.stdenv.isLinux {
          # Prints (or with --install, installs) the Ledger/Trezor udev rules.
          install-udev-rules = {
            type = "app";
            program = toString (pkgs.writeShellScript "install-udev-rules" ''
              set -eu
              rules=${workbench.${system}.udevRules.udev-rules}/lib/udev/rules.d/70-cardano-spo-workbench.rules
              dest=/etc/udev/rules.d/70-cardano-spo-workbench.rules
              if [ -e /etc/NIXOS ]; then
                echo "NixOS detected: /etc is managed declaratively. Add to your configuration:"
                echo "  services.udev.packages = [ <this flake>.packages.${system}.udev-rules ];"
                echo "(or, for Ledger only: hardware.ledger.enable = true;)"
                exit 0
              fi
              if [ "''${1:-}" = "--install" ]; then
                sudo install -Dm644 "$rules" "$dest"
                sudo udevadm control --reload-rules
                sudo udevadm trigger
                echo "Installed $dest. Unplug and replug your device."
              else
                echo "Rules file: $rules"
                echo
                echo "Install it with this command, or re-run with --install:"
                echo "  sudo install -Dm644 $rules $dest && sudo udevadm control --reload-rules && sudo udevadm trigger"
              fi
            '');
          };
          update-readme = {
            type = "app";
            program = toString (pkgs.writeShellScript "update-readme" ''
              set -eu
              readme="''${1:-readme.md}"
              doc=${pkgs.writeText "requirements.md" requirementsDoc}
              tmp="$(mktemp)"
              ${pkgs.gawk}/bin/awk -v doc="$doc" '
                $0 == "${endMarker}" { skip = 0 }
                !skip { print }
                $0 == "${beginMarker}" {
                  skip = 1
                  while ((getline line < doc) > 0) print line
                }
              ' "$readme" > "$tmp"
              cat "$tmp" > "$readme"
              rm -f "$tmp"
              echo "updated $readme"
            '');
          };
        });

      formatter = forAllSystems (system: workbench.${system}.pkgs.nixfmt-rfc-style);
    };
}
