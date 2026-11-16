# `spo`: the Go reference implementation (spo/), wrapped with the toolchain
# manifest of this release set.
#
# The manifest gives the binary the absolute store path, pinned version and
# upstream version bounds of every external tool, so `spo` drives exactly the
# tools it was built with and refuses anything else (concern X1). The Go tests
# run in the unwrapped derivation, which does not reference the Cardano
# toolchain, so `nix flake check` stays cheap on systems without an upstream
# binary cache for cardano-cli.
{ pkgs
, lib
, buildGoModule # from a nixpkgs that carries the Go version spo/go.mod needs
, versions
, requirements # tools/spo-compat.nix: bounds parsed from upstream 00_common.sh
, cardano-cli
, cardano-node
, bech32
, cardano-hw-cli
, cardano-signer
, workbench # tools/workbench.nix: the parity tests' oracle (ADR 0001)
}:
let
  version = "0.1.0";

  orEmpty = v: if v == null then "" else v;

  toolchain = pkgs.writeText "spo-toolchain.json" (builtins.toJSON {
    release = versions.tools.spo-scripts.version;
    tools = {
      cardano-cli = {
        path = "${cardano-cli}/bin/cardano-cli";
        version = versions.tools.cardano-cli.version;
        min = orEmpty requirements.minCliVersion;
        max = orEmpty requirements.maxCliVersion;
      };
      cardano-node = {
        path = "${cardano-node}/bin/cardano-node";
        version = versions.tools.cardano-node.version;
        min = orEmpty requirements.minNodeVersion;
        max = orEmpty requirements.maxNodeVersion;
      };
      cardano-hw-cli = {
        path = "${cardano-hw-cli}/bin/cardano-hw-cli";
        # Pinned per platform (see versions.nix), so take the built artifact's.
        version = cardano-hw-cli.version;
        min = orEmpty requirements.minHardwareCliVersion;
      };
      cardano-signer = {
        path = "${cardano-signer}/bin/cardano-signer";
        version = versions.tools.cardano-signer.version;
        min = orEmpty requirements.minCardanoSignerVersion;
      };
      bech32.path = "${bech32}/bin/bech32";
      # Only for importing and exporting upstream `enc` keys (concern X5).
      gpg.path = "${pkgs.gnupg}/bin/gpg";
    };
  });

  unwrapped = buildGoModule {
    pname = "spo-unwrapped";
    inherit version;
    src = lib.cleanSource ../spo;
    vendorHash = "sha256-xJjJYo1XjvhGCCLPFXSZRxxORVKp1rJpIEaeHPMVw7U=";
    env.CGO_ENABLED = 0;
    subPackages = [ "cmd/spo" ];
    ldflags = [ "-s" "-w" "-X main.version=${version}" ];
    # subPackages limits the build; the tests cover the whole module.
    checkPhase = ''
      runHook preCheck
      export HOME=$TMPDIR
      go vet ./...
      go test ./...
      runHook postCheck
    '';
    meta = {
      description = "Stake pool operations from one binary (unwrapped; no toolchain manifest)";
      license = lib.licenses.gpl3Only;
      mainProgram = "spo";
    };
  };

  # Differential tests against the pinned upstream scripts (concern C4). They
  # need the whole Cardano toolchain, so they are a separate check from the
  # unit tests.
  parity = unwrapped.overrideAttrs (old: {
    pname = "spo-parity";
    checkPhase = ''
      runHook preCheck
      export HOME=$TMPDIR
      export SPO_TOOLCHAIN=${toolchain}
      export SPO_PARITY_WORKBENCH=${workbench}/bin/workbench
      # The preview Shelley genesis of the release set: the same file the
      # workbench manifest gives the upstream scripts, so both sides of the
      # opcert parity test use one genesis.
      export SPO_PARITY_SHELLEY_GENESIS_PREVIEW=$(${pkgs.jq}/bin/jq -r .networks.preview.common.genesisfile ${workbench.toolchain})
      go test -count=1 -v ./test/parity/ | tee parity.log
      if grep -q -- "--- SKIP" parity.log; then
        echo "a parity test was skipped; the check must run them all"
        exit 1
      fi
      runHook postCheck
    '';
  });

  package = pkgs.runCommand "spo-${version}"
    {
      nativeBuildInputs = [ pkgs.makeWrapper ];
      passthru = { inherit toolchain unwrapped parity; tests = unwrapped; };
      meta = unwrapped.meta // {
        description = "Stake pool operations from one binary, with sealed keys and multi-party signing";
        platforms = lib.platforms.unix;
      };
    } ''
    mkdir -p $out/bin
    makeWrapper ${unwrapped}/bin/spo $out/bin/spo --set-default SPO_TOOLCHAIN ${toolchain}
  '';
in
package
