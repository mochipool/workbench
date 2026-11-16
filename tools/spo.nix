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
    vendorHash = "sha256-L3GVdLHm53ZsghDjAub+Z2Ch889pHQBYmUc/3ZQ67bk=";
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

  package = pkgs.runCommand "spo-${version}"
    {
      nativeBuildInputs = [ pkgs.makeWrapper ];
      passthru = { inherit toolchain unwrapped; tests = unwrapped; };
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
