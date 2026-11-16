# `workbench`: the workflow orchestrator (orchestrator/), wrapped with the
# toolchain manifest of this release set.
#
# The manifest maps each network to its SPO scripts variant and common.inc
# settings, so a `workbench` binary always drives exactly the binaries it was
# built with. The unit tests are a separate derivation (`tests`) that does not
# reference the Cardano toolchain, so `nix flake check` stays cheap on systems
# without an upstream binary cache for cardano-cli.
{ pkgs
, lib
, spo # tools/spo-scripts.nix
, versions
}:
let
  python = pkgs.python3;
  src = lib.cleanSource ../orchestrator;

  networks = {
    mainnet = "Mainnet";
    preprod = "PreProd";
    preview = "Preview";
  };

  toolchain = pkgs.writeText "workbench-toolchain.json" (builtins.toJSON {
    release = lib.mapAttrs (_: t: t.version) versions.tools;
    networks = lib.mapAttrs (_: network: {
      scriptsDir = "${(spo.mkCommon { overrides = { inherit network; }; }).derivation}/bin";
      common = lib.mapAttrs (_: toString) (spo.mkParams { overrides = { inherit network; }; });
    }) networks;
  });

  runtimeDeps = spo.buildInputs ++ [ pkgs.coreutils pkgs.gnugrep pkgs.gnused pkgs.gawk ];

  package = python.pkgs.buildPythonApplication {
    pname = "spo-workbench";
    version = "0.1.0";
    pyproject = true;
    inherit src;
    build-system = [ python.pkgs.setuptools ];
    # Tests run in the separate `tests` derivation.
    doCheck = false;
    makeWrapperArgs = [
      "--set-default SPO_WB_TOOLCHAIN ${toolchain}"
      "--prefix PATH : ${lib.makeBinPath runtimeDeps}"
    ];
    passthru = { inherit toolchain tests; };
    meta = {
      description = "Resumable, validated workflows over the Cardano SPO scripts";
      license = lib.licenses.gpl3Only;
      mainProgram = "workbench";
      platforms = lib.platforms.unix;
    };
  };

  tests = pkgs.runCommand "workbench-tests"
    {
      nativeBuildInputs = [ (python.withPackages (p: [ p.pytest ])) ];
    } ''
    cp -r ${src} src && chmod -R u+w src && cd src
    PYTHONPATH=$PWD/src python -m pytest -q -p no:cacheprovider -m "not e2e" tests
    touch $out
  '';
in
package
