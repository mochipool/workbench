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
, spoScripts # tools/spo-scripts.nix: for the per-network genesis paths (mkParams)
}:
let
  version = "0.1.0";

  orEmpty = v: if v == null then "" else v;

  # Bundled genesis files per network, derived as tools/workbench.nix derives
  # them for the upstream scripts, so both sides use the same files.
  networks = lib.mapAttrs
    (_: network:
      let params = spoScripts.mkParams { overrides = { inherit network; }; }; in {
        shelleyGenesis = toString params.genesisfile;
        byronGenesis = toString params.genesisfile_byron;
      })
    { mainnet = "Mainnet"; preprod = "PreProd"; preview = "Preview"; };

  toolchain = pkgs.writeText "spo-toolchain.json" (builtins.toJSON {
    release = versions.tools.spo-scripts.version;
    inherit networks;
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
      # FIDO2 factors for unlocking a workspace (ADR 0011, decision 8): the
      # libfido2 command-line tools, driven by adapters/fido2cli. The version
      # is gated on fido2-token (`-V`); the three tools come from one package.
      fido2-token = {
        path = "${pkgs.libfido2}/bin/fido2-token";
        version = pkgs.libfido2.version;
      };
      fido2-cred.path = "${pkgs.libfido2}/bin/fido2-cred";
      fido2-assert.path = "${pkgs.libfido2}/bin/fido2-assert";
    };
  });

  unwrapped = buildGoModule {
    pname = "spo-unwrapped";
    inherit version;
    src = lib.cleanSource ../spo;
    vendorHash = "sha256-PsMNy89IZaot0kUXmL3PASHiR5RG1iaewM23uMSzX6Q=";
    env.CGO_ENABLED = 0;
    # `spo` opens workspaces. The block producer's start-up helper `spo-node-keys`
    # (ADR 0011 decision 2), the only plaintext writer of a signing key, is its own
    # package (`nodeKeys` below), so a producer host installs it without `spo`.
    # The checks below prove from the import graphs that `spo` holds no plaintext
    # writer and that the helper holds no way to open a workspace.
    subPackages = [ "cmd/spo" ];
    ldflags = [ "-s" "-w" "-X main.version=${version}" ];
    # subPackages limits the build; the tests cover the whole module.
    checkPhase = ''
      runHook preCheck
      export HOME=$TMPDIR
      go vet ./...
      go test ./...
      # The tests above run without the plainlayout tag. The tagged build is
      # not a release: it wires the test-only plain store (ADR 0011 (proposed),
      # SPO-Xcustody-INV-001), so it is vetted and the architecture test checks
      # its import graph too.
      go vet -tags plainlayout ./...
      go test -count=1 -tags plainlayout ./internal/archtest/ ./test/plainstore/
      go test -count=1 -tags plainlayout -run TestPlainLayoutTagWiresTheStore ./cmd/spo/
      # The release binary must be unable to write a signing key or any other
      # secret unencrypted: the writable plain store is not in its dependency
      # set (the release is built with no tags).
      go list -deps ./cmd/spo > release-deps.txt
      go list -deps -tags plainlayout ./cmd/spo > tagged-deps.txt
      if grep -e '/test/plainstore' -e '/spo/test/' release-deps.txt; then
        echo "the release build contains the test-only plain store"
        exit 1
      fi
      # The node-delivery exception: the workspace-opening binary holds no
      # plaintext writer, and the start-up helper holds no way to open a
      # workspace (no sealed store, no slot or key-wrapping code, no factor
      # source). A package that is not in the build cannot be linked.
      go list -deps ./cmd/spo-node-keys > helper-deps.txt
      if grep -e '/internal/adapters/nodefiles' release-deps.txt tagged-deps.txt; then
        echo "the workspace-opening binary contains the plaintext writer of the start-up helper"
        exit 1
      fi
      if grep -e '/internal/adapters/sqlitestore' -e '/internal/platform/seal' -e '/internal/adapters/fido2cli' -e '/internal/adapters/cli' -e '/internal/adapters/partystore' -e 'modernc.org/sqlite' helper-deps.txt || grep -x 'github.com/mochipool/workbench/spo/internal/adapters/native' helper-deps.txt; then
        echo "the start-up helper contains code that opens a workspace"
        exit 1
      fi
      grep -q '/internal/adapters/nodefiles' helper-deps.txt \
        || { echo "the start-up helper no longer contains its writer: the checks above prove nothing"; exit 1; }
      rm helper-deps.txt
      grep -q '/internal/adapters/upstreamdir' release-deps.txt \
        || { echo "the release build lacks the read-only upstream reader"; exit 1; }
      grep -q '/test/plainstore' tagged-deps.txt \
        || { echo "the plainlayout tag no longer brings the plain store in: the check above proves nothing"; exit 1; }
      rm release-deps.txt tagged-deps.txt
      runHook postCheck
    '';
    # The installed release binary has no way to write a secret in clear: no
    # --upstream-layout, no key protect/unprotect, no --plaintext. The help
    # of the commands that had them is searched for the words.
    doInstallCheck = true;
    installCheckPhase = ''
      runHook preInstallCheck
      export HOME=$TMPDIR
      spo=$out/bin/spo
      refuse() { # the words that must not be in a help text
        if "$spo" "$@" --help 2>&1 | grep -w -e '--upstream-layout' -e '--plaintext' -e 'unprotect'; then
          echo "spo $* --help names a plaintext writer"
          exit 1
        fi
      }
      refuse
      refuse workspace
      refuse workspace export
      refuse workspace import
      refuse node export
      refuse key
      "$spo" key --help 2>&1 | grep -q 'convert' || { echo "spo key convert is missing"; exit 1; }
      "$spo" node --help 2>&1 | grep -q 'export' || { echo "spo node export is missing"; exit 1; }
      if "$spo" --upstream-layout version >/dev/null 2>&1; then
        echo "the release binary accepts --upstream-layout"
        exit 1
      fi
      # (`spo key unprotect x` only prints the help of `key`, as any group does
      # with an unknown word; the help above has no such command.)
      if "$spo" key --help 2>&1 | grep -w -e 'protect' -e 'unprotect'; then
        echo "the release binary has key protect or unprotect"
        exit 1
      fi
      if "$spo" workspace export "$TMPDIR/x" --plaintext >/dev/null 2>&1; then
        echo "the release binary has workspace export --plaintext"
        exit 1
      fi
      runHook postInstallCheck
    '';
    meta = {
      description = "Stake pool operations from one binary (unwrapped; no toolchain manifest)";
      license = lib.licenses.gpl3Only;
      mainProgram = "spo";
    };
  };

  # The start-up helper alone: no `spo`, no toolchain manifest, no external tool.
  nodeKeys = buildGoModule {
    pname = "spo-node-keys";
    inherit version;
    src = lib.cleanSource ../spo;
    vendorHash = "sha256-PsMNy89IZaot0kUXmL3PASHiR5RG1iaewM23uMSzX6Q=";
    env.CGO_ENABLED = 0;
    subPackages = [ "cmd/spo-node-keys" ];
    ldflags = [ "-s" "-w" ];
    doCheck = false; # `unwrapped` runs every test of the module
    doInstallCheck = true;
    installCheckPhase = ''
      runHook preInstallCheck
      [ -x "$out/bin/spo-node-keys" ] || { echo "spo-node-keys is not installed"; exit 1; }
      [ ! -e "$out/bin/spo" ] || { echo "the helper package holds spo"; exit 1; }
      helper_usage=$("$out/bin/spo-node-keys" 2>&1 || true)
      echo "$helper_usage" | grep -q 'usage: spo-node-keys deliver' || { echo "spo-node-keys has no usage text"; exit 1; }
      if "$out/bin/spo-node-keys" --version >/dev/null 2>&1; then
        echo "spo-node-keys accepted an unknown command"
        exit 1
      fi
      runHook postInstallCheck
    '';
    meta = {
      description = "Block producer start-up helper: decrypts a spo node export into a ramfs directory";
      license = lib.licenses.gpl3Only;
      mainProgram = "spo-node-keys";
    };
  };

  # Differential tests against the pinned upstream scripts (concern C4). They
  # need the whole Cardano toolchain, so they are a separate check from the
  # unit tests.
  parity = unwrapped.overrideAttrs (old: {
    pname = "spo-parity";
    # This one is a test run, not the release binary: it is built with the
    # plainlayout tag, and the release checks of unwrapped do not apply.
    tags = [ "plainlayout" ];
    doInstallCheck = false;
    # A build with the plainlayout tag writes secrets in clear, so its output
    # must not be a usable program: the install phase writes a log and a marker
    # and no binary (SPO-Xcustody-INV-001). `taggedNoBinary` below checks it.
    installPhase = ''
      runHook preInstall
      mkdir -p $out
      if [ -f parity.log ]; then cp parity.log $out/parity.log; fi
      echo "spo-parity: the tests passed; this build has the plainlayout tag and installs no binary" > $out/PASSED
      runHook postInstall
    '';
    # Some upstream scripts read their confirmation from the controlling
    # terminal; the tests drive those through script(1).
    nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ pkgs.util-linux pkgs.jq pkgs.openssl ];
    checkPhase = ''
      runHook preCheck
      export HOME=$TMPDIR
      export SPO_TOOLCHAIN=${toolchain}
      export SPO_PARITY_WORKBENCH=${workbench}/bin/workbench
      # The preview Shelley genesis of the release set: the same file the
      # workbench manifest gives the upstream scripts, so both sides of the
      # opcert parity test use one genesis.
      export SPO_PARITY_SHELLEY_GENESIS_PREVIEW=$(${pkgs.jq}/bin/jq -r .networks.preview.common.genesisfile ${workbench.toolchain})
      go test -count=1 -timeout 30m -tags plainlayout -v ./test/parity/ | tee parity.log
      # The gpg paths of the binary (export, import with a password, key
      # convert) need the toolchain manifest set above.
      go test -count=1 -timeout 10m -tags plainlayout -run 'TestEncryptedKeysThroughGPG' ./cmd/spo/
      # cardano-signer is a prebuilt binary that cannot run in the sandbox
      # (tools/cardano-signer.nix), so the tests that need it skip here and
      # run in the development loop. Any other skip fails the check.
      skips=$(grep -c -- "--- SKIP" parity.log || true)
      # Besides the signer, two tests need the network on purpose (they ask
      # or record the live Koios service) and are opt-in.
      allowed=$(grep -c -e "cardano-signer cannot run here" -e "set SPO_PARITY_NETWORK=1" -e "set SPO_PARITY_RECORD_AIRGAP" parity.log || true)
      if [ "$skips" != "$allowed" ]; then
        echo "a parity test was skipped; the check must run them all"
        exit 1
      fi
      runHook postCheck
    '';
  });

  # Every build variant of the binary defined in this file. A new variant is
  # added here; whether it carries the plainlayout tag is read from the
  # derivation's own `tags` attribute, not from a second list.
  variants = { inherit unwrapped parity; };
  isTagged = d: builtins.elem "plainlayout" (d.tags or [ ]);
  taggedDerivations = lib.filter isTagged (lib.attrValues variants);
  # Every output of every tagged derivation (a derivation may have several).
  taggedOutputs = lib.concatMap (d: map (o: d.${o}) (d.outputs or [ "out" ])) taggedDerivations;

  # No derivation built with the plainlayout tag may install anything that can
  # be run or that can point at something that can: any file with an execute
  # bit (for the owner, the group or others), any symbolic link, and a bin or
  # sbin directory fail the check. The release derivation may not carry the tag.
  taggedNoBinary =
    assert lib.assertMsg (taggedDerivations != [ ]) "no variant carries the plainlayout tag: the check below would prove nothing";
    assert lib.assertMsg (!(isTagged unwrapped)) "the release derivation carries the plainlayout tag";
    pkgs.runCommand "spo-tagged-no-binary" { } ''
      status=0
      for d in ${lib.concatStringsSep " " (map toString taggedOutputs)}; do
        if [ -e "$d/bin" ] || [ -e "$d/sbin" ]; then
          echo "$d is built with the plainlayout tag and has a bin or sbin directory"
          status=1
        fi
        found=$(find "$d" \( -type l -o -type f -perm /111 \) -print)
        if [ -n "$found" ]; then
          echo "$d is built with the plainlayout tag and holds an executable file or a symbolic link:"
          echo "$found"
          status=1
        fi
      done
      [ "$status" = 0 ] || exit 1
      echo ok > $out
    '';

  package = pkgs.runCommand "spo-${version}"
    {
      nativeBuildInputs = [ pkgs.makeWrapper ];
      passthru = { inherit toolchain unwrapped parity taggedNoBinary nodeKeys; tests = unwrapped; };
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
