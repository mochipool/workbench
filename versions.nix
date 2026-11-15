# versions.nix — single source of truth for the workbench release set.
#
# Every tool version listed here has been verified compatible with the others:
#
#   cardano-node 11.1.3 ships cardano-cli 11.2.3.0 (release-notes dependency table)
#   spo-scripts Update-2026-04 enforces: cli >= 11.0.0, node >= 11.0.0,
#     cardano-hw-cli >= 1.20.0, cardano-signer >= 1.35.0 (00_common.sh)
#   cardano-hw-cli 1.20.0 and cardano-signer 1.35.0 are the latest stable
#     releases satisfying those minimums.
#
# Consistency is enforced mechanically:
#   - checks.<system>.version-manifest fails if the flake inputs are locked to
#     revisions other than the ones declared here.
#   - checks.<system>.spo-compat parses the min/max version requirements out of
#     the SPO scripts' 00_common.sh and fails if any pinned tool violates them.
#
# To cut a new release set, see RELEASING.md.
{
  # Systems supported by the intersection of all bundled tooling.
  #   - cardano-node: native flake support for all four since the 10.6 line
  #   - cardano-cli: flake supports all four; note there is no native
  #     aarch64-linux binary cache upstream (first build compiles from source)
  #   - cardano-hw-cli: prebuilt linux-x64, linux-arm64 and (native) mac-arm64
  #     binaries since 1.20.0; there is no mac-x64 artifact any more, so
  #     x86_64-darwin is no longer supported
  #   - cardano-signer: prebuilt linux-x64, linux-arm64 and mac-x64 binaries;
  #     Apple Silicon runs mac-x64 via Rosetta 2
  #   - spo-scripts: portable bash
  supportedSystems = [
    "x86_64-linux"
    "aarch64-linux"
    "aarch64-darwin"
  ];

  tools = {
    cardano-node = {
      version = "11.1.3";
      ref = "11.1.3";
      rev = "938cba990357ae7c4b7f95c8f75dd9d31174bbeb";
    };

    # Kept in its own input because the CLI releases async from the node.
    # Policy: pin the version listed in the cardano-node release notes'
    # dependency table; only diverge to a newer CLI when the SPO scripts
    # require it and the node release notes do not forbid it.
    cardano-cli = {
      version = "11.2.3.0";
      ref = "cardano-cli-11.2.3.0";
      rev = "eac27b8b0437a80cea2152917850aadea5749d90";
    };

    # Martin Lang's StakePool Operator Scripts.
    spo-scripts = {
      version = "Update-2026-04";
      ref = "Update-2026-04";
      rev = "85e783f6886b449fbb0bb85f33f8d3a84bb6303d";
    };

    # Prebuilt release binaries (no upstream nix support); hashes are SRI.
    # Artifacts are pinned per platform so one broken upstream artifact can be
    # held back without moving the rest (1.18.2-1.19.1 linux-arm64 shipped a
    # broken pkg snapshot; fixed upstream in 1.20.0). Every platform version
    # is validated against the SPO scripts' minimum by checks.<system>.spo-compat.
    cardano-hw-cli = {
      version = "1.20.0";
      platforms = {
        linux-x64 = {
          version = "1.20.0";
          hash = "sha256-82Ss4zzLiWYu+ahVN/C4Lc4txzcPGyR46ZQIQjV0biE=";
        };
        linux-arm64 = {
          version = "1.20.0";
          hash = "sha256-Ck1voKmbvaEKnUmUY/lsET90eh5EnxjJ7TnUqivSJt0=";
        };
        mac-arm64 = {
          version = "1.20.0";
          hash = "sha256-U9ERqaBwgnuCx/jcOUh3m12+dIpJOJbvm2lG422PKHE=";
        };
      };
      autocompleteHash = "sha256-1NqxWEoFG33oqJ3AfGGLUcP7k81TjDm1zL3FYs070pM=";
    };

    # Trezor's official CLI (used for firmware updates). Built from PyPI by
    # tools/trezorctl.nix because nixpkgs lags upstream. 0.20.1 is the newest
    # release that works with the nixpkgs cryptography (0.20.2 needs >= 47).
    trezorctl = {
      version = "0.20.1";
      hash = "sha256-BvIe8bCtIPi8Ig8iny/zq/7cFekMo7va/NlnpgMeLLM=";
    };

    cardano-signer = {
      version = "1.35.0";
      hashes = {
        linux-x64 = "sha256-UkDmnUPeADSzVlk8tpoYApVHzOS/4osOnDn4f4Wn2gc=";
        linux-arm64 = "sha256-tMvwsTid3ByBjRGW+/0QbNmyhFQC3ZISNQWq5uRhLp0=";
        mac-x64 = "sha256-GLd3c92ZtHen7tK4CDbprnSoKyAFT4qxZLTviX2x+HQ=";
      };
    };
  };
}
