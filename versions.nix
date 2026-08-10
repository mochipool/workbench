# versions.nix — single source of truth for the workbench release set.
#
# Every tool version listed here has been verified compatible with the others:
#
#   cardano-node 11.0.1 ships cardano-cli 11.0.0.0 (release-notes dependency table)
#   spo-scripts Update-2026-03 enforces: cli >= 11.0.0, node >= 11.0.0,
#     cardano-hw-cli >= 1.19.0, cardano-signer >= 1.27.0 (00_common.sh)
#   cardano-hw-cli 1.19.1 and cardano-signer 1.35.0 are the latest stable
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
  #   - cardano-hw-cli / cardano-signer: prebuilt linux-x64, linux-arm64 and
  #     mac-x64 binaries; Apple Silicon runs mac-x64 via Rosetta 2
  #   - spo-scripts: portable bash
  supportedSystems = [
    "x86_64-linux"
    "aarch64-linux"
    "x86_64-darwin"
    "aarch64-darwin"
  ];

  tools = {
    cardano-node = {
      version = "11.0.1";
      ref = "11.0.1";
      rev = "97036a66bcf8c89f687ae57a048eecc0389977ef";
    };

    # Kept in its own input because the CLI releases async from the node.
    # Policy: pin the version listed in the cardano-node release notes'
    # dependency table; only diverge to a newer CLI when the SPO scripts
    # require it and the node release notes do not forbid it.
    cardano-cli = {
      version = "11.0.0.0";
      ref = "cardano-cli-11.0.0.0";
      rev = "01a89dad991e5a19990150b4e1de348a1481a37a";
    };

    # Martin Lang's StakePool Operator Scripts.
    spo-scripts = {
      version = "Update-2026-03";
      ref = "Update-2026-03";
      rev = "765dc4e1eee5406dc9e6fa30e7280eca36e0bac9";
    };

    # Prebuilt release binaries (no upstream nix support); hashes are SRI.
    cardano-hw-cli = {
      version = "1.19.1";
      hashes = {
        linux-x64 = "sha256-CJNJ68/ipGXjAfqvB3+glPbbhZ6SqrVvJW8yUpW3ZHQ=";
        linux-arm64 = "sha256-uYAgD3yWwslQ6m8Kee2BKAr9HAN+49ccS4hVpP+taGs=";
        mac-x64 = "sha256-KkW4sTWlF9dMdcbIubjT5itm8ZFNSDbQVRHnWWwfEVQ=";
      };
      autocompleteHash = "sha256-1NqxWEoFG33oqJ3AfGGLUcP7k81TjDm1zL3FYs070pM=";
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
