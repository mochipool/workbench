# Real registry entries (oracle of the attestation construction)

Fetched on 2026-11-16 from the public repository
`cardano-foundation/cardano-token-registry` (`mappings/<subject>.json`, via
`raw.githubusercontent.com`; public data, nothing about this project was sent).
Not edited.

| File | Subject | Notes |
| --- | --- | --- |
| `hosky_mapping.json` | `a0028f35...484f534b59` (HOSKY) | no `policy` member; `description` has sequence number 1, the rest 0; `decimals` is a JSON number; the logo is a PNG |
| `policy_v1_unlimited_mapping.json` | `dae1b46d...665748454154` | `policy` tag 0: `all` of one `sig`, no time lock |
| `policy_v2_timelocked_mapping.json` | `ad4930cb...4744414441` | `policy` tag 1: `all` of `before` and `sig` |

`verify_test.go` verifies every attestation of these files with the public keys
they carry and rebuilds each `policy` value from its script. The same check was
made once, outside the test, over 26 further entries of the registry (all
properties of all of them verified, one older entry did not, which predates this
construction).
