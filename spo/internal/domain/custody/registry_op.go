package custody

// OpSignRegistryEntry is the signature of a token-registry entry (CIP-26):
// ed25519 over a 32-byte message, by a minting-policy key. Only the policy
// role has it, and only a signer that holds the key in process claims it (a
// hardware wallet has no such operation, so a hardware policy is refused by
// the signing plan before anything is read or written; SPO-12a-IN-002).
const OpSignRegistryEntry Operation = "sign-token-registry-entry"
