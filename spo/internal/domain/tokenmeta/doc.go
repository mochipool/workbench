// Package tokenmeta is the native-token registry entry of CIP-26: the subject
// (policy id and asset name, hex), the properties name, description, ticker,
// url, logo and decimals, each with a value, a sequence number and
// attestation signatures, and the policy script that ties the subject to the
// keys that may sign. It builds an entry, checks the field limits of the
// registry, renders the file the registry takes as a pull request, parses the
// answer of a registry server, and verifies the attestations. It is pure: the
// key that signs is behind Signer, and files and the network are the use
// cases' and adapters'.
//
// The attestation construction (CIP-26, "Attestation Signatures") is checked
// against real entries of cardano-foundation/cardano-token-registry (see
// testdata/README.md and verify_test.go): an ed25519 signature, by a key of
// the policy, over
//
//	blake2b-256( blake2b-256(CBOR subject) ++ blake2b-256(CBOR property name)
//	             ++ blake2b-256(CBOR value) ++ blake2b-256(CBOR sequence number) )
//
// where the subject and the property name are CBOR text strings (the hex text
// of the subject, not its bytes), a text property is a CBOR text string, the
// decimals a CBOR unsigned integer, the sequence number a CBOR unsigned
// integer, and the logo the CBOR byte string of the decoded PNG (not the
// base64 text; the CIP's text leaves this open and the real entries settle it).
package tokenmeta
