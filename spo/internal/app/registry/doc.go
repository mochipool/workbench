// Package registry holds the use cases of the Cardano Token Registry
// (CIP-26): GenerateTokenMetadata builds, signs and stores the registry entry
// of an asset (upstream 12a_genAssetMeta), and CheckTokenMetadata compares the
// local asset record with what a registry server serves (upstream
// 12b_checkAssetMetaServer).
//
// Upstream drives the external `token-metadata-creator`, which is not in the
// pinned toolchain. Here the entry is built natively by domain/tokenmeta and
// signed through a registry signer behind a signing plan (ADR 0007, ADR 0008).
// Submitting the file to the registry (a pull request) stays with the operator.
package registry
