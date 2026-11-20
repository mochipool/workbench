package relaystore

import "strings"

// PolicyStatements are the bucket policy statements, the lifecycle rule and
// the bucket settings ADR 0015 decision 3 requires, for an operator to compare
// with what is applied. REGISTRY, WORKING and ROLE_ARN are the operator's;
// NODEKEY is filled in.
//
// UNVERIFIED. None of these statements was checked against AWS or any other
// store; they are written from memory of AWS's documentation and only the
// stand-in (test/s3stand) emulates any of them. In particular it is not
// checked whether s3:object-lock-remaining-retention-days is evaluated for a
// PutObject that carries the lock headers (the statements below deny it on
// s3:PutObjectRetention only; a role that can put an object with a lock may
// be able to set any date in the put itself), nor how s3:if-none-match and
// s3:if-match behave in a Null condition. An operator must test each
// statement on the store before relying on it.
//
// What the tools assume whatever the policy: the relay's role can write a
// tombstone version with any lock its put carries, a short one included. So
// store verify fails a lock shorter than its tombstone's life, migrate-store
// writes its own version over one (it never counts it as carried), and the
// relay's revoke does the same (objregistry, PRE-811).
const policyStatements = `Registry bucket (versioning Enabled; Object Lock enabled with NO default retention rule):
  {"Sid": "DenySimpleDeleteOfTombstonesAndMarker", "Effect": "Deny", "Principal": "*",
   "Action": "s3:DeleteObject",
   "Resource": ["arn:aws:s3:::REGISTRY/relays/*/registry/tombstones/*", "arn:aws:s3:::REGISTRY/relays/*/marker"]}
  {"Sid": "DenyGovernanceBypass", "Effect": "Deny", "Principal": "*",
   "Action": "s3:BypassGovernanceRetention", "Resource": "arn:aws:s3:::REGISTRY/*"}
  {"Sid": "DenyLongTombstoneLocks", "Effect": "Deny", "Principal": {"AWS": "ROLE_ARN"},
   "Action": "s3:PutObjectRetention", "Resource": "arn:aws:s3:::REGISTRY/relays/*/registry/tombstones/*",
   "Condition": {"NumericGreaterThan": {"s3:object-lock-remaining-retention-days": "182"}}}
  {"Sid": "DenyLongMarkerLocks", "Effect": "Deny", "Principal": {"AWS": "ROLE_ARN"},
   "Action": "s3:PutObjectRetention", "Resource": "arn:aws:s3:::REGISTRY/relays/*/marker",
   "Condition": {"NumericGreaterThan": {"s3:object-lock-remaining-retention-days": "366"}}}
  {"Sid": "DenyLegalHold", "Effect": "Deny", "Principal": {"AWS": "ROLE_ARN"},
   "Action": "s3:PutObjectLegalHold", "Resource": "arn:aws:s3:::REGISTRY/*"}
  {"Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
   "Resource": ["arn:aws:s3:::REGISTRY", "arn:aws:s3:::REGISTRY/*"],
   "Condition": {"Bool": {"aws:SecureTransport": "false"}}}
  {"Sid": "DenyUnconditionalPut", "Effect": "Deny", "Principal": "*", "Action": "s3:PutObject",
   "Resource": "arn:aws:s3:::REGISTRY/*",
   "Condition": {"Null": {"s3:if-none-match": "true", "s3:if-match": "true"}}}
Registry bucket lifecycle (one rule per identity; no rule touches registry/tombstones/ or marker):
  {"ID": "spo-relay-NODEKEY-bindings", "Status": "Enabled",
   "Filter": {"Prefix": "relays/NODEKEY/registry/bindings/"},
   "NoncurrentVersionExpiration": {"NoncurrentDays": 1},
   "Expiration": {"ExpiredObjectDeleteMarker": true}}
Working bucket (versioning never enabled; no lifecycle rule needed):
  {"Sid": "DenyLeaseDelete", "Effect": "Deny", "Principal": "*",
   "Action": "s3:DeleteObject", "Resource": "arn:aws:s3:::WORKING/relays/*/lease"}
  {"Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
   "Resource": ["arn:aws:s3:::WORKING", "arn:aws:s3:::WORKING/*"],
   "Condition": {"Bool": {"aws:SecureTransport": "false"}}}
  {"Sid": "DenyUnconditionalPut", "Effect": "Deny", "Principal": "*", "Action": "s3:PutObject",
   "Resource": "arn:aws:s3:::WORKING/*",
   "Condition": {"Null": {"s3:if-none-match": "true", "s3:if-match": "true"}}}
`

// PolicyStatements is the reference block with the identity's node key.
func PolicyStatements(nodeHex string) string {
	return strings.ReplaceAll(policyStatements, "NODEKEY", nodeHex)
}

// missingClientCalls are the requests a fuller verify needs and the narrow
// client (adapters/objstore/s3client) cannot make; they are not added here.
const missingClientCalls = "the store client has no GetBucketPolicy, no GetBucketLifecycleConfiguration, no GetBucketEncryption, " +
	"and its GetObjectLockConfiguration reads ObjectLockEnabled only, not the default retention Rule; " +
	"compare the bucket settings with the reference statements below using the store's own console or command line"
