package ports

// MetadataFileReader reads a user metadata file (`.json` or `.cbor`) by the
// path the operator typed. The files are read in place, never copied or
// changed (SPO-Pparam-OUT-003). A missing file is an error that wraps
// ErrNotFound (SPO-Pparam-PRE-005).
type MetadataFileReader interface {
	ReadMetadataFile(path string) ([]byte, error)
}

// MessageEncrypter encrypts transaction message lines with CIP-83 `basic`
// encryption: the lines as compact JSON, AES-256-CBC with PBKDF2-HMAC-SHA256
// (10 000 iterations) and a random salt, as `openssl enc -aes-256-cbc -pbkdf2
// -iter 10000 -a` does, the base64 split into lines of at most 64 characters
// (SPO-Pparam-EXT-001). A nil passphrase means the default `cardano`
// (SPO-Pparam-IF-012). The passphrase is read, never kept.
type MessageEncrypter interface {
	EncryptMessages(lines []string, passphrase *Secret) ([]string, error)
}
