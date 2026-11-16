package fsstore

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// maxMetadataFile bounds a user metadata file. Transaction metadata is part of
// a transaction of at most 16 KiB on mainnet, so a file beyond this is not
// metadata.
const maxMetadataFile = 1 << 20

// MetadataFiles reads the user's metadata files (`.json`, `.cbor`) in place
// from the file system, by the path the operator typed, relative to the
// working directory. It never writes (SPO-Pparam-OUT-003).
type MetadataFiles struct{}

// ReadMetadataFile implements ports.MetadataFileReader. A missing file wraps
// ports.ErrNotFound; a directory or an oversized file is refused.
//
// spec: SPO-Pparam-PRE-005, SPO-Pparam-OUT-003
func (MetadataFiles) ReadMetadataFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: the metadata file %q does not exist", ports.ErrNotFound, path)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("the metadata file %q is not a regular file", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxMetadataFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxMetadataFile {
		return nil, fmt.Errorf("the metadata file %q is larger than %d bytes", path, maxMetadataFile)
	}
	return b, nil
}

var _ ports.MetadataFileReader = MetadataFiles{}
