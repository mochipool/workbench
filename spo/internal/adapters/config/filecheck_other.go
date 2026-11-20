//go:build !unix

package config

import (
	"fmt"
	"os"
)

// readFile reads spo.toml of dir. Without a Unix owner and mode to check, the
// file never names a Vault or KMS backend (SPO-Xunlock-PRE-050): it fails closed.
func readFile(dir string) (data []byte, untrusted error, err error) {
	data, err = os.ReadFile(Path(dir))
	if err != nil {
		return nil, nil, err
	}
	if len(data) > MaxFileSize {
		return nil, nil, fmt.Errorf("%s is larger than %d bytes", Path(dir), MaxFileSize)
	}
	return data, fmt.Errorf("%w: %s: %w", ErrUntrustedFile, Path(dir), fmt.Errorf("%w (its owner and mode cannot be checked on this platform)", ErrPlatformUnchecked)), nil
}
