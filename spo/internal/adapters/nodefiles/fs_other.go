//go:build !linux

package nodefiles

import (
	"errors"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var errLinuxOnly = errors.New("the RAM file-system check exists for Linux only, so no key is written in clear on this platform")

// Dir is never opened on this platform.
type Dir struct{}

// OpenDir always refuses.
func (Writer) OpenDir(string) (*Dir, error) { return nil, errLinuxOnly }

// Close does nothing.
func (*Dir) Close() error { return nil }

// Write always refuses.
func (*Dir) Write(ports.HotFileKind, *secret.Buffer) (string, error) { return "", errLinuxOnly }

// Remove does nothing.
func (*Dir) Remove(ports.HotFileKind) {}
