// Package cardanocli implements the Ledger and KeyGen ports by running the
// pinned cardano-cli.
package cardanocli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ErrNoMemoryFS means no memory-backed directory is available for the two
// key kinds cardano-cli cannot write to a pipe.
var ErrNoMemoryFS = errors.New("no memory-backed directory for key generation (set XDG_RUNTIME_DIR to a tmpfs)")

// KeyGen generates key pairs with cardano-cli.
type KeyGen struct {
	Toolchain ports.Toolchain
	Run       execx.Runner
	// ScratchDirs are candidate parents for the short-lived key file, tried
	// in order. Each must be on a memory-backed file system. Empty means
	// $XDG_RUNTIME_DIR, then /dev/shm.
	ScratchDirs []string
}

var keygenCmd = map[ports.KeyKind]string{
	ports.KeyKES: "key-gen-KES",
	ports.KeyVRF: "key-gen-VRF",
}

// Generate implements ports.KeyGen.
//
// cardano-cli 11.2.3.0 writes KES and VRF signing keys by creating a
// temporary file beside the destination and renaming it, so neither a pipe
// nor /dev/stdout works (see the X2 finding in the concerns register, and
// the quirk under SPO-04c-INV-002). The key is therefore written into a
// private 0700 directory on a memory-backed file system, read into guarded
// memory, overwritten and removed. It never reaches a disk.
//
// spec: SPO-04c-EXT-001
func (k KeyGen) Generate(ctx context.Context, kind ports.KeyKind) (ports.KeyPair, error) {
	sub, ok := keygenCmd[kind]
	if !ok {
		return ports.KeyPair{}, fmt.Errorf("cardanocli: cannot generate %q keys", kind)
	}
	cli, err := k.Toolchain.Tool(ctx, ports.CardanoCLI)
	if err != nil {
		return ports.KeyPair{}, err
	}
	dir, err := k.scratch()
	if err != nil {
		return ports.KeyPair{}, err
	}
	defer os.RemoveAll(dir)
	vpath, spath := filepath.Join(dir, "vkey"), filepath.Join(dir, "skey")
	defer wipe(spath)

	if _, err := k.Run.Run(ctx, execx.Cmd{
		Path: cli.Path,
		Args: execx.Lits("latest", "node", sub, "--verification-key-file", vpath, "--signing-key-file", spath),
		Dir:  dir,
	}); err != nil {
		return ports.KeyPair{}, err
	}

	f, err := os.Open(spath)
	if err != nil {
		return ports.KeyPair{}, err
	}
	skey, err := secret.Read(f)
	f.Close()
	if err != nil {
		return ports.KeyPair{}, err
	}
	vkey, err := os.ReadFile(vpath)
	if err != nil {
		skey.Destroy()
		return ports.KeyPair{}, err
	}
	return ports.KeyPair{VKey: vkey, SKey: skey}, nil
}

func (k KeyGen) scratch() (string, error) {
	candidates := k.ScratchDirs
	if len(candidates) == 0 {
		if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
			candidates = append(candidates, d)
		}
		candidates = append(candidates, "/dev/shm")
	}
	for _, parent := range candidates {
		if !filepath.IsAbs(parent) || !memoryBacked(parent) {
			continue
		}
		dir, err := os.MkdirTemp(parent, "spo-keygen-*") // mode 0700
		if err == nil {
			return dir, nil
		}
	}
	return "", ErrNoMemoryFS
}

// wipe overwrites a file with zeros before it is removed.
func wipe(path string) {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil {
		f.Write(make([]byte, st.Size()))
		f.Sync()
	}
}

var _ ports.KeyGen = KeyGen{}
