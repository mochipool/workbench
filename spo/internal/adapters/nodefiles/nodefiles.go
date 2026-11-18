// Package nodefiles is the node-delivery exception to the rule that the release
// binary writes no secret unencrypted (ADR 0011 decisions 1 and 2; spec
// SPO-Xcustody-INV-006 to INV-009). cardano-node reads kes.skey, vrf.skey and
// the operational certificate from files in clear, so a block producer cannot
// be run without them. This package is the only writer of a signing key in
// clear, and it belongs to the block producer's start-up helper
// (cmd/spo-node-keys), a separate binary that cannot open a workspace.
//
// It is narrow by construction:
//
//   - the writer takes a pool.HotKind, which has exactly three values (KES
//     signing key, VRF signing key, operational certificate); no cold, payment,
//     stake, DRep or committee key, no mnemonic and no other secret has a kind
//     to be named by;
//   - it refuses an envelope that is not, by members, text-envelope type and
//     exact cborHex length, the file of its kind (pool.ValidateHot);
//   - it opens the directory with O_DIRECTORY|O_NOFOLLOW, checks the open
//     descriptor (owner, mode, file-system type) with fstat and fstatfs, and
//     creates each file relative to that descriptor with O_CREAT|O_EXCL|
//     O_NOFOLLOW, mode 0400, so a path swapped after the check changes nothing;
//   - the directory must be on ramfs, which is never swapped; tmpfs is refused.
//
// The internal/archtest rules keep every other package from importing it, pin
// the table of kinds and the only file-creation calls of the package.
package nodefiles

import (
	"errors"

	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Writer implements ports.NodeFiles. The zero value is the release rule.
type Writer struct {
	// allowFS replaces the file-system rule (ramfs only). It is unexported and
	// set only from export_test.go: no build outside this package's tests can
	// relax the rule.
	allowFS func(fsType int64) bool
}

var _ ports.NodeFiles = Writer{}

// ErrNotHot is the refusal of an envelope that is not a hot file of its kind.
var ErrNotHot = pool.ErrNotHot

// ErrDirectory: the directory is not one a plaintext key may be written to.
var ErrDirectory = errors.New("nodefiles: the directory is not acceptable for a key in clear")

// ErrExists: a file of that name is already there; a delivery never replaces one.
var ErrExists = errors.New("nodefiles: the file already exists; it is never replaced")

// WriteHot implements ports.NodeFiles: it opens dir, writes one file and
// closes it.
func (w Writer) WriteHot(dir string, kind ports.HotFileKind, envelope *secret.Buffer) (string, error) {
	d, err := w.OpenDir(dir)
	if err != nil {
		return "", err
	}
	defer d.Close()
	return d.Write(kind, envelope)
}

// ramfsMagic is RAMFS_MAGIC of linux/magic.h. tmpfs (0x01021994) is not accepted.
const ramfsMagic = 0x858458f6

func (w Writer) fsOK(t int64) bool {
	if w.allowFS != nil {
		return w.allowFS(t)
	}
	return t == ramfsMagic
}

// tmpfsMagic is TMPFS_MAGIC. tmpfs is accepted only when its mount has the
// `noswap` option (Linux 6.4), which keeps its pages out of swap; ramfs never
// swaps.
const tmpfsMagic = 0x01021994
