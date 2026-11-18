//go:build linux

package nodefiles

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"os"

	"golang.org/x/sys/unix"

	"github.com/mochipool/workbench/spo/internal/adapters/nodeage"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// IdentityCredential is the name of the systemd credential that holds the
// producer's age identity (the secret key of the recipient the operator gave
// `node export`). The service that runs the helper loads it with
// LoadCredentialEncrypted=, and systemd decrypts it (with the host's TPM, when
// the credential was bound to one) into $CREDENTIALS_DIRECTORY for that service.
const IdentityCredential = "spo-node-age-identity"

// DeliverConfig is one start-up delivery.
type DeliverConfig struct {
	// From holds the three ciphertext files of `node export`.
	From string
	// To is the ramfs directory the node reads its files from.
	To string
	// CredentialsDir is the directory that holds IdentityCredential
	// ($CREDENTIALS_DIRECTORY of the service).
	CredentialsDir string
	// Derive checks the KES key against the certificate and the VRF key against
	// itself.
	Derive ports.HotVKeyDeriver
}

// ErrRoot: the helper writes files for the user it runs as, so it refuses to
// run as root.
var ErrRoot = errors.New("the start-up helper runs as the node's own user, not as root: its files are owned by the user it runs as")

// Deliver is the start-up helper. It reads the producer's identity from the
// credentials directory, decrypts the three ciphertext files of From, checks
// each by its kind, checks that the certificate names the KES key, and only then
// writes kes.skey, vrf.skey and node.cert (mode 0400, this user) into To. It
// refuses a ciphertext sealed to another recipient, a tampered one, a file of
// another kind, a certificate for another KES key, and a directory that is not a
// private ramfs directory; when a write fails, the files it created are removed.
// It returns the paths written. It cannot open a workspace: nothing it imports
// reaches the store.
//
// spec: SPO-Xcustody-INV-007, SPO-Xcustody-INV-008, SPO-Xcustody-PR-002, SPO-Xcustody-MODE-001, SPO-Xcustody-MODE-002, SPO-Xcustody-PRE-012, SPO-Xcustody-PRE-013, SPO-Xcustody-PRE-014
func (w Writer) Deliver(ctx context.Context, cfg DeliverConfig) ([]string, error) {
	if os.Geteuid() == 0 {
		return nil, ErrRoot
	}
	if cfg.Derive == nil {
		return nil, errors.New("no key deriver wired")
	}
	if cfg.CredentialsDir == "" {
		return nil, errors.New("no credentials directory: the helper's identity comes from a systemd credential named " + IdentityCredential)
	}
	id, err := w.readIdentity(cfg.CredentialsDir)
	if err != nil {
		return nil, err
	}

	// The ciphertext: its directory may be root's or the user's, never writable by others.
	from, st, err := openDirFD(cfg.From)
	if err != nil {
		return nil, err
	}
	defer from.Close()
	if err := checkDirFD(from, st, true); err != nil {
		return nil, err
	}
	plain := map[pool.HotKind]*secret.Buffer{}
	headers := map[pool.HotKind]pool.DeliveryHeader{}
	defer func() {
		for _, b := range plain {
			b.Destroy()
		}
	}()
	for _, k := range pool.HotKinds() {
		spec, _ := k.Spec()
		ct, err := readFileAt(from, spec.CipherFile(), 64<<10, false)
		if err != nil {
			return nil, err
		}
		pt, err := id.Open(ct, 4096)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", spec.CipherFile(), err)
		}
		// the file carries its header: the plaintext kept is the envelope
		var h pool.DeliveryHeader
		var env []byte
		if err := pt.Use(func(b []byte) error {
			var e error
			h, env, e = pool.UnframeDelivery(b)
			if e == nil {
				env = append([]byte(nil), env...)
			}
			return e
		}); err != nil {
			pt.Destroy()
			return nil, fmt.Errorf("%s: %w", spec.CipherFile(), err)
		}
		pt.Destroy()
		if h.Kind != spec.File {
			clear(env)
			return nil, fmt.Errorf("%s: the header says it is %q", spec.CipherFile(), h.Kind)
		}
		headers[k] = h
		plain[k] = secret.Take(env)
		if err := plain[k].Use(func(b []byte) error { return pool.ValidateHot(k, b) }); err != nil {
			return nil, fmt.Errorf("%s: %w", spec.CipherFile(), err)
		}
	}
	// one delivery: the same pool, KES number and certificate counter in all three
	first := headers[pool.HotKES]
	for _, k := range pool.HotKinds() {
		h := headers[k]
		if h.PoolID != first.PoolID || h.KesNumber != first.KesNumber || h.Counter != first.Counter {
			return nil, errors.New("the three files do not belong to one delivery (pool, KES number or certificate counter differ)")
		}
	}
	if err := checkPair(ctx, cfg.Derive, plain, headers[pool.HotKES]); err != nil {
		return nil, err
	}

	d, err := w.OpenDir(cfg.To)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	var written []string
	var kinds []ports.HotFileKind
	for _, k := range pool.HotKinds() {
		p, err := d.Write(k, plain[k])
		if err != nil {
			for _, kk := range kinds {
				d.Remove(kk)
			}
			return nil, err
		}
		kinds = append(kinds, k)
		written = append(written, p)
	}
	return written, nil
}

// checkPair: the KES key derives the verification key the certificate names, and
// the VRF key is whole.
func checkPair(ctx context.Context, d ports.HotVKeyDeriver, plain map[pool.HotKind]*secret.Buffer, h pool.DeliveryHeader) error {
	var oc pool.OpCert
	if err := plain[pool.HotOpCert].Use(func(b []byte) error {
		var e error
		oc, e = pool.ParseOpCert(b)
		return e
	}); err != nil {
		return err
	}
	pid, perr := chain.PoolIDOf(oc.ColdVKey[:])
	if perr != nil || hex.EncodeToString(pid[:]) != h.PoolID || oc.Counter != h.Counter {
		return errors.New("the operational certificate is not the one the headers name (pool id or counter)")
	}
	if custody.VerifyOpCertOwnKey(custody.OpCert{KesVKey: oc.KesVKey, Counter: oc.Counter, KesPeriod: oc.KesPeriod, ColdVKey: oc.ColdVKey, Signature: oc.Signature}, pool.MaxSaneKesPeriod) != nil {
		return errors.New("the operational certificate's cold signature does not verify")
	}
	vk, err := d.DeriveKES(ctx, plain[pool.HotKES])
	if err != nil {
		return err
	}
	if !bytes.Equal(vk, oc.KesVKey[:]) {
		return errors.New("the operational certificate does not name the KES key that was delivered with it")
	}
	if _, err := d.DeriveVRF(ctx, plain[pool.HotVRF]); err != nil {
		return err
	}
	return nil
}

// readIdentity reads the credential into guarded memory and parses it. The
// credentials directory must be a private directory on the file system the rule
// accepts (ramfs), and the credential a plain file with no group or other bits.
func (w Writer) readIdentity(dir string) (*nodeage.Identity, error) {
	f, st, err := openDirFD(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := checkDirFD(f, st, true); err != nil {
		return nil, err
	}
	var sfs unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &sfs); err != nil || !w.dirFSOK(st, int64(sfs.Type)) {
		return nil, fmt.Errorf("%w: the credentials directory %s is not on a ramfs mount: the identity must not sit on a disk", ErrDirectory, dir)
	}
	raw, err := readFileAt(f, IdentityCredential, 1024, true)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, nodeage.ErrIdentity
	}
	text := secret.Take(raw)
	defer text.Destroy()
	return nodeage.ParseIdentity(text)
}
