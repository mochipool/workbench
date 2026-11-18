package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
)

// safeText quotes a text a peer chose (a label, a purpose, a reason, a
// metadata value) so that nothing in it is interpreted by the terminal: control
// characters, escape sequences, bidirectional overrides and line or paragraph
// separators are written as escapes (strconv.Quote escapes everything that is
// not printable: format characters and U+2028/2029 included).
func safeText(s string) string { return strconv.Quote(s) }

// ---- the signer's own keys, from the store ---------------------------------------------

// storeKeyDirectory is multisig.KeyFinder and party.OwnedKeys over the keys in
// this workspace's store, and nothing else (ADR 0005, obligation 2): which key
// the signer holds for a hash, and which payment and stake key hashes it owns.
type storeKeyDirectory struct {
	keys []storeKey
}

type storeKey struct {
	role  custody.Role
	owner string // the store name, for this file only; no key reference carries it
	hash  [28]byte
}

// loadStoreKeys reads the verification keys of the store's payment, stake and
// pool cold keys. It needs the store to list its artefacts.
func loadStoreKeys(ctx context.Context, store ports.NamedStore) (*storeKeyDirectory, error) {
	lister, ok := store.(ports.SourceLister)
	if !ok {
		return nil, errors.New("this workspace's store cannot list its keys, so the signer cannot tell which keys it holds")
	}
	listing, err := lister.List(ctx)
	if err != nil {
		return nil, err
	}
	type kinds struct {
		role         custody.Role
		skey, hwsKey ports.Kind
	}
	byV := map[ports.Kind]kinds{
		ports.AddrVKey:    {custody.RolePayment, ports.AddrSKey, ports.AddrHwsFile},
		ports.StakingVKey: {custody.RoleStake, ports.StakingSKey, ports.StakingHwsFile},
		ports.NodeVKey:    {custody.RolePoolCold, ports.NodeSKey, ports.NodeHwsFile},
	}
	d := &storeKeyDirectory{}
	err = store.View(ctx, func(r ports.NamedReader) error {
		for _, e := range listing.Entries {
			k, ok := byV[e.Ref.Kind]
			if !ok {
				continue
			}
			raw, err := r.Get(e.Ref)
			if err != nil {
				continue
			}
			env, err := pool.ParseEnvelope(raw)
			if err != nil {
				continue
			}
			key32, err := env.Key32()
			if err != nil {
				continue
			}
			sk := storeKey{role: k.role, owner: e.Ref.Name, hash: [28]byte(txbuild.HashKey(key32))}
			// A key is held when a signing key or a hardware signing file is
			// here; which signer answers is the directory's business.
			hw, _ := r.Exists(ports.NamedRef{Name: e.Ref.Name, Kind: k.hwsKey})
			has, _ := r.Exists(ports.NamedRef{Name: e.Ref.Name, Kind: k.skey})
			if !hw && !has {
				continue // a verification key with no signing key here is not held
			}
			d.keys = append(d.keys, sk)
		}
		return nil
	})
	return d, err
}

// FindKey implements multisig.KeyFinder.
func (d *storeKeyDirectory) FindKey(_ context.Context, role custody.Role, hash [28]byte) (custody.KeyRef, bool, error) {
	for _, k := range d.keys {
		if k.role == role && k.hash == hash {
			id, err := identity.NewRef(identity.KindKeyHash, hash[:])
			if err != nil {
				return custody.KeyRef{}, false, err
			}
			return custody.KeyRef{Role: role, Identity: id}, true, nil
		}
	}
	return custody.KeyRef{}, false, nil
}

// Owned is the payment and stake key hashes of this store, and no others.
func (d *storeKeyDirectory) Owned() party.OwnedKeys {
	var o party.OwnedKeys
	for _, k := range d.keys {
		switch k.role {
		case custody.RolePayment:
			o.Payment = append(o.Payment, k.hash)
		case custody.RoleStake:
			o.Stake = append(o.Stake, k.hash)
		}
	}
	return o
}

// ---- the approval gate ---------------------------------------------------------------------

// passphraseGate asks for the workspace passphrase again (or, in a factor session,
// for a fresh presentation of the authenticator) before a key signs
// (SPO-Xparty-INV-016, ADR 0005 obligation 6). It asks for every key role, the
// pool cold, payment and owner stake keys the spec names included. It compares
// with the passphrase this session was opened with, so a stolen open terminal
// cannot sign by pressing yes alone.
type passphraseGate struct {
	a *app
	s *session
	// note names the request and its net (set by the approval that asked).
	note func() string
}

func (g passphraseGate) Reauthenticate(ctx context.Context, key custody.KeyRef, bodyHash [32]byte) error {
	if g.s == nil || (g.s.Pass == nil && !g.s.factorSession) {
		return errors.New("there is no workspace passphrase to check against: nothing was signed")
	}
	note := ""
	if g.note != nil {
		note = g.note()
	}
	// The label the operator gave the key (where one exists) and the key hash: a
	// name alone does not say which key signs.
	label := ""
	{
		idx := labels.NewIndex(g.s.Anchored)
		if homes, herr := idx.Homes(ctx, key.Identity); herr == nil {
			var names []string
			for _, h := range homes {
				if h.Role == key.Role {
					if l, ok, _ := labels.LabelOf(ctx, g.s.Anchored, h.Anchor); ok {
						names = append(names, safeText(l.Name))
					}
				}
			}
			if len(names) > 0 {
				label = " stored as " + strings.Join(names, ", ")
			}
		}
	}
	fmt.Fprintf(g.a.d.Out, "About to sign with the %s key%s, key hash %s, over body %x (%s).\n", key.Role, label, key.Identity, bodyHash[:], note)
	flushTypedAhead(g.a.term)
	if g.s.factorSession {
		// ADR 0011, Amends ADR 0005: the gate is "a fresh presentation of a factor
		// that the workspace policy accepts". There is no passphrase here; the
		// authenticator is asked again and its answer checked against the slot.
		ra, ok := g.s.Sealed.(FactorReauth)
		if !ok || g.a.d.Factors == nil {
			return errors.New("this workspace unlocks through FIDO2 factors and there is no factor source to ask again: nothing was signed")
		}
		fmt.Fprintf(g.a.d.Err, "Present the authenticator again to sign (%s).\n", note)
		if err := ra.Reauthenticate(ctx, g.a.reauthOpen()); err != nil {
			return fmt.Errorf("the authenticator was not presented again, so nothing was signed: %w", err)
		}
		return nil
	}
	typed, err := g.a.term.ReadSecret(ctx, "Type the workspace passphrase again to sign ("+note+"): ")
	if errors.Is(err, ErrNoTerminal) {
		return errors.New("no terminal to ask the passphrase on: an approval needs the passphrase again, and nothing was signed")
	}
	if err != nil {
		return err
	}
	defer typed.Destroy()
	if !equalSecrets(g.s.Pass, typed) {
		return errors.New("that is not this workspace's passphrase: nothing was signed")
	}
	return nil
}

// ---- directories --------------------------------------------------------------------------

// partyDirs are the directories of the file transport.
type partyDirs struct{ inbox, outbox string }

// dirs resolves the inbox and the outbox: the flag, else [party] in spo.toml,
// else party/inbox and party/outbox in the workspace. A relative path is
// relative to the workspace directory.
func (r *partyRun) dirs(inbox, outbox string) partyDirs {
	d := partyDirs{inbox: inbox, outbox: outbox}
	cfg := r.o.Config.Party
	if d.inbox == "" && cfg != nil {
		d.inbox = cfg.Inbox
	}
	if d.outbox == "" && cfg != nil {
		d.outbox = cfg.Outbox
	}
	if d.inbox == "" {
		d.inbox = filepath.Join("party", "inbox")
	}
	if d.outbox == "" {
		d.outbox = filepath.Join("party", "outbox")
	}
	rel := func(p string) string {
		if filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(r.a.workspace, p)
	}
	d.inbox, d.outbox = rel(d.inbox), rel(d.outbox)
	return d
}

// ensure creates a directory only the operator can write to, when it does not
// exist. An existing directory is left as it is: the transport judges it.
func ensureDir(dir string) error {
	if _, err := os.Lstat(dir); err == nil {
		return nil
	}
	return os.MkdirAll(dir, 0o700)
}

// ---- the signer's own chain view ----------------------------------------------------------

// maxSnapshotBytes bounds what --own-snapshot reads.
const maxSnapshotBytes = 256 << 20

// readSnapshot is ADR 0005, obligation 3: an offline snapshot becomes the
// signer's own chain view only from a file the operator named for that
// purpose, and never from one of these. It opens the file ONCE, without
// following a link, judges the open descriptor and reads the bytes from it, so
// what is judged is what is read. It refuses:
//
//   - a path inside this workspace's party store: the sealed workspace file, its
//     head and lock files, and the party directory (default inbox and outbox);
//   - a path inside the inbox or the outbox in effect, and inside the inbox or
//     outbox that spo.toml configures even when another --inbox or --outbox is
//     given (a file that arrived there was written by a peer, or by us for a
//     peer);
//   - a file that is a symbolic link, is not a regular file, is not owned by the
//     operator, is writable by its group or by others, or has more than one
//     hard link (a hard link into the inbox is the same file, whatever its
//     path);
//   - a file with an ancestor directory that others can replace (the sshd
//     StrictModes rule, as for the inbox).
//
// What it cannot tell: a file a peer's bundle wrote somewhere else on this disk
// (`offline extract` and a copy from a stick leave no record of where a file
// came from), a transfer file whose history was written by another party, or a
// snapshot the operator took on another machine. The operator names the file,
// and it is the operator's statement that this machine took it. That includes
// this workspace's own offline transfer file: it is a snapshot only when the
// operator names it here.
//
// It returns the bytes and the real path, for the operator's information.
func (r *partyRun) readSnapshot(path string, d partyDirs) ([]byte, string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, "", err
	}
	f, err := os.OpenFile(abs, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if lst, lerr := os.Lstat(abs); lerr == nil && lst.Mode()&os.ModeSymlink != 0 {
			return nil, "", fmt.Errorf("--own-snapshot %s is a symbolic link: name the file itself", path)
		}
		return nil, "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, "", err
	}
	if !st.Mode().IsRegular() {
		return nil, "", fmt.Errorf("--own-snapshot %s is not a regular file", path)
	}
	if st.Mode().Perm()&0o022 != 0 {
		return nil, "", fmt.Errorf("--own-snapshot %s is writable by its group or by others (mode %04o): somebody else could have chosen what each input is", path, st.Mode().Perm())
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		if int(sys.Uid) != os.Geteuid() {
			return nil, "", fmt.Errorf("--own-snapshot %s is owned by uid %d, not by you", path, sys.Uid)
		}
		if sys.Nlink != 1 {
			return nil, "", fmt.Errorf("--own-snapshot %s has %d hard links: it may be the same file as one in an inbox, an outbox or the party store, under another name. Copy it (cp) and name the copy", path, sys.Nlink)
		}
	}
	real, err := filepath.EvalSymlinks(abs) // a link above the file
	if err != nil {
		return nil, "", err
	}
	wsReal, err := filepath.EvalSymlinks(r.a.workspace)
	if err != nil {
		wsReal = r.a.workspace
	}
	if base := filepath.Base(real); filepath.Dir(real) == wsReal && strings.HasPrefix(base, WorkspaceFile) {
		return nil, "", fmt.Errorf("--own-snapshot %s is the sealed workspace (or its head or lock file), the party store: refused", path)
	}
	cfgd := r.dirs("", "") // what spo.toml (or the defaults) say, whatever the flags
	for _, dir := range []string{filepath.Join(r.a.workspace, "party"), d.inbox, d.outbox, cfgd.inbox, cfgd.outbox} {
		dr, err := filepath.EvalSymlinks(dir)
		if err != nil {
			dr, err = filepath.Abs(dir)
			if err != nil {
				continue
			}
		}
		if rel, err := filepath.Rel(dr, real); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, "", fmt.Errorf("--own-snapshot %s is inside %s, a directory envelopes and peers' files go through: refused", path, dir)
		}
	}
	check := r.kit().CheckAncestors
	if check == nil {
		return nil, "", errors.New("configuration error: this build wires no check of the directories above a snapshot, so --own-snapshot is refused")
	}
	if err := check(real); err != nil {
		return nil, "", fmt.Errorf("--own-snapshot %s: %w", path, err)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSnapshotBytes+1))
	if err != nil {
		return nil, "", err
	}
	if len(data) > maxSnapshotBytes {
		return nil, "", fmt.Errorf("--own-snapshot %s is larger than %d bytes", path, maxSnapshotBytes)
	}
	return data, real, nil
}

// privateCopy puts the bytes of a snapshot, already judged, in a file only
// this user can reach (a 0700 directory made for it), for the reader that
// takes a path; the copy is removed when the command ends. The reader never
// goes back to the path the operator named.
func (r *partyRun) privateCopy(data []byte) (string, error) {
	dir, err := os.MkdirTemp("", "spo-snapshot-")
	if err != nil {
		return "", err
	}
	r.cleanups = append(r.cleanups, func() { os.RemoveAll(dir) })
	p := filepath.Join(dir, "snapshot.json")
	if err := os.WriteFile(p, data, 0o400); err != nil {
		return "", err
	}
	return p, nil
}

// signer builds the signer role from the workspace (ADR 0005, "Obligations on
// whatever wires a signer"), and describes the chain view it has.
func (r *partyRun) signer(ctx context.Context, snapshot string, d partyDirs) (multisig.Signer, string, error) {
	k := r.kit()
	// Obligation 1: the address inspector is the one the root wired for the
	// party stack, always. Without it the signer would refuse every request;
	// that is a configuration error, not a refusal of a request.
	if k.Addresses == nil {
		return multisig.Signer{}, "", fmt.Errorf("configuration error: this build wires no address inspector for the party stack, so a signer cannot classify any input or output and would refuse every request: %w", multisig.ErrNoAddressInspector)
	}
	magic, err := networkMagic(r.o)
	if err != nil {
		return multisig.Signer{}, "", err
	}
	// Obligation 2: what this signer owns and holds is read from this store.
	dir, err := loadStoreKeys(ctx, r.s.Store)
	if err != nil {
		return multisig.Signer{}, "", err
	}
	idx := labels.NewIndex(r.s.Anchored)
	// The role history of an identity, from the stored key records, until the
	// workspace's role-history record exists (ADR 0010 decision 1).
	history := func(ctx context.Context, id identity.Ref) (custody.RoleHistory, bool, error) {
		return ports.RoleHistoryOf(ctx, idx, id)
	}
	sg := multisig.Signer{Node: r.node(), Signers: r.env.Signers, Keys: dir, History: history, NetworkMagic: magic, Owned: dir.Owned(), Addresses: k.Addresses,
		Gate: passphraseGate{a: r.a, s: r.s, note: func() string { return r.gateNote }}}
	// Obligation 3: the resolver is the operator's own provider or a snapshot
	// the operator named, and nothing else.
	why := ""
	switch {
	case snapshot != "":
		if r.env.SnapshotResolver == nil {
			return multisig.Signer{}, "", errors.New("this build reads no offline snapshot")
		}
		data, real, err := r.readSnapshot(snapshot, d)
		if err != nil {
			return multisig.Signer{}, "", err
		}
		p, err := r.privateCopy(data)
		if err != nil {
			return multisig.Signer{}, "", err
		}
		sg.Resolver = multisig.OwnSnapshot(r.env.SnapshotResolver(p)) // the bytes of the operator's own file: judged above
		why = "your own snapshot " + real
	case r.env.OwnUtxos != nil:
		sg.Resolver = multisig.OwnProvider(r.env.OwnUtxos) // the provider this workspace is configured with
		why = "the provider this workspace is configured with"
		if s := r.env.Source(CapUtxos); s != "" {
			why += " (" + s + ")"
		}
	default:
		why = "none: this workspace's mode has no provider of its own to ask (light mode has one), and no --own-snapshot was given"
	}
	// An invitation carries the coordinator's tailcat address: a sealed record.
	sg.OnInvite = func(w ports.NamedWriter, from party.Party, inv party.Invite) error {
		buf, err := secret.TryTake([]byte(inv.Address))
		if err != nil {
			return err
		}
		defer buf.Destroy()
		return w.PutSecret(ports.NamedRef{Name: from.Name, Kind: ports.TailcatAddr}, buf)
	}
	return sg, why, nil
}

// mapSignerErr turns the errors a signer's Handle can return into the sentence
// an operator needs. A missing address inspector is a configuration error,
// never presented as a refusal of a request.
func mapSignerErr(err error) error {
	if errors.Is(err, multisig.ErrNoAddressInspector) {
		return fmt.Errorf("configuration error, not a refusal of the request: %w", err)
	}
	return err
}
