package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/domain/txparam"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// The extra parameters of a transaction command (spec/upstream Pparam, the
// words after the mandatory arguments of upstream's scripts) are dedicated
// flags here, not trailing words: a flag is checked by the command line before
// anything runs, appears in --help, and cannot be mistaken for an argument.
//
//	--message TEXT            one CIP-20 line, at most 64 bytes (repeatable; the command's own flag)
//	--metadata-file FILE      a .json or .cbor metadata file, in command-line order (repeatable)
//	--encrypt-messages        CIP-83 `basic` encryption of the message lines
//	--message-passphrase-fd N the encryption passphrase from a descriptor; else asked for without echo
//	--utxo-limit N            spend at most N UTxOs (payments and asset sends)
//	--only-utxo-with-asset ID spend only UTxOs that hold the asset (repeatable)
//	--skip-utxo-with-asset ID never spend UTxOs that hold the asset (repeatable)
//	--input TXHASH#IX         spend exactly these UTxOs (repeatable)
//
// Each flag is turned into the equivalent upstream word and parsed by
// txparam.Parse with the acceptance row of the command, so the domain's
// refusals (a bad extension, a malformed reference, a limit of zero, a message
// of the wrong size) are the ones upstream's grammar has. The passphrase is
// never a word: it goes from the terminal or the descriptor into guarded
// memory and stays there.

type extraKind int

const (
	// extraCert: certificate transactions (stake, pool, DRep, committee, vote,
	// action): messages, metadata files, encryption.
	extraCert extraKind = iota
	// extraSend: payments: the above and the UTxO filters.
	extraSend
	// extraAssets: asset sends: the above, --lovelace and --keep-policy.
	extraAssets
	// extraMint: mint and burn: messages, metadata files, encryption, --input.
	extraMint
)

type extraFlags struct {
	kind  extraKind
	msgs  *[]string
	files []string
	// records are stored registration records (`<name>.calidus-registration.json`,
	// `<name>.vote-registration.cbor`) attached like metadata files, read
	// through the workspace and never exported to disk.
	records []string
	// only, skip and inputs are lists; each flag value is one list entry.
	only, skip, inputs []string
	keep               []string
	limit              string
	lovelace           string
	encrypt            bool
	passFD             int

	// ex is the parsed result, nil when no extra parameter was given.
	ex *txparam.Extras
	// pass is the message passphrase, held between withEnv's prompt and the
	// end of the command; nil means the CIP-83 default.
	pass *ports.Secret
}

func (f *extraFlags) add(cmd *cobra.Command, msgs *[]string, kind extraKind) {
	f.kind, f.msgs, f.passFD = kind, msgs, -1
	fl := cmd.Flags()
	fl.StringArrayVar(&f.files, "metadata-file", nil, "attach a metadata file, .json or .cbor, as another label of the transaction's metadata (repeatable)")
	fl.StringArrayVar(&f.records, "metadata-record", nil, "attach a registration record of the workspace as metadata, by the name the registration command printed (NAME.calidus-registration.json or NAME.vote-registration.cbor; repeatable); no file is written")
	fl.BoolVar(&f.encrypt, "encrypt-messages", false, "encrypt the --message lines with CIP-83 basic encryption; the passphrase is asked for without echo, or read from --message-passphrase-fd (an empty one is the CIP-83 default, \"cardano\")")
	fl.IntVar(&f.passFD, "message-passphrase-fd", -1, "read the message passphrase from this inherited file descriptor (trailing newline stripped); there is no passphrase flag or variable")
	if kind == extraSend || kind == extraAssets {
		fl.StringVar(&f.limit, "utxo-limit", "", "spend at most this many UTxOs of the source")
		fl.StringArrayVar(&f.only, "only-utxo-with-asset", nil, "spend only UTxOs that hold this asset: a policy id, or a policy id and the asset name in hex (repeatable)")
		fl.StringArrayVar(&f.skip, "skip-utxo-with-asset", nil, "never spend UTxOs that hold this asset: a policy id, or a policy id and the asset name in hex (repeatable)")
	}
	if kind != extraCert {
		fl.StringArrayVar(&f.inputs, "input", nil, "spend exactly this UTxO, TXHASH#INDEX (repeatable)")
	}
	if kind == extraAssets {
		fl.StringVar(&f.lovelace, "lovelace", "", "send this many lovelace along with the assets (raised to the destination's minimum)")
		fl.StringArrayVar(&f.keep, "keep-policy", nil, "with ALLASSETS: keep the assets of this policy id on the source (repeatable)")
	}
}

func (f *extraFlags) accepts() txparam.Accepts {
	switch f.kind {
	case extraSend:
		return txparam.ForSendLovelaces
	case extraAssets:
		return txparam.ForSendAssets
	case extraMint:
		return txparam.ForMint
	}
	return txparam.ForCertificate
}

// words returns the upstream words the flags stand for.
func (f *extraFlags) words() ([]string, error) {
	var w []string
	for _, p := range f.files {
		if strings.TrimSpace(p) == "" {
			return nil, errors.New("--metadata-file needs a file name")
		}
		w = append(w, p)
	}
	for _, r := range f.records {
		if _, err := recordRef(r); err != nil {
			return nil, err
		}
		w = append(w, r) // the extension tells the format
	}
	list := func(flag, key string, vals []string) error {
		if len(vals) == 0 {
			return nil
		}
		for _, v := range vals {
			if strings.TrimSpace(v) == "" || strings.Contains(v, "|") {
				return fmt.Errorf("%s: %q is not one entry (repeat the flag instead of using |)", flag, v)
			}
		}
		w = append(w, key+strings.Join(vals, "|"))
		return nil
	}
	if f.limit != "" {
		w = append(w, "utxolimit:"+f.limit)
	}
	if err := list("--only-utxo-with-asset", "onlyutxowithasset:", f.only); err != nil {
		return nil, err
	}
	if err := list("--skip-utxo-with-asset", "skiputxowithasset:", f.skip); err != nil {
		return nil, err
	}
	if err := list("--input", "", f.inputs); err != nil {
		return nil, err
	}
	if err := list("--keep-policy", "keeppolicy:", f.keep); err != nil {
		return nil, err
	}
	if f.lovelace != "" {
		if strings.Trim(f.lovelace, "0123456789") != "" {
			return nil, fmt.Errorf("--lovelace: %q is not a number of lovelace", f.lovelace)
		}
		w = append(w, f.lovelace)
	}
	if f.encrypt {
		w = append(w, "enc:basic")
	}
	return w, nil
}

// parse turns the flags into Extras. It reads no file and asks nothing.
func (f *extraFlags) parse() error {
	f.ex = nil
	words, err := f.words()
	if err != nil {
		return err
	}
	messages := 0
	if f.msgs != nil {
		messages = len(*f.msgs)
	}
	encrypting := f.encrypt && messages > 0
	if len(words) == 0 {
		return nil
	}
	// An entry that is not a reference would be taken as a file word by the
	// grammar; say what the flag wanted.
	if len(f.inputs) > 0 {
		chk, err := txparam.Parse([]string{strings.Join(f.inputs, "|")}, txparam.Accepts{UtxoList: txparam.Effect})
		if err != nil && !errors.Is(err, txparam.ErrBadUtxoRef) || err == nil && len(chk.Inputs) == 0 {
			return fmt.Errorf("%w: --input takes TXHASH#INDEX, not %q", txparam.ErrBadUtxoRef, strings.Join(f.inputs, "|"))
		} else if err != nil {
			return err
		}
	}
	// The message lines are the command's own flag and are kept verbatim (a
	// line may hold a | here, which the upstream word would split): the
	// parser is given them as options, so the encryption mode survives
	// although the words hold no msg: word. The use case encrypts whatever
	// lines it gets, and refuses a mode other than basic.
	opt := txparam.Options{}
	if f.msgs != nil {
		opt.Messages = *f.msgs
	}
	if f.encrypt {
		opt.Encryption = "basic"
	}
	ex, err := txparam.ParseWith(words, f.accepts(), opt)
	if err != nil {
		return err
	}
	if !encrypting && !ex.HasFilters() && len(ex.MetadataFiles) == 0 && !ex.HasLovelaces && len(ex.KeepPolicies) == 0 {
		return nil
	}
	f.ex = &ex
	return nil
}

// needs are the capabilities the given flags use.
func (f *extraFlags) needs() []Need {
	var n []Need
	if len(f.files) > 0 || len(f.records) > 0 {
		n = append(n, CapMetaFiles)
	}
	if f.encrypt && f.msgs != nil && len(*f.msgs) > 0 {
		n = append(n, CapMsgEncrypt)
	}
	return n
}

// secret reads the message passphrase when the messages are encrypted. It
// returns nil for the CIP-83 default.
func (a *app) messagePassphrase(ctx context.Context, f *extraFlags) (*ports.Secret, error) {
	if !f.encrypt || f.msgs == nil || len(*f.msgs) == 0 {
		return nil, nil
	}
	if f.passFD >= 0 {
		if a.passFD == f.passFD {
			return nil, errors.New("--message-passphrase-fd and --passphrase-fd name the same descriptor")
		}
		return readFDSecret(f.passFD, "the message passphrase")
	}
	p, err := a.term.ReadSecret(ctx, "Message passphrase (empty for the CIP-83 default): ")
	if errors.Is(err, ErrNoTerminal) {
		return nil, errors.New("no terminal to ask for the message passphrase on; give it on a file descriptor with --message-passphrase-fd N")
	}
	if err != nil {
		return nil, err
	}
	if p.Len() == 0 {
		p.Destroy()
		return nil, nil
	}
	again, err := a.term.ReadSecret(ctx, "Repeat the message passphrase: ")
	if err != nil {
		p.Destroy()
		return nil, err
	}
	same := equalSecrets(p, again)
	again.Destroy()
	if !same {
		p.Destroy()
		return nil, errors.New("the two entries differ; nothing was done")
	}
	return p, nil
}

// recordRef maps the name of a registration record, as the registration
// commands print it, to its artefact.
func recordRef(name string) (ports.NamedRef, error) {
	for _, k := range []ports.Kind{ports.CalidusRegistration, ports.VoteRegistration} {
		if stem, ok := strings.CutSuffix(name, "."+string(k)); ok {
			ref := ports.NamedRef{Name: stem, Kind: k}
			if err := ref.Validate(); err != nil {
				return ports.NamedRef{}, fmt.Errorf("--metadata-record %q: %w", name, err)
			}
			return ref, nil
		}
	}
	return ports.NamedRef{}, fmt.Errorf("--metadata-record %q: give the record's name with its extension, NAME.calidus-registration.json or NAME.vote-registration.cbor, as the registration command printed it", name)
}

// recordFiles reads the records named by --metadata-record through the
// workspace and every other path from the next reader.
type recordFiles struct {
	store   ports.NamedStore
	records map[string]ports.NamedRef
	next    ports.MetadataFileReader
}

func newRecordFiles(store ports.NamedStore, names []string, next ports.MetadataFileReader) (ports.MetadataFileReader, error) {
	m := map[string]ports.NamedRef{}
	for _, n := range names {
		ref, err := recordRef(n)
		if err != nil {
			return nil, err
		}
		m[n] = ref
	}
	return recordFiles{store: store, records: m, next: next}, nil
}

// ReadMetadataFile implements ports.MetadataFileReader.
func (r recordFiles) ReadMetadataFile(path string) ([]byte, error) {
	ref, ok := r.records[path]
	if !ok {
		if r.next == nil {
			return nil, fmt.Errorf("%w: %s", ports.ErrNotFound, path)
		}
		return r.next.ReadMetadataFile(path)
	}
	var b []byte
	err := r.store.View(context.Background(), func(rd ports.NamedReader) error {
		var e error
		b, e = rd.Get(ref)
		return e
	})
	if errors.Is(err, ports.ErrNotFound) {
		return nil, fmt.Errorf("%w: the workspace holds no record %s", ports.ErrNotFound, path)
	}
	return b, err
}
