package txflow

import (
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/domain/txparam"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ExtrasPorts are the ports the extra parameters need: the reader of user
// metadata files and the CIP-83 encrypter. Either may be nil when the
// composition never receives a request that needs it; a request that does is
// then refused with ErrMisconfigured, not skipped.
type ExtrasPorts struct {
	Files     ports.MetadataFileReader
	Encrypter ports.MessageEncrypter
}

// ResolvedExtras is the metadata of the extra parameters, ready for a draft:
// the user files read and checked, and the message lines, encrypted when the
// mode asks for it.
type ResolvedExtras struct {
	Files      []txbuild.MetadataFile
	Lines      []string
	Encryption string
}

// ResolveExtras reads and checks the metadata files, then encrypts the
// message lines when `enc:basic` was given. lines are the message lines the
// request already carries (a plain Message field); the extras' own lines
// follow them. Nothing is built, queried or written.
//
// spec: SPO-Pparam-IF-010, SPO-Pparam-IF-011, SPO-Pparam-IF-012, SPO-Pparam-IF-013, SPO-Pparam-IF-014,
// spec: SPO-Pparam-IF-015, SPO-Pparam-IF-016, SPO-Pparam-PRE-005, SPO-Pparam-EXT-001, SPO-Pparam-SEC-001
func ResolveExtras(p ExtrasPorts, ex *txparam.Extras, lines []string, pass *ports.Secret) (ResolvedExtras, error) {
	out := ResolvedExtras{Lines: append([]string(nil), lines...)}
	if ex == nil {
		return out, nil
	}
	if err := txparam.CheckMessages(ex.Messages); err != nil {
		return ResolvedExtras{}, err
	}
	out.Lines = append(out.Lines, ex.Messages...)
	if err := txparam.CheckMessages(out.Lines); err != nil {
		return ResolvedExtras{}, err
	}
	if len(ex.MetadataFiles) > 0 && p.Files == nil {
		return ResolvedExtras{}, fmt.Errorf("%w: no reader for metadata files", ErrMisconfigured)
	}
	for _, f := range ex.MetadataFiles {
		data, err := p.Files.ReadMetadataFile(f.Path)
		if err != nil {
			if errors.Is(err, ports.ErrNotFound) {
				return ResolvedExtras{}, fmt.Errorf("%w: %v", txparam.ErrBadMetadataFile, err)
			}
			return ResolvedExtras{}, err
		}
		format := txbuild.MetadataJSON
		if f.Format == txparam.FileCBOR {
			format = txbuild.MetadataCBOR
		} else if err := txparam.CheckMetadataJSON(f.Path, data); err != nil {
			return ResolvedExtras{}, err
		}
		out.Files = append(out.Files, txbuild.MetadataFile{Name: f.Path, Format: format, Data: data})
	}
	switch ex.Encryption {
	case "":
	case "basic":
		if len(out.Lines) == 0 {
			break // enc: without a message has no effect (IF-013)
		}
		if p.Encrypter == nil {
			return ResolvedExtras{}, fmt.Errorf("%w: no message encrypter", ErrMisconfigured)
		}
		enc, err := p.Encrypter.EncryptMessages(out.Lines, pass)
		if err != nil {
			return ResolvedExtras{}, fmt.Errorf("encrypt the message: %w", err)
		}
		out.Lines, out.Encryption = enc, "basic"
	default:
		return ResolvedExtras{}, fmt.Errorf("%w: %q", txparam.ErrBadEncryption, ex.Encryption)
	}
	return out, nil
}

// Attach puts the resolved metadata on a draft.
func (r ResolvedExtras) Attach(d txbuild.Draft) (txbuild.Draft, error) {
	return d.WithMetadata(r.Files, r.Lines, r.Encryption)
}

// FilterCandidates applies the UTxO filters of the extras to the UTxOs of
// the paying address. With no extras the set is returned unchanged. The
// selection strategy then chooses among the candidates (hazard H4).
func FilterCandidates(ex *txparam.Extras, utxos []chain.Utxo) []chain.Utxo {
	if ex == nil || !ex.HasFilters() {
		return utxos
	}
	return txparam.FilterUtxos(utxos, *ex)
}
