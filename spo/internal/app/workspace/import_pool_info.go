package workspace

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals of the pool import and export (upstream 0x_importHelper).
var (
	// ErrOffline: a pool id needs a chain reader; offline mode has none, and the
	// export needs the online source (SPO-0x-PRE-001, SPO-0x-PRE-002).
	ErrOffline = errors.New("no chain reader is available (offline mode): give an info file made on an online machine")
	// ErrBadPoolID: the argument is neither 56 hex digits nor a pool1 id
	// (SPO-0x-IN-002).
	ErrBadPoolID = errors.New("not a pool id: 56 hexadecimal digits or a bech32 pool1... id")
	// ErrBadInfo: the info is not usable (SPO-0x-IN-001).
	ErrBadInfo = errors.New("the pool info is not usable")
	// ErrPoolNotOnChain: the provider says the pool does not exist.
	ErrPoolNotOnChain = errors.New("the chain provider says this pool does not exist")
	// ErrChainUnreadable: the provider did not say (a failed or empty read). It
	// is never taken for "no such pool".
	ErrChainUnreadable = errors.New("the pool could not be read from the chain provider")
	// ErrMetadata: the published metadata cannot be fetched or is not JSON
	// (SPO-0x-EXT-003).
	ErrMetadata = errors.New("the published pool metadata cannot be used")
	// ErrMetadataHash: the fetched metadata does not hash to the registered
	// meta_hash.
	ErrMetadataHash = errors.New("the published pool metadata does not match the registered hash")
	// ErrExportExists: the export file exists (SPO-0x-PRE-003).
	ErrExportExists = errors.New("the export file already exists")
)

// PoolInfoSource is where the pool's registration data comes from: a pool id,
// to read from the chain, or the content of an info file (SPO-0x-IF-003).
type PoolInfoSource struct {
	// PoolID is 56 hex digits or a pool1... id.
	PoolID string
	// InfoFile is the content of an info file; it wins when both are set, as an
	// existing file does upstream.
	InfoFile []byte
	// AcceptMetadataMismatch takes a published metadata document whose hash is
	// not the registered one (the pool changed it after registering).
	AcceptMetadataMismatch bool
}

// PoolInfoAcquirer holds the ports that read a pool's registration data.
type PoolInfoAcquirer struct {
	Pools    ports.PoolInfoReader // nil: offline mode
	Updates  ports.PoolUpdateReader
	Metadata ports.MetadataFetcher
	Hasher   ports.PoolMetadataHasher
}

// metaURLOK is the check of SPO-0x-IN-001: `https?://...`, at most 64
// characters.
func metaURLOK(u string) bool {
	return (strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://")) && len(u) <= 64
}

// Acquire gets the info: from the info file, or from the chain (pool_info, the
// latest pool_updates, the published metadata). The reads are three-valued: a
// pool that does not exist is ErrPoolNotOnChain, a failed or empty read is
// ErrChainUnreadable with the provider's reason, and neither is taken for the
// other. The published metadata is checked against the registered hash; a
// difference is refused unless the source says to accept it, because the
// metadata text goes into the descriptor (SPO-0x-SEC-003).
//
// spec: SPO-0x-IF-003, SPO-0x-IN-001, SPO-0x-IN-002, SPO-0x-PRE-001, SPO-0x-EXT-001, SPO-0x-EXT-002, SPO-0x-EXT-003, SPO-0x-INV-001, SPO-0x-MODE-001
func (a PoolInfoAcquirer) Acquire(ctx context.Context, src PoolInfoSource) (chain.PoolInfo, error) {
	if len(src.InfoFile) > 0 {
		info, err := chain.ParsePoolInfo(src.InfoFile)
		if err != nil {
			return chain.PoolInfo{}, fmt.Errorf("%w: %v", ErrBadInfo, err)
		}
		if !metaURLOK(info.MetaURL) {
			return chain.PoolInfo{}, fmt.Errorf("%w: meta_url must be http(s):// and at most 64 characters", ErrBadInfo)
		}
		return info, nil
	}
	word, err := stake.ParsePoolWord(src.PoolID)
	if err != nil || !word.IsID {
		return chain.PoolInfo{}, ErrBadPoolID
	}
	if a.Pools == nil || a.Updates == nil || a.Metadata == nil {
		return chain.PoolInfo{}, ErrOffline
	}
	rd, err := a.Pools.PoolInfo(ctx, word.Pool)
	if err != nil {
		return chain.PoolInfo{}, fmt.Errorf("%w: %v", ErrChainUnreadable, err)
	}
	info, ok := rd.Get()
	switch {
	case rd.IsNone():
		return chain.PoolInfo{}, ErrPoolNotOnChain
	case !ok:
		return chain.PoolInfo{}, fmt.Errorf("%w: %s", ErrChainUnreadable, rd.Why())
	}
	if info.IDBech != word.Pool.Bech32() {
		return chain.PoolInfo{}, fmt.Errorf("%w: the provider answered for another pool", ErrChainUnreadable)
	}
	if !metaURLOK(info.MetaURL) {
		return chain.PoolInfo{}, fmt.Errorf("%w: meta_url must be http(s):// and at most 64 characters", ErrBadInfo)
	}
	ud, err := a.Updates.LatestPoolUpdate(ctx, word.Pool)
	if err != nil {
		return chain.PoolInfo{}, fmt.Errorf("%w: %v", ErrChainUnreadable, err)
	}
	upd, ok := ud.Get()
	switch {
	case ud.IsNone():
		return chain.PoolInfo{}, fmt.Errorf("%w: the pool has no update", ErrPoolNotOnChain)
	case !ok:
		return chain.PoolInfo{}, fmt.Errorf("%w: %s", ErrChainUnreadable, ud.Why())
	}
	info.HasLastUpdate, info.LastUpdateTime, info.LastUpdateEpoch = true, upd.BlockTime, upd.ActiveEpoch

	raw, err := a.Metadata.Fetch(ctx, info.MetaURL)
	if err != nil {
		return chain.PoolInfo{}, fmt.Errorf("%w: %v", ErrMetadata, err)
	}
	if len(raw) > pool.MaxMetadataBytes {
		return chain.PoolInfo{}, fmt.Errorf("%w: larger than %d bytes", ErrMetadata, pool.MaxMetadataBytes)
	}
	var compact bytes.Buffer
	if json.Valid(raw) && json.Compact(&compact, raw) == nil {
		info.Metadata = append(json.RawMessage(nil), compact.Bytes()...)
	} else {
		return chain.PoolInfo{}, fmt.Errorf("%w: not JSON", ErrMetadata)
	}
	if a.Hasher != nil && info.MetaHash != "" && !src.AcceptMetadataMismatch {
		h, err := a.Hasher.MetadataHash(raw)
		if err != nil {
			return chain.PoolInfo{}, fmt.Errorf("%w: %v", ErrMetadata, err)
		}
		if hex.EncodeToString(h[:]) != strings.ToLower(info.MetaHash) {
			return chain.PoolInfo{}, ErrMetadataHash
		}
	}
	return info, nil
}

// ExportPoolInfo writes a pool's public registration data to a file, so that
// an offline machine, which cannot query the chain, can import from it
// (upstream 0x_importHelper with a third argument). Where upstream ends with
// exit 1 even on success (SPO-0x-INV-002), success is a nil error.
type ExportPoolInfo struct {
	PoolInfoAcquirer
	// Sink writes the export file; it refuses a name that is not a plain file
	// name.
	Sink ports.FileSink
	// Attacher adds the file to the transfer file when the request asks.
	Attacher ports.TransferAttacher
}

// ExportRequest names the source and the file.
type ExportRequest struct {
	Source PoolInfoSource
	// File is the plain name of the export file.
	File string
	// Attach adds the file to the transfer file (the prompt of SPO-0x-PR-001,
	// default no).
	Attach bool
}

// Exported is the result.
type Exported struct {
	File     string
	Info     chain.PoolInfo
	Attached bool
}

// Run exports.
//
// spec: SPO-0x-IF-004, SPO-0x-PRE-002, SPO-0x-PRE-003, SPO-0x-OUT-001, SPO-0x-PR-001, SPO-0x-INV-002
func (uc ExportPoolInfo) Run(ctx context.Context, req ExportRequest) (Exported, error) {
	if uc.Pools == nil {
		return Exported{}, ErrOffline
	}
	if uc.Sink == nil || req.File == "" {
		return Exported{}, errors.New("an export needs a file name and a file sink")
	}
	info, err := uc.Acquire(ctx, req.Source)
	if err != nil {
		return Exported{}, err
	}
	content := info.JSON()
	written, err := uc.Sink.WriteFile(ctx, req.File, content, false)
	if err != nil {
		return Exported{}, err
	}
	if !written {
		return Exported{}, fmt.Errorf("%w: %s", ErrExportExists, req.File)
	}
	res := Exported{File: req.File, Info: info}
	if req.Attach {
		if uc.Attacher == nil {
			return res, errors.New("no transfer file is available to attach the export to")
		}
		if err := uc.Attacher.Attach(ctx, req.File, content); err != nil {
			return res, fmt.Errorf("the file was written but not attached: %w", err)
		}
		res.Attached = true
	}
	return res, nil
}
