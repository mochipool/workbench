package relayself

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// MaxBindingFileBytes bounds a binding file (SPO-Xparty-IF-009); a reader
// refuses a larger one before it reads it all.
const MaxBindingFileBytes = 2048

// ErrBindingFile: the file is not a binding file of this version.
var ErrBindingFile = errors.New("not a binding file: want {\"v\": 1, \"statement\": hex, \"cose_key\": hex}, at most 2048 bytes")

type bindingFile struct {
	V         int    `json:"v"`
	Statement string `json:"statement"`
	COSEKey   string `json:"cose_key"`
}

// EncodeBindingFile is the companion file of the identity document: this
// device's binding (SPO-Xparty-IF-009).
func EncodeBindingFile(statement, key []byte) ([]byte, error) {
	if len(statement) == 0 || len(statement) > relaybind.MaxSign1Bytes || len(key) == 0 || len(key) > relaybind.MaxKeyBytes {
		return nil, ErrBindingFile
	}
	b, err := json.Marshal(bindingFile{V: 1, Statement: hx(statement), COSEKey: hx(key)})
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// DecodeBindingFile reads a binding file strictly (SPO-Xparty-IF-009): the
// size first, then strict JSON of version 1 with lower-case hex of 1 to 512 and
// 1 to 128 bytes. It does not verify the binding: the evidence check does.
func DecodeBindingFile(b []byte) (statement, key []byte, err error) {
	if len(b) > MaxBindingFileBytes {
		return nil, nil, fmt.Errorf("%w: %d bytes", ErrBindingFile, len(b))
	}
	var f bindingFile
	if err := ports.UnmarshalStrict(b, &f); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrBindingFile, err)
	}
	if f.V != 1 {
		return nil, nil, fmt.Errorf("%w: version %d", ErrBindingFile, f.V)
	}
	if statement, err = unhx(f.Statement, 1, relaybind.MaxSign1Bytes); err != nil {
		return nil, nil, fmt.Errorf("%w: the statement: %v", ErrBindingFile, err)
	}
	if key, err = unhx(f.COSEKey, 1, relaybind.MaxKeyBytes); err != nil {
		return nil, nil, fmt.Errorf("%w: the key: %v", ErrBindingFile, err)
	}
	return statement, key, nil
}

// BindingFile is this device's current binding as the companion file, or
// ErrNoBinding.
//
// spec: SPO-Xparty-IF-009
func (s State) BindingFile() ([]byte, error) {
	if s.Binding == nil {
		return nil, ErrNoBinding
	}
	return EncodeBindingFile(s.Binding.Statement, s.Binding.Key)
}
