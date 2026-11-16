package main

import (
	"context"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// The sealed workspace folds its write-ahead log on request, so that a party
// rotation does not leave the replaced old keys in it.
var _ ports.WALCheckpointer = sealedStore{}

// CheckpointWAL implements ports.WALCheckpointer.
func (w sealedStore) CheckpointWAL(ctx context.Context) error { return w.s.CheckpointWAL(ctx) }
