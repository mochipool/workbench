package sqlitestore

import (
	"crypto/sha256"

	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// anchorOf is a deterministic anchor identity for a test owner called name.
func anchorOf(name string) identity.Ref {
	sum := sha256.Sum224([]byte("sqlitestore test owner " + name))
	r, err := identity.NewRef(identity.KindKeyHash, sum[:])
	if err != nil {
		panic(err)
	}
	return r
}

// rf is the reference of kind (and number) of the test owner called name.
func rf(name string, k ports.Kind, num ...int) ports.Ref {
	r := ports.Ref{Anchor: anchorOf(name), Kind: k}
	if len(num) > 0 {
		r.Num = num[0]
	}
	return r
}
