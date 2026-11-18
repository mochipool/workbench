//go:build unix

package mailboxstore

import (
	"reflect"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/layoutdir"
	objdir "github.com/mochipool/workbench/spo/internal/adapters/objstore/dir"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Remove exists on no type a backup sink can reach, and the mailbox store is no
// sink: it has none of the object ports.
//
// spec: SPO-Xmailbox-SEC-009
func TestRemoveIsOnTheMailboxStoreOnly(t *testing.T) {
	var s any = (*Store)(nil)
	if _, ok := s.(ports.ObjectWriter); ok {
		t.Error("the mailbox store is an ObjectWriter")
	}
	if _, ok := s.(ports.ObjectReader); ok {
		t.Error("the mailbox store is an ObjectReader")
	}
	for _, typ := range []reflect.Type{reflect.TypeOf(&objdir.Store{}), reflect.TypeOf(&layoutdir.Dir{})} {
		for i := range typ.NumMethod() {
			name := typ.Method(i).Name
			if strings.Contains(name, "Remove") || strings.Contains(name, "Delete") || strings.Contains(name, "Unlink") {
				t.Errorf("%v has a %s method", typ, name)
			}
		}
	}
	// and the mailbox store reaches none of the sink types
	if _, ok := s.(ports.ObjectLister); ok {
		t.Error("the mailbox store is an ObjectLister")
	}
}
