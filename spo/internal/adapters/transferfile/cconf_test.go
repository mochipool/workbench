package transferfile

import (
	"context"
	"errors"
	"testing"
)

// Offline, the era is `protocol.era` of the transfer file. Upstream reads it
// without a null filter and gets the text `null`, which the era resolution
// maps to `auto`; the port refuses a file with no era.
//
// spec: SPO-Cconf-MODE-007, SPO-Cconf-OUT-005
func TestOfflineEraIsProtocolEra(t *testing.T) {
	if era, err := write(t, snapshot).Era(context.Background()); err != nil || era != "conway" {
		t.Fatalf("%q %v", era, err)
	}
	if _, err := write(t, `{"protocol":{"parameters":{}}}`).Era(context.Background()); !errors.Is(err, ErrInvalidFile) {
		t.Fatalf("a file without protocol.era: %v", err)
	}
}
