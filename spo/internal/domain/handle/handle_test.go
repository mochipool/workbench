package handle

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// spec: SPO-Caddr-IF-001, SPO-Caddr-PRE-004
func TestParseLowercasesAndChecksTheFormat(t *testing.T) {
	h, err := Parse("$AlIcE")
	if err != nil || h.Name != "alice" || h.Sub {
		t.Fatalf("%+v %v", h, err)
	}
	h, err = Parse("$00F@Hal")
	if err != nil || h.Name != "00f@hal" || !h.Sub || h.NameHex() != "3030664068616c" {
		t.Fatalf("%+v %v", h, err)
	}
	for _, bad := range []string{"", "alice", "$", "$a@b@c", "$a b", "$@b", "$a@", "$" + "abcdefghijklmnop", "$ü"} {
		if _, err := Parse(bad); !errors.Is(err, ErrFormat) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// The address in the inline datum of a recorded virtual sub-handle of the
// Preview network ($00f@hal, public data, spo/internal/adapters/koios/testdata)
// is the address the Handle API states for it. A base address is read from
// the datum and encoded with addr_test; the mainnet prefix is addr.
//
// spec: SPO-Caddr-INV-007, SPO-Caddr-INV-008
func TestDatumAddressAgainstARecordedHandle(t *testing.T) {
	read := func(name string) []byte {
		b, err := os.ReadFile("../../adapters/koios/testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var rec struct {
		Resolved struct{ Ada string } `json:"resolved_addresses"`
	}
	if err := json.Unmarshal(read("handle_api_virtual_subhandle.json"), &rec); err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Datum struct{ Bytes string } `json:"inline_datum"`
	}
	if err := json.Unmarshal(read("handle_asset_utxos_virtual.json"), &rows); err != nil || len(rows) != 1 {
		t.Fatal(err, rows)
	}
	got, err := DatumAddress(rows[0].Datum.Bytes, false)
	if err != nil || got != rec.Resolved.Ada {
		t.Fatalf("%q %v, the Handle API says %q", got, err, rec.Resolved.Ada)
	}
	main, err := DatumAddress(rows[0].Datum.Bytes, true)
	if err != nil || main[:5] != "addr1" {
		t.Errorf("mainnet prefix: %q %v", main, err)
	}
	for _, bad := range []string{"", "d8799f00ff", "7265736f6c7665645f616464726573736573", "7265736f6c7665645f616464726573736573436164615839" + "00"} {
		if _, err := DatumAddress(bad, false); !errors.Is(err, ErrDatum) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}
