package qrcode

import (
	"strings"
	"testing"
)

const payload = "01000102030405060708090a0b0c0d0e0f6465666768696a6b6c6d6e6fda6cf38a6d4b47df2b250777a067c1ee9e4af75fb198a996349f71256fc8455bc2391fcee820ffa6c5bb702dcb26cb819baf1848add77cb1a6643b9c412e7cc7c8b29a87c24e15460d9a50c16a08e668"

// spec: SPO-09a-OUT-007
func TestTerminalDrawing(t *testing.T) {
	s, err := (Renderer{}).Terminal([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) < 20 || strings.Count(s, "█") == 0 {
		t.Errorf("drawing: %d lines", len(lines))
	}
	w := len([]rune(lines[0]))
	for _, l := range lines {
		if len([]rune(l)) != w {
			t.Fatalf("ragged line %q", l)
		}
	}
	if _, err := (Renderer{}).Terminal(nil); err == nil {
		t.Error("empty payload")
	}
}
