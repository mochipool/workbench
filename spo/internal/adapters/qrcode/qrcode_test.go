package qrcode

import (
	"bytes"
	"errors"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/ports"
)

const payload = "01000102030405060708090a0b0c0d0e0f6465666768696a6b6c6d6e6fda6cf38a6d4b47df2b250777a067c1ee9e4af75fb198a996349f71256fc8455bc2391fcee820ffa6c5bb702dcb26cb819baf1848add77cb1a6643b9c412e7cc7c8b29a87c24e15460d9a50c16a08e668"

// spec: SPO-09a-EXT-005, SPO-09a-PRE-010, SPO-Pfiles-SEC-001
func TestWritePNGIsPrivateAndNeverOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k.catalyst-qrcode.png")
	if err := (Renderer{}).WritePNG(path, []byte(payload)); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", st, err)
	}
	b, _ := os.ReadFile(path)
	img, err := png.Decode(bytes.NewReader(b))
	if err != nil || img.Bounds().Dx() != img.Bounds().Dy() || img.Bounds().Dx() < 100 {
		t.Fatalf("not a square PNG: %v", err)
	}
	// A second write is refused and leaves the first alone.
	if err := (Renderer{}).WritePNG(path, []byte(payload)); !errors.Is(err, ports.ErrQRFileExists) {
		t.Errorf("overwrite: %v", err)
	}
	if b2, _ := os.ReadFile(path); !bytes.Equal(b, b2) {
		t.Error("the file changed")
	}
	// A symbolic link at the path is not written through.
	target := filepath.Join(t.TempDir(), "target")
	link := filepath.Join(t.TempDir(), "link.png")
	if err := os.Symlink(target, link); err != nil {
		t.Skip(err)
	}
	if err := (Renderer{}).WritePNG(link, []byte(payload)); err == nil {
		t.Error("wrote through a symlink")
	}
	if _, err := os.Stat(target); err == nil {
		t.Error("the link target was created")
	}
}

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
