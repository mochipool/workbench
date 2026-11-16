package secret

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestTakeWipesSource(t *testing.T) {
	src := []byte("5820aabbccddeeff")
	s := Take(src)
	defer s.Destroy()
	if !bytes.Equal(src, make([]byte, len(src))) {
		t.Fatal("source was not wiped")
	}
	var got []byte
	if err := s.Use(func(b []byte) error { got = append(got, b...); return nil }); err != nil {
		t.Fatal(err)
	}
	if string(got) != "5820aabbccddeeff" {
		t.Fatalf("content changed: %q", got)
	}
}

// E8: a secret must not leak through formatting or serialisation.
func TestNeverPrintsOrSerialises(t *testing.T) {
	s := Take([]byte("topsecretkey"))
	defer s.Destroy()
	for _, out := range []string{
		fmt.Sprint(s), fmt.Sprintf("%v", s), fmt.Sprintf("%+v", s), fmt.Sprintf("%#v", s), fmt.Sprintf("%s", s),
	} {
		if strings.Contains(out, "topsecret") {
			t.Fatalf("leaked through formatting: %q", out)
		}
	}
	if _, err := json.Marshal(s); err == nil {
		t.Fatal("JSON serialisation of a secret succeeded")
	}
}

func TestUseAfterDestroy(t *testing.T) {
	s := New(32)
	s.Destroy()
	s.Destroy()
	if err := s.Use(func([]byte) error { return nil }); err != ErrDestroyed {
		t.Fatalf("got %v, want ErrDestroyed", err)
	}
}

func TestHardenProcess(t *testing.T) {
	if err := HardenProcess(); err != nil {
		t.Fatal(err)
	}
}
