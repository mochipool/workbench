package uihint

import (
	"reflect"
	"testing"

	"github.com/spf13/cobra"
)

func TestHintsRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		enc  string
		want Spec
	}{
		{Names(ClassPool), Spec{Kind: KindName, Class: ClassPool}},
		{File(), Spec{Kind: KindFile}},
		{File(".json", ".cbor"), Spec{Kind: KindFile, Exts: []string{".json", ".cbor"}}},
		{NewFile(".json"), Spec{Kind: KindNewFile, Exts: []string{".json"}}},
		{Dir(), Spec{Kind: KindDir}},
	} {
		got, ok := Decode(tc.enc)
		if !ok || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("Decode(%q) = %+v, %v; want %+v", tc.enc, got, ok, tc.want)
		}
	}
	for _, bad := range []string{"", "name", "name:nonsense", "wat:x"} {
		if _, ok := Decode(bad); ok {
			t.Errorf("Decode(%q) accepted", bad)
		}
	}
}

// The group annotations are cobra's private strings; this fails when a cobra
// upgrade renames them, so the form never silently loses its exclusions.
func TestGroupsReadCobraAnnotations(t *testing.T) {
	c := &cobra.Command{Use: "x"}
	c.Flags().String("a", "", "")
	c.Flags().String("b", "", "")
	c.Flags().String("c", "", "")
	c.MarkFlagsMutuallyExclusive("a", "b")
	c.MarkFlagsRequiredTogether("b", "c")
	c.MarkFlagsOneRequired("a", "c")
	got := Groups(c)
	want := []Group{{Exclusive, []string{"a", "b"}}, {Together, []string{"b", "c"}}, {OneRequired, []string{"a", "c"}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Groups = %+v, want %+v", got, want)
	}
}
