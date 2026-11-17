package identity

import "testing"

// One tag that is a prefix of another must not make two identities collide
// under concatenation of tag and bytes. The registry has no such pair now (a
// JSON-mapped kind has only its mapped tag), so the test registers one.
//
// spec: SPO-Xidentity-INV-008
func TestPrefixTagsDoNotCollide(t *testing.T) {
	short, long := Tag("spo/obj/v1/test-prefix"), Tag("spo/obj/v1/test-prefix/map1")
	tags[short], tags[long] = KindAuditEvent, KindAuditEvent
	defer delete(tags, short)
	defer delete(tags, long)
	for _, c := range []struct{ a, b any }{
		{"/map1xyz", "xyz"},
		{[]byte("/map1xyz"), []byte("xyz")},
	} {
		x, err := ContentOf(short, c.a)
		if err != nil {
			t.Fatal(err)
		}
		y, err := ContentOf(long, c.b)
		if err != nil {
			t.Fatal(err)
		}
		if x == y {
			t.Errorf("%v / %v collide", c.a, c.b)
		}
	}
}
