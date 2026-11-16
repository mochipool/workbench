package endpoint

import "testing"

func TestSame(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"https://api.koios.rest/api/v1", "https://API.Koios.rest:443/api/v0", true},
		{"https://preview.koios.rest/api/v1", "https://cardano-preview.blockfrost.io/api/v0", false},
		{"/run/node.socket", "http://127.0.0.1:8080/api/v1", true},
		{"unix:/run/node.socket", "https://localhost/api", true},
		{"tcp://[::1]:3001", "http://127.0.0.1:9/x", true},
		{"tcp://10.0.0.5:3001", "https://10.0.0.5/api", true},
		{"tcp://10.0.0.5:3001", "https://10.0.0.6/api", false},
		{"https://koios.example./a", "https://koios.example/b", true},
		{"", "https://x.example", false},
	} {
		if got := Same(c.a, c.b); got != c.want {
			t.Errorf("%q %q: %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// Every spelling of one address is one host: numeric IPv4 forms (decimal,
// hexadecimal, octal, short), IPv4-mapped IPv6, an IPv6 zone, case and trailing
// dots; all of 127.0.0.0/8 and ::1 are this machine.
func TestEquivalentSpellingsAreOneHost(t *testing.T) {
	loopbacks := []string{
		"http://2130706433/x", "http://0x7f000001/x", "http://0177.0.0.1/x", "http://127.1/x", "http://127.0.1/x",
		"http://127.255.255.254/x", "http://[::ffff:127.0.0.1]/x", "http://[::ffff:7f00:1]/x", "http://[::1]/x", "http://[::1%25lo]:3001/x",
		"http://[0:0:0:0:0:0:0:1]/x", "http://LOCALHOST./x", "http://127.0.0.1../x", "http://0.0.0.0/x", "http://0/x", "http://[::]/x",
		"tcp://127.0.0.2:3001", "http://foo.localhost/x",
	}
	for _, a := range loopbacks {
		if h, lb := Host(a); h != Loopback || !lb {
			t.Errorf("%q is %q (%v), want this machine", a, h, lb)
		}
		if !Same(a, "http://localhost/y") {
			t.Errorf("%q is not the same as localhost", a)
		}
	}
	same := [][2]string{
		{"http://3232235777/x", "http://192.168.1.1:80/y"},         // decimal
		{"http://0xc0a80101/x", "http://192.168.1.1/y"},            // hexadecimal
		{"http://0300.0250.01.01/x", "http://192.168.1.1/y"},       // octal
		{"http://192.168.257/x", "http://192.168.1.1/y"},           // short, the last number fills the rest
		{"http://[::ffff:192.168.1.1]/x", "http://192.168.1.1/y"},  // IPv4-mapped
		{"http://[FE80::1%25eth0]/x", "http://[fe80::1]/y"},        // zone and case
		{"http://[fe80::1%25eth1]/x", "http://[fe80::1%25eth0]/y"}, // a zone is an interface, not a host
		{"https://Example.ORG./x", "https://example.org/y"},
	}
	for _, c := range same {
		if !Same(c[0], c[1]) {
			t.Errorf("%q and %q are one host", c[0], c[1])
		}
	}
	notSame := [][2]string{
		{"http://192.168.1.1/x", "http://192.168.1.2/y"},
		{"http://0xc0a80102/x", "http://192.168.1.1/y"},
		{"http://256.1.1.1/x", "http://1.1.1.1/y"}, // not an address: a name
		{"http://[2001:db8::1]/x", "http://[2001:db8::2]/y"},
		{"http://127.0.0.1/x", "http://128.0.0.1/y"},
		{"http://koios.example/x", "http://koios.example.net/y"},
	}
	for _, c := range notSame {
		if Same(c[0], c[1]) {
			t.Errorf("%q and %q are not one host", c[0], c[1])
		}
	}
}
