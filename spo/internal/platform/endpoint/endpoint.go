// Package endpoint normalises where a chain provider lives, to decide whether
// two providers are on one host (ADR 0006: a cross-check needs different
// operators, so two sources behind one host are one source).
//
// Nothing is resolved over the network: a name is compared as written, after
// lower-casing, removing trailing dots, the port, IPv6 brackets and an IPv6
// zone. A numeric IPv4 host is read in every form a resolver accepts (decimal
// 2130706433, hexadecimal 0x7f000001, octal, short 127.1), an IPv4-mapped IPv6
// address as the IPv4 address, so two spellings of one address are one host.
// Every address of 127.0.0.0/8, ::1, "localhost" and a Unix socket path are all
// "this machine".
package endpoint

import (
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Loopback is the host name given to everything on this machine.
const Loopback = "this machine"

// Host is the normalised host of an endpoint: a URL (https://host:port/path),
// "tcp://host:port", "unix:PATH" or a bare socket path, and loopback is true
// when it is this machine. An endpoint with no host gives "" and false.
func Host(raw string) (host string, loopback bool) {
	raw = strings.TrimSpace(raw)
	switch {
	case raw == "":
		return "", false
	case strings.HasPrefix(raw, "unix:"), strings.HasPrefix(raw, "/"), strings.HasPrefix(raw, "./"), !strings.Contains(raw, "://") && !strings.Contains(raw, ":"):
		return Loopback, true
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		// host:port with no scheme
		h, _, serr := net.SplitHostPort(raw)
		if serr != nil {
			return "", false
		}
		return normalise(h)
	}
	return normalise(u.Hostname())
}

func normalise(h string) (string, bool) {
	h = strings.ToLower(strings.TrimRight(strings.Trim(h, "[]"), "."))
	// An IPv6 zone (fe80::1%eth0, or %25eth0 as a URL writes it) names an
	// interface of this machine, not another host.
	if k := strings.IndexByte(h, '%'); k >= 0 {
		h = h[:k]
	}
	if h == "" {
		return "", false
	}
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return Loopback, true
	}
	ip := net.ParseIP(h)
	if ip == nil {
		ip = legacyIPv4(h)
	}
	if ip != nil {
		// Every address of 127.0.0.0/8, ::1, the unspecified addresses and their
		// IPv4-mapped forms are this machine.
		if ip.IsLoopback() || ip.IsUnspecified() {
			return Loopback, true
		}
		return ip.String(), false
	}
	return h, false
}

// legacyIPv4 reads the numeric IPv4 forms a resolver accepts and net.ParseIP
// does not: a single number (2130706433), hexadecimal (0x7f000001), octal
// (0177.0.0.1) and the short forms in which the last number fills the rest
// (127.1, 127.0.1). nil when h is not one.
func legacyIPv4(h string) net.IP {
	parts := strings.Split(h, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return nil
	}
	vals := make([]uint64, len(parts))
	for i, p := range parts {
		if p == "" {
			return nil
		}
		base := 10
		switch {
		case strings.HasPrefix(p, "0x"):
			base, p = 16, p[2:]
			if p == "" {
				return nil
			}
		case len(p) > 1 && p[0] == '0':
			base, p = 8, p[1:]
		}
		v, err := strconv.ParseUint(p, base, 32)
		if err != nil {
			return nil
		}
		vals[i] = v
	}
	last := vals[len(vals)-1]
	if last >= 1<<(8*uint(5-len(vals))) {
		return nil
	}
	var n uint64
	for i, v := range vals[:len(vals)-1] {
		if v > 255 {
			return nil
		}
		n |= v << (8 * uint(3-i))
	}
	n |= last
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// Same reports whether two endpoints are on one host: the same normalised
// name, or both on this machine. An endpoint with no host is never the same.
func Same(a, b string) bool {
	ha, _ := Host(a)
	hb, _ := Host(b)
	return ha != "" && ha == hb
}
