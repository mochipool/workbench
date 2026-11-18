//go:build linux

package nodefiles

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// mountHasNoswap reports whether every mount of the device major:minor in a
// mountinfo listing is a tmpfs with the `noswap` option (in the per-mount or the
// super-block options), and that there is at least one. A mount of that device
// that is not a tmpfs, or has no noswap, makes the answer false: the rule is
// the most restrictive reading.
func mountHasNoswap(r io.Reader, major, minor uint32) (bool, error) {
	want := fmt.Sprintf("%d:%d", major, minor)
	sc := bufio.NewScanner(r)
	found := false
	for sc.Scan() {
		line := sc.Text()
		// id parent major:minor root mountpoint options [optional fields] - fstype source superoptions
		pre, post, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		f := strings.Fields(pre)
		if len(f) < 6 || f[2] != want {
			continue
		}
		g := strings.Fields(post)
		if len(g) < 3 || g[0] != "tmpfs" {
			return false, nil
		}
		opts := strings.Split(f[5], ",")
		opts = append(opts, strings.Split(g[2], ",")...)
		has := false
		for _, o := range opts {
			has = has || o == "noswap"
		}
		if !has {
			return false, nil
		}
		found = true
	}
	return found, sc.Err()
}
