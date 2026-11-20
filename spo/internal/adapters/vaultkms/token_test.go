package vaultkms

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// projectedToken lays out a token as kubelet projects it: the mount directory,
// a timestamped directory holding the file (mode 0644, kubelet's default), a
// "..data" link to it and a "token -> ..data/token" link. It returns the path
// of the link.
func projectedToken(t *testing.T, jwt string, mountMode os.FileMode) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "serviceaccount")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	ts := filepath.Join(root, "..2026_11_20_10_00_00.000000001")
	if err := os.Mkdir(ts, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ts, "token"), []byte(jwt+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, l := range [][2]string{{filepath.Base(ts), "..data"}, {"..data/token", "token"}} {
		if err := os.Symlink(l[0], filepath.Join(root, l[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(root, mountMode); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, "token")
}

// The web identity token is read as kubelet projects it (a link into the
// timestamped directory, mode 0644): by platform/mountfile's Token rule, not by
// the rule of a secret file of the user (no link, mode 0600). A token in a
// directory another user can write, or missing, is still refused, before
// anything is sent.
//
// spec: SPO-Xunlock-IF-011, SPO-Xunlock-PRE-048
func TestKMSReadsAProjectedToken(t *testing.T) {
	f := newFakeKMS()
	srv, o := tlsKMS(t, f)
	s := &fakeSTS{jwt: "eyJ.projected.token", role: "arn:aws:iam::111122223333:role/spo-unlock", kms: f, expires: time.Now().Add(time.Hour)}
	ssrv := httptest.NewServer(s)
	defer ssrv.Close()
	o.Getenv = env()
	o.PrivateSTSEndpoint, o.AllowLoopbackHTTP, o.RoleARN = ssrv.URL, true, s.role
	try := func(file string) error {
		o.WebIdentityTokenFile = file
		k, err := NewKMS(kmsRef(srv.URL), o)
		if err != nil {
			return err
		}
		b := newB(t)
		defer b.Destroy()
		_, err = k.Wrap(context.Background(), b, wcA)
		return err
	}
	good := projectedToken(t, s.jwt, 0o755)
	if err := try(good); err != nil {
		t.Fatalf("a projected token: %v", err)
	}
	if s.hits.Load() != 1 {
		t.Fatalf("STS asked %d times", s.hits.Load())
	}
	open := projectedToken(t, s.jwt, 0o777)
	if err := try(open); !errors.Is(err, ports.ErrBackendCredential) || !strings.Contains(err.Error(), "writable") {
		t.Errorf("a token in a directory others can write: %v", err)
	}
	missing := filepath.Join(filepath.Dir(good), "none")
	if err := try(missing); !errors.Is(err, ports.ErrBackendCredential) || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("a missing token: %v", err)
	}
	if s.hits.Load() != 1 {
		t.Errorf("a refused token reached STS: %d calls", s.hits.Load())
	}
}
