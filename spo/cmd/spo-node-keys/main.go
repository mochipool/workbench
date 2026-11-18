// Command spo-node-keys is the block producer's start-up helper (ADR 0011
// decision 2): it decrypts the three files that `spo node export` delivered
// (age ciphertext) into a ramfs directory for cardano-node, mode 0400, and does
// nothing else. It is the only writer of a signing key in clear in this
// project, and it cannot open a workspace: it is a separate program whose
// import graph holds no workspace store, no slot code and no vault (checked by
// internal/archtest). It holds the producer's age identity only in memory, read
// from the systemd credential spo-node-age-identity.
//
//	spo-node-keys deliver --from DIR --to DIR
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/mochipool/workbench/spo/internal/adapters/native/hotkeys"
	"github.com/mochipool/workbench/spo/internal/adapters/nodefiles"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

const usage = `usage: spo-node-keys deliver --from DIR --to DIR

Decrypts kes.skey.age, vrf.skey.age and node.cert.age from DIR (the output of
"spo node export") into kes.skey, vrf.skey and node.cert in --to, mode 0400, owned
by the user this runs as (never root). --to must be an existing private
directory on a ramfs mount. The age identity is read from the systemd credential
spo-node-age-identity in $CREDENTIALS_DIRECTORY (LoadCredentialEncrypted=).`

func main() { os.Exit(run(os.Args[1:], os.Getenv)) }

func run(args []string, getenv func(string) string) int {
	if len(args) == 0 || args[0] != "deliver" {
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
	var from, to string
	rest := args[1:]
	for len(rest) > 0 {
		if len(rest) < 2 || (rest[0] != "--from" && rest[0] != "--to") {
			fmt.Fprintln(os.Stderr, usage)
			return 2
		}
		if rest[0] == "--from" {
			from = rest[1]
		} else {
			to = rest[1]
		}
		rest = rest[2:]
	}
	if from == "" || to == "" {
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
	if err := secret.HardenProcess(); err != nil {
		fmt.Fprintln(os.Stderr, "spo-node-keys: cannot harden the process:", err)
		return 1
	}
	if err := secret.Init(); err != nil {
		fmt.Fprintln(os.Stderr, "spo-node-keys:", err)
		return 1
	}
	defer secret.Purge()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	paths, err := nodefiles.Writer{}.Deliver(ctx, nodefiles.DeliverConfig{
		From: from, To: to, CredentialsDir: getenv("CREDENTIALS_DIRECTORY"), Derive: hotkeys.Deriver{},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "spo-node-keys:", err)
		return 1
	}
	for _, p := range paths {
		fmt.Println(p)
	}
	return 0
}
