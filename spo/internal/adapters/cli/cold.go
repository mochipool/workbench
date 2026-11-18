package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// COLD-ROLE SUB-KEY FACTORS (ADR 0011 decision 6).
//
// Records of a key whose identity has a cold role are sealed so that the
// unlocked workspace alone does not open them. What opens one is a fresh
// presentation: under standard a sub-key passphrase (--cold-passphrase-fd, or a
// prompt) that is not the workspace passphrase and not any slot's passphrase,
// under hardware and strict the daily authenticator again (a touch, and its PIN
// as for the unlock). The store asks for it at the moment a cold record is
// written, opened (signing) or carried across a rotation, never otherwise.

// ColdOpen is what a command can present of the cold sub-key factor.
type ColdOpen struct {
	// Passphrase asks for the sub-key passphrase (standard). create is true when a
	// sub-key is being made: it is asked twice, and not accepted when it opens a
	// passphrase slot.
	Passphrase func(ctx context.Context, create bool) (*secret.Buffer, error)
	// Factors presents the authenticator (hardware, strict): the daily one, with
	// the PIN of this command.
	Factors *FactorOpen
	// LeaveUnreachable names the cold-role records (kind/label) a recovery may leave
	// under their old cold factor (--leave-unreachable).
	LeaveUnreachable []string
}

// ColdFactors is the optional interface of a SealedStore that takes the cold
// sub-key factor: the store asks it at the moment a cold-role record needs it.
type ColdFactors interface {
	SetColdSource(c ColdOpen)
}

// coldOpen is what this command presents of the cold sub-key factor.
func (a *app) coldOpen() ColdOpen {
	c := ColdOpen{Passphrase: a.coldPassphrase}
	// A recovery-composite session unlocks with the RECOVERY authenticator, which is
	// never a cold sub-key factor (ADR 0011: no cold record is bound to it); the
	// cold records of such a session are reached through their recovery wraps.
	if a.d.Factors != nil && a.unlock != "recovery-composite" {
		f := a.factorOpenFor(false)
		c.Factors = &f
	}
	return c
}

// coldPassphrase reads the sub-key passphrase: once per command from
// --cold-passphrase-fd (held in guarded memory, a fresh copy for each caller), or
// from the terminal, twice when a new one is made.
func (a *app) coldPassphrase(ctx context.Context, create bool) (*secret.Buffer, error) {
	if a.coldPass == nil {
		var p *secret.Buffer
		var err error
		if a.coldFD >= 0 {
			p, err = readFDSecret(a.coldFD, "the cold-key passphrase")
		} else {
			p, err = a.askColdPassphrase(ctx, create, "Cold-key passphrase (the sub-key that opens cold keys; not the workspace passphrase)", "--cold-passphrase-fd N")
		}
		if err != nil {
			return nil, err
		}
		a.coldPass = p
	}
	return secret.Fill(a.coldPass.Len(), func(dst []byte) error {
		return a.coldPass.Use(func(b []byte) error { copy(dst, b); return nil })
	})
}

// newColdPassphrase reads the sub-key passphrase of the table a rotation writes:
// --new-cold-passphrase-fd, or two prompts.
func (a *app) newColdPassphrase(ctx context.Context, _ bool) (*secret.Buffer, error) {
	if a.newColdPass == nil {
		var p *secret.Buffer
		var err error
		if a.newColdFD >= 0 {
			p, err = readFDSecret(a.newColdFD, "the new cold-key passphrase")
		} else {
			p, err = a.askColdPassphrase(ctx, true, "NEW cold-key passphrase", "--new-cold-passphrase-fd N")
		}
		if err != nil {
			return nil, err
		}
		a.newColdPass = p
	}
	return secret.Fill(a.newColdPass.Len(), func(dst []byte) error {
		return a.newColdPass.Use(func(b []byte) error { copy(dst, b); return nil })
	})
}

func (a *app) askColdPassphrase(ctx context.Context, create bool, what, flag string) (*secret.Buffer, error) {
	p, err := a.term.ReadSecret(ctx, what+": ")
	if errors.Is(err, ErrNoTerminal) {
		return nil, fmt.Errorf("no terminal to ask for the cold-key passphrase on; give it on a file descriptor with %s", flag)
	}
	if err != nil {
		return nil, err
	}
	if p.Len() == 0 {
		p.Destroy()
		return nil, errors.New("the cold-key passphrase is empty")
	}
	if create {
		again, err := a.term.ReadSecret(ctx, "Repeat it: ")
		if err != nil {
			p.Destroy()
			return nil, err
		}
		same := equalSecrets(p, again)
		again.Destroy()
		if !same {
			p.Destroy()
			return nil, errors.New("the two entries differ; nothing was changed")
		}
	}
	return p, nil
}

// destroyCold wipes the cold-key passphrases this command held.
func (a *app) destroyCold() {
	if a.coldPass != nil {
		a.coldPass.Destroy()
		a.coldPass = nil
	}
	if a.newColdPass != nil {
		a.newColdPass.Destroy()
		a.newColdPass = nil
	}
}

// RecoveryDiscarder is the optional interface of a SealedStore that can drop a
// recovery presentation that was not used.
type RecoveryDiscarder interface{ DiscardRecovery() }

// discardRecovery drops the recovery presentation of st, if it can.
func discardRecovery(st SealedStore) {
	if d, ok := st.(RecoveryDiscarder); ok {
		d.DiscardRecovery()
	}
}

// ColdRecoverer is the optional interface of a SealedStore whose recovery rekey
// (`store recover`) also re-establishes the cold-role records under a new cold
// factor.
type ColdRecoverer interface {
	ChangePassphraseRekeyCold(ctx context.Context, newPassphrase *secret.Buffer, cold ColdOpen) (*secret.Buffer, error)
}

// ColdWrapCounter is the optional interface of a SealedStore that counts its
// cold-role records and those with no recovery wrap (readable with the workspace
// key: the wrap is authenticated by the outer layer).
type ColdWrapCounter interface {
	ColdWithoutWrap(ctx context.Context) (cold, without int, err error)
}

// ColdProblemLister is the optional interface of a SealedStore that names the
// cold-role records the workspace key alone shows to be out of step with the
// workspace (header kind against policy, credential of no current daily slot, a
// record a rotation or recovery left under its old cold factor). Each line is
// "kind/label: why".
type ColdProblemLister interface {
	ColdProblems(ctx context.Context) ([]string, error)
}

// ColdVerifier is the optional interface of a SealedStore that can open its
// cold-role payloads with the factor, read-only.
type ColdVerifier interface {
	VerifyColdPayloads(ctx context.Context) (int, error)
}

// coldNoWrapLine is what `store slots` prints for cold records with no recovery
// wrap (`store verify` prints the same fact as a note, from the store).
func coldNoWrapLine(n int) string {
	return fmt.Sprintf("%d cold records without a recovery wrap: the recovery key does not reach them; `spo store passphrase change` (or `spo store recovery-key new`) binds a recovery key and adds the wraps, and asks for the cold factor once", n)
}
