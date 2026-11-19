package mailbox_test

import (
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
)

func framesByName(t *testing.T) map[string][]byte {
	t.Helper()
	frames := map[string][]byte{}
	for _, f := range tableFrames(t) {
		frames[f.name] = f.frame
	}
	return frames
}

// stageDecodeAny decodes the named frame at the first stage and side that
// accepts it. The message is what a session would hand to a transition.
func stageDecodeAny(t *testing.T, frames map[string][]byte, name string) mailbox.Message {
	t.Helper()
	for _, st := range []mailbox.Stage{mailbox.StageV2Authed, mailbox.StageV2PreAuth} {
		if m, err := mailbox.DecodeFromClientIn(st, frames[name]); err == nil {
			return m
		}
		if m, err := mailbox.DecodeFromRelayIn(st, frames[name]); err == nil {
			return m
		}
	}
	t.Fatalf("no stage decodes %s", name)
	return nil
}

// The relay's sequence from its offer: Revokes first (a Revoke keeps the stage),
// then the Auth; after it a second Auth and a Revoke are refused and Put, Fetch
// and Ack are accepted.
//
// spec: SPO-Xmailbox-OUT-051
func TestRelaySequence(t *testing.T) {
	frames := framesByName(t)
	st, err := mailbox.StageForOffer(mailbox.V2)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"revoke device", "revoke wallet", "revoke device"} {
		m, err := mailbox.DecodeFromClientIn(st, frames[name])
		if err != nil {
			t.Fatalf("%s at %v: %v", name, st, err)
		}
		if st, err = st.AfterRevoke(m); err != nil {
			t.Fatalf("AfterRevoke(%s): %v", name, err)
		}
		if st != mailbox.StageV2PreAuth {
			t.Fatalf("after %s: %v", name, st)
		}
	}
	m, err := mailbox.DecodeFromClientIn(st, frames["auth"])
	if err != nil {
		t.Fatal(err)
	}
	if st, err = st.AfterAuth(m); err != nil {
		t.Fatal(err)
	}
	if st != mailbox.StageV2Authed {
		t.Fatalf("after the Auth: %v", st)
	}
	for _, name := range []string{"auth", "revoke device", "revoke wallet"} {
		if _, err := mailbox.DecodeFromClientIn(st, frames[name]); !errors.Is(err, mailbox.ErrStage) {
			t.Errorf("%s after the Auth: %v", name, err)
		}
	}
	for _, name := range []string{"put", "fetch", "ack"} {
		if _, err := mailbox.DecodeFromClientIn(st, frames[name]); err != nil {
			t.Errorf("%s after the Auth: %v", name, err)
		}
	}
}

// The same relay with no Revoke before the Auth.
//
// spec: SPO-Xmailbox-OUT-051
func TestRelaySequenceWithoutARevoke(t *testing.T) {
	frames := framesByName(t)
	st, _ := mailbox.StageForOffer(mailbox.V2)
	m, err := mailbox.DecodeFromClientIn(st, frames["auth"])
	if err != nil {
		t.Fatal(err)
	}
	if st, err = st.AfterAuth(m); err != nil || st != mailbox.StageV2Authed {
		t.Fatalf("%v, %v", st, err)
	}
	if _, err := mailbox.DecodeFromClientIn(st, frames["auth"]); !errors.Is(err, mailbox.ErrStage) {
		t.Errorf("a second Auth: %v", err)
	}
	if _, err := mailbox.DecodeFromClientIn(st, frames["put"]); err != nil {
		t.Errorf("a Put: %v", err)
	}
}

// Only the set of version 2 has an offer: every other set is ErrVersion and
// gives no stage.
//
// spec: SPO-Xmailbox-OUT-050, SPO-Xmailbox-OUT-051
func TestOnlyAnOfferOfVersionTwoHasAStage(t *testing.T) {
	for _, v := range []mailbox.Versions{0, 1, 3, 4, 255} {
		if st, err := mailbox.StageForOffer(v); !errors.Is(err, mailbox.ErrVersion) || st != 0 {
			t.Errorf("StageForOffer(%b) = %v, %v", v, st, err)
		}
	}
	if st, err := mailbox.StageForOffer(mailbox.V2); err != nil || st != mailbox.StageV2PreAuth {
		t.Errorf("StageForOffer(V2) = %v, %v", st, err)
	}
	for _, v := range []uint{0, 1, 3, 65535} {
		if st, err := mailbox.StageAfterChoice(v); !errors.Is(err, mailbox.ErrVersion) || st != 0 {
			t.Errorf("StageAfterChoice(%d) = %v, %v", v, st, err)
		}
	}
	if st, err := mailbox.StageAfterChoice(2); err != nil || st != mailbox.StageV2PreAuth {
		t.Errorf("StageAfterChoice(2) = %v, %v", st, err)
	}
}

// Every transition is a function of the source stage and the accepted
// message; anything else is an error and returns no stage.
//
// spec: SPO-Xmailbox-OUT-051
func TestStageTransitionsTakeTheAcceptedMessage(t *testing.T) {
	frames := framesByName(t)
	msg := func(name string) mailbox.Message { return stageDecodeAny(t, frames, name) }
	stages := []mailbox.Stage{mailbox.StageV2PreAuth, mailbox.StageV2Authed, 0, 3, 255}

	// AfterAuth, per source stage and message.
	for _, from := range stages {
		for _, name := range []string{"auth", "revoke device", "revoke wallet", "put", "fetch", "ack", "authok", "challenge"} {
			got, err := from.AfterAuth(msg(name))
			if from == mailbox.StageV2PreAuth && name == "auth" {
				if err != nil || got != mailbox.StageV2Authed {
					t.Errorf("AfterAuth(%s) from %v: %v, %v", name, from, got, err)
				}
			} else if !errors.Is(err, mailbox.ErrStage) || got != 0 {
				t.Errorf("AfterAuth(%s) from %v: %v, %v", name, from, got, err)
			}
		}
		if got, err := from.AfterAuth(nil); !errors.Is(err, mailbox.ErrStage) || got != 0 {
			t.Errorf("AfterAuth(nil) from %v: %v, %v", from, got, err)
		}
	}

	// AfterRevoke.
	for _, from := range stages {
		for _, name := range []string{"revoke device", "revoke wallet", "auth", "put", "fetch", "ack", "revoke result", "challenge"} {
			got, err := from.AfterRevoke(msg(name))
			isRevoke := name == "revoke device" || name == "revoke wallet"
			if isRevoke && from == mailbox.StageV2PreAuth {
				if err != nil || got != mailbox.StageV2PreAuth {
					t.Errorf("AfterRevoke(%s) from %v: %v, %v", name, from, got, err)
				}
			} else if !errors.Is(err, mailbox.ErrStage) || got != 0 {
				t.Errorf("AfterRevoke(%s) from %v: %v, %v", name, from, got, err)
			}
		}
		if got, err := from.AfterRevoke(nil); !errors.Is(err, mailbox.ErrStage) || got != 0 {
			t.Errorf("AfterRevoke(nil) from %v: %v, %v", from, got, err)
		}
	}

	// AfterAuthOK, the client's move.
	for _, from := range stages {
		for _, name := range []string{"authok", "auth", "put result", "items", "revoke result", "error"} {
			got, err := from.AfterAuthOK(msg(name))
			if from == mailbox.StageV2PreAuth && name == "authok" {
				if err != nil || got != mailbox.StageV2Authed {
					t.Errorf("AfterAuthOK(%s) from %v: %v, %v", name, from, got, err)
				}
			} else if !errors.Is(err, mailbox.ErrStage) || got != 0 {
				t.Errorf("AfterAuthOK(%s) from %v: %v, %v", name, from, got, err)
			}
		}
		if got, err := from.AfterAuthOK(nil); !errors.Is(err, mailbox.ErrStage) || got != 0 {
			t.Errorf("AfterAuthOK(nil) from %v: %v, %v", from, got, err)
		}
	}
}

// The client's sequence: it chooses version 2 from the Challenge, reads the
// AuthOK and from then on reads the frames of an authenticated connection. A
// Challenge is the first frame; the client's own rule, not the decoder's, stops a
// second one.
//
// spec: SPO-Xmailbox-OUT-051
func TestClientSequence(t *testing.T) {
	frames := framesByName(t)
	st, err := mailbox.StageAfterChoice(2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mailbox.DecodeFromRelayIn(st, frames["challenge"]); err != nil {
		t.Errorf("the Challenge: %v", err)
	}
	if _, err := mailbox.DecodeFromRelayIn(st, frames["put result"]); !errors.Is(err, mailbox.ErrStage) {
		t.Errorf("a PutResult before the AuthOK: %v", err)
	}
	m, err := mailbox.DecodeFromRelayIn(st, frames["authok"])
	if err != nil {
		t.Fatal(err)
	}
	if st, err = st.AfterAuthOK(m); err != nil || st != mailbox.StageV2Authed {
		t.Fatalf("%v, %v", st, err)
	}
	if _, err := mailbox.DecodeFromRelayIn(st, frames["put result"]); err != nil {
		t.Errorf("a PutResult after the AuthOK: %v", err)
	}
	if _, err := mailbox.DecodeFromRelayIn(st, frames["authok"]); !errors.Is(err, mailbox.ErrStage) {
		t.Errorf("a second AuthOK: %v", err)
	}
	if _, err := mailbox.DecodeFromRelayIn(st, frames["challenge"]); !errors.Is(err, mailbox.ErrStage) {
		t.Errorf("a Challenge after the AuthOK: %v", err)
	}
}
