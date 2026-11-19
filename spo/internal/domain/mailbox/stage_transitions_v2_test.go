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

// decodeAny decodes the named frame at the first stage that accepts it, from
// the side that sends it. The message is what a session would hand to a
// transition.
func decodeAny(t *testing.T, frames map[string][]byte, name string) mailbox.Message {
	t.Helper()
	for _, st := range []mailbox.Stage{mailbox.StageV2Authed, mailbox.StageUnversioned, mailbox.StageV2PreAuth, mailbox.StageV1} {
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

// M1. A relay that offers both versions starts at StageUnversioned. After it
// has accepted a version 2 Auth, a second Auth and a Revoke are refused, and
// Put, Fetch and Ack are accepted.
//
// spec: SPO-Xmailbox-OUT-051
func TestRelaySequenceFromBothVersions(t *testing.T) {
	frames := framesByName(t)
	st, err := mailbox.StageForOffer(mailbox.BothVersions)
	if err != nil {
		t.Fatal(err)
	}
	// Revokes come first; a version 1 Auth can no longer follow the first.
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
		if _, err := mailbox.DecodeFromClientIn(st, frames["auth v1"]); !errors.Is(err, mailbox.ErrVersion) {
			t.Fatalf("a version 1 Auth after %s: %v", name, err)
		}
	}
	m, err := mailbox.DecodeFromClientIn(st, frames["auth v2"])
	if err != nil {
		t.Fatal(err)
	}
	if st, err = st.AfterAuth(m); err != nil {
		t.Fatal(err)
	}
	if st != mailbox.StageV2Authed {
		t.Fatalf("after the Auth: %v", st)
	}
	for _, name := range []string{"auth v2", "auth v1", "revoke device", "revoke wallet"} {
		if _, err := mailbox.DecodeFromClientIn(st, frames[name]); !errors.Is(err, mailbox.ErrStage) {
			t.Errorf("%s after the Auth: %v", name, err)
		}
	}
	for _, name := range []string{"put v2", "fetch", "ack"} {
		if _, err := mailbox.DecodeFromClientIn(st, frames[name]); err != nil {
			t.Errorf("%s after the Auth: %v", name, err)
		}
	}
}

// The same relay with no Revoke before the Auth, and a relay that offers only
// version 2.
//
// spec: SPO-Xmailbox-OUT-051
func TestRelaySequenceWithoutARevoke(t *testing.T) {
	frames := framesByName(t)
	for _, offer := range []mailbox.Versions{mailbox.BothVersions, mailbox.V2} {
		st, _ := mailbox.StageForOffer(offer)
		m, err := mailbox.DecodeFromClientIn(st, frames["auth v2"])
		if err != nil {
			t.Fatal(err)
		}
		if st, err = st.AfterAuth(m); err != nil || st != mailbox.StageV2Authed {
			t.Fatalf("offer %b: %v, %v", offer, st, err)
		}
		if _, err := mailbox.DecodeFromClientIn(st, frames["auth v2"]); !errors.Is(err, mailbox.ErrStage) {
			t.Errorf("offer %b: a second Auth: %v", offer, err)
		}
		if _, err := mailbox.DecodeFromClientIn(st, frames["put v2"]); err != nil {
			t.Errorf("offer %b: a Put: %v", offer, err)
		}
	}
}

// The version 1 sequence: a version 1 Auth accepted at StageUnversioned or
// StageV1 leaves the stage at StageV1, which is the rule of version 1 as it
// always was (every frame of the sender is allowed; the session knows whether
// it has authenticated).
//
// spec: SPO-Xmailbox-OUT-051, SPO-Xmailbox-OUT-052
func TestRelaySequenceInVersion1(t *testing.T) {
	frames := framesByName(t)
	for _, offer := range []mailbox.Versions{mailbox.BothVersions, mailbox.V1} {
		st, _ := mailbox.StageForOffer(offer)
		m, err := mailbox.DecodeFromClientIn(st, frames["auth v1"])
		if err != nil {
			t.Fatalf("offer %b: %v", offer, err)
		}
		if st, err = st.AfterAuth(m); err != nil || st != mailbox.StageV1 {
			t.Fatalf("offer %b: %v, %v", offer, st, err)
		}
		// From here the relay speaks version 1 exactly.
		for _, name := range []string{"put v1", "fetch", "ack", "auth v1"} {
			a, errA := mailbox.DecodeFromClient(frames[name])
			b, errB := mailbox.DecodeFromClientIn(st, frames[name])
			if errA != nil || errB != nil || !equalMsgs(a, b) {
				t.Errorf("offer %b: %s: %v / %v", offer, name, errA, errB)
			}
		}
		// A version 2 frame is not one of version 1.
		if _, err := mailbox.DecodeFromClientIn(st, frames["revoke device"]); !errors.Is(err, mailbox.ErrUnknownType) {
			t.Errorf("offer %b: a Revoke at version 1: %v", offer, err)
		}
		if _, err := mailbox.DecodeFromClientIn(st, frames["auth v2"]); !errors.Is(err, mailbox.ErrMalformed) {
			t.Errorf("offer %b: a version 2 Auth at version 1: %v", offer, err)
		}
	}
}

// Every transition is a function of the source stage and the accepted
// message; anything else is an error and returns no stage.
//
// spec: SPO-Xmailbox-OUT-051
func TestStageTransitionsTakeTheAcceptedMessage(t *testing.T) {
	frames := framesByName(t)
	msg := func(name string) mailbox.Message { return decodeAny(t, frames, name) }
	stages := []mailbox.Stage{mailbox.StageUnversioned, mailbox.StageV1, mailbox.StageV2PreAuth, mailbox.StageV2Authed, 0, 5, 255}

	// AfterAuth, per source stage and message.
	authCases := map[mailbox.Stage]map[string]mailbox.Stage{
		mailbox.StageUnversioned: {"auth v1": mailbox.StageV1, "auth v2": mailbox.StageV2Authed},
		mailbox.StageV1:          {"auth v1": mailbox.StageV1},
		mailbox.StageV2PreAuth:   {"auth v2": mailbox.StageV2Authed},
	}
	for _, from := range stages {
		for _, name := range []string{"auth v1", "auth v2", "revoke device", "revoke wallet", "put v1", "put v2", "fetch", "ack", "authok v1", "authok v2", "challenge"} {
			got, err := from.AfterAuth(msg(name))
			if want, ok := authCases[from][name]; ok {
				if err != nil || got != want {
					t.Errorf("AfterAuth(%s) from %v: %v, %v, want %v", name, from, got, err, want)
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
		for _, name := range []string{"revoke device", "revoke wallet", "auth v1", "auth v2", "put v2", "fetch", "ack", "revoke result", "challenge"} {
			got, err := from.AfterRevoke(msg(name))
			isRevoke := name == "revoke device" || name == "revoke wallet"
			if isRevoke && (from == mailbox.StageUnversioned || from == mailbox.StageV2PreAuth) {
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
	okCases := map[mailbox.Stage]map[string]mailbox.Stage{
		mailbox.StageV1:        {"authok v1": mailbox.StageV1},
		mailbox.StageV2PreAuth: {"authok v2": mailbox.StageV2Authed},
	}
	for _, from := range stages {
		for _, name := range []string{"authok v1", "authok v2", "auth v1", "auth v2", "put result", "items", "revoke result", "error"} {
			got, err := from.AfterAuthOK(msg(name))
			if want, ok := okCases[from][name]; ok {
				if err != nil || got != want {
					t.Errorf("AfterAuthOK(%s) from %v: %v, %v, want %v", name, from, got, err, want)
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

// The client's sequence: it chooses a version from the Challenge, reads the
// AuthOK and from then on reads the frames of an authenticated connection.
//
// spec: SPO-Xmailbox-OUT-051
func TestClientSequence(t *testing.T) {
	frames := framesByName(t)
	st, err := mailbox.StageAfterChoice(2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mailbox.DecodeFromRelayIn(st, frames["put result"]); !errors.Is(err, mailbox.ErrStage) {
		t.Errorf("a PutResult before the AuthOK: %v", err)
	}
	m, err := mailbox.DecodeFromRelayIn(st, frames["authok v2"])
	if err != nil {
		t.Fatal(err)
	}
	if st, err = st.AfterAuthOK(m); err != nil || st != mailbox.StageV2Authed {
		t.Fatalf("%v, %v", st, err)
	}
	if _, err := mailbox.DecodeFromRelayIn(st, frames["put result"]); err != nil {
		t.Errorf("a PutResult after the AuthOK: %v", err)
	}
	if _, err := mailbox.DecodeFromRelayIn(st, frames["authok v2"]); !errors.Is(err, mailbox.ErrStage) {
		t.Errorf("a second AuthOK: %v", err)
	}
}
