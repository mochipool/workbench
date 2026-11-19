package mailbox

import "fmt"

// Versions is the set of protocol versions an endpoint speaks.
//
// There is one version, 2 (ADR 0014): version 1 was deleted from this package in
// the series of changes that moved the relay session and the client to version 2.
// The set stays because the Challenge announces a range, and a relay that offers
// version 1 only is something a client must refuse: V2.Choose(1, 1) is
// ErrVersion. A client speaks V2 only; nothing here remembers what a relay has
// offered before, because a relay that rewrites its own Challenge can only harm
// the client that pinned its key (SPO-Xmailbox-SEC-036).
type Versions uint8

// V2 is the one version of this record.
const V2 Versions = 1 << 1

// Valid reports whether v is the set of version 2.
func (v Versions) Valid() bool { return v == V2 }

// Has reports whether version is in the set.
func (v Versions) Has(version uint) bool { return version == Version2 && v == V2 }

// Range is the [min, max] a relay announces in its Challenge for this set. A
// set that is not valid gives 0, 0.
func (v Versions) Range() (min, max uint) {
	if !v.Valid() {
		return 0, 0
	}
	return Version2, Version2
}

// Choose is the client's rule: version 2 if it is in the relay's announced range
// [min, max]. A range that is malformed is ErrMalformed; a range that does not
// hold version 2 is ErrVersion. A client whose set is V2 therefore refuses a
// Challenge that offers only version 1 with ErrVersion.
func (v Versions) Choose(min, max uint) (uint, error) {
	if min < 1 || min > max || max > MaxVersion {
		return 0, bad(ErrMalformed, "version range %d..%d", min, max)
	}
	if v.Has(Version2) && Version2 >= min && Version2 <= max {
		return Version2, nil
	}
	return 0, bad(ErrVersion, "this code speaks version %d, the peer %d..%d", Version2, min, max)
}

// Stage is the state of a connection that decides which frames its peer may
// send. The zero value is invalid and refuses everything.
//
// A session obtains its first stage from StageForOffer (relay) or
// StageAfterChoice (client) and moves it only with AfterRevoke, AfterAuth and
// AfterAuthOK, each of which takes the message the session has accepted and
// refuses a message that does not belong to the stage. The constants name the
// stages for comparison, for the decoders in a test and for a log line; a
// session does not assign them.
type Stage uint8

const (
	// StageV2PreAuth: the connection is open and the Auth is not yet accepted. The
	// relay has sent a Challenge and reads Revokes and the Auth; the client reads
	// the Challenge, the answers to its Revokes and the AuthOK.
	StageV2PreAuth Stage = iota + 1
	// StageV2Authed: authenticated.
	StageV2Authed
)

// Valid reports whether s is one of the two stages.
func (s Stage) Valid() bool { return s >= StageV2PreAuth && s <= StageV2Authed }

// String names the stage.
func (s Stage) String() string {
	switch s {
	case StageV2PreAuth:
		return "v2-before-auth"
	case StageV2Authed:
		return "v2-authenticated"
	}
	return fmt.Sprintf("invalid stage %d", uint8(s))
}

// StageForOffer is the stage a relay starts in, after sending a Challenge that
// offers the versions of v: StageV2PreAuth for version 2. Any other set is
// ErrVersion.
func StageForOffer(v Versions) (Stage, error) {
	if v == V2 {
		return StageV2PreAuth, nil
	}
	return 0, bad(ErrVersion, "an offer of the versions %#b", uint8(v))
}

// StageAfterChoice is the stage of a client that has chosen version: StageV2PreAuth
// for version 2, ErrVersion for any other number.
func StageAfterChoice(version uint) (Stage, error) {
	if version == Version2 {
		return StageV2PreAuth, nil
	}
	return 0, bad(ErrVersion, "version %d", version)
}

// AfterAuth is the relay's stage after it has accepted the Auth m at stage s: an
// AuthV2 at StageV2PreAuth gives StageV2Authed. Anything else (another message,
// an Auth at StageV2Authed, an invalid stage) is ErrStage and gives no stage.
//
// The session calls it once the Auth has been verified and accepted.
func (s Stage) AfterAuth(m Message) (Stage, error) {
	if _, ok := m.(AuthV2); ok && s == StageV2PreAuth {
		return StageV2Authed, nil
	}
	return 0, bad(ErrStage, "%T cannot be accepted at the stage %v", m, s)
}

// AfterAuthOK is the client's stage after it has read the AuthOK m at stage s: an
// AuthOKV2 at StageV2PreAuth gives StageV2Authed, anything else is ErrStage and
// gives no stage.
func (s Stage) AfterAuthOK(m Message) (Stage, error) {
	if _, ok := m.(AuthOKV2); ok && s == StageV2PreAuth {
		return StageV2Authed, nil
	}
	return 0, bad(ErrStage, "%T cannot be read at the stage %v", m, s)
}

// AfterRevoke is the relay's stage after it has read the Revoke m at stage s. A
// Revoke is allowed only before the Auth, so StageV2PreAuth stays. Anything else (a
// message that is not a Revoke, a Revoke at StageV2Authed, an invalid stage) is
// ErrStage and gives no stage. The session calls it for every Revoke that
// decoded, whether it then verified the Revoke or refused it.
func (s Stage) AfterRevoke(m Message) (Stage, error) {
	switch m.(type) {
	case RevokeByDevice, RevokeByWallet:
		if s == StageV2PreAuth {
			return StageV2PreAuth, nil
		}
	}
	return 0, bad(ErrStage, "%T cannot be accepted at the stage %v", m, s)
}
