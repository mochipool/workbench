package mailbox

import "fmt"

// Versions is the set of protocol versions an endpoint speaks.
//
// Version 2 is the only version that will be deployed: version 1 is deleted
// from this package in the same series of changes that moves the relay session
// and the client to version 2. The sets exist so that the two can move one
// after the other. A client speaks V2 only; nothing here remembers what a relay
// has offered before, because a relay that rewrites its own Challenge can only
// harm the client that pinned its key (SPO-Xmailbox-SEC-036).
type Versions uint8

const (
	// V1 and V2 are the two versions of this record.
	V1 Versions = 1 << 0
	V2 Versions = 1 << 1
	// BothVersions exists only for the interim relay: the session still speaks
	// version 1 and has not moved to version 2 yet. It goes with version 1. A
	// client never configures it.
	BothVersions = V1 | V2
)

// Valid reports whether v is not empty and holds only known versions.
func (v Versions) Valid() bool { return v != 0 && v&^BothVersions == 0 }

// Has reports whether version is in the set.
func (v Versions) Has(version uint) bool {
	switch version {
	case Version1:
		return v&V1 != 0
	case Version2:
		return v&V2 != 0
	}
	return false
}

// Range is the [min, max] a relay announces in its Challenge for this set. A
// set that is not valid gives 0, 0. The two versions are adjacent, so a range
// holds exactly the versions of the set.
func (v Versions) Range() (min, max uint) {
	if !v.Valid() {
		return 0, 0
	}
	min, max = Version2, Version1
	if v&V1 != 0 {
		min = Version1
	}
	if v&V2 != 0 {
		max = Version2
	}
	return min, max
}

// Choose is the client's rule: the highest version that is both in the relay's
// announced range [min, max] and in v. A range that is malformed is
// ErrMalformed; no common version is ErrVersion. A client whose set is V2 only
// therefore refuses a Challenge that offers only version 1 with ErrVersion.
func (v Versions) Choose(min, max uint) (uint, error) {
	if min < 1 || min > max || max > MaxVersion {
		return 0, bad(ErrMalformed, "version range %d..%d", min, max)
	}
	for n := uint(Version2); n >= Version1; n-- {
		if v.Has(n) && n >= min && n <= max {
			return n, nil
		}
	}
	return 0, bad(ErrVersion, "this code speaks %s, the peer %d..%d", v.names(), min, max)
}

func (v Versions) names() string {
	switch v {
	case V1:
		return "version 1"
	case V2:
		return "version 2"
	case BothVersions:
		return "versions 1 and 2"
	}
	return "no version"
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
	// StageUnversioned: no version is chosen yet. The relay has sent a
	// Challenge that offers both versions and reads the first frame; the client
	// has not read the Challenge.
	StageUnversioned Stage = iota + 1
	// StageV1: a version 1 connection, as version 1 always was.
	StageV1
	// StageV2PreAuth: version 2 is chosen and the Auth is not yet accepted.
	StageV2PreAuth
	// StageV2Authed: version 2, authenticated.
	StageV2Authed
)

// Valid reports whether s is one of the four stages.
func (s Stage) Valid() bool { return s >= StageUnversioned && s <= StageV2Authed }

// String names the stage.
func (s Stage) String() string {
	switch s {
	case StageUnversioned:
		return "unversioned"
	case StageV1:
		return "v1"
	case StageV2PreAuth:
		return "v2-before-auth"
	case StageV2Authed:
		return "v2-authenticated"
	}
	return fmt.Sprintf("invalid stage %d", uint8(s))
}

// StageForOffer is the stage a relay starts in, after sending a Challenge that
// offers the versions of v: StageV1 for version 1 only, StageV2PreAuth for
// version 2 only, StageUnversioned for both.
func StageForOffer(v Versions) (Stage, error) {
	switch v {
	case V1:
		return StageV1, nil
	case V2:
		return StageV2PreAuth, nil
	case BothVersions:
		return StageUnversioned, nil
	}
	return 0, bad(ErrVersion, "an offer of %s", v.names())
}

// StageAfterChoice is the stage of a client that has chosen version.
func StageAfterChoice(version uint) (Stage, error) {
	switch version {
	case Version1:
		return StageV1, nil
	case Version2:
		return StageV2PreAuth, nil
	}
	return 0, bad(ErrVersion, "version %d", version)
}

// AfterAuth is the relay's stage after it has accepted the Auth m at stage s:
//
//   - an Auth (version 1) at StageUnversioned or StageV1 gives StageV1. Version
//     1 has no stage after its Auth in this package: every frame of the client
//     is allowed at StageV1 and the version 1 session keeps its own record of
//     whether the Auth was accepted (SPO-Xmailbox-OUT-052). The stage does not
//     disturb that; it only fixes the connection to version 1, which a
//     StageUnversioned connection was not yet.
//   - an AuthV2 at StageUnversioned or StageV2PreAuth gives StageV2Authed.
//   - anything else (another message, an Auth of the version the stage does not
//     speak, an Auth at StageV2Authed, an invalid stage) is ErrStage and gives
//     no stage.
//
// The session calls it once the Auth has been verified and accepted.
func (s Stage) AfterAuth(m Message) (Stage, error) {
	switch m.(type) {
	case Auth:
		if s == StageUnversioned || s == StageV1 {
			return StageV1, nil
		}
	case AuthV2:
		if s == StageUnversioned || s == StageV2PreAuth {
			return StageV2Authed, nil
		}
	}
	return 0, bad(ErrStage, "%T cannot be accepted at the stage %v", m, s)
}

// AfterAuthOK is the client's stage after it has read the AuthOK m at stage s:
// an AuthOKV2 at StageV2PreAuth gives StageV2Authed, an AuthOK (version 1) at
// StageV1 gives StageV1 (as for AfterAuth), anything else is ErrStage and gives
// no stage.
func (s Stage) AfterAuthOK(m Message) (Stage, error) {
	switch m.(type) {
	case AuthOK:
		if s == StageV1 {
			return StageV1, nil
		}
	case AuthOKV2:
		if s == StageV2PreAuth {
			return StageV2Authed, nil
		}
	}
	return 0, bad(ErrStage, "%T cannot be read at the stage %v", m, s)
}

// AfterRevoke is the relay's stage after it has read the Revoke m at stage s.
// A Revoke is a version 2 frame, so StageUnversioned gives StageV2PreAuth, after
// which a version 1 Auth is refused, and StageV2PreAuth stays. Anything else (a
// message that is not a Revoke, a Revoke at StageV1 or StageV2Authed, an invalid
// stage) is ErrStage and gives no stage. The session calls it for every Revoke
// that decoded, whether it then verified the Revoke or refused it.
func (s Stage) AfterRevoke(m Message) (Stage, error) {
	switch m.(type) {
	case RevokeByDevice, RevokeByWallet:
		if s == StageUnversioned || s == StageV2PreAuth {
			return StageV2PreAuth, nil
		}
	}
	return 0, bad(ErrStage, "%T cannot be accepted at the stage %v", m, s)
}
