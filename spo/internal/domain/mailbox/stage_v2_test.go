package mailbox_test

import (
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
)

// The frames of the table, by name: one valid frame of each kind.
type namedFrame struct {
	name  string
	frame []byte
}

func tableFrames(t *testing.T) []namedFrame {
	t.Helper()
	h := hash(9)
	enc := func(m mailbox.Message) []byte { return mustEncodeV(t, 2, m) }
	keys := mailbox.DeviceKeys{Ed25519: edk(5), X25519: xk(6)}
	return []namedFrame{
		{"challenge", enc(mailbox.Challenge{Min: 2, Max: 2, Nonce: nonce(1), RelayKey: nk(2), RelayTime: 5})},
		{"auth", enc(mailbox.AuthV2{Fingerprint: fp(3), Signature: sig(4), Keys: keys, Sign1: bs(10, 7), Key: bs(5, 8), Senders: []mailbox.WalletKey{wk(1)}})},
		{"authok", enc(mailbox.AuthOKV2{MaxEnvelope: 10, MaxEntries: 11, MaxBytes: 12, RetentionSeconds: 13, Until: 14})},
		{"put", enc(mailbox.PutV2{RequestID: 7, WalletKey: wk(3), To: fp(4), Mid: hash(5), Size: 99})},
		{"put result", enc(mailbox.PutResult{RequestID: 7, Status: mailbox.StatusFull})},
		{"fetch", enc(mailbox.Fetch{RequestID: 8, After: &h, MaxItems: 1})},
		{"items", enc(mailbox.Items{RequestID: 8, Entries: []mailbox.Item{{Mid: hash(1), Size: 10}}})},
		{"ack", enc(mailbox.Ack{RequestID: 9, Mids: []mailbox.Hash{hash(1)}})},
		{"ack result", enc(mailbox.AckResult{RequestID: 9, Deleted: 1})},
		{"error", enc(mailbox.Error{Code: mailbox.CodeAuth})},
		{"revoke device", enc(mailbox.RevokeByDevice{RequestID: 3, Keys: keys, NotBefore: 5, Signature: sig(9)})},
		{"revoke wallet", enc(mailbox.RevokeByWallet{RequestID: 4, Sign1: bs(10, 3), Key: bs(5, 4)})},
		{"revoke result", enc(mailbox.RevokeResult{RequestID: 3, Status: mailbox.RevokeRecorded})},
	}
}

// The table of who may send which frame, at which stage. A frame not in a cell
// is refused. This is the table of the spec, written out independently of the
// decoder. The Challenge is the first frame of a connection, so the stage before
// the Auth takes it (a client that reads a second one stops itself: it expects an
// AuthOK or a RevokeResult).
var acceptedFrames = map[struct {
	stage  mailbox.Stage
	client bool
}][]string{
	{mailbox.StageV2PreAuth, true}:  {"auth", "revoke device", "revoke wallet"},
	{mailbox.StageV2PreAuth, false}: {"challenge", "authok", "error", "revoke result"},
	{mailbox.StageV2Authed, true}:   {"put", "fetch", "ack"},
	{mailbox.StageV2Authed, false}:  {"put result", "items", "ack result", "error"},
}

// spec: SPO-Xmailbox-OUT-051, SPO-Xmailbox-PRE-029
func TestTheStageTable(t *testing.T) {
	frames := tableFrames(t)
	if len(acceptedFrames) != 4 {
		t.Fatal("the table has four cells")
	}
	for cell, names := range acceptedFrames {
		ok := map[string]bool{}
		for _, n := range names {
			ok[n] = true
		}
		for _, f := range frames {
			var m mailbox.Message
			var err error
			if cell.client {
				m, err = mailbox.DecodeFromClientIn(cell.stage, f.frame)
			} else {
				m, err = mailbox.DecodeFromRelayIn(cell.stage, f.frame)
			}
			switch {
			case ok[f.name] && err != nil:
				t.Errorf("%v client=%v: %s is refused: %v", cell.stage, cell.client, f.name, err)
			case ok[f.name] && !sameBytesOf(t, m, f.frame):
				t.Errorf("%v client=%v: %s decodes to something else", cell.stage, cell.client, f.name)
			case !ok[f.name] && err == nil:
				t.Errorf("%v client=%v: %s is accepted", cell.stage, cell.client, f.name)
			case !ok[f.name] && m != nil:
				t.Errorf("%v client=%v: %s is refused but a message is returned", cell.stage, cell.client, f.name)
			}
		}
	}
}

func sameBytesOf(t *testing.T, m mailbox.Message, frame []byte) bool {
	t.Helper()
	b, err := reencode(m)
	return err == nil && sameBytes(b, frame)
}

// Each refusal of the table names its reason: the wrong sender, or a frame of
// the right sender at the wrong stage; a frame of the retired version 1 is the
// wrong version or the wrong shape.
//
// spec: SPO-Xmailbox-OUT-051, SPO-Xmailbox-PRE-029
func TestTheStageTableRefusalsNameTheirReason(t *testing.T) {
	byName := map[string][]byte{}
	for _, f := range tableFrames(t) {
		byName[f.name] = f.frame
	}
	type call struct {
		stage  mailbox.Stage
		client bool
	}
	for _, c := range []struct {
		name string
		at   call
		want error
	}{
		// The wrong sender.
		{"revoke device", call{mailbox.StageV2PreAuth, false}, mailbox.ErrDirection},
		{"revoke wallet", call{mailbox.StageV2PreAuth, false}, mailbox.ErrDirection},
		{"revoke result", call{mailbox.StageV2PreAuth, true}, mailbox.ErrDirection},
		{"auth", call{mailbox.StageV2PreAuth, false}, mailbox.ErrDirection},
		{"challenge", call{mailbox.StageV2PreAuth, true}, mailbox.ErrDirection},
		{"put result", call{mailbox.StageV2Authed, true}, mailbox.ErrDirection},
		// The right sender at the wrong stage.
		{"put", call{mailbox.StageV2PreAuth, true}, mailbox.ErrStage},
		{"fetch", call{mailbox.StageV2PreAuth, true}, mailbox.ErrStage},
		{"ack", call{mailbox.StageV2PreAuth, true}, mailbox.ErrStage},
		{"auth", call{mailbox.StageV2Authed, true}, mailbox.ErrStage},
		{"revoke device", call{mailbox.StageV2Authed, true}, mailbox.ErrStage},
		{"revoke wallet", call{mailbox.StageV2Authed, true}, mailbox.ErrStage},
		{"challenge", call{mailbox.StageV2Authed, false}, mailbox.ErrStage},
		{"authok", call{mailbox.StageV2Authed, false}, mailbox.ErrStage},
		{"revoke result", call{mailbox.StageV2Authed, false}, mailbox.ErrStage},
		{"put result", call{mailbox.StageV2PreAuth, false}, mailbox.ErrStage},
		{"items", call{mailbox.StageV2PreAuth, false}, mailbox.ErrStage},
		{"ack result", call{mailbox.StageV2PreAuth, false}, mailbox.ErrStage},
	} {
		var err error
		if c.at.client {
			_, err = mailbox.DecodeFromClientIn(c.at.stage, byName[c.name])
		} else {
			_, err = mailbox.DecodeFromRelayIn(c.at.stage, byName[c.name])
		}
		if !errors.Is(err, c.want) {
			t.Errorf("%s at %v (client=%v): %v, want %v", c.name, c.at.stage, c.at.client, err, c.want)
		}
	}
	// The frames of the retired version 1 on a version 2 connection: an Auth of
	// version 1 (or any version but 2) is the wrong version, and a Put or an AuthOK
	// of the old shape is the wrong shape.
	for _, v := range []uint64{0, 1, 3, 65535} {
		_, err := mailbox.DecodeFromClientIn(mailbox.StageV2PreAuth, cbor(t, 1, v, fpb(3), sigb(4)))
		if !errors.Is(err, mailbox.ErrVersion) {
			t.Errorf("an Auth of version %d: %v", v, err)
		}
	}
	if _, err := mailbox.DecodeFromClientIn(mailbox.StageV2PreAuth, cbor(t, 1)); !errors.Is(err, mailbox.ErrMalformed) {
		t.Errorf("an Auth with no version: %v", err)
	}
	if _, err := mailbox.DecodeFromClientIn(mailbox.StageV2PreAuth, cbor(t, 1, "2", fpb(3), sigb(4))); !errors.Is(err, mailbox.ErrMalformed) {
		t.Errorf("an Auth with a text version: %v", err)
	}
	if _, err := mailbox.DecodeFromClientIn(mailbox.StageV2Authed, cbor(t, 3, 7, fpb(4), hashb(5), 99)); !errors.Is(err, mailbox.ErrMalformed) {
		t.Errorf("a Put of the retired shape: %v", err)
	}
	if _, err := mailbox.DecodeFromRelayIn(mailbox.StageV2PreAuth, cbor(t, 2, 1, 10, 11, 12, 13)); !errors.Is(err, mailbox.ErrMalformed) {
		t.Errorf("an AuthOK of the retired shape (five fields): %v", err)
	}
	if _, err := mailbox.DecodeFromRelayIn(mailbox.StageV2PreAuth, cbor(t, 2, 1, 10, 11, 12, 13, 14)); !errors.Is(err, mailbox.ErrVersion) {
		t.Errorf("an AuthOK of version 1 with an until: %v", err)
	}
	if m, err := mailbox.DecodeFromClientIn(mailbox.StageV2PreAuth, byName["auth"]); err != nil {
		t.Errorf("an Auth: %v", err)
	} else if _, ok := m.(mailbox.AuthV2); !ok {
		t.Errorf("decoded to %T", m)
	}
	// An invalid stage refuses everything.
	for _, st := range []mailbox.Stage{0, 3, 4, 255} {
		for name, b := range byName {
			if _, err := mailbox.DecodeFromClientIn(st, b); !errors.Is(err, mailbox.ErrStage) {
				t.Errorf("stage %d from the client, %s: %v", st, name, err)
			}
			if _, err := mailbox.DecodeFromRelayIn(st, b); !errors.Is(err, mailbox.ErrStage) {
				t.Errorf("stage %d from the relay, %s: %v", st, name, err)
			}
		}
	}
}

// The reason is decided by the type, before the fields are looked at: junk
// fields of a type that the stage does not allow are refused as the stage says,
// and junk of an allowed type is refused as a malformed message.
//
// spec: SPO-Xmailbox-OUT-051, SPO-Xmailbox-PRE-004
func TestStageIsDecidedByTheTypeAlone(t *testing.T) {
	sender := func(typ uint64) (client bool) {
		switch typ {
		case 1, 3, 5, 7, 10:
			return true
		}
		return false
	}
	for cell, names := range acceptedFrames {
		allowedTypes := map[uint64]bool{}
		for _, n := range names {
			switch n {
			case "challenge":
				allowedTypes[0] = true
			case "auth":
				allowedTypes[1] = true
			case "authok":
				allowedTypes[2] = true
			case "put":
				allowedTypes[3] = true
			case "put result":
				allowedTypes[4] = true
			case "fetch":
				allowedTypes[5] = true
			case "items":
				allowedTypes[6] = true
			case "ack":
				allowedTypes[7] = true
			case "ack result":
				allowedTypes[8] = true
			case "error":
				allowedTypes[9] = true
			case "revoke device", "revoke wallet":
				allowedTypes[10] = true
			case "revoke result":
				allowedTypes[11] = true
			}
		}
		for typ := uint64(0); typ <= 11; typ++ {
			junk := cbor(t, typ, "junk")
			var err error
			if cell.client {
				_, err = mailbox.DecodeFromClientIn(cell.stage, junk)
			} else {
				_, err = mailbox.DecodeFromRelayIn(cell.stage, junk)
			}
			switch {
			case sender(typ) != cell.client:
				if !errors.Is(err, mailbox.ErrDirection) {
					t.Errorf("%v client=%v type %d: %v", cell.stage, cell.client, typ, err)
				}
			case !allowedTypes[typ]:
				if !errors.Is(err, mailbox.ErrStage) {
					t.Errorf("%v client=%v type %d: %v", cell.stage, cell.client, typ, err)
				}
			default:
				if err == nil || errors.Is(err, mailbox.ErrStage) || errors.Is(err, mailbox.ErrDirection) || errors.Is(err, mailbox.ErrUnknownType) {
					t.Errorf("%v client=%v type %d: %v", cell.stage, cell.client, typ, err)
				}
			}
		}
		for _, typ := range []uint64{12, 255, 1 << 32, 1<<32 + 10, 1 << 63, 1<<64 - 1} {
			var err error
			if cell.client {
				_, err = mailbox.DecodeFromClientIn(cell.stage, cbor(t, typ))
			} else {
				_, err = mailbox.DecodeFromRelayIn(cell.stage, cbor(t, typ))
			}
			if !errors.Is(err, mailbox.ErrUnknownType) {
				t.Errorf("%v client=%v type %d: %v", cell.stage, cell.client, typ, err)
			}
		}
	}
}

func equalMsgs(a, b mailbox.Message) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	x, errX := reencode(a)
	y, errY := reencode(b)
	return errX == nil && errY == nil && sameBytes(x, y)
}
