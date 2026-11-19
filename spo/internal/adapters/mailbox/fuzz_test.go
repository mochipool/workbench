package mailbox_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// FuzzClientAgainstArbitraryRelayBytes gives the client arbitrary bytes as the
// relay's stream: from the first byte (mode 0), after an honest Challenge
// (mode 1) or after an honest handshake (mode 2). The first byte of the input
// also picks the operation (Receive or Send). The client never panics, always
// returns within its context, returns only the errors it documents, and never
// delivers an envelope whose hash was not verified: a delivered envelope's
// bytes and its Blake2b-256 both appear in the input (the relay's only source),
// so the hash it was checked against was announced by the relay in a header.
//
// spec: SPO-Xmailbox-INV-018
func FuzzClientAgainstArbitraryRelayBytes(f *testing.F) {
	env := newEnv(40, 9)
	items, _ := wire.Encode(wire.Items{RequestID: 1, Entries: []wire.Item{{Mid: wire.HashOf(env), Size: uint32(len(env))}}})
	itemsFrame, _ := wire.AppendFrame(nil, items)
	rawFrame := append([]byte{0, 0, 0, byte(len(env))}, env...)
	okPut, _ := wire.Encode(wire.PutResult{RequestID: 1, Status: wire.StatusStored})
	okPutFrame, _ := wire.AppendFrame(nil, okPut)
	ch, _ := wire.Encode(wire.Challenge{Min: 1, Max: 1, RelayKey: party.NodeKey{}, RelayTime: 1_700_000_000})
	chFrame, _ := wire.AppendFrame(nil, ch)
	auth, _ := wire.Encode(wire.AuthOK{Version: 1, MaxEnvelope: 1 << 20, MaxEntries: 256, MaxBytes: 64 << 20, RetentionSeconds: 86400})
	authFrame, _ := wire.AppendFrame(nil, auth)
	errFrame, _ := wire.AppendFrame(nil, []byte{0x82, 0x09, 0x04})

	f.Add(append([]byte{0}, chFrame...))                                                         // Receive, from the first byte
	f.Add(append(append([]byte{2}, itemsFrame...), rawFrame...))                                 // Receive, an honest page
	f.Add(append([]byte{0x82}, okPutFrame...))                                                   // Send, stored
	f.Add(append(append([]byte{1}, authFrame...), itemsFrame...))                                // Receive, after Challenge
	f.Add(append([]byte{2}, errFrame...))                                                        // Receive, an Error frame
	f.Add([]byte{0, 0xff, 0xff, 0xff, 0xff})                                                     // an absurd length
	f.Add([]byte{2, 0, 0, 0, 3, 0x9f, 0x00, 0xff})                                               // an indefinite array
	f.Add(append(append([]byte{2}, itemsFrame...), append([]byte{0, 0, 0, 40}, env[:10]...)...)) // a short body

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 || len(data) > 600 {
			t.Skip()
		}
		mode, send := data[0]&3, data[0]&0x80 != 0
		payload := data[1:]
		h := newHostile(t, func(s *sconn) {
			switch mode {
			case 0:
				s.raw(payload)
			case 1:
				s.challenge(hs{})
				if _, err := s.recv(); err != nil {
					return
				}
				s.raw(payload)
			default:
				if !s.handshake(hs{}) {
					return
				}
				s.raw(payload)
			}
			s.st.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
			buf := make([]byte, 4096)
			for {
				if _, err := s.st.Read(buf); err != nil {
					return
				}
			}
		})
		c := h.client(func(cfg *mailbox.Config) {
			l := &cfg.Limits
			l.HandshakeTimeout, l.IdleTimeout, l.BodyTimeout, l.WriteTimeout, l.DialTimeout = 60*time.Millisecond, 60*time.Millisecond, 60*time.Millisecond, 60*time.Millisecond, 60*time.Millisecond
			l.OpTimeout, l.MinPoll, l.BackoffMin, l.BackoffMax = 300*time.Millisecond, 5*time.Millisecond, 5*time.Millisecond, 20*time.Millisecond
			l.WaitSeconds, l.MaxBytesRead = -1, 64<<10
		})
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		defer cancel()
		if send {
			err := c.Send(ctx, party.Fingerprint{1}, newEnv(30, 1))
			if err != nil && !errors.Is(err, ports.ErrNoRoute) && !errors.Is(err, ports.ErrRefusedByTransport) &&
				!errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Send returned an error outside the documented set: %v", err)
			}
		} else {
			got, err := c.Receive(ctx)
			if err == nil {
				if !bytes.Contains(data, got.Envelope) || !bytes.Contains(data, hashBytes(got.Envelope)) {
					t.Fatalf("an envelope of %d bytes was delivered that the relay's bytes do not announce and carry", len(got.Envelope))
				}
				if got.Via() != ports.ViaNetwork || len(got.Envelope) == 0 || len(got.Envelope) > wire.MaxEnvelopeBytes {
					t.Fatalf("a delivery of kind %v and %d bytes", got.Via(), len(got.Envelope))
				}
			} else if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, mailbox.ErrProtocol) &&
				!errors.Is(err, mailbox.ErrRelayKey) && !errors.Is(err, mailbox.ErrRelayError) && !errors.Is(err, mailbox.ErrSigner) {
				t.Fatalf("Receive returned an error outside the documented set: %v", err)
			}
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("the operation took %v against a 250 ms context", d)
		}
	})
}

func hashBytes(b []byte) []byte { h := wire.HashOf(b); return h[:] }
