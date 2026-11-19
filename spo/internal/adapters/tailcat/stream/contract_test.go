package stream

import (
	"testing"

	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

// The port contract suite of the relay's stream ports, against the real
// tailcat listener, dialer and streams (ADR 0013 work package 5). The one
// tunnel fault the suite needs, a cut, is injected by a test wrapper (see
// cutState); everything else is the real tunnel.
//
// spec: SPO-Xmailbox-IF-003
// spec: SPO-Xmailbox-IF-004
func TestStreamContractOverTailcat(t *testing.T) {
	reg := relayRegion(t)
	relayporttest.RunStream(t, realRig(reg))
}
