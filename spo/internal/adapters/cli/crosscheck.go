package cli

import (
	"fmt"
	"strings"

	"github.com/mochipool/workbench/spo/internal/platform/endpoint"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// CheckIndependentSources refuses an Env in which a harmful-if-false read
// (ADR 0006) has the same provider as its own second source. Two answers from
// one provider are one answer: the check would pass while corroborating
// nothing, so the Env is not built. It is run where the Env is wired, for every
// pair of a reader and its cross-check.
func (e *Env) CheckIndependentSources() error {
	var bad []string
	e.sharedHost = nil
	pair := func(name string, primary, second any) {
		if isNil(primary) || isNil(second) {
			return
		}
		p, ok1 := primary.(ports.ChainSource)
		s, ok2 := second.(ports.ChainSource)
		if ok1 && ok2 && p.Source() == s.Source() {
			bad = append(bad, fmt.Sprintf("%s is read from %s and cross-checked against %s", name, p.Source(), s.Source()))
			return
		}
		if ok1 && ok2 {
			pe, se := e.Endpoints[string(p.Source())], e.Endpoints[string(s.Source())]
			if endpoint.Same(pe, se) {
				h, _ := endpoint.Host(pe)
				if !e.SameHostOK {
					bad = append(bad, fmt.Sprintf("%s is read from %s and cross-checked against %s, but both are on the host %s", name, p.Source(), s.Source(), shown(h)))
				} else {
					e.sharedHost = append(e.sharedHost, fmt.Sprintf("%s: %s and %s", name, p.Source(), s.Source()))
				}
			}
		}
	}
	pair("the reward account", e.Rewards, e.CrossCheck)
	pair("the pool registration", e.Pools, e.PoolCross)
	pair("the DRep state", e.DReps, e.DRepCross)
	pair("the operational certificate counter", e.OpCertCounters, e.OpCertCross)
	if len(bad) == 0 {
		return nil
	}
	return fmt.Errorf("a cross-check needs a second, different provider (a different operator running a different chain follower, not another name for the same host): %s; if both really are independent behind one host, set same_host_ok = true under [provider] in spo.toml, which weakens the check", strings.Join(bad, "; "))
}

// SharedHostNote is the sentence a transaction summary carries when two sources
// of a cross-check share a host and [provider] same_host_ok let them through: ""
// when none did. A command that relied on a cross-check says it, because the
// agreement then does not show that the sources are independent.
func (e *Env) SharedHostNote() string {
	if len(e.sharedHost) == 0 {
		return ""
	}
	return "the two sources share a host (" + strings.Join(e.sharedHost, "; ") + "); independence acknowledged in spo.toml (same_host_ok)"
}
