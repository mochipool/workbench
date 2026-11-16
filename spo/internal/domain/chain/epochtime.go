package chain

import "time"

// TimeUntilNextEpoch is the time from now to the next epoch boundary, in the
// range one slot-second to a whole epoch: exactly on a boundary it is a
// whole epoch (SPO-Cchain-OUT-002). It is computed from the genesis start and
// the clock only, in every work mode, with the assumption that every epoch
// since the start has the same length (true for networks that started in
// Shelley and, with the Byron start and epochs of the genesis, for the others
// when the start is the Shelley system start). Unlike upstream, which uses
// the slot count as a number of seconds, the epoch length is slots times the
// slot length (SPO-Cchain-INV-007).
func TimeUntilNextEpoch(g Genesis, now time.Time) (time.Duration, bool) {
	if g.EpochLength == 0 || g.SlotLength <= 0 || now.Before(g.SystemStart) {
		return 0, false
	}
	epoch := time.Duration(g.EpochLength) * g.SlotLength
	elapsed := now.Sub(g.SystemStart).Truncate(time.Second)
	return epoch - elapsed%epoch, true
}
