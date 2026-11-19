package relayregistry

// bucket is the token bucket of the relay-wide cap on new bindings, in integer
// arithmetic on relay time (no clock, no floats). One token is tokenUnits units;
// the bucket gains perHour units a second, which is perHour tokens an hour, and
// holds at most burst tokens. It starts full.
type bucket struct {
	perHour int64
	cap     int64 // burst * tokenUnits
	tokens  int64
	last    int64
	started bool
}

const tokenUnits int64 = 3600

func newBucket(perHour, burst int) bucket {
	return bucket{perHour: int64(perHour), cap: int64(burst) * tokenUnits, tokens: int64(burst) * tokenUnits}
}

// at is the token count at time now, without changing the bucket. A clock that
// steps back gains nothing.
func (b *bucket) at(now int64) int64 {
	if !b.started || now <= b.last {
		return b.tokens
	}
	elapsed := now - b.last
	if elapsed > b.cap { // more than enough to fill it; also keeps the product small
		elapsed = b.cap
	}
	t := b.tokens + elapsed*b.perHour
	if t > b.cap {
		t = b.cap
	}
	return t
}

// has reports whether one token is available at now.
func (b *bucket) has(now int64) bool { return b.at(now) >= tokenUnits }

// whole is the number of whole tokens available at now.
func (b *bucket) whole(now int64) int { return int(b.at(now) / tokenUnits) }

// take uses one token at now. The caller has checked has.
func (b *bucket) take(now int64) {
	t := b.at(now) - tokenUnits
	if t < 0 {
		t = 0
	}
	b.tokens = t
	if !b.started || now > b.last {
		b.last = now
	}
	b.started = true
}
