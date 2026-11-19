package relaybind

// checkPublicKey refuses an Ed25519 verification key that is a small-order
// point or that is not a canonical encoding (ADR 0014 decision 3, revised after
// the package review). With the identity point, for instance, R = identity and
// S = 0 verify for every message.
//
// A point is small-order exactly when its y coordinate is one of five values:
// 0 (the two points of order 4), 1 (the identity), p-1 (order 2) and the two y
// values of the four points of order 8. The sign bit (bit 255) does not change
// y, so every encoding of a small-order point is refused, including the
// non-canonical ones that set the sign bit of x = 0. A y of p or more (up to
// 2^255 - 1) is not canonical and is refused too: such an encoding means y - p.
//
// Everything here is a comparison of 32 bytes; it allocates nothing.
func checkPublicKey(k []byte) error {
	if len(k) != 32 {
		return ErrWeakKey
	}
	var y [32]byte
	copy(y[:], k)
	y[31] &^= 0x80 // drop the sign bit of x
	if yAtLeastP(&y) {
		return ErrWeakKey
	}
	for i := range smallOrderY {
		if y == smallOrderY[i] {
			return ErrWeakKey
		}
	}
	return nil
}

// yAtLeastP reports y >= p = 2^255 - 19 for a little-endian y below 2^255.
func yAtLeastP(y *[32]byte) bool {
	if y[31] != 0x7f {
		return false
	}
	for _, c := range y[1:31] {
		if c != 0xff {
			return false
		}
	}
	return y[0] >= 0xed
}

// smallOrderY are the y coordinates (little-endian) of the eight small-order
// points of Curve25519 in Edwards form: 0, 1, p-1, and the two of order 8.
var smallOrderY = [5][32]byte{
	{},  // y = 0: the two points of order 4
	{1}, // y = 1: the identity
	{0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, // y = p-1: order 2
	{0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
		0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a}, // order 8
	{0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
		0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05}, // order 8
}
