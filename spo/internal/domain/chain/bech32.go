package chain

import (
	"errors"
	"fmt"
	"strings"
)

// Bech32 (BIP-173), with no length limit: Cardano addresses exceed 90
// characters. Only the original checksum constant is accepted.

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var bech32Gen = [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

func bech32Polymod(values []byte) uint32 {
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= bech32Gen[i]
			}
		}
	}
	return chk
}

func bech32HRPExpand(hrp string) []byte {
	out := make([]byte, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]&31)
	}
	return out
}

func convertBits(data []byte, from, to uint, pad bool) ([]byte, error) {
	var acc uint32
	var bits uint
	var out []byte
	maxv := uint32(1)<<to - 1
	for _, v := range data {
		if uint32(v)>>from != 0 {
			return nil, errors.New("bech32: value out of range")
		}
		acc = acc<<from | uint32(v)
		bits += from
		for bits >= to {
			bits -= to
			out = append(out, byte(acc>>bits&maxv))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte(acc<<(to-bits)&maxv))
		}
	} else if bits >= from || acc<<(to-bits)&maxv != 0 {
		return nil, errors.New("bech32: invalid padding")
	}
	return out, nil
}

// Bech32Encode encodes data (bytes) under a lower-case human-readable part.
func Bech32Encode(hrp string, data []byte) (string, error) {
	if hrp == "" || hrp != strings.ToLower(hrp) {
		return "", errors.New("bech32: hrp must be non-empty lower case")
	}
	for i := 0; i < len(hrp); i++ {
		if hrp[i] < 33 || hrp[i] > 126 {
			return "", errors.New("bech32: invalid hrp character")
		}
	}
	d5, err := convertBits(data, 8, 5, true)
	if err != nil {
		return "", err
	}
	values := append(append(bech32HRPExpand(hrp), d5...), 0, 0, 0, 0, 0, 0)
	mod := bech32Polymod(values) ^ 1
	var sb strings.Builder
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, v := range d5 {
		sb.WriteByte(bech32Charset[v])
	}
	for i := 0; i < 6; i++ {
		sb.WriteByte(bech32Charset[(mod>>uint(5*(5-i)))&31])
	}
	return sb.String(), nil
}

// Bech32Decode returns the human-readable part and the data bytes. Mixed
// case, a bad character or a bad checksum is an error.
func Bech32Decode(s string) (string, []byte, error) {
	if s != strings.ToLower(s) && s != strings.ToUpper(s) {
		return "", nil, errors.New("bech32: mixed case")
	}
	s = strings.ToLower(s)
	pos := strings.LastIndexByte(s, '1')
	if pos < 1 || pos+7 > len(s) {
		return "", nil, errors.New("bech32: bad separator position")
	}
	hrp := s[:pos]
	for i := 0; i < len(hrp); i++ {
		if hrp[i] < 33 || hrp[i] > 126 {
			return "", nil, errors.New("bech32: invalid hrp character")
		}
	}
	d5 := make([]byte, 0, len(s)-pos-1)
	for i := pos + 1; i < len(s); i++ {
		idx := strings.IndexByte(bech32Charset, s[i])
		if idx < 0 {
			return "", nil, fmt.Errorf("bech32: invalid character %q", s[i])
		}
		d5 = append(d5, byte(idx))
	}
	if bech32Polymod(append(bech32HRPExpand(hrp), d5...)) != 1 {
		return "", nil, errors.New("bech32: bad checksum")
	}
	data, err := convertBits(d5[:len(d5)-6], 5, 8, false)
	if err != nil {
		return "", nil, err
	}
	return hrp, data, nil
}

// Bech32 is the "pool1..." form of the pool id.
func (p PoolID) Bech32() string {
	s, _ := Bech32Encode("pool", p[:]) // cannot fail for a valid hrp
	return s
}

// ParsePoolBech32 reads a "pool1..." id.
func ParsePoolBech32(s string) (PoolID, error) {
	hrp, data, err := Bech32Decode(s)
	if err != nil {
		return PoolID{}, err
	}
	if hrp != "pool" || len(data) != 28 {
		return PoolID{}, errors.New("not a pool id (want hrp pool and 28 bytes)")
	}
	var p PoolID
	copy(p[:], data)
	return p, nil
}
