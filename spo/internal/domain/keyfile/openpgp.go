package keyfile

import (
	"errors"
	"fmt"
)

// ErrNotSymmetricPGP means a message is not what the export's gpg command
// makes: one symmetric-key encrypted session key packet (tag 3) with the pinned
// parameters, followed by one integrity-protected encrypted data packet
// (tag 18), and nothing else.
var ErrNotSymmetricPGP = errors.New("not a password-encrypted OpenPGP message with an integrity packet")

const (
	// MinExportCount is the S2K iteration count the export pins
	// (--s2k-count 65011712, the largest the one-octet coding can express).
	MinExportCount = 65011712

	// minDataBody is the least body length of a tag 18 packet that holds an
	// MDC-protected message: 1 version octet, 18 octets of the CFB random
	// prefix (16 block octets and 2 repeated), the shortest literal data packet
	// (2 octets of header, 1 format, 1 file name length, 4 date: 8) and the 22
	// octets of the MDC packet (tag 0xD3, length 0x14, 20 hash octets). A
	// shorter body cannot be an encrypted, integrity-protected message.
	minDataBody = 1 + 18 + 8 + 22
)

// SymmetricMessage describes a checked OpenPGP symmetric message. It holds
// parameters only, never a key or a plaintext.
type SymmetricMessage struct {
	Version    int // of the session key packet: 4
	Cipher     int // OpenPGP symmetric algorithm id (9 is AES-256)
	S2KMode    int // 3 is iterated and salted
	HashAlgo   int // of the S2K (10 is SHA-512)
	CountCoded int // the one-octet iteration count of mode 3
	Count      int // the iteration count it decodes to
}

// openpgpPacket is one packet header and body.
type openpgpPacket struct {
	tag  int
	body []byte
}

// parsePGPPackets splits msg into packets. It understands old and new format
// headers, partial body lengths and the indeterminate length of an old format
// data packet (which runs to the end of the message). It refuses a truncated
// packet.
func parsePGPPackets(msg []byte) ([]openpgpPacket, error) {
	var out []openpgpPacket
	for i := 0; i < len(msg); {
		ctb := msg[i]
		i++
		if ctb&0x80 == 0 {
			return nil, fmt.Errorf("%w: not a packet header", ErrNotSymmetricPGP)
		}
		var tag int
		var body []byte
		take := func(n int) ([]byte, bool) {
			if n < 0 || n > len(msg)-i {
				return nil, false
			}
			b := msg[i : i+n]
			i += n
			return b, true
		}
		if ctb&0x40 == 0 { // old format
			tag = int(ctb>>2) & 0x0f
			var n int
			switch ctb & 3 {
			case 0, 1, 2:
				w := 1 << (ctb & 3)
				if w > len(msg)-i {
					return nil, fmt.Errorf("%w: truncated header", ErrNotSymmetricPGP)
				}
				for _, c := range msg[i : i+w] {
					n = n<<8 | int(c)
				}
				i += w
			default: // indeterminate: to the end
				n = len(msg) - i
			}
			b, ok := take(n)
			if !ok {
				return nil, fmt.Errorf("%w: truncated packet", ErrNotSymmetricPGP)
			}
			body = b
		} else { // new format, with partial body lengths
			tag = int(ctb & 0x3f)
			for {
				if i >= len(msg) {
					return nil, fmt.Errorf("%w: truncated header", ErrNotSymmetricPGP)
				}
				o := int(msg[i])
				i++
				var n int
				partial := false
				switch {
				case o < 192:
					n = o
				case o < 224:
					if i >= len(msg) {
						return nil, fmt.Errorf("%w: truncated header", ErrNotSymmetricPGP)
					}
					n = (o-192)<<8 + int(msg[i]) + 192
					i++
				case o < 255:
					n = 1 << (o & 0x1f)
					partial = true
				default:
					if len(msg)-i < 4 {
						return nil, fmt.Errorf("%w: truncated header", ErrNotSymmetricPGP)
					}
					n = int(msg[i])<<24 | int(msg[i+1])<<16 | int(msg[i+2])<<8 | int(msg[i+3])
					i += 4
				}
				b, ok := take(n)
				if !ok {
					return nil, fmt.Errorf("%w: truncated packet", ErrNotSymmetricPGP)
				}
				body = append(body, b...)
				if !partial {
					break
				}
			}
		}
		out = append(out, openpgpPacket{tag: tag, body: body})
	}
	return out, nil
}

// CheckSymmetricMessage requires msg to be exactly what the export's gpg
// command emits: one tag 3 packet (version 4, AES-256, S2K mode 3, SHA-512, a
// count of at least MinExportCount, and no encrypted session key, so the
// password is the key), then one tag 18 packet whose version octet is 1 and
// whose body is at least minDataBody octets, and nothing else. Version 5 and
// the AEAD packet (tag 20) are not accepted: gpg with the pinned options does
// not make them. An unencrypted literal packet, a public-key encrypted packet,
// a packet without integrity protection (tag 9), a repeated or missing packet
// and trailing bytes are refused. Nothing is decrypted.
//
// What this proves, and what it cannot: ciphertext cannot be told from
// plaintext by looking at it, so this check shows that the envelope has the
// form of a password-encrypted message, not that its content is encrypted. That
// guarantee comes from the producers: the only writers of such an envelope are
// the gpg adapter, which encrypts with the pinned options and verifies the
// result decrypts, and an upstream-encrypted record kept verbatim from an
// import. A body of plausible length that is plaintext passes this check.
//
// spec: SPO-Xcustody-INV-001, SPO-Xcustody-INV-004, SPO-Ckey-INV-003
func CheckSymmetricMessage(msg []byte) (SymmetricMessage, error) {
	var m SymmetricMessage
	pk, err := parsePGPPackets(msg)
	if err != nil {
		return m, err
	}
	if len(pk) != 2 || pk[0].tag != 3 || pk[1].tag != 18 {
		return m, fmt.Errorf("%w: the packets are not one session key packet and one integrity-protected data packet", ErrNotSymmetricPGP)
	}
	// Version, cipher, S2K mode, hash, 8 octets of salt, the count octet: 13,
	// and nothing after it (an encrypted session key would follow).
	b := pk[0].body
	if len(b) != 13 || b[0] != 4 {
		return m, fmt.Errorf("%w: the session key packet is not version 4 without an encrypted session key", ErrNotSymmetricPGP)
	}
	m.Version = int(b[0])
	m.Cipher = int(b[1])
	m.S2KMode = int(b[2])
	m.HashAlgo = int(b[3])
	m.CountCoded = int(b[12])
	m.Count = (16 + m.CountCoded&15) << (uint(m.CountCoded>>4) + 6)
	if m.Cipher != 9 {
		return m, fmt.Errorf("%w: the cipher is not AES-256", ErrNotSymmetricPGP)
	}
	if m.S2KMode != 3 {
		return m, fmt.Errorf("%w: the key derivation is not iterated and salted", ErrNotSymmetricPGP)
	}
	if m.HashAlgo != 10 {
		return m, fmt.Errorf("%w: the key derivation does not use SHA-512", ErrNotSymmetricPGP)
	}
	if m.Count < MinExportCount {
		return m, fmt.Errorf("%w: the key derivation iterates %d times, fewer than %d", ErrNotSymmetricPGP, m.Count, MinExportCount)
	}
	d := pk[1].body
	if len(d) < minDataBody || d[0] != 1 {
		return m, fmt.Errorf("%w: the data packet is not a version 1 integrity-protected packet of the least size", ErrNotSymmetricPGP)
	}
	return m, nil
}
