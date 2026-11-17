package keyfile

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
)

// bech32SecretRE finds a bech32 string whose human-readable part is the one of
// a private key (CIP-5): ed25519_sk, ed25519e_sk, ed25519_seed, xprv and every
// name ending _sk, _xsk or _seed (root_xsk, acct_xsk, addr_xsk, stake_xsk,
// pool_sk, kes_sk, vrf_sk, drep_sk, drep_xsk, cc_cold_sk, cc_hot_sk,
// cc_cold_xsk, cc_hot_xsk, policy_sk, the _shared_xsk forms, ...). It looks
// anywhere in the text, in either case.
var bech32SecretRE = regexp.MustCompile(`(?i)(?:^|[^a-z0-9_])(?:xprv|[a-z0-9]+(?:_[a-z0-9]+)*_(?:sk|xsk|seed))1[02-9ac-hj-np-z]{20,}`)

// SecretFileReason says why a file must not be copied into something that is
// carried or shared in clear, or "" when nothing about it says it is a secret.
// It looks at the name (a signing key `.skey`, a hardware signing file
// `.hwsfile`, a `.mnemonics` file) and at the content: a cardano-cli text
// envelope of a signing key, upstream's encrypted-key envelope, a hardware
// signing file, a JSON envelope whose type names a signing key, and a mnemonic
// word list (12, 15, 18, 21 or 24 lower-case words). The reason names the
// category and never quotes the content.
//
// This is a guard against a slip, not a proof that a file is harmless: a file
// disguised on purpose passes.
//
// spec: SPO-Xcustody-INV-001
func SecretFileReason(name string, data []byte) string {
	// A byte order mark must not hide content from the checks below. UTF-8 is
	// dropped; a UTF-16 file is refused, since its text cannot be inspected as
	// it stands and no cardano-cli file is written in it.
	if bytes.HasPrefix(data, []byte{0xff, 0xfe}) || bytes.HasPrefix(data, []byte{0xfe, 0xff}) {
		return "it is UTF-16 text, which cannot be checked for a secret"
	}
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	n := strings.ToLower(name)
	switch {
	case strings.HasSuffix(n, ".skey"):
		return "its name says it is a signing key (.skey)"
	case strings.HasSuffix(n, ".hwsfile"):
		return "its name says it is a hardware signing file (.hwsfile)"
	case strings.HasSuffix(n, ".mnemonics"):
		return "its name says it is a mnemonic file (.mnemonics)"
	}
	if info, err := Classify(data); err == nil || info.Form != FormMalformed || info.Type != "" {
		switch info.Form {
		case FormPlain:
			return "it is a cardano-cli signing key envelope"
		case FormEncrypted:
			return "it is an upstream encrypted-key envelope: it holds a signing key protected by a password only"
		case FormHardware:
			return "it is a hardware signing file"
		}
		if strings.Contains(info.Type, "SigningKey") {
			return "it is an envelope of a signing key type"
		}
	}
	if bytes.Contains(data, []byte(`"encrHex"`)) {
		return "it looks like an upstream encrypted-key envelope"
	}
	if bech32SecretRE.Match(data) {
		return "it holds a bech32 private key (CIP-5 prefix such as ed25519_sk, xprv, root_xsk, kes_sk)"
	}
	if isBareKeyHex(data) {
		return "it is only a 64 or 128 character hex string, the size of a private key"
	}
	if r := jsonSecretReason(data); r != "" {
		return r
	}
	if looksLikeMnemonic(data) {
		return "it looks like a mnemonic word list"
	}
	return ""
}

// isBareKeyHex reports whether the whole file, apart from surrounding white
// space, is 64 or 128 hexadecimal characters: a raw Ed25519 seed or an
// extended key.
func isBareKeyHex(data []byte) bool {
	t := bytes.TrimSpace(data)
	if len(t) != 64 && len(t) != 128 {
		return false
	}
	for _, c := range t {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// jsonSecretReason looks through a JSON document of any shape, arrays and
// nested objects included, for an envelope of a signing key, of a hardware
// signing file or of upstream's encrypted form.
func jsonSecretReason(data []byte) string {
	var v any
	if json.Unmarshal(bytes.TrimSpace(data), &v) != nil {
		return ""
	}
	var walk func(v any, depth int) string
	walk = func(v any, depth int) string {
		if depth > 32 {
			return ""
		}
		switch x := v.(type) {
		case map[string]any:
			typ, _ := x["type"].(string)
			if _, ok := x["encrHex"]; ok {
				return "it holds an upstream encrypted-key envelope"
			}
			if _, ok := x["cborXPubKeyHex"]; ok || strings.Contains(typ, "HWSigningFile") {
				return "it holds a hardware signing file"
			}
			if strings.Contains(typ, "SigningKey") {
				return "it holds an envelope of a signing key type"
			}
			for _, e := range x {
				if r := walk(e, depth+1); r != "" {
					return r
				}
			}
		case []any:
			for _, e := range x {
				if r := walk(e, depth+1); r != "" {
					return r
				}
			}
		}
		return ""
	}
	return walk(v, 0)
}

// looksLikeMnemonic reports whether the text is 12, 15, 18, 21 or 24 words of
// 3 to 8 letters, in either case, separated by anything but letters: spaces,
// line breaks, commas, numbering such as "1." or "2)". A JSON object is never
// one (metadata has words in it); a JSON array of strings is read as its
// words.
func looksLikeMnemonic(data []byte) bool {
	text := string(data)
	var v any
	if json.Unmarshal(bytes.TrimSpace(data), &v) == nil {
		arr, ok := v.([]any)
		if !ok {
			return false
		}
		var parts []string
		for _, e := range arr {
			s, ok := e.(string)
			if !ok {
				return false
			}
			parts = append(parts, s)
		}
		text = strings.Join(parts, " ")
	}
	words := strings.FieldsFunc(text, func(r rune) bool { return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r > 127) })
	switch len(words) {
	case 12, 15, 18, 21, 24:
	default:
		return false
	}
	for _, w := range words {
		if len(w) < 3 || len(w) > 8 {
			return false
		}
		for i := 0; i < len(w); i++ {
			if c := w[i]; c >= 0x80 {
				return false
			}
		}
	}
	return true
}
