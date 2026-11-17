package keyfile

import (
	"strings"
	"testing"
)

const words12 = "abandon ability able about above absent absorb abstract absurd abuse access accident"

// What a transfer file legitimately is passes: verification keys, certificates,
// transactions, witnesses, metadata, and text that only resembles a secret.
//
// spec: SPO-Xcustody-PRE-004
func TestSecretFileReasonAcceptsOrdinaryTransferFiles(t *testing.T) {
	for name, content := range map[string]string{
		"verification key":  `{"type":"PaymentVerificationKeyShelley_ed25519","description":"","cborHex":"5820` + strings.Repeat("ab", 32) + `"}`,
		"certificate":       `{"type":"CertificateShelley","description":"Stake Address Registration Certificate","cborHex":"82008200581c` + strings.Repeat("cd", 28) + `"}`,
		"transaction":       `{"type":"Unwitnessed Tx ConwayEra","description":"Ledger Cddl Format","cborHex":"84a40081"}`,
		"witness":           `{"type":"TxWitness ConwayEra","description":"","cborHex":"82008258` + strings.Repeat("ab", 8) + `"}`,
		"metadata":          `{"674":{"msg":["one two three four five six seven eight nine ten eleven twelve"]}}`,
		"metadata of words": `{"a":"one","b":"two","c":"six","d":"ten","e":"cat","f":"dog","g":"fox","h":"bee","i":"ant","j":"owl","k":"yak","l":"emu"}`,
		"a bech32 address":  "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwq2ytjqp",
		"a bech32 vkey":     "ed25519_vk1" + strings.Repeat("q", 30),
		"eleven words":      "abandon ability able about above absent absorb abstract absurd abuse access",
		"hex of 40":         strings.Repeat("ab", 20),
		"a tx id in text":   "tx " + strings.Repeat("ab", 32),
	} {
		if why := SecretFileReason("f.json", []byte(content)); why != "" {
			t.Errorf("%s refused: %s", name, why)
		}
	}
}

// spec: SPO-Xcustody-PRE-004
func TestSecretFileReasonRefusesSecretsInTheirDisguises(t *testing.T) {
	sk := `{"type":"PaymentSigningKeyShelley_ed25519","description":"","cborHex":"5820` + strings.Repeat("ab", 32) + `"}`
	enc := `{"type":"PaymentSigningKeyShelley_ed25519","description":"Encrypted x","encrHex":"` + strings.Repeat("8c", 40) + `"}`
	bech := func(hrp string) string { return hrp + "1" + strings.Repeat("qpzry9x8gf2tvdw0s3jn54khce6mua7l", 2) }
	cases := map[string]string{
		"a signing key":                      sk,
		"a BOM then a signing key":           "\xef\xbb\xbf" + sk,
		"a UTF-16 mark":                      "\xff\xfe" + sk,
		"an array with a signing key":        "[" + `{"type":"Tx"},` + sk + "]",
		"a nested object with a signing key": `{"files":{"a":{"b":[` + sk + `]}}}`,
		"an array with an encrypted key":     "[" + enc + "]",
		"an array with a hardware key":       `[{"type":"PaymentHWSigningFileShelley_ed25519","description":"x","cborXPubKeyHex":"5840aa"}]`,
		"64 hex":                             strings.Repeat("0a", 32) + "\n",
		"128 hex, upper case":                strings.ToUpper(strings.Repeat("0a", 64)),
		"64 hex with a BOM":                  "\xef\xbb\xbf" + strings.Repeat("0a", 32),
		"mnemonic in capitals":               strings.ToUpper(words12),
		"mnemonic with commas":               strings.ReplaceAll(words12, " ", ", "),
		"mnemonic numbered":                  "1. abandon\n2. ability\n3. able\n4. about\n5. above\n6. absent\n7. absorb\n8. abstract\n9. absurd\n10) abuse\n11) access\n12) accident\n",
		"mnemonic over lines":                strings.ReplaceAll(words12, " ", "\n"),
		"mnemonic in a JSON array":           `["abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse","access","accident"]`,
		"mnemonic with a BOM":                "\xef\xbb\xbf" + words12,
		"mnemonic mixed case":                "Abandon Ability ABLE about Above absent absorb abstract absurd abuse access accident",
	}
	for _, hrp := range []string{"ed25519_sk", "ed25519e_sk", "ed25519_seed", "xprv", "acct_xsk", "root_xsk", "addr_xsk", "stake_xsk", "pool_sk",
		"kes_sk", "vrf_sk", "drep_sk", "drep_xsk", "cc_cold_sk", "cc_hot_sk", "cc_cold_xsk", "cc_hot_xsk", "acct_shared_xsk", "root_shared_xsk", "policy_sk"} {
		cases["bech32 "+hrp] = bech(hrp) + "\n"
		cases["bech32 upper "+hrp] = strings.ToUpper(bech(hrp))
		cases["bech32 "+hrp+" in text"] = "key: " + bech(hrp) + " end"
	}
	for name, content := range cases {
		why := SecretFileReason("transfer.txt", []byte(content))
		if why == "" {
			t.Errorf("%s was accepted", name)
		}
		if strings.Contains(why, strings.Repeat("qpzry9x8", 2)) {
			t.Errorf("%s: the reason quotes the content: %s", name, why)
		}
	}
}
