package fsstore

import "github.com/mochipool/workbench/spo/internal/ports"

// File names of the governance artefacts, as upstream's scripts name them.
//
// spec: SPO-Pfiles-OUT-024, SPO-Pfiles-OUT-025, SPO-Pfiles-OUT-026, SPO-Pfiles-OUT-027, SPO-Pfiles-OUT-028, SPO-Pfiles-OUT-029, SPO-Pfiles-OUT-030
func init() {
	for k, ext := range map[ports.Kind]string{
		ports.DRepSKey: ".drep.skey", ports.DRepHwsFile: ".drep.hwsfile", ports.DRepID: ".drep.id", ports.DRepMnemonics: ".drep.mnemonics",
		ports.DRepRegCert: ".drep-reg.cert", ports.DRepRetCert: ".drep-ret.cert",
		ports.CCColdVKey: ".cc-cold.vkey", ports.CCColdSKey: ".cc-cold.skey", ports.CCColdHwsFile: ".cc-cold.hwsfile",
		ports.CCColdHash: ".cc-cold.hash", ports.CCColdMnemonics: ".cc-cold.mnemonics",
		ports.CCHotVKey: ".cc-hot.vkey", ports.CCHotSKey: ".cc-hot.skey", ports.CCHotHwsFile: ".cc-hot.hwsfile",
		ports.CCHotHash: ".cc-hot.hash", ports.CCHotMnemonics: ".cc-hot.mnemonics",
		ports.CCHotCert: ".cc-hot.cert", ports.CCColdRetCert: ".cc-cold-ret.cert",
		ports.VoteDRepFile: ".drep.vote", ports.VoteCCHotFile: ".cc-hot.vote", ports.VotePoolFile: ".pool.vote",
		ports.GovActionFile: ".action",
	} {
		ext := ext
		layout[k] = func(r ports.Ref) string { return r.Name + ext }
	}
	// Vote files keep the process default mode, as upstream's `echo >` leaves
	// them (SPO-Pfiles-OUT-029); every other governance artefact is locked.
	for _, k := range []ports.Kind{ports.VoteDRepFile, ports.VoteCCHotFile, ports.VotePoolFile} {
		modes[k] = 0o644
	}
}
