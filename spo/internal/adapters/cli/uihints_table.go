package cli

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/platform/uihint"
)

// What each argument and flag holds, for the drivers that help fill it in
// (the TUI's completion and file picker, the shell completion). Keeping it in
// one table means a command file never carries UI code; the cost is that a
// renamed argument must be renamed here, which TestUIHintTableMatchesTheTree
// (cmd/spo) enforces.
//
// args is keyed by command path (without "spo") and then by the argument's
// label as the usage line spells it between its brackets; flags by command
// path and flag name. flagsEverywhere applies to every command that has the
// flag.

var (
	hWallet = uihint.Names(uihint.ClassWallet)
	hPool   = uihint.Names(uihint.ClassPool)
	hStake  = uihint.Names(uihint.ClassStake)
	hPolicy = uihint.Names(uihint.ClassPolicy)
	hAsset  = uihint.Names(uihint.ClassAsset)
	hDRep   = uihint.Names(uihint.ClassDRep)
	hCold   = uihint.Names(uihint.ClassCommitteeCold)
	hHot    = uihint.Names(uihint.ClassCommitteeHot)
	hVoting = uihint.Names(uihint.ClassVotingKey)
	hCal    = uihint.Names(uihint.ClassCalidus)
	hParty  = uihint.Names(uihint.ClassParty)
	hFile   = uihint.File()
	hJSON   = uihint.File(".json")
)

var argHints = map[string]map[string]string{
	"address":                        {"name|address": hWallet},
	"action create":                  {"return": hStake},
	"action submit":                  {"payer": hWallet, "action-file": hFile},
	"asset burn":                     {"policy.asset": hAsset, "payer": hWallet},
	"asset mint":                     {"policy.asset": hAsset, "payer": hWallet},
	"asset show":                     {"policy.asset": hAsset},
	"asset meta check":               {"policy.asset|subject": hAsset},
	"asset meta generate":            {"policy.asset": hAsset},
	"catalyst register":              {"stake-name": hStake, "rewards-address|name": hStake},
	"committee authorize":            {"cold": hCold, "hot": hHot, "payer": hWallet},
	"committee resign":               {"cold": hCold, "payer": hWallet},
	"committee status":               {"name|hash|id": hCold},
	"drep register":                  {"name": hDRep, "payer": hWallet},
	"drep retire":                    {"name": hDRep, "payer": hWallet},
	"drep status":                    {"name|id": hDRep},
	"key protect":                    {"file": hFile},
	"key unprotect":                  {"file": hFile},
	"offline add":                    {"name": hWallet},
	"offline add-drep":               {"name": hStake},
	"offline attach":                 {"file": hFile},
	"party connect":                  {"COORDINATOR": hParty},
	"party enroll":                   {"FILE": hFile},
	"party export":                   {"FILE": uihint.NewFile()},
	"party inbox import":             {"FILE|DIR": hFile},
	"party outbox export":            {"DIR": uihint.Dir()},
	"party request export":           {"POOL": hPool},
	"party request queue":            {"POOL": hPool},
	"party revoke":                   {"NAME": hParty},
	"party scope":                    {"NAME": hParty},
	"poll submit":                    {"payer": hWallet, "destination": hWallet, "pool": hPool},
	"pool bls generate":              {"pool": hPool},
	"pool calidus register-metadata": {"calidus-name": hCal, "pool": hPool},
	"pool calidus status":            {"calidus-id|public-key|pool|name|all": hCal},
	"pool cert generate":             {"pool": hPool},
	"pool descriptor new":            {"pool": hPool},
	"pool descriptor set":            {"pool": hPool},
	"pool descriptor show":           {"pool": hPool},
	"pool export-info":               {"file": uihint.NewFile(".json")},
	"pool import":                    {"pool-id|info.json": hJSON},
	"pool kes generate":              {"pool": hPool},
	"pool keys generate":             {"pool": hPool},
	"pool metadata show":             {"pool": hPool},
	"pool opcert check":              {"pool": hPool},
	"pool opcert counter":            {"pool|pool-id": hPool},
	"pool opcert issue":              {"pool": hPool},
	"pool opcert new-counter":        {"pool": hPool},
	"pool register":                  {"pool": hPool, "payer": hWallet},
	"pool retire":                    {"pool": hPool, "payer": hWallet},
	"pool retire-cert":               {"pool": hPool},
	"pool status":                    {"pool|pool-id": hPool},
	"pool vrf generate":              {"pool": hPool},
	"pool witness clear":             {"pool": hPool},
	"pool witness import":            {"pool": hPool, "file": hFile},
	"pool witness info":              {"pool": hPool},
	"pool witness sign":              {"file": hFile},
	"pool witness status":            {"pool": hPool},
	"stake delegate":                 {"delegator-name": hStake, "pool-id|pool-name": hPool},
	"stake delegation-cert":          {"pool-id|pool-name": hPool, "delegator-name": hStake},
	"stake deregister":               {"stake-name": hStake, "payer-name": hWallet},
	"stake register":                 {"stake-name": hStake, "payer-name": hWallet},
	"stake status":                   {"stake-name|stake-address": hStake},
	"stake vote-delegate":            {"delegator-name": hStake},
	"stake vote-delegation-cert":     {"delegator-name": hStake},
	"store backup":                   {"dest": uihint.NewFile()},
	"store restore":                  {"backup": hFile},
	"vote create":                    {"voter": hDRep},
	"vote submit":                    {"payer": hWallet, "vote-file": hFile},
	"wallet claim-rewards":           {"stake-name": hStake, "destination": hWallet},
	"wallet send":                    {"from": hWallet, "to": hWallet},
	"wallet send-assets":             {"from": hWallet, "to": hWallet},
	"workspace export":               {"dir": uihint.Dir()},
	"workspace import":               {"dir": uihint.Dir()},
}

var flagHints = map[string]map[string]string{
	"asset meta generate":  {"out": uihint.NewFile(".json")},
	"catalyst register":    {"vote-key": hVoting},
	"offline extract":      {"dir": uihint.Dir()},
	"party request export": {"out": uihint.Dir()},
	"party serve":          {"invite": hParty, "outbox": uihint.Dir()},
	"poll answer":          {"out": uihint.NewFile(".cbor")},
	"poll submit":          {"metadata-file": uihint.File(".cbor")},
	"pool descriptor new":  {"owner": hStake, "reward": hStake},
	"pool import":          {"cold": hFile, "vrf": hFile},
	"pool opcert check":    {"opcert-file": hFile},
	"pool witness sign":    {"key": hStake},
	"stake delegate":       {"payer": hWallet},
	"stake vote-delegate":  {"payer": hWallet},
	"store verify":         {"backup": hFile},
	"vote submit":          {"voter": hDRep},
	"wallet claim-rewards": {"payer": hWallet},
}

// flagsEverywhere hints a flag by name on every command that has it.
var flagsEverywhere = map[string]string{
	"transfer-file":   uihint.NewFile(".json"),
	"shelley-genesis": hJSON,
	"byron-genesis":   hJSON,
	"metadata-file":   uihint.File(".json", ".cbor"),
	"own-snapshot":    hJSON,
	"outbox":          uihint.Dir(),
	"inbox":           uihint.Dir(),
}

// applyHints sets the hints of one command from the tables.
func applyHints(root, c *cobra.Command) {
	path := strings.TrimPrefix(c.CommandPath(), root.Name()+" ")
	for label, h := range argHints[path] {
		uihint.SetArg(c, label, h)
	}
	for name, h := range flagsEverywhere {
		if f := c.Flags().Lookup(name); f != nil {
			uihint.SetFlag(f, h)
		}
	}
	for name, h := range flagHints[path] {
		if f := c.Flags().Lookup(name); f != nil {
			uihint.SetFlag(f, h)
		}
	}
}
